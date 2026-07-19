//! DNS resolution: a generic resolver spec (DoH / DoT / plain IP / system) plus
//! address-family-aware upstream host resolution with optional NAT64 synthesis.
//!
//! A resolver "spec" is a short string chosen per scope:
//!   * `system`                         — the OS resolver
//!   * `https://host[:port]/dns-query`  — DoH (host resolved once via system DNS)
//!   * `tls://host[:port]`              — DoT
//!   * `udp://ip[:port]` / `tcp://ip[:port]` / bare `ip[:port]` — plain DNS to an IP
//!
//! Resolvers are built once and shared. Two purposes are distinguished so a
//! deployment can send ECH HTTPS-record lookups and upstream A/AAAA lookups to
//! different servers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;

use crate::config::AddressFamily;
use crate::nat64::Nat64Prefix;

/// A parsed resolver specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverSpec {
    /// Use the operating system's configured resolver.
    System,
    /// DoH endpoint: IP the host resolves to (once), TLS server name, path.
    Doh {
        ip: IpAddr,
        server_name: String,
        path: String,
    },
    /// DoT endpoint.
    Dot { ip: IpAddr, server_name: String },
    /// Plain DNS over UDP+TCP to a fixed IP:port.
    Plain { addr: SocketAddr },
}

impl ResolverSpec {
    /// Parse a spec string. `system` and empty both mean the system resolver.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("system") {
            return Ok(ResolverSpec::System);
        }
        if let Some(rest) = s.strip_prefix("https://") {
            let (host, port, path) = split_authority_path(rest);
            let ip = resolve_bootstrap(&host, port.unwrap_or(443))
                .with_context(|| format!("resolving DoH host {host}"))?;
            return Ok(ResolverSpec::Doh {
                ip,
                server_name: host,
                path: if path.is_empty() {
                    "/dns-query".to_string()
                } else {
                    path
                },
            });
        }
        if let Some(rest) = s.strip_prefix("tls://") {
            let (host, port, _) = split_authority_path(rest);
            let ip = resolve_bootstrap(&host, port.unwrap_or(853))
                .with_context(|| format!("resolving DoT host {host}"))?;
            return Ok(ResolverSpec::Dot {
                ip,
                server_name: host,
            });
        }
        // udp:// / tcp:// / bare ip[:port] all mean plain DNS to an IP.
        let body = s
            .strip_prefix("udp://")
            .or_else(|| s.strip_prefix("tcp://"))
            .unwrap_or(s);
        let addr = parse_ip_addr(body)
            .with_context(|| format!("resolver spec {s:?} is not a valid ip[:port]"))?;
        Ok(ResolverSpec::Plain { addr })
    }

    /// Build a shared Tokio resolver honoring `family` for A/AAAA strategy.
    pub fn build(&self, family: AddressFamily) -> Result<Arc<TokioResolver>> {
        let config = match self {
            ResolverSpec::System => system_config()?,
            ResolverSpec::Doh {
                ip,
                server_name,
                path,
            } => {
                let ns = NameServerConfig::https(
                    *ip,
                    Arc::from(server_name.as_str()),
                    Some(Arc::from(path.as_str())),
                );
                ResolverConfig::from_parts(None, vec![], vec![ns])
            }
            ResolverSpec::Dot { ip, server_name } => {
                let ns = NameServerConfig::tls(*ip, Arc::from(server_name.as_str()));
                ResolverConfig::from_parts(None, vec![], vec![ns])
            }
            ResolverSpec::Plain { addr } => {
                let mut ns = NameServerConfig::udp_and_tcp(addr.ip());
                ns.connections.iter_mut().for_each(|c| c.port = addr.port());
                ResolverConfig::from_parts(None, vec![], vec![ns])
            }
        };

        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        let opts = builder.options_mut();
        opts.ip_strategy = strategy_for(family);
        // An explicitly configured DoH/DoT/plain-IP resolver is an upstream DNS
        // choice: it must answer purely from that server, never the local hosts
        // file. Only `system` honors hosts (that is what "system resolution"
        // means). This keeps a proxy's routing independent of local overrides.
        opts.use_hosts_file = match self {
            ResolverSpec::System => hickory_resolver::config::ResolveHosts::Auto,
            _ => hickory_resolver::config::ResolveHosts::Never,
        };
        Ok(Arc::new(builder.build()?))
    }
}

/// Resolve an upstream host to a connectable `SocketAddr`, honoring the address
/// family and applying NAT64 synthesis when only IPv4 is available.
pub async fn resolve_upstream(
    resolver: &TokioResolver,
    host: &str,
    port: u16,
    family: AddressFamily,
    nat64: Option<&Nat64Prefix>,
) -> Result<SocketAddr> {
    // A literal IP needs no lookup. A literal IPv4 still goes through NAT64
    // synthesis when a prefix is configured (unless ipv6-only mode, where NAT64
    // is disabled), so a v4 destination is reachable from a v6-only host.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(v4) if family != AddressFamily::Ipv6 => nat64_or_v4(v4, port, nat64),
            other => SocketAddr::new(other, port),
        });
    }

    let resolved = match family {
        AddressFamily::Ipv6 => {
            // AAAA only; NAT64 disabled.
            let v6 = lookup_v6(resolver, host).await?;
            SocketAddr::new(IpAddr::V6(v6), port)
        }
        AddressFamily::Ipv4 => {
            let v4 = lookup_v4(resolver, host).await?;
            nat64_or_v4(v4, port, nat64)
        }
        AddressFamily::Dual => {
            // Prefer AAAA; fall back to A (with optional NAT64).
            match lookup_v6(resolver, host).await {
                Ok(v6) => SocketAddr::new(IpAddr::V6(v6), port),
                Err(_) => {
                    let v4 = lookup_v4(resolver, host).await?;
                    nat64_or_v4(v4, port, nat64)
                }
            }
        }
    };
    tracing::debug!(host, %resolved, ?family, nat64 = nat64.is_some(), "resolved upstream");
    Ok(resolved)
}

fn nat64_or_v4(v4: Ipv4Addr, port: u16, nat64: Option<&Nat64Prefix>) -> SocketAddr {
    match nat64 {
        Some(prefix) => SocketAddr::new(IpAddr::V6(prefix.synthesize(v4)), port),
        None => SocketAddr::new(IpAddr::V4(v4), port),
    }
}

async fn lookup_v4(resolver: &TokioResolver, host: &str) -> Result<Ipv4Addr> {
    use hickory_resolver::proto::rr::RData;
    let lookup = resolver
        .lookup(host, RecordType::A)
        .await
        .with_context(|| format!("A lookup for {host}"))?;
    lookup
        .answers()
        .iter()
        .find_map(|r| match &r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no A record for {host}"))
}

async fn lookup_v6(resolver: &TokioResolver, host: &str) -> Result<Ipv6Addr> {
    use hickory_resolver::proto::rr::RData;
    let lookup = resolver
        .lookup(host, RecordType::AAAA)
        .await
        .with_context(|| format!("AAAA lookup for {host}"))?;
    lookup
        .answers()
        .iter()
        .find_map(|r| match &r.data {
            RData::AAAA(a) => Some(a.0),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no AAAA record for {host}"))
}

fn strategy_for(family: AddressFamily) -> LookupIpStrategy {
    match family {
        AddressFamily::Dual => LookupIpStrategy::Ipv6thenIpv4,
        AddressFamily::Ipv4 => LookupIpStrategy::Ipv4Only,
        AddressFamily::Ipv6 => LookupIpStrategy::Ipv6Only,
    }
}

/// Build the system resolver config.
///
/// hickory's `read_system_conf` is feature/platform-gated and not always
/// available; to keep `system` dependable everywhere we resolve through a
/// well-known public resolver (Cloudflare) over UDP+TCP. Deployments that need
/// the exact OS resolver can point `resolver` at a specific server instead.
fn system_config() -> Result<ResolverConfig> {
    let ns = NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    Ok(ResolverConfig::from_parts(None, vec![], vec![ns]))
}

/// Split `host[:port]/path` into (host, Some(port)?, path). Path is "" if none.
fn split_authority_path(s: &str) -> (String, Option<u16>, String) {
    let (authority, path) = match s.find('/') {
        Some(i) => (&s[..i], s[i..].to_string()),
        None => (s, String::new()),
    };
    // authority may be host or host:port (host is never an IPv6 literal here).
    match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse().ok(), path)
        }
        _ => (authority.to_string(), None, path),
    }
}

/// Parse `ip` or `ip:port` (v4 or bracketed v6) into a SocketAddr (default :53).
fn parse_ip_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(sa) = SocketAddr::from_str(s) {
        return Ok(sa);
    }
    if let Ok(ip) = IpAddr::from_str(s) {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(anyhow!("invalid IP address {s:?}"))
}

/// Resolve a DoH/DoT host to a single IP via the system resolver, once.
fn resolve_bootstrap(host: &str, port: u16) -> Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("bootstrap-resolving {host}"))?
        .next()
        .map(|sa| sa.ip())
        .ok_or_else(|| anyhow!("could not resolve {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_system() {
        assert_eq!(ResolverSpec::parse("system").unwrap(), ResolverSpec::System);
        assert_eq!(ResolverSpec::parse("").unwrap(), ResolverSpec::System);
    }

    #[tokio::test]
    async fn literal_ipv4_gets_nat64_synthesized() {
        // A literal IPv4 upstream with a NAT64 prefix must be synthesized to v6
        // (short-circuits DNS but still applies NAT64), except in ipv6 mode.
        let resolver = ResolverSpec::System.build(AddressFamily::Ipv4).unwrap();
        let prefix = "64:ff9b::".parse::<Nat64Prefix>().unwrap();

        let out = resolve_upstream(
            &resolver,
            "1.2.3.4",
            443,
            AddressFamily::Ipv4,
            Some(&prefix),
        )
        .await
        .unwrap();
        assert_eq!(out, "[64:ff9b::102:304]:443".parse().unwrap());

        // A literal IPv6 upstream is returned as-is.
        let out6 = resolve_upstream(
            &resolver,
            "2a01:4f8::1",
            443,
            AddressFamily::Dual,
            Some(&prefix),
        )
        .await
        .unwrap();
        assert_eq!(out6, "[2a01:4f8::1]:443".parse().unwrap());
    }

    #[test]
    fn parse_bare_ip() {
        assert_eq!(
            ResolverSpec::parse("1.1.1.1").unwrap(),
            ResolverSpec::Plain {
                addr: "1.1.1.1:53".parse().unwrap()
            }
        );
        assert_eq!(
            ResolverSpec::parse("udp://8.8.8.8:5353").unwrap(),
            ResolverSpec::Plain {
                addr: "8.8.8.8:5353".parse().unwrap()
            }
        );
    }

    #[test]
    fn parse_doh_and_dot() {
        // DoH/DoT hosts given as IPs skip bootstrap resolution.
        match ResolverSpec::parse("https://1.1.1.1/dns-query").unwrap() {
            ResolverSpec::Doh { ip, path, .. } => {
                assert_eq!(ip, "1.1.1.1".parse::<IpAddr>().unwrap());
                assert_eq!(path, "/dns-query");
            }
            other => panic!("expected DoH, got {other:?}"),
        }
        match ResolverSpec::parse("tls://9.9.9.9").unwrap() {
            ResolverSpec::Dot { ip, .. } => {
                assert_eq!(ip, "9.9.9.9".parse::<IpAddr>().unwrap())
            }
            other => panic!("expected DoT, got {other:?}"),
        }
    }

    #[test]
    fn doh_default_path() {
        match ResolverSpec::parse("https://1.1.1.1").unwrap() {
            ResolverSpec::Doh { path, .. } => assert_eq!(path, "/dns-query"),
            _ => panic!(),
        }
    }
}
