//! The per-listener forwarding data path.
//!
//! For each accepted connection:
//!
//! 1. Peek (non-consuming) to learn the routing key — TLS SNI or HTTP Host.
//! 2. Resolve it to a route (exact > wildcard > suffix > regex > default_route).
//! 3. `raw` splices the untouched TCP stream to the upstream. Every other type
//!    terminates inbound TLS (issuing a cert for the SNI via the dynamic CA
//!    resolver) and re-originates: `ech` over TLS 1.3 + Encrypted Client Hello
//!    (with retry), `tls` over plain TLS (optional override SNI), `http` as
//!    cleartext.
//! 4. No route and no default_route → apply the fail policy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rustls::client::EchStatus;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tracing::{debug, info, warn};

use crate::config::{AddressFamily, FailPolicy, RouteType};
use crate::dns::resolve_upstream;
use crate::ech::EchProvider;
use crate::nat64::Nat64Prefix;
use crate::peek::{classify, Inbound};
use crate::router::Router;

const COPY_BUF_SIZE: usize = 64 * 1024;

/// Everything a single route needs at runtime.
pub struct RouteRuntime {
    pub name: String,
    pub route_type: RouteType,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub override_sni: Option<String>,
    pub require_ech: bool,
    pub max_retries: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub address_family: AddressFamily,
    pub nat64: Option<Nat64Prefix>,
    pub fail: FailPolicy,
    /// DNS resolver for upstream A/AAAA.
    pub addr_resolver: Arc<hickory_resolver::TokioResolver>,
    /// ECH provider (only for `ech` routes).
    pub ech: Option<EchProvider>,
    /// Verified web-PKI roots for upstream TLS (`ech`/`tls`).
    pub root_store: Arc<rustls::RootCertStore>,
}

/// Immutable per-listener state shared with every connection task.
pub struct ListenerState {
    pub addr: SocketAddr,
    pub router: Router,
    pub routes: Vec<Arc<RouteRuntime>>,
    /// Server config whose cert resolver issues per-SNI certs from the CA.
    pub tls_server_config: Arc<ServerConfig>,
    /// Fail policy for connections matching no route and no default_route.
    pub unmatched: FailPolicy,
}

/// Bind and serve one listener until it errors unrecoverably.
pub async fn serve(state: Arc<ListenerState>) -> Result<()> {
    let listener = TcpListener::bind(state.addr)
        .await
        .with_context(|| format!("binding listener {}", state.addr))?;
    info!(addr = %state.addr, routes = state.routes.len(), "listening");

    loop {
        let (client, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                warn!(addr = %state.addr, error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatch(client, peer, &state).await {
                debug!(%peer, error = %format!("{e:#}"), "connection closed with error");
            }
        });
    }
}

async fn dispatch(client: TcpStream, peer: SocketAddr, state: &ListenerState) -> Result<()> {
    client.set_nodelay(true).ok();

    let inbound = classify(&client).await;
    let key = inbound.key();

    let route_id = match key {
        Some(k) => state.router.match_host(k),
        None => state.router.match_host(""),
    };

    let Some(id) = route_id else {
        return apply_fail(client, peer, &inbound, &state.unmatched, "unmatched").await;
    };
    let rt = &state.routes[id];

    // Effective inner/override name: explicit override_sni, else the inbound key.
    let sni = match rt.override_sni.as_deref() {
        Some(fixed) => Some(fixed.to_string()),
        None => key.map(strip_port),
    };

    debug!(%peer, route = %rt.name, key = key.unwrap_or("<none>"), tls = inbound.is_tls(), "routed");

    // raw: never terminate, never issue a cert — splice the untouched stream.
    if rt.route_type == RouteType::Raw {
        return raw_passthrough(client, peer, rt, &inbound).await;
    }

    // Everything else terminates inbound TLS (plaintext HTTP is spliced as-is).
    let result = if inbound.is_tls() {
        serve_terminated(client, peer, rt, state, sni).await
    } else {
        // Cleartext inbound: no TLS to terminate; forward per route type.
        serve_plaintext(client, peer, rt, sni).await
    };

    // On failure, honor the route's fail policy where it makes sense.
    if let Err(e) = result {
        debug!(%peer, route = %rt.name, error = %format!("{e:#}"), "route failed");
        return Err(e);
    }
    Ok(())
}

/// Terminate inbound TLS with the dynamic-cert server config, then re-originate.
async fn serve_terminated(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    state: &ListenerState,
    sni: Option<String>,
) -> Result<()> {
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client);
    let start = acceptor.await?;
    let tls = start.into_stream(state.tls_server_config.clone()).await?;
    forward(tls, peer, rt, sni).await
}

/// Forward a cleartext inbound connection (no inbound TLS).
async fn serve_plaintext(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    sni: Option<String>,
) -> Result<()> {
    forward(client, peer, rt, sni).await
}

/// Dial the upstream per route type and splice bytes.
async fn forward<S>(
    inbound: S,
    peer: SocketAddr,
    rt: &RouteRuntime,
    sni: Option<String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let upstream_addr = resolve_upstream(
        &rt.addr_resolver,
        &rt.upstream_host,
        rt.upstream_port,
        rt.address_family,
        rt.nat64.as_ref(),
    )
    .await
    .with_context(|| format!("resolving upstream {}", rt.upstream_host))?;

    match rt.route_type {
        RouteType::Http => {
            let up = dial(upstream_addr, rt.connect_timeout).await?;
            splice(inbound, up, rt.idle_timeout).await
        }
        RouteType::Tls => {
            let name = sni.clone().unwrap_or_else(|| rt.upstream_host.clone());
            let up = dial_tls(upstream_addr, &name, rt).await?;
            splice(inbound, up, rt.idle_timeout).await
        }
        RouteType::Ech => {
            let inner = sni.clone().ok_or_else(|| {
                anyhow!("ech route {} has no SNI/Host and no override_sni", rt.name)
            })?;
            let up = dial_ech(upstream_addr, &inner, peer, rt).await?;
            splice(inbound, up, rt.idle_timeout).await
        }
        RouteType::Raw => unreachable!("raw handled before termination"),
    }
}

/// Plain TCP dial with a timeout.
async fn dial(addr: SocketAddr, connect_timeout: Duration) -> Result<TcpStream> {
    let up = timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("upstream connect timed out"))?
        .with_context(|| format!("connecting to {addr}"))?;
    up.set_nodelay(true).ok();
    Ok(up)
}

/// Dial a plain-TLS upstream, verifying the presented `server_name`.
async fn dial_tls(
    addr: SocketAddr,
    server_name: &str,
    rt: &RouteRuntime,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = plain_tls_config(rt.root_store.clone());
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow!("invalid upstream SNI {server_name:?}"))?;
    let tcp = dial(addr, rt.connect_timeout).await?;
    let tls = timeout(rt.connect_timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| anyhow!("upstream TLS handshake timed out"))?
        .context("upstream TLS handshake")?;
    Ok(tls)
}

/// Dial an ECH upstream for `inner`, with retry on ECH rejection.
async fn dial_ech(
    addr: SocketAddr,
    inner: &str,
    peer: SocketAddr,
    rt: &RouteRuntime,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let ech = rt
        .ech
        .as_ref()
        .ok_or_else(|| anyhow!("ech route {} missing ECH provider", rt.name))?;

    let name = ServerName::try_from(inner.to_string())
        .map_err(|_| anyhow!("invalid inner SNI {inner:?}"))?;

    let mut attempt = 0u32;
    loop {
        let client = ech
            .client(inner)
            .await
            .context("assembling ECH client config")?;
        let connector = TlsConnector::from(client.client_config.clone());
        let tcp = dial(addr, rt.connect_timeout).await?;

        match timeout(rt.connect_timeout, connector.connect(name.clone(), tcp)).await {
            Ok(Ok(tls)) => {
                let status = tls.get_ref().1.ech_status();
                match (rt.require_ech, status) {
                    (true, EchStatus::Accepted) => {
                        debug!(%peer, route = %rt.name, "ECH accepted");
                        return Ok(tls);
                    }
                    (false, s) => {
                        debug!(%peer, route = %rt.name, status = ?s, "forwarding (ECH not required)");
                        return Ok(tls);
                    }
                    (true, s) => {
                        // ECH required but not accepted on a completed handshake.
                        return Err(anyhow!("ECH required but status was {s:?}"));
                    }
                }
            }
            Ok(Err(e)) if is_ech_reject(&e) && attempt < rt.max_retries => {
                attempt += 1;
                warn!(%peer, route = %rt.name, attempt, "ECH rejected; refreshing config and retrying");
                // Force a fresh ECHConfig fetch (server rotated keys; DNS/source
                // now carries the new one) before the next attempt.
                ech.invalidate(inner).await;
                continue;
            }
            Ok(Err(e)) => return Err(e).context("upstream ECH handshake"),
            Err(_) => return Err(anyhow!("upstream ECH handshake timed out")),
        }
    }
}

/// Whether an I/O error is rustls's "server rejected ECH" signal.
///
/// tokio-rustls surfaces rustls errors wrapped in `io::Error`; we downcast to
/// the typed `rustls::Error` and match the exact
/// `PeerIncompatible::ServerRejectedEncryptedClientHello` variant, rather than
/// matching on the Display string (which could false-positive on unrelated
/// errors that merely contain "ECH").
fn is_ech_reject(e: &std::io::Error) -> bool {
    matches!(
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_)
        ))
    )
}

/// Splice bytes bidirectionally, enforcing a true **idle** timeout: the clock
/// resets on every chunk in either direction, so long-lived but active
/// connections (WebSocket, streaming) are never cut — only genuinely idle ones.
/// `idle` of zero disables the timeout.
///
/// Both directions are driven to completion independently (a half-close in one
/// direction does not tear down the other), so request/response and duplex
/// protocols both work. The splice ends when both directions have closed, or
/// when the idle timeout fires, whichever comes first.
async fn splice<A, B>(a: A, b: B, idle: Duration) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let activity = Arc::new(tokio::sync::Notify::new());

    // Run both directions to completion; only the idle guard races them.
    let both = async {
        let a2b = pump_direction(&mut ar, &mut bw, &activity);
        let b2a = pump_direction(&mut br, &mut aw, &activity);
        let (r1, r2) = tokio::join!(a2b, b2a);
        r1.context("proxying data (c->u)")?;
        r2.context("proxying data (u->c)")?;
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        r = both => r,
        _ = idle_guard(&activity, idle) => Err(anyhow!("idle timeout")),
    }
}

/// Copy one direction, signaling `activity` on every chunk. On EOF it
/// half-closes the writer (so the peer sees the close) and returns, leaving the
/// other direction free to continue.
async fn pump_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    activity: &tokio::sync::Notify,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; COPY_BUF_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        activity.notify_one();
    }
}

/// Resolve only when no activity has been signaled for `idle`. Never resolves
/// when `idle` is zero (timeout disabled). `Notify` holds a single permit, so a
/// notification arriving between `.notified()` awaits is not lost — it is
/// consumed by the next await, correctly resetting the clock.
async fn idle_guard(activity: &tokio::sync::Notify, idle: Duration) {
    if idle.is_zero() {
        std::future::pending::<()>().await;
        return;
    }
    loop {
        match timeout(idle, activity.notified()).await {
            Ok(()) => continue, // activity: reset the idle clock
            Err(_) => return,   // no activity within `idle`: time out
        }
    }
}

/// Raw byte-pump passthrough (no termination, no cert). Because nothing is
/// consumed, the route's fail policy can still be applied if the upstream is
/// unreachable.
async fn raw_passthrough(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    inbound: &Inbound,
) -> Result<()> {
    let dialed = async {
        let upstream_addr = resolve_upstream(
            &rt.addr_resolver,
            &rt.upstream_host,
            rt.upstream_port,
            rt.address_family,
            rt.nat64.as_ref(),
        )
        .await?;
        dial(upstream_addr, rt.connect_timeout).await
    }
    .await;

    match dialed {
        Ok(up) => splice_tcp(client, up, rt.idle_timeout).await,
        Err(e) => {
            debug!(%peer, route = %rt.name, error = %format!("{e:#}"), "raw upstream failed; applying fail policy");
            apply_fail(client, peer, inbound, &rt.fail, "raw-fail").await
        }
    }
}

/// Raw TCP splice with the same true-idle-timeout semantics as [`splice`].
async fn splice_tcp(a: TcpStream, b: TcpStream, idle: Duration) -> Result<()> {
    splice(a, b, idle).await
}

/// Apply a fail/unmatched policy to a never-decrypted stream.
async fn apply_fail(
    client: TcpStream,
    peer: SocketAddr,
    inbound: &Inbound,
    policy: &FailPolicy,
    ctx: &str,
) -> Result<()> {
    match policy {
        FailPolicy::Close => {
            debug!(%peer, %ctx, "closing");
            Ok(())
        }
        FailPolicy::Passthrough { addr } => {
            let up = dial(*addr, Duration::from_secs(10)).await?;
            splice_tcp(client, up, Duration::from_secs(120)).await
        }
        FailPolicy::SystemOutbound => {
            let host = inbound
                .key()
                .ok_or_else(|| anyhow!("{ctx}: no SNI/Host for system-outbound"))?;
            let port = if inbound.is_tls() { 443 } else { 80 };
            let host = strip_port(host);
            let up = TcpStream::connect((host.as_str(), port)).await?;
            up.set_nodelay(true).ok();
            splice_tcp(client, up, Duration::from_secs(120)).await
        }
    }
}

/// Build a plain-TLS client config (TLS 1.2/1.3) trusting `roots`.
fn plain_tls_config(roots: Arc<rustls::RootCertStore>) -> ClientConfig {
    ClientConfig::builder()
        .with_root_certificates(roots.as_ref().clone())
        .with_no_client_auth()
}

/// Strip a trailing `:port` from a routing key, returning the bare host.
/// Handles `[v6]:port` (unwraps the brackets and drops the port), a bare DNS
/// name / IPv4 with a port, and a bare host with no port.
fn strip_port(host: &str) -> String {
    if let Some(rest) = host.strip_prefix('[') {
        // [v6] or [v6]:port — return the inner literal without brackets/port.
        if let Some((inner, _tail)) = rest.split_once(']') {
            return inner.to_string();
        }
        return rest.to_string();
    }
    // A bare IPv6 literal (multiple colons, no brackets) has no port to strip.
    if host.matches(':').count() > 1 {
        return host.to_string();
    }
    host.split(':').next().unwrap_or(host).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_port_forms() {
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("1.2.3.4:443"), "1.2.3.4");
        // Bracketed IPv6 with and without a port.
        assert_eq!(strip_port("[::1]:443"), "::1");
        assert_eq!(strip_port("[2a01:4f8::1]:443"), "2a01:4f8::1");
        assert_eq!(strip_port("[::1]"), "::1");
        // Bare IPv6 literal: nothing to strip.
        assert_eq!(strip_port("2a01:4f8::1"), "2a01:4f8::1");
    }

    // The half-close regression: after one direction reaches EOF, the other
    // must still deliver its full payload. Models a request/response where the
    // client half-closes its write side and then reads the response.
    #[tokio::test]
    async fn splice_survives_half_close_both_directions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Two in-memory duplex pipes act as the "client" and "upstream" ends.
        let (mut client, client_gate) = tokio::io::duplex(64 * 1024);
        let (mut upstream, upstream_gate) = tokio::io::duplex(64 * 1024);

        // splice() bridges the two gate ends.
        let spliced = tokio::spawn(async move {
            splice(client_gate, upstream_gate, Duration::from_secs(5)).await
        });

        let big = vec![0xABu8; 256 * 1024];
        let big_for_upstream = big.clone();

        // Upstream side: read the full request, then stream a large response.
        // Runs concurrently so the >buffer response doesn't deadlock.
        let upstream_task = tokio::spawn(async move {
            let mut got = Vec::new();
            upstream.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"REQUEST");
            upstream.write_all(&big_for_upstream).await.unwrap();
            upstream.shutdown().await.unwrap();
        });

        // Client sends a request, half-closes its write side, then reads the
        // response — which must arrive in full despite the half-close.
        client.write_all(b"REQUEST").await.unwrap();
        client.shutdown().await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp.len(), big.len(), "response truncated by half-close");
        assert_eq!(resp, big);

        upstream_task.await.unwrap();
        spliced.await.unwrap().unwrap();
    }

    #[test]
    fn ech_reject_detection_is_typed() {
        // A plain io::Error that merely mentions ECH must NOT be treated as a
        // rustls ECH rejection (the old string-match bug).
        let bogus = std::io::Error::other("connection to ECH-named-host failed");
        assert!(!is_ech_reject(&bogus));
        // The real signal is a downcastable rustls PeerIncompatible variant.
        let real = std::io::Error::other(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(None),
        ));
        assert!(is_ech_reject(&real));
    }
}
