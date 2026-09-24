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
//!
//! # HTTP/2
//!
//! Because step 3 *splices bytes* rather than parsing HTTP, the inbound and
//! upstream framing must be the same protocol — there is no h2↔h1 translation.
//! HTTP/2 is therefore a single coupled switch per route, and is negotiated two
//! different ways depending on whether the upstream speaks ALPN:
//!
//! * `tls` / `ech` — **ALPN mirroring**. The upstream is dialed *first*, offering
//!   the intersection of what the client offered and what the route allows;
//!   whatever it selects is then advertised verbatim on the inbound handshake.
//!   A protocol mismatch is structurally impossible, and falling back to
//!   HTTP/1.1 happens per connection against the live upstream rather than
//!   against a cached guess. See [`serve_mirrored`].
//! * `http` — the upstream is cleartext and has no ALPN, so the client's own
//!   preference decides. An h2 connection is spliced to the backend as
//!   prior-knowledge h2c (RFC 9113 §3.4), which is byte-identical to h2 over
//!   TLS. A startup probe (`src/probe.rs`) validates that the backend really
//!   speaks h2c, but never silently downgrades the route.

use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rustls::client::EchStatus;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::time::timeout;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tracing::{debug, info, warn};

use crate::config::{AddressFamily, FailPolicy, RouteType, SniPolicy};
use crate::dns::ResolvedAddrs;
use crate::ech::EchProvider;
use crate::nat64::Nat64Prefix;
use crate::peek::{classify, Inbound};
use crate::pool::PoolHandle;
use crate::resolver::{observed_dns_sans, DynamicResolver};
use crate::router::Router;
use crate::verify::UpstreamVerify;

const COPY_BUF_SIZE: usize = 64 * 1024;

/// Where a route's connections go, and what turns that into an address.
///
/// The two cases are settled by different machinery, so they carry different
/// data: a direct upstream is resolved per connection through this route's own
/// resolver, family and NAT64 prefix, while a pool has already resolved, probed
/// and ranked its endpoints and simply hands over the current best one.
pub enum Upstream {
    Direct {
        /// Fixed upstream host, or `None` to reflect the matched source SNI/Host
        /// (the port-stripped routing key) per connection.
        host: Option<String>,
        family: AddressFamily,
        nat64: Option<Nat64Prefix>,
        /// DNS resolver for upstream A/AAAA.
        resolver: Arc<crate::dns_resolvers::DnsResolver>,
    },
    /// A pool's current best endpoint for this route's view.
    Pool(PoolHandle),
}

impl Upstream {
    /// The host name for this connection: the dial target for a direct upstream,
    /// and in both cases the name an upstream certificate is verified against
    /// when no `override_sni` supplies one.
    ///
    /// `None` for a pool: a pool selects an *address*, and no hostname describes
    /// it. A `tls`/`ech` route over a pool therefore takes its verification name
    /// from the inbound SNI or from `override_sni`, never from the upstream.
    fn dial_host(&self, key: Option<&str>) -> Option<String> {
        match self {
            Upstream::Direct { host, .. } => match host.as_deref() {
                Some(fixed) => Some(fixed.to_string()),
                None => key.map(strip_port),
            },
            Upstream::Pool(_) => None,
        }
    }

    /// Where to dial on `port` — both address families when the upstream
    /// publishes both, for [`dial`] to race.
    async fn resolve(
        &self,
        port: u16,
        dial_host: Option<&str>,
        route: &str,
    ) -> Result<ResolvedAddrs> {
        match self {
            Upstream::Direct {
                family,
                nat64,
                resolver,
                ..
            } => {
                let host = dial_host.ok_or_else(|| {
                    anyhow!(
                        "route {route} reflects the source SNI/Host upstream, but the \
                         connection presented none"
                    )
                })?;
                resolver
                    .lookup_addr(host, port, *family, nat64.as_ref())
                    .await
                    .with_context(|| format!("resolving upstream {host}"))
            }
            // No I/O and no DNS: the probe task already decided. A failure here
            // means every candidate is degraded and no fallback is usable, which
            // the route's fail policy then handles.
            //
            // One address, deliberately: a pool has already ranked every
            // candidate across both families, so racing two of them here would
            // second-guess that ranking with a measurement it cannot see.
            Upstream::Pool(handle) => handle
                .pick(port)
                .map(ResolvedAddrs::single)
                .with_context(|| format!("route {route}: selecting a pool endpoint")),
        }
    }
}

/// Everything a single route needs at runtime.
pub struct RouteRuntime {
    pub name: String,
    pub route_type: RouteType,
    pub upstream: Upstream,
    pub upstream_port: u16,
    /// What SNI to present upstream: reflect the inbound name, force a fixed
    /// one, or send no `server_name` extension at all.
    pub sni_policy: SniPolicy,
    /// Allow HTTP/2 on this route. Always false for `raw`.
    pub http2: bool,
    pub require_ech: bool,
    pub max_retries: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub fail: FailPolicy,
    /// ECH provider (only for `ech` routes).
    pub ech: Option<EchProvider>,
    /// How this route verifies the upstream certificate. `None` for `http` and
    /// `raw`, which originate no TLS and so have nothing to verify.
    ///
    /// Installed in the prebuilt configs below, and in [`EchProvider`]'s own for
    /// an `ech` route, so the handshake needs nothing from here. The handle is
    /// kept for the one decision outside the handshake: what name to open a
    /// connection with when the route transmits none and the connection supplied
    /// none ([`silent_name_override`]).
    pub verify: Option<Arc<UpstreamVerify>>,
    /// Prebuilt upstream client configs, one per ALPN offer (`tls` routes only).
    pub tls: Option<ClientConfigs>,
}

/// The upstream `ClientConfig`s for a `tls` route, one per ALPN offer the data
/// path can produce.
///
/// [`negotiable_alpn`] narrows every client offer to a subsequence of
/// [`SUPPORTED_ALPN`], so exactly four offers exist. Building them once at
/// startup keeps the per-connection cost to an `Arc` clone, and — unlike a
/// config built per connection — lets rustls's client session store actually
/// resume upstream sessions, since that store lives in the config.
pub struct ClientConfigs {
    /// No ALPN extension at all — the client offered none we can carry.
    none: Arc<ClientConfig>,
    /// `["http/1.1"]`.
    h1: Arc<ClientConfig>,
    /// `["h2"]`.
    h2: Arc<ClientConfig>,
    /// `["h2", "http/1.1"]`, h2 preferred.
    h2h1: Arc<ClientConfig>,
}

impl ClientConfigs {
    /// Build the four variants under one verification policy.
    ///
    /// `enable_sni` is false for a route with `override_sni = ""`: the
    /// certificate is still verified, only the extension is withheld.
    pub fn new(verify: &UpstreamVerify, enable_sni: bool) -> Self {
        let build = |alpn: &[&[u8]]| {
            let mut cfg = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verify.verifier())
                .with_no_client_auth();
            cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
            cfg.enable_sni = enable_sni;
            Arc::new(cfg)
        };
        Self {
            none: build(&[]),
            h1: build(&[b"http/1.1"]),
            h2: build(&[b"h2"]),
            h2h1: build(&[b"h2", b"http/1.1"]),
        }
    }

    /// The config advertising exactly `offer`.
    ///
    /// Total by construction: `offer` only ever holds protocols from
    /// [`SUPPORTED_ALPN`]. An offer naming neither means "no extension", which
    /// is also what an empty offer means.
    fn select(&self, offer: &[Vec<u8>]) -> &Arc<ClientConfig> {
        let offered = |p: &[u8]| offer.iter().any(|o| o.as_slice() == p);
        match (offered(b"h2"), offered(b"http/1.1")) {
            (true, true) => &self.h2h1,
            (true, false) => &self.h2,
            (false, true) => &self.h1,
            (false, false) => &self.none,
        }
    }
}

/// The inbound `ServerConfig`s, which differ *only* in the ALPN protocols they
/// advertise. All share one cert resolver (issuing per-SNI certs from the CA),
/// one ticketer and one session cache.
///
/// Sharing resumption state across them is safe: rustls warns that configs
/// sharing a ticketer/session store should have equivalent `verifier` and
/// `cert_resolver` (a session originated under one must not be resumed under a
/// weaker one) — and here those are literally the same objects. Only
/// `alpn_protocols` differs, which does not affect session security.
///
/// Pre-building the handful of variants at startup keeps the per-connection cost
/// to an `Arc` clone; the alternative (cloning and mutating a `ServerConfig` per
/// connection) would copy the whole config on every handshake.
pub struct ServerConfigs {
    /// No ALPN extension at all — used when the client offered none.
    pub none: Arc<ServerConfig>,
    /// `["http/1.1"]`. The default for every route without HTTP/2 enabled.
    pub h1: Arc<ServerConfig>,
    /// `["h2"]` — the upstream selected HTTP/2, so we mirror exactly that.
    pub h2: Arc<ServerConfig>,
    /// `["h2", "http/1.1"]`, h2 preferred. Used by `http` routes, where there is
    /// no upstream ALPN to mirror and the client's preference decides.
    pub h2h1: Arc<ServerConfig>,
}

/// Immutable per-listener state shared with every connection task.
pub struct ListenerState {
    pub addr: SocketAddr,
    /// Shared with this listener's certificate resolver, which routes each
    /// ClientHello's SNI to decide what the certificate may cover.
    pub router: Arc<Router>,
    pub routes: Vec<Arc<RouteRuntime>>,
    /// Inbound server configs, selected per connection by negotiated ALPN.
    pub server_configs: Arc<ServerConfigs>,
    /// Fail policy for connections matching no route and no default_route.
    pub unmatched: FailPolicy,
    /// This listener's certificate resolver. The data path reports each
    /// upstream's real certificate SANs back to it, which is what lets issued
    /// certificates mirror the coverage the upstream actually grants instead of
    /// guessing at it (see [`crate::resolver`]).
    pub cert_resolver: Arc<DynamicResolver>,
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

    // Effective inner/override name. This is the name the upstream certificate
    // is verified against, so `Omit` still resolves one (the inbound key) — the
    // policy only decides whether it is *transmitted* as an SNI extension.
    let sni = match &rt.sni_policy {
        SniPolicy::Fixed(fixed) => Some(fixed.clone()),
        SniPolicy::Reflect | SniPolicy::Omit => key.map(strip_port),
    };

    // Effective dial host: the fixed upstream host, else the matched source
    // SNI/Host (port-stripped). `None` here means either the route reflects but
    // the connection carried no SNI/Host, or the upstream is a pool (which picks
    // an address, not a name) — both handled at dial time per route type.
    let dial_host = rt.upstream.dial_host(key);

    debug!(%peer, route = %rt.name, key = key.unwrap_or("<none>"), tls = inbound.is_tls(), "routed");

    // raw: never terminate, never issue a cert — splice the untouched stream.
    if rt.route_type == RouteType::Raw {
        return raw_passthrough(client, peer, rt, &inbound, dial_host).await;
    }

    // Everything else terminates inbound TLS (plaintext HTTP is spliced as-is).
    let result = if inbound.is_tls() {
        // With HTTP/2 allowed on a TLS-upstream route we must know what the
        // upstream negotiates before answering the client, which inverts the
        // usual order (upstream first, then inbound handshake). Every other case
        // keeps the original ordering and the plain http/1.1 config.
        let mirror = rt.http2 && matches!(rt.route_type, RouteType::Tls | RouteType::Ech);
        if mirror {
            serve_mirrored(client, peer, rt, state, sni, dial_host).await
        } else {
            serve_terminated(client, peer, rt, state, sni, dial_host).await
        }
    } else {
        // Cleartext inbound: no TLS to terminate; forward per route type.
        serve_plaintext(client, peer, rt, state, sni, dial_host).await
    };

    // On failure, honor the route's fail policy where it makes sense.
    if let Err(e) = result {
        debug!(%peer, route = %rt.name, error = %format!("{e:#}"), "route failed");
        return Err(e);
    }
    Ok(())
}

/// The ALPN protocols this gateway can carry, most preferred first. Anything
/// else the client offers is ignored: we can only splice a protocol whose
/// framing we pass through unchanged, and these are the two that matter.
const SUPPORTED_ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Narrow a client's ALPN offer to what this gateway can splice, ordered by our
/// own preference (h2 first) so the upstream always sees a stable offer.
///
/// An empty result means "send no ALPN extension upstream" — either the client
/// offered none, or it offered only protocols we cannot carry.
fn negotiable_alpn(client_offer: Option<Vec<&[u8]>>) -> Vec<Vec<u8>> {
    let Some(offered) = client_offer else {
        return Vec::new();
    };
    SUPPORTED_ALPN
        .iter()
        .filter(|ours| offered.iter().any(|theirs| theirs == *ours))
        .map(|p| p.to_vec())
        .collect()
}

/// Which inbound ALPN to advertise, given what the upstream selected and what
/// the client originally offered. This is the mirroring rule.
fn mirror_choice<'a>(
    configs: &'a ServerConfigs,
    upstream_selected: Option<&[u8]>,
    client_offered_any: bool,
) -> &'a Arc<ServerConfig> {
    match upstream_selected {
        Some(b"h2") => &configs.h2,
        Some(b"http/1.1") => &configs.h1,
        // The upstream named nothing. With no client offer either, answer
        // without an ALPN extension. If the client did offer, it must have been
        // something the upstream declined to name, so settle on HTTP/1.1 — the
        // implicit default both ends already understand.
        _ if !client_offered_any => &configs.none,
        _ => &configs.h1,
    }
}

/// Report the upstream's real certificate SANs to this listener's resolver, so
/// the certificate *this* gateway serves for `sni` mirrors the coverage the
/// upstream actually grants.
///
/// # Why this is on the data path
///
/// The upstream's certificate is the only authority on which names it will answer
/// for over one connection. A gateway that invents a wildcard the upstream does
/// not back lets a browser coalesce a second origin onto the connection
/// (RFC 9113 §9.1.1); the upstream then sees an `:authority` outside what its own
/// handshake authorized and rejects it — the 403 this mechanism exists to remove.
/// The certificate resolver runs inside the *inbound* handshake and cannot dial
/// anywhere, so the observation has to arrive from here, where the upstream
/// handshake actually completes.
///
/// # Why it does not block
///
/// The connection in hand is already served: its certificate was issued before
/// the client's ClientHello was answered. What mirroring affects is the client's
/// **next** connection — the one it could coalesce onto — so there is nothing to
/// wait for. The common case is an upstream whose certificate has not changed, so
/// that case is settled inline with a cache lookup and a slice comparison
/// ([`DynamicResolver::mirror_is_current`]); only a genuine change reaches the
/// blocking pool, where a signature and two file writes are allowed to take their
/// time.
fn record_upstream_coverage(
    state: &ListenerState,
    rt: &RouteRuntime,
    sni: Option<&String>,
    session: &rustls::ClientConnection,
) {
    // Only a reflecting route asks the upstream about the very name this
    // certificate is for. A fixed `override_sni` asks every upstream for the
    // same name, and `override_sni = ""` asks for none at all and is answered
    // with the upstream's *default* certificate — in both cases the reply says
    // nothing about the inbound name, so mirroring it would attach one
    // upstream's coverage to every name routed here.
    //
    // What the reply had to *prove* is the route's `[verify]` policy, and that
    // is not consulted here: the policy is part of the certificate scope
    // ([`crate::certscope`]), so coverage learned under a weakened one is
    // already confined to names held to the same policy.
    if rt.sni_policy != SniPolicy::Reflect {
        return;
    }
    let Some(sni) = sni else { return };
    let Some(chain) = session.peer_certificates() else {
        return;
    };

    let observed = observed_dns_sans(chain);
    if state.cert_resolver.mirror_is_current(sni, &observed) {
        return;
    }

    let resolver = state.cert_resolver.clone();
    let host = sni.clone();
    let route = rt.name.clone();
    // Detached: the certificate it produces is for a future connection, and the
    // current one must not wait on a signature.
    tokio::task::spawn_blocking(move || {
        debug!(route = %route, host = %host, sans = ?observed, "observed upstream certificate");
        resolver.record_upstream_sans(&host, &observed);
    });
}

/// Terminate inbound TLS with the dynamic-cert server config, then re-originate.
///
/// The original ordering: the inbound handshake completes first, then the
/// upstream is dialed. Used whenever HTTP/2 is not in play, so the default path
/// is unchanged — `http/1.1` is advertised and no extra work is done.
async fn serve_terminated(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    state: &ListenerState,
    sni: Option<String>,
    dial_host: Option<String>,
) -> Result<()> {
    // `http` routes with HTTP/2 enabled offer both protocols and let the client
    // choose: the cleartext upstream has no ALPN of its own to mirror, and an h2
    // stream is spliced onward as prior-knowledge h2c.
    let config = if rt.http2 && rt.route_type == RouteType::Http {
        state.server_configs.h2h1.clone()
    } else {
        state.server_configs.h1.clone()
    };
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client);
    let start = acceptor.await?;
    let tls = start.into_stream(config).await?;
    if let Some(p) = tls.get_ref().1.alpn_protocol() {
        debug!(%peer, route = %rt.name, alpn = %String::from_utf8_lossy(p), "inbound ALPN");
    }
    forward(tls, peer, rt, state, sni, dial_host).await
}

/// Terminate inbound TLS **after** dialing the upstream, advertising exactly the
/// protocol the upstream selected. Used for `tls`/`ech` routes with HTTP/2
/// enabled.
///
/// Ordering matters here. We read the client's ALPN offer from the ClientHello
/// without committing to a `ServerConfig`, dial the upstream with the subset of
/// that offer we support, observe what it actually chose, and only then finish
/// the inbound handshake announcing that same protocol. The two sides therefore
/// cannot disagree, and an upstream that only speaks HTTP/1.1 transparently
/// downgrades this connection without any configuration or cached probe result.
///
/// Two consequences of the inversion, both deliberate:
///
/// * The upstream is dialed slightly earlier in the connection's life than on
///   the default path (before the inbound handshake rather than after).
/// * If the upstream dial fails we hold a `StartHandshake`, whose ClientHello
///   bytes have already been consumed by the acceptor — so the stream can no
///   longer be spliced elsewhere and a `passthrough` fail policy is not
///   applicable. This is not a regression: terminating routes never applied a
///   fail policy (it is reached only for unmatched connections and `raw`
///   upstream failures), and the observable result — the connection is dropped
///   and the error logged — is exactly what the default path already does when
///   its upstream is unreachable.
async fn serve_mirrored(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    state: &ListenerState,
    sni: Option<String>,
    dial_host: Option<String>,
) -> Result<()> {
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client);
    let start = acceptor.await?;

    // What the client is willing to speak, narrowed to what we can splice.
    let client_offer = negotiable_alpn(start.client_hello().alpn().map(Iterator::collect));

    let upstream_addrs = rt
        .upstream
        .resolve(rt.upstream_port, dial_host.as_deref(), &rt.name)
        .await?;

    // Dial first, so the upstream's choice can drive the inbound handshake.
    let up = match rt.route_type {
        RouteType::Tls => {
            let name = tls_verification_name(rt, &sni, dial_host.as_deref())?;
            dial_tls(upstream_addrs, &name, rt, &client_offer).await?
        }
        RouteType::Ech => {
            let inner = ech_inner_name(rt, &sni)?;
            dial_ech(upstream_addrs, &inner, peer, rt, &client_offer).await?
        }
        RouteType::Http | RouteType::Raw => {
            unreachable!("mirroring only applies to tls/ech routes")
        }
    };

    let selected = up.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);

    // The upstream handshake is complete: learn what its certificate really
    // covers before this connection is spliced away. On this path it matters
    // most — HTTP/2 is on, so coalescing is exactly what the client may do next.
    record_upstream_coverage(state, rt, sni.as_ref(), up.get_ref().1);

    let config = mirror_choice(
        &state.server_configs,
        selected.as_deref(),
        !client_offer.is_empty(),
    )
    .clone();
    debug!(
        %peer,
        route = %rt.name,
        upstream_alpn = %selected.as_deref().map_or("<none>".into(), |p| String::from_utf8_lossy(p).into_owned()),
        "mirroring upstream ALPN to the client"
    );

    let tls = start.into_stream(config).await?;

    let observer = transfer_observer(rt, up.get_ref().0.peer_addr().ok());
    splice(tls, up, rt.idle_timeout, observer).await
}

/// Forward a cleartext inbound connection (no inbound TLS).
async fn serve_plaintext(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    state: &ListenerState,
    sni: Option<String>,
    dial_host: Option<String>,
) -> Result<()> {
    forward(client, peer, rt, state, sni, dial_host).await
}

/// Dial the upstream per route type and splice bytes.
async fn forward<S>(
    inbound: S,
    peer: SocketAddr,
    rt: &RouteRuntime,
    state: &ListenerState,
    sni: Option<String>,
    dial_host: Option<String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let upstream_addrs = rt
        .upstream
        .resolve(rt.upstream_port, dial_host.as_deref(), &rt.name)
        .await?;

    match rt.route_type {
        RouteType::Http => {
            let up = dial(upstream_addrs, rt.connect_timeout).await?;
            let observer = transfer_observer(rt, up.peer_addr().ok());
            splice(inbound, up, rt.idle_timeout, observer).await
        }
        // These arms are only reached on the non-mirrored path (HTTP/2 disabled),
        // where inbound was negotiated as http/1.1 — so offer nothing upstream
        // and let it default to HTTP/1.1 too, exactly as before.
        RouteType::Tls => {
            let name = tls_verification_name(rt, &sni, dial_host.as_deref())?;
            let up = dial_tls(upstream_addrs, &name, rt, &[]).await?;
            // HTTP/2 is off for this connection, so it cannot coalesce — but a
            // later connection for the same name can, and this is a free look at
            // what the upstream's certificate covers.
            record_upstream_coverage(state, rt, sni.as_ref(), up.get_ref().1);
            let observer = transfer_observer(rt, up.get_ref().0.peer_addr().ok());
            splice(inbound, up, rt.idle_timeout, observer).await
        }
        RouteType::Ech => {
            let inner = ech_inner_name(rt, &sni)?;
            let up = dial_ech(upstream_addrs, &inner, peer, rt, &[]).await?;
            record_upstream_coverage(state, rt, sni.as_ref(), up.get_ref().1);
            let observer = transfer_observer(rt, up.get_ref().0.peer_addr().ok());
            splice(inbound, up, rt.idle_timeout, observer).await
        }
        RouteType::Raw => unreachable!("raw handled before termination"),
    }
}

/// The name a `tls` route verifies the upstream certificate against.
///
/// Order: the route's effective SNI (a fixed `override_sni`, or the reflected
/// inbound name), else the dial host. A direct upstream always has one of the
/// two, so this only fails for a pool — which selects an *address*, and no
/// hostname describes it — on a connection that carried no SNI/Host and whose
/// route pins no name.
///
/// That case is an error rather than a fallback to the address, because the only
/// certificate an IP-named verification could accept is one with an IP SAN, which
/// no CDN edge serves. Reporting it names the fix (`override_sni`) instead of
/// failing later inside the handshake with a name-mismatch nobody can act on.
///
/// Suppressing SNI changes what is *transmitted*, not what is *trusted*: the
/// name returned here is still handed to the handshake. What the upstream
/// certificate must prove about it is the route's `[verify]` policy.
fn tls_verification_name(
    rt: &RouteRuntime,
    sni: &Option<String>,
    dial_host: Option<&str>,
) -> Result<String> {
    if let Some(name) = sni {
        return Ok(name.clone());
    }
    if let Some(host) = dial_host {
        return Ok(host.to_string());
    }
    if let Some(fixed) = silent_name_override(rt) {
        return Ok(fixed.to_string());
    }
    Err(anyhow!(
        "tls route {}: no name to verify the upstream certificate against — the \
         connection carried no SNI/Host, and an upstream pool selects an address \
         rather than a name. Set `override_sni` on this route",
        rt.name
    ))
}

/// The inner name an `ech` route puts in the encrypted ClientHello.
///
/// Required even when it will not be *sent* in the clear: it is the name the
/// handshake requests of the upstream, and by default the name its certificate
/// must be valid for.
fn ech_inner_name(rt: &RouteRuntime, sni: &Option<String>) -> Result<String> {
    if let Some(name) = sni {
        return Ok(name.clone());
    }
    if let Some(fixed) = silent_name_override(rt) {
        return Ok(fixed.to_string());
    }
    Err(anyhow!(
        "ech route {}: the connection carried no SNI/Host to use as the inner \
         name, and no override_sni supplies one",
        rt.name
    ))
}

/// `verify.name` as a *last* source for the name to open a connection with, but
/// only on a route that transmits no name at all.
///
/// rustls needs some `ServerName` to dial with, and under a `name` override that
/// value decides nothing that is checked — so on an `override_sni = ""` route,
/// where it is never put on the wire, reusing it is free and saves an otherwise
/// unserviceable connection.
///
/// Deliberately not offered to the other SNI policies. This gateway keeps three
/// things apart — who we dial, what name we transmit, and what name we trust
/// (see [`crate::verify`]) — and a route that *does* transmit its name would be
/// having the third silently decide the second. `override_sni` is the field that
/// owns what goes on the wire, and the error above says so.
fn silent_name_override(rt: &RouteRuntime) -> Option<&str> {
    if rt.sni_policy != SniPolicy::Omit {
        return None;
    }
    rt.verify.as_ref()?.name_override()
}

/// RFC 8305 §5 "Connection Attempt Delay": how long the first address family
/// gets to itself before the second starts alongside it.
///
/// The RFC's recommended value. What matters is that it is far shorter than a
/// TCP SYN timeout, so a family whose packets are silently dropped costs this
/// much instead of the whole connect budget.
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Plain TCP dial, bounded as a whole by `connect_timeout`.
///
/// With two address families available this is a Happy Eyeballs race (RFC 8305)
/// rather than a try-then-fall-back: the primary gets [`ATTEMPT_DELAY`] alone,
/// then the alternative starts in parallel and the first connection to complete
/// wins. Racing is what covers the failure that actually matters — a host with
/// no working IPv6 route usually *blackholes* the SYN rather than refusing it,
/// so there is no error to trigger a fallback on and an error-driven one would
/// sit out the entire timeout before trying the address that would have worked.
///
/// `connect_timeout` bounds the race, not each attempt, so a route's configured
/// budget stays its real worst case.
async fn dial(addrs: ResolvedAddrs, connect_timeout: Duration) -> Result<TcpStream> {
    let stream = match addrs.fallback {
        None => timeout(connect_timeout, TcpStream::connect(addrs.primary))
            .await
            .map_err(|_| anyhow!("upstream connect to {} timed out", addrs.primary))?
            .with_context(|| format!("connecting to {}", addrs.primary))?,
        Some(fallback) => {
            let race = race_families(addrs.primary, fallback);
            timeout(connect_timeout, race).await.map_err(|_| {
                anyhow!(
                    "upstream connect timed out (raced {} and {fallback})",
                    addrs.primary
                )
            })??
        }
    };
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// Race two addresses of the same upstream and return the first socket to
/// connect, per RFC 8305.
///
/// Deliberately unbounded in time: the caller owns the budget, and applying one
/// here as well would make the two attempts cost twice what the route asked for.
/// The loser's in-flight connect is cancelled by dropping its future.
async fn race_families(primary: SocketAddr, fallback: SocketAddr) -> Result<TcpStream> {
    let mut primary_fut = pin!(TcpStream::connect(primary));

    // The head start. A primary that fails inside it does not get to hold the
    // alternative back for the remainder — the delay bounds how long we wait on
    // silence, not on an answer.
    let mut primary_err = {
        let delay = pin!(tokio::time::sleep(ATTEMPT_DELAY));
        tokio::select! {
            biased;
            r = &mut primary_fut => match r {
                Ok(stream) => return Ok(stream),
                Err(e) => Some(e),
            },
            () = delay => None,
        }
    };

    // `primary_err` distinguishes the two ways the head start can end, and they
    // mean different things to whoever reads this: an error is a host with no
    // route to that family, silence is a path that drops packets.
    debug!(
        %primary,
        %fallback,
        ?primary_err,
        "primary did not connect first; racing the second address family"
    );
    let mut fallback_fut = pin!(TcpStream::connect(fallback));
    let mut fallback_err: Option<std::io::Error> = None;

    loop {
        if let (Some(pe), Some(fe)) = (&primary_err, &fallback_err) {
            return Err(anyhow!(
                "connecting to {primary} ({pe}) and {fallback} ({fe})"
            ));
        }
        // `biased` keeps the primary family preferred when both are ready in the
        // same poll, which is the tie-break RFC 6724 already made at resolution.
        // Each arm is disabled once its future has completed, so neither is
        // polled after returning `Ready`.
        tokio::select! {
            biased;
            r = &mut primary_fut, if primary_err.is_none() => match r {
                Ok(stream) => return Ok(stream),
                Err(e) => primary_err = Some(e),
            },
            r = &mut fallback_fut, if fallback_err.is_none() => match r {
                Ok(stream) => return Ok(stream),
                Err(e) => fallback_err = Some(e),
            },
        }
    }
}

/// Dial a plain-TLS upstream, verifying the presented `server_name` and offering
/// `alpn` (empty = no ALPN extension).
///
/// `server_name` is the name the handshake requests. Whether it is **sent** as
/// an SNI extension depends on the route's [`SniPolicy`] (`Omit` clears
/// `enable_sni` on every prebuilt config), and what the certificate must prove
/// about it depends on the route's `[verify]` policy — by default that it is
/// valid for exactly this name under the web PKI.
async fn dial_tls(
    addrs: ResolvedAddrs,
    server_name: &str,
    rt: &RouteRuntime,
    alpn: &[Vec<u8>],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let configs = rt
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("tls route {} missing its upstream TLS configs", rt.name))?;
    let connector = TlsConnector::from(configs.select(alpn).clone());
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow!("invalid upstream SNI {server_name:?}"))?;
    let tcp = dial(addrs, rt.connect_timeout).await?;
    let tls = timeout(rt.connect_timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| anyhow!("upstream TLS handshake timed out"))?
        .context("upstream TLS handshake")?;
    Ok(tls)
}

/// Dial an ECH upstream for `inner` offering `alpn`, with retry on ECH rejection.
async fn dial_ech(
    addrs: ResolvedAddrs,
    inner: &str,
    peer: SocketAddr,
    rt: &RouteRuntime,
    alpn: &[Vec<u8>],
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
            .client(inner, alpn)
            .await
            .context("assembling ECH client config")?;
        let generation = client.generation;
        let connector = TlsConnector::from(client.client_config.clone());
        let tcp = dial(addrs, rt.connect_timeout).await?;

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
                ech.invalidate_after_rejection(inner, generation).await;
                continue;
            }
            Ok(Err(e)) => return Err(e).context("upstream ECH handshake"),
            Err(_) => return Err(anyhow!("upstream ECH handshake timed out")),
        }
    }
}

/// Whether an I/O error is rustls's "server rejected ECH" signal.
///
/// Delegates to [`crate::ech::is_ech_reject_io`]. A resolver's own handshake
/// needs the identical verdict, so the predicate lives in `ech` and both paths
/// call it rather than each carrying a copy that could drift.
fn is_ech_reject(e: &std::io::Error) -> bool {
    crate::ech::is_ech_reject_io(e)
}

struct Report<'a> {
    observer: Option<(&'a PoolHandle, IpAddr)>,
    started: Instant,
    upload: u64,
    download: u64,
}

impl Drop for Report<'_> {
    fn drop(&mut self) {
        let Some((pool, addr)) = self.observer else {
            return;
        };
        let bytes = self.upload.saturating_add(self.download);
        if bytes == 0 {
            return;
        }
        // TCP EOF says nothing about application-level completion. Keep the
        // entire forwarding lifetime for every exit, including normal EOF,
        // so a missing or truncated response cannot hide its waiting time.
        let elapsed = self.started.elapsed().max(Duration::from_nanos(1));
        pool.observe_transfer(addr, bytes, elapsed);
    }
}

pub(super) async fn splice<A, B>(
    a: A,
    b: B,
    idle: Duration,
    observer: Option<(&PoolHandle, IpAddr)>,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let activity = Notify::new();
    let mut report = Report {
        observer,
        started: Instant::now(),
        upload: 0,
        download: 0,
    };
    let tracked = report.observer.is_some();
    let both = async {
        let a2b = async {
            pump(&mut ar, &mut bw, &activity, &mut report.upload, tracked)
                .await
                .context("proxying data (c->u)")
        };
        let b2a = async {
            pump(&mut br, &mut aw, &activity, &mut report.download, tracked)
                .await
                .context("proxying data (u->c)")
        };
        // EOF in one direction still allows the other to finish. An I/O error
        // ends the splice immediately, including when idle timeout is disabled.
        tokio::try_join!(a2b, b2a)?;
        Ok(())
    };
    tokio::select! {
        result = both => result,
        _ = idle_guard(&activity, idle) => Err(anyhow!("idle timeout")),
    }
}

async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    activity: &Notify,
    bytes: &mut u64,
    tracked: bool,
) -> Result<()> {
    let mut buf = vec![0u8; COPY_BUF_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let mut sent = 0;
        while sent < n {
            let written = writer.write(&buf[sent..n]).await?;
            if written == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
            }
            if tracked {
                *bytes = bytes.saturating_add(written as u64);
            }
            sent += written;
            activity.notify_one();
        }
    }
}

async fn idle_guard(activity: &Notify, idle: Duration) {
    if idle.is_zero() {
        std::future::pending::<()>().await;
    }
    while timeout(idle, activity.notified()).await.is_ok() {}
}

/// Observation is opt-in, avoiding per-write counters and clock reads when disabled.
fn transfer_observer(
    rt: &RouteRuntime,
    addr: Option<SocketAddr>,
) -> Option<(&PoolHandle, std::net::IpAddr)> {
    let Upstream::Pool(handle) = &rt.upstream else {
        return None;
    };
    if !handle.observes_transfers() {
        return None;
    }
    Some((handle, addr?.ip()))
}

/// Raw byte-pump passthrough (no termination, no cert). Because nothing is
/// consumed, the route's fail policy can still be applied if the upstream is
/// unreachable.
async fn raw_passthrough(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    inbound: &Inbound,
    dial_host: Option<String>,
) -> Result<()> {
    let dialed = async {
        let upstream_addrs = rt
            .upstream
            .resolve(rt.upstream_port, dial_host.as_deref(), &rt.name)
            .await?;
        dial(upstream_addrs, rt.connect_timeout).await
    }
    .await;

    match dialed {
        Ok(up) => {
            let observer = transfer_observer(rt, up.peer_addr().ok());
            splice(client, up, rt.idle_timeout, observer).await
        }
        Err(e) => {
            debug!(%peer, route = %rt.name, error = %format!("{e:#}"), "raw upstream failed; applying fail policy");
            apply_fail(client, peer, inbound, &rt.fail, "raw-fail").await
        }
    }
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
            let up = dial(ResolvedAddrs::single(*addr), Duration::from_secs(10)).await?;
            splice(client, up, Duration::from_secs(120), None).await
        }
        FailPolicy::SystemOutbound => {
            let host = inbound
                .key()
                .ok_or_else(|| anyhow!("{ctx}: no SNI/Host for system-outbound"))?;
            let port = if inbound.is_tls() { 443 } else { 80 };
            let host = strip_port(host);
            let up = TcpStream::connect((host.as_str(), port)).await?;
            up.set_nodelay(true).ok();
            splice(client, up, Duration::from_secs(120), None).await
        }
    }
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
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use tokio::io::ReadBuf;

    /// A listening socket plus its address. Held by the caller so the port
    /// stays bound for the duration of a test.
    async fn listening() -> (tokio::net::TcpListener, SocketAddr) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        (l, addr)
    }

    /// An address nothing is listening on: bound to learn a free port, then
    /// released. Connecting to it either is refused outright or — on hosts that
    /// drop the SYN instead — hangs, and the race must handle both.
    fn dead_addr() -> SocketAddr {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    }

    /// Both addresses reachable: the primary gets a head start and must win, so
    /// a healthy dual-stack upstream keeps its RFC 6724 family preference
    /// instead of drifting to whichever socket happened to be faster.
    #[tokio::test]
    async fn the_race_prefers_the_primary_when_both_connect() {
        let (_p, primary) = listening().await;
        let (_f, fallback) = listening().await;

        let up = race_families(primary, fallback).await.unwrap();
        assert_eq!(up.peer_addr().unwrap(), primary);
    }

    /// The whole point: a primary that cannot be connected to must not sink the
    /// dial when a second family is available. Covers both shapes of a broken
    /// path — an immediate refusal, and a SYN that goes unanswered until the
    /// attempt delay hands over.
    #[tokio::test]
    async fn the_race_wins_on_the_fallback_when_the_primary_is_dead() {
        let primary = dead_addr();
        let (_f, fallback) = listening().await;

        let up = race_families(primary, fallback).await.unwrap();
        assert_eq!(up.peer_addr().unwrap(), fallback);
    }

    /// Neither address usable: the error has to name both, because "connection
    /// refused" against one address of two does not tell an operator which leg
    /// of a dual-stack upstream to go fix.
    #[tokio::test]
    async fn a_failed_race_reports_both_addresses() {
        let primary = dead_addr();
        let fallback = dead_addr();

        // Built by hand rather than via `dual`: the families are irrelevant
        // here, only that there are two addresses and neither answers.
        let addrs = ResolvedAddrs {
            primary,
            fallback: Some(fallback),
        };
        let err = dial(addrs, Duration::from_millis(600)).await.unwrap_err();

        // Either both connects were refused or the budget expired first; both
        // reports are required to carry both addresses.
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains(&primary.to_string()) && rendered.contains(&fallback.to_string()),
            "error names only one leg: {rendered}"
        );
    }

    /// A single address keeps the plain path — no race, and the error still
    /// says where it was trying to go.
    #[tokio::test]
    async fn a_single_address_dials_directly() {
        let (_l, addr) = listening().await;
        let up = dial(ResolvedAddrs::single(addr), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(up.peer_addr().unwrap(), addr);

        let dead = dead_addr();
        let err = dial(ResolvedAddrs::single(dead), Duration::from_millis(600))
            .await
            .unwrap_err();
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains(&dead.to_string()),
            "error does not name the address: {rendered}"
        );
    }

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
            splice(client_gate, upstream_gate, Duration::from_secs(5), None).await
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
    fn negotiable_alpn_filters_and_reorders() {
        fn v<'a>(s: &[&'a str]) -> Option<Vec<&'a [u8]>> {
            Some(s.iter().map(|x| x.as_bytes()).collect())
        }
        // Our preference wins over the client's ordering.
        assert_eq!(
            negotiable_alpn(v(&["http/1.1", "h2"])),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // Unsupported protocols are dropped.
        assert_eq!(
            negotiable_alpn(v(&["h3", "spdy/3", "http/1.1"])),
            vec![b"http/1.1".to_vec()]
        );
        // Nothing we can carry, and no extension at all, both yield an empty
        // offer — meaning "send no ALPN extension upstream".
        assert!(negotiable_alpn(v(&["h3"])).is_empty());
        assert!(negotiable_alpn(None).is_empty());
    }

    /// The mirroring rule: the inbound answer always follows the upstream.
    #[test]
    fn mirror_choice_follows_the_upstream() {
        let configs = test_configs();
        let picked = |sel: Option<&[u8]>, offered: bool| {
            let c = mirror_choice(&configs, sel, offered);
            c.alpn_protocols.clone()
        };

        // Upstream chose h2 -> we advertise h2. Upstream chose http/1.1 -> h1,
        // even though the client would have preferred h2. This is the whole
        // point: no mismatch is possible.
        assert_eq!(picked(Some(b"h2"), true), vec![b"h2".to_vec()]);
        assert_eq!(picked(Some(b"http/1.1"), true), vec![b"http/1.1".to_vec()]);

        // Upstream named nothing but the client did offer -> settle on http/1.1.
        assert_eq!(picked(None, true), vec![b"http/1.1".to_vec()]);
        // Neither side used ALPN -> answer with no ALPN extension.
        assert!(picked(None, false).is_empty());
        // An unrecognized upstream selection is treated like "nothing named".
        assert_eq!(picked(Some(b"h3"), true), vec![b"http/1.1".to_vec()]);
    }

    /// Build the four ALPN variants over a dummy cert resolver, mirroring how
    /// `main.rs` assembles them.
    fn test_configs() -> ServerConfigs {
        #[derive(Debug)]
        struct NoCerts;
        impl rustls::server::ResolvesServerCert for NoCerts {
            fn resolve(
                &self,
                _hello: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                None
            }
        }
        // `main()` installs this process-wide; tests must do it themselves.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let base = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCerts));
        let with = |p: Vec<Vec<u8>>| {
            let mut c = base.clone();
            c.alpn_protocols = p;
            Arc::new(c)
        };
        ServerConfigs {
            none: with(Vec::new()),
            h1: with(vec![b"http/1.1".to_vec()]),
            h2: with(vec![b"h2".to_vec()]),
            h2h1: with(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        }
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

    fn assert_stalled_sample_is_slow(obs: &crate::pool::PassiveObs, wait: Duration) {
        use crate::scoring::{default_nig_prior, score};
        use rand::SeedableRng;

        assert!(obs.elapsed >= wait);
        let mut stalled = default_nig_prior();
        let mut responsive = default_nig_prior();
        for _ in 0..30 {
            stalled.observe(obs.bytes as f64 / obs.elapsed.as_secs_f64(), 0.95);
            responsive.observe(8192.0 / 0.03, 0.95);
        }
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let rtt = Duration::from_millis(1);
        let stalled_wins = (0..10_000)
            .filter(|_| {
                score(rtt, &stalled, 1_000_000, &mut rng)
                    < score(rtt, &responsive, 1_000_000, &mut rng)
            })
            .count();
        assert!(
            stalled_wins < 100,
            "stalled upstream won {stalled_wins}/10000"
        );
    }

    #[tokio::test]
    async fn idle_timeout_keeps_counts_and_waiting_time() {
        let (handle, mut observations) = crate::pool::test_support::observer();
        let (mut client, gate_client) = tokio::io::duplex(8192);
        let (gate_upstream, mut upstream) = tokio::io::duplex(8192);
        let worker = tokio::spawn(async move {
            splice(
                gate_client,
                gate_upstream,
                Duration::from_millis(100),
                Some((&handle, "127.0.0.1".parse().unwrap())),
            )
            .await
        });
        let payload = [42u8; 4096];
        upstream.write_all(&payload).await.unwrap();
        let mut received = [0u8; 4096];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        assert!(worker
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("idle timeout"));
        let obs = observations.recv().await.unwrap();
        assert_eq!(obs.bytes, 4096);
        assert!(obs.elapsed >= Duration::from_millis(100));
        assert!(
            observations.try_recv().is_err(),
            "reported the same connection twice"
        );
    }

    #[tokio::test]
    async fn cancellation_still_reports_already_forwarded_bytes() {
        let (handle, mut observations) = crate::pool::test_support::observer();
        let (mut client, gate_client) = tokio::io::duplex(128);
        let (gate_upstream, mut upstream) = tokio::io::duplex(128);
        let worker = tokio::spawn(async move {
            splice(
                gate_client,
                gate_upstream,
                Duration::ZERO,
                Some((&handle, "127.0.0.1".parse().unwrap())),
            )
            .await
        });
        upstream.write_all(b"response").await.unwrap();
        let mut received = [0u8; 8];
        client.read_exact(&mut received).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        let obs = observations.recv().await.unwrap();
        assert_eq!(obs.bytes, 8);
        assert!(obs.elapsed >= Duration::from_millis(40));
    }

    #[tokio::test]
    async fn stalled_responses_do_not_learn_faster_than_successful_transfers() {
        // Cover both a silent upstream and one that sends only a response prefix.
        for response in [b"".as_slice(), b"HTTP/1.1 200 OK\r\n"] {
            let (handle, mut observations) = crate::pool::test_support::observer();
            let (mut client, gate_client) = tokio::io::duplex(128);
            let (gate_upstream, mut upstream) = tokio::io::duplex(128);
            let request = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n";
            client.write_all(request).await.unwrap();
            let worker = tokio::spawn(async move {
                splice(
                    gate_client,
                    gate_upstream,
                    Duration::from_millis(40),
                    Some((&handle, "127.0.0.1".parse().unwrap())),
                )
                .await
            });
            let mut received = vec![0; request.len()];
            upstream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, request);
            upstream.write_all(response).await.unwrap();
            let mut received = vec![0; response.len()];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, response);
            assert!(worker
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("idle timeout"));

            let obs = observations.try_recv().unwrap();
            assert_eq!(obs.bytes, (request.len() + response.len()) as u64);
            assert_stalled_sample_is_slow(&obs, Duration::from_millis(40));
            assert!(observations.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn normal_eof_does_not_hide_missing_or_truncated_response() {
        for response in [
            b"".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 8192\r\n\r\nx",
        ] {
            let (handle, mut observations) = crate::pool::test_support::observer();
            let (mut client, gate_client) = tokio::io::duplex(128);
            let (gate_upstream, mut upstream) = tokio::io::duplex(128);
            let request = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n";
            client.write_all(request).await.unwrap();
            client.shutdown().await.unwrap();
            let wait = Duration::from_millis(40);
            let (result, ()) = tokio::join!(
                splice(
                    gate_client,
                    gate_upstream,
                    Duration::from_secs(1),
                    Some((&handle, "127.0.0.1".parse().unwrap())),
                ),
                async {
                    let mut received = Vec::new();
                    upstream.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, request);
                    upstream.write_all(response).await.unwrap();
                    tokio::time::sleep(wait).await;
                    upstream.shutdown().await.unwrap();
                }
            );
            result.unwrap();
            let mut received = Vec::new();
            client.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, response);
            let obs = observations.try_recv().unwrap();
            assert_eq!(obs.bytes, (request.len() + response.len()) as u64);
            assert_stalled_sample_is_slow(&obs, wait);
            assert!(observations.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn clean_close_includes_time_after_the_last_write() {
        let (handle, mut observations) = crate::pool::test_support::observer();
        let (mut client, gate_client) = tokio::io::duplex(128);
        let (gate_upstream, mut upstream) = tokio::io::duplex(128);
        let worker = tokio::spawn(async move {
            splice(
                gate_client,
                gate_upstream,
                Duration::ZERO,
                Some((&handle, "127.0.0.1".parse().unwrap())),
            )
            .await
        });
        upstream.write_all(b"response").await.unwrap();
        let mut received = [0; 8];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"response");
        tokio::time::sleep(Duration::from_millis(40)).await;
        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();
        worker.await.unwrap().unwrap();
        let obs = observations.try_recv().unwrap();
        assert_eq!(obs.bytes, 8);
        assert!(obs.elapsed >= Duration::from_millis(40));
        assert!(observations.try_recv().is_err());
    }

    #[tokio::test]
    async fn empty_transfers_do_not_create_observations() {
        let (handle, mut observations) = crate::pool::test_support::observer();
        let (mut client, gate_client) = tokio::io::duplex(128);
        let (gate_upstream, mut upstream) = tokio::io::duplex(128);
        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();
        splice(
            gate_client,
            gate_upstream,
            Duration::ZERO,
            Some((&handle, "127.0.0.1".parse().unwrap())),
        )
        .await
        .unwrap();
        assert!(observations.try_recv().is_err());
    }

    struct PartialFailure {
        remaining: usize,
        delay: Duration,
        error_after: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl AsyncRead for PartialFailure {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PartialFailure {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.remaining == 0 {
                let delay = self.delay;
                let timer = self
                    .error_after
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(delay)));
                std::task::ready!(timer.as_mut().poll(cx));
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            let n = self.remaining.min(buf.len());
            self.remaining -= n;
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn write_failure_keeps_partial_bytes_and_wait_without_waiting_for_peer_eof() {
        let (handle, mut observations) = crate::pool::test_support::observer();
        let (mut client, gate_client) = tokio::io::duplex(128);
        client.write_all(b"partially delivered").await.unwrap();
        let failed = PartialFailure {
            remaining: 7,
            delay: Duration::from_millis(40),
            error_after: None,
        };
        let result = timeout(
            Duration::from_secs(2),
            splice(
                gate_client,
                failed,
                Duration::ZERO,
                Some((&handle, "127.0.0.1".parse().unwrap())),
            ),
        )
        .await
        .expect("I/O failure must finish even if the opposite reader never closes");
        assert_eq!(
            result
                .unwrap_err()
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::BrokenPipe
        );
        let obs = observations.try_recv().unwrap();
        assert_eq!(obs.bytes, 7);
        assert!(obs.elapsed >= Duration::from_millis(40));
        assert!(observations.try_recv().is_err());
    }

    #[tokio::test]
    async fn partial_write_before_error_is_counted_exactly() {
        let mut reader = &b"partially delivered"[..];
        let mut writer = PartialFailure {
            remaining: 7,
            delay: Duration::ZERO,
            error_after: None,
        };
        let mut bytes = 0;
        assert!(
            pump(&mut reader, &mut writer, &Notify::new(), &mut bytes, true)
                .await
                .is_err()
        );
        assert_eq!(bytes, 7);
    }
}
