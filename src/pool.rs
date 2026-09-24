//! Adaptive upstream endpoint selection.
//!
//! A pool is a named set of upstream endpoints with background health probing
//! and adaptive selection. It solves one problem: when several candidates serve
//! the same role, send traffic to the best one and fail over when it degrades.
//!
//! # Targets and candidates
//!
//! The two layers are distinct throughout this module, and keeping them apart is
//! what makes every index in the configuration well-defined:
//!
//! * A **target** is one `targets` entry. It has a stable index, and that index
//!   is the only addressing unit in the config: `fallback`, `nat64.from` and
//!   `select` all name targets.
//! * A **candidate** is one probed endpoint — an address. One target yields many:
//!   a domain yields one per A/AAAA record, a CIDR one per sampled address, and
//!   the NAT64 projection adds one per (IPv4 candidate × prefix).
//!
//! Tags live on candidates, because that is where they are *knowable*: whether a
//! domain contributes an `ipv4` or an `ipv6` endpoint is a fact about its DNS
//! answer, not about the line the operator wrote. This is why no load-time rule
//! can require that an index "references an `ipv4` candidate" — at load time
//! there are no candidates. Indices are bounds-checked at load; tag mismatches
//! are reported at runtime, where they are first observable.
//!
//! # What is measured, and on which port
//!
//! The probe measures *link quality to an edge node*: `sni` and `port` belong to
//! the pool, not to any consuming route. A pool referenced by twenty routes with
//! twenty different names is still one ranking of one set of edges. A consumer
//! then applies its own port to the address the pool selected, which is why
//! `@pool:8443` needs no separate pool.
//!
//! # Where the work happens
//!
//! One task per pool does all of it: re-resolving domain targets, probing due
//! candidates, and recomputing the ranking. The data path samples a published
//! model snapshot and updates its view's atomic incumbent — see [`Pool::pick`].
//! Nothing on the data path can trigger a probe, so a burst
//! of traffic cannot turn into a burst of probes.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock, Weak};

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use rustls::client::EchStatus;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::scoring::{default_nig_prior, score, KalmanRtt, NigThroughput, SubnetKey};
use url::Url;

use crate::config::{AddressFamily, EffectiveProbeEch, PoolDef, ProbeSpec, Selector, TargetDef};
use crate::dns_resolvers::DnsResolver;
use crate::ech::{is_ech_reject_io, EchProvider};
use crate::nat64::Nat64Prefix;
use crate::verify::UpstreamVerify;

/// The tag vocabulary. These three strings are the *only* automatic tags, and
/// they are also what `address_family` uses, so an operator learns one set of
/// words. No abbreviations, no alternative spellings.
const TAG_IPV4: &str = "ipv4";
const TAG_IPV6: &str = "ipv6";
const TAG_NAT64: &str = "nat64";

/// Hard cap on candidates produced by expanding one CIDR target without an
/// explicit `[N]` sample count.
///
/// A `/12` holds a million addresses; expanding it would probe forever and
/// allocate accordingly. A documented warning cannot prevent that, so the limit
/// is enforced at load time with an error naming the fix.
const MAX_CIDR_EXPANSION: usize = 64;

/// Default upper bound on concurrent probes within one pool, so a large pool cannot open
/// hundreds of sockets in one cycle. Configurable via `probe.max_concurrent_probes`.
const DEFAULT_MAX_CONCURRENT_PROBES: usize = 16;
/// Finite telemetry and per-wakeup work budgets. Traffic never waits for probes.
const OBSERVATION_CAPACITY: usize = 2048;
const OBSERVATION_BATCH: usize = 64;
const MAX_PARKED_CANDIDATES: usize = 4096;
const MAX_IDLE_SUBNET_PRIORS: usize = 1024;

/// Default Kalman process-noise Q (ms²). Low enough to give a stable steady-state
/// estimate but high enough to let the filter track gradual CDN RTT drift.
const DEFAULT_KALMAN_Q: f64 = 0.01;

/// Default Kalman observation-noise R (ms²). Calibrated to typical probe jitter.
const DEFAULT_KALMAN_R: f64 = 0.1;

/// Default throughput discount factor applied before each new observation.
const DEFAULT_THROUGHPUT_DISCOUNT: f64 = 0.95;

/// How long a candidate that has left the live set is retained in the parked map
/// before its state is truly discarded. CDN IP rotation often brings the same
/// address back within minutes; retaining its Kalman and NIG state avoids
/// a cold-start penalty on re-entry.
const PARK_DURATION: Duration = Duration::from_secs(600);

/// Relative margin a challenger must beat the incumbent by to overtake it.
/// Applied to the score (seconds), not raw Duration, so the same percentage
/// applies whether scoring by RTT alone or by rtt + payload/throughput.
const HYSTERESIS_FRACTION: f64 = 0.20; // 20%

/// Absolute floor on that margin, for endpoints that are all fast.
const HYSTERESIS_FLOOR: Duration = Duration::from_millis(5);

// ---------------------------------------------------------------------------
// The probe plan
// ---------------------------------------------------------------------------

/// Default probed port for `tcp` and `tls`. An `http` probe takes its port from
/// the URL.
const DEFAULT_PROBE_PORT: u16 = 443;

/// Default per-candidate deadline for `tcp` and `tls`: a handshake still
/// unfinished after this long is not a path worth ranking.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// Default per-candidate deadline for `http`, which adds a request/response
/// round trip on top of the handshake.
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Default probe cycle for a healthy candidate.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(300);

/// Default first retry delay for a degraded candidate, doubling up to
/// [`DEFAULT_INTERVAL`].
const DEFAULT_DEGRADED_INTERVAL: Duration = Duration::from_secs(30);

/// Default consecutive failures before a candidate is marked degraded.
const DEFAULT_FAIL_THRESHOLD: u32 = 2;

/// ALPN offered by an `https` probe.
///
/// HTTP/1.1 only, and deliberately so: the probe writes an HTTP/1.1 request onto
/// the stream, so offering `h2` to an origin that supports it — which is most of
/// them — would negotiate a protocol the probe cannot speak and fail every
/// candidate. A `tls` probe offers nothing at all; it has no protocol to
/// negotiate because it stops at the handshake.
const HTTP_PROBE_ALPN: &[&[u8]] = &[b"http/1.1"];

/// How much of an HTTP response to buffer. Enough for any status line; the probe
/// stops reading the moment it has one.
const STATUS_LINE_BUF: usize = 128;

/// What one probe does, with every default applied and every reusable artifact
/// built once.
///
/// Built at startup and then only read, so nothing on the probe path parses a
/// URL, assembles a request or clones a root store — work that would otherwise
/// repeat per candidate per cycle and dwarf the measurement it exists to take.
struct ProbePlan {
    /// The port every candidate is dialled on. For `http` it comes from the URL,
    /// so all three modes answer this question in one place.
    port: u16,
    /// Per-candidate deadline.
    timeout: Duration,
    kind: ProbeKind,
}

/// The mode-specific half of a [`ProbePlan`].
///
/// Which instant stops the clock differs per variant, and each is the last
/// moment that still says something about the path.
enum ProbeKind {
    /// Connect only. The clock stops at connect completion.
    Tcp,

    /// Handshake only. The clock stops at handshake completion.
    Tls(TlsProbe),

    /// Request and response. The clock stops at the first response byte: that is
    /// when the origin demonstrably answered, and waiting for a body would
    /// measure its size instead of the path.
    Http {
        /// The full request, rendered once. It never varies by candidate — a
        /// pool probes one origin across many addresses.
        request: String,
        /// Response codes that count as healthy. Non-empty.
        expect_status: Vec<u16>,
        /// `None` for an `http://` URL.
        tls: Option<TlsProbe>,
    },
}

/// The TLS half of a `tls` or `https` probe.
struct TlsProbe {
    /// The name sent in the ClientHello — the *inner* one under ECH — and the
    /// name the certificate is verified against.
    sni: String,
    config: TlsSource,
}

/// Where a probe's `ClientConfig` comes from.
///
/// Either way it is built once and reused: a config carries the whole handshake
/// policy, so rebuilding one per probe would redo that work on every cycle of
/// every candidate.
enum TlsSource {
    /// No ECH: one config, with the probe's ALPN offer already baked in.
    Plain(Arc<ClientConfig>),

    /// ECH: the same provider the route and resolver paths use. It memoizes one
    /// config per (inner name, ALPN offer) and refreshes the ECHConfigList on
    /// the TTL of the HTTPS record, so a probe cycle costs no DoH lookup.
    Ech {
        provider: Arc<EchProvider>,
        alpn: Vec<Vec<u8>>,
        /// Fail the candidate unless ECH was actually negotiated.
        require_ech: bool,
        /// Retry budget for a server that rejects ECH because its published key
        /// rotated. Each retry refetches the config first.
        max_retries: u32,
    },
}

/// The cadence and scoring parameters for one pool, with defaults applied.
struct ProbeTiming {
    interval: Duration,
    degraded_interval: Duration,
    fail_threshold: u32,
    /// Upper bound on probes running concurrently within one cycle.
    max_concurrent_probes: usize,
    /// Reference payload size for the `rtt + payload/throughput` score formula.
    /// Zero disables throughput scoring and falls back to pure RTT ranking.
    score_payload_bytes: u64,
    /// NIG time-discount factor applied before each passive throughput observation.
    throughput_discount: f64,
    /// Kalman process-noise Q (ms²).
    kalman_q: f64,
    /// Kalman observation-noise R (ms²).
    kalman_r: f64,
}

/// The ECH inputs a pool cannot resolve for itself.
///
/// `ech_resolver` names a `[resolvers.*]` entry, and only `main` holds the
/// registry — the same split that keeps [`PoolBuilder::new`] free of resolver
/// lookup for the pool's own targets.
pub struct ProbeEchSetup {
    pub ech: EffectiveProbeEch,
    pub resolver: Arc<DnsResolver>,
}

// ---------------------------------------------------------------------------
// Target specifications
// ---------------------------------------------------------------------------

/// A parsed `targets` entry: what kind of endpoint source it is.
///
/// The kind is inferred from the string so the common case stays one token.
/// Checked at config load, so a malformed target is a startup error rather than a
/// pool that silently contributes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSpec {
    /// A DNS name, re-resolved on every probe cycle.
    Domain(String),
    /// A literal address.
    Ip(IpAddr),
    /// A network, sampled or fully expanded.
    Cidr { net: IpNet, sample: Option<usize> },
}

impl TargetSpec {
    /// Parse one target address specification.
    ///
    /// Inference order matters: `/` marks a CIDR before anything else, because
    /// `10.0.0.0/8` also "contains no colon" and would otherwise read as a
    /// hostname. Then a successful IP parse, then a domain.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            bail!("empty target");
        }

        // Optional `[N]` sampling suffix, only meaningful on a CIDR.
        let (body, sample) = match s.strip_suffix(']') {
            Some(head) => match head.rsplit_once('[') {
                Some((base, n)) => {
                    let n: usize = n.trim().parse().with_context(|| {
                        format!("sample count in {s:?} must be a positive integer")
                    })?;
                    if n == 0 {
                        bail!("sample count in {s:?} must be at least 1");
                    }
                    (base.trim(), Some(n))
                }
                None => bail!("unmatched ']' in target {s:?}"),
            },
            None => (s, None),
        };

        if body.contains('/') {
            let net: IpNet = body
                .parse()
                .with_context(|| format!("target {s:?} is not a valid CIDR"))?;
            if sample.is_none() {
                let size = network_size(&net);
                if size > MAX_CIDR_EXPANSION as u128 {
                    bail!(
                        "target {s:?} expands to {size} addresses, over the limit of \
                         {MAX_CIDR_EXPANSION}; append a sample count, e.g. \"{body}[4]\""
                    );
                }
            }
            return Ok(TargetSpec::Cidr { net, sample });
        }

        if sample.is_some() {
            bail!("sample count in {s:?} only applies to a CIDR target");
        }

        if let Ok(ip) = body.parse::<IpAddr>() {
            return Ok(TargetSpec::Ip(ip));
        }

        // A domain. Reject the shapes that indicate a mistyped address rather
        // than a name, so they fail at load instead of as an NXDOMAIN later.
        if body.contains(':') {
            bail!(
                "target {s:?} looks like an IPv6 address but does not parse as one \
                 (a domain target must not contain ':')"
            );
        }
        Ok(TargetSpec::Domain(body.to_string()))
    }
}

/// Number of addresses in a network, saturating for very large IPv6 prefixes.
fn network_size(net: &IpNet) -> u128 {
    let host_bits = u32::from(net.max_prefix_len() - net.prefix_len());
    if host_bits >= 128 {
        u128::MAX
    } else {
        1u128 << host_bits
    }
}

/// A target after load-time parsing, with CIDR sampling already drawn.
///
/// Samples are drawn once, at startup, rather than per cycle: re-drawing would
/// discard every RTT measurement each cycle and make the ranking meaningless. A
/// sampled address that turns out to be dead is instead replaced through the
/// normal degradation path (see [`PoolState::resample_dead`]).
struct Target {
    /// Index in the config's `targets` array. The addressing unit for
    /// `select`, `fallback` and `nat64.from`.
    index: usize,
    spec: TargetSpec,
    /// Operator-supplied tags, appended to the automatic ones.
    custom_tags: Arc<[String]>,
    /// For a CIDR: the addresses drawn from it. Empty for other kinds.
    sampled: Vec<IpAddr>,
}

// ---------------------------------------------------------------------------
// Candidates
// ---------------------------------------------------------------------------

/// One probed endpoint.
#[derive(Debug, Clone)]
struct Candidate {
    addr: IpAddr,
    /// Which target produced it.
    target: usize,
    /// Automatic tags plus the target's custom ones.
    tags: Vec<String>,
}

impl Candidate {
    fn matches(&self, sel: &[Selector]) -> bool {
        // An empty selector list is "no filter": written explicitly, it widens a
        // template's filter back to everything.
        if sel.is_empty() {
            return true;
        }
        sel.iter().any(|s| match s {
            Selector::Index(i) => *i == self.target,
            Selector::Tag(t) => self.tags.iter().any(|own| own == t),
        })
    }
}

/// Health of one endpoint, keyed by address so it survives a candidate-set
/// change (a domain's records rotating, a dead sample being replaced).
#[derive(Debug, Clone)]
struct Health {
    /// Kalman filter over RTT; provides the posterior mean used for ranking.
    kalman: KalmanRtt,
    /// NIG conjugate posterior over log-throughput; used for Thompson Sampling.
    nig: NigThroughput,
    consecutive_failures: u32,
    degraded: bool,
    /// When this endpoint is next due. Per-candidate, which is what lets a
    /// permanently dead endpoint back off without slowing the whole pool.
    next_probe: Instant,
    /// Current backoff delay, doubling on each failure up to `interval`.
    backoff: Duration,
}

impl Health {
    fn new(due: Instant, backoff: Duration, q: f64, r: f64) -> Self {
        Self {
            kalman: KalmanRtt::new(q, r),
            nig: default_nig_prior(),
            consecutive_failures: 0,
            degraded: false,
            next_probe: due,
            backoff,
        }
    }

    /// Current RTT estimate, available after the first successful probe.
    fn rtt(&self) -> Option<Duration> {
        if self.kalman.is_initialized() {
            Some(self.kalman.estimate())
        } else {
            None
        }
    }

    fn record_success(&mut self, sample: Duration, interval: Duration, base_backoff: Duration) {
        let alarm = self.kalman.update(sample);
        if alarm {
            warn!(
                rtt_ms = sample.as_millis(),
                "CUSUM detected an upward RTT regime change; Kalman variance reset for fast reconvergence"
            );
        }
        self.consecutive_failures = 0;
        self.degraded = false;
        self.backoff = base_backoff;
        self.next_probe = Instant::now() + interval;
    }

    fn record_failure(&mut self, threshold: u32, interval: Duration, base_backoff: Duration) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let newly_degraded = !self.degraded && self.consecutive_failures >= threshold;
        if newly_degraded {
            self.degraded = true;
            self.backoff = base_backoff;
        } else if self.degraded {
            // Exponential backoff, capped at the healthy interval: a dead
            // endpoint settles at the same cost as a live one instead of
            // probing forever at the fast rate.
            self.backoff = (self.backoff * 2).min(interval);
        }
        // A candidate below the threshold retries at the base delay: it may be a
        // single dropped packet, and waiting a full interval to find out would
        // leave a healthy endpoint out of the ranking for minutes.
        let delay = if self.degraded {
            self.backoff
        } else {
            base_backoff
        };
        self.next_probe = Instant::now() + delay;
    }

    /// Incorporate one passive throughput observation from a completed connection.
    fn observe_throughput(&mut self, bytes: u64, elapsed: Duration, discount: f64) {
        if elapsed.is_zero() || bytes == 0 {
            return;
        }
        let bps = bytes as f64 / elapsed.as_secs_f64();
        self.nig.observe(bps, discount);
    }
}

// ---------------------------------------------------------------------------
// Views and the published ranking
// ---------------------------------------------------------------------------

/// One consumer's registered candidate filter.
///
/// Views are registered while routes are built, so by the time traffic arrives
/// the probe task already knows every filter that will ever be asked about and
/// publishes a finished, ordered list for each. That is what keeps `select`
/// evaluation off the data path entirely: it is not evaluated per connection, it
/// is evaluated per probe cycle.
struct View {
    selectors: Vec<Selector>,
}

/// A finished, ordered answer for one view.
struct ViewRanking {
    /// Healthy addresses, best first.
    ordered: Vec<Arc<SelectionModel>>,
    incumbent: AtomicUsize,
    /// The safety net, used only while `ordered` is empty.
    fallback: Option<IpAddr>,
}

/// Models and ordering are replaced wholesale by the pool worker. Connections
/// only mutate each view's atomic incumbent within a published snapshot.
struct Ranking {
    per_view: Vec<ViewRanking>,
}

impl Ranking {
    /// An empty ranking, published before the first probe cycle completes so the
    /// data path always has something well-formed to read.
    fn empty(views: usize) -> Self {
        Self {
            per_view: (0..views)
                .map(|_| ViewRanking {
                    ordered: Vec::new(),
                    incumbent: AtomicUsize::new(0),
                    fallback: None,
                })
                .collect(),
        }
    }
}

struct SelectionModel {
    pub addr: IpAddr,
    pub rtt: Duration,
    pub throughput: NigThroughput,
}

fn choose_candidate(
    models: &[Arc<SelectionModel>],
    incumbent: &AtomicUsize,
    payload: u64,
) -> Option<IpAddr> {
    if payload == 0 {
        return models.first().map(|m| m.addr);
    }
    let mut rng = rand::rng();
    choose_with(models, incumbent, |model| {
        score(model.rtt, &model.throughput, payload, &mut rng)
    })
}

fn choose_with(
    models: &[Arc<SelectionModel>],
    incumbent: &AtomicUsize,
    mut score: impl FnMut(&SelectionModel) -> f64,
) -> Option<IpAddr> {
    if models.is_empty() {
        return None;
    }
    let previous = incumbent.load(Ordering::Relaxed).min(models.len() - 1);
    let mut incumbent_score = 0.0;
    let mut best = 0;
    let mut best_score = f64::INFINITY;
    for (index, model) in models.iter().enumerate() {
        let value = score(model);
        if index == previous {
            incumbent_score = value;
        }
        if value < best_score {
            best = index;
            best_score = value;
        }
    }
    let (chosen, chosen_score) = if best == previous || beats(best_score, incumbent_score) {
        (best, best_score)
    } else {
        (previous, incumbent_score)
    };
    incumbent.store(chosen, Ordering::Relaxed);
    tracing::debug!(candidate = %models[chosen].addr, score_s = chosen_score, "selected pool candidate");
    Some(models[chosen].addr)
}

/// A route's handle on a pool: the pool plus which registered view it reads.
///
/// Cloneable and cheap; one per route that references the pool.
pub struct PoolHandle {
    pool: Arc<Pool>,
    view: usize,
}

impl PoolHandle {
    /// The pool's declared name, for diagnostics.
    pub fn name(&self) -> &str {
        &self.pool.name
    }

    /// The address to dial right now, on `port`.
    ///
    /// No I/O, allocation, or selector evaluation. Adaptive mode draws one
    /// score per eligible endpoint from a shared immutable model snapshot.
    pub fn pick(&self, port: u16) -> Result<SocketAddr> {
        self.pool.pick(self.view, port)
    }

    pub fn observes_transfers(&self) -> bool {
        self.pool.obs_tx.is_some()
    }

    /// Never block traffic. Overload discards new telemetry with a counted,
    /// rate-limited diagnostic rather than allocating an unbounded backlog.
    pub fn observe_transfer(&self, addr: IpAddr, bytes: u64, elapsed: Duration) {
        if bytes == 0 || elapsed.is_zero() {
            return;
        }
        if let Some(tx) = &self.pool.obs_tx {
            if matches!(
                tx.try_send(PassiveObs {
                    addr,
                    bytes,
                    elapsed
                }),
                Err(mpsc::error::TrySendError::Full(_))
            ) {
                self.pool
                    .dropped_observations
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The pool
// ---------------------------------------------------------------------------

/// One passive throughput observation reported by the proxy after a connection closes.
pub struct PassiveObs {
    /// The upstream IP address that served the connection.
    pub addr: IpAddr,
    /// Total bytes transferred (both directions).
    pub bytes: u64,
    /// Wall time of the data transfer phase (excluding connection setup).
    pub elapsed: Duration,
}

/// Everything a pool needs at runtime, plus its published ranking.
pub struct Pool {
    name: String,
    targets: Vec<Target>,
    probe: ProbePlan,
    timing: ProbeTiming,
    /// NAT64 projection, if configured.
    nat64: Option<Nat64Projection>,
    /// Index into `targets` for the fallback, if configured.
    fallback: Option<usize>,
    resolver: Arc<DnsResolver>,
    views: Vec<View>,
    /// The current answer for every view.
    ///
    /// `RwLock<Arc<_>>` and never a lock held across work: a reader clones the
    /// `Arc` out and releases the lock immediately, so publishing a new ranking
    /// holds the write lock only for the swap. A reader in flight keeps using the
    /// snapshot it started with. Same shape as [`crate::dns_resolvers::DnsResolver`].
    ranking: RwLock<Arc<Ranking>>,
    /// Sink for passive throughput observations from the proxy.
    obs_tx: Option<mpsc::Sender<PassiveObs>>,
    dropped_observations: AtomicU64,
}

/// NAT64 projection parameters, resolved at build.
struct Nat64Projection {
    prefixes: Vec<Nat64Prefix>,
    /// Target indices whose IPv4 candidates participate; `None` = all.
    from: Option<Vec<usize>>,
    timeout: Duration,
}

impl Pool {
    /// The view id matching `selectors`, registered during the build pass.
    ///
    /// Views are registered before any pool is spawned, so this is a lookup and
    /// never a mutation: by the time routes are built, every filter that will
    /// ever be asked about is already published.
    pub fn view_for(&self, selectors: Option<&[Selector]>) -> Option<usize> {
        let wanted = selectors.unwrap_or(&[]);
        self.views.iter().position(|v| v.selectors == wanted)
    }

    /// The address to dial for `view`, on `port`.
    fn pick(&self, view: usize, port: u16) -> Result<SocketAddr> {
        let snapshot = {
            let guard = self.ranking.read().expect("pool ranking lock poisoned");
            guard.clone()
        };
        let vr = snapshot
            .per_view
            .get(view)
            .ok_or_else(|| anyhow!("pool {}: unregistered view {view}", self.name))?;

        if let Some(ip) =
            choose_candidate(&vr.ordered, &vr.incumbent, self.timing.score_payload_bytes)
        {
            return Ok(SocketAddr::new(ip, port));
        }
        if let Some(ip) = vr.fallback {
            return Ok(SocketAddr::new(ip, port));
        }
        // No healthy candidate and no usable fallback. An error rather than a
        // guess: the route's own fail policy is the right place to decide what
        // happens to the connection.
        Err(anyhow!(
            "pool {}: no healthy candidate and no usable fallback",
            self.name
        ))
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// A pool under construction, collecting the views its consumers need.
///
/// Two-phase on purpose: routes are built before anything is spawned, so every
/// `select` is known by the time the probe task starts and no view has to be
/// registered against a running pool.
pub struct PoolBuilder {
    name: String,
    def: PoolDef,
    targets: Vec<Target>,
    probe: ProbePlan,
    timing: ProbeTiming,
    resolver: Arc<DnsResolver>,
    views: Vec<View>,
}

impl PoolBuilder {
    /// Parse and prepare one pool definition. Draws CIDR samples and builds the
    /// probe's reusable TLS artifacts; performs no I/O and starts nothing.
    ///
    /// `spec` is the caller's already-validated probe reduction rather than one
    /// taken from `def` here, because resolving `probe.ech.ech_resolver` needs
    /// the resolver registry that only `main` holds — and reducing twice is how
    /// the two copies would eventually come to disagree.
    pub fn new(
        name: &str,
        def: &PoolDef,
        spec: ProbeSpec,
        resolver: Arc<DnsResolver>,
        probe_ech: Option<ProbeEchSetup>,
        verify: Arc<UpstreamVerify>,
    ) -> Result<Self> {
        def.probe
            .validate_parameters()
            .map_err(|e| anyhow!("[pools.{name}.probe]: {e}"))?;
        let mut targets = Vec::with_capacity(def.targets.len());
        for (index, t) in def.targets.iter().enumerate() {
            let target = TargetSpec::parse(t.addr())
                .with_context(|| format!("[pools.{name}]: targets[{index}]"))?;
            let sampled = match &target {
                TargetSpec::Cidr { net, sample } => draw_sample(net, *sample),
                _ => Vec::new(),
            };
            targets.push(Target {
                index,
                spec: target,
                custom_tags: tags_of(t),
                sampled,
            });
        }

        Ok(Self {
            name: name.to_string(),
            def: def.clone(),
            targets,
            probe: build_probe_plan(spec, probe_ech, verify),
            timing: ProbeTiming {
                interval: def.probe.interval.unwrap_or(DEFAULT_INTERVAL),
                degraded_interval: def
                    .probe
                    .degraded_interval
                    .unwrap_or(DEFAULT_DEGRADED_INTERVAL),
                fail_threshold: def.probe.fail_threshold.unwrap_or(DEFAULT_FAIL_THRESHOLD),
                max_concurrent_probes: def
                    .probe
                    .max_concurrent_probes
                    .unwrap_or(DEFAULT_MAX_CONCURRENT_PROBES),
                score_payload_bytes: def.probe.score_payload_bytes.unwrap_or(0),
                throughput_discount: def
                    .probe
                    .throughput_discount
                    .unwrap_or(DEFAULT_THROUGHPUT_DISCOUNT),
                kalman_q: def.probe.rtt_process_noise.unwrap_or(DEFAULT_KALMAN_Q),
                kalman_r: def.probe.rtt_obs_noise.unwrap_or(DEFAULT_KALMAN_R),
            },
            resolver,
            views: Vec::new(),
        })
    }

    /// Register a consumer's filter, returning the view id it should read.
    ///
    /// Identical filters share a view: many routes usually want the same subset,
    /// and one ordered list per distinct filter is all the probe task should have
    /// to compute.
    pub fn register_view(&mut self, selectors: Option<&[Selector]>) -> usize {
        let selectors: Vec<Selector> = selectors.unwrap_or(&[]).to_vec();
        if let Some(existing) = self.views.iter().position(|v| v.selectors == selectors) {
            return existing;
        }
        self.views.push(View { selectors });
        self.views.len() - 1
    }

    /// Whether any route actually reads this pool.
    pub fn is_used(&self) -> bool {
        !self.views.is_empty()
    }

    /// Finish the pool and spawn its probe task.
    pub fn spawn(self) -> Result<Arc<Pool>> {
        let nat64 =
            match &self.def.nat64 {
                None => None,
                Some(n) => {
                    let mut prefixes = Vec::with_capacity(n.prefixes.len());
                    for p in &n.prefixes {
                        prefixes.push(p.parse::<Nat64Prefix>().with_context(|| {
                            format!("[pools.{}.nat64]: prefix {p:?}", self.name)
                        })?);
                    }
                    Some(Nat64Projection {
                        prefixes,
                        from: n.from.clone(),
                        timeout: n.timeout.unwrap_or(self.probe.timeout),
                    })
                }
            };

        let view_count = self.views.len();
        let (obs_tx, obs_rx) = mpsc::channel(OBSERVATION_CAPACITY);
        let obs_tx = (self.timing.score_payload_bytes != 0).then_some(obs_tx);
        let pool = Arc::new(Pool {
            name: self.name,
            targets: self.targets,
            probe: self.probe,
            timing: self.timing,
            nat64,
            fallback: self.def.fallback,
            resolver: self.resolver,
            views: self.views,
            ranking: RwLock::new(Arc::new(Ranking::empty(view_count))),
            obs_tx,
            dropped_observations: AtomicU64::new(0),
        });

        // The task holds only a `Weak`, so it stops on its own if the pool is
        // dropped rather than keeping it alive forever. Same pattern as the ECH
        // refresher in `dns_resolvers`, and the reason no cancellation-token
        // plumbing is needed to shut a pool down.
        let weak = Arc::downgrade(&pool);
        tokio::spawn(async move { run_probe_loop(weak, obs_rx).await });

        Ok(pool)
    }

    /// A handle for one consumer, reading `view`.
    pub fn handle(pool: Arc<Pool>, view: usize) -> PoolHandle {
        PoolHandle { pool, view }
    }
}

/// Apply the defaults and build everything a probe can reuse across candidates.
fn build_probe_plan(
    spec: ProbeSpec,
    ech: Option<ProbeEchSetup>,
    verify: Arc<UpstreamVerify>,
) -> ProbePlan {
    match spec {
        ProbeSpec::Tcp { port, timeout } => ProbePlan {
            port: port.unwrap_or(DEFAULT_PROBE_PORT),
            timeout: timeout.unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT),
            kind: ProbeKind::Tcp,
        },

        ProbeSpec::Tls {
            port, sni, timeout, ..
        } => {
            let port = port.unwrap_or(DEFAULT_PROBE_PORT);
            ProbePlan {
                port,
                timeout: timeout.unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT),
                // No ALPN: a `tls` probe stops at the handshake, so it has no
                // protocol to negotiate.
                kind: ProbeKind::Tls(build_tls_probe(sni, &[], port, ech, verify)),
            }
        }

        ProbeSpec::Http {
            url,
            expect_status,
            timeout,
            ..
        } => {
            // `ProbeSpec::Http` guarantees an http/https URL carrying a host, so
            // both the host and the port are known here.
            let host = url
                .host_str()
                .expect("ProbeSpec::Http carries a URL with a host");
            let port = url
                .port_or_known_default()
                .expect("http and https have known default ports");
            let tls = (url.scheme() == "https").then(|| {
                build_tls_probe(tls_name_from_url(&url), HTTP_PROBE_ALPN, port, ech, verify)
            });
            ProbePlan {
                port,
                timeout: timeout.unwrap_or(DEFAULT_HTTP_TIMEOUT),
                kind: ProbeKind::Http {
                    request: http_request(&url, host),
                    expect_status,
                    tls,
                },
            }
        }
    }
}

/// Return the certificate identity from a probe URL in the representation
/// rustls expects. `Url::host_str()` deliberately brackets IPv6 literals for
/// use in an HTTP authority; rustls `ServerName` requires the bare IP instead.
fn tls_name_from_url(url: &Url) -> String {
    match url
        .host()
        .expect("ProbeSpec::Http carries a URL with a host")
    {
        url::Host::Domain(name) => name.to_string(),
        url::Host::Ipv4(addr) => addr.to_string(),
        url::Host::Ipv6(addr) => addr.to_string(),
    }
}

/// Build the TLS half of a probe: one `ClientConfig`, or the ECH provider that
/// hands out one per (inner name, ALPN offer) and keeps it fresh.
fn build_tls_probe(
    sni: String,
    alpn: &[&[u8]],
    port: u16,
    ech: Option<ProbeEchSetup>,
    verify: Arc<UpstreamVerify>,
) -> TlsProbe {
    let alpn: Vec<Vec<u8>> = alpn.iter().map(|p| p.to_vec()).collect();
    let config = match ech {
        Some(ProbeEchSetup { ech, resolver }) => {
            let EffectiveProbeEch {
                settings,
                require_ech,
                ech_refresh,
                ech_resolver: _,
            } = ech;
            let max_retries = settings.max_retries;
            TlsSource::Ech {
                provider: Arc::new(EchProvider::new(
                    settings,
                    port,
                    require_ech,
                    // A probe has no `override_sni`: the inner hello always
                    // carries the very name whose reachability is measured.
                    true,
                    resolver,
                    verify,
                    ech_refresh,
                )),
                alpn,
                require_ech,
                max_retries,
            }
        }
        None => {
            let mut cfg = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verify.verifier())
                .with_no_client_auth();
            cfg.alpn_protocols = alpn;
            TlsSource::Plain(Arc::new(cfg))
        }
    };
    TlsProbe { sni, config }
}

/// Render the probe request once, at startup.
///
/// `Connection: close` so the origin does not hold the socket open waiting for a
/// second request that will never come.
fn http_request(url: &Url, host: &str) -> String {
    // `Url::port` is `None` exactly when the port is the scheme's default, which
    // is also when RFC 9110 leaves it out of `Host`.
    let authority = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    format!(
        "GET {target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: sni-gate-probe\r\n\
         Accept: */*\r\nConnection: close\r\n\r\n"
    )
}

/// Automatic-plus-custom tags for a target definition. Automatic tags are added
/// per candidate (they depend on the resolved address family), so this carries
/// only the operator's own.
fn tags_of(t: &TargetDef) -> Arc<[String]> {
    t.tags()
        .iter()
        .map(|s| s.trim().to_string())
        .collect::<Vec<_>>()
        .into()
}

/// Draw `sample` random addresses from `net`, or expand it fully when no sample
/// count was given.
///
/// Sampling avoids materializing a large range and is what makes a `/12` usable
/// as a target at all. Duplicates are avoided where the range allows it.
fn draw_sample(net: &IpNet, sample: Option<usize>) -> Vec<IpAddr> {
    let size = network_size(net);
    let Some(want) = sample else {
        // Full expansion; the load-time check already bounded the size.
        return net.hosts().take(MAX_CIDR_EXPANSION).collect();
    };

    let want = (want as u128).min(size) as usize;
    let mut out = Vec::with_capacity(want);
    let mut seen: HashSet<IpAddr> = HashSet::with_capacity(want);
    // Bounded attempts: with `want` close to `size` the last few draws collide
    // often, and an unbounded loop would spin. Falling short is harmless — the
    // pool simply has fewer candidates.
    let mut attempts = 0usize;
    let max_attempts = want.saturating_mul(8).max(16);
    while out.len() < want && attempts < max_attempts {
        attempts += 1;
        let offset = rand::random_range(0..size);
        let addr = offset_into(net, offset);
        if seen.insert(addr) {
            out.push(addr);
        }
    }
    out
}

/// The address at `offset` within `net`.
fn offset_into(net: &IpNet, offset: u128) -> IpAddr {
    match net {
        IpNet::V4(n) => {
            let base = u32::from(n.network());
            IpAddr::V4(Ipv4Addr::from(base.wrapping_add(offset as u32)))
        }
        IpNet::V6(n) => {
            let base = u128::from(n.network());
            IpAddr::V6(Ipv6Addr::from(base.wrapping_add(offset)))
        }
    }
}

// ---------------------------------------------------------------------------
// The probe loop
// ---------------------------------------------------------------------------

/// Mutable state owned solely by the probe task.
struct PoolState {
    /// Health per address, surviving candidate-set changes.
    health: HashMap<IpAddr, Health>,
    /// The previous global order, used to apply hysteresis.
    order: Vec<IpAddr>,
    /// Candidates that recently left the live set, retained for `PARK_DURATION`
    /// so their Kalman and NIG history survives a DNS rotation cycle.
    parked: HashMap<IpAddr, (Health, Instant)>,
    /// Per-subnet NIG prior, propagated from any candidate that shares the prefix.
    /// New candidates inherit from this prior so Thompson Sampling is effective
    /// even before an individual address has received a direct observation.
    subnet_priors: HashMap<SubnetKey, SubnetPrior>,
    /// Passive throughput observations queued by the proxy.
    obs_rx: mpsc::Receiver<PassiveObs>,
    observations_open: bool,
    last_feedback_warning: Instant,
    /// Best address from the last logged cycle, used to suppress redundant INFO logs.
    last_logged_best: Option<IpAddr>,
    /// Healthy count from the last logged cycle.
    last_logged_healthy: usize,
    /// Addresses replaced because they never came up, so a dead CIDR sample is
    /// not retried forever.
    resampled: HashSet<IpAddr>,
    /// Extra addresses drawn to replace dead samples, per target index.
    replacements: HashMap<usize, Vec<IpAddr>>,
    /// Last DNS answer per domain target index, and when it was obtained.
    ///
    /// Cached rather than re-queried each pass because the loop wakes on the
    /// *earliest due candidate*, not on `interval`. A single candidate backing off
    /// at `degraded_interval` would otherwise drag every domain target through a
    /// fresh lookup at that cadence — DNS load rising precisely when part of the
    /// pool is already unhealthy. Refreshed on `interval`, which is the cadence
    /// the operator asked for.
    resolved: HashMap<usize, Vec<IpAddr>>,
    /// When `resolved` was last refreshed. `None` before the first resolution.
    resolved_at: Option<Instant>,
}

struct SubnetPrior {
    model: NigThroughput,
    last_used: Instant,
}

impl PoolState {
    pub(super) fn observe(&mut self, obs: PassiveObs, discount: f64, now: Instant) -> bool {
        if obs.bytes == 0 || obs.elapsed.is_zero() {
            return false;
        }
        let active = self.health.contains_key(&obs.addr);
        let health = self.health.get_mut(&obs.addr).or_else(|| {
            self.parked
                .get_mut(&obs.addr)
                .filter(|(_, expires)| *expires > now)
                .map(|(h, _)| h)
        });
        let Some(health) = health else {
            return false;
        };
        health.observe_throughput(obs.bytes, obs.elapsed, discount);
        let bps = obs.bytes as f64 / obs.elapsed.as_secs_f64();
        let prior = self
            .subnet_priors
            .entry(SubnetKey::of(obs.addr))
            .or_insert_with(|| SubnetPrior {
                model: default_nig_prior(),
                last_used: now,
            });
        prior.model.observe(bps, discount);
        prior.last_used = now;
        debug!(addr = %obs.addr, bytes = obs.bytes, throughput_mbps = bps * 8.0 / 1_000_000.0,
            "observed passive throughput");
        active
    }

    pub(super) fn prune_history(&mut self, now: Instant) {
        self.parked.retain(|_, (_, expires)| *expires > now);
        if self.parked.len() > MAX_PARKED_CANDIDATES {
            let mut oldest: Vec<_> = self
                .parked
                .iter()
                .map(|(addr, (_, expires))| (*addr, *expires))
                .collect();
            oldest.sort_unstable_by_key(|(_, expires)| *expires);
            for (addr, _) in oldest
                .into_iter()
                .take(self.parked.len() - MAX_PARKED_CANDIDATES)
            {
                self.parked.remove(&addr);
            }
        }
        let retained: HashSet<_> = self
            .health
            .keys()
            .chain(self.parked.keys())
            .copied()
            .map(SubnetKey::of)
            .collect();
        self.subnet_priors.retain(|key, prior| {
            retained.contains(key) || now.duration_since(prior.last_used) < PARK_DURATION
        });
        let mut idle: Vec<_> = self
            .subnet_priors
            .iter()
            .filter(|(key, _)| !retained.contains(key))
            .map(|(key, prior)| (*key, prior.last_used))
            .collect();
        if idle.len() > MAX_IDLE_SUBNET_PRIORS {
            idle.sort_unstable_by_key(|(_, last_used)| *last_used);
            let excess = idle.len() - MAX_IDLE_SUBNET_PRIORS;
            for (key, _) in idle.into_iter().take(excess) {
                self.subnet_priors.remove(&key);
            }
        }
    }
}

async fn run_probe_loop(weak: Weak<Pool>, obs_rx: mpsc::Receiver<PassiveObs>) {
    let mut state = PoolState::new(obs_rx);
    let mut candidates = Vec::new();
    tokio::time::sleep(Duration::from_millis(rand::random_range(0..400))).await;
    loop {
        let Some(pool) = weak.upgrade() else {
            return;
        };
        refresh_domains(&pool, &mut state, &candidates).await;
        candidates = build_candidates(&pool, &mut state);
        recompute_order(&mut state, &pool.timing, &candidates);
        publish(&pool, &state, &candidates);
        run_cycle(&pool, &mut state, &candidates).await;
        recompute_order(&mut state, &pool.timing, &candidates);
        publish(&pool, &state, &candidates);
        log_cycle(&pool, &mut state, &candidates);
        let deadline = Instant::now() + next_due(&pool, &state, &candidates);
        drop(pool);
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                obs = state.obs_rx.recv(), if state.observations_open => {
                    let Some(pool) = weak.upgrade() else { return; };
                    process_observations(&pool, &mut state, &candidates, obs);
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

/// Consume bounded telemetry batches while DNS or another asynchronous job is
/// in flight. Receiving telemetry never restarts or delays the job's deadline.
async fn with_observations<T>(
    work: impl Future<Output = T>,
    pool: &Arc<Pool>,
    state: &mut PoolState,
    candidates: &[Candidate],
) -> T {
    tokio::pin!(work);
    loop {
        tokio::select! {
            output = &mut work => return output,
            obs = state.obs_rx.recv(), if state.observations_open => {
                process_observations(pool, state, candidates, obs);
                tokio::task::yield_now().await;
            }
        }
    }
}

fn process_observations(
    pool: &Arc<Pool>,
    state: &mut PoolState,
    candidates: &[Candidate],
    first: Option<PassiveObs>,
) {
    let Some(first) = first else {
        state.observations_open = false;
        return;
    };
    let now = Instant::now();
    let mut obs = Some(first);
    let mut changed = false;
    for _ in 0..OBSERVATION_BATCH {
        let Some(value) = obs.take().or_else(|| state.obs_rx.try_recv().ok()) else {
            break;
        };
        changed |= state.observe(value, pool.timing.throughput_discount, now);
    }
    if changed {
        publish(pool, state, candidates);
    }
    if state.last_feedback_warning.elapsed() >= Duration::from_secs(60) {
        let dropped = pool.dropped_observations.swap(0, Ordering::Relaxed);
        if dropped != 0 {
            warn!(pool = %pool.name, dropped, "pool telemetry capacity exceeded; new observations dropped");
        }
        state.last_feedback_warning = now;
    }
}

async fn refresh_domains(pool: &Arc<Pool>, state: &mut PoolState, candidates: &[Candidate]) {
    if state
        .resolved_at
        .is_some_and(|at| at.elapsed() < dns_refresh(pool, state))
    {
        return;
    }
    state.resolved_at = Some(Instant::now());
    for target in &pool.targets {
        if let TargetSpec::Domain(name) = &target.spec {
            let lookup = pool.resolver.resolve_all(name, AddressFamily::Dual);
            match with_observations(lookup, pool, state, candidates).await {
                Ok(ips) => {
                    state.resolved.insert(target.index, ips);
                }
                Err(e) => warn!(pool = %pool.name, target = target.index, domain = %name,
                    error = %format!("{e:#}"), cached = state.resolved.contains_key(&target.index),
                    "pool target did not resolve; keeping the previous addresses"),
            }
        }
    }
}

/// DNS refresh cadence: fast retry until every domain has an initial answer.
///
/// `interval` once every domain target has an answer, but `degraded_interval`
/// while any of them has none. Without that distinction a failed *first*
/// resolution would be retried only after a full `interval` — five minutes, by
/// default, during which a pool whose only target is a domain has no candidates
/// and serves nothing. The fast path is for acquiring an answer, not for
/// refreshing one.
fn dns_refresh(pool: &Pool, state: &PoolState) -> Duration {
    let missing = pool
        .targets
        .iter()
        .filter(|t| matches!(t.spec, TargetSpec::Domain(_)))
        .any(|t| !state.resolved.contains_key(&t.index));
    if missing {
        pool.timing.degraded_interval
    } else {
        pool.timing.interval
    }
}

/// How long until this pool next has work: the earliest due candidate, or the
/// next domain re-resolution, whichever comes first.
///
/// The DNS deadline has to be part of this. A pool whose only target is a domain
/// that has not resolved yet has *no candidates*, so a candidate-only calculation
/// would sleep for a full `interval` and strand the pool for five minutes — which
/// is exactly the case the faster first-resolution retry exists to cover.
fn next_due(pool: &Pool, state: &PoolState, candidates: &[Candidate]) -> Duration {
    let now = Instant::now();
    let soonest_probe = candidates
        .iter()
        .filter_map(|c| state.health.get(&c.addr))
        .map(|h| h.next_probe.saturating_duration_since(now))
        .min();
    let dns_deadline = match state.resolved_at {
        None => Duration::ZERO,
        Some(at) => dns_refresh(pool, state).saturating_sub(at.elapsed()),
    };
    // Only domain targets need re-resolution; a pool of literals and CIDRs has no
    // DNS deadline to honour at all.
    let has_domain = pool
        .targets
        .iter()
        .any(|t| matches!(t.spec, TargetSpec::Domain(_)));

    let wait = match (soonest_probe, has_domain) {
        (Some(p), true) => p.min(dns_deadline),
        (Some(p), false) => p,
        (None, true) => dns_deadline,
        // No candidates and nothing to resolve: every target is a literal or a
        // CIDR whose samples were all retired. Re-check on the healthy interval
        // rather than spinning.
        (None, false) => pool.timing.interval,
    };
    // Never busy-loop, even when several deadlines are already past.
    wait.max(Duration::from_millis(50))
}

/// Expand every target using cached DNS answers and apply the NAT64 projection.
fn build_candidates(pool: &Arc<Pool>, state: &mut PoolState) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();

    for target in &pool.targets {
        match &target.spec {
            TargetSpec::Ip(ip) => push_candidate(&mut out, target, *ip),
            TargetSpec::Cidr { .. } => {
                for ip in &target.sampled {
                    if !state.resampled.contains(ip) {
                        push_candidate(&mut out, target, *ip);
                    }
                }
                for ip in state.replacements.get(&target.index).into_iter().flatten() {
                    push_candidate(&mut out, target, *ip);
                }
            }
            TargetSpec::Domain(_) => {
                for ip in state.resolved.get(&target.index).into_iter().flatten() {
                    push_candidate(&mut out, target, *ip);
                }
            }
        }
    }

    // NAT64 projection: for each participating IPv4 candidate × prefix, one
    // synthesized IPv6 candidate. Ranked independently of its original, because
    // a slow NAT64 gateway says nothing about the native IPv4 path.
    if let Some(n) = &pool.nat64 {
        let mut synthesized: Vec<Candidate> = Vec::new();
        for c in &out {
            let IpAddr::V4(v4) = c.addr else { continue };
            let participates = match &n.from {
                None => true,
                Some(list) => list.contains(&c.target),
            };
            if !participates {
                continue;
            }
            for prefix in &n.prefixes {
                let addr = IpAddr::V6(prefix.synthesize(v4));
                let mut tags = vec![TAG_NAT64.to_string(), TAG_IPV6.to_string()];
                // Custom tags follow the target, so a `select` on a custom tag
                // reaches the projection of that target too.
                for t in pool.targets[c.target].custom_tags.iter() {
                    tags.push(t.clone());
                }
                synthesized.push(Candidate {
                    addr,
                    target: c.target,
                    tags,
                });
            }
        }
        out.extend(synthesized);
    }

    // `from` naming a target that yields no IPv4 is not an error — a domain's
    // records can change — but it is worth saying once per cycle.
    if let Some(n) = &pool.nat64 {
        for i in n.from.iter().flatten() {
            let has_v4 = out
                .iter()
                .any(|c| c.target == *i && matches!(c.addr, IpAddr::V4(_)));
            if !has_v4 {
                warn!(
                    pool = %pool.name,
                    target = *i,
                    "nat64.from names a target with no IPv4 candidate, so it contributes no \
                     synthesized address"
                );
            }
        }
    }

    // Keep one candidate per target provenance even when several targets resolve
    // to the same address. `select` addresses target indices and tags, so
    // collapsing here would erase the later target's identity. Endpoint-level
    // work below is deduplicated by address instead: health is keyed by `IpAddr`,
    // probes run once per address, and the ranking contains each address once.

    // Give every new address a health entry, due immediately.
    // New arrivals inherit from the parked map first, then from the subnet prior,
    // so Kalman and NIG state survives a DNS rotation cycle.
    let now = Instant::now();
    let live: HashSet<IpAddr> = out.iter().map(|c| c.addr).collect();

    // Expire historical priors before newcomers can make their subnet live.
    // Enforce the new parked-set cap after returning candidates are restored.
    state.prune_history(now);

    // Move departing candidates into the parked map rather than discarding their state.
    let park_until = now + PARK_DURATION;
    let departing: Vec<IpAddr> = state
        .health
        .keys()
        .filter(|a| !live.contains(*a))
        .copied()
        .collect();
    for addr in departing {
        if let Some(h) = state.health.remove(&addr) {
            state.parked.insert(addr, (h, park_until));
        }
    }
    for c in &out {
        if !state.health.contains_key(&c.addr) {
            let h = if let Some((parked_h, _)) = state.parked.remove(&c.addr) {
                // Restore the full history from the parked map.
                parked_h
            } else {
                // New candidate: inherit subnet prior when available.
                let mut h = Health::new(
                    now,
                    pool.timing.degraded_interval,
                    pool.timing.kalman_q,
                    pool.timing.kalman_r,
                );
                let key = SubnetKey::of(c.addr);
                if let Some(subnet) = state.subnet_priors.get(&key) {
                    h.nig = subnet.model.clone();
                }
                h
            };
            state.health.insert(c.addr, h);
        }
    }

    state.prune_history(now);
    out
}

fn push_candidate(out: &mut Vec<Candidate>, target: &Target, addr: IpAddr) {
    let mut tags = Vec::with_capacity(target.custom_tags.len() + 1);
    tags.push(
        match addr {
            IpAddr::V4(_) => TAG_IPV4,
            IpAddr::V6(_) => TAG_IPV6,
        }
        .to_string(),
    );
    for t in target.custom_tags.iter() {
        tags.push(t.clone());
    }
    out.push(Candidate {
        addr,
        target: target.index,
        tags,
    });
}

/// Probe every due candidate and fold the results into health.
async fn run_cycle(pool: &Arc<Pool>, state: &mut PoolState, candidates: &[Candidate]) {
    let now = Instant::now();
    let mut seen = HashSet::with_capacity(candidates.len());
    let due: Vec<Candidate> = candidates
        .iter()
        // Candidate records preserve target/tag provenance, but an address is one
        // endpoint and must be probed only once per cycle.
        .filter(|c| seen.insert(c.addr))
        .filter(|c| match state.health.get(&c.addr) {
            Some(h) => h.next_probe <= now,
            // A candidate with no health entry yet has never been probed, so it
            // is due immediately.
            None => true,
        })
        .cloned()
        .collect();
    if due.is_empty() {
        return;
    }

    let mut due = due.into_iter();
    let mut set = tokio::task::JoinSet::new();
    loop {
        while set.len() < pool.timing.max_concurrent_probes {
            let Some(c) = due.next() else {
                break;
            };
            let pool = pool.clone();
            let budget = match (&pool.nat64, c.tags.iter().any(|t| t == TAG_NAT64)) {
                (Some(n), true) => n.timeout,
                _ => pool.probe.timeout,
            };
            set.spawn(async move { (c.addr, probe_one(&pool, c.addr, budget).await) });
        }
        if set.is_empty() {
            break;
        }
        let Some(joined) = with_observations(set.join_next(), pool, state, candidates).await else {
            break;
        };
        let Ok((addr, outcome)) = joined else {
            warn!(pool = %pool.name, "a probe task panicked");
            continue;
        };
        let Some(h) = state.health.get_mut(&addr) else {
            continue;
        };
        match outcome {
            Ok(rtt) => {
                let was_degraded = h.degraded;
                h.record_success(rtt, pool.timing.interval, pool.timing.degraded_interval);
                if was_degraded {
                    info!(
                        pool = %pool.name,
                        candidate = %addr,
                        rtt_ms = rtt.as_millis(),
                        "candidate recovered and re-entered the ranking"
                    );
                }
            }
            Err(e) => {
                let was_degraded = h.degraded;
                h.record_failure(
                    pool.timing.fail_threshold,
                    pool.timing.interval,
                    pool.timing.degraded_interval,
                );
                if !was_degraded && h.degraded {
                    warn!(
                        pool = %pool.name,
                        candidate = %addr,
                        failures = h.consecutive_failures,
                        error = %format!("{e:#}"),
                        "candidate degraded; excluded from the ranking"
                    );
                } else {
                    debug!(
                        pool = %pool.name,
                        candidate = %addr,
                        failures = h.consecutive_failures,
                        error = %format!("{e:#}"),
                        "probe failed"
                    );
                }
            }
        }
    }

    state.resample_dead(pool, candidates);
}

impl PoolState {
    fn new(obs_rx: mpsc::Receiver<PassiveObs>) -> Self {
        Self {
            health: HashMap::new(),
            order: Vec::new(),
            parked: HashMap::new(),
            subnet_priors: HashMap::new(),
            obs_rx,
            observations_open: true,
            last_feedback_warning: Instant::now(),
            last_logged_best: None,
            last_logged_healthy: 0,
            resampled: HashSet::new(),
            replacements: HashMap::new(),
            resolved: HashMap::new(),
            resolved_at: None,
        }
    }

    /// Replace a CIDR sample that has backed off to the cap without ever
    /// succeeding.
    ///
    /// Sampling a `/12` will sometimes draw an address nothing answers on.
    /// Without this the pool would carry that dead weight for the life of the
    /// process; with it, the sample space is eventually explored while measured
    /// endpoints are never discarded.
    fn resample_dead(&mut self, pool: &Arc<Pool>, candidates: &[Candidate]) {
        let mut reserved: HashSet<IpAddr> = self.health.keys().copied().collect();
        reserved.extend(self.resampled.iter().copied());
        let mut planned_keys: HashSet<(usize, IpAddr)> = HashSet::new();
        let mut planned: Vec<(usize, IpAddr, IpAddr)> = Vec::new();

        for c in candidates {
            let Some(h) = self.health.get(&c.addr) else {
                continue;
            };
            // Only replace an endpoint that has never answered. An endpoint that
            // worked before may simply be in a temporary outage, and its RTT history
            // remains useful when it recovers.
            if !h.degraded || h.rtt().is_some() || h.backoff < pool.timing.interval {
                continue;
            }
            let target = &pool.targets[c.target];
            let TargetSpec::Cidr { net, sample } = &target.spec else {
                continue;
            };
            if sample.is_none() {
                continue;
            }
            if !planned_keys.insert((c.target, c.addr)) {
                continue;
            }
            let Some(new_addr) = draw_fresh_sample(net, &reserved) else {
                continue;
            };
            reserved.insert(new_addr);
            planned.push((c.target, c.addr, new_addr));
        }

        let mut retired = HashSet::new();
        for (target, dead, replacement) in planned {
            info!(
                pool = %pool.name,
                target,
                dead = %dead,
                replacement = %replacement,
                "replacing a CIDR sample that never answered"
            );
            replace_recorded_sample(&mut self.replacements, target, dead, replacement);
            retired.insert(dead);
        }

        // Retire shared endpoint state only after all target provenances have been
        // inspected, so one target cannot hide another by removing health early.
        for dead in retired {
            self.resampled.insert(dead);
            self.health.remove(&dead);
            self.order.retain(|a| *a != dead);
        }
    }
}

/// Draw an address not already present in the pool. Starting at a random offset
/// keeps CIDR sampling distributed; checking at most `reserved.len() + 1`
/// consecutive addresses guarantees a free one is found whenever one exists.
fn draw_fresh_sample(net: &IpNet, reserved: &HashSet<IpAddr>) -> Option<IpAddr> {
    let size = network_size(net);
    if size == 0 {
        return None;
    }
    let attempts = ((reserved.len() as u128).saturating_add(1)).min(size) as usize;
    let start = rand::random_range(0..size);
    for step in 0..attempts {
        let offset = start.wrapping_add(step as u128) % size;
        let addr = offset_into(net, offset);
        if !reserved.contains(&addr) {
            return Some(addr);
        }
    }
    None
}

/// Rotate one active CIDR replacement in place rather than keeping a history.
fn replace_recorded_sample(
    replacements: &mut HashMap<usize, Vec<IpAddr>>,
    target: usize,
    dead: IpAddr,
    replacement: IpAddr,
) {
    let active = replacements.entry(target).or_default();
    active.retain(|addr| *addr != dead);
    if !active.contains(&replacement) {
        active.push(replacement);
    }
}

/// Recompute the preference order and store it back on the state.
///
/// Storing it is what makes hysteresis work at all: the margin is applied
/// relative to the *previous* order, so an order that is recomputed and then
/// discarded leaves every cycle starting from scratch — which is a plain sort, and
/// exactly the churn the margin exists to prevent.
fn recompute_order(state: &mut PoolState, timing: &ProbeTiming, candidates: &[Candidate]) {
    let order = reorder_with_hysteresis(&state.order, state, timing, candidates);
    state.order = order;
}

/// Publish the current order and every view's answer.
fn publish(pool: &Arc<Pool>, state: &PoolState, candidates: &[Candidate]) {
    let old = pool
        .ranking
        .read()
        .expect("pool ranking lock poisoned")
        .clone();
    let models: HashMap<_, _> = state
        .health
        .iter()
        .filter_map(|(addr, h)| {
            if h.degraded {
                return None;
            }
            Some((
                *addr,
                Arc::new(SelectionModel {
                    addr: *addr,
                    rtt: h.rtt()?,
                    throughput: h.nig.clone(),
                }),
            ))
        })
        .collect();
    let per_view = pool
        .views
        .iter()
        .enumerate()
        .map(|(index, view)| {
            let eligible: HashSet<_> = candidates
                .iter()
                .filter(|c| c.matches(&view.selectors))
                .map(|c| c.addr)
                .collect();
            let ordered: Vec<_> = state
                .order
                .iter()
                .filter(|addr| eligible.contains(addr))
                .filter_map(|addr| models.get(addr).cloned())
                .collect();
            let previous = old
                .per_view
                .get(index)
                .and_then(|v| v.ordered.get(v.incumbent.load(Ordering::Relaxed)))
                .map(|m| m.addr);
            let incumbent = previous
                .and_then(|addr| ordered.iter().position(|m| m.addr == addr))
                .unwrap_or(0);
            let fallback = pool.fallback.and_then(|t| {
                candidates
                    .iter()
                    .find(|c| c.target == t && c.matches(&view.selectors))
                    .map(|c| c.addr)
            });
            ViewRanking {
                ordered,
                fallback,
                incumbent: AtomicUsize::new(incumbent),
            }
        })
        .collect();
    *pool.ranking.write().expect("pool ranking lock poisoned") = Arc::new(Ranking { per_view });
}

/// Rebuild the preference order from the previous one, promoting a candidate
/// only when it beats the one ahead of it by a margin.
///
/// Starting from the previous order rather than sorting afresh is what gives
/// stability: two endpoints a millisecond apart would otherwise trade places
/// every cycle, moving traffic between edges for no gain and invalidating the
/// upstream-certificate mirror each time. The margin is applied pairwise, so no
/// pair reorders on noise — not merely the top two.
fn reorder_with_hysteresis(
    prev: &[IpAddr],
    state: &PoolState,
    timing: &ProbeTiming,
    candidates: &[Candidate],
) -> Vec<IpAddr> {
    let healthy = |addr: &IpAddr| -> Option<f64> {
        let h = state.health.get(addr)?;
        if h.degraded || !h.kalman.is_initialized() {
            return None;
        }
        Some(
            h.kalman.estimate().as_secs_f64()
                + timing.score_payload_bytes as f64 / h.nig.typical_bps(),
        )
    };
    let live: HashSet<IpAddr> = candidates.iter().map(|c| c.addr).collect();

    // Keep the previous order for endpoints still healthy and still present.
    let mut order: Vec<IpAddr> = prev
        .iter()
        .filter(|a| live.contains(*a) && healthy(a).is_some())
        .copied()
        .collect();

    // Append newcomers, best first, so a new endpoint enters at its measured
    // position rather than at the front.
    let mut known: HashSet<IpAddr> = order.iter().copied().collect();
    let mut fresh: Vec<(IpAddr, f64)> = candidates
        .iter()
        .filter(|c| known.insert(c.addr))
        .filter_map(|c| healthy(&c.addr).map(|s| (c.addr, s)))
        .collect();
    fresh.sort_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    order.extend(fresh.into_iter().map(|(a, _)| a));

    // Insertion pass with a threshold: move each entry forward only while it
    // beats its predecessor by the margin.
    for i in 1..order.len() {
        let mut j = i;
        while j > 0 {
            let Some(cur) = healthy(&order[j]) else { break };
            let Some(ahead) = healthy(&order[j - 1]) else {
                break;
            };
            if beats(cur, ahead) {
                order.swap(j, j - 1);
                j -= 1;
            } else {
                break;
            }
        }
    }

    // Log top 5 ranked candidates when debug logging is enabled
    if tracing::enabled!(tracing::Level::DEBUG) && !order.is_empty() {
        for (i, addr) in order.iter().take(5).enumerate() {
            if let Some(h) = state.health.get(addr) {
                let s = healthy(addr).expect("ranked endpoint has a measurement");
                debug!(
                    rank = i + 1,
                    addr = %addr,
                    score_s = format!("{:.3}", s),
                    rtt_ms = h.rtt().map(|d| d.as_millis()),
                    "pool baseline candidate"
                );
            }
        }
    }

    order
}

/// Whether `challenger` is enough faster than `incumbent` to overtake it.
///
/// The score is in seconds, so the margin is applied in seconds. 20% or 5ms,
/// whichever is larger.
fn beats(challenger: f64, incumbent: f64) -> bool {
    let margin = (incumbent * HYSTERESIS_FRACTION).max(HYSTERESIS_FLOOR.as_secs_f64());
    challenger + margin < incumbent
}

fn log_cycle(pool: &Arc<Pool>, state: &mut PoolState, candidates: &[Candidate]) {
    let live: HashSet<IpAddr> = candidates.iter().map(|c| c.addr).collect();
    let total = live.len();
    let healthy = live
        .iter()
        .filter(|addr| state.health.get(*addr).is_some_and(|h| !h.degraded))
        .count();
    let snapshot = {
        let guard = pool.ranking.read().expect("pool ranking lock poisoned");
        guard.clone()
    };
    let best = snapshot
        .per_view
        .first()
        .and_then(|v| v.ordered.first().map(|m| m.addr));
    let best_rtt = best
        .and_then(|a| state.health.get(&a))
        .and_then(|h| h.rtt())
        .map(|d| d.as_millis());

    // Only log at INFO level when the state has changed; otherwise use DEBUG.
    let changed = state.last_logged_best != best || state.last_logged_healthy != healthy;
    if changed {
        info!(
            pool = %pool.name,
            healthy,
            total,
            best = best.map(|b| b.to_string()).unwrap_or_else(|| "<none>".into()),
            best_rtt_ms = best_rtt.unwrap_or(0),
            "probe cycle complete"
        );
        state.last_logged_best = best;
        state.last_logged_healthy = healthy;
    } else {
        debug!(
            pool = %pool.name,
            healthy,
            total,
            "probe cycle complete (no change)"
        );
    }

    if healthy == 0 && total > 0 {
        warn!(
            pool = %pool.name,
            total,
            "every candidate is degraded; consumers fall back until one recovers"
        );
    }
}

// ---------------------------------------------------------------------------
// Probing one candidate
// ---------------------------------------------------------------------------

/// Probe one address, returning the measured round-trip time.
async fn probe_one(pool: &Pool, addr: IpAddr, budget: Duration) -> Result<Duration> {
    let target = SocketAddr::new(addr, pool.probe.port);
    timeout(budget, probe_exchange(&pool.probe.kind, target))
        .await
        .map_err(|_| anyhow!("probe timed out after {budget:?}"))?
}

async fn probe_exchange(kind: &ProbeKind, target: SocketAddr) -> Result<Duration> {
    match kind {
        ProbeKind::Tcp => {
            let started = Instant::now();
            connect(target).await?;
            Ok(started.elapsed())
        }

        ProbeKind::Tls(tls) => {
            let (_stream, started) = tls_connect(tls, target).await?;
            Ok(started.elapsed())
        }

        ProbeKind::Http {
            request,
            expect_status,
            tls: Some(tls),
        } => {
            let (stream, started) = tls_connect(tls, target).await?;
            http_exchange(stream, started, request, expect_status).await
        }

        ProbeKind::Http {
            request,
            expect_status,
            tls: None,
        } => {
            let started = Instant::now();
            let stream = connect(target).await?;
            http_exchange(stream, started, request, expect_status).await
        }
    }
}

async fn connect(target: SocketAddr) -> Result<TcpStream> {
    let tcp = TcpStream::connect(target)
        .await
        .with_context(|| format!("connecting to {target}"))?;
    tcp.set_nodelay(true).ok();
    Ok(tcp)
}

/// Dial and complete the TLS handshake, retrying when the server rejects ECH.
///
/// Returns the stream together with the instant the *successful* attempt began,
/// so that a retry does not charge the abandoned attempt to the measured RTT —
/// and neither does the DoH lookup that a refetch may have needed.
async fn tls_connect(
    tls: &TlsProbe,
    target: SocketAddr,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, Instant)> {
    let name = ServerName::try_from(tls.sni.clone())
        .map_err(|_| anyhow!("invalid probe sni {:?}", tls.sni))?;

    let (provider, alpn, require_ech, max_retries) = match &tls.config {
        TlsSource::Plain(config) => {
            let connector = TlsConnector::from(config.clone());
            let started = Instant::now();
            let tcp = connect(target).await?;
            let stream = connector
                .connect(name, tcp)
                .await
                .context("probe TLS handshake")?;
            return Ok((stream, started));
        }
        TlsSource::Ech {
            provider,
            alpn,
            require_ech,
            max_retries,
        } => (provider, alpn, *require_ech, *max_retries),
    };

    let mut attempt = 0u32;
    loop {
        // Cached after the first call, and refreshed on the HTTPS record's own
        // TTL rather than per probe.
        let client = provider
            .client(&tls.sni, alpn)
            .await
            .context("assembling the probe ECH client config")?;
        let generation = client.generation;
        let connector = TlsConnector::from(client.client_config);

        let started = Instant::now();
        let tcp = connect(target).await?;
        match connector.connect(name.clone(), tcp).await {
            Ok(stream) => {
                // Real ECH aborts the handshake on rejection, but GREASE — what
                // `require_ech = false` falls back to when no ECHConfig is
                // published — completes with the SNI in the clear. Reading the
                // status is what tells the two apart.
                let status = stream.get_ref().1.ech_status();
                if require_ech && status != EchStatus::Accepted {
                    bail!("probe required ECH but the handshake status was {status:?}");
                }
                return Ok((stream, started));
            }
            Err(e) if is_ech_reject_io(&e) && attempt < max_retries => {
                attempt += 1;
                debug!(
                    sni = %tls.sni,
                    %target,
                    attempt,
                    "probe ECH rejected; refreshing the config and retrying"
                );
                // The server's published key rotated out from under the cached
                // config. Only evict the generation this handshake used; a
                // slower rejection must not discard a concurrent refresh.
                provider
                    .invalidate_after_rejection(&tls.sni, generation)
                    .await;
            }
            Err(e) => return Err(e).context("probe TLS handshake"),
        }
    }
}

/// Send the prepared request and read exactly as far as the status line.
async fn http_exchange<S>(
    mut stream: S,
    started: Instant,
    request: &str,
    expect_status: &[u16],
) -> Result<Duration>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(request.as_bytes())
        .await
        .context("sending the probe request")?;
    stream.flush().await.context("flushing the probe request")?;

    let mut buf = [0u8; STATUS_LINE_BUF];
    let mut have = 0usize;
    let mut rtt = None;
    while have < buf.len() {
        let n = stream
            .read(&mut buf[have..])
            .await
            .context("reading the probe response")?;
        if n == 0 {
            break;
        }
        // The clock stops at the first byte: that is when the origin
        // demonstrably answered, and reading on would measure the response size
        // instead of the path.
        rtt.get_or_insert_with(|| started.elapsed());
        // Only the new bytes need scanning, plus the one before them in case the
        // CR and the LF arrived in different reads.
        let from = have.saturating_sub(1);
        have += n;
        if buf[from..have].windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }

    let rtt = rtt.ok_or_else(|| anyhow!("upstream closed without sending a response"))?;
    let status = parse_status(&buf[..have])?;
    if !expect_status.contains(&status) {
        bail!("probe response status {status} is not among the accepted {expect_status:?}");
    }
    Ok(rtt)
}

/// Extract the status code from an HTTP response's first line.
fn parse_status(bytes: &[u8]) -> Result<u16> {
    let text = std::str::from_utf8(bytes).context("probe response is not valid UTF-8")?;
    let line = text.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("empty probe response"))?;
    if !version.starts_with("HTTP/") {
        bail!("probe response does not start with an HTTP status line: {line:?}");
    }
    let code = parts
        .next()
        .ok_or_else(|| anyhow!("probe response has no status code: {line:?}"))?;
    code.parse::<u16>()
        .with_context(|| format!("probe response status {code:?} is not a number"))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(super) fn fixture(payload: u64) -> (Arc<Pool>, PoolState, Vec<Candidate>) {
        let (tx, rx) = mpsc::channel(OBSERVATION_CAPACITY);
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        let resolver = DnsResolver::new(
            "test".into(),
            crate::dns::ResolverSpec::System
                .build(AddressFamily::Dual)
                .unwrap(),
            None,
            None,
        );
        let pool = Arc::new(Pool {
            name: "test".into(),
            targets: vec![Target {
                index: 0,
                spec: TargetSpec::Ip(addr),
                custom_tags: Arc::from([]),
                sampled: Vec::new(),
            }],
            probe: ProbePlan {
                port: 9,
                timeout: Duration::from_millis(20),
                kind: ProbeKind::Tcp,
            },
            timing: ProbeTiming {
                interval: Duration::from_secs(300),
                degraded_interval: Duration::from_secs(30),
                fail_threshold: 2,
                max_concurrent_probes: 16,
                score_payload_bytes: payload,
                throughput_discount: 0.95,
                kalman_q: DEFAULT_KALMAN_Q,
                kalman_r: DEFAULT_KALMAN_R,
            },
            nat64: None,
            fallback: None,
            resolver,
            views: vec![View {
                selectors: Vec::new(),
            }],
            ranking: RwLock::new(Arc::new(Ranking::empty(1))),
            obs_tx: (payload != 0).then_some(tx),
            dropped_observations: AtomicU64::new(0),
        });
        let mut state = PoolState::new(rx);
        let mut h = Health::new(
            Instant::now(),
            Duration::from_secs(30),
            DEFAULT_KALMAN_Q,
            DEFAULT_KALMAN_R,
        );
        h.record_success(
            Duration::from_millis(25),
            pool.timing.interval,
            pool.timing.degraded_interval,
        );
        state.health.insert(addr, h);
        let candidates = vec![Candidate {
            addr,
            target: 0,
            tags: vec!["ipv4".into()],
        }];
        recompute_order(&mut state, &pool.timing, &candidates);
        publish(&pool, &state, &candidates);
        (pool, state, candidates)
    }

    pub(crate) fn observer() -> (PoolHandle, mpsc::Receiver<PassiveObs>) {
        let (pool, state, _) = fixture(1_000_000);
        (PoolBuilder::handle(pool, 0), state.obs_rx)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::fixture;
    use super::*;
    use crate::scoring::default_nig_prior;

    /// `Host` carries the port exactly when it is not the scheme's default, and
    /// the request target carries the query. Both are rendered once at startup,
    /// so getting them wrong here would be wrong for every candidate forever.
    #[test]
    fn the_probe_request_is_rendered_per_rfc_9110() {
        let rendered = |raw: &str| {
            let url: Url = raw.parse().unwrap();
            let host = url.host_str().unwrap().to_string();
            http_request(&url, &host)
        };

        // Default port for the scheme: omitted, even when written out.
        assert!(rendered("https://x.example/p").contains("\r\nHost: x.example\r\n"));
        assert!(rendered("https://x.example:443/p").contains("\r\nHost: x.example\r\n"));
        assert!(rendered("http://x.example:80/p").contains("\r\nHost: x.example\r\n"));

        // Non-default port: present, because the origin needs it to pick a vhost.
        assert!(rendered("https://x.example:8443/p").contains("\r\nHost: x.example:8443\r\n"));
        assert!(rendered("http://x.example:8080/p").contains("\r\nHost: x.example:8080\r\n"));

        // The request target is the path plus the query, never the whole URL.
        let req = rendered("https://x.example/cdn-cgi/trace?v=1");
        assert!(
            req.starts_with("GET /cdn-cgi/trace?v=1 HTTP/1.1\r\n"),
            "{req:?}"
        );
        assert!(rendered("https://x.example").starts_with("GET / HTTP/1.1\r\n"));

        // `Connection: close`, so the origin does not wait for a second request.
        assert!(rendered("https://x.example/p").ends_with("Connection: close\r\n\r\n"));
    }

    /// URL syntax brackets an IPv6 literal in an HTTP authority, while rustls
    /// accepts it as a `ServerName::IpAddress` only without those brackets.
    #[test]
    fn an_ipv6_probe_url_uses_a_bare_tls_identity() {
        let url: Url = "https://[2001:db8::1]/health".parse().unwrap();
        assert_eq!(url.host_str(), Some("[2001:db8::1]"));
        let tls_name = tls_name_from_url(&url);
        assert_eq!(tls_name, "2001:db8::1");
        assert!(ServerName::try_from(tls_name).is_ok());

        let request = http_request(&url, url.host_str().unwrap());
        assert!(request.contains("\r\nHost: [2001:db8::1]\r\n"));
    }

    /// The status line may arrive split across reads, including between the CR
    /// and the LF — the incremental scan must still find it.
    #[test]
    fn a_status_line_split_across_reads_is_still_parsed() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // A duplex whose server half dribbles the response out one CRLF half
            // at a time.
            let (client, mut server) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let mut sink = [0u8; 256];
                let _ = server.read(&mut sink).await;
                for chunk in [&b"HTTP/1.1 204 No Content\r"[..], &b"\nX: y\r\n\r\n"[..]] {
                    server.write_all(chunk).await.unwrap();
                    server.flush().await.unwrap();
                    tokio::task::yield_now().await;
                }
            });
            http_exchange(client, Instant::now(), "GET / HTTP/1.1\r\n\r\n", &[204])
                .await
                .unwrap();
        });
    }

    /// A response the probe can read but did not ask for fails the candidate.
    #[test]
    fn an_unexpected_status_fails_the_probe() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (client, mut server) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let mut sink = [0u8; 256];
                let _ = server.read(&mut sink).await;
                server
                    .write_all(b"HTTP/1.1 503 Unavailable\r\n\r\n")
                    .await
                    .unwrap();
            });
            let err = http_exchange(client, Instant::now(), "GET / HTTP/1.1\r\n\r\n", &[200])
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("503"), "unhelpful: {err}");
        });
    }

    #[test]
    fn target_kind_is_inferred() {
        assert_eq!(
            TargetSpec::parse("cf.example.com").unwrap(),
            TargetSpec::Domain("cf.example.com".into())
        );
        assert_eq!(
            TargetSpec::parse("1.2.3.4").unwrap(),
            TargetSpec::Ip("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            TargetSpec::parse("2606:4700::1").unwrap(),
            TargetSpec::Ip("2606:4700::1".parse().unwrap())
        );
        // A CIDR is detected before the hostname rule, which is why a value with
        // no colon still reads as a network.
        match TargetSpec::parse("104.16.0.0/12[4]").unwrap() {
            TargetSpec::Cidr { net, sample } => {
                assert_eq!(net, "104.16.0.0/12".parse::<IpNet>().unwrap());
                assert_eq!(sample, Some(4));
            }
            other => panic!("expected CIDR, got {other:?}"),
        }
    }

    /// The guard that a documentation note cannot provide: a large prefix
    /// without a sample count is refused, naming the fix.
    #[test]
    fn unbounded_cidr_expansion_is_rejected() {
        let err = TargetSpec::parse("104.16.0.0/12").unwrap_err().to_string();
        assert!(err.contains("sample count"), "unhelpful message: {err}");
        // A small prefix needs no sample count.
        assert!(TargetSpec::parse("192.0.2.0/29").is_ok());
    }

    #[test]
    fn malformed_targets_are_rejected() {
        for bad in [
            "",
            "   ",
            "not a cidr/xx",
            "10.0.0.0/33",
            "1.2.3.4[2]",         // sampling only applies to a CIDR
            "192.0.2.0/29[0]",    // zero samples
            "192.0.2.0/29[abc]",  // non-numeric
            "2606:4700::/32[4]x", // trailing junk
            "bad:host",           // colon in a domain
        ] {
            assert!(
                TargetSpec::parse(bad).is_err(),
                "{bad:?} must not parse as a target"
            );
        }
    }

    #[test]
    fn sampling_stays_inside_the_network_and_is_bounded() {
        let net: IpNet = "104.16.0.0/12".parse().unwrap();
        let drawn = draw_sample(&net, Some(4));
        assert_eq!(drawn.len(), 4);
        for a in &drawn {
            assert!(net.contains(a), "{a} outside {net}");
        }
        // Asking for more than the network holds yields only what exists, and
        // terminates rather than spinning on collisions.
        let tiny: IpNet = "192.0.2.0/30".parse().unwrap();
        let all = draw_sample(&tiny, Some(50));
        assert!(all.len() <= 4, "drew {} from a /30", all.len());
    }

    #[test]
    fn ipv6_sampling_stays_inside_the_network() {
        let net: IpNet = "2606:4700::/32".parse().unwrap();
        let drawn = draw_sample(&net, Some(4));
        assert_eq!(drawn.len(), 4);
        for a in &drawn {
            assert!(net.contains(a), "{a} outside {net}");
        }
    }

    fn candidate(addr: &str, target: usize, tags: &[&str]) -> Candidate {
        Candidate {
            addr: addr.parse().unwrap(),
            target,
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Indices address *targets* and tags address candidates; both are unioned.
    #[test]
    fn select_unions_indices_and_tags() {
        let c = candidate("1.2.3.4", 1, &["ipv4", "edge"]);

        assert!(c.matches(&[]), "an empty filter selects everything");
        assert!(c.matches(&[Selector::Index(1)]));
        assert!(!c.matches(&[Selector::Index(0)]));
        assert!(c.matches(&[Selector::Tag("ipv4".into())]));
        assert!(c.matches(&[Selector::Tag("edge".into())]));
        assert!(!c.matches(&[Selector::Tag("ipv6".into())]));
        // OR across kinds.
        assert!(c.matches(&[Selector::Tag("ipv6".into()), Selector::Index(1)]));
        assert!(!c.matches(&[Selector::Tag("ipv6".into()), Selector::Index(0)]));
    }

    #[test]
    fn cidr_replacement_chain_keeps_only_active_addresses() {
        let target = 3usize;
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let c: IpAddr = "192.0.2.3".parse().unwrap();
        let d: IpAddr = "192.0.2.4".parse().unwrap();
        let mut replacements = HashMap::from([(target, vec![a])]);

        replace_recorded_sample(&mut replacements, target, a, b);
        replace_recorded_sample(&mut replacements, target, b, c);
        replace_recorded_sample(&mut replacements, target, c, d);
        assert_eq!(replacements.get(&target), Some(&vec![d]));
    }

    #[test]
    fn duplicate_address_provenance_is_ranked_once() {
        let addr = "1.1.1.1";
        let candidates = vec![
            candidate(addr, 0, &["ipv4", "first"]),
            candidate(addr, 1, &["ipv4", "second"]),
        ];
        let state = state_with(&[(addr, Some(20), false)]);
        let timing = ProbeTiming {
            interval: Duration::from_secs(300),
            degraded_interval: Duration::from_secs(30),
            fail_threshold: 2,
            max_concurrent_probes: 16,
            score_payload_bytes: 0,
            throughput_discount: 0.95,
            kalman_q: 0.01,
            kalman_r: 0.1,
        };
        let order = reorder_with_hysteresis(&[], &state, &timing, &candidates);
        assert_eq!(order, vec![addr.parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn hysteresis_margin_ignores_noise_but_yields_to_real_gains() {
        // 1ms apart at 50ms: noise, no overtake.
        assert!(!beats(0.049, 0.050));
        // 20% better: overtake.
        assert!(beats(0.035, 0.050));
        // At sub-millisecond RTTs the absolute floor governs.
        assert!(!beats(0.0009, 0.001));
        assert!(beats(0.001, 0.010));
    }

    fn state_with(rtts: &[(&str, Option<u64>, bool)]) -> PoolState {
        let (tx, rx) = mpsc::channel(OBSERVATION_CAPACITY);
        let mut health = HashMap::new();
        for (addr, ms, degraded) in rtts {
            let mut h = Health::new(
                Instant::now(),
                Duration::from_secs(30),
                DEFAULT_KALMAN_Q,
                DEFAULT_KALMAN_R,
            );
            if let Some(ms) = ms {
                // Simulate convergence by feeding the same value repeatedly.
                for _ in 0..30 {
                    h.kalman.update(Duration::from_millis(*ms));
                }
            }
            h.degraded = *degraded;
            health.insert(addr.parse::<IpAddr>().unwrap(), h);
        }
        drop(tx); // drop the sender so the receiver never blocks
        PoolState {
            health,
            obs_rx: rx,
            ..PoolState::new(mpsc::channel(OBSERVATION_CAPACITY).1)
        }
    }

    /// Hysteresis only works if the computed order is *kept*.
    ///
    /// A regression test for a real defect: `publish` computed the order and
    /// dropped it, leaving `state.order` permanently empty. Every cycle then
    /// started from scratch — a plain RTT sort, which is exactly the churn the
    /// margin exists to prevent. Asserting through `recompute_order` catches that,
    /// where a test calling `reorder_with_hysteresis` directly cannot: passing
    /// `prev` by hand is precisely the step that was missing in production.
    #[test]
    fn the_computed_order_is_stored_so_hysteresis_persists() {
        let candidates = vec![
            candidate("1.1.1.1", 0, &["ipv4"]),
            candidate("2.2.2.2", 0, &["ipv4"]),
        ];

        // Cycle 1: nothing measured yet, so nothing is ranked.
        let mut state = state_with(&[("1.1.1.1", None, false), ("2.2.2.2", None, false)]);
        let timing = ProbeTiming {
            interval: Duration::from_secs(300),
            degraded_interval: Duration::from_secs(30),
            fail_threshold: 2,
            max_concurrent_probes: 16,
            score_payload_bytes: 0,
            throughput_discount: 0.95,
            kalman_q: 0.01,
            kalman_r: 0.1,
        };
        recompute_order(&mut state, &timing, &candidates);
        assert!(state.order.is_empty());

        // Cycle 2: 1.1.1.1 measured first and leads.
        state
            .health
            .get_mut(&"1.1.1.1".parse().unwrap())
            .unwrap()
            .kalman
            .update(Duration::from_millis(50));
        for _ in 0..29 {
            state
                .health
                .get_mut(&"1.1.1.1".parse().unwrap())
                .unwrap()
                .kalman
                .update(Duration::from_millis(50));
        }
        recompute_order(
            &mut state,
            &ProbeTiming {
                interval: Duration::from_secs(300),
                degraded_interval: Duration::from_secs(30),
                fail_threshold: 2,
                max_concurrent_probes: 16,
                score_payload_bytes: 0,
                throughput_discount: 0.95,
                kalman_q: 0.01,
                kalman_r: 0.1,
            },
            &candidates,
        );
        assert_eq!(
            state.order,
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()],
            "the order must be stored, not recomputed and discarded"
        );

        // Cycle 3: 2.2.2.2 arrives 1ms faster. Stored order + margin means the
        // leader holds; without storage this would flip to a bare sort.
        for _ in 0..30 {
            state
                .health
                .get_mut(&"2.2.2.2".parse().unwrap())
                .unwrap()
                .kalman
                .update(Duration::from_millis(49));
        }
        let timing = ProbeTiming {
            interval: Duration::from_secs(300),
            degraded_interval: Duration::from_secs(30),
            fail_threshold: 2,
            max_concurrent_probes: 16,
            score_payload_bytes: 0,
            throughput_discount: 0.95,
            kalman_q: 0.01,
            kalman_r: 0.1,
        };
        recompute_order(&mut state, &timing, &candidates);
        assert_eq!(
            state.order.first(),
            Some(&"1.1.1.1".parse::<IpAddr>().unwrap()),
            "a 1ms gain must not flip the leader across cycles"
        );

        // Cycle 4: a decisive gain does take the lead.
        for _ in 0..30 {
            state
                .health
                .get_mut(&"2.2.2.2".parse().unwrap())
                .unwrap()
                .kalman
                .update(Duration::from_millis(20));
        }
        recompute_order(&mut state, &timing, &candidates);
        assert_eq!(
            state.order.first(),
            Some(&"2.2.2.2".parse::<IpAddr>().unwrap()),
            "a decisive gain must take the lead"
        );
    }

    /// The leader must not change on a 1ms difference, which is what keeps
    /// connections and the upstream-certificate mirror stable.
    #[test]
    fn ranking_is_stable_under_noise() {
        let candidates = vec![
            candidate("1.1.1.1", 0, &["ipv4"]),
            candidate("2.2.2.2", 0, &["ipv4"]),
        ];
        let state = state_with(&[("1.1.1.1", Some(50), false), ("2.2.2.2", Some(49), false)]);
        let prev = vec!["1.1.1.1".parse().unwrap()];
        let timing = ProbeTiming {
            interval: Duration::from_secs(300),
            degraded_interval: Duration::from_secs(30),
            fail_threshold: 2,
            max_concurrent_probes: 16,
            score_payload_bytes: 0,
            throughput_discount: 0.95,
            kalman_q: 0.01,
            kalman_r: 0.1,
        };
        let order = reorder_with_hysteresis(&prev, &state, &timing, &candidates);
        assert_eq!(
            order[0],
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "a 1ms gain must not flip the leader"
        );

        // A decisive gain does flip it.
        let state = state_with(&[("1.1.1.1", Some(50), false), ("2.2.2.2", Some(20), false)]);
        let order = reorder_with_hysteresis(&prev, &state, &timing, &candidates);
        assert_eq!(order[0], "2.2.2.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn degraded_and_unmeasured_candidates_leave_the_order() {
        let candidates = vec![
            candidate("1.1.1.1", 0, &["ipv4"]),
            candidate("2.2.2.2", 0, &["ipv4"]),
            candidate("3.3.3.3", 0, &["ipv4"]),
        ];
        let state = state_with(&[
            ("1.1.1.1", Some(10), true), // degraded
            ("2.2.2.2", Some(30), false),
            ("3.3.3.3", None, false), // never measured
        ]);
        let timing = ProbeTiming {
            interval: Duration::from_secs(300),
            degraded_interval: Duration::from_secs(30),
            fail_threshold: 2,
            max_concurrent_probes: 16,
            score_payload_bytes: 0,
            throughput_discount: 0.95,
            kalman_q: 0.01,
            kalman_r: 0.1,
        };
        let order = reorder_with_hysteresis(&[], &state, &timing, &candidates);
        assert_eq!(order, vec!["2.2.2.2".parse::<IpAddr>().unwrap()]);
    }

    /// Backoff must double up to the healthy interval and no further, so a dead
    /// endpoint costs the same as a live one instead of probing forever fast.
    #[test]
    fn degraded_backoff_doubles_and_caps() {
        let interval = Duration::from_secs(300);
        let base = Duration::from_secs(30);
        let mut h = Health::new(Instant::now(), base, DEFAULT_KALMAN_Q, DEFAULT_KALMAN_R);

        for i in 0..5 {
            h.record_failure(2, interval, base);
            if i == 1 {
                // After the second failure (threshold = 2), it becomes degraded
                // and backoff starts at base.
                assert!(h.degraded);
                assert_eq!(h.backoff, base);
            }
        }
        // After repeated failures, backoff should have doubled: 30 → 60 → 120 → 240.
        // The final doubling would be 480, but that exceeds the 300s cap.
        assert_eq!(h.backoff, Duration::from_secs(240));
        h.record_failure(2, interval, base);
        assert_eq!(
            h.backoff, interval,
            "backoff must cap at the healthy interval"
        );

        // A success resets degradation and backoff.
        h.record_success(Duration::from_millis(25), interval, base);
        assert!(!h.degraded);
        assert_eq!(h.backoff, base);
        let estimated = h.rtt().expect("RTT should be available after convergence");
        assert!(
            estimated.as_millis() >= 24 && estimated.as_millis() <= 26,
            "RTT estimate {estimated:?} should be close to 25ms"
        );

        // After reset, degradation and doubling restart from scratch.
        h.record_failure(2, interval, base);
        assert!(!h.degraded, "one failure below threshold");
        assert_eq!(h.backoff, base);

        h.record_failure(2, interval, base);
        assert!(h.degraded, "second failure meets threshold");
        assert_eq!(h.backoff, base, "newly degraded starts at base");

        for expected in [60u64, 120, 240, 300, 300] {
            h.record_failure(2, interval, base);
            assert_eq!(h.backoff, Duration::from_secs(expected));
        }
    }

    #[test]
    fn recovery_clears_degradation_and_resets_backoff() {
        let interval = Duration::from_secs(300);
        let base = Duration::from_secs(30);
        let mut h = Health::new(Instant::now(), base, DEFAULT_KALMAN_Q, DEFAULT_KALMAN_R);
        h.record_failure(1, interval, base);
        h.record_failure(1, interval, base);
        assert!(h.degraded);

        h.record_success(Duration::from_millis(25), interval, base);
        assert!(!h.degraded);
        assert_eq!(h.consecutive_failures, 0);
        assert_eq!(h.backoff, base);
        let estimated = h.rtt().expect("RTT should be available after convergence");
        assert!(
            estimated.as_millis() >= 24 && estimated.as_millis() <= 26,
            "RTT estimate {estimated:?} should be close to 25ms"
        );
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n").unwrap(), 200);
        assert_eq!(parse_status(b"HTTP/1.0 403 Forbidden\r\n").unwrap(), 403);
        assert_eq!(parse_status(b"HTTP/2 204 \r\n").unwrap(), 204);
        // Not HTTP at all: a TLS record or a raw banner must not read as 200.
        assert!(parse_status(b"\x16\x03\x01\x00\x01").is_err());
        assert!(parse_status(b"SSH-2.0-OpenSSH\r\n").is_err());
        assert!(parse_status(b"HTTP/1.1\r\n").is_err());
        assert!(parse_status(b"HTTP/1.1 abc OK\r\n").is_err());
    }

    fn models() -> Vec<Arc<SelectionModel>> {
        (1..=32)
            .map(|i| {
                Arc::new(SelectionModel {
                    addr: std::net::Ipv4Addr::new(192, 0, 2, i).into(),
                    rtt: Duration::from_millis(20),
                    throughput: default_nig_prior(),
                })
            })
            .collect()
    }

    #[test]
    fn each_candidate_is_scored_once_and_position_does_not_change_winner() {
        let mut models = models();
        let wanted = models[31].addr;
        for _ in 0..32 {
            let mut seen = std::collections::HashSet::new();
            let chosen = choose_with(&models, &AtomicUsize::new(0), |m| {
                assert!(seen.insert(m.addr), "candidate sampled twice");
                if m.addr == wanted {
                    0.01
                } else {
                    1.0
                }
            });
            assert_eq!(chosen, Some(wanted));
            assert_eq!(seen.len(), models.len());
            models.rotate_left(1);
        }
    }

    #[test]
    fn repeated_connections_explore_without_republishing() {
        let models = models();
        let incumbent = AtomicUsize::new(0);
        let choices: std::collections::HashSet<_> = (0..2000)
            .map(|_| choose_candidate(&models, &incumbent, 1_000_000).unwrap())
            .collect();
        assert!(
            choices.len() > 16,
            "only explored {} endpoints",
            choices.len()
        );
        for _ in 0..100 {
            assert_eq!(
                choose_candidate(&models, &incumbent, 0),
                Some(models[0].addr)
            );
        }
    }

    #[tokio::test]
    async fn bounded_feedback_and_disabled_scoring_do_not_grow_backlogs() {
        for payload in [0, 1_000_000] {
            let (pool, state, candidates) = fixture(payload);
            let handle = PoolBuilder::handle(pool.clone(), 0);
            for _ in 0..100_000 {
                handle.observe_transfer(candidates[0].addr, 1024, Duration::from_millis(1));
            }
            let accepted = if payload == 0 {
                0
            } else {
                OBSERVATION_CAPACITY
            };
            assert_eq!(state.obs_rx.len(), accepted);
            assert_eq!(
                pool.dropped_observations.load(Ordering::Relaxed),
                if payload == 0 {
                    0
                } else {
                    100_000 - accepted as u64
                }
            );
        }
    }

    #[tokio::test]
    async fn one_batch_has_a_fixed_work_budget() {
        let (pool, mut state, candidates) = fixture(1_000_000);
        let handle = PoolBuilder::handle(pool.clone(), 0);
        for _ in 0..OBSERVATION_CAPACITY {
            handle.observe_transfer(candidates[0].addr, 1024, Duration::from_millis(1));
        }
        let first = state.obs_rx.recv().await;
        process_observations(&pool, &mut state, &candidates, first);
        assert_eq!(state.obs_rx.len(), OBSERVATION_CAPACITY - OBSERVATION_BATCH);
    }

    #[tokio::test]
    async fn observations_publish_while_other_work_is_pending() {
        let (pool, mut state, candidates) = fixture(1_000_000);
        let handle = PoolBuilder::handle(pool.clone(), 0);
        let addr = candidates[0].addr;
        let before = state.health[&addr].nig.mu;
        let worker_pool = pool.clone();
        let worker = tokio::spawn(async move {
            with_observations(
                std::future::pending::<()>(),
                &worker_pool,
                &mut state,
                &candidates,
            )
            .await;
        });
        handle.observe_transfer(addr, 1_000_000, Duration::from_millis(1));
        timeout(Duration::from_secs(2), async {
            loop {
                let mu = pool.ranking.read().unwrap().per_view[0].ordered[0]
                    .throughput
                    .mu;
                if mu > before {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("feedback waited for unrelated work");
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn parked_transfers_update_the_state_restored_after_dns_rotation() {
        let (pool, mut state, candidates) = fixture(1_000_000);
        let addr = candidates[0].addr;
        let h = state.health.remove(&addr).unwrap();
        let before = h.nig.mu;
        let now = Instant::now();
        state.parked.insert(addr, (h, now + PARK_DURATION));
        state.observe(
            PassiveObs {
                addr,
                bytes: 1_000_000,
                elapsed: Duration::from_millis(1),
            },
            0.95,
            now,
        );
        let updated = state.parked[&addr].0.nig.mu;
        assert!(updated > before);
        build_candidates(&pool, &mut state);
        assert_eq!(state.health[&addr].nig.mu, updated);
        assert!(!state.parked.contains_key(&addr));
    }

    #[tokio::test]
    async fn history_is_bounded_and_expired_observations_cannot_resurrect_it() {
        let (_, mut state, candidates) = fixture(1_000_000);
        let now = Instant::now();
        let h = state.health[&candidates[0].addr].clone();
        for index in 0..(MAX_PARKED_CANDIDATES + 100) {
            let addr = IpAddr::V4(Ipv4Addr::new(10, (index / 256) as u8, index as u8, 1));
            state.parked.insert(addr, (h.clone(), now + PARK_DURATION));
            state.subnet_priors.insert(
                SubnetKey::of(addr),
                SubnetPrior {
                    model: default_nig_prior(),
                    last_used: now,
                },
            );
        }
        state.prune_history(now);
        assert_eq!(state.parked.len(), MAX_PARKED_CANDIDATES);
        assert!(state.subnet_priors.len() <= MAX_PARKED_CANDIDATES + MAX_IDLE_SUBNET_PRIORS);
        let later = now + PARK_DURATION + Duration::from_secs(1);
        state.prune_history(later);
        assert!(state.parked.is_empty());
        assert!(state.subnet_priors.is_empty());
        state.observe(
            PassiveObs {
                addr: "10.0.0.1".parse().unwrap(),
                bytes: 1024,
                elapsed: Duration::from_secs(1),
            },
            0.95,
            later,
        );
        assert!(state.subnet_priors.is_empty());
    }

    #[tokio::test]
    async fn new_candidates_cannot_revive_expired_subnet_priors() {
        for expired in [false, true] {
            let (pool, mut state, candidates) = fixture(1_000_000);
            let addr = candidates[0].addr;
            let key = SubnetKey::of(addr);
            let now = Instant::now();
            let mut learned = default_nig_prior();
            learned.observe(1_000_000_000.0, 0.95);
            let expected = if expired {
                default_nig_prior()
            } else {
                learned.clone()
            };
            state.health.clear();
            state.subnet_priors.insert(
                key,
                SubnetPrior {
                    model: learned,
                    last_used: if expired {
                        now - PARK_DURATION - Duration::from_secs(1)
                    } else {
                        now
                    },
                },
            );

            build_candidates(&pool, &mut state);

            let actual = &state.health[&addr].nig;
            assert_eq!(actual.mu, expected.mu);
            assert_eq!(actual.kappa, expected.kappa);
            assert_eq!(actual.alpha, expected.alpha);
            assert_eq!(actual.beta, expected.beta);
            assert_eq!(state.subnet_priors.contains_key(&key), !expired);
        }
    }

    #[tokio::test]
    async fn high_measurement_noise_does_not_exclude_healthy_endpoints() {
        let (pool, mut state, candidates) = fixture(1_000_000);
        let addr = candidates[0].addr;
        let h = state.health.get_mut(&addr).unwrap();
        h.kalman = KalmanRtt::new(10.0, 10.0);
        for _ in 0..1000 {
            h.kalman.update(Duration::from_millis(50));
        }
        assert!(h.kalman.variance > 5.0);
        recompute_order(&mut state, &pool.timing, &candidates);
        publish(&pool, &state, &candidates);
        assert_eq!(pool.pick(0, 443).unwrap().ip(), addr);
    }
}
