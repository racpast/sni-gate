//! Configuration model and hierarchical resolution.
//!
//! The document is TOML. It has a `[global]` block, one or more `[[listener]]`
//! blocks (each binding an address), and within each listener a set of
//! `[[listener.route]]` rules plus an optional `[listener.default_route]`.
//!
//! Many settings are *overridable* and resolved by walking outward from the
//! most specific scope to the least:
//!
//!   route.ech  →  route  →  listener.default_route  →  listener  →  global
//!
//! An unset value at a deeper scope inherits from the next scope out. The
//! [`Effective`] view computes the flattened settings for one route so the data
//! path never has to re-walk the hierarchy.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::error::ConfigError;

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------

/// Top-level configuration document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub global: Global,

    /// Certificate authority + issuance settings (dynamic per-SNI certs).
    pub ca: CaConfig,

    #[serde(default)]
    pub issuance: IssuanceConfig,

    #[serde(default)]
    pub store: StoreConfig,

    #[serde(default)]
    pub cache: CacheConfig,

    /// One or more inbound listeners.
    #[serde(rename = "listener")]
    pub listeners: Vec<Listener>,
}

/// Process-wide defaults and the outermost fallback scope.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Global {
    /// `tracing` filter directive; env `SNI_GATE_LOG` / `RUST_LOG` override it.
    #[serde(default = "default_log")]
    pub log: String,

    /// Overridable knobs shared with deeper scopes.
    #[serde(flatten)]
    pub common: CommonOpts,

    /// Policy for connections matching no route and no default_route.
    #[serde(default)]
    pub unmatched: FailPolicy,
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// One inbound bind address and its routes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    /// Address to accept on, e.g. "0.0.0.0:443".
    pub addr: SocketAddr,

    /// Overridable knobs; inherit from `[global]`, override per route.
    #[serde(flatten)]
    pub common: CommonOpts,

    /// Routes matched by inbound SNI/Host.
    #[serde(default, rename = "route")]
    pub routes: Vec<Route>,

    /// Catch-all for SNI/Host matching no route.
    #[serde(default)]
    pub default_route: Option<Route>,
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------

/// How an upstream connection is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteType {
    /// Re-originate to the upstream over TLS 1.3 + Encrypted Client Hello.
    Ech,
    /// Re-originate over plain TLS (optionally with an overridden SNI).
    Tls,
    /// Forward as cleartext HTTP (no upstream TLS).
    Http,
    /// Do not terminate: splice the raw TCP byte stream to the upstream.
    /// No certificate is issued.
    Raw,
}

/// One SNI/Host-matched forwarding rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Human-readable name for logs.
    #[serde(default)]
    pub name: Option<String>,

    /// Upstream protocol handling.
    #[serde(rename = "type")]
    pub route_type: RouteType,

    /// Patterns matched against the inbound SNI/Host. Each is one of:
    ///   exact `p.example.com` · wildcard `*.example.com` (one left label) ·
    ///   suffix `.example.com` (domain and any subdomain) · regex `~<re>`.
    /// Not used by `default_route`.
    #[serde(default)]
    pub match_sni: Vec<String>,

    /// Upstream to dial. Both the host and the port may be defaulted:
    ///
    ///   * `"host:port"`  — fixed host and port (IPv6 in brackets).
    ///   * `"host"`       — fixed host; port = this listener's port.
    ///   * `"8443"`       — port only; host = the matched source SNI/Host.
    ///   * *(omitted)*    — host = the matched source SNI/Host; port = this
    ///     listener's port.
    ///
    /// When the host is defaulted it is the *routing key* the connection was
    /// matched on (the inbound SNI/Host, port-stripped) — resolved per
    /// connection. `override_sni` does not affect the dial target; it only sets
    /// the upstream TLS server name for `tls`/`ech`.
    #[serde(default)]
    pub upstream: Option<String>,

    /// SNI sent to the upstream. Unset = use the inbound SNI verbatim. For
    /// `ech` routes this is the inner (protected) name; for `tls` the SNI on
    /// the upstream handshake. Ignored for `http`/`raw`.
    #[serde(default)]
    pub override_sni: Option<String>,

    /// ECH settings. Required in practice for `type = "ech"`.
    #[serde(default)]
    pub ech: Option<EchConfig>,

    /// Optional PEM cert chain pinned for local termination when this route's
    /// name is presented. Falls back to the dynamic CA issuer.
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,

    /// Overridable knobs; inherit from listener then global.
    #[serde(flatten)]
    pub common: CommonOpts,

    /// Per-route failure policy (e.g. ECH unavailable, upstream unreachable).
    #[serde(default)]
    pub fail: Option<FailPolicy>,
}

/// Per-route ECH settings (deepest scope for ECH-related overrides).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EchConfig {
    /// Where the ECHConfigList comes from.
    #[serde(default)]
    pub mode: EchMode,

    /// Base64 ECHConfigList for `static` / `doh-with-fallback`.
    #[serde(default)]
    pub config: Option<String>,

    /// Name whose HTTPS record is queried for `ech=` (doh modes). Unset = the
    /// effective inner name (override_sni or inbound SNI).
    #[serde(default)]
    pub ech_domain: Option<String>,

    /// Fail closed unless ECH is negotiated. Inherits, default true.
    #[serde(default)]
    pub require_ech: Option<bool>,

    /// Max ECH retry attempts on server rejection (retry_configs). Default 2.
    #[serde(default)]
    pub max_retries: Option<u32>,

    /// ECH refresh bound override (deepest scope).
    #[serde(default, with = "humantime_serde::option")]
    pub ech_refresh: Option<Duration>,

    /// Resolver override used specifically for the ECH HTTPS-record lookup.
    #[serde(default)]
    pub ech_resolver: Option<String>,
}

/// How the ECHConfigList for a route is sourced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EchMode {
    /// Look up the HTTPS record via the resolver and extract `ech=`.
    #[default]
    Doh,
    /// Use a fixed inline base64 ECHConfigList. Never refreshed.
    Static,
    /// Prefer DoH, fall back to the inline `config` if lookup fails.
    DohWithFallback,
}

// ---------------------------------------------------------------------------
// Overridable common options (the fallback ladder)
// ---------------------------------------------------------------------------

/// Settings that may be set at any scope and inherit outward. Every field is
/// `Option`; `None` means "inherit from the enclosing scope".
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CommonOpts {
    /// Generic resolver spec (DoH/DoT/IP/system). Used for both ECH lookups and
    /// upstream A/AAAA unless a purpose-specific resolver overrides it.
    #[serde(default)]
    pub resolver: Option<String>,

    /// Resolver used specifically for ECH HTTPS-record lookups.
    #[serde(default)]
    pub ech_resolver: Option<String>,

    /// Resolver used specifically for upstream A/AAAA resolution.
    #[serde(default)]
    pub addr_resolver: Option<String>,

    /// Default ECH refresh bound.
    #[serde(default, with = "humantime_serde::option")]
    pub ech_refresh: Option<Duration>,

    /// NAT64 /96 prefix for synthesizing IPv6 from a resolved IPv4 upstream.
    #[serde(default)]
    pub nat64_prefix: Option<String>,

    /// Address family for upstream hostname resolution.
    #[serde(default)]
    pub address_family: Option<AddressFamily>,

    /// Fail closed unless ECH negotiated (ech routes).
    #[serde(default)]
    pub require_ech: Option<bool>,

    /// Upstream connect + handshake timeout.
    #[serde(default, with = "humantime_serde::option")]
    pub connect_timeout: Option<Duration>,

    /// Idle timeout for the proxied byte stream in each direction.
    #[serde(default, with = "humantime_serde::option")]
    pub idle_timeout: Option<Duration>,
}

/// Upstream address family selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    /// Prefer AAAA, fall back to A; NAT64 may synthesize v6 from an A record.
    #[default]
    Dual,
    /// A records only (NAT64 may still synthesize v6 from the A record).
    Ipv4,
    /// AAAA records only; NAT64 disabled.
    Ipv6,
}

/// What to do when a connection cannot be served (unmatched, or a route's
/// failure). Applied to the (possibly never-decrypted) stream.
///
/// Accepts two spellings in TOML for convenience:
///   * a bare string for field-less modes — `unmatched = "close"` /
///     `unmatched = "system-outbound"`
///   * a table for modes that carry data — `unmatched = { mode = "passthrough",
///     addr = "127.0.0.1:80" }`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum FailPolicy {
    /// Drop the connection. Safe default.
    #[default]
    Close,
    /// Transparent egress: dial the real target named by the SNI/Host directly.
    SystemOutbound,
    /// Splice the raw stream to a fixed address.
    Passthrough { addr: SocketAddr },
}

impl<'de> Deserialize<'de> for FailPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // A bare string selects a field-less mode; a table selects any mode
        // (and is required for modes carrying data, e.g. passthrough's addr).
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Str(String),
            Table {
                mode: String,
                #[serde(default)]
                addr: Option<SocketAddr>,
            },
        }

        let (mode, addr) = match Repr::deserialize(deserializer)? {
            Repr::Str(s) => (s, None),
            Repr::Table { mode, addr } => (mode, addr),
        };

        match mode.as_str() {
            "close" => Ok(FailPolicy::Close),
            "system-outbound" => Ok(FailPolicy::SystemOutbound),
            "passthrough" => {
                let addr = addr.ok_or_else(|| {
                    serde::de::Error::custom("fail mode \"passthrough\" requires an `addr`")
                })?;
                Ok(FailPolicy::Passthrough { addr })
            }
            other => Err(serde::de::Error::custom(format!(
                "unknown fail mode {other:?} (expected close | system-outbound | passthrough)"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// CA / issuance / store / cache (dynamic certificate stack)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    #[serde(default = "default_ca_common_name")]
    pub common_name: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub country: String,
    #[serde(default = "default_leaf_validity_days")]
    pub leaf_validity_days: u32,
    #[serde(default)]
    pub install_to_system_root: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceConfig {
    #[serde(default = "default_true")]
    pub wildcard: bool,
}

impl Default for IssuanceConfig {
    fn default() -> Self {
        Self { wildcard: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_store_dir")]
    pub dir: PathBuf,
    #[serde(default = "default_renew_margin_days")]
    pub renew_margin_days: u32,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: default_store_dir(),
            renew_margin_days: default_renew_margin_days(),
        }
    }
}

/// Public-suffix list source for wildcard base derivation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PslConfig {
    #[serde(default = "default_psl_source")]
    pub source: PslSource,
    #[serde(default = "default_psl_path")]
    pub path: PathBuf,
    #[serde(default = "default_psl_url")]
    pub url: String,
    #[serde(default = "default_psl_cron")]
    pub cron: String,
    #[serde(default = "default_psl_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub proxy: String,
}

impl Default for PslConfig {
    fn default() -> Self {
        Self {
            source: PslSource::Embedded,
            path: default_psl_path(),
            url: default_psl_url(),
            cron: default_psl_cron(),
            timeout_secs: default_psl_timeout_secs(),
            proxy: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PslSource {
    Embedded,
    File,
    Network,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default = "default_cache_capacity")]
    pub capacity: u64,
    #[serde(default = "default_cache_ttl_secs")]
    pub ttl_secs: u64,
    /// Public-suffix list settings live under `[cache.psl]` — nested so the
    /// wildcard/PSL machinery stays together.
    #[serde(default)]
    pub psl: PslConfig,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: default_cache_capacity(),
            ttl_secs: default_cache_ttl_secs(),
            psl: PslConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Effective (flattened) route settings
// ---------------------------------------------------------------------------

/// The fully-resolved settings for one route after applying the fallback
/// ladder. Computed once at startup; the data path reads these directly.
#[derive(Debug, Clone)]
pub struct Effective {
    pub ech_resolver: Option<String>,
    pub addr_resolver: Option<String>,
    pub ech_refresh: Duration,
    pub nat64_prefix: Option<String>,
    pub address_family: AddressFamily,
    pub require_ech: bool,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub fail: FailPolicy,
}

impl Config {
    /// Load and validate a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_path_buf(), e))?;
        let cfg: Config = toml::from_str(&text).map_err(ConfigError::Parse)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.listeners.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one [[listener]] is required".into(),
            ));
        }
        // Reject duplicate listen addresses.
        for (i, a) in self.listeners.iter().enumerate() {
            for b in &self.listeners[i + 1..] {
                if a.addr == b.addr {
                    return Err(ConfigError::Invalid(format!(
                        "duplicate listener address {}",
                        a.addr
                    )));
                }
            }
            let port = a.addr.port();
            for r in &a.routes {
                r.validate(false, port)?;
            }
            if let Some(d) = &a.default_route {
                d.validate(true, port)?;
            }
        }
        if self.ca.leaf_validity_days < 1 {
            return Err(ConfigError::Invalid(
                "ca.leaf_validity_days must be >= 1".into(),
            ));
        }
        if self.store.renew_margin_days >= self.ca.leaf_validity_days {
            return Err(ConfigError::Invalid(
                "store.renew_margin_days must be < ca.leaf_validity_days".into(),
            ));
        }
        Ok(())
    }

    /// Compute the effective settings for `route` within `listener`, applying
    /// route.ech → route → listener → global fallback.
    pub fn effective(&self, listener: &Listener, route: &Route) -> Effective {
        let g = &self.global.common;
        let l = &listener.common;
        let r = &route.common;
        let e = route.ech.as_ref();

        // Helper: first Some in deepest→shallowest order.
        macro_rules! pick {
            ($($opt:expr),+ $(,)?) => {{ None $(.or_else(|| $opt.clone()))+ }};
        }

        let ech_resolver = pick!(
            e.and_then(|e| e.ech_resolver.clone()),
            r.ech_resolver,
            r.resolver,
            l.ech_resolver,
            l.resolver,
            g.ech_resolver,
            g.resolver,
        );
        let addr_resolver = pick!(
            r.addr_resolver,
            r.resolver,
            l.addr_resolver,
            l.resolver,
            g.addr_resolver,
            g.resolver
        );

        let ech_refresh = e
            .and_then(|e| e.ech_refresh)
            .or(r.ech_refresh)
            .or(l.ech_refresh)
            .or(g.ech_refresh)
            .unwrap_or_else(default_ech_refresh);

        let nat64_prefix = pick!(r.nat64_prefix, l.nat64_prefix, g.nat64_prefix);

        let address_family = r
            .address_family
            .or(l.address_family)
            .or(g.address_family)
            .unwrap_or_default();

        let require_ech = e
            .and_then(|e| e.require_ech)
            .or(r.require_ech)
            .or(l.require_ech)
            .or(g.require_ech)
            .unwrap_or(true);

        let connect_timeout = r
            .connect_timeout
            .or(l.connect_timeout)
            .or(g.connect_timeout)
            .unwrap_or_else(default_connect_timeout);

        let idle_timeout = r
            .idle_timeout
            .or(l.idle_timeout)
            .or(g.idle_timeout)
            .unwrap_or_else(default_idle_timeout);

        let fail = route
            .fail
            .clone()
            .unwrap_or_else(|| self.global.unmatched.clone());

        Effective {
            ech_resolver,
            addr_resolver,
            ech_refresh,
            nat64_prefix,
            address_family,
            require_ech,
            connect_timeout,
            idle_timeout,
            fail,
        }
    }
}

impl Route {
    /// Display name for logs.
    pub fn label(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.match_sni.first().cloned())
            .unwrap_or_else(|| format!("{:?}", self.route_type).to_lowercase())
    }

    /// Resolve `upstream` against `listener_port`, filling in the defaulted
    /// pieces. Returns `(host, port)` where `host` is `None` when it should be
    /// taken from the matched source SNI/Host at connection time (dynamic).
    ///
    ///   * absent           → `(None, listener_port)`
    ///   * `"8443"`         → `(None, 8443)`
    ///   * `"host"`         → `(Some(host), listener_port)`
    ///   * `"host:port"`    → `(Some(host), port)`
    pub fn resolved_upstream(
        &self,
        listener_port: u16,
    ) -> Result<(Option<String>, u16), ConfigError> {
        let Some(spec) = self.upstream.as_deref() else {
            return Ok((None, listener_port));
        };
        let parsed = parse_upstream(spec).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "route {}: invalid upstream {:?}",
                self.label(),
                spec
            ))
        })?;
        Ok((parsed.host, parsed.port.unwrap_or(listener_port)))
    }

    fn validate(&self, is_default: bool, listener_port: u16) -> Result<(), ConfigError> {
        // `upstream` may be omitted (dynamic host + listener port). When set, it
        // must parse; an explicitly empty/whitespace string is a mistake.
        if let Some(spec) = self.upstream.as_deref() {
            if spec.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "route {}: upstream, when set, must not be empty (omit it to \
                     reflect the source SNI/Host to this listener's port)",
                    self.label()
                )));
            }
        }
        self.resolved_upstream(listener_port)?;
        if !is_default && self.match_sni.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "route {}: match_sni needs at least one pattern (or use default_route)",
                self.label()
            )));
        }
        if self.route_type == RouteType::Ech && self.ech.is_none() {
            return Err(ConfigError::Invalid(format!(
                "route {}: type = \"ech\" requires an [ech] table",
                self.label()
            )));
        }
        if self.cert_file.is_some() != self.key_file.is_some() {
            return Err(ConfigError::Invalid(format!(
                "route {}: cert_file and key_file must be set together",
                self.label()
            )));
        }
        if let Some(ov) = &self.override_sni {
            if ov.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "route {}: override_sni, when set, must not be empty",
                    self.label()
                )));
            }
        }
        Ok(())
    }
}

/// Parse an upstream address into (host, port).
///
/// Accepted forms:
///   * `host:port`        — a DNS name or IPv4 with a port
///   * `[v6]:port`        — an IPv6 literal in brackets with a port
///
/// A bare IPv6 literal without brackets (e.g. `2a01:4f8::1:443`) is rejected:
/// it is ambiguous because the colons cannot be split reliably. Such addresses
/// must be written in bracket form `[2a01:4f8::1]:443`. Returns `None` on any
/// malformed input.
pub fn split_host_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port
        let (host, tail) = rest.split_once(']')?;
        // Validate it really is an IPv6 literal.
        host.parse::<std::net::Ipv6Addr>().ok()?;
        let port = tail.strip_prefix(':')?;
        Some((host.to_string(), port.parse().ok()?))
    } else {
        // Exactly one colon is required: host:port. More than one colon means an
        // unbracketed IPv6 literal, which is ambiguous and must use [..] form.
        let (host, port) = s.rsplit_once(':')?;
        if host.is_empty() || host.contains(':') {
            return None;
        }
        Some((host.to_string(), port.parse().ok()?))
    }
}

/// A parsed `upstream` value with independently-optional host and port.
///
/// `host = None` means "use the matched source SNI/Host"; `port = None` means
/// "use the parent listener's port". The two are resolved by
/// [`Route::resolved_upstream`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSpec {
    pub host: Option<String>,
    pub port: Option<u16>,
}

/// Parse a non-empty `upstream` value into an [`UpstreamSpec`].
///
/// Accepted forms (after trimming):
///   * `"8443"`        — a bare port (all digits): host defaulted, port fixed.
///   * `"host:port"`   — a DNS name or IPv4 with a port.
///   * `"[v6]:port"`   — an IPv6 literal in brackets with a port.
///   * `"host"`        — a bare host with no port: port defaulted.
///
/// A bare, unbracketed IPv6 literal is rejected (ambiguous — must use `[v6]`),
/// as are malformed ports. Returns `None` on any unrecognized input. The empty
/// string is *not* a valid spec here; omit the field to default both parts.
pub fn parse_upstream(s: &str) -> Option<UpstreamSpec> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // A bare port (all digits) defaults the host. Checked first because a value
    // like "443" is both a valid u16 and a colon-free "host".
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return Some(UpstreamSpec {
            host: None,
            port: Some(s.parse().ok()?),
        });
    }
    // A colon (bracketed or not) means an explicit port is present; delegate to
    // the strict host:port / [v6]:port parser.
    if s.contains(':') {
        let (host, port) = split_host_port(s)?;
        return Some(UpstreamSpec {
            host: Some(host),
            port: Some(port),
        });
    }
    // Otherwise a bare host with no port; the port defaults to the listener's.
    Some(UpstreamSpec {
        host: Some(s.to_string()),
        port: None,
    })
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_log() -> String {
    "info".to_string()
}
fn default_true() -> bool {
    true
}
fn default_ca_common_name() -> String {
    "SNI Gate Local CA".to_string()
}
fn default_leaf_validity_days() -> u32 {
    397
}
fn default_store_dir() -> PathBuf {
    PathBuf::from("certs")
}
fn default_renew_margin_days() -> u32 {
    30
}
fn default_cache_capacity() -> u64 {
    8_192
}
fn default_cache_ttl_secs() -> u64 {
    24 * 60 * 60
}
fn default_ech_refresh() -> Duration {
    Duration::from_secs(3600)
}
fn default_connect_timeout() -> Duration {
    Duration::from_secs(15)
}
fn default_idle_timeout() -> Duration {
    // A true idle timeout (reset on every chunk). 5 minutes tolerates
    // WebSocket/streaming connections that are quiet between messages while
    // still reaping genuinely dead ones. Set `idle_timeout = "0s"` to disable.
    Duration::from_secs(300)
}
fn default_psl_source() -> PslSource {
    PslSource::Embedded
}
fn default_psl_path() -> PathBuf {
    PathBuf::from("public_suffix_list.dat")
}
fn default_psl_url() -> String {
    "https://publicsuffix.org/list/public_suffix_list.dat".to_string()
}
fn default_psl_cron() -> String {
    "0 17 3 * * 0".to_string()
}
fn default_psl_timeout_secs() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_variants() {
        // host:port and IPv4:port
        assert_eq!(split_host_port("a.com:443"), Some(("a.com".into(), 443)));
        assert_eq!(
            split_host_port("1.2.3.4:443"),
            Some(("1.2.3.4".into(), 443))
        );
        // Bracketed IPv6 is accepted.
        assert_eq!(
            split_host_port("[2a01:4f8::1]:443"),
            Some(("2a01:4f8::1".into(), 443))
        );
        assert_eq!(
            split_host_port("[2a01:4f8:c2c:123f:64:5:6812:202f]:443"),
            Some(("2a01:4f8:c2c:123f:64:5:6812:202f".into(), 443))
        );
        // A bare (unbracketed) IPv6 literal is ambiguous and rejected: the user
        // must write [v6]:port. This is the bug from the field report where
        // "2a01:...:202f:443" was mis-split with the IP treated as a hostname.
        assert_eq!(
            split_host_port("2a01:4f8:c2c:123f:64:5:6812:202f:443"),
            None
        );
        assert_eq!(split_host_port("2a01:4f8::1:443"), None);
        // Malformed.
        assert_eq!(split_host_port("no-port"), None);
        assert_eq!(split_host_port("a.com:bad"), None);
        // A bracketed non-IPv6 is rejected.
        assert_eq!(split_host_port("[not-v6]:443"), None);
    }

    #[test]
    fn parse_upstream_variants() {
        let spec = |host: Option<&str>, port: Option<u16>| {
            Some(UpstreamSpec {
                host: host.map(str::to_string),
                port,
            })
        };
        // Bare port: host defaulted, port fixed.
        assert_eq!(parse_upstream("8443"), spec(None, Some(8443)));
        assert_eq!(parse_upstream("443"), spec(None, Some(443)));
        // Bare host: port defaulted.
        assert_eq!(
            parse_upstream("cdn.example.com"),
            spec(Some("cdn.example.com"), None)
        );
        // host:port and IPv4:port.
        assert_eq!(parse_upstream("a.com:443"), spec(Some("a.com"), Some(443)));
        assert_eq!(
            parse_upstream("1.2.3.4:8443"),
            spec(Some("1.2.3.4"), Some(8443))
        );
        // Bracketed IPv6 with a port.
        assert_eq!(
            parse_upstream("[2a01:4f8::1]:443"),
            spec(Some("2a01:4f8::1"), Some(443))
        );
        // Surrounding whitespace is tolerated.
        assert_eq!(parse_upstream("  9000  "), spec(None, Some(9000)));
        // Rejected: empty, bare v6, bad port, port overflow, bracketed non-v6.
        assert_eq!(parse_upstream(""), None);
        assert_eq!(parse_upstream("   "), None);
        assert_eq!(parse_upstream("2a01:4f8::1:443"), None);
        assert_eq!(parse_upstream("a.com:bad"), None);
        assert_eq!(parse_upstream("99999"), None);
        assert_eq!(parse_upstream("[not-v6]:443"), None);
    }

    #[test]
    fn resolved_upstream_defaults() {
        let route = |upstream: Option<&str>| Route {
            name: None,
            route_type: RouteType::Raw,
            match_sni: vec![".x.com".into()],
            upstream: upstream.map(str::to_string),
            override_sni: None,
            ech: None,
            cert_file: None,
            key_file: None,
            common: CommonOpts::default(),
            fail: None,
        };
        // Omitted: dynamic host, listener port.
        assert_eq!(route(None).resolved_upstream(8443).unwrap(), (None, 8443));
        // Port-only: dynamic host, explicit port.
        assert_eq!(
            route(Some("9001")).resolved_upstream(443).unwrap(),
            (None, 9001)
        );
        // Bare host: fixed host, listener port.
        assert_eq!(
            route(Some("cdn.x")).resolved_upstream(443).unwrap(),
            (Some("cdn.x".into()), 443)
        );
        // host:port: both fixed.
        assert_eq!(
            route(Some("cdn.x:8080")).resolved_upstream(443).unwrap(),
            (Some("cdn.x".into()), 8080)
        );
        // An explicitly empty string is a config error, not a silent default.
        assert!(route(Some("  ")).resolved_upstream(443).is_err());
    }

    #[test]
    fn fail_policy_string_and_table_forms() {
        #[derive(Deserialize)]
        struct W {
            p: FailPolicy,
        }
        // Bare-string forms.
        let close: W = toml::from_str(r#"p = "close""#).unwrap();
        assert_eq!(close.p, FailPolicy::Close);
        let sysout: W = toml::from_str(r#"p = "system-outbound""#).unwrap();
        assert_eq!(sysout.p, FailPolicy::SystemOutbound);
        // Table form for passthrough (needs addr).
        let pass: W =
            toml::from_str(r#"p = { mode = "passthrough", addr = "127.0.0.1:80" }"#).unwrap();
        assert_eq!(
            pass.p,
            FailPolicy::Passthrough {
                addr: "127.0.0.1:80".parse().unwrap()
            }
        );
        // Table form for a field-less mode is also accepted (back-compat).
        let close2: W = toml::from_str(r#"p = { mode = "close" }"#).unwrap();
        assert_eq!(close2.p, FailPolicy::Close);
        // passthrough without addr is an error.
        assert!(toml::from_str::<W>(r#"p = { mode = "passthrough" }"#).is_err());
        // Unknown mode is an error.
        assert!(toml::from_str::<W>(r#"p = "bogus""#).is_err());
    }

    // A config exercising the fallback ladder: global sets defaults, the
    // listener overrides some, and one route overrides more.
    const HIER: &str = r#"
[global]
resolver = "https://global.example/dns-query"
nat64_prefix = "64:ff9b::"
connect_timeout = "9s"

[ca]
cert_path = "ca.crt"
key_path = "ca.key"

[[listener]]
addr = "0.0.0.0:443"
addr_resolver = "tls://1.1.1.1:853"
connect_timeout = "3s"

  [[listener.route]]
  name = "inherits"
  type = "tls"
  match_sni = [".inherit.com"]
  upstream = "u1:443"

  [[listener.route]]
  name = "overrides"
  type = "tls"
  match_sni = [".override.com"]
  upstream = "u2:443"
  nat64_prefix = "2a01:4f8:c2c:123f:64:5"
  connect_timeout = "1s"
  addr_resolver = "9.9.9.9"
"#;

    #[test]
    fn hierarchical_fallback() {
        let cfg: Config = toml::from_str(HIER).unwrap();
        cfg.validate().unwrap();
        let listener = &cfg.listeners[0];

        // Route 0 inherits: addr_resolver from listener, nat64 from global,
        // connect_timeout from the listener (nearer than global).
        let e0 = cfg.effective(listener, &listener.routes[0]);
        assert_eq!(e0.addr_resolver.as_deref(), Some("tls://1.1.1.1:853"));
        assert_eq!(e0.nat64_prefix.as_deref(), Some("64:ff9b::"));
        assert_eq!(e0.connect_timeout, Duration::from_secs(3));

        // Route 1 overrides all three at the route scope.
        let e1 = cfg.effective(listener, &listener.routes[1]);
        assert_eq!(e1.addr_resolver.as_deref(), Some("9.9.9.9"));
        assert_eq!(e1.nat64_prefix.as_deref(), Some("2a01:4f8:c2c:123f:64:5"));
        assert_eq!(e1.connect_timeout, Duration::from_secs(1));
    }
}
