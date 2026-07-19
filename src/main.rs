//! sni-gate — a multi-listener SNI/Host-routing TLS gateway.
//!
//! Each inbound port routes connections by TLS SNI (or HTTP Host) to an
//! upstream that may be ECH, plain TLS, cleartext HTTP, or raw passthrough.
//! Whenever it terminates TLS it issues a certificate for that name and its
//! wildcard from a local CA (persisted, cached, public-suffix-aware).

mod ca;
mod config;
mod dns;
mod ech;
mod error;
mod nat64;
mod peek;
mod proxy;
mod psl_source;
mod resolver;
mod router;
mod store;
mod suffix;
mod trust;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use rustls::{RootCertStore, ServerConfig};
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::ca::{CaParams, CertificateAuthority};
use crate::config::{Config, Listener, Route, RouteType};
use crate::dns::ResolverSpec;
use crate::ech::EchProvider;
use crate::nat64::Nat64Prefix;
use crate::proxy::{ListenerState, RouteRuntime};
use crate::resolver::{DynamicResolver, ResolverParams};
use crate::router::Router;
use crate::store::CertStore;

/// Resolver cache key: (spec string, address family).
type ResolverCache = HashMap<(String, config::AddressFamily), Arc<hickory_resolver::TokioResolver>>;

#[derive(Debug, Parser)]
#[command(
    name = "sni-gate",
    version,
    about = "SNI/Host-routing TLS gateway with dynamic cert issuance and ECH"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "sni-gate.toml")]
    config: PathBuf,
}

fn main() -> ExitCode {
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("fatal: failed to install the aws-lc-rs crypto provider");
        return ExitCode::FAILURE;
    }

    let cli = Cli::parse();
    let cfg = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            return ExitCode::FAILURE;
        }
    };
    init_tracing(&cfg.global.log);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "failed to build tokio runtime");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %format!("{e:#}"), "fatal");
            ExitCode::FAILURE
        }
    }
}

async fn run(cfg: Config) -> Result<()> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        listeners = cfg.listeners.len(),
        "starting sni-gate"
    );

    // --- Dynamic certificate stack (shared across all listeners) ---
    let ca = CertificateAuthority::load_or_generate(CaParams {
        cert_path: &cfg.ca.cert_path,
        key_path: &cfg.ca.key_path,
        common_name: &cfg.ca.common_name,
        organization: &cfg.ca.organization,
        country: &cfg.ca.country,
        leaf_validity_days: cfg.ca.leaf_validity_days,
    })
    .context("initializing certificate authority")?;

    if cfg.ca.install_to_system_root {
        if let Err(e) = trust::ensure_installed(ca.cert_der()) {
            tracing::warn!(error = %e, "could not install CA into system root store");
        }
    }

    let suffix = psl_source::load(&cfg.cache.psl).context("initializing public suffix list")?;
    psl_source::spawn_refresher(&cfg.cache.psl, suffix.clone());

    let store = if cfg.store.enabled {
        let s = CertStore::new(cfg.store.dir.clone(), cfg.store.renew_margin_days);
        s.init().context("initializing certificate store")?;
        Some(s)
    } else {
        None
    };

    let dyn_resolver = Arc::new(DynamicResolver::new(ResolverParams {
        ca,
        suffix,
        store,
        wildcard: cfg.issuance.wildcard,
        cache_capacity: cfg.cache.capacity,
        cache_ttl: Duration::from_secs(cfg.cache.ttl_secs),
    }));

    // One server config for local termination; the resolver issues for any SNI.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(dyn_resolver);
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    if let Ok(t) = rustls::crypto::aws_lc_rs::Ticketer::new() {
        server_config.ticketer = t;
    }
    server_config.session_storage = rustls::server::ServerSessionMemoryCache::new(8192);
    let tls_server_config = Arc::new(server_config);

    // Shared web-PKI roots for upstream TLS verification.
    let root_store = Arc::new(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    });

    let mut resolver_cache: ResolverCache = HashMap::new();

    // --- Build every listener ---
    let mut listener_states: Vec<Arc<ListenerState>> = Vec::new();
    for listener in &cfg.listeners {
        let state = build_listener(
            &cfg,
            listener,
            tls_server_config.clone(),
            root_store.clone(),
            &mut resolver_cache,
        )?;
        listener_states.push(Arc::new(state));
    }

    // --- Spawn all listeners ---
    let mut set = tokio::task::JoinSet::new();
    for st in listener_states {
        let addr = st.addr;
        set.spawn(async move {
            proxy::serve(st)
                .await
                .with_context(|| format!("listener {addr}"))
        });
    }

    tokio::select! {
        Some(joined) = set.join_next() => {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(e).context("listener task panicked"),
            }
        }
        _ = shutdown_signal() => info!("shutdown signal received; exiting"),
    }
    Ok(())
}

/// Assemble one listener's router + route runtimes from config.
fn build_listener(
    cfg: &Config,
    listener: &Listener,
    tls_server_config: Arc<ServerConfig>,
    root_store: Arc<RootCertStore>,
    resolver_cache: &mut ResolverCache,
) -> Result<ListenerState> {
    let mut runtimes: Vec<Arc<RouteRuntime>> = Vec::new();
    let mut patterns: Vec<Vec<String>> = Vec::new();

    for route in &listener.routes {
        runtimes.push(Arc::new(build_route(
            cfg,
            listener,
            route,
            &root_store,
            resolver_cache,
        )?));
        patterns.push(route.match_sni.clone());
    }

    let default_id = if let Some(d) = &listener.default_route {
        let id = runtimes.len();
        runtimes.push(Arc::new(build_route(
            cfg,
            listener,
            d,
            &root_store,
            resolver_cache,
        )?));
        patterns.push(Vec::new());
        Some(id)
    } else {
        None
    };

    let router = Router::build(&patterns, default_id)
        .map_err(|e| anyhow::anyhow!("listener {}: {e}", listener.addr))?;

    Ok(ListenerState {
        addr: listener.addr,
        router,
        routes: runtimes,
        tls_server_config,
        unmatched: cfg.global.unmatched.clone(),
    })
}

/// Build one route's runtime, flattening effective settings and building (or
/// reusing) its resolvers and ECH provider.
fn build_route(
    cfg: &Config,
    listener: &Listener,
    route: &Route,
    root_store: &Arc<RootCertStore>,
    resolver_cache: &mut ResolverCache,
) -> Result<RouteRuntime> {
    let eff = cfg.effective(listener, route);
    let (host, port) = route
        .upstream_host_port()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // NAT64 disabled in ipv6-only mode.
    let nat64 = match (&eff.nat64_prefix, eff.address_family) {
        (_, config::AddressFamily::Ipv6) => None,
        (Some(p), _) => Some(
            p.parse::<Nat64Prefix>()
                .with_context(|| format!("route {}: invalid nat64_prefix", route.label()))?,
        ),
        (None, _) => None,
    };

    let addr_spec = eff.addr_resolver.clone().unwrap_or_default();
    let addr_resolver = get_resolver(resolver_cache, &addr_spec, eff.address_family)?;

    let ech = if route.route_type == RouteType::Ech {
        let settings = route
            .ech
            .clone()
            .ok_or_else(|| anyhow::anyhow!("route {}: type=ech requires [ech]", route.label()))?;
        let ech_spec = eff.ech_resolver.clone().unwrap_or_default();
        // HTTPS records are resolved dual-family regardless of upstream family.
        let ech_resolver = get_resolver(resolver_cache, &ech_spec, config::AddressFamily::Dual)?;
        Some(EchProvider::new(
            settings,
            port,
            eff.require_ech,
            ech_resolver,
            root_store.clone(),
            eff.ech_refresh,
        ))
    } else {
        None
    };

    let max_retries = route.ech.as_ref().and_then(|e| e.max_retries).unwrap_or(2);

    Ok(RouteRuntime {
        name: route.label(),
        route_type: route.route_type,
        upstream_host: host,
        upstream_port: port,
        override_sni: route.override_sni.clone(),
        require_ech: eff.require_ech,
        max_retries,
        connect_timeout: eff.connect_timeout,
        idle_timeout: eff.idle_timeout,
        address_family: eff.address_family,
        nat64,
        fail: eff.fail,
        addr_resolver,
        ech,
        root_store: root_store.clone(),
    })
}

/// Get or build a resolver for `spec` under `family`.
fn get_resolver(
    cache: &mut ResolverCache,
    spec: &str,
    family: config::AddressFamily,
) -> Result<Arc<hickory_resolver::TokioResolver>> {
    let key = (spec.to_string(), family);
    if let Some(r) = cache.get(&key) {
        return Ok(r.clone());
    }
    let parsed = ResolverSpec::parse(spec).with_context(|| format!("resolver spec {spec:?}"))?;
    let r = parsed
        .build(family)
        .with_context(|| format!("building resolver {spec:?}"))?;
    cache.insert(key, r.clone());
    Ok(r)
}

fn init_tracing(directive: &str) {
    let filter = EnvFilter::try_from_env("SNI_GATE_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new(directive));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).with_ansi(false))
        .init();
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
