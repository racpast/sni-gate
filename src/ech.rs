//! ECH client-config acquisition and assembly.
//!
//! For a route of `type = "ech"`, this resolves the ECHConfigList (from DoH, a
//! static inline value, or DoH-with-static-fallback), turns it into a rustls
//! `ClientConfig` with ECH + TLS 1.3, and caches the result per inner name with
//! background-free TTL refresh. It also supports rebuilding from server-provided
//! `retry_configs` for the ECH retry path (driven by the proxy).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use hickory_resolver::proto::rr::rdata::svcb::SvcParamValue;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::aws_lc_rs::hpke::{ALL_SUPPORTED_SUITES, DH_KEM_X25519_HKDF_SHA256_AES_128};
use rustls::crypto::hpke::Hpke as _;
use rustls::pki_types::EchConfigListBytes;
use rustls::{ClientConfig, RootCertStore};
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::config::{EchConfig as EchSettings, EchMode as SourceMode};
use crate::error::EchError;

/// A resolved ECH client config plus its refresh deadline.
#[derive(Clone)]
struct Cached {
    client_config: Arc<ClientConfig>,
    refresh_at: Instant,
}

/// Per-route ECH provider, caching a client config per inner name.
pub struct EchProvider {
    settings: EchSettings,
    /// Fixed upstream port, used for RFC 9460 port-prefix HTTPS lookups.
    upstream_port: u16,
    require_ech: bool,
    resolver: Arc<TokioResolver>,
    root_store: Arc<RootCertStore>,
    refresh_bound: Duration,
    cache: RwLock<HashMap<String, Cached>>,
}

/// A ready-to-use ECH client config handed to the connection path.
pub struct EchClient {
    pub client_config: Arc<ClientConfig>,
}

impl EchProvider {
    pub fn new(
        settings: EchSettings,
        upstream_port: u16,
        require_ech: bool,
        resolver: Arc<TokioResolver>,
        root_store: Arc<RootCertStore>,
        refresh_bound: Duration,
    ) -> Self {
        Self {
            settings,
            upstream_port,
            require_ech,
            resolver,
            root_store,
            refresh_bound,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Return a client config with ECH set up for `inner_name`, (re)building from
    /// the source when the cached entry is missing or stale. On refresh failure
    /// the previous good entry is kept.
    pub async fn client(&self, inner_name: &str) -> Result<EchClient, EchError> {
        {
            let guard = self.cache.read().await;
            if let Some(c) = guard.get(inner_name) {
                if Instant::now() < c.refresh_at {
                    return Ok(c.into());
                }
            }
        }

        let mut guard = self.cache.write().await;
        if let Some(c) = guard.get(inner_name) {
            if Instant::now() < c.refresh_at {
                return Ok(c.into());
            }
        }

        match self.build(inner_name).await {
            Ok(fresh) => {
                let out = (&fresh).into();
                guard.insert(inner_name.to_string(), fresh);
                Ok(out)
            }
            Err(e) => {
                if let Some(c) = guard.get_mut(inner_name) {
                    warn!(inner = %inner_name, error = %e, "ECH refresh failed; keeping cached config");
                    c.refresh_at = Instant::now() + Duration::from_secs(30);
                    return Ok((&*c).into());
                }
                Err(e)
            }
        }
    }

    /// Evict the cached config for `inner_name` so the next `client()` call
    /// re-fetches a fresh ECHConfig. Used by the ECH retry path after the server
    /// rejects ECH (its published key rotated).
    pub async fn invalidate(&self, inner_name: &str) {
        self.cache.write().await.remove(inner_name);
    }

    async fn build(&self, inner_name: &str) -> Result<Cached, EchError> {
        let (ech_bytes, ttl) = self.acquire_config_list(inner_name).await?;

        let (mode, real_ech) = match ech_bytes {
            Some(bytes) => (build_real_ech_mode(bytes)?, true),
            None => {
                if self.require_ech {
                    return Err(EchError::NoRecord(self.lookup_name(inner_name)));
                }
                warn!(inner = %inner_name, "no ECHConfig; sending GREASE (require_ech = false)");
                (grease_mode()?, false)
            }
        };

        let client_config = Arc::new(self.assemble_client_config(mode)?);
        let refresh = ttl
            .map(|t| t.min(self.refresh_bound))
            .unwrap_or(self.refresh_bound)
            .max(Duration::from_secs(5));

        debug!(inner = %inner_name, real_ech, refresh_secs = refresh.as_secs(), "assembled ECH client config");
        Ok(Cached {
            client_config,
            refresh_at: Instant::now() + refresh,
        })
    }

    async fn acquire_config_list(
        &self,
        inner_name: &str,
    ) -> Result<(Option<EchConfigListBytes<'static>>, Option<Duration>), EchError> {
        match self.settings.mode {
            SourceMode::Static => {
                let cfg = self
                    .settings
                    .config
                    .as_deref()
                    .ok_or_else(|| EchError::NoCompatibleConfig)?;
                Ok((Some(decode_ech_b64(cfg)?), None))
            }
            SourceMode::Doh => match self.lookup_doh(inner_name).await {
                Ok(Some((b, ttl))) => Ok((Some(b), ttl)),
                Ok(None) => Ok((None, None)),
                Err(e) => Err(e),
            },
            SourceMode::DohWithFallback => match self.lookup_doh(inner_name).await {
                Ok(Some((b, ttl))) => Ok((Some(b), ttl)),
                _ => {
                    let cfg = self
                        .settings
                        .config
                        .as_deref()
                        .ok_or_else(|| EchError::NoCompatibleConfig)?;
                    warn!(inner = %inner_name, "DoH ECH lookup empty; using static fallback");
                    Ok((Some(decode_ech_b64(cfg)?), None))
                }
            },
        }
    }

    /// The DNS name whose HTTPS record carries `ech=`. Uses the configured
    /// `ech_domain` if set, else the inner name; RFC 9460 port-prefix for non-443.
    fn lookup_name(&self, inner_name: &str) -> String {
        let base = self.settings.ech_domain.as_deref().unwrap_or(inner_name);
        match self.upstream_port {
            443 => base.to_string(),
            p => format!("_{p}._https.{base}"),
        }
    }

    async fn lookup_doh(
        &self,
        inner_name: &str,
    ) -> Result<Option<(EchConfigListBytes<'static>, Option<Duration>)>, EchError> {
        let name = self.lookup_name(inner_name);
        let lookup = self
            .resolver
            .lookup(name.clone(), RecordType::HTTPS)
            .await
            .map_err(|e| EchError::Lookup {
                name: name.clone(),
                source: anyhow::Error::new(e),
            })?;

        for record in lookup.answers() {
            let ttl = Some(Duration::from_secs(record.ttl as u64));
            if let RData::HTTPS(https) = &record.data {
                for (_key, value) in &https.svc_params {
                    if let SvcParamValue::EchConfigList(list) = value {
                        let bytes = EchConfigListBytes::from(list.0.clone());
                        return Ok(Some((bytes, ttl)));
                    }
                }
            }
        }
        Ok(None)
    }

    fn assemble_client_config(&self, ech_mode: EchMode) -> Result<ClientConfig, EchError> {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = ClientConfig::builder_with_provider(provider.into())
            .with_ech(ech_mode)
            .map_err(EchError::Rustls)?
            .with_root_certificates(self.root_store.as_ref().clone())
            .with_no_client_auth();
        Ok(config)
    }
}

impl From<&Cached> for EchClient {
    fn from(c: &Cached) -> Self {
        EchClient {
            client_config: c.client_config.clone(),
        }
    }
}

/// Decode a base64 ECHConfigList.
fn decode_ech_b64(s: &str) -> Result<EchConfigListBytes<'static>, EchError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(EchError::Base64)?;
    Ok(EchConfigListBytes::from(raw))
}

/// Build a real-ECH mode, selecting a compatible HPKE suite.
fn build_real_ech_mode(bytes: EchConfigListBytes<'static>) -> Result<EchMode, EchError> {
    let config =
        EchConfig::new(bytes, ALL_SUPPORTED_SUITES).map_err(|_| EchError::NoCompatibleConfig)?;
    Ok(EchMode::from(config))
}

/// Build a GREASE mode (anti-ossification placeholder).
fn grease_mode() -> Result<EchMode, EchError> {
    let suite = DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (public_key, _secret) = suite.generate_key_pair().map_err(EchError::Rustls)?;
    Ok(EchMode::from(EchGreaseConfig::new(suite, public_key)))
}
