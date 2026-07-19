//! `ResolvesServerCert` implementation that mints (and caches) a certificate
//! for whatever SNI host name the client presents during the TLS handshake.
//!
//! Lookup order for each SNI host:
//!   1. In-memory cache, keyed by the wildcard base (so every sibling
//!      subdomain of `a.com` shares one cached certificate).
//!   2. On-disk store (if persistence is enabled), re-hydrated into the cache.
//!   3. Fresh issuance from the CA, then persisted and cached.
//!
//! Issuance for a given base is de-duplicated (single-flight), so a burst of
//! concurrent first-time handshakes signs the certificate only once.

use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::aws_lc_rs::sign::any_ecdsa_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::ca::CertificateAuthority;
use crate::store::CertStore;
use crate::suffix::SuffixList;

/// Resolves a server certificate per SNI, issuing on demand and caching the
/// result by wildcard base name.
pub struct DynamicResolver {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for DynamicResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicResolver")
            .field("cache_entries", &self.inner.cache.entry_count())
            .finish()
    }
}

struct Inner {
    ca: CertificateAuthority,
    suffix: Arc<SuffixList>,
    store: Option<CertStore>,
    wildcard: bool,
    cache: moka::sync::Cache<String, Arc<CertifiedKey>>,
    /// Per-base locks providing single-flight issuance.
    locks: moka::sync::Cache<String, Arc<std::sync::Mutex<()>>>,
}

/// Construction parameters for [`DynamicResolver`].
pub struct ResolverParams {
    pub ca: CertificateAuthority,
    pub suffix: Arc<SuffixList>,
    pub store: Option<CertStore>,
    pub wildcard: bool,
    pub cache_capacity: u64,
    pub cache_ttl: Duration,
}

impl DynamicResolver {
    pub fn new(params: ResolverParams) -> Self {
        let cache = moka::sync::Cache::builder()
            .max_capacity(params.cache_capacity)
            .time_to_live(params.cache_ttl)
            .build();
        let locks = moka::sync::Cache::builder()
            .max_capacity(params.cache_capacity)
            .time_to_idle(Duration::from_secs(60))
            .build();
        Self {
            inner: Arc::new(Inner {
                ca: params.ca,
                suffix: params.suffix,
                store: params.store,
                wildcard: params.wildcard,
                cache,
                locks,
            }),
        }
    }

    /// Return a certificate for `sni_host`, from cache, disk, or fresh issuance.
    fn get_or_issue(&self, sni_host: &str) -> anyhow::Result<Arc<CertifiedKey>> {
        let inner = &self.inner;

        // Compute the wildcard base (or exact name when wildcards are off).
        let certificand = if inner.wildcard {
            inner.suffix.wildcard_base(sni_host)
        } else {
            crate::suffix::Certificand::exact(sni_host)
        };
        let base = certificand.base.clone();

        if let Some(existing) = inner.cache.get(&base) {
            return Ok(existing);
        }

        // Single-flight: only one task issues for a given base at a time.
        let lock = inner
            .locks
            .get_with(base.clone(), || Arc::new(std::sync::Mutex::new(())));
        let _guard = lock.lock().unwrap_or_else(|p| p.into_inner());

        // Another task may have populated the cache while we waited.
        if let Some(existing) = inner.cache.get(&base) {
            return Ok(existing);
        }

        // Try the on-disk store before signing anew.
        if let Some(store) = &inner.store {
            if let Some(stored) = store.load(&base) {
                let key = any_ecdsa_type(&stored.key)
                    .map_err(|e| anyhow::anyhow!("loading persisted key for {base}: {e}"))?;
                let certified = Arc::new(CertifiedKey::new(stored.chain, key));
                inner.cache.insert(base.clone(), certified.clone());
                tracing::info!(base = %base, "loaded certificate from store");
                return Ok(certified);
            }
        }

        // Issue fresh.
        let issued = inner.ca.issue(&base, &certificand.sans)?;
        let key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(issued.key_der.clone().into()))
            .map_err(|e| anyhow::anyhow!("loading issued key for {base}: {e}"))?;
        let certified = Arc::new(CertifiedKey::new(issued.chain.clone(), key));

        if let Some(store) = &inner.store {
            if let Err(err) = store.save(&base, &issued.chain_pem, &issued.key_pem) {
                // Persistence is best-effort; serving continues from memory.
                tracing::warn!(base = %base, error = %err, "failed to persist certificate");
            }
        }

        inner.cache.insert(base.clone(), certified.clone());
        tracing::info!(base = %base, sans = ?certificand.sans, "issued certificate");
        Ok(certified)
    }
}

impl ResolvesServerCert for DynamicResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = match client_hello.server_name() {
            Some(name) => name,
            None => {
                tracing::debug!("handshake without SNI; no certificate resolved");
                return None;
            }
        };

        match self.get_or_issue(host) {
            Ok(key) => Some(key),
            Err(err) => {
                tracing::error!(host, error = %err, "certificate issuance failed");
                None
            }
        }
    }
}
