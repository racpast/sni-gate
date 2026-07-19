//! On-disk persistence of issued certificates.
//!
//! Each certificate is stored as a `<base>.crt` (PEM chain, leaf first) and a
//! `<base>.key` (PEM PKCS#8 private key) pair, keyed by the wildcard base name.
//! Because a base is a registrable domain or a subdomain (never a wildcard or
//! IP with path-unsafe characters), it maps directly to a safe file stem.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration, OffsetDateTime};

/// Manages the certificate directory.
pub struct CertStore {
    dir: PathBuf,
    /// Re-issue when a persisted certificate is within this margin of expiry.
    renew_margin: Duration,
}

/// Certificate material loaded from disk.
pub struct StoredCertificate {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub not_after: OffsetDateTime,
}

impl CertStore {
    pub fn new(dir: PathBuf, renew_margin_days: u32) -> Self {
        Self {
            dir,
            renew_margin: Duration::days(i64::from(renew_margin_days)),
        }
    }

    /// Ensure the store directory exists.
    pub fn init(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating certificate store {}", self.dir.display()))
    }

    fn cert_path(&self, base: &str) -> PathBuf {
        self.dir.join(format!("{base}.crt"))
    }

    fn key_path(&self, base: &str) -> PathBuf {
        self.dir.join(format!("{base}.key"))
    }

    /// Load a persisted certificate for `base`, if present and not within the
    /// renewal margin of expiry. Returns `None` to signal "issue a fresh one".
    pub fn load(&self, base: &str) -> Option<StoredCertificate> {
        let cert_path = self.cert_path(base);
        let key_path = self.key_path(base);
        if !cert_path.exists() || !key_path.exists() {
            return None;
        }
        match self.load_inner(&cert_path, &key_path) {
            Ok(stored) if !self.needs_renewal(stored.not_after) => Some(stored),
            Ok(_) => {
                tracing::debug!(base, "persisted certificate near expiry; will re-issue");
                None
            }
            Err(err) => {
                tracing::warn!(base, error = %err, "failed to load persisted certificate; re-issuing");
                None
            }
        }
    }

    fn load_inner(&self, cert_path: &Path, key_path: &Path) -> Result<StoredCertificate> {
        let cert_pem = std::fs::read(cert_path).context("reading persisted certificate")?;
        let key_pem = std::fs::read(key_path).context("reading persisted key")?;

        let chain = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parsing persisted certificate chain")?;
        anyhow::ensure!(!chain.is_empty(), "persisted certificate chain is empty");

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("parsing persisted private key")?
            .context("persisted key file contains no private key")?;

        let not_after =
            leaf_not_after(&chain[0]).context("reading persisted certificate expiry")?;

        Ok(StoredCertificate {
            chain,
            key,
            not_after,
        })
    }

    /// Persist a certificate chain and key for `base`, written atomically so a
    /// crash mid-write never leaves a half-file that would fail to load.
    pub fn save(&self, base: &str, chain_pem: &str, key_pem: &str) -> Result<()> {
        write_atomic(&self.cert_path(base), chain_pem.as_bytes())
            .context("persisting certificate chain")?;
        write_atomic_private(&self.key_path(base), key_pem.as_bytes())
            .context("persisting private key")?;
        Ok(())
    }

    fn needs_renewal(&self, not_after: OffsetDateTime) -> bool {
        OffsetDateTime::now_utc() + self.renew_margin >= not_after
    }
}

/// Extract the `notAfter` time from a DER-encoded certificate.
fn leaf_not_after(der: &CertificateDer<'_>) -> Result<OffsetDateTime> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
        .map_err(|e| anyhow::anyhow!("parsing certificate DER: {e}"))?;
    let ts = cert.validity().not_after.timestamp();
    OffsetDateTime::from_unix_timestamp(ts).context("certificate notAfter out of range")
}

/// Atomically write `bytes` to `path` via a temporary file + rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Atomically write a private key, restricting permissions where supported.
fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
