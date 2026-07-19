//! Optional installation of the CA certificate into the OS trusted-root store.
//!
//! This is a sensitive, privileged operation, so it is opt-in via
//! `ca.install_to_system_root`. Installation is idempotent: if a certificate
//! with the same SHA-1 fingerprint is already trusted, nothing is done.

use anyhow::Result;
use rustls::pki_types::CertificateDer;
use sha1::{Digest, Sha1};

/// Ensure the CA certificate is present in the OS trusted-root store.
pub fn ensure_installed(ca_der: &CertificateDer<'_>) -> Result<()> {
    let fingerprint = sha1_hex(ca_der.as_ref());

    #[cfg(windows)]
    {
        windows::ensure_installed(ca_der, &fingerprint)
    }
    #[cfg(not(windows))]
    {
        let _ = (ca_der, &fingerprint);
        anyhow::bail!("automatic CA installation is only implemented on Windows");
    }
}

/// Uppercase hex SHA-1, the thumbprint format the Windows cert store uses.
fn sha1_hex(der: &[u8]) -> String {
    let digest = Sha1::digest(der);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

#[cfg(windows)]
mod windows {
    use super::*;
    use anyhow::Context;
    use std::io::Write;
    use std::process::Command;

    /// Install into `Cert:\LocalMachine\Root` via `certutil`, skipping if the
    /// thumbprint is already present.
    pub fn ensure_installed(ca_der: &CertificateDer<'_>, fingerprint: &str) -> Result<()> {
        if is_present(fingerprint)? {
            tracing::info!(fingerprint, "CA already trusted; skipping installation");
            return Ok(());
        }

        // Write the DER to a temp file for certutil to read.
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("sni-frontend-ca-{fingerprint}.cer"));
        {
            let mut f = std::fs::File::create(&tmp).context("creating temp CA file")?;
            f.write_all(ca_der.as_ref())
                .context("writing temp CA file")?;
        }

        let output = Command::new("certutil")
            .args(["-addstore", "-f", "Root"])
            .arg(&tmp)
            .output()
            .context("running certutil -addstore (Administrator required)")?;

        let _ = std::fs::remove_file(&tmp);

        if output.status.success() {
            tracing::warn!(fingerprint, "installed CA into LocalMachine Root store");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "certutil -addstore failed (need Administrator?): {}",
                stderr.trim()
            );
        }
    }

    /// True if a certificate with this thumbprint is already in the Root store.
    fn is_present(fingerprint: &str) -> Result<bool> {
        let output = Command::new("certutil")
            .args(["-store", "Root", fingerprint])
            .output()
            .context("running certutil -store")?;
        Ok(output.status.success())
    }
}
