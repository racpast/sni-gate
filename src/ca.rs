//! Certificate authority: load an existing local CA or generate one, and
//! issue short-lived leaf certificates for arbitrary SNI host names.

use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::CertificateDer;
use time::{Duration, OffsetDateTime};

/// A loaded certificate authority capable of issuing leaf certificates.
///
/// The owned [`Issuer`] holds the CA distinguished name, key-usage set and
/// signing key, and is reused across every issuance.
pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    /// CA certificate in DER form, appended to every issued chain so clients
    /// that lack the root can still build a path (harmless if already trusted).
    ca_cert_der: CertificateDer<'static>,
    /// CA certificate PEM, appended to persisted leaf chains.
    ca_cert_pem: String,
    leaf_validity: Duration,
    /// Organization (O) stamped onto issued leaf certificates. Empty = omit.
    organization: String,
    /// Country (C) stamped onto issued leaf certificates. Empty = omit.
    country: String,
}

/// Parameters for loading or generating a CA.
pub struct CaParams<'a> {
    pub cert_path: &'a Path,
    pub key_path: &'a Path,
    pub common_name: &'a str,
    pub organization: &'a str,
    pub country: &'a str,
    pub leaf_validity_days: u32,
}

impl CertificateAuthority {
    /// Load the CA from disk, generating and persisting a fresh one if either
    /// the certificate or the key file is missing.
    pub fn load_or_generate(params: CaParams<'_>) -> Result<Self> {
        let leaf_validity = Duration::days(i64::from(params.leaf_validity_days));

        if params.cert_path.exists() && params.key_path.exists() {
            Self::load(&params, leaf_validity)
                .with_context(|| format!("loading CA from {}", params.cert_path.display()))
        } else {
            Self::generate(&params, leaf_validity)
                .with_context(|| format!("generating CA at {}", params.cert_path.display()))
        }
    }

    /// Path on disk where the CA certificate lives, for trust-store install.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    fn load(params: &CaParams<'_>, leaf_validity: Duration) -> Result<Self> {
        let cert_pem =
            std::fs::read_to_string(params.cert_path).context("reading CA certificate")?;
        let key_pem = std::fs::read_to_string(params.key_path).context("reading CA private key")?;

        let key_pair = KeyPair::from_pem(&key_pem).context("parsing CA private key")?;
        let ca_cert_der = pem_to_der(&cert_pem).context("decoding CA certificate PEM")?;

        // `from_ca_cert_pem` reconstructs the issuer (DN + key usages) from the
        // stored certificate, so re-issued leaves keep a consistent issuer name.
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
            .context("reconstructing issuer from CA certificate")?;

        tracing::info!(cert = %params.cert_path.display(), "loaded existing CA");
        Ok(Self {
            issuer,
            ca_cert_der,
            ca_cert_pem: cert_pem.clone(),
            leaf_validity,
            organization: params.organization.to_string(),
            country: params.country.to_string(),
        })
    }

    fn generate(params: &CaParams<'_>, leaf_validity: Duration) -> Result<Self> {
        let key_pair = KeyPair::generate().context("generating CA key pair")?;

        let mut cert_params = CertificateParams::default();
        cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        cert_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        cert_params.distinguished_name =
            build_dn(params.common_name, params.organization, params.country);

        let now = OffsetDateTime::now_utc();
        cert_params.not_before = now - Duration::days(1);
        cert_params.not_after = now + Duration::days(3650); // 10 years for the root.

        let ca_cert = cert_params
            .self_signed(&key_pair)
            .context("self-signing CA certificate")?;

        let cert_pem = ca_cert.pem();
        let key_pem = key_pair.serialize_pem();

        if let Some(parent) = params.cert_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(params.cert_path, &cert_pem).context("writing CA certificate")?;
        write_private_key(params.key_path, &key_pem).context("writing CA private key")?;

        let ca_cert_der = ca_cert.der().clone();
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
            .context("building issuer from generated CA")?;

        tracing::warn!(
            cert = %params.cert_path.display(),
            key = %params.key_path.display(),
            "generated a new local CA; import the certificate into your trust store"
        );
        Ok(Self {
            issuer,
            ca_cert_der,
            ca_cert_pem: cert_pem.clone(),
            leaf_validity,
            organization: params.organization.to_string(),
            country: params.country.to_string(),
        })
    }

    /// Issue a leaf certificate covering `sans`, with `common_name` as the CN.
    ///
    /// `sans` may contain DNS names (including single-level wildcards like
    /// `*.a.com`) and IP literals. Returns the DER-encoded chain (leaf first,
    /// CA appended), the leaf's PKCS#8 private key in DER form, and the leaf's
    /// expiry so callers can schedule renewal.
    pub fn issue(&self, common_name: &str, sans: &[String]) -> Result<IssuedCertificate> {
        let key_pair = KeyPair::generate().context("generating leaf key pair")?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.subject_alt_names = sans
            .iter()
            .map(|s| san_for_name(s))
            .collect::<Result<Vec<_>>>()?;

        params.distinguished_name = build_dn(common_name, &self.organization, &self.country);

        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1); // tolerate minor clock skew
        params.not_after = now + self.leaf_validity;

        let leaf = params
            .signed_by(&key_pair, &self.issuer)
            .context("signing leaf certificate")?;

        // PEM chain (leaf + CA) for persistence; DER for the live rustls key.
        let chain_pem = format!("{}{}", leaf.pem(), self.ca_cert_pem);
        let key_pem = key_pair.serialize_pem();

        let chain = vec![leaf.der().clone(), self.ca_cert_der.clone()];
        let key_der = key_pair.serialize_der();

        Ok(IssuedCertificate {
            chain,
            key_der,
            chain_pem,
            key_pem,
        })
    }
}

/// A freshly issued leaf certificate and its private key.
pub struct IssuedCertificate {
    pub chain: Vec<CertificateDer<'static>>,
    pub key_der: Vec<u8>,
    /// PEM chain (leaf first, CA appended) for on-disk persistence.
    pub chain_pem: String,
    /// PEM PKCS#8 private key for on-disk persistence.
    pub key_pem: String,
}

/// Build a distinguished name, omitting empty organization/country fields.
fn build_dn(common_name: &str, organization: &str, country: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    if !organization.is_empty() {
        dn.push(DnType::OrganizationName, organization);
    }
    if !country.is_empty() {
        dn.push(DnType::CountryName, country);
    }
    dn
}

/// Build a subject-alternative-name entry, choosing DNS vs IP automatically.
/// DNS names may be wildcards (e.g. `*.a.com`).
fn san_for_name(name: &str) -> Result<SanType> {
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        Ok(SanType::IpAddress(ip))
    } else {
        let dns = name
            .try_into()
            .with_context(|| format!("{name:?} is not a valid DNS name"))?;
        Ok(SanType::DnsName(dns))
    }
}

/// Decode a single PEM certificate block into DER.
fn pem_to_der(cert_pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = std::io::Cursor::new(cert_pem.as_bytes());
    let der = rustls_pemfile::certs(&mut reader)
        .next()
        .context("no certificate found in CA PEM")?
        .context("malformed certificate in CA PEM")?;
    Ok(der)
}

/// Write a private key with owner-only permissions where the platform allows.
fn write_private_key(path: &Path, pem: &str) -> Result<()> {
    std::fs::write(path, pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
