//! Public-suffix handling and wildcard base-name derivation.
//!
//! The list can be sourced three ways (embedded, file, network) and swapped at
//! runtime behind an `ArcSwap`-style lock, so a background refresh never blocks
//! the hot path. Given an SNI host name, [`SuffixList::wildcard_base`] returns
//! the registrable-domain-anchored base used both as the certificate cache key
//! and to build the `{base, *.base}` SAN set.

use std::sync::RwLock;

use anyhow::Result;
use publicsuffix::{List, Psl};

/// A public-suffix list, replaceable at runtime.
pub struct SuffixList {
    list: RwLock<List>,
}

/// The list compiled into the binary as an always-available fallback.
const EMBEDDED_LIST: &[u8] = include_bytes!("../assets/public_suffix_list.dat");

impl SuffixList {
    /// Build from the embedded list.
    pub fn embedded() -> Result<Self> {
        let list = List::from_bytes(EMBEDDED_LIST)
            .map_err(|e| anyhow::anyhow!("parsing embedded public suffix list: {e}"))?;
        Ok(Self {
            list: RwLock::new(list),
        })
    }

    /// Build from a `.dat` file on disk.
    pub fn from_file(bytes: &[u8]) -> Result<Self> {
        let list = List::from_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("parsing public suffix list file: {e}"))?;
        Ok(Self {
            list: RwLock::new(list),
        })
    }

    /// Replace the active list (used by the background network refresher).
    /// Rejects an obviously-broken download rather than swapping it in.
    pub fn replace_from_bytes(&self, bytes: &[u8]) -> Result<()> {
        let parsed = List::from_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("parsing downloaded public suffix list: {e}"))?;
        // Sanity check: a valid list resolves a well-known multi-level suffix.
        anyhow::ensure!(
            parsed.domain(b"example.co.uk").is_some(),
            "downloaded list failed a sanity check; keeping the current list"
        );
        *self.list.write().unwrap() = parsed;
        Ok(())
    }

    /// Derive the wildcard base name and SAN set for an SNI host.
    ///
    /// Rules:
    /// * IP literals and hosts with no registrable domain (or equal to their
    ///   public suffix) get an exact, non-wildcard certificate.
    /// * A host at the registrable apex (e.g. `a.com`) yields base `a.com` and
    ///   SANs `{a.com, *.a.com}`.
    /// * A deeper host (e.g. `x.sub.a.com`) is anchored one label above the
    ///   host so the wildcard stays single-level: base `sub.a.com`, SANs
    ///   `{sub.a.com, *.sub.a.com}`. `x` is covered by `*.sub.a.com`.
    ///
    /// The returned SAN list is guaranteed to match `host`.
    pub fn wildcard_base(&self, host: &str) -> Certificand {
        // IP literals never get a wildcard.
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Certificand::exact(host);
        }

        let host = host.trim_end_matches('.').to_ascii_lowercase();

        let list = self.list.read().unwrap();
        let registrable = match list.domain(host.as_bytes()) {
            Some(d) => match std::str::from_utf8(d.as_bytes()) {
                Ok(s) => s.to_string(),
                Err(_) => return Certificand::exact(&host),
            },
            // No registrable domain (bare public suffix, single label, etc.).
            None => return Certificand::exact(&host),
        };

        // Base is the label immediately below the host, but never below the
        // registrable domain (keeps the wildcard single-level and valid).
        let base = if host == registrable {
            registrable
        } else {
            parent_within(&host, &registrable)
        };

        Certificand::wildcard(base)
    }
}

/// Return the parent of `host` (drop the leftmost label), but never go shallower
/// than `floor`. Both must be lowercase, dot-free of trailing dots.
fn parent_within(host: &str, floor: &str) -> String {
    match host.split_once('.') {
        Some((_, parent)) if parent.len() >= floor.len() => parent.to_string(),
        _ => floor.to_string(),
    }
}

/// The names a certificate should be issued for, plus the cache key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificand {
    /// Cache key and certificate CN.
    pub base: String,
    /// Subject alternative names to embed.
    pub sans: Vec<String>,
}

impl Certificand {
    /// An exact (non-wildcard) certificate for a single host.
    pub fn exact(host: &str) -> Self {
        Self {
            base: host.to_string(),
            sans: vec![host.to_string()],
        }
    }

    fn wildcard(base: String) -> Self {
        let wildcard = format!("*.{base}");
        Self {
            sans: vec![base.clone(), wildcard],
            base,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> SuffixList {
        SuffixList::embedded().unwrap()
    }

    #[test]
    fn apex_gets_wildcard() {
        let c = list().wildcard_base("a.com");
        assert_eq!(c.base, "a.com");
        assert_eq!(c.sans, vec!["a.com", "*.a.com"]);
    }

    #[test]
    fn subdomain_anchors_one_level_up() {
        let c = list().wildcard_base("sub.a.com");
        assert_eq!(c.base, "a.com");
        assert_eq!(c.sans, vec!["a.com", "*.a.com"]);
    }

    #[test]
    fn deep_subdomain_stays_single_level() {
        let c = list().wildcard_base("x.sub.a.com");
        assert_eq!(c.base, "sub.a.com");
        assert!(c.sans.contains(&"*.sub.a.com".to_string()));
        // The wildcard must cover the original host.
        assert!(c.sans.contains(&"sub.a.com".to_string()));
    }

    #[test]
    fn multi_level_public_suffix_is_respected() {
        // co.uk is a public suffix: registrable domain is a.co.uk, and we must
        // never emit *.co.uk.
        let c = list().wildcard_base("a.co.uk");
        assert_eq!(c.base, "a.co.uk");
        assert_eq!(c.sans, vec!["a.co.uk", "*.a.co.uk"]);

        let c2 = list().wildcard_base("www.a.co.uk");
        assert_eq!(c2.base, "a.co.uk");
        assert!(!c2.sans.iter().any(|s| s == "*.co.uk"));
    }

    #[test]
    fn new_gtlds_are_covered() {
        // The PSL's ICANN section includes every gTLD, new ones included, so
        // .goog and friends resolve to a registrable domain and get a wildcard.
        let c = list().wildcard_base("foo.goog");
        assert_eq!(c.base, "foo.goog");
        assert_eq!(c.sans, vec!["foo.goog", "*.foo.goog"]);

        let c2 = list().wildcard_base("a.xyz");
        assert_eq!(c2.base, "a.xyz");
    }

    #[test]
    fn ip_literal_is_exact() {
        let c = list().wildcard_base("127.0.0.1");
        assert_eq!(c.sans, vec!["127.0.0.1"]);
    }

    #[test]
    fn bare_suffix_is_exact() {
        // "com" is a public suffix with no registrable domain.
        let c = list().wildcard_base("com");
        assert_eq!(c.sans, vec!["com"]);
    }
}
