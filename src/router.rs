//! SNI/Host router.
//!
//! Patterns are compiled once at startup into O(1) lookup maps (exact, wildcard,
//! suffix) plus a precompiled regex list. Matching follows a fixed precedence so
//! the most specific rule always wins:
//!
//!   1. exact       `p.example.com`
//!   2. wildcard    `*.example.com`  (one left label)
//!   3. suffix      `.example.com`   (example.com and any subdomain)
//!   4. regex       `~<pattern>`     (config order)
//!   5. default server
//!
//! Hosts are normalized (lowercased, trailing dot removed) before matching.

use std::collections::HashMap;

use regex::Regex;

use crate::error::ConfigError;

/// Index into the runtime route table. The default server, if present, is a
/// route like any other and is referenced by its own id.
pub type RouteId = usize;

/// A compiled router. Cheap to share behind an `Arc`.
#[derive(Debug)]
pub struct Router {
    exact: HashMap<String, RouteId>,
    /// Keyed by the parent domain: `*.example.com` -> "example.com".
    wildcard: HashMap<String, RouteId>,
    /// Keyed by the domain: `.example.com` -> "example.com".
    suffix: HashMap<String, RouteId>,
    regex: Vec<(Regex, RouteId)>,
    default: Option<RouteId>,
}

impl Router {
    /// Build a router from each route's patterns. `patterns[i]` are the raw
    /// `match_sni` entries for route id `i`. `default` is the id of the default
    /// server route, if any.
    ///
    /// Later duplicate keys within the same tier are rejected so routing is
    /// deterministic and misconfiguration is caught at load time.
    pub fn build(patterns: &[Vec<String>], default: Option<RouteId>) -> Result<Self, ConfigError> {
        let mut exact = HashMap::new();
        let mut wildcard = HashMap::new();
        let mut suffix = HashMap::new();
        let mut regex = Vec::new();

        for (id, pats) in patterns.iter().enumerate() {
            for pat in pats {
                let pat = pat.trim();
                if pat.is_empty() {
                    continue;
                }
                if let Some(rest) = pat.strip_prefix('~') {
                    let re = Regex::new(rest).map_err(|e| {
                        ConfigError::Invalid(format!("invalid regex pattern `{pat}`: {e}"))
                    })?;
                    regex.push((re, id));
                } else if let Some(rest) = pat.strip_prefix("*.") {
                    insert_unique(&mut wildcard, normalize(rest), id, pat)?;
                } else if let Some(rest) = pat.strip_prefix('.') {
                    insert_unique(&mut suffix, normalize(rest), id, pat)?;
                } else {
                    insert_unique(&mut exact, normalize(pat), id, pat)?;
                }
            }
        }

        Ok(Router {
            exact,
            wildcard,
            suffix,
            regex,
            default,
        })
    }

    /// Resolve a host to a route id following the precedence order. Returns the
    /// default server id when nothing else matches (or `None` if there is none).
    pub fn match_host(&self, host: &str) -> Option<RouteId> {
        let host = normalize(host);
        if host.is_empty() {
            return self.default;
        }

        // 1. exact
        if let Some(&id) = self.exact.get(&host) {
            return Some(id);
        }

        // 2. wildcard: strip exactly one leftmost label, match the parent.
        if let Some(parent) = host.split_once('.').map(|(_, rest)| rest) {
            if let Some(&id) = self.wildcard.get(parent) {
                return Some(id);
            }
        }

        // 3. suffix: the domain itself, or any ancestor domain.
        //    e.g. host = a.b.example.com is checked against a.b.example.com,
        //    b.example.com, example.com, com — the first present in the suffix
        //    map wins. `.example.com` is stored as key "example.com" so it
        //    matches both example.com and any subdomain.
        if !self.suffix.is_empty() {
            let mut cur = host.as_str();
            loop {
                if let Some(&id) = self.suffix.get(cur) {
                    return Some(id);
                }
                match cur.split_once('.') {
                    Some((_, rest)) => cur = rest,
                    None => break,
                }
            }
        }

        // 4. regex, in config order
        for (re, id) in &self.regex {
            if re.is_match(&host) {
                return Some(*id);
            }
        }

        // 5. default
        self.default
    }
}

/// Normalize a host for matching: lowercase, strip a trailing dot, strip a
/// port suffix if present (Host headers may carry `:port`).
fn normalize(host: &str) -> String {
    let host = host.trim();
    // Strip a :port (but not part of an IPv6 literal in brackets).
    let host = if host.starts_with('[') {
        host
    } else {
        host.split(':').next().unwrap_or(host)
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn insert_unique(
    map: &mut HashMap<String, RouteId>,
    key: String,
    id: RouteId,
    pat: &str,
) -> Result<(), ConfigError> {
    if map.contains_key(&key) {
        return Err(ConfigError::Invalid(format!(
            "duplicate match pattern `{pat}` maps to more than one route"
        )));
    }
    map.insert(key, id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> Router {
        // id 0: exact p.nginxsni.com
        // id 1: suffix .nginxsni.com
        // id 2: wildcard *.wild.com
        // id 3: regex ^p[0-9]+\.re\.com$
        Router::build(
            &[
                vec!["p.nginxsni.com".into()],
                vec![".nginxsni.com".into()],
                vec!["*.wild.com".into()],
                vec!["~^p[0-9]+\\.re\\.com$".into()],
            ],
            Some(9),
        )
        .unwrap()
    }

    #[test]
    fn exact_beats_suffix() {
        assert_eq!(router().match_host("p.nginxsni.com"), Some(0));
    }

    #[test]
    fn suffix_matches_sub_and_root() {
        let r = router();
        assert_eq!(r.match_host("x.nginxsni.com"), Some(1));
        assert_eq!(r.match_host("nginxsni.com"), Some(1));
        assert_eq!(r.match_host("a.b.nginxsni.com"), Some(1));
    }

    #[test]
    fn wildcard_one_label_only() {
        let r = router();
        assert_eq!(r.match_host("a.wild.com"), Some(2));
        // two labels left of wild.com must NOT match the wildcard
        assert_eq!(r.match_host("a.b.wild.com"), Some(9)); // falls to default
    }

    #[test]
    fn regex_matches() {
        assert_eq!(router().match_host("p12.re.com"), Some(3));
    }

    #[test]
    fn default_and_empty() {
        let r = router();
        assert_eq!(r.match_host("nope.example.org"), Some(9));
        assert_eq!(r.match_host(""), Some(9));
    }

    #[test]
    fn normalize_port_and_case() {
        assert_eq!(router().match_host("P.NginxSNI.com:443"), Some(0));
    }
}
