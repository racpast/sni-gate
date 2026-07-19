//! NAT64 IPv6 address synthesis (RFC 6052).
//!
//! This module embeds a 32-bit IPv4 address into an IPv6 NAT64 prefix so that
//! IPv6-only clients can reach IPv4-only destinations through a NAT64 gateway.
//!
//! Only the common `/96` prefix length is supported. For a `/96` prefix the
//! four IPv4 octets occupy the final 32 bits (bits 96..128) of the resulting
//! 128-bit IPv6 address, as described in RFC 6052 §2.2.
//!
//! Two prefix spellings are accepted by [`Nat64Prefix::from_str`]:
//!
//! * A full IPv6 literal using `::` compression, e.g. `"64:ff9b::"`. Only its
//!   top 96 bits are used; the low 32 bits are ignored (and expected to be 0).
//! * A bare `/96` prefix written as exactly six hextet groups without `::`,
//!   e.g. `"2a01:4f8:c2c:123f:64:5"`. The six groups form the top 96 bits and
//!   the low 32 bits are zeroed, ready for an IPv4 to be embedded.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use anyhow::{bail, Context, Result};

/// A parsed NAT64 `/96` prefix.
///
/// Internally the full 128-bit value is stored, but only the top 96 bits are
/// significant; the low 32 bits are always zero and are the slot into which an
/// IPv4 address is embedded during synthesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nat64Prefix {
    /// The 128-bit prefix. The low 32 bits are guaranteed to be zero.
    prefix: u128,
}

impl Nat64Prefix {
    /// Mask covering the top 96 bits of a 128-bit address.
    const TOP96_MASK: u128 = !((1u128 << 32) - 1);

    /// Build a prefix directly from an [`Ipv6Addr`], keeping only the top 96
    /// bits. Any bits in the low 32 are discarded (zeroed).
    pub fn from_ipv6(addr: Ipv6Addr) -> Self {
        let prefix = u128::from(addr) & Self::TOP96_MASK;
        Nat64Prefix { prefix }
    }

    /// Synthesize an IPv6 address by embedding `ipv4` into the low 32 bits of
    /// the `/96` prefix (RFC 6052 §2.2).
    pub fn synthesize(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        // The IPv4 address maps to a 32-bit big-endian integer; place it in the
        // final 32 bits of the prefix. The prefix's low 32 bits are already 0.
        let embedded = self.prefix | u128::from(u32::from(ipv4));
        Ipv6Addr::from(embedded)
    }

    /// The underlying 128-bit prefix value (low 32 bits are zero).
    #[cfg(test)]
    pub fn as_u128(&self) -> u128 {
        self.prefix
    }
}

impl FromStr for Nat64Prefix {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            bail!("empty NAT64 prefix");
        }

        // Strip an optional "/96" (or any "/NN") suffix. Only /96 is supported.
        let (addr_part, prefix_len) = match trimmed.split_once('/') {
            Some((addr, len)) => {
                let len: u8 = len
                    .parse()
                    .with_context(|| format!("invalid prefix length in {trimmed:?}"))?;
                (addr, Some(len))
            }
            None => (trimmed, None),
        };

        if let Some(len) = prefix_len {
            if len != 96 {
                bail!("unsupported NAT64 prefix length /{len}; only /96 is supported");
            }
        }

        let addr = parse_prefix_address(addr_part)
            .with_context(|| format!("invalid NAT64 prefix {trimmed:?}"))?;

        Ok(Nat64Prefix::from_ipv6(addr))
    }
}

/// Parse the address portion of a NAT64 prefix into a full [`Ipv6Addr`].
///
/// Accepts either:
/// * a standard IPv6 literal (which may use `::` compression), or
/// * exactly six colon-separated hextet groups with no `::` compression, which
///   are interpreted as the top 96 bits of a `/96` prefix (the remaining two
///   groups are zero-filled).
fn parse_prefix_address(addr: &str) -> Result<Ipv6Addr> {
    // First, try to parse as a complete IPv6 literal. This handles anything
    // containing "::" as well as full eight-group forms.
    if let Ok(v6) = Ipv6Addr::from_str(addr) {
        return Ok(v6);
    }

    // Otherwise, accept a bare /96 prefix given as exactly six hextet groups.
    let groups = count_groups(addr);
    if groups == 6 && !addr.contains("::") {
        // Append two zero groups to complete the 128-bit literal, then parse.
        let completed = format!("{addr}:0:0");
        let v6 = Ipv6Addr::from_str(&completed)
            .with_context(|| format!("could not complete /96 prefix {addr:?}"))?;
        return Ok(v6);
    }

    bail!("prefix {addr:?} is neither a valid IPv6 literal nor a 6-group /96 prefix")
}

/// Count the number of colon-separated groups in `s`.
///
/// This is a simple structural helper used to detect the bare six-group `/96`
/// spelling; it does not validate that each group is a valid hextet.
fn count_groups(s: &str) -> usize {
    if s.is_empty() {
        0
    } else {
        s.split(':').count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_prefix_synthesis() {
        // 64:ff9b::/96 + 1.2.3.4 => 64:ff9b::102:304
        let prefix = Nat64Prefix::from_str("64:ff9b::").unwrap();
        let out = prefix.synthesize(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(out, Ipv6Addr::from_str("64:ff9b::102:304").unwrap());
    }

    #[test]
    fn user_six_group_prefix_synthesis() {
        // "2a01:4f8:c2c:123f:64:5" is a bare /96 prefix (6 groups).
        // 203.0.113.5 == 0xcb.00.71.05 == 0xcb007105.
        let prefix = Nat64Prefix::from_str("2a01:4f8:c2c:123f:64:5").unwrap();
        let out = prefix.synthesize(Ipv4Addr::new(203, 0, 113, 5));

        // Expected: top 96 bits = 2a01:4f8:c2c:123f:64:5, low 32 bits = cb00:7105.
        let expected = Ipv6Addr::from_str("2a01:4f8:c2c:123f:64:5:cb00:7105").unwrap();
        assert_eq!(out, expected);

        // Cross-check the raw last 32 bits.
        assert_eq!((prefix.as_u128() & 0xFFFF_FFFF), 0);
        assert_eq!((u128::from(out) & 0xFFFF_FFFF) as u32, 0xcb00_7105);
    }

    #[test]
    fn full_ipv6_prefix_parses() {
        // A "/96"-style prefix given as a compressed IPv6 literal parses fine.
        let prefix = Nat64Prefix::from_str("64:ff9b::").unwrap();
        // Low 32 bits must be zeroed after parsing.
        assert_eq!(prefix.as_u128() & 0xFFFF_FFFF, 0);
    }

    #[test]
    fn slash_96_suffix_is_accepted() {
        let a = Nat64Prefix::from_str("64:ff9b::/96").unwrap();
        let b = Nat64Prefix::from_str("64:ff9b::").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn top96_bits_are_preserved_and_low_bits_masked() {
        // Even if a full literal carries low bits, they are masked away.
        let prefix = Nat64Prefix::from_str("64:ff9b::dead:beef").unwrap();
        assert_eq!(prefix.as_u128() & 0xFFFF_FFFF, 0);
        // Top 96 bits still equal 64:ff9b::
        assert_eq!(
            prefix.as_u128() & Nat64Prefix::TOP96_MASK,
            u128::from(Ipv6Addr::from_str("64:ff9b::").unwrap())
        );
    }

    #[test]
    fn invalid_inputs_error() {
        // Empty.
        assert!(Nat64Prefix::from_str("").is_err());
        // Garbage.
        assert!(Nat64Prefix::from_str("not-an-address").is_err());
        // Unsupported prefix length.
        assert!(Nat64Prefix::from_str("64:ff9b::/64").is_err());
        // Too few groups without "::".
        assert!(Nat64Prefix::from_str("2a01:4f8:c2c").is_err());
        // A hextet out of range.
        assert!(Nat64Prefix::from_str("2a01:4f8:c2c:123f:64:zzzz").is_err());
    }
}
