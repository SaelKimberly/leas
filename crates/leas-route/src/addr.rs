//! Network address primitives: hosts, CIDR blocks, port ranges.

use crate::error::RouteError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A network host: either a literal IP address or a domain name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetHost {
    Ip(IpAddr),
    Domain(String),
}

impl NetHost {
    /// Infers IP vs domain: parses as `IpAddr` first, falls back to domain.
    pub fn new(host: &str) -> Self {
        host.parse::<IpAddr>()
            .map_or_else(|_| Self::Domain(host.to_owned()), Self::Ip)
    }

    #[must_use]
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            // `Display` keeps the IP arm allocation-free for callers that
            // only need formatting; a borrowed slice is impossible without
            // caching the rendering, so this arm owns the one string.
            Self::Ip(ip) => std::borrow::Cow::Owned(ip.to_string()),
            Self::Domain(d) => std::borrow::Cow::Borrowed(d),
        }
    }
}

impl std::fmt::Display for NetHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Domain(d) => f.write_str(d),
        }
    }
}

/// A destination address: host plus port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetAddr {
    pub host: NetHost,
    pub port: u16,
}

/// An inclusive IPv4/IPv6 CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cidr {
    pub addr: IpAddr,
    pub bits: u8,
}

impl Cidr {
    /// Parses `"10.0.0.0/8"` into a [`Cidr`].
    ///
    /// # Errors
    /// Returns [`RouteError::Parse`] when the address or prefix length is invalid.
    pub fn parse(s: &str) -> Result<Self, RouteError> {
        let Some((addr, bits)) = s.split_once('/') else {
            return Err(RouteError::Parse {
                rule_index: 0,
                field: "cidr",
                message: "missing '/' prefix length".to_owned(),
            });
        };
        let addr: IpAddr = addr.parse().map_err(|e| RouteError::Parse {
            rule_index: 0,
            field: "cidr",
            message: format!("invalid address: {e}"),
        })?;
        let bits: u8 = bits.parse().map_err(|e| RouteError::Parse {
            rule_index: 0,
            field: "cidr",
            message: format!("invalid prefix length: {e}"),
        })?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if bits > max {
            return Err(RouteError::Parse {
                rule_index: 0,
                field: "cidr",
                message: format!("prefix length {bits} exceeds /{max}"),
            });
        }
        Ok(Self { addr, bits })
    }

    /// Returns whether `ip` falls inside this block (inclusive mask).
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, *ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                self.bits <= 32 && prefix_match(&a.octets(), &b.octets(), self.bits)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                self.bits <= 128 && prefix_match(&a.octets(), &b.octets(), self.bits)
            }
            _ => false,
        }
    }
}

/// Byte-wise inclusive prefix comparison over octet arrays.
pub(crate) fn prefix_match(a: &[u8], b: &[u8], bits: u8) -> bool {
    let (full, rem) = ((bits / 8) as usize, bits % 8);
    a[..full] == b[..full] && (rem == 0 || a[full] >> (8 - rem) == b[full] >> (8 - rem))
}

/// An inclusive TCP/UDP port range `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// Returns whether `port` is within `[start, end]` inclusive.
    #[must_use]
    pub const fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_infers_ip_vs_domain() {
        assert_eq!(NetHost::new("1.2.3.4"), NetHost::Ip([1, 2, 3, 4].into()));
        assert_eq!(
            NetHost::new("example.com"),
            NetHost::Domain("example.com".into())
        );
    }
    #[test]
    fn cidr_contains_boundary() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(&"10.255.1.1".parse().unwrap()));
        assert!(!c.contains(&"11.0.0.1".parse().unwrap()));
    }
    #[test]
    fn cidr_rejects_bad_input() {
        assert!(matches!(
            Cidr::parse("300.1.1.1/8"),
            Err(RouteError::Parse { .. })
        ));
    }
    #[test]
    fn port_range_inclusive() {
        let r = PortRange {
            start: 1000,
            end: 2000,
        };
        assert!(r.contains(1000) && r.contains(2000) && !r.contains(999));
    }
}
