use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use leas_proto::proto_spec::HostKind;
use leas_proto::proto_spec::endpoint::EndpointEssentials;

use crate::error::NativeError;

/// Remote host: parsed IP or DNS name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

impl Host {
    /// Parse a host string: `IpAddr` when it parses, else `Domain`.
    #[must_use]
    pub fn new(host: &str) -> Self {
        host.parse::<IpAddr>()
            .map_or_else(|_| Self::Domain(host.to_string()), Self::Ip)
    }

    #[must_use]
    pub const fn kind(&self) -> HostKind {
        match self {
            Self::Ip(IpAddr::V4(_)) => HostKind::Ipv4,
            Self::Ip(IpAddr::V6(_)) => HostKind::Ipv6,
            Self::Domain(_) => HostKind::Dns,
        }
    }

    /// Raw host string (domain or IP, no IPv6 brackets).
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Domain(d) => d.clone(),
        }
    }
}

impl From<&str> for Host {
    fn from(host: &str) -> Self {
        Self::new(host)
    }
}

/// A destination address on the wire: host + port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAddr {
    pub host: Host,
    pub port: u16,
}

impl TargetAddr {
    #[must_use]
    pub fn new(host: impl Into<Host>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Build from an endpoint's host/port (resolve later; IP hosts stay IP).
    #[must_use]
    pub fn from_endpoint(e: &EndpointEssentials) -> Self {
        Self {
            host: Host::new(&e.host),
            port: e.port,
        }
    }
}

// v2ray wire address types (common/protocol/payload.go AddressType).
pub const ADDR_TYPE_IPV4: u8 = 1;
pub const ADDR_TYPE_DOMAIN: u8 = 2;
pub const ADDR_TYPE_IPV6: u8 = 3;

/// Encode a destination in v2ray wire format: **port first, then address**
/// (`PortThenAddress`), address = type byte + payload.
pub fn encode_addr(target: &TargetAddr) -> Result<Vec<u8>, NativeError> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            out.push(ADDR_TYPE_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            out.push(ADDR_TYPE_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            out.push(ADDR_TYPE_DOMAIN);
            let len = u8::try_from(domain.len()).map_err(|_| {
                NativeError::Config(format!("domain longer than 255 bytes: {domain}"))
            })?;
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(out)
}

// Trojan / SOCKS5-ATYP family bytes. Distinct from the VLESS/VMess wire
// family ([`ADDR_TYPE_*`]): trojan's address parser uses the classic
// SOCKS5 address types (xray-core `proxy/trojan/protocol.go`
// `AddressFamilyByte(0x01,IPv4)/(0x04,IPv6)/(0x03,Domain)`; sing-box's
// `SocksaddrSerializer` is byte-identical).
pub const TROJAN_ATYP_IPV4: u8 = 0x01;
pub const TROJAN_ATYP_DOMAIN: u8 = 0x03;
pub const TROJAN_ATYP_IPV6: u8 = 0x04;

/// Bytes following the ATYP byte (and, for the domain family, following
/// the domain length byte) of a port-last address: `addr || port BE2`.
///
/// The single owner of the port-last address layout: the trojan UDP frame
/// reader sizes its read from it and [`decode_addr_port_last`] bounds-checks
/// with it, so neither can drift from [`encode_addr_port_last`]. `None` for
/// an unknown family byte. `domain_len` is ignored by the fixed-size
/// families.
#[must_use]
pub const fn addr_port_last_tail_len(atyp: u8, domain_len: u8) -> Option<usize> {
    match atyp {
        TROJAN_ATYP_IPV4 => Some(4 + 2),
        TROJAN_ATYP_IPV6 => Some(16 + 2),
        // `as` (not `usize::from`): the `From` trait is not callable in a
        // const fn.
        TROJAN_ATYP_DOMAIN => Some(domain_len as usize + 2),
        _ => None,
    }
}

/// Encode a destination in **port-last** order with the **trojan** family
/// bytes: address (SOCKS5-ATYP type byte + payload), then port BE2.
///
/// Trojan's address parser is built without the `PortFirst()` option
/// (xray-core `proxy/trojan/protocol.go` `NewAddressParser`), so the wire
/// order is `ATYP | addr | port` — the reverse of VLESS/VMess
/// ([`encode_addr`]) — and the family bytes are the SOCKS5 set
/// (`0x01`/`0x03`/`0x04`), NOT the VLESS/VMess `ADDR_TYPE_*` (1/2/3).
pub fn encode_addr_port_last(target: &TargetAddr) -> Result<Vec<u8>, NativeError> {
    let mut out = Vec::with_capacity(1 + 16 + 2);
    write_addr_port_last(&mut out, target)?;
    Ok(out)
}

/// [`encode_addr_port_last`] into a caller-owned buffer: the UDP reply path
/// frames one datagram per packet and reuses its buffer.
pub fn write_addr_port_last(out: &mut Vec<u8>, target: &TargetAddr) -> Result<(), NativeError> {
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            out.push(TROJAN_ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            out.push(TROJAN_ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            out.push(TROJAN_ATYP_DOMAIN);
            let len = u8::try_from(domain.len()).map_err(|_| {
                NativeError::Config(format!("domain longer than 255 bytes: {domain}"))
            })?;
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

/// Decode one wire address; returns the address plus the unconsumed tail.
#[must_use]
pub fn decode_addr(bytes: &[u8]) -> Option<(TargetAddr, &[u8])> {
    if bytes.len() < 3 {
        return None;
    }
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    match bytes[2] {
        ADDR_TYPE_IPV4 => {
            if bytes.len() < 3 + 4 {
                return None;
            }
            let ip = Ipv4Addr::new(bytes[3], bytes[4], bytes[5], bytes[6]);
            Some((TargetAddr::new(Host::Ip(IpAddr::V4(ip)), port), &bytes[7..]))
        }
        ADDR_TYPE_DOMAIN => {
            if bytes.len() < 4 {
                return None;
            }
            let len = usize::from(bytes[3]);
            if bytes.len() < 4 + len {
                return None;
            }
            let domain = std::str::from_utf8(&bytes[4..4 + len]).ok()?.to_string();
            Some((
                TargetAddr::new(Host::Domain(domain), port),
                &bytes[4 + len..],
            ))
        }
        ADDR_TYPE_IPV6 => {
            if bytes.len() < 3 + 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[3..19]);
            Some((
                TargetAddr::new(Host::Ip(IpAddr::V6(Ipv6Addr::from(octets))), port),
                &bytes[19..],
            ))
        }
        _ => None,
    }
}

/// Decode one trojan-family (SOCKS5-ATYP, port-last) wire address; returns
/// the address plus the unconsumed tail.
///
/// Mirrors the trojan address parsers (xray `NewAddressParser` without
/// `PortFirst()`, sing-box `SocksaddrSerializer`): `ATYP | addr | port BE2`
/// with the SOCKS5 family bytes (`0x01` IPv4 / `0x03` domain / `0x04`
/// IPv6) — the reverse byte order and family set of [`decode_addr`].
#[must_use]
pub fn decode_addr_port_last(bytes: &[u8]) -> Option<(TargetAddr, &[u8])> {
    let (&atyp, rest) = bytes.split_first()?;
    // Only the domain family carries a length byte; the IP families have a
    // fixed-size address.
    let (domain_len, rest) = if atyp == TROJAN_ATYP_DOMAIN {
        let (&len, after_len) = rest.split_first()?;
        (len, after_len)
    } else {
        (0, rest)
    };
    let tail = addr_port_last_tail_len(atyp, domain_len)?;
    if rest.len() < tail {
        return None;
    }
    let (addr, port_be) = rest[..tail].split_at(tail - 2);
    let port = u16::from_be_bytes([port_be[0], port_be[1]]);
    let host = match atyp {
        TROJAN_ATYP_IPV4 => Host::Ip(IpAddr::V4(Ipv4Addr::new(
            addr[0], addr[1], addr[2], addr[3],
        ))),
        TROJAN_ATYP_IPV6 => {
            let mut oct = [0u8; 16];
            oct.copy_from_slice(addr);
            Host::Ip(IpAddr::V6(Ipv6Addr::from(oct)))
        }
        // The domain family — the only other one `addr_port_last_tail_len`
        // accepts.
        _ => Host::Domain(std::str::from_utf8(addr).ok()?.to_string()),
    };
    Some((TargetAddr::new(host, port), &rest[tail..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_ipv4_is_port_first() {
        let t = TargetAddr::new(Host::new("127.0.0.1"), 8080);
        assert_eq!(
            encode_addr(&t).unwrap(),
            vec![0x1f, 0x90, 0x01, 127, 0, 0, 1]
        );
    }

    #[test]
    fn encode_domain() {
        let t = TargetAddr::new(Host::Domain("example.com".into()), 443);
        assert_eq!(
            encode_addr(&t).unwrap(),
            vec![
                0x01, 0xbb, 0x02, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                b'm'
            ]
        );
    }

    #[test]
    fn encode_domain_too_long_is_config_error() {
        let t = TargetAddr::new(Host::Domain("a".repeat(256)), 443);
        let err = encode_addr(&t).unwrap_err();
        assert!(err.to_string().contains("domain longer than 255 bytes"));
    }

    #[test]
    fn encode_ipv6() {
        let t = TargetAddr::new(Host::new("::1"), 1234);
        let mut expected = vec![0x04, 0xd2, 0x03];
        expected.extend_from_slice(&[0u8; 15]);
        expected.push(1);
        assert_eq!(encode_addr(&t).unwrap(), expected);
    }

    #[test]
    fn decode_roundtrip_all_types() {
        for t in [
            TargetAddr::new(Host::new("1.2.3.4"), 80),
            TargetAddr::new(Host::Domain("sub.example.org".into()), 255),
            TargetAddr::new(Host::new("2001:db8::1"), 443),
        ] {
            let encoded = encode_addr(&t).unwrap();
            let (decoded, tail) = decode_addr(&encoded).expect("decode");
            assert_eq!(decoded, t);
            assert!(tail.is_empty());
        }
    }

    #[test]
    fn decode_domain_with_tail_keeps_rest() {
        let t = TargetAddr::new(Host::Domain("x.io".into()), 9);
        let mut bytes = encode_addr(&t).unwrap();
        bytes.push(0xAA);
        let (decoded, tail) = decode_addr(&bytes).expect("decode");
        assert_eq!(decoded, t);
        assert_eq!(tail, &[0xAA]);
    }

    #[test]
    fn decode_truncated_inputs_return_none() {
        assert!(decode_addr(&[]).is_none());
        assert!(decode_addr(&[0x00, 0x50]).is_none());
        assert!(decode_addr(&[0x00, 0x50, 0x01, 0x7f]).is_none());
        // Domain type byte present but the length byte is missing — used to
        // panic OOB on `bytes[3]`.
        assert!(decode_addr(&[0x00, 0x50, 0x02]).is_none());
        assert!(decode_addr(&[0x00, 0x50, 0x02, 0x05, b'a']).is_none());
        assert!(decode_addr(&[0x00, 0x50, 0x09, 0x00]).is_none());
    }

    #[test]
    fn encode_port_last_is_atyp_addr_port() {
        // IPv4: ATYP 0x01 | 4-byte addr | port BE2 (port LAST — reverse of
        // the v2ray wire).
        let t = TargetAddr::new(Host::new("127.0.0.1"), 8080);
        assert_eq!(
            encode_addr_port_last(&t).unwrap(),
            vec![0x01, 127, 0, 0, 1, 0x1f, 0x90]
        );
        // Domain: ATYP 0x03 | len | bytes | port BE2.
        let d = TargetAddr::new(Host::Domain("x.io".into()), 9);
        assert_eq!(
            encode_addr_port_last(&d).unwrap(),
            vec![0x03, 4, b'x', b'.', b'i', b'o', 0x00, 0x09]
        );
    }

    #[test]
    fn decode_port_last_roundtrip_all_types() {
        for t in [
            TargetAddr::new(Host::new("1.2.3.4"), 80),
            TargetAddr::new(Host::Domain("sub.example.org".into()), 255),
            TargetAddr::new(Host::new("2001:db8::1"), 443),
        ] {
            let encoded = encode_addr_port_last(&t).unwrap();
            let (decoded, tail) = decode_addr_port_last(&encoded).expect("decode");
            assert_eq!(decoded, t);
            assert!(tail.is_empty());
        }
    }

    #[test]
    fn decode_port_last_truncated_and_unknown_atyp() {
        assert!(decode_addr_port_last(&[]).is_none());
        assert!(decode_addr_port_last(&[0x01, 1, 2, 3]).is_none()); // missing port
        assert!(decode_addr_port_last(&[0x03, 5, b'a']).is_none()); // short domain
        assert!(decode_addr_port_last(&[0x02, 1, 2, 3, 4, 0, 80]).is_none()); // unknown ATYP
    }

    #[test]
    fn port_last_tail_len_matches_the_encoder() {
        // The tail after the ATYP byte (and after the domain length byte):
        // addr || port BE2.
        assert_eq!(addr_port_last_tail_len(TROJAN_ATYP_IPV4, 0), Some(4 + 2));
        assert_eq!(addr_port_last_tail_len(TROJAN_ATYP_IPV6, 0), Some(16 + 2));
        assert_eq!(addr_port_last_tail_len(TROJAN_ATYP_DOMAIN, 7), Some(7 + 2));
        // A domain length is meaningless for the fixed-size families.
        assert_eq!(addr_port_last_tail_len(TROJAN_ATYP_IPV4, 200), Some(6));
        // Unknown family (0x02 is the VLESS/VMess domain byte, not a
        // SOCKS5-ATYP one).
        assert_eq!(addr_port_last_tail_len(0x02, 4), None);

        // Family for family, the helper sizes exactly what the encoder
        // emitted after the type (and length) byte.
        for t in [
            TargetAddr::new(Host::new("1.2.3.4"), 80),
            TargetAddr::new(Host::new("2001:db8::1"), 443),
            TargetAddr::new(Host::Domain("sub.example.org".into()), 9),
        ] {
            let wire = encode_addr_port_last(&t).unwrap();
            let (head, domain_len) = if wire[0] == TROJAN_ATYP_DOMAIN {
                (2, wire[1])
            } else {
                (1, 0)
            };
            assert_eq!(
                addr_port_last_tail_len(wire[0], domain_len),
                Some(wire.len() - head),
                "tail length must match the encoded form of {t:?}"
            );
        }
    }
}
