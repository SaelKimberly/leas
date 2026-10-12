use std::str::FromStr;

use nom::{
    Input, Offset, Parser,
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{char, digit1, hex_digit0, u16},
    combinator::recognize,
    error::{Error, ErrorKind},
    multi::separated_list1,
    sequence::{delimited, preceded, separated_pair},
};
use rustls::pki_types::{DnsName, InvalidDnsNameError, IpAddr, Ipv4Addr, Ipv6Addr, ServerName};

use super::{RawResult, Span};
use crate::PortSpec;

trait XNom<'a>: Sized {
    fn xnom<T>(
        self,
        p: impl Parser<Span<'a>, Output = T, Error = nom::error::Error<Span<'a>>>,
    ) -> RawResult<'a, T>;
}

impl<'a> XNom<'a> for Span<'a> {
    fn xnom<T>(
        self,
        mut p: impl Parser<Self, Output = T, Error = nom::error::Error<Self>>,
    ) -> RawResult<'a, T> {
        p.parse(self)
    }
}

impl<'a> XNom<'a> for &'a str {
    fn xnom<T>(
        self,
        mut p: impl Parser<Span<'a>, Output = T, Error = nom::error::Error<Span<'a>>>,
    ) -> RawResult<'a, T> {
        p.parse(self.as_bytes())
    }
}

#[inline]
const fn _unchecked_str(s: Span<'_>) -> &str {
    unsafe { str::from_utf8_unchecked(s) }
}

/// # Errors
///
/// If the input is not a valid DNS name.
pub fn dns_name(span: Span<'_>) -> RawResult<'_, DnsName<'static>> {
    recognize(take_while1(|c: u8| {
        c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_' || c > 127
    }))
    .map_res(|c: Span| {
        let raw = unsafe { str::from_utf8_unchecked(c) };
        if raw.is_ascii() {
            return DnsName::try_from_str(raw)
                .map(|n| n.to_owned())
                .inspect_err(|_| tracing::trace!("Invalid DNS name detected: {raw}"));
        }
        // Non-ASCII — attempt IDNA conversion
        match idna::domain_to_ascii(raw) {
            Ok(ascii) => DnsName::try_from_str(&ascii)
                .map(|n| n.to_owned())
                .inspect_err(|_| tracing::trace!("IDN -> Punycode failed: {raw} -> {ascii}")),
            Err(e) => {
                tracing::trace!("IDNA conversion failed: {raw} ({e})");
                Err(InvalidDnsNameError)
            }
        }
    })
    .parse(span)
}

/// Parse an IPv4 address.
///
/// # Errors
///
/// - [`Verify`] if the address is invalid.
pub fn ipv4(span: Span<'_>) -> RawResult<'_, Ipv4Addr> {
    let (tail, raw_ip) = recognize((
        digit1,
        char('.'),
        digit1,
        char('.'),
        digit1,
        char('.'),
        digit1,
    ))
    .map(_unchecked_str)
    .parse(span)?;

    let Ok(ip) = <std::net::Ipv4Addr as FromStr>::from_str(raw_ip).inspect_err(|e| {
        tracing::trace!("Invalid IPv4 address: {raw_ip} ({e})");
    }) else {
        crate::nom_bail!(span, Verify)
    };

    Ok((tail, ip.into()))
}

/// Parse an IPv6 address.
///
/// # Errors
///
/// - [`Verify`] if the address is invalid.
pub fn ipv6(span: Span<'_>) -> RawResult<'_, Ipv6Addr> {
    let (tail, raw_ip) = alt((
        recognize(preceded(tag("::ffff:"), ipv4)),
        recognize(separated_list1(tag(":"), hex_digit0)),
    ))
    .map(_unchecked_str)
    .parse(span)?;

    let Ok(ip) = <std::net::Ipv6Addr as FromStr>::from_str(raw_ip).inspect_err(|e| {
        tracing::trace!("Invalid IPv6 address: {raw_ip} ({e})");
    }) else {
        crate::nom_bail!(span, Verify)
    };

    Ok((tail, ip.into()))
}

/// Parse a host name (IP address or DNS name).
///
/// # Errors
///
/// - [`Verify`] if the host name is invalid.
pub fn host(span: Span<'_>) -> RawResult<'_, ServerName<'_>> {
    alt((
        ipv4.map(IpAddr::V4).map(ServerName::IpAddress),
        delimited(tag("["), ipv6, tag("]"))
            .map(IpAddr::V6)
            .map(ServerName::IpAddress),
        ipv6.map(IpAddr::V6).map(ServerName::IpAddress),
        dns_name.map(ServerName::DnsName),
    ))
    .parse(span)
    .inspect_err(|_| tracing::trace!("Failed to parse host name"))
}

/// Hysteria2 port hopping feature parser (single port or range of ports collection)
/// e.g. 1234,1235,1236-1238,1240
///
/// # Errors
///
/// - [`Verify`] if the port is invalid.
pub fn port_specs(span: Span<'_>) -> RawResult<'_, PortSpec> {
    let mut spec = PortSpec::new();
    let mut base = span;
    loop {
        let (tail, p1) = u16.parse(base)?;
        let tail = if let Ok((tail, p2)) = tail.xnom(preceded(tag("-"), u16)) {
            spec.add_range(p1..p2);
            tail
        } else {
            spec.add(p1);
            tail
        };
        match tag(",").parse(tail) {
            RawResult::Ok((tail, _)) => base = tail,
            _ => break Ok((tail, spec.sort())),
        }
    }
}

/// Designed specifically for Hysteria2 port hopping feature
///
/// # Errors
/// - [`Verify`] if the port spec is invalid
pub fn host_port_spec(span: Span<'_>) -> RawResult<'_, (ServerName<'_>, PortSpec)> {
    if let Ok((tail, host_port)) = separated_pair(host, tag(":"), port_specs).parse(span) {
        Ok((tail, host_port))
    } else if let Ok((_, mut parts)) =
        span.xnom(separated_list1(tag(":"), hex_digit0.map(_unchecked_str)))
    {
        let Some(last_part) = parts.pop() else {
            return Err(nom::Err::Error(Error::new(span, ErrorKind::Verify)));
        };

        let raw_ip = parts.join(":");
        let ip = <std::net::Ipv6Addr as FromStr>::from_str(&raw_ip).map_err(|e| {
            tracing::trace!("Invalid IPv6 address: {raw_ip} ({e})");
            nom::Err::Error(Error::new(span, ErrorKind::Verify))
        })?;

        let port_area = span.take_from(span.offset(last_part.as_bytes()));
        let (tail, port) = port_specs(port_area)?;

        Ok((tail, (ServerName::IpAddress(IpAddr::V6(ip.into())), port)))
    } else {
        crate::nom_bail!(span, Verify)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_port_spec() {
        let s = "100-120,122";
        let (_, spec) = super::port_specs(s.as_bytes()).unwrap();

        assert_eq!(spec.length(), 22);
        assert_eq!(
            spec.iter().collect::<Vec<_>>(),
            &[
                100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
                116, 117, 118, 119, 120, 122
            ]
        );
    }

    /// A descending range (`"2000-1000"`) used to underflow `add_range`
    /// (panic in debug, inconsistent spec in release); it must parse to an
    /// empty spec instead (finding f14), and an over-budget span must be
    /// refused (finding f15).
    #[test]
    fn test_port_spec_rejects_descending_and_oversized_spans() {
        let (_, spec) = super::port_specs(b"2000-1000").unwrap();
        assert_eq!(spec.length(), 0, "descending range contributes nothing");
        assert!(spec.first().is_none());

        let (_, spec) = super::port_specs(b"1-65535").unwrap();
        assert_eq!(spec.length(), 0, "over-budget span is refused");

        // A valid small range is unaffected.
        let (_, spec) = super::port_specs(b"1000-1010").unwrap();
        assert_eq!(spec.length(), 11);
    }

    #[test]
    fn test_dns_name_idn() {
        let s = "例子.测试".as_bytes();
        let (tail, name) = super::dns_name(s).unwrap();
        assert!(tail.is_empty());
        assert_eq!(name.as_ref(), "xn--fsqu00a.xn--0zwm56d");
    }

    #[test]
    fn test_dns_name_mixed_idn() {
        let s = "你好.example.com".as_bytes();
        let (tail, name) = super::dns_name(s).unwrap();
        assert!(tail.is_empty());
        assert_eq!(name.as_ref(), "xn--6qq79v.example.com");
    }

    #[test]
    fn test_dns_name_ascii_still_works() {
        let s = b"example.com";
        let (tail, name) = super::dns_name(s).unwrap();
        assert!(tail.is_empty());
        assert_eq!(name.as_ref(), "example.com");
    }

    #[test]
    fn test_dns_name_stops_at_port() {
        let s = "例子.测试:443".as_bytes();
        let (tail, name) = super::dns_name(s).unwrap();
        assert_eq!(tail, b":443");
        assert_eq!(name.as_ref(), "xn--fsqu00a.xn--0zwm56d");
    }

    #[test]
    fn test_dns_name_invalid_idn_still_fails() {
        // Combining characters without a base character fail IDNA validation
        let s = "\u{0300}".as_bytes();
        assert!(super::dns_name(s).is_err());
        let s = "\u{200D}".as_bytes();
        assert!(super::dns_name(s).is_err());
        let s = "\u{2028}".as_bytes();
        assert!(super::dns_name(s).is_err());
    }
}
