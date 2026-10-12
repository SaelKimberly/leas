//! VLESS packetaddr destination-header codec (spec §4.3).
//!
//! In `packetaddr` mode the VLESS header destination is the magic fqdn
//! (`sp.packet-addr.v2fly.arpa`, port 0 — the target stays out of the
//! header; see `udp_header_target`), and each datagram's frame payload
//! carries a per-packet destination header:
//!
//! `atyp(1B) | addr | port(2B BE)`
//!
//! (sing serializer order — atyp first, then address, then port). The magic
//! fqdn appears ONLY in the header, never in the frame: sing-vmess's
//! packetaddr `AddressSerializer` registers just the IP family bytes and
//! writes no magic prefix (verified against sing-box 1.13.16
//! `sing-vmess@v0.2.8` + the mihomo `sing-vmess` fork — a magic-prefixed
//! frame makes the sing-box server reject the packet as an unknown address
//! family). The plan spec §4.3's `magic | atyp | addr | port` frame format
//! is corrected here (deviation recorded in the Task 5 report). atyp:
//! IPv4 = `0x01`, IPv6 = `0x02`. fqdn targets are unsupported (spec §4.3) —
//! `SocketAddr` is IP-only, so `encode_dest` can never produce one.

use std::io;
use std::net::{IpAddr, SocketAddr};

/// The magic fqdn marking the packetaddr header destination (sing-vmess
/// `SeqPacketMagicAddress`; spec §4.3). Used by `udp_header_target`, never
/// inside a frame.
pub const MAGIC: &str = "sp.packet-addr.v2fly.arpa";

const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;

/// Encodes a destination as `atyp | addr | port(2B BE)`.
///
/// `SocketAddr` is IP-only, so the fqdn case (a client error per spec §4.3)
/// is unreachable and this always succeeds. The header is at most
/// `1 + 16 + 2 = 19` bytes — well within a u16 frame.
pub fn encode_dest(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 2);
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

/// Decodes a packetaddr destination header, returning `(dest, payload)`
/// where `payload` is the remainder of the frame after the header.
///
/// The first byte is the address family — an unknown atyp is an error,
/// never delivered as garbage (the sing serializer behaves the same:
/// `ReadAddrPort` rejects unregistered family bytes). Truncated headers
/// are errors too (spec §6).
pub fn decode_dest(data: &[u8]) -> io::Result<(SocketAddr, &[u8])> {
    let mut rest = data;
    let atyp = take(&mut rest, 1, "atyp")?[0];
    let ip = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(take(&mut rest, 4, "IPv4 address")?);
            IpAddr::V4(octets.into())
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(take(&mut rest, 16, "IPv6 address")?);
            IpAddr::V6(octets.into())
        }
        other => return Err(invalid(format_args!("unsupported atyp 0x{other:02x}"))),
    };
    let mut port = [0u8; 2];
    port.copy_from_slice(take(&mut rest, 2, "port")?);
    Ok((SocketAddr::new(ip, u16::from_be_bytes(port)), rest))
}

/// Splits `n` bytes off the front of `rest`, erroring on truncation.
fn take<'a>(rest: &mut &'a [u8], n: usize, what: &str) -> io::Result<&'a [u8]> {
    let (head, tail) = rest
        .split_at_checked(n)
        .ok_or_else(|| invalid(format_args!("truncated ({what})")))?;
    *rest = tail;
    Ok(head)
}

/// Builds an `InvalidData` error with the packetaddr context prefix.
fn invalid(what: impl core::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("vless packetaddr {what}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_ipv4() {
        let dest = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
        assert_eq!(encode_dest(dest), [0x01, 127, 0, 0, 1, 0x1F, 0x90]);
    }

    #[test]
    fn encode_ipv6() {
        let dest = "[::1]:53".parse::<SocketAddr>().unwrap();
        let mut expected = vec![0x02];
        expected.extend_from_slice(&[0u8; 15]);
        expected.push(1);
        expected.extend_from_slice(&[0x00, 0x35]);
        assert_eq!(encode_dest(dest), expected);
    }

    #[test]
    fn decode_roundtrip() {
        let dest = "[2001:db8::1]:443".parse::<SocketAddr>().unwrap();
        let mut data = encode_dest(dest);
        data.extend_from_slice(b"payload");
        let (got, payload) = decode_dest(&data).unwrap();
        assert_eq!(got, dest);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn decode_truncated_is_error() {
        // IPv4 atyp but only 2 of the 4 address bytes.
        let err = decode_dest(&[0x01, 127, 0]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decode_unknown_atyp_is_error() {
        // atyp 0x03 (unsupported per spec §4.3) — must be rejected, never
        // parsed as an address. The first frame byte IS the atyp (no magic
        // prefix in the frame — sing serializer semantics), so any byte
        // outside {0x01, 0x02} errors the same way.
        let err = decode_dest(&[0x03, 127, 0, 0, 1, 0x1F, 0x90]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = decode_dest(b"not-an-atyp\x00").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
