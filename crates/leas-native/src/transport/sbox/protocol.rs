//! The versioned handshake and the per-stream framing (`protocol.go` at the
//! pinned reference).
//!
//! Handshake bytes are the FIRST bytes on the carrier, prepended to the first
//! payload write by the caller:
//!
//! ```text
//! [1B Version][1B Protocol]
//! if Version == 1: [1B PaddingFlag]
//!                  if PaddingFlag: [2B PadLen BE][PadLen random bytes]
//! ```
//!
//! Version0 carries no padding byte at all. A padding-enabled server rejects
//! anything else (`ReadRequest`), so padding is a handshake property, never a
//! later option.

use crate::addr::{Host, TargetAddr};

/// No padding: exactly two bytes.
pub const VERSION0: u8 = 0;
/// The padded-capable request version.
pub const VERSION1: u8 = 1;

/// `smux` (the `SagerNet` fork).
pub const PROTOCOL_SMUX: u8 = 0;
/// `yamux`.
pub const PROTOCOL_YAMUX: u8 = 1;
/// `h2mux` (HTTP/2).
pub const PROTOCOL_H2MUX: u8 = 2;

/// The padding length range the reference draws from: `256 + rand(0..512)`.
pub const PAD_MIN: usize = 256;
/// `PAD_MAX` is exclusive; the wire carries `PAD_MIN..PAD_MAX`.
pub const PAD_MAX: usize = 768;

/// One handshake request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub version: u8,
    pub protocol: u8,
    pub padding: bool,
}

impl Request {
    /// Encode the request, drawing fresh padding bytes when asked.
    ///
    /// # Errors
    ///
    /// Never fails today; kept fallible-free for symmetry with the reader.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + PAD_MAX);
        out.push(self.version);
        out.push(self.protocol);
        if self.version == VERSION1 {
            out.push(u8::from(self.padding));
            if self.padding {
                let pad_len = pad_len();
                out.extend_from_slice(&(u16::try_from(pad_len).expect("pad < 768")).to_be_bytes());
                let start = out.len();
                out.resize(start + pad_len, 0);
                crate::rand::fill_nonsecret(&mut out[start..]);
            }
        }
        out
    }

    /// Decode a request from the front of `buf`; returns it and the bytes
    /// consumed. `None` when the buffer is short or the version is unknown.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        let (&version, rest) = buf.split_first()?;
        if version > VERSION1 {
            return None;
        }
        let (&protocol, rest) = rest.split_first()?;
        let mut used = 2;
        let mut padding = false;
        if version == VERSION1 {
            let (&flag, rest) = rest.split_first()?;
            used += 1;
            padding = flag != 0;
            if padding {
                if rest.len() < 2 {
                    return None;
                }
                let pad_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
                used += 2 + pad_len;
                if buf.len() < used {
                    return None;
                }
            }
        }
        Some((
            Self {
                version,
                protocol,
                padding,
            },
            used,
        ))
    }
}

/// One stream's request: `[2B flags][ATYP addr][port]`. **No version byte** —
/// the reference's `streamRequestLen` counts one for its buffer estimate but
/// `EncodeStreamRequest` never writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRequest {
    pub udp: bool,
    /// `Addr` flag: the destination is an address the server must parse
    /// (packet-address mode). Our client never sets it for TCP.
    pub packet_addr: bool,
    pub target: TargetAddr,
}

/// `flags` bit: UDP stream.
pub const FLAG_UDP: u16 = 0x1;
/// `flags` bit: packet-address mode.
pub const FLAG_ADDR: u16 = 0x2;

impl StreamRequest {
    /// Append the encoded request to `out`.
    ///
    /// # Errors
    ///
    /// [`crate::NativeError::Config`] for a domain longer than 255 bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), crate::NativeError> {
        let mut flags = 0u16;
        if self.udp {
            flags |= FLAG_UDP;
        }
        if self.packet_addr {
            flags |= FLAG_ADDR;
        }
        out.extend_from_slice(&flags.to_be_bytes());
        crate::addr::write_addr_port_last(out, &self.target)
    }

    /// Decode one request from the front of `buf`; `None` when short.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 2 {
            return None;
        }
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let (target, tail) = crate::addr::decode_addr_port_last(&buf[2..])?;
        let used = buf.len() - tail.len();
        Some((
            Self {
                udp: flags & FLAG_UDP != 0,
                packet_addr: flags & FLAG_ADDR != 0,
                target,
            },
            used,
        ))
    }
}

/// One stream's response: a status byte, then (on error) a uvarint-length
/// message (`SagerNet/sing@v0.9.5` `common/varbin/slices.go`: `ReadSlice` =
/// uvarint count + that many bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamResponse {
    Ok,
    Error(String),
}

/// Status byte: success.
pub const STATUS_SUCCESS: u8 = 0;
/// Status byte: error.
pub const STATUS_ERROR: u8 = 1;

impl StreamResponse {
    /// Decode a response from the front of `buf`; `None` when short.
    ///
    /// Status semantics follow the reference exactly: `protocol.go` defines
    /// `statusSuccess = 0` and `statusError = 1`, and `clientConn.readResponse`
    /// treats anything other than `statusError` as success. Only a future
    /// protocol version would add a status, and the reference would not
    /// recognise it as an error either.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        let (&status, rest) = buf.split_first()?;
        if status != STATUS_ERROR {
            return Some((Self::Ok, 1));
        }
        let (len, len_used) = uvarint(rest)?;
        let start = 1 + len_used;
        let end = start.checked_add(len)?;
        if buf.len() < end {
            return None;
        }
        let message = String::from_utf8_lossy(&buf[start..end]).into_owned();
        Some((Self::Error(message), end))
    }

    /// Encode a response (used by the reference-vector tests and a future
    /// server role).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ok => vec![STATUS_SUCCESS],
            Self::Error(message) => {
                let mut out = Vec::with_capacity(2 + message.len());
                out.push(STATUS_ERROR);
                put_uvarint(&mut out, message.len());
                out.extend_from_slice(message.as_bytes());
                out
            }
        }
    }
}

/// The destination the mux carrier targets (`sp.mux.sing-box.arpa:444`), not
/// the flow target.
#[must_use]
pub fn mux_destination() -> TargetAddr {
    TargetAddr::new(Host::Domain("sp.mux.sing-box.arpa".to_owned()), 444)
}

/// One fresh padding length, `PAD_MIN..PAD_MAX` (reference: `256 + rand(512)`).
#[must_use]
pub(crate) fn pad_len() -> usize {
    PAD_MIN + random_below(PAD_MAX - PAD_MIN)
}

fn random_below(bound: usize) -> usize {
    let mut bytes = [0u8; 2];
    crate::rand::fill_nonsecret(&mut bytes);
    usize::from(u16::from_be_bytes(bytes)) % bound
}

fn uvarint(buf: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        let part = usize::from(byte & 0x7f).checked_shl(shift)?;
        value = value.checked_add(part)?;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift = shift.checked_add(7)?;
        if shift >= usize::BITS {
            return None;
        }
    }
    None
}

fn put_uvarint(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = u8::try_from(value & 0x7f).unwrap_or(0x7f);
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn version0_is_exactly_two_bytes() {
        let request = Request {
            version: VERSION0,
            protocol: PROTOCOL_H2MUX,
            padding: false,
        };
        assert_eq!(request.encode(), vec![0x00, 0x02]);
        let (decoded, used) = Request::decode(&request.encode()).expect("decode");
        assert_eq!(used, 2);
        assert!(!decoded.padding);
    }

    #[test]
    fn version1_unpadded_is_three_bytes() {
        let request = Request {
            version: VERSION1,
            protocol: PROTOCOL_SMUX,
            padding: false,
        };
        assert_eq!(request.encode(), vec![0x01, 0x00, 0x00]);
    }

    #[test]
    fn version1_padding_carries_a_256_to_767_byte_block() {
        let request = Request {
            version: VERSION1,
            protocol: PROTOCOL_YAMUX,
            padding: true,
        };
        for _ in 0..64 {
            let bytes = request.encode();
            assert_eq!(bytes[..3], [1, 1, 1], "version, protocol, padding flag");
            let pad_len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
            assert!((PAD_MIN..PAD_MAX).contains(&pad_len), "pad_len {pad_len}");
            assert_eq!(bytes.len(), 5 + pad_len);
            let (decoded, used) = Request::decode(&bytes).expect("decode");
            assert_eq!(used, bytes.len());
            assert!(decoded.padding);
        }
    }

    #[test]
    fn version0_with_a_padding_byte_is_not_a_valid_padding_request() {
        // A Version0 client cannot pad: the byte after the protocol is
        // already the mux protocol's first byte. Decoding stays at 2.
        let (decoded, used) = Request::decode(&[0x00, 0x02, 0xAA]).expect("decode");
        assert_eq!(used, 2);
        assert!(!decoded.padding);
    }

    #[test]
    fn stream_request_has_no_version_byte_and_round_trips() {
        for (host, wire_atyp) in [
            (Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0x01u8),
            (Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)), 0x04u8),
            (Host::Domain("example.com".to_owned()), 0x03u8),
        ] {
            let request = StreamRequest {
                udp: false,
                packet_addr: false,
                target: TargetAddr::new(host, 443),
            };
            let mut out = Vec::new();
            request.encode(&mut out).expect("encode");
            assert_eq!(out[2], wire_atyp, "flags then ATYP, no version byte");
            let (decoded, used) = StreamRequest::decode(&out).expect("decode");
            assert_eq!(used, out.len());
            assert_eq!(decoded, request);
        }

        let udp = StreamRequest {
            udp: true,
            packet_addr: true,
            target: TargetAddr::new(Host::Domain("dns.example".to_owned()), 53),
        };
        let mut out = Vec::new();
        udp.encode(&mut out).expect("encode");
        assert_eq!(&out[..2], [0x00, 0x03], "UDP | Addr flags");
    }

    #[test]
    fn stream_response_ok_and_error_vectors() {
        assert_eq!(StreamResponse::Ok.encode(), vec![0x00]);
        let error = StreamResponse::Error("denied".to_owned());
        let bytes = error.encode();
        assert_eq!(&bytes[..2], [0x01, 0x06], "status then uvarint length");
        let (decoded, used) = StreamResponse::decode(&bytes).expect("decode");
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, error);
        // Long messages use a multi-byte uvarint (128 bytes → 0x80 0x01).
        let long = StreamResponse::Error("x".repeat(128));
        let bytes = long.encode();
        assert_eq!(&bytes[1..3], [0x80, 0x01]);
    }

    #[test]
    fn unknown_status_is_success_per_the_reference() {
        // `clientConn.readResponse` errors only on `statusError` (1); any other
        // status is treated as success. Pinned so a future status cannot be
        // mistaken for an error silently.
        let (decoded, used) = StreamResponse::decode(&[0x02]).expect("decode");
        assert_eq!(decoded, StreamResponse::Ok);
        assert_eq!(used, 1);
    }

    #[test]
    fn mux_destination_matches_the_reference() {
        let dest = mux_destination();
        assert!(matches!(dest.host, Host::Domain(ref d) if d == "sp.mux.sing-box.arpa"));
        assert_eq!(dest.port, 444);
    }
}
