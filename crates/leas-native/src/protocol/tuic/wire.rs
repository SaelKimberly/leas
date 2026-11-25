//! Sans-I/O TUIC v5 framing.
//!
//! Wire authority: `thirdparty/mihomo/transport/tuic/v5/{protocol,packet,frag}.go`
//! and `sing-quic/tuic/{protocol,client,service,packet}.go`. This module owns
//! every byte and no runtime: no quinn, no tokio, no async.
//!
//! ```text
//! AUTHENTICATE: 05 00 | uuid[16] | token[32]                 (uni stream)
//! CONNECT:      05 01 | ATYP addr | port[2]                 (bidi stream)
//! PACKET:       05 02 | session[2] packet[2] total id len[2]
//!                      | addr port[2] (first) | 0xff (later) | payload
//! DISSOCIATE:   05 03 | session[2]                          (uni stream)
//! HEARTBEAT:    05 04                                       (DATAGRAM)
//! ```

use std::fmt;
use std::time::{Duration, Instant};

use crate::addr::Host;

pub const VERSION: u8 = 5;

pub const AUTHENTICATE: u8 = 0;
pub const CONNECT: u8 = 1;
pub const PACKET: u8 = 2;
pub const DISSOCIATE: u8 = 3;
pub const HEARTBEAT: u8 = 4;

pub const TOKEN_LEN: usize = 32;
pub const AUTH_LEN: usize = 2 + 16 + TOKEN_LEN;
pub const MAX_DOMAIN: usize = 255;
/// `version | command | ATYP | len | 255 domain | port`.
pub const CONNECT_HEADER_MAX: usize = 2 + 1 + 1 + MAX_DOMAIN + 2;
pub const PACKET_HEADER_LEN: usize = 10;
pub const CONTINUATION: u8 = 0xff;

/// Live UDP assemblies kept per association before the oldest is evicted.
pub const DEFRAG_SLOTS: usize = 64;
/// A partial assembly older than this is dropped on the next feed.
pub const DEFRAG_TTL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Short,
    BadVersion(u8),
    BadCommand(u8),
    BadAddress(u8),
    EmptyName,
    NameTooLong,
    BadFragment,
    Trailing,
    PayloadTooLarge,
    MissingDestination,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short => f.write_str("truncated frame"),
            Self::BadVersion(v) => write!(f, "unknown TUIC version {v}"),
            Self::BadCommand(c) => write!(f, "unknown TUIC command {c:#x}"),
            Self::BadAddress(a) => write!(f, "unknown TUIC address type {a:#x}"),
            Self::EmptyName => f.write_str("empty TUIC domain"),
            Self::NameTooLong => f.write_str("TUIC domain exceeds 255 bytes"),
            Self::BadFragment => f.write_str("malformed TUIC packet fragment"),
            Self::Trailing => f.write_str("trailing bytes after TUIC frame"),
            Self::PayloadTooLarge => f.write_str("TUIC payload exceeds u16"),
            Self::MissingDestination => f.write_str("first TUIC fragment has no destination"),
        }
    }
}

impl std::error::Error for WireError {}

/// A borrowed wire address: IPv4, IPv6, or a domain's raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Address<'a> {
    V4([u8; 4]),
    V6([u8; 16]),
    Name(&'a [u8]),
}

impl<'a> Address<'a> {
    /// The address for a dial target. A domain longer than 255 bytes cannot
    /// be represented.
    pub const fn of_host(host: &'a Host) -> Result<Self, WireError> {
        match host {
            Host::Ip(std::net::IpAddr::V4(ip)) => Ok(Self::V4(ip.octets())),
            Host::Ip(std::net::IpAddr::V6(ip)) => Ok(Self::V6(ip.octets())),
            Host::Domain(domain) => {
                let bytes = domain.as_bytes();
                if bytes.is_empty() {
                    Err(WireError::EmptyName)
                } else if bytes.len() > MAX_DOMAIN {
                    Err(WireError::NameTooLong)
                } else {
                    Ok(Self::Name(bytes))
                }
            }
        }
    }

    #[must_use]
    pub const fn wire_len(self) -> usize {
        match self {
            Self::V4(_) => 5,
            Self::V6(_) => 17,
            Self::Name(bytes) => 2 + bytes.len(),
        }
    }

    fn encode_into(self, out: &mut [u8]) -> Option<usize> {
        match self {
            Self::V4(octets) => {
                *out.get_mut(0)? = 1;
                out.get_mut(1..5)?.copy_from_slice(&octets);
                Some(5)
            }
            Self::V6(octets) => {
                *out.get_mut(0)? = 2;
                out.get_mut(1..17)?.copy_from_slice(&octets);
                Some(17)
            }
            Self::Name(bytes) => {
                let len = u8::try_from(bytes.len()).ok()?;
                *out.get_mut(0)? = 0;
                *out.get_mut(1)? = len;
                out.get_mut(2..2 + bytes.len())?.copy_from_slice(bytes);
                Some(2 + bytes.len())
            }
        }
    }

    fn take(data: &'a [u8], at: &mut usize) -> Result<Self, WireError> {
        let kind = *data.get(*at).ok_or(WireError::Short)?;
        *at += 1;
        match kind {
            0 => {
                let len = usize::from(*data.get(*at).ok_or(WireError::Short)?);
                *at += 1;
                let end = at.checked_add(len).ok_or(WireError::Short)?;
                let name = data.get(*at..end).ok_or(WireError::Short)?;
                *at = end;
                if name.is_empty() {
                    return Err(WireError::EmptyName);
                }
                Ok(Self::Name(name))
            }
            1 => {
                let end = at.checked_add(4).ok_or(WireError::Short)?;
                let octets: [u8; 4] = data
                    .get(*at..end)
                    .ok_or(WireError::Short)?
                    .try_into()
                    .expect("four bytes");
                *at = end;
                Ok(Self::V4(octets))
            }
            2 => {
                let end = at.checked_add(16).ok_or(WireError::Short)?;
                let octets: [u8; 16] = data
                    .get(*at..end)
                    .ok_or(WireError::Short)?
                    .try_into()
                    .expect("sixteen bytes");
                *at = end;
                Ok(Self::V6(octets))
            }
            other => Err(WireError::BadAddress(other)),
        }
    }

    fn to_owned(self) -> OwnedAddress {
        match self {
            Self::V4(octets) => OwnedAddress::V4(octets),
            Self::V6(octets) => OwnedAddress::V6(octets),
            Self::Name(bytes) => OwnedAddress::Name(bytes.into()),
        }
    }
}

/// An owned address for a completed reassembly, whose fragments outlive the
/// receive buffer that carried the first one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedAddress {
    V4([u8; 4]),
    V6([u8; 16]),
    Name(Box<[u8]>),
}

impl OwnedAddress {
    /// The reply address as a socket address; a domain has no `SocketAddr`
    /// form, so it reports `None` (the house datagram convention).
    #[must_use]
    pub fn socket_addr(&self, port: u16) -> Option<std::net::SocketAddr> {
        match self {
            Self::V4(octets) => Some(std::net::SocketAddr::from((*octets, port))),
            Self::V6(octets) => Some(std::net::SocketAddr::from((*octets, port))),
            Self::Name(_) => None,
        }
    }
}

/// The 50-byte auth request.
#[must_use]
pub fn auth_frame(uuid: &[u8; 16], token: &[u8; TOKEN_LEN]) -> [u8; AUTH_LEN] {
    let mut frame = [0u8; AUTH_LEN];
    frame[0] = VERSION;
    frame[1] = AUTHENTICATE;
    frame[2..18].copy_from_slice(uuid);
    frame[18..].copy_from_slice(token);
    frame
}

/// Build the CONNECT header into a caller's stack buffer. The returned length
/// is what the stream wrapper prepends to the first payload.
pub fn connect_header(
    destination: Address<'_>,
    port: u16,
    out: &mut [u8; CONNECT_HEADER_MAX],
) -> Result<usize, WireError> {
    out[0] = VERSION;
    out[1] = CONNECT;
    let at = 2;
    let addr_len = destination
        .encode_into(&mut out[at..])
        .ok_or(WireError::EmptyName)?;
    let port_at = at + addr_len;
    out[port_at..port_at + 2].copy_from_slice(&port.to_be_bytes());
    Ok(port_at + 2)
}

#[must_use]
pub const fn dissociate_frame(session: u16) -> [u8; 4] {
    let bytes = session.to_be_bytes();
    [VERSION, DISSOCIATE, bytes[0], bytes[1]]
}

#[must_use]
pub const fn heartbeat_frame() -> [u8; 2] {
    [VERSION, HEARTBEAT]
}

/// One parsed PACKET frame. `destination` is present only on the first
/// fragment; continuations carry the `0xff` marker instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub session: u16,
    pub id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    pub destination: Option<(Address<'a>, u16)>,
    pub payload: &'a [u8],
}

/// Parse one PACKET frame prefix and return it with the bytes consumed.
pub fn parse_packet_prefix(data: &[u8]) -> Result<(Packet<'_>, usize), WireError> {
    if data.len() < PACKET_HEADER_LEN {
        return Err(WireError::Short);
    }
    let version = data[0];
    if version != VERSION {
        return Err(WireError::BadVersion(version));
    }
    if data[1] != PACKET {
        return Err(WireError::BadCommand(data[1]));
    }
    let session = u16::from_be_bytes([data[2], data[3]]);
    let packet = u16::from_be_bytes([data[4], data[5]]);
    let frag_total = data[6];
    let frag_id = data[7];
    if frag_total == 0 || frag_id >= frag_total {
        return Err(WireError::BadFragment);
    }
    let payload_len = usize::from(u16::from_be_bytes([data[8], data[9]]));
    let mut at = PACKET_HEADER_LEN;
    let destination = if frag_id == 0 {
        let address = Address::take(data, &mut at)?;
        let end = at.checked_add(2).ok_or(WireError::Short)?;
        let port = data.get(at..end).ok_or(WireError::Short)?;
        at = end;
        Some((address, u16::from_be_bytes([port[0], port[1]])))
    } else {
        let marker = *data.get(at).ok_or(WireError::Short)?;
        if marker != CONTINUATION {
            return Err(WireError::BadFragment);
        }
        at += 1;
        None
    };
    let end = at.checked_add(payload_len).ok_or(WireError::Short)?;
    let payload = data.get(at..end).ok_or(WireError::Short)?;
    Ok((
        Packet {
            session,
            id: packet,
            frag_total,
            frag_id,
            destination,
            payload,
        },
        end,
    ))
}

/// Parse exactly one PACKET frame; trailing bytes are refused.
pub fn parse_packet(data: &[u8]) -> Result<Packet<'_>, WireError> {
    let (packet, end) = parse_packet_prefix(data)?;
    if end != data.len() {
        return Err(WireError::Trailing);
    }
    Ok(packet)
}

/// Encode one PACKET frame into a reusable buffer.
pub fn encode_packet_into(
    session: u16,
    packet: u16,
    frag_total: u8,
    frag_id: u8,
    destination: Option<(Address<'_>, u16)>,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), WireError> {
    if frag_total == 0 || frag_id >= frag_total {
        return Err(WireError::BadFragment);
    }
    let payload_len = u16::try_from(payload.len()).map_err(|_| WireError::PayloadTooLarge)?;
    if (frag_id == 0) != destination.is_some() {
        return Err(WireError::BadFragment);
    }
    out.clear();
    out.reserve(PACKET_HEADER_LEN + payload.len() + 18);
    out.extend_from_slice(&[VERSION, PACKET]);
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(&packet.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    out.extend_from_slice(&payload_len.to_be_bytes());
    if let Some((address, port)) = destination {
        let at = out.len();
        out.resize(at + address.wire_len() + 2, 0);
        let len = address
            .encode_into(&mut out[at..])
            .ok_or(WireError::MissingDestination)?;
        out[at + len..at + len + 2].copy_from_slice(&port.to_be_bytes());
    } else {
        out.push(CONTINUATION);
    }
    out.extend_from_slice(payload);
    Ok(())
}

/// How a payload splits into PACKET frames under a datagram budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentPlan {
    pub total: u8,
    pub first: usize,
    pub continuation: usize,
}

/// `max` is the whole-frame datagram budget (quinn's `max_datagram_size`).
/// `address_len` excludes the two port bytes.
#[must_use]
pub fn fragment_plan(max: usize, address_len: usize, payload_len: usize) -> Option<FragmentPlan> {
    let first_overhead = PACKET_HEADER_LEN.checked_add(address_len)?.checked_add(2)?;
    if max <= first_overhead || max <= PACKET_HEADER_LEN + 1 {
        return None;
    }
    let first = max - first_overhead;
    let continuation = max - (PACKET_HEADER_LEN + 1);
    let total = if payload_len <= first {
        1
    } else {
        1usize.checked_add((payload_len - first).div_ceil(continuation))?
    };
    let total = u8::try_from(total).ok()?;
    Some(FragmentPlan {
        total,
        first,
        continuation,
    })
}

/// A completed PACKET reassembly.
#[derive(Debug, PartialEq, Eq)]
pub struct Assembled {
    pub destination: (OwnedAddress, u16),
    pub payload: Vec<u8>,
}

struct Assembly {
    session: u16,
    id: u16,
    total: u8,
    destination: Option<(OwnedAddress, u16)>,
    parts: Vec<Option<Vec<u8>>>,
    count: usize,
    last: Instant,
}

/// Bounded, time-aware PACKET reassembly. `now` is supplied by the caller so
/// the state machine stays sans-I/O and testable.
pub struct Defragger {
    assemblies: Vec<Assembly>,
}

impl Defragger {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            assemblies: Vec::new(),
        }
    }

    /// Feed one fragment. Returns the packet when the last missing fragment
    /// arrives. A single-fragment packet is handed back immediately.
    pub fn feed(&mut self, packet: Packet<'_>, now: Instant) -> Option<Assembled> {
        if packet.frag_total <= 1 {
            let (address, port) = packet.destination?;
            return Some(Assembled {
                destination: (address.to_owned(), port),
                payload: packet.payload.to_vec(),
            });
        }
        if packet.frag_id >= packet.frag_total {
            return None;
        }
        let index = match self
            .assemblies
            .iter()
            .position(|a| a.session == packet.session && a.id == packet.id)
        {
            Some(index)
                if now.saturating_duration_since(self.assemblies[index].last) <= DEFRAG_TTL =>
            {
                index
            }
            Some(index) => {
                self.assemblies.swap_remove(index);
                self.insert(packet, now)
            }
            None => self.insert(packet, now),
        };
        let assembly = &mut self.assemblies[index];
        if assembly.total != packet.frag_total {
            assembly.total = packet.frag_total;
            assembly.destination = None;
            assembly.parts = vec![None; usize::from(packet.frag_total)];
            assembly.count = 0;
        }
        assembly.last = now;
        if packet.frag_id == 0 {
            assembly.destination = packet.destination.map(|(a, p)| (a.to_owned(), p));
        }
        let slot = assembly.parts.get_mut(usize::from(packet.frag_id))?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(packet.payload.to_vec());
        assembly.count += 1;
        if assembly.count != usize::from(assembly.total) {
            return None;
        }
        let assembly = self.assemblies.remove(index);
        let (address, port) = assembly.destination?;
        let total_len = assembly
            .parts
            .iter()
            .try_fold(0usize, |sum, part| sum.checked_add(part.as_ref()?.len()))?;
        let mut payload = Vec::with_capacity(total_len);
        for part in assembly.parts {
            payload.extend_from_slice(part.as_deref()?);
        }
        Some(Assembled {
            destination: (address, port),
            payload,
        })
    }

    fn insert(&mut self, packet: Packet<'_>, now: Instant) -> usize {
        self.make_room(now);
        self.assemblies.push(Assembly {
            session: packet.session,
            id: packet.id,
            total: packet.frag_total,
            destination: None,
            parts: vec![None; usize::from(packet.frag_total)],
            count: 0,
            last: now,
        });
        self.assemblies.len() - 1
    }

    fn make_room(&mut self, now: Instant) {
        self.assemblies
            .retain(|a| now.saturating_duration_since(a.last) <= DEFRAG_TTL);
        if self.assemblies.len() < DEFRAG_SLOTS {
            return;
        }
        if let Some((oldest, _)) = self
            .assemblies
            .iter()
            .enumerate()
            .min_by_key(|(_, assembly)| assembly.last)
        {
            self.assemblies.swap_remove(oldest);
        }
    }
}

impl Default for Defragger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(name: &str) -> Address<'_> {
        match name.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => Address::V4(ip.octets()),
            Ok(std::net::IpAddr::V6(ip)) => Address::V6(ip.octets()),
            Err(_) => Address::Name(name.as_bytes()),
        }
    }

    #[test]
    fn auth_frame_is_the_golden_50_bytes() {
        let mut uuid = [0u8; 16];
        for (i, byte) in uuid.iter_mut().enumerate() {
            *byte = u8::try_from(i).expect("index");
        }
        let mut token = [0u8; 32];
        for (i, byte) in token.iter_mut().enumerate() {
            *byte = u8::try_from(i + 16).expect("index");
        }
        let frame = auth_frame(&uuid, &token);
        assert_eq!(frame.len(), 50);
        assert_eq!(&frame[..2], &[5, 0]);
        assert_eq!(&frame[2..18], &uuid);
        assert_eq!(&frame[18..], &token);
    }

    #[test]
    fn connect_headers_match_the_reference_bytes() {
        let mut out = [0u8; CONNECT_HEADER_MAX];
        let len = connect_header(address("127.0.0.1"), 80, &mut out).expect("header");
        assert_eq!(&out[..len], &[5, 1, 1, 127, 0, 0, 1, 0, 80]);

        let len = connect_header(address("2001:db8::1"), 443, &mut out).expect("header");
        assert_eq!(out[..len][..3], [5, 1, 2]);
        assert_eq!(out[len - 2..len], [1, 187]);

        let len = connect_header(address("dns.example"), 53, &mut out).expect("header");
        assert_eq!(len, 17);
        assert_eq!(&out[..2], &[5, 1]);
        assert_eq!(out[2], 0);
        assert_eq!(out[3], 11);
        assert_eq!(&out[4..15], b"dns.example");
        assert_eq!(&out[15..17], &[0, 53]);
    }

    #[test]
    fn a_packet_round_trips_and_continuations_use_ff() {
        let destination = address("1.2.3.4");
        let mut frame = Vec::new();
        encode_packet_into(
            0x1234,
            0x5678,
            2,
            0,
            Some((destination, 53)),
            &[0xaa, 0xbb, 0xcc],
            &mut frame,
        )
        .expect("encode");
        assert_eq!(
            frame,
            [
                5, 2, 0x12, 0x34, 0x56, 0x78, 2, 0, 0, 3, 1, 1, 2, 3, 4, 0, 53, 0xaa, 0xbb, 0xcc
            ]
        );
        let packet = parse_packet(&frame).expect("parse");
        assert_eq!(packet.session, 0x1234);
        assert_eq!(packet.id, 0x5678);
        assert_eq!(packet.frag_total, 2);
        assert_eq!(packet.frag_id, 0);
        assert_eq!(packet.destination, Some((destination, 53)));
        assert_eq!(packet.payload, [0xaa, 0xbb, 0xcc]);

        encode_packet_into(0x1234, 0x5678, 2, 1, None, &[0xdd], &mut frame).expect("encode");
        assert_eq!(frame[10], CONTINUATION);
        let packet = parse_packet(&frame).expect("parse");
        assert_eq!(packet.destination, None);
        assert_eq!(packet.payload, [0xdd]);

        frame[10] = 0;
        assert_eq!(parse_packet(&frame), Err(WireError::BadFragment));
    }

    #[test]
    fn packet_validation_refuses_bad_fragments_and_trailing_bytes() {
        let destination = address("192.0.2.1");
        let mut frame = Vec::new();
        encode_packet_into(1, 2, 1, 0, Some((destination, 53)), b"x", &mut frame).expect("encode");
        frame.push(0);
        assert_eq!(parse_packet(&frame), Err(WireError::Trailing));

        let mut zero_total = frame[..frame.len() - 1].to_vec();
        zero_total[6] = 0;
        assert_eq!(parse_packet(&zero_total), Err(WireError::BadFragment));

        let mut bad_index = zero_total;
        bad_index[6] = 1;
        bad_index[7] = 1;
        assert_eq!(parse_packet(&bad_index), Err(WireError::BadFragment));
    }

    #[test]
    fn every_truncation_is_short_and_never_panics() {
        let destination = address("dns.example");
        for id in [0, 1] {
            let mut frame = Vec::new();
            let destination = if id == 0 {
                Some((destination, 53))
            } else {
                None
            };
            encode_packet_into(1, 2, 2, id, destination, &[7u8; 32], &mut frame).expect("encode");
            for end in 0..frame.len() {
                assert_eq!(
                    parse_packet_prefix(&frame[..end]),
                    Err(WireError::Short),
                    "id {id} truncated to {end}"
                );
            }
        }
    }

    #[test]
    fn a_packet_prefix_stops_at_the_first_boundary() {
        let destination = address("192.0.2.1");
        let mut first = Vec::new();
        encode_packet_into(1, 2, 1, 0, Some((destination, 53)), b"first", &mut first)
            .expect("encode");
        let first_len = first.len();
        let mut second = Vec::new();
        encode_packet_into(1, 3, 1, 0, Some((destination, 53)), b"second", &mut second)
            .expect("encode");
        first.extend_from_slice(&second);
        let (packet, used) = parse_packet_prefix(&first).expect("first");
        assert_eq!(used, first_len);
        assert_eq!(packet.payload, b"first");
        let (packet, _) = parse_packet_prefix(&first[used..]).expect("second");
        assert_eq!(packet.payload, b"second");
    }

    #[test]
    fn fragment_plans_respect_the_budget_and_the_255_cap() {
        let address_len = address("dns.example").wire_len();
        let plan = fragment_plan(28, address_len, 40).expect("plan");
        assert!(plan.total > 1);
        assert_eq!(plan.first, 28 - 10 - address_len - 2);
        assert_eq!(plan.continuation, 17);

        let plan = fragment_plan(1200, 17, 4000).expect("plan");
        assert_eq!(plan.first, 1171);
        assert_eq!(plan.continuation, 1189);
        assert_eq!(plan.total, 4);

        assert_eq!(fragment_plan(10 + 5 + 2, 5, 1), None);
        assert_eq!(fragment_plan(20, 9, 1_000_000), None);
    }

    #[test]
    fn defrag_reassembles_out_of_order_and_keeps_the_first_address() {
        let now = Instant::now();
        let destination = address("192.0.2.9");
        let mut defrag = Defragger::new();

        let mut second = Vec::new();
        encode_packet_into(7, 9, 2, 1, None, &[2, 3], &mut second).expect("encode");
        assert!(
            defrag
                .feed(parse_packet(&second).expect("parse"), now)
                .is_none()
        );

        let mut first = Vec::new();
        encode_packet_into(7, 9, 2, 0, Some((destination, 53)), &[1], &mut first).expect("encode");
        let assembled = defrag
            .feed(parse_packet(&first).expect("parse"), now)
            .expect("assembled");
        assert_eq!(assembled.payload, [1, 2, 3]);
        assert_eq!(assembled.destination.1, 53);
        assert_eq!(assembled.destination.0, OwnedAddress::V4([192, 0, 2, 9]));
    }

    #[test]
    fn defrag_drops_duplicates_and_expires_partials() {
        let now = Instant::now();
        let destination = address("192.0.2.9");
        let mut first = Vec::new();
        encode_packet_into(7, 9, 2, 0, Some((destination, 53)), &[1], &mut first).expect("encode");
        let packet = parse_packet(&first).expect("parse");
        let mut defrag = Defragger::new();
        assert!(defrag.feed(packet, now).is_none());
        assert!(defrag.feed(packet, now).is_none());

        let later = now + DEFRAG_TTL + Duration::from_secs(1);
        let mut second = Vec::new();
        encode_packet_into(7, 9, 2, 1, None, &[2], &mut second).expect("encode");
        assert!(
            defrag
                .feed(parse_packet(&second).expect("parse"), later)
                .is_none()
        );
    }

    #[test]
    fn defrag_caps_live_assemblies() {
        let now = Instant::now();
        let destination = address("192.0.2.9");
        let mut defrag = Defragger::new();
        for id in 0..=u16::try_from(DEFRAG_SLOTS).expect("slots") {
            let mut frame = Vec::new();
            encode_packet_into(
                id,
                1,
                2,
                0,
                Some((destination, 53)),
                &[u8::try_from(id % 256).expect("byte")],
                &mut frame,
            )
            .expect("encode");
            assert!(
                defrag
                    .feed(parse_packet(&frame).expect("parse"), now)
                    .is_none()
            );
        }
        assert_eq!(defrag.assemblies.len(), DEFRAG_SLOTS);
    }

    #[test]
    fn a_dissociate_and_heartbeat_have_fixed_bytes() {
        assert_eq!(dissociate_frame(0x1234), [5, 3, 0x12, 0x34]);
        assert_eq!(heartbeat_frame(), [5, 4]);
    }
}
