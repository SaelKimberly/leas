//! Hysteria2 UDP relay: QUIC DATAGRAM frames carrying the `UDPMessage`
//! wire format, with fragmentation on `DatagramTooLarge` and per-session
//! defragmentation.
//!
//! Wire contract: `thirdparty/hysteria/core/internal/protocol/proxy.go`
//! (`UDPMessage`), sing-box via `sing-quic/hysteria2` (same wire). A UDP
//! "session" is a client-chosen `sessionID` (hysteria starts at 1 and
//! increments per session; this client opens one session per tunnel). Each
//! datagram carries a full `UDPMessage`:
//!
//! ```text
//! SessionID (uint32 BE) | PacketID (uint16 BE) | FragID (uint8) |
//! FragCount (uint8) | AddrLen (QUIC varint) | Addr | Data...
//! ```
//!
//! Oversized datagrams are fragmented (one `PacketID`, `FragID`/`FragCount`
//! splitting the payload); the receiver reassembles by `PacketID`.
//!
//! Outbound messages are borrowed views (`UdpMessageRef`) serialized into
//! one reusable per-session buffer (upstream's `SendBuf`,
//! `core/client/udp.go:160`); inbound ones are owned (`UdpMessage`) because
//! the defragmenter holds fragments until a message assembles.
//!
//! [`UdpConn::split`] hands the two directions out separately — quinn's
//! datagram send and receive both take `&Connection`, so this is a real
//! split of the session state, not a byte stream cut in half: the
//! defragmenter goes with the reader, the send buffer and the `PacketID`
//! counter with the writer, and the session guard is shared so neither half
//! can tear the QUIC session down while the other lives.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use quinn::{Connection, SendDatagramError};

use super::quic::{H3Keepalive, put_varint, read_varint, varint_len};

/// Max address bytes a `UDPMessage` may carry: `ParseUDPMessage` bounds the
/// address by `MaxMessageLength`, not `MaxAddressLength`
/// (`thirdparty/hysteria/core/internal/protocol/proxy.go:212`).
const MAX_MESSAGE_LEN: usize = 2048;
/// Max UDP payload per datagram (`MaxUDPSize`): the size of the per-session
/// send buffer upstream (`core/client/udp.go:160`) and of the buffer the
/// server relays replies from (`core/server/udp.go:182`).
const MAX_UDP_SIZE: usize = 4096;
/// Fallback datagram budget when the peer does not advertise one
/// (`MaxDatagramFrameSize`).
const DEFAULT_DATAGRAM_BUDGET: usize = 1200;
/// The client-chosen `sessionID` for this tunnel: hysteria starts at 1 and
/// increments per session, and this client opens one session per tunnel
/// (`core/client/udp.go`). Both directions filter/stamp with it.
const SESSION_ID: u32 = 1;

/// A `UDPMessage` on its way out: the header fields with the address and
/// payload BORROWED — the send path serializes them straight into the
/// session buffer instead of copying them into an owned message.
struct UdpMessageRef<'a> {
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    /// The Socksaddr string form (`host:port` / `[v6]:port`).
    addr: &'a str,
    data: &'a [u8],
}

impl UdpMessageRef<'_> {
    /// Bytes ahead of the payload (hysteria `UDPMessage.HeaderSize`).
    const fn header_size(&self) -> usize {
        4 + 2 + 1 + 1 + varint_len(self.addr.len() as u64) + self.addr.len()
    }

    const fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    /// Serialize into `buf` (hysteria `UDPMessage.Serialize`): one exact
    /// reservation, then the header and the borrowed payload — no
    /// intermediate buffer, no copy of `addr`/`data` into an owned message.
    fn serialize_into(&self, buf: &mut BytesMut) {
        buf.reserve(self.size());
        buf.put_u32(self.session_id);
        buf.put_u16(self.packet_id);
        buf.put_u8(self.frag_id);
        buf.put_u8(self.frag_count);
        put_varint(buf, self.addr.len() as u64);
        buf.put_slice(self.addr.as_bytes());
        buf.put_slice(self.data);
    }
}

/// A parsed inbound `UDPMessage` (hysteria `protocol.UDPMessage`) — owned
/// because the defragmenter keeps fragments until the message assembles.
struct UdpMessage {
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    /// The Socksaddr string form (`host:port` / `[v6]:port`).
    addr: String,
    data: Vec<u8>,
}

impl UdpMessage {
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        let session_id = u32::from_be_bytes(buf[0..4].try_into().ok()?);
        let packet_id = u16::from_be_bytes(buf[4..6].try_into().ok()?);
        let frag_id = buf[6];
        let frag_count = buf[7];
        let (addr_len, rest) = read_varint(&buf[8..])?;
        let addr_len = usize::try_from(addr_len).ok()?;
        // `rest.len() <= addr_len` mirrors upstream's guard: at least one
        // payload byte must follow the address (`ParseUDPMessage`,
        // `internal/protocol/proxy.go:216`). Such a datagram is dropped by
        // the receive loop, never fatal.
        if addr_len == 0 || addr_len > MAX_MESSAGE_LEN || rest.len() <= addr_len {
            return None;
        }
        let addr = std::str::from_utf8(&rest[..addr_len]).ok()?.to_string();
        let data = rest[addr_len..].to_vec();
        Some(Self {
            session_id,
            packet_id,
            frag_id,
            frag_count,
            addr,
            data,
        })
    }
}

/// Per-session defragmentation (hysteria `frag.Defragger`): reassembles
/// `FragCount` fragments sharing one `PacketID`; a new `PacketID` discards
/// the previous partial message.
struct Defragger {
    pkt_id: u16,
    frags: Vec<Option<UdpMessage>>,
    count: usize,
    size: usize,
}

impl Defragger {
    const fn new() -> Self {
        Self {
            pkt_id: 0,
            frags: Vec::new(),
            count: 0,
            size: 0,
        }
    }

    /// Feed one fragment; returns the assembled message when complete.
    fn feed(&mut self, m: UdpMessage) -> Option<UdpMessage> {
        if m.frag_count <= 1 {
            return Some(m);
        }
        if m.frag_id >= m.frag_count {
            return None;
        }
        if m.packet_id != self.pkt_id || m.frag_count as usize != self.frags.len() {
            // New message — discard the previous partial state.
            self.pkt_id = m.packet_id;
            self.frags = (0..m.frag_count as usize).map(|_| None).collect();
            let data_len = m.data.len();
            let slot = m.frag_id as usize;
            self.frags[slot] = Some(m);
            self.count = 1;
            self.size = data_len;
        } else if self.frags[m.frag_id as usize].is_none() {
            let data_len = m.data.len();
            let slot = m.frag_id as usize;
            self.frags[slot] = Some(m);
            self.count += 1;
            self.size += data_len;
            if self.count == self.frags.len() {
                // All fragments present — assemble.
                let mut data = Vec::with_capacity(self.size);
                for frag in &self.frags {
                    data.extend_from_slice(&frag.as_ref()?.data);
                }
                let first = self.frags.iter().flatten().next()?;
                return Some(UdpMessage {
                    session_id: first.session_id,
                    packet_id: first.packet_id,
                    frag_id: 0,
                    frag_count: 1,
                    addr: first.addr.clone(),
                    data,
                });
            }
        }
        None
    }
}

/// The Socksaddr string form for an IP destination (`host:port` /
/// `[v6]:port`).
fn sockaddr_string(sa: SocketAddr) -> String {
    match sa {
        SocketAddr::V4(v4) => format!("{v4}"),
        // SocketAddrV6's Display already brackets the address and appends
        // the port (`[::1]:443`).
        SocketAddr::V6(v6) => format!("{v6}"),
    }
}

/// Decide one received datagram: `Some((dest, payload))` to deliver it,
/// `None` to drop it and keep reading.
///
/// Dropped: another session's datagram, an unparsable `UDPMessage`
/// (upstream does the same — "invalid message, this is fine - just wait for
/// the next", `core/client/client.go:325`), and an incomplete fragment.
/// `dest` is `None` when the reply address is not an IP form (a domain, or
/// the server's address-override hook `core/server/udp.go:166`) — the
/// datagram API has no other way to say "no per-packet address".
fn accept_datagram(
    defrag: &mut Defragger,
    session_id: u32,
    bytes: &[u8],
) -> Option<(Option<SocketAddr>, Vec<u8>)> {
    let msg = UdpMessage::parse(bytes)?;
    if msg.session_id != session_id {
        return None;
    }
    let assembled = defrag.feed(msg)?;
    Some((assembled.addr.parse().ok(), assembled.data))
}

/// Read-direction state: the session filter and the defragmenter, which
/// holds fragments until a message assembles. Whichever end reads owns it —
/// the combined [`UdpConn`] or the split [`UdpReader`].
struct ReadState {
    session_id: u32,
    defrag: Defragger,
}

impl ReadState {
    const fn new(session_id: u32) -> Self {
        Self {
            session_id,
            defrag: Defragger::new(),
        }
    }

    /// The one receive implementation, with the connection as a parameter:
    /// [`UdpConn::recv`] and [`UdpReader::recv`] are both exactly this.
    ///
    /// Cancellation-safe: quinn's `read_datagram` future carries no partial
    /// state — each poll either takes a whole datagram off the connection's
    /// queue or registers a waker — and the defragmenter lives in `self`
    /// rather than in the future, so a `recv` dropped mid-message keeps
    /// every fragment it has already accepted.
    async fn recv_from(
        &mut self,
        conn: &Connection,
    ) -> io::Result<Option<(Option<SocketAddr>, Vec<u8>)>> {
        loop {
            let Ok(bytes) = conn.read_datagram().await else {
                return Ok(None); // connection closed = clean EOF
            };
            if let Some(delivered) = accept_datagram(&mut self.defrag, self.session_id, &bytes) {
                return Ok(Some(delivered));
            }
        }
    }
}

/// Write-direction state: the session destination, the `PacketID` counter
/// and the reusable serialization buffer. Whichever end writes owns it —
/// the combined [`UdpConn`] or the split [`UdpWriter`].
struct WriteState {
    session_id: u32,
    /// The session destination in hysteria's Socksaddr wire form (rendered
    /// once from `ctx.target`): the address a send without a per-packet
    /// destination carries.
    target: String,
    /// Next `PacketID` for fragmented sends (nonzero).
    next_packet_id: u16,
    /// Serialization scratch reused by every datagram: each message is split
    /// off it and handed to quinn without a copy (upstream keeps one
    /// per-session `SendBuf`, `core/client/udp.go:160`).
    send_buf: BytesMut,
}

impl WriteState {
    fn new(session_id: u32, target: String) -> Self {
        Self {
            session_id,
            target,
            next_packet_id: 1,
            send_buf: BytesMut::with_capacity(MAX_UDP_SIZE),
        }
    }

    /// The one send implementation, with the connection as a parameter:
    /// [`UdpConn::send`] and [`UdpWriter::send`] are both exactly this.
    /// Synchronous because quinn's datagram send is — the public wrappers
    /// are `async` only to match the datagram API.
    fn send_to(
        &mut self,
        conn: &Connection,
        dest: Option<SocketAddr>,
        payload: &[u8],
    ) -> io::Result<()> {
        if payload.len() > MAX_UDP_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "hy2 udp datagram too large ({}, max {MAX_UDP_SIZE})",
                    payload.len()
                ),
            ));
        }
        // The per-packet address, rendered once per send: every fragment
        // borrows it instead of cloning.
        let per_packet = dest.map(sockaddr_string);
        let session_target = self.target.as_str();
        let msg = UdpMessageRef {
            session_id: self.session_id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            // `dest: None` = "the session destination", never "no address".
            addr: per_packet.as_deref().unwrap_or(session_target),
            data: payload,
        };
        // Bound before the match so the buffer reborrow ends here: the
        // fragment path needs it again.
        let unfragmented = send_datagram(conn, &mut self.send_buf, &msg);
        match unfragmented {
            Ok(()) => Ok(()),
            Err(SendDatagramError::TooLarge) => {
                let budget = conn.max_datagram_size().unwrap_or(DEFAULT_DATAGRAM_BUDGET);
                let packet_id = self.next_packet_id;
                self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);
                send_fragmented(conn, &mut self.send_buf, &msg, packet_id, budget)
            }
            Err(e) => Err(io::Error::other(format!("hy2 udp send: {e}"))),
        }
    }
}

/// The session's liveness guard, shared by both halves of a
/// [`split`](UdpConn::split).
///
/// In production this is the h3 keep-alive from the auth exchange
/// ([`H3Keepalive`]): dropping the last `SendRequest` clone closes the h3
/// session, which tears the whole quinn connection down. Type-erased because
/// nothing here ever *uses* it, only holds it, and shared because the
/// session must outlive EITHER half — the guard unwinds when the last half
/// goes away, never when the first one does (the tests hold a drop probe
/// through it to prove exactly that).
type SessionGuard = Arc<dyn Send + Sync>;

/// A Hysteria2 UDP connection over QUIC datagrams (one UDP session).
///
/// Sends `UDPMessage` frames (with fragmentation on `DatagramTooLarge`);
/// receives and defragments the server's replies for this session.
/// [`split`](Self::split) hands the two directions out as independent halves.
pub struct UdpConn {
    conn: Connection,
    /// Keeps the h3 session (and the quinn connection) alive.
    session: SessionGuard,
    read: ReadState,
    write: WriteState,
}

impl UdpConn {
    #[must_use]
    pub(super) fn new(conn: Connection, keepalive: H3Keepalive, target: String) -> Self {
        Self::with_session_guard(conn, Arc::new(keepalive), target)
    }

    /// [`new`](Self::new) with the session guard already erased and
    /// shareable — the seam the tests open a session over without running an
    /// h3 handshake.
    fn with_session_guard(conn: Connection, session: SessionGuard, target: String) -> Self {
        Self {
            conn,
            session,
            read: ReadState::new(SESSION_ID),
            write: WriteState::new(SESSION_ID, target),
        }
    }

    /// Send one datagram to `dest`, or — with `dest: None` — to the session
    /// destination this tunnel was opened for. Every `UDPMessage` carries an
    /// address on the wire (upstream takes it per call, `udpConn.Send`,
    /// `core/client/udp.go:52`), so `None` means "the session destination",
    /// never "no address".
    // quinn's datagram send is synchronous; `send` is async only to match
    // the `PacketTunnel` datagram API (the stream-chain variants do await).
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn send(&mut self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        self.write.send_to(&self.conn, dest, payload)
    }

    /// Receive one datagram. `Ok(None)` on a clean end-of-stream (the QUIC
    /// connection closed). Undeliverable datagrams — another session's,
    /// malformed, or an incomplete fragment — are dropped and the loop keeps
    /// reading, exactly as upstream does (`core/client/client.go:325`). The
    /// returned address is `None` when the reply carried a non-IP Socksaddr
    /// (a domain): the datagram API has no other way to say "no per-packet
    /// address".
    pub async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Vec<u8>)>> {
        self.read.recv_from(&self.conn).await
    }

    /// Split the session into halves that may be used concurrently from
    /// separate tasks — a reader parked in [`UdpReader::recv`] no longer
    /// blocks [`UdpWriter::send`].
    ///
    /// A genuine split, not a byte-stream split: quinn's datagram send and
    /// receive both take `&Connection` and the handle is `Clone`, so neither
    /// half gains a lock. The reader takes the defragmenter, the writer takes
    /// the send buffer and the `PacketID` counter, and both hold the session
    /// guard so the QUIC session survives until the LAST half is dropped.
    // Infallible for this carrier; the `io::Result` is the shared split
    // contract (the stream carriers refuse some modes).
    pub fn split(self) -> io::Result<(UdpReader, UdpWriter)> {
        let Self {
            conn,
            session,
            read,
            write,
        } = self;
        Ok((
            UdpReader {
                conn: conn.clone(),
                _session: Arc::clone(&session),
                read,
            },
            UdpWriter {
                conn,
                _session: session,
                write,
            },
        ))
    }
}

/// The read half of a [`split`](UdpConn::split) session.
///
/// Owns the defragmenter and a handle on the QUIC connection. Independent of
/// [`UdpWriter`], so a dedicated task may park in [`recv`](Self::recv) for
/// the session's whole life.
pub struct UdpReader {
    conn: Connection,
    /// Keeps the h3 session (and the quinn connection) alive.
    _session: SessionGuard,
    read: ReadState,
}

impl UdpReader {
    /// Receive one datagram — [`UdpConn::recv`] exactly, same implementation
    /// and same `Ok(None)` end-of-stream semantics.
    ///
    /// Cancellation-safe: quinn's `read_datagram` keeps no partial state and
    /// the defragmenter lives in this half, so a dropped `recv` future loses
    /// neither a datagram nor a fragment already accepted.
    pub async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Vec<u8>)>> {
        self.read.recv_from(&self.conn).await
    }
}

/// The write half of a [`split`](UdpConn::split) session: the serialization
/// buffer, the `PacketID` counter and a handle on the QUIC connection.
pub struct UdpWriter {
    conn: Connection,
    /// Keeps the h3 session (and the quinn connection) alive.
    _session: SessionGuard,
    write: WriteState,
}

impl UdpWriter {
    /// Send one datagram — [`UdpConn::send`] exactly, same implementation
    /// and same `dest: None` = session-destination meaning.
    // Async only to match the datagram API; quinn's datagram send is
    // synchronous.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn send(&mut self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        self.write.send_to(&self.conn, dest, payload)
    }
}

/// One unfragmented datagram send: serialize into the session buffer and
/// hand quinn exactly those bytes — `split().freeze()` transfers the written
/// range with no copy and leaves the tail for the next datagram.
fn send_datagram(
    conn: &Connection,
    buf: &mut BytesMut,
    msg: &UdpMessageRef<'_>,
) -> Result<(), SendDatagramError> {
    msg.serialize_into(buf);
    conn.send_datagram(buf.split().freeze())
}

/// Fragment `msg` into `budget`-bounded datagrams sharing one `PacketID`
/// (hysteria `frag.FragUDPMessage` on `DatagramTooLarge`). Every fragment
/// borrows the original address and a slice of the original payload.
#[allow(clippy::cast_possible_truncation)] // both casts are `frag_count`-bounded, checked below
fn send_fragmented(
    conn: &Connection,
    buf: &mut BytesMut,
    msg: &UdpMessageRef<'_>,
    packet_id: u16,
    budget: usize,
) -> io::Result<()> {
    let max_payload = budget.saturating_sub(msg.header_size());
    if max_payload == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hy2 udp: datagram budget smaller than the message header",
        ));
    }
    let frag_count = msg.data.len().div_ceil(max_payload);
    if frag_count > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hy2 udp: datagram needs too many fragments",
        ));
    }
    let frag_count = frag_count as u8;
    for (i, chunk) in msg.data.chunks(max_payload).enumerate() {
        let frag = UdpMessageRef {
            session_id: msg.session_id,
            packet_id,
            frag_id: i as u8,
            frag_count,
            addr: msg.addr,
            data: chunk,
        };
        send_datagram(conn, buf, &frag)
            .map_err(|e| io::Error::other(format!("hy2 udp fragment: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::{Pin, pin};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use parking_lot::Mutex;

    /// One outbound `UDPMessage` view (session 1, unfragmented).
    fn out<'a>(addr: &'a str, data: &'a [u8]) -> UdpMessageRef<'a> {
        UdpMessageRef {
            session_id: 1,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr,
            data,
        }
    }

    /// One serialized `UDPMessage`, as the server puts it on the wire.
    fn wire(session_id: u32, addr: &str, data: &[u8]) -> BytesMut {
        let msg = UdpMessageRef {
            session_id,
            ..out(addr, data)
        };
        let mut buf = BytesMut::new();
        msg.serialize_into(&mut buf);
        buf
    }

    /// One inbound fragment of packet `pkt`.
    fn frag(pkt: u16, id: u8, count: u8, data: &[u8]) -> UdpMessage {
        UdpMessage {
            session_id: 1,
            packet_id: pkt,
            frag_id: id,
            frag_count: count,
            addr: "8.8.8.8:53".into(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn udp_message_serialize_parse_roundtrip() {
        let m = out("1.2.3.4:53", b"hello");
        let mut buf = BytesMut::new();
        m.serialize_into(&mut buf);
        assert_eq!(buf.len(), m.size());
        let parsed = UdpMessage::parse(&buf).expect("parses");
        assert_eq!(parsed.session_id, 1);
        assert_eq!(parsed.packet_id, 0);
        assert_eq!(parsed.frag_id, 0);
        assert_eq!(parsed.frag_count, 1);
        assert_eq!(parsed.addr, "1.2.3.4:53");
        assert_eq!(parsed.data, b"hello");
    }

    #[test]
    fn udp_message_wire_layout_exact() {
        // "1.2.3.4:53" is 10 bytes → 1-byte varint 0x0a. Fixed header 8B.
        let m = out("1.2.3.4:53", b"hi");
        let mut buf = BytesMut::new();
        m.serialize_into(&mut buf);
        let mut expect = vec![
            0, 0, 0, 1, // session 1
            0, 0,  // packet 0
            0,  // frag 0
            1,  // frag count 1
            10, // addr len
        ];
        expect.extend_from_slice(b"1.2.3.4:53");
        expect.extend_from_slice(b"hi");
        assert_eq!(&buf[..], &expect[..]);
    }

    #[test]
    fn addr_len_past_63_uses_the_two_byte_varint() {
        // A 64-byte address leaves the 1-byte varint range (RFC 9000 §16):
        // the prefix becomes `0x4000 | len`, and the header grows with it —
        // sizing the header with a fixed 1-byte varint would truncate the
        // payload.
        let addr = format!("{}:53", "a".repeat(61));
        assert_eq!(addr.len(), 64);
        let m = out(&addr, b"x");
        assert_eq!(m.header_size(), 8 + 2 + 64);
        let mut buf = BytesMut::new();
        m.serialize_into(&mut buf);
        assert_eq!(buf.len(), m.size());
        assert_eq!(&buf[8..10], &[0x40, 0x40]);
        assert_eq!(&buf[10..74], addr.as_bytes());
        assert_eq!(&buf[74..], b"x");
        // ...and the reader consumes the same varint width.
        let parsed = UdpMessage::parse(&buf).expect("parses");
        assert_eq!(parsed.addr, addr);
        assert_eq!(parsed.data, b"x");
    }

    #[test]
    fn parse_rejects_truncated_or_empty() {
        assert!(UdpMessage::parse(&[]).is_none());
        assert!(UdpMessage::parse(&[0, 0, 0, 1, 0, 0, 0]).is_none());
        // addr len 9 but only 3 bytes follow
        let mut buf = vec![0u8; 8 + 3];
        buf[3] = 1;
        buf[7] = 1;
        buf[8] = 9;
        buf.extend_from_slice(b"1.2.3");
        assert!(UdpMessage::parse(&buf[..8 + 3]).is_none());
        // Address but no payload byte: upstream's parser rejects it too
        // (`ParseUDPMessage`, `internal/protocol/proxy.go:216`).
        let empty = wire(1, "1.2.3.4:53", b"");
        assert!(UdpMessage::parse(&empty).is_none(), "no payload byte");
    }

    #[test]
    fn accept_drops_undeliverable_datagrams() {
        let mut d = Defragger::new();
        // Truncated, another session's, and payload-less datagrams are all
        // dropped — never an error, or one bad datagram would kill the
        // session (`client.go:325`).
        assert!(accept_datagram(&mut d, 1, &[0, 0, 0, 1]).is_none(), "short");
        let foreign = wire(2, "1.2.3.4:53", b"x");
        assert!(
            accept_datagram(&mut d, 1, &foreign).is_none(),
            "other session"
        );
        let empty = wire(1, "1.2.3.4:53", b"");
        assert!(
            accept_datagram(&mut d, 1, &empty).is_none(),
            "empty payload"
        );
        // ...and the next good datagram still arrives.
        let good = wire(1, "1.2.3.4:53", b"pong");
        let (dest, data) = accept_datagram(&mut d, 1, &good).expect("delivered");
        assert_eq!(dest, Some("1.2.3.4:53".parse().unwrap()));
        assert_eq!(data, b"pong");
    }

    #[test]
    fn accept_reports_no_address_for_non_ip_reply() {
        // A domain reply address (the server's override hook,
        // `core/server/udp.go:166`) is delivered with `dest: None`, not
        // rejected — `Option<SocketAddr>` already encodes "no per-packet
        // address".
        let mut d = Defragger::new();
        let msg = wire(1, "example.com:53", b"hi");
        let (dest, data) = accept_datagram(&mut d, 1, &msg).expect("delivered");
        assert_eq!(dest, None);
        assert_eq!(data, b"hi");
    }

    #[test]
    fn defragger_reassembles_in_order() {
        let mut d = Defragger::new();
        assert!(d.feed(frag(7, 0, 2, b"ab")).is_none());
        let out = d.feed(frag(7, 1, 2, b"c")).expect("assembled");
        assert_eq!(out.frag_count, 1);
        assert_eq!(out.data, b"abc");
    }

    #[test]
    fn defragger_reassembles_out_of_order() {
        // Fragments arrive 1 then 0: the payload must land in `FragID`
        // order, not arrival order.
        let mut d = Defragger::new();
        assert!(d.feed(frag(9, 1, 2, b"world")).is_none());
        let out = d.feed(frag(9, 0, 2, b"hello ")).expect("assembled");
        assert_eq!(out.data, b"hello world");
    }

    #[test]
    fn defragger_new_packet_discards_partial() {
        // Packet 7 never completes (1 of 3 fragments); packet 8 then
        // arrives in full. Only packet 8 assembles, carrying only its own
        // payload.
        let mut d = Defragger::new();
        assert!(d.feed(frag(7, 0, 3, b"seven")).is_none());
        assert!(d.feed(frag(8, 0, 2, b"ei")).is_none());
        let out = d.feed(frag(8, 1, 2, b"ght")).expect("packet 8 assembled");
        assert_eq!(out.packet_id, 8);
        assert_eq!(out.data, b"eight");
    }

    #[test]
    fn defragger_ignores_duplicate_fragment() {
        // A re-delivered fragment must not be counted twice: without the
        // occupied-slot guard the duplicate would complete the message early
        // and double its data.
        let mut d = Defragger::new();
        assert!(d.feed(frag(11, 0, 3, b"aa")).is_none());
        assert!(d.feed(frag(11, 0, 3, b"aa")).is_none(), "duplicate frag 0");
        assert!(d.feed(frag(11, 1, 3, b"bb")).is_none(), "still one short");
        let out = d.feed(frag(11, 2, 3, b"cc")).expect("assembled");
        assert_eq!(out.data, b"aabbcc");
    }

    #[test]
    fn defragger_rejects_frag_id_past_count() {
        // `FragID >= FragCount` is nonsense (`frag.Defragger.Feed`,
        // `internal/frag/frag.go:51`): dropped without touching the slots,
        // so the real fragments still assemble.
        let mut d = Defragger::new();
        assert!(d.feed(frag(13, 2, 2, b"x")).is_none());
        assert!(d.feed(frag(13, 9, 2, b"y")).is_none());
        assert!(d.feed(frag(13, 0, 2, b"ok")).is_none());
        let out = d.feed(frag(13, 1, 2, b"!")).expect("assembled");
        assert_eq!(out.data, b"ok!");
    }

    #[test]
    fn sockaddr_string_forms() {
        assert_eq!(sockaddr_string("1.2.3.4:53".parse().unwrap()), "1.2.3.4:53");
        assert_eq!(sockaddr_string("[::1]:443".parse().unwrap()), "[::1]:443");
    }

    // ── split halves over a real loopback QUIC session ────────────────────

    /// The session destination the tunnels under test are opened for: the
    /// address a `send(None, …)` must put on the wire.
    const SESSION_TARGET: &str = "9.9.9.9:53";
    /// A per-packet destination.
    const DEST: &str = "1.2.3.4:53";
    /// The datagram sequence both shapes must put on the wire identically: a
    /// per-packet IPv4 destination, the session destination, and a per-packet
    /// IPv6 destination.
    const EXCHANGE: [(Option<&str>, &[u8]); 3] = [
        (Some(DEST), b"one"),
        (None, b"two"),
        (Some("[2001:db8::1]:5353"), b"three"),
    ];

    /// What the peer saw and what the carrier delivered for [`EXCHANGE`].
    type Exchange = (Vec<Vec<u8>>, Vec<(Option<SocketAddr>, Vec<u8>)>);

    /// One test destination in `SocketAddr` form.
    fn sockaddr(spec: &str) -> SocketAddr {
        spec.parse().expect("test destination parses")
    }

    /// One serialized `UDPMessage` fragment, as the server puts it on the
    /// wire.
    fn wire_frag(pkt: u16, id: u8, count: u8, addr: &str, data: &[u8]) -> BytesMut {
        let msg = UdpMessageRef {
            packet_id: pkt,
            frag_id: id,
            frag_count: count,
            ..out(addr, data)
        };
        let mut buf = BytesMut::new();
        msg.serialize_into(&mut buf);
        buf
    }

    /// A session guard that records its own drop — the stand-in for the h3
    /// keep-alive, which the halves must share rather than drop with the
    /// first one to go.
    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A session guard plus the flag it sets when it is finally released.
    fn probe() -> (SessionGuard, Arc<AtomicBool>) {
        let flag = Arc::new(AtomicBool::new(false));
        (Arc::new(DropProbe(Arc::clone(&flag))), flag)
    }

    /// A loopback QUIC pair with datagrams enabled (quinn's default):
    /// `(client, server, client endpoint, server endpoint)`.
    ///
    /// The connections come out by value so the type under test can hold the
    /// ONLY client-side handle — a spare handle here would keep the session
    /// alive on its own and the lifetime assertions would prove nothing. The
    /// endpoints come out because a dropped endpoint takes its driver with it.
    async fn quic_pair() -> (Connection, Connection, quinn::Endpoint, quinn::Endpoint) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
        let cert_der = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                .expect("key der");

        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server tls");
        server_tls.alpn_protocols = vec![super::super::ALPN_H3.to_vec()];
        let server_ep = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
                    .expect("quic server config"),
            )),
            "127.0.0.1:0".parse().expect("bind addr"),
        )
        .expect("quic server endpoint");
        let server_addr = server_ep.local_addr().expect("server addr");

        let accepting = {
            let ep = server_ep.clone();
            tokio::spawn(async move {
                ep.accept()
                    .await
                    .expect("incoming conn")
                    .await
                    .expect("server handshake")
            })
        };

        let mut client_tls = rustls::ClientConfig::builder()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                roots.add(cert_der).expect("root add");
                roots
            })
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![super::super::ALPN_H3.to_vec()];
        let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().expect("bind addr"))
            .expect("quic client endpoint");
        let client = client_ep
            .connect_with(
                quinn::ClientConfig::new(Arc::new(
                    quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
                        .expect("quic client config"),
                )),
                server_addr,
                "localhost",
            )
            .expect("connect")
            .await
            .expect("client handshake");
        let server = accepting.await.expect("accept task");
        (client, server, client_ep, server_ep)
    }

    /// A tunnel over `conn` with a watchable session guard, opened for
    /// [`SESSION_TARGET`].
    fn conn_over(conn: Connection, session: SessionGuard) -> UdpConn {
        UdpConn::with_session_guard(conn, session, SESSION_TARGET.to_string())
    }

    /// The server side: echo every datagram back verbatim (the hysteria2
    /// server relaying replies for this session) until the session ends, and
    /// log the raw bytes it saw so a test can compare wire images.
    fn spawn_echo(server: Connection) -> Arc<Mutex<Vec<Vec<u8>>>> {
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok(bytes) = server.read_datagram().await {
                seen.lock().push(bytes.to_vec());
                if server.send_datagram(bytes).is_err() {
                    break;
                }
            }
        });
        log
    }

    /// Poll `fut` exactly once, then let the caller drop it: one cancelled
    /// step of a future.
    fn poll_once<F: Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// Poll a fresh `recv` once and drop it — a cancelled receive.
    async fn cancelled_recv(reader: &mut UdpReader) {
        assert!(
            tokio::time::timeout(Duration::ZERO, reader.recv())
                .await
                .is_err(),
            "the recv should have been cancelled, not completed"
        );
    }

    #[tokio::test]
    async fn split_halves_round_trip_exactly_like_the_unsplit_conn() {
        let unsplit: Exchange = {
            let (client, server, _client_ep, _server_ep) = quic_pair().await;
            let seen = spawn_echo(server);
            let mut conn = conn_over(client, probe().0);
            for (dest, payload) in EXCHANGE {
                conn.send(dest.map(sockaddr), payload).await.expect("send");
            }
            let mut got = Vec::new();
            for _ in 0..EXCHANGE.len() {
                got.push(conn.recv().await.expect("recv").expect("datagram"));
            }
            (seen.lock().clone(), got)
        };

        let split: Exchange = {
            let (client, server, _client_ep, _server_ep) = quic_pair().await;
            let seen = spawn_echo(server);
            let (mut reader, mut writer) = conn_over(client, probe().0).split().expect("split");
            for (dest, payload) in EXCHANGE {
                writer
                    .send(dest.map(sockaddr), payload)
                    .await
                    .expect("send");
            }
            let mut got = Vec::new();
            for _ in 0..EXCHANGE.len() {
                got.push(reader.recv().await.expect("recv").expect("datagram"));
            }
            (seen.lock().clone(), got)
        };

        // Byte-for-byte the same `UDPMessage`s on the wire (session id,
        // PacketID, address form) and the same delivered datagrams: the split
        // moved state around, it changed no behaviour.
        assert_eq!(split.0, unsplit.0, "same bytes on the wire");
        assert_eq!(split.1, unsplit.1, "same delivered datagrams");
        // ...and both delivered what we sent, with `dest: None` carrying the
        // session destination (the reply address comes back parsed).
        let expect: Vec<(Option<SocketAddr>, Vec<u8>)> = EXCHANGE
            .iter()
            .map(|(dest, payload)| {
                (
                    Some(sockaddr(dest.unwrap_or(SESSION_TARGET))),
                    payload.to_vec(),
                )
            })
            .collect();
        assert_eq!(unsplit.1, expect);
    }

    #[tokio::test]
    async fn both_shapes_reject_an_oversize_payload_identically() {
        let (client, _server, _client_ep, _server_ep) = quic_pair().await;
        let too_big = vec![0u8; MAX_UDP_SIZE + 1];
        let mut conn = conn_over(client.clone(), probe().0);
        let combined = conn.send(None, &too_big).await.expect_err("rejected");
        let (_reader, mut writer) = conn_over(client, probe().0).split().expect("split");
        let half = writer.send(None, &too_big).await.expect_err("rejected");
        assert_eq!(combined.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(half.kind(), combined.kind());
        assert_eq!(half.to_string(), combined.to_string());
        assert_eq!(
            combined.to_string(),
            format!(
                "hy2 udp datagram too large ({}, max {MAX_UDP_SIZE})",
                too_big.len()
            )
        );
    }

    #[tokio::test]
    async fn split_halves_fragment_and_reassemble_an_oversize_datagram() {
        let (client, server, _client_ep, _server_ep) = quic_pair().await;
        let budget = client.max_datagram_size().expect("peer supports datagrams");
        // Larger than one QUIC datagram but within `MAX_UDP_SIZE`: quinn
        // answers `TooLarge` and the writer fragments (`frag.FragUDPMessage`).
        let payload: Vec<u8> = (0..3000).map(|i| b"abcdefghij"[i % 10]).collect();
        assert!(
            payload.len() > budget,
            "payload must not fit one datagram (budget {budget})"
        );

        let seen = spawn_echo(server);
        let (mut reader, mut writer) = conn_over(client, probe().0).split().expect("split");
        writer
            .send(Some(sockaddr(DEST)), &payload)
            .await
            .expect("send");
        // Every fragment echoes back and the reader's defragmenter puts the
        // datagram together again.
        let (dest, got) = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("recv completes")
            .expect("recv")
            .expect("assembled datagram");
        assert_eq!(dest, Some(sockaddr(DEST)));
        assert_eq!(got, payload);

        // One `PacketID` for the whole message (the first fragmented send is
        // 1), `FragID` 0..count in order, the address on every fragment.
        let frags = seen.lock().clone();
        assert!(frags.len() > 1, "the datagram must have been fragmented");
        for (i, raw) in frags.iter().enumerate() {
            let m = UdpMessage::parse(raw).expect("fragment parses");
            assert_eq!(m.session_id, SESSION_ID);
            assert_eq!(m.packet_id, 1, "one PacketID for the whole message");
            assert_eq!(usize::from(m.frag_count), frags.len());
            assert_eq!(usize::from(m.frag_id), i);
            assert_eq!(m.addr, DEST);
            assert!(raw.len() <= budget, "fragment fits the datagram budget");
        }
    }

    #[tokio::test]
    async fn a_split_send_completes_while_the_reader_half_is_parked() {
        let (client, server, _client_ep, _server_ep) = quic_pair().await;
        let _seen = spawn_echo(server);
        let (mut reader, mut writer) = conn_over(client, probe().0).split().expect("split");

        // The reader parks inside `recv` in its own task — the shape the
        // unsplit tunnel cannot serve, since its `recv` and `send` both need
        // `&mut self`.
        let reading = tokio::spawn(async move {
            let got = reader.recv().await;
            (reader, got)
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        writer.send(None, b"parked").await.expect("send");
        let (mut reader, got) = tokio::time::timeout(Duration::from_secs(5), reading)
            .await
            .expect("reader completes")
            .expect("reader task");
        assert_eq!(
            got.expect("recv").expect("datagram"),
            (Some(sockaddr(SESSION_TARGET)), b"parked".to_vec())
        );

        // ...and the same thing without a task: an already-pending `recv`
        // future stays alive across a `send` on the writer half.
        let mut pending = pin!(reader.recv());
        assert!(poll_once(pending.as_mut()).is_pending(), "recv is parked");
        writer.send(None, b"second").await.expect("send");
        let (dest, payload) = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .expect("recv completes")
            .expect("recv")
            .expect("datagram");
        assert_eq!(dest, Some(sockaddr(SESSION_TARGET)));
        assert_eq!(payload, b"second");
    }

    #[tokio::test]
    async fn a_cancelled_recv_keeps_the_fragments_it_accepted() {
        let (client, server, _client_ep, _server_ep) = quic_pair().await;
        let (mut reader, _writer) = conn_over(client, probe().0).split().expect("split");

        // Cancelled with nothing queued: quinn's `read_datagram` future keeps
        // no state of its own, so nothing is consumed.
        cancelled_recv(&mut reader).await;

        // Fragment 0 of a two-fragment message arrives, and the `recv` that
        // accepts it is cancelled before the message can assemble — the point
        // where the stream carriers lose bytes. The fragment survives because
        // the defragmenter lives in the half, not in the future.
        server
            .send_datagram(wire_frag(4, 0, 2, DEST, b"hello").freeze())
            .expect("frag 0");
        for _ in 0..100 {
            cancelled_recv(&mut reader).await;
            if reader.read.defrag.count == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(reader.read.defrag.count, 1, "fragment 0 was accepted");
        assert_eq!(reader.read.defrag.pkt_id, 4, "...and kept, after the drop");

        // The rest of the message arrives at a fresh `recv`: the datagram is
        // delivered whole, nothing lost to the cancellations.
        server
            .send_datagram(wire_frag(4, 1, 2, DEST, b" world").freeze())
            .expect("frag 1");
        let (dest, got) = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("recv completes")
            .expect("recv")
            .expect("datagram");
        assert_eq!(dest, Some(sockaddr(DEST)));
        assert_eq!(got, b"hello world");
    }

    #[tokio::test]
    async fn the_reader_half_reports_eof_when_the_session_closes() {
        let (client, server, _client_ep, _server_ep) = quic_pair().await;
        let (mut reader, _writer) = conn_over(client, probe().0).split().expect("split");
        // A clean close at a message boundary, nothing in flight.
        server.close(0u32.into(), b"bye");
        let got = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("recv completes")
            .expect("a closed session is not an error");
        assert!(got.is_none(), "clean end-of-stream is Ok(None)");
    }

    #[tokio::test]
    async fn the_reader_half_keeps_the_session_alive_after_the_writer_drops() {
        let (client, server, _client_ep, _server_ep) = quic_pair().await;
        let (guard, released) = probe();
        // The halves hold the only client-side connection handle: if the
        // session died with the writer, this `recv` would see EOF instead of
        // the server's datagram.
        let (mut reader, writer) = conn_over(client, guard).split().expect("split");
        drop(writer);
        assert!(
            !released.load(Ordering::SeqCst),
            "one half gone: the session guard stays"
        );

        server
            .send_datagram(wire(SESSION_ID, DEST, b"still here").freeze())
            .expect("server datagram");
        let (dest, got) = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("recv completes")
            .expect("recv")
            .expect("datagram");
        assert_eq!(dest, Some(sockaddr(DEST)));
        assert_eq!(got, b"still here");

        drop(reader);
        assert!(
            released.load(Ordering::SeqCst),
            "last half gone: the guard is released"
        );
    }

    #[tokio::test]
    async fn the_writer_half_keeps_the_session_alive_after_the_reader_drops() {
        let (client, server, _client_ep, _server_ep) = quic_pair().await;
        let (guard, released) = probe();
        let (reader, mut writer) = conn_over(client, guard).split().expect("split");
        drop(reader);
        assert!(
            !released.load(Ordering::SeqCst),
            "one half gone: the session guard stays"
        );

        writer.send(None, b"still here").await.expect("send");
        let raw = tokio::time::timeout(Duration::from_secs(5), server.read_datagram())
            .await
            .expect("server datagram arrives")
            .expect("server datagram");
        let m = UdpMessage::parse(&raw).expect("parses");
        assert_eq!(m.addr, SESSION_TARGET);
        assert_eq!(m.data, b"still here");

        drop(writer);
        assert!(
            released.load(Ordering::SeqCst),
            "last half gone: the guard is released"
        );
    }
}
