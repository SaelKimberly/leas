//! Trojan — native client.
//!
//! Wire contract: xray-core / sing-box `proxy/trojan` (MIT; sing-box
//! `transport/trojan/protocol.go`). The client writes the request header
//! `hex(sha224(password)) (56 ASCII bytes) || CRLF || command || address ||
//! CRLF` where the address is **port-last** (`ATYP | addr | port BE2` —
//! trojan's `NewAddressParser` has no `PortFirst()` option, and sing-box's
//! `SocksaddrSerializer` is port-last too), command `1` = TCP / `3` = UDP.
//! There is **no server response header**: after the request the server
//! relays the target's bytes raw in both directions (xray `server.go`
//! `handleConnection` and `<sing>/protocol/trojan/client.go` both relay
//! without a response frame). The tunnel is pure passthrough.
//!
//! The trojan address uses the SOCKS5-ATYP family bytes (`0x01` IPv4 /
//! `0x03` domain / `0x04` IPv6) in port-last order —
//! [`crate::addr::encode_addr_port_last`] — NOT the VLESS/VMess
//! `ADDR_TYPE_*` (1/2/3) set, which those protocols' parsers expect.

use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use leas_proto::proto_spec::TrojanConfig;

use crate::BoxStream;
use crate::addr::{
    TargetAddr, addr_port_last_tail_len, decode_addr_port_last, encode_addr_port_last,
};
use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};

/// TCP command byte (`protocol.go` `commandTCP`).
const COMMAND_TCP: u8 = 1;
/// UDP command byte (`protocol.go` `commandUDP`).
const COMMAND_UDP: u8 = 3;
/// The protocol's record separator (`protocol.go` `crlf`).
const CRLF: [u8; 2] = [0x0d, 0x0a];
/// xray's UDP payload cap (`protocol.go` `maxLength = 8192`): its
/// `PacketReader` rejects anything longer, so the writer never emits a
/// bigger datagram. The read side has no cap — sing-box's `ReadPacket`
/// (`transport/trojan/protocol.go`) reads the length field's full u16
/// range, and we deliberately follow that permissive peer.
const MAX_UDP_PAYLOAD: usize = 8192;
/// The widest port-last wire address: `ATYP | len | domain(255) | port BE2`
/// — the domain form (IPv4 is 7 bytes, IPv6 19). Every wire address fits,
/// so the reader buffers one in a fixed-size array and parses it in place.
const MAX_WIRE_ADDR: usize = 1 + 1 + 255 + 2;
/// A frame's fixed-width head at its widest: the wire address
/// ([`MAX_WIRE_ADDR`]) plus the 2-byte BE length and the CRLF separator.
/// The reader buffers the head in one array of this size and the writer's
/// scratch starts with room for one, so only the payload grows either.
const MAX_FRAME_HEAD: usize = MAX_WIRE_ADDR + 2 + 2;
/// The 56-byte lowercase hex encoding of `sha224(password)` — the wire auth
/// hash (`config.go` `hexSha224`).
///
/// Wipes on drop: it travels on the wire but is a replayable bearer
/// credential, so a stale stack copy is as good as the password.
#[must_use]
pub fn auth_key(password: &str) -> Zeroizing<[u8; 56]> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha224::digest(password.as_bytes());
    let mut out = Zeroizing::new([0u8; 56]);
    for (i, byte) in digest.iter().enumerate() {
        out[i * 2] = HEX[usize::from(byte >> 4)];
        out[i * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    out
}

/// Encode the trojan TCP request header (`protocol.go` `writeHeader` /
/// `sing-box` `ClientHandshake`): `key || CRLF || command || addr || CRLF`.
fn encode_request(key: &[u8; 56], target: &TargetAddr) -> Result<Vec<u8>, NativeError> {
    let mut out = Vec::with_capacity(56 + 2 + 1 + 1 + 2 + 16 + 2);
    out.extend_from_slice(key);
    out.extend_from_slice(&CRLF);
    out.push(COMMAND_TCP);
    out.extend_from_slice(&encode_addr_port_last(target)?);
    out.extend_from_slice(&CRLF);
    Ok(out)
}

/// trojan has no response header to peel. UDP rides
/// [`connect_udp`] (command 3 + per-datagram address framing).
pub async fn connect(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &TrojanConfig,
) -> Result<BoxStream, NativeError> {
    let request = encode_request(&auth_key(&cfg.password), &ctx.target)?;
    let timeout = timeouts::PROTOCOL;
    let mut stream = stream;
    tokio::time::timeout(timeout, stream.write_all(&request))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "trojan request write",
            limit: timeout,
        })??;
    Ok(stream)
}

/// Encode the trojan UDP request header: command 3 + the session target
/// (port-last) — xray `writeHeader` with `commandUDP`, sing-box
/// `ClientHandshakePacket`.
fn encode_udp_request(key: &[u8; 56], target: &TargetAddr) -> Result<Vec<u8>, NativeError> {
    let mut out = Vec::with_capacity(56 + 2 + 1 + 1 + 2 + 16 + 2);
    out.extend_from_slice(key);
    out.extend_from_slice(&CRLF);
    out.push(COMMAND_UDP);
    out.extend_from_slice(&encode_addr_port_last(target)?);
    out.extend_from_slice(&CRLF);
    Ok(out)
}

/// Append a per-packet destination in trojan port-last form
/// (`ATYP | addr | port BE2`) — the address half of xray
/// `PacketWriter.writePacket` / sing-box `WritePacket`. This is the IP-only
/// half of [`crate::addr::encode_addr_port_last`]: a `SocketAddr` has no
/// domain form, so it cannot fail, and it writes into the caller's buffer
/// rather than allocating per datagram.
fn push_socket_addr_port_last(out: &mut Vec<u8>, dest: std::net::SocketAddr) {
    match dest.ip() {
        std::net::IpAddr::V4(ip) => {
            out.push(crate::addr::TROJAN_ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            out.push(crate::addr::TROJAN_ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&dest.port().to_be_bytes());
}

/// The error a stream that ends part-way through a frame reports — the
/// same `ErrorKind::UnexpectedEof` / `"early eof"` pair `read_exact` gave
/// before the reader accumulated frames itself.
fn early_eof() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "early eof")
}

/// The read direction's state: the frame currently arriving.
///
/// The partial frame lives here instead of in `recv`'s locals so a
/// cancelled `recv` — a `select!` branch that lost the race, a `timeout`
/// that fired — resumes on the byte it stopped at instead of dropping the
/// bytes it had already taken off the stream (which would desynchronize
/// every later frame). Every `await` below is one
/// [`AsyncReadExt::read`], which is cancel-safe — a dropped `read` future
/// has read nothing — and its byte count is committed to `self` before the
/// next one, so after a cancellation the state is exactly "this much of
/// the frame has arrived".
struct ReadState {
    /// `ATYP | addr | port BE2 | len BE2 | CRLF` — the frame's fixed-width
    /// head. Every wire address fits, so the head is buffered and parsed
    /// in place, with no allocation.
    head: [u8; MAX_FRAME_HEAD],
    /// How much of `head` the frame in flight has delivered.
    head_filled: usize,
    /// The frame's payload, sized from its length field and filled in
    /// place: it is moved out to the caller, never copied.
    payload: Vec<u8>,
    /// How much of `payload` the frame in flight has delivered.
    payload_filled: usize,
}

impl ReadState {
    /// A reader positioned at a frame boundary with nothing buffered.
    const fn new() -> Self {
        Self {
            head: [0u8; MAX_FRAME_HEAD],
            head_filled: 0,
            payload: Vec::new(),
            payload_filled: 0,
        }
    }

    /// Fill `head[..want]`, keeping whatever earlier (possibly cancelled)
    /// calls already buffered. An EOF here is part-way through a frame, so
    /// it is [`early_eof`]; the clean end-of-stream case is the ATYP byte
    /// in [`Self::read_frame`], and only there.
    async fn fill_head<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        want: usize,
    ) -> std::io::Result<()> {
        while self.head_filled < want {
            let n = r.read(&mut self.head[self.head_filled..want]).await?;
            if n == 0 {
                return Err(early_eof());
            }
            self.head_filled += n;
        }
        Ok(())
    }

    /// Fill `payload[..want]`, keeping whatever earlier calls already
    /// buffered. Length-exact: a short payload would deliver a truncated
    /// datagram and desynchronize every later frame, so an EOF is an
    /// error.
    async fn fill_payload<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        want: usize,
    ) -> std::io::Result<()> {
        if self.payload.len() != want {
            // The frame's one allocation. A resumed frame re-derives the
            // same `want` from the same head, so its buffer is already
            // sized and the bytes in it survive.
            debug_assert_eq!(self.payload_filled, 0, "a resumed frame keeps its buffer");
            self.payload = vec![0u8; want];
        }
        while self.payload_filled < want {
            let n = r.read(&mut self.payload[self.payload_filled..]).await?;
            if n == 0 {
                return Err(early_eof());
            }
            self.payload_filled += n;
        }
        Ok(())
    }

    /// Read one trojan UDP datagram frame; `Ok(None)` on a clean EOF at a
    /// frame boundary (xray `PacketReader` / sing-box `ReadPacket`). A
    /// truncated frame — partial address, length, CRLF or short payload —
    /// is `UnexpectedEof`.
    async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> std::io::Result<Option<(TargetAddr, Vec<u8>)>> {
        // A frame boundary is the only place an EOF is legal, so the ATYP
        // byte is a plain `read`: `fill_head` would turn a clean
        // end-of-stream into `UnexpectedEof`. A cancelled call may have
        // taken it already, in which case there is nothing to read.
        if self.head_filled == 0 {
            let n = r.read(&mut self.head[..1]).await?;
            if n == 0 {
                return Ok(None); // clean EOF at a frame boundary
            }
            self.head_filled = n; // a one-byte buffer reads 0 or 1
        }
        let atyp = self.head[0];
        // The domain family prefixes the name with a length byte; the IP
        // families are fixed-width. `addr_head` is the address bytes up to
        // and including that length byte.
        let (addr_head, domain_len) = if atyp == crate::addr::TROJAN_ATYP_DOMAIN {
            self.fill_head(r, 2).await?;
            (2, self.head[1])
        } else {
            (1, 0)
        };
        // How many bytes follow the head — the family layout has one owner.
        let tail = addr_port_last_tail_len(atyp, domain_len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("trojan udp frame: unknown address type {atyp}"),
            )
        })?;
        let addr_end = addr_head + tail;
        self.fill_head(r, addr_end).await?;

        // `head[..addr_end]` is now the full `ATYP|addr|port` address.
        let (dest, _) = decode_addr_port_last(&self.head[..addr_end]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trojan udp frame: malformed address",
            )
        })?;

        // The 2-byte BE payload length and the CRLF separator: four
        // fixed-width bytes, one fill. Every u16 is a legal length —
        // sing-box's `ReadPacket` (`transport/trojan/protocol.go`) reads
        // the field uncapped, xray's `PacketReader` rejects more than
        // `maxLength` = 8192 (`proxy/trojan/protocol.go`); we follow
        // sing-box's permissive read and keep xray's cap on the writer
        // (`MAX_UDP_PAYLOAD`).
        let head_end = addr_end + 4;
        self.fill_head(r, head_end).await?;
        let payload_len = usize::from(u16::from_be_bytes([
            self.head[addr_end],
            self.head[addr_end + 1],
        ]));
        if self.head[addr_end + 2..head_end] != CRLF {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trojan udp frame: missing CRLF",
            ));
        }
        self.fill_payload(r, payload_len).await?;

        // The frame is complete: hand the payload over by move and reset
        // to the next frame boundary.
        self.head_filled = 0;
        self.payload_filled = 0;
        Ok(Some((dest, std::mem::take(&mut self.payload))))
    }

    /// Receive one datagram from `r`. `Ok(None)` on a clean EOF at a frame
    /// boundary.
    ///
    /// Returns the frame's per-packet destination for the IP forms, and
    /// `None` for the domain form — no per-packet address. A reply
    /// addressed by domain is ordinary traffic, not an error: for a domain
    /// destination sing-box maps the reply address back to the original
    /// FQDN by default (`route/conn.go` wraps the relay in a
    /// `NATPacketConn` unless `udp_disable_domain_unmapping`), and xray's
    /// `PacketReader` parses the domain family too (`addrParser` carries
    /// `0x03`).
    async fn recv_from<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> std::io::Result<Option<(Option<std::net::SocketAddr>, Vec<u8>)>> {
        let Some((dest, payload)) = self.read_frame(r).await? else {
            return Ok(None);
        };
        let sa = match dest.host {
            crate::addr::Host::Ip(ip) => Some(std::net::SocketAddr::new(ip, dest.port)),
            // A domain has no `SocketAddr` form; the datagram still stands.
            crate::addr::Host::Domain(_) => None,
        };
        Ok(Some((sa, payload)))
    }
}

/// The write direction's state: the session address an unaddressed
/// datagram defaults to, and the scratch its frame is assembled in.
struct WriteState {
    /// The session target from the request header, pre-encoded port-last —
    /// the frame address when a `send` carries no per-packet destination
    /// (xray `PacketWriter` defaults `target := &w.Target`). The session
    /// target never changes, so it is encoded once, at construction.
    session_addr: Vec<u8>,
    /// Scratch for the outgoing frame, reused across datagrams: it grows to
    /// the session's largest frame and then stays put, so the steady state
    /// allocates nothing per datagram.
    frame: Vec<u8>,
}

impl WriteState {
    /// Pre-encode the session target — the default frame address. Fails
    /// only on a target that has no wire form (a domain over 255 bytes).
    fn new(target: &TargetAddr) -> Result<Self, NativeError> {
        Ok(Self {
            session_addr: encode_addr_port_last(target)?,
            frame: Vec::with_capacity(MAX_FRAME_HEAD),
        })
    }

    /// Write one datagram to `w` as `addr (port-last) || len(2B BE) ||
    /// CRLF || payload` — xray `PacketWriter.writePacket`, sing-box
    /// `WritePacket`.
    ///
    /// `dest: None` uses the session target (the request-header
    /// destination); `Some(addr)` carries that address in the frame —
    /// trojan frames every datagram with its own destination, so any
    /// per-packet address is legal. The frame is assembled in the reused
    /// scratch buffer and written with a single `write_all`: one datagram
    /// is one record on the wire. An oversize payload is rejected before
    /// anything reaches the stream.
    async fn send_to<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        dest: Option<std::net::SocketAddr>,
        payload: &[u8],
    ) -> std::io::Result<()> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "trojan udp datagram too large ({}, max {MAX_UDP_PAYLOAD})",
                    payload.len()
                ),
            ));
        }
        let len = u16::try_from(payload.len()).expect("payload bounded by MAX_UDP_PAYLOAD");
        self.frame.clear();
        match dest {
            Some(sa) => push_socket_addr_port_last(&mut self.frame, sa),
            None => self.frame.extend_from_slice(&self.session_addr),
        }
        self.frame.extend_from_slice(&len.to_be_bytes());
        self.frame.extend_from_slice(&CRLF);
        self.frame.extend_from_slice(payload);
        w.write_all(&self.frame).await
    }
}

/// A trojan UDP connection over the tunnel stream (command 3).
///
/// Each datagram is an address-prefixed frame `ATYP|addr|port || len ||
/// CRLF || payload` in both directions — the address is per-packet (the
/// session target is the default when the caller passes no destination),
/// matching xray `PacketWriter`/`PacketReader` and sing-box `WritePacket`/
/// `ReadPacket`. There is no response header to peel (trojan relays raw).
///
/// The two directions are independent state ([`ReadState`], [`WriteState`])
/// over one stream, so [`Self::split`] can hand them to separate tasks.
/// The combined form keeps owning the stream outright — the split's
/// `tokio::io::split` lock never touches this path.
pub struct PacketConn<S> {
    inner: S,
    /// Read-direction state: the frame currently arriving.
    read: ReadState,
    /// Write-direction state: the session address and the frame scratch.
    write: WriteState,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> PacketConn<S> {
    /// Wrap the tunnel stream (the command-3 header already written) and
    /// pre-encode the session target — the default frame address. Fails
    /// only on a target that has no wire form (a domain over 255 bytes).
    pub fn new(inner: S, target: &TargetAddr) -> Result<Self, NativeError> {
        Ok(Self {
            inner,
            read: ReadState::new(),
            write: WriteState::new(target)?,
        })
    }

    /// Send one datagram as `addr (port-last) || len(2B BE) || CRLF ||
    /// payload` — xray `PacketWriter.writePacket`, sing-box `WritePacket`.
    ///
    /// `dest: None` uses the session target (the request-header
    /// destination); `Some(addr)` carries that address in the frame —
    /// trojan frames every datagram with its own destination, so any
    /// per-packet address is legal. The frame is assembled in the reused
    /// scratch buffer and written with a single `write_all`: one datagram
    /// is one record on the wire.
    pub async fn send(
        &mut self,
        dest: Option<std::net::SocketAddr>,
        payload: &[u8],
    ) -> std::io::Result<()> {
        self.write.send_to(&mut self.inner, dest, payload).await
    }

    /// Receive one datagram. `Ok(None)` on a clean EOF at a frame boundary.
    ///
    /// Returns the frame's per-packet destination for the IP forms, and
    /// `None` for the domain form — no per-packet address. A reply
    /// addressed by domain is ordinary traffic, not an error: for a domain
    /// destination sing-box maps the reply address back to the original
    /// FQDN by default (`route/conn.go` wraps the relay in a
    /// `NATPacketConn` unless `udp_disable_domain_unmapping`), and xray's
    /// `PacketReader` parses the domain family too (`addrParser` carries
    /// `0x03`).
    pub async fn recv(
        &mut self,
    ) -> std::io::Result<Option<(Option<std::net::SocketAddr>, Vec<u8>)>> {
        self.read.recv_from(&mut self.inner).await
    }

    /// Split into halves that may be used concurrently from separate
    /// tasks: the reader owns the read direction, the writer the write
    /// direction.
    ///
    /// A dedicated reader task is how a caller avoids racing `recv` in a
    /// `select!` — the frame state moves into [`PacketReader`], so the
    /// half-received frame a cancelled `recv` left behind survives the
    /// split too. trojan is a plain byte stream in both directions, so
    /// this never fails; the `io::Result` matches the sibling carriers,
    /// where a mode can genuinely be unsplittable.
    pub fn split(self) -> std::io::Result<SplitHalves<S>> {
        let Self { inner, read, write } = self;
        let (rx, tx) = tokio::io::split(inner);
        Ok((
            PacketReader {
                inner: rx,
                state: read,
            },
            PacketWriter {
                inner: tx,
                state: write,
            },
        ))
    }
}

/// The halves [`PacketConn::split`] produces: the read direction over the
/// stream's read half, the write direction over its write half. Named so
/// the split signature stays one type, not a nested tuple.
pub type SplitHalves<S> = (
    PacketReader<tokio::io::ReadHalf<S>>,
    PacketWriter<tokio::io::WriteHalf<S>>,
);

/// The read half of a [`PacketConn`] — see [`PacketConn::split`].
///
/// Owning only the read direction is what lets the reader live in its own
/// task: its `recv` future never has to be raced against a write, so it is
/// never dropped mid-frame.
pub struct PacketReader<R> {
    inner: R,
    /// The read-direction state moved out of the combined `PacketConn`.
    state: ReadState,
}

impl<R: tokio::io::AsyncRead + Unpin> PacketReader<R> {
    /// Receive one datagram — [`PacketConn::recv`] on the read half:
    /// one implementation, the same results (`Ok(None)` on a clean EOF at
    /// a frame boundary, a `None` destination for a domain-addressed
    /// frame).
    pub async fn recv(
        &mut self,
    ) -> std::io::Result<Option<(Option<std::net::SocketAddr>, Vec<u8>)>> {
        self.state.recv_from(&mut self.inner).await
    }
}

/// The write half of a [`PacketConn`] — see [`PacketConn::split`].
pub struct PacketWriter<W> {
    inner: W,
    /// The write-direction state moved out of the combined `PacketConn`:
    /// the pre-encoded session address and the frame scratch.
    state: WriteState,
}

impl<W: tokio::io::AsyncWrite + Unpin> PacketWriter<W> {
    /// Send one datagram — [`PacketConn::send`] on the write half: the
    /// same framing, the same oversize rejection, the same session-address
    /// default.
    pub async fn send(
        &mut self,
        dest: Option<std::net::SocketAddr>,
        payload: &[u8],
    ) -> std::io::Result<()> {
        self.state.send_to(&mut self.inner, dest, payload).await
    }
}

/// Connect through a Trojan outbound with a UDP datagram tunnel (command 3).
///
/// Writes the UDP request header (`key || CRLF || 3 || session-target
/// port-last || CRLF`) then wraps the stream in the address-framed
/// [`PacketConn`]. No server response header — the server relays the
/// target's UDP datagrams raw (xray `server.go` `handleUDP` / sing-box
/// `service.go`).
pub async fn connect_udp(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &TrojanConfig,
) -> Result<PacketConn<BoxStream>, NativeError> {
    let request = encode_udp_request(&auth_key(&cfg.password), &ctx.target)?;
    let timeout = timeouts::PROTOCOL;
    let mut stream = stream;
    tokio::time::timeout(timeout, stream.write_all(&request))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "trojan udp request write",
            limit: timeout,
        })??;
    PacketConn::new(stream, &ctx.target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Host, TargetAddr};

    /// NIST SHA-224("") = d14a028c...e42f — the digest the raw hash must match.
    #[test]
    fn auth_key_nist_empty_vector() {
        let key = auth_key("");
        let hex = key.iter().map(|b| char::from(*b)).collect::<String>();
        assert_eq!(
            hex,
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    /// `auth_key` is genuinely the hex of `sha224(password)` (not a stale
    /// constant): recompute with the `sha2` crate and compare.
    #[test]
    fn auth_key_matches_sha224_wiring() {
        let password = "secret-token";
        let key = auth_key(password);
        let expect: Vec<u8> = Sha224::digest(password.as_bytes())
            .iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect();
        assert_eq!(&key[..], &expect[..]);
    }

    #[test]
    fn request_header_wire_order() {
        let key = auth_key("pw");
        // Domain target: ATYP(1) len(11) "example.com" port(443 BE) — the
        // address comes BEFORE the port (port-last), and there is a CRLF at
        // both the start and the end.
        let req = encode_request(
            &key,
            &TargetAddr::new(Host::Domain("example.com".into()), 443),
        )
        .unwrap();
        let mut expect = Vec::new();
        expect.extend_from_slice(key.as_slice());
        expect.extend_from_slice(&CRLF);
        expect.push(1); // command TCP
        expect.push(crate::addr::TROJAN_ATYP_DOMAIN); // ATYP (SOCKS5 0x03)
        expect.push(11); // domain len ("example.com")
        expect.extend_from_slice(b"example.com");
        expect.extend_from_slice(&443u16.to_be_bytes()); // port LAST
        expect.extend_from_slice(&CRLF);
        assert_eq!(req, expect);
    }

    #[test]
    fn udp_request_header_uses_command_3() {
        let key = auth_key("pw");
        let req = encode_udp_request(
            &key,
            &TargetAddr::new(Host::Domain("example.com".into()), 443),
        )
        .unwrap();
        let mut expect = Vec::new();
        expect.extend_from_slice(key.as_slice());
        expect.extend_from_slice(&CRLF);
        expect.push(3); // command UDP
        expect.push(crate::addr::TROJAN_ATYP_DOMAIN);
        expect.push(11);
        expect.extend_from_slice(b"example.com");
        expect.extend_from_slice(&443u16.to_be_bytes());
        expect.extend_from_slice(&CRLF);
        assert_eq!(req, expect);
    }

    #[tokio::test]
    async fn packet_conn_wire_frame_exact() {
        use tokio::io::AsyncReadExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        // send(Some(v4:5353), b"hi") → the exact address-prefixed frame.
        conn.send(Some("9.9.9.9:5353".parse().unwrap()), b"hi")
            .await
            .unwrap();
        let mut got = vec![0u8; 64];
        let n = server.read(&mut got).await.unwrap();
        let mut expect = vec![0x01, 9, 9, 9, 9, 0x14, 0xe9]; // ATYP IPv4 + 9.9.9.9 + port 5353
        expect.extend_from_slice(&2u16.to_be_bytes()); // len
        expect.extend_from_slice(&CRLF);
        expect.extend_from_slice(b"hi");
        assert_eq!(&got[..n], &expect[..]);
    }

    #[tokio::test]
    async fn packet_conn_send_none_uses_session_target() {
        use tokio::io::AsyncReadExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        conn.send(None, b"x").await.unwrap();
        let mut got = vec![0u8; 32];
        let n = server.read(&mut got).await.unwrap();
        let mut expect = vec![0x01, 1, 2, 3, 4, 0x00, 0x35]; // session target 1.2.3.4:53
        expect.extend_from_slice(&1u16.to_be_bytes());
        expect.extend_from_slice(&CRLF);
        expect.push(b'x');
        assert_eq!(&got[..n], &expect[..]);
    }

    #[tokio::test]
    async fn packet_conn_recv_parses_frame() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        // Peer writes a reply frame: addr + len + CRLF + payload.
        let mut frame = vec![0x01, 8, 8, 8, 8, 0x00, 0x35];
        frame.extend_from_slice(&3u16.to_be_bytes());
        frame.extend_from_slice(&CRLF);
        frame.extend_from_slice(b"hey");
        server.write_all(&frame).await.unwrap();
        let (dest, payload) = conn.recv().await.unwrap().expect("a datagram");
        assert_eq!(dest, Some("8.8.8.8:53".parse().unwrap()));
        assert_eq!(payload, b"hey");
    }

    #[tokio::test]
    async fn packet_conn_recv_clean_eof_is_none() {
        let (client, server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        drop(server);
        assert!(conn.recv().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn packet_conn_recv_truncated_frame_is_error() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        server.write_all(&[0x01, 8, 8]).await.unwrap(); // ATYP IPv4 + 2 addr bytes only
        drop(server); // close the write half so read_exact hits EOF
        let err = conn.recv().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn packet_conn_send_oversized_rejected() {
        let (client, _server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        let big = vec![0u8; MAX_UDP_PAYLOAD + 1];
        let err = conn.send(None, &big).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn connect_udp_writes_command_3_header() {
        use tokio::io::AsyncReadExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let cfg: leas_proto::proto_spec::TrojanConfig = serde_json::from_value(serde_json::json!({
            "schema": "Trojan",
            "password": "pw",
            "transport": { "type": "tcp" }
        }))
        .expect("trojan config parses");
        let params = crate::context::NativeConnectParams::new(
            leas_proto::proto_spec::ProtocolConfig::Trojan(cfg.clone()),
            leas_proto::proto_spec::endpoint::EndpointEssentials::new("1.2.3.4", 443),
            TargetAddr::new(Host::Domain("example.com".into()), 443),
        );
        let ctx = crate::context::LinkContext::new(
            params,
            TargetAddr::new(Host::Domain("example.com".into()), 443),
        );
        let conn = connect_udp(&ctx, Box::new(client), &cfg).await.unwrap();
        drop(conn);
        let mut got = vec![0u8; 128];
        let n = server.read(&mut got).await.unwrap();
        let key = auth_key("pw");
        let mut expect = Vec::new();
        expect.extend_from_slice(key.as_slice());
        expect.extend_from_slice(&CRLF);
        expect.push(3);
        expect.push(crate::addr::TROJAN_ATYP_DOMAIN);
        expect.push(11);
        expect.extend_from_slice(b"example.com");
        expect.extend_from_slice(&443u16.to_be_bytes());
        expect.extend_from_slice(&CRLF);
        assert_eq!(&got[..n], &expect[..]);
    }

    /// A domain session target is pre-encoded once at construction, so a
    /// `send(None, ..)` emits the port-last domain form (`0x03 | len |
    /// name | port`) — the common case, and the one that used to clone a
    /// `String` per datagram.
    #[tokio::test]
    async fn packet_conn_send_none_uses_domain_session_target() {
        use tokio::io::AsyncReadExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::Domain("example.com".into()), 443);
        let mut conn = PacketConn::new(client, &target).unwrap();
        conn.send(None, b"q").await.unwrap();
        let mut got = vec![0u8; 64];
        let n = server.read(&mut got).await.unwrap();
        let mut expect = vec![crate::addr::TROJAN_ATYP_DOMAIN, 11];
        expect.extend_from_slice(b"example.com");
        expect.extend_from_slice(&443u16.to_be_bytes()); // port LAST
        expect.extend_from_slice(&1u16.to_be_bytes()); // payload len
        expect.extend_from_slice(&CRLF);
        expect.push(b'q');
        assert_eq!(&got[..n], &expect[..]);
    }

    /// The IPv6 per-packet form: the SOCKS5 family byte `0x04` (NOT the
    /// VLESS/VMess `3`), the 16 octets, then the port — port-last.
    #[tokio::test]
    async fn packet_conn_send_ipv6_per_packet_address() {
        use tokio::io::AsyncReadExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        let ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        conn.send(Some(std::net::SocketAddr::from((ip, 443))), b"z")
            .await
            .unwrap();
        let mut got = [0u8; 1 + 16 + 2 + 2 + 2 + 1];
        server.read_exact(&mut got).await.unwrap();
        let mut expect = vec![crate::addr::TROJAN_ATYP_IPV6];
        expect.extend_from_slice(&ip.octets());
        expect.extend_from_slice(&443u16.to_be_bytes());
        expect.extend_from_slice(&1u16.to_be_bytes());
        expect.extend_from_slice(&CRLF);
        expect.push(b'z');
        assert_eq!(&got[..], &expect[..]);
    }

    /// The scratch frame buffer is reset per datagram: two sends produce
    /// two independent frames, never the second appended to the first.
    #[tokio::test]
    async fn packet_conn_send_reuses_scratch_per_datagram() {
        use tokio::io::AsyncReadExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        conn.send(None, b"one").await.unwrap();
        conn.send(Some("9.9.9.9:5353".parse().unwrap()), b"two")
            .await
            .unwrap();
        let mut got = [0u8; 2 * (7 + 2 + 2 + 3)];
        server.read_exact(&mut got).await.unwrap();
        let mut expect = vec![0x01, 1, 2, 3, 4, 0x00, 0x35]; // session target
        expect.extend_from_slice(&3u16.to_be_bytes());
        expect.extend_from_slice(&CRLF);
        expect.extend_from_slice(b"one");
        expect.extend_from_slice(&[0x01, 9, 9, 9, 9, 0x14, 0xe9]); // 9.9.9.9:5353
        expect.extend_from_slice(&3u16.to_be_bytes());
        expect.extend_from_slice(&CRLF);
        expect.extend_from_slice(b"two");
        assert_eq!(&got[..], &expect[..]);
    }

    /// sing-box maps a UDP reply's address back to the original FQDN by
    /// default for a domain destination (`route/conn.go`;
    /// `udp_disable_domain_unmapping` opts out), so a domain-addressed
    /// reply frame is ordinary traffic: the datagram is delivered with no
    /// per-packet address instead of killing the tunnel.
    #[tokio::test]
    async fn packet_conn_recv_domain_reply_has_no_address() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::Domain("example.com".into()), 443);
        let mut conn = PacketConn::new(client, &target).unwrap();
        let mut frame = vec![crate::addr::TROJAN_ATYP_DOMAIN, 11];
        frame.extend_from_slice(b"example.com");
        frame.extend_from_slice(&443u16.to_be_bytes());
        frame.extend_from_slice(&2u16.to_be_bytes());
        frame.extend_from_slice(&CRLF);
        frame.extend_from_slice(b"ok");
        server.write_all(&frame).await.unwrap();
        let (dest, payload) = conn.recv().await.unwrap().expect("a datagram");
        assert_eq!(dest, None);
        assert_eq!(payload, b"ok");
    }

    /// The payload read is length-exact: a frame that promises 5 bytes and
    /// delivers 3 is `UnexpectedEof`, never a short datagram. A single
    /// `read` here would hand back `abc` and desynchronize every later
    /// frame.
    #[tokio::test]
    async fn packet_conn_recv_short_payload_is_error() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        let mut frame = vec![0x01, 8, 8, 8, 8, 0x00, 0x35];
        frame.extend_from_slice(&5u16.to_be_bytes()); // promises 5
        frame.extend_from_slice(&CRLF);
        frame.extend_from_slice(b"abc"); // delivers 3
        server.write_all(&frame).await.unwrap();
        drop(server); // no more bytes are coming
        let err = conn.recv().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// One datagram split across two writer flights is still one datagram:
    /// the reader accumulates to the frame length instead of returning the
    /// first flight.
    #[tokio::test]
    async fn packet_conn_recv_reassembles_split_payload() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        let mut first = vec![0x01, 8, 8, 8, 8, 0x00, 0x35];
        first.extend_from_slice(&6u16.to_be_bytes());
        first.extend_from_slice(&CRLF);
        first.extend_from_slice(b"abc"); // half the payload
        // The reader blocks on the rest before the second flight lands.
        let (received, ()) = tokio::join!(conn.recv(), async {
            server.write_all(&first).await.unwrap();
            tokio::task::yield_now().await;
            server.write_all(b"def").await.unwrap();
        });
        let (dest, payload) = received.unwrap().expect("a datagram");
        assert_eq!(dest, Some("8.8.8.8:53".parse().unwrap()));
        assert_eq!(payload, b"abcdef");
    }

    /// A separator that is not CRLF is malformed data, not a short read.
    #[tokio::test]
    async fn packet_conn_recv_bad_crlf_is_invalid_data() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        let mut frame = vec![0x01, 8, 8, 8, 8, 0x00, 0x35];
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&[0x0d, 0x00]); // CR without LF
        frame.push(b'x');
        server.write_all(&frame).await.unwrap();
        drop(server);
        let err = conn.recv().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// `ADDR_TYPE_DOMAIN` (0x02) is the VLESS/VMess family byte, not one of
    /// trojan's SOCKS5 set: an unknown ATYP is rejected, never parsed as an
    /// address.
    #[tokio::test]
    async fn packet_conn_recv_unknown_atyp_is_invalid_data() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::new(Host::new("1.2.3.4"), 53);
        let mut conn = PacketConn::new(client, &target).unwrap();
        let frame = [
            crate::addr::ADDR_TYPE_DOMAIN,
            4,
            b'x',
            b'.',
            b'i',
            b'o',
            0,
            9,
        ];
        server.write_all(&frame).await.unwrap();
        drop(server); // a reader that keeps reading fails, never hangs
        let err = conn.recv().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// `addr || len(2B BE) || CRLF || payload` — one wire frame, the shape
    /// both directions use; the fake peer builds its replies with it and
    /// the split tests build their expectations with it.
    fn push_frame(out: &mut Vec<u8>, addr: &[u8], payload: &[u8]) {
        out.extend_from_slice(addr);
        out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&CRLF);
        out.extend_from_slice(payload);
    }

    /// The session target of every split test — `1.2.3.4:53`.
    fn split_target() -> TargetAddr {
        TargetAddr::new(Host::new("1.2.3.4"), 53)
    }

    /// [`split_target`] in port-last wire form: the frame address a
    /// `send(None, ..)` emits.
    const SESSION_WIRE: [u8; 7] = [0x01, 1, 2, 3, 4, 0x00, 0x35];

    /// An IPv4 reply address on the wire — `8.8.8.8:53`.
    const REPLY_V4_WIRE: [u8; 7] = [0x01, 8, 8, 8, 8, 0x00, 0x35];

    /// The datagrams the round-trip tests send: the session default, a
    /// per-packet IPv4 destination, and a per-packet IPv6 one.
    fn outbound_script() -> [(Option<std::net::SocketAddr>, &'static [u8]); 3] {
        [
            (None, b"one".as_slice()),
            (Some("9.9.9.9:5353".parse().unwrap()), b"two".as_slice()),
            (
                Some("[2001:db8::1]:443".parse().unwrap()),
                b"three".as_slice(),
            ),
        ]
    }

    /// The exact wire bytes [`outbound_script`] must produce.
    fn expected_outbound_wire() -> Vec<u8> {
        let mut wire = Vec::new();
        push_frame(&mut wire, &SESSION_WIRE, b"one");
        push_frame(&mut wire, &[0x01, 9, 9, 9, 9, 0x14, 0xe9], b"two"); // 9.9.9.9:5353
        let ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut v6 = vec![crate::addr::TROJAN_ATYP_IPV6];
        v6.extend_from_slice(&ip.octets());
        v6.extend_from_slice(&443u16.to_be_bytes());
        push_frame(&mut wire, &v6, b"three");
        wire
    }

    /// The frames the fake peer feeds back: an IPv4 reply, an IPv6 reply,
    /// and a domain-addressed reply — the form that carries no
    /// `SocketAddr`.
    fn inbound_frames() -> Vec<u8> {
        let mut wire = Vec::new();
        push_frame(&mut wire, &REPLY_V4_WIRE, b"a4");
        let ip: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut v6 = vec![crate::addr::TROJAN_ATYP_IPV6];
        v6.extend_from_slice(&ip.octets());
        v6.extend_from_slice(&53u16.to_be_bytes());
        push_frame(&mut wire, &v6, b"a6");
        let mut dom = vec![crate::addr::TROJAN_ATYP_DOMAIN, 11];
        dom.extend_from_slice(b"example.com");
        dom.extend_from_slice(&443u16.to_be_bytes());
        push_frame(&mut wire, &dom, b"ad");
        wire
    }

    /// What [`inbound_frames`] must decode to — the domain-addressed frame
    /// last, with no per-packet address.
    fn expected_inbound() -> Vec<(Option<std::net::SocketAddr>, Vec<u8>)> {
        vec![
            (Some("8.8.8.8:53".parse().unwrap()), b"a4".to_vec()),
            (Some("[2001:db8::2]:53".parse().unwrap()), b"a6".to_vec()),
            (None, b"ad".to_vec()),
        ]
    }

    /// Drive the script through the unsplit `PacketConn` — the reference
    /// the split halves must match byte for byte and value for value.
    /// Returns (wire the peer saw, datagrams the client received).
    async fn drive_unsplit() -> (Vec<u8>, Vec<(Option<std::net::SocketAddr>, Vec<u8>)>) {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut conn = PacketConn::new(client, &split_target()).unwrap();
        server.write_all(&inbound_frames()).await.unwrap();
        for (dest, payload) in outbound_script() {
            conn.send(dest, payload).await.unwrap();
        }
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(conn.recv().await.unwrap().expect("a datagram"));
        }
        drop(conn); // EOF, so the peer's read_to_end returns the whole wire
        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        (wire, got)
    }

    /// The same script through a [`PacketConn::split`] pair.
    async fn drive_split() -> (Vec<u8>, Vec<(Option<std::net::SocketAddr>, Vec<u8>)>) {
        let (client, mut server) = tokio::io::duplex(4096);
        let (mut reader, mut writer) = PacketConn::new(client, &split_target())
            .unwrap()
            .split()
            .unwrap();
        server.write_all(&inbound_frames()).await.unwrap();
        for (dest, payload) in outbound_script() {
            writer.send(dest, payload).await.unwrap();
        }
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(reader.recv().await.unwrap().expect("a datagram"));
        }
        // The halves jointly own the stream: it closes when both are gone.
        drop(reader);
        drop(writer);
        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        (wire, got)
    }

    /// A split pair is the same carrier as the unsplit `PacketConn`: the
    /// same wire bytes out (session default, per-packet IPv4, per-packet
    /// IPv6) and the same datagrams in (IPv4, IPv6, and a domain-addressed
    /// frame that yields no `SocketAddr`).
    #[tokio::test]
    async fn split_round_trips_like_unsplit() {
        let (unsplit_wire, unsplit_recv) = drive_unsplit().await;
        let (split_wire, split_recv) = drive_split().await;
        assert_eq!(split_wire, unsplit_wire);
        assert_eq!(split_recv, unsplit_recv);
        // …and both are what the protocol calls for, not two copies of one
        // bug.
        assert_eq!(split_wire, expected_outbound_wire());
        assert_eq!(split_recv, expected_inbound());
    }

    /// The case the unsplit tunnel could not serve: a `recv` future is
    /// already parked in its own task when a datagram goes out on the
    /// writer. Both complete — no `select!`, so no cancelled read.
    #[tokio::test]
    async fn split_write_during_pending_recv() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (mut reader, mut writer) = PacketConn::new(client, &split_target())
            .unwrap()
            .split()
            .unwrap();
        // The reader parks on an empty stream in a separate task.
        let reading = tokio::spawn(async move { reader.recv().await });
        tokio::task::yield_now().await;
        // The write half is unaffected by the parked read.
        writer.send(None, b"ping").await.unwrap();
        let mut request = vec![0u8; SESSION_WIRE.len() + 2 + 2 + 4];
        server.read_exact(&mut request).await.unwrap();
        let mut expect = Vec::new();
        push_frame(&mut expect, &SESSION_WIRE, b"ping");
        assert_eq!(request, expect);
        // The still-parked reader then takes the reply.
        let mut reply = Vec::new();
        push_frame(&mut reply, &REPLY_V4_WIRE, b"pong");
        server.write_all(&reply).await.unwrap();
        let (dest, payload) = reading.await.unwrap().unwrap().expect("a datagram");
        assert_eq!(dest, Some("8.8.8.8:53".parse().unwrap()));
        assert_eq!(payload, b"pong");
    }

    /// A reader half cancelled mid-payload keeps the bytes it already took
    /// off the stream: the partial frame lives in the reader, not in the
    /// `recv` future. This is the desynchronization the split exists to
    /// prevent — a `read_exact`-into-locals reader would drop the head and
    /// the first three payload bytes here.
    #[tokio::test]
    async fn split_recv_resumes_after_cancellation_mid_payload() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (mut reader, _writer) = PacketConn::new(client, &split_target())
            .unwrap()
            .split()
            .unwrap();
        // First flight: the whole head plus half of a 6-byte payload.
        let mut first = REPLY_V4_WIRE.to_vec();
        first.extend_from_slice(&6u16.to_be_bytes());
        first.extend_from_slice(&CRLF);
        first.extend_from_slice(b"abc");
        server.write_all(&first).await.unwrap();
        // Poll `recv` exactly once, then drop it: it consumes the flight
        // and parks on the rest of the payload.
        tokio::select! {
            biased;
            got = reader.recv() => panic!("recv completed mid-frame: {got:?}"),
            () = std::future::ready(()) => {}
        }
        // The cancelled poll took the whole flight off the stream, and it
        // is in the READER: the head (addr + len + CRLF) plus three
        // payload bytes. Nothing can put those bytes back, which is why
        // the old `read_exact`-into-locals reader desynchronized here.
        assert_eq!(reader.state.head_filled, REPLY_V4_WIRE.len() + 4);
        assert_eq!(reader.state.payload_filled, 3);
        server.write_all(b"def").await.unwrap();
        let (dest, payload) = reader.recv().await.unwrap().expect("a datagram");
        assert_eq!(dest, Some("8.8.8.8:53".parse().unwrap()));
        assert_eq!(payload, b"abcdef", "a cancelled recv must not lose bytes");
    }

    /// Cancellation part-way through the *address* resumes too — the
    /// nastiest case, because the ATYP byte a cancelled call took cannot be
    /// re-read: it has to still be in the reader. Proven on the combined
    /// `PacketConn`, which carries the same read state as the split half.
    #[tokio::test]
    async fn packet_conn_recv_resumes_after_cancellation_mid_address() {
        let (client, mut server) = tokio::io::duplex(1024);
        let mut conn = PacketConn::new(client, &split_target()).unwrap();
        server.write_all(&REPLY_V4_WIRE[..3]).await.unwrap(); // ATYP + 2 addr bytes
        tokio::select! {
            biased;
            got = conn.recv() => panic!("recv completed mid-address: {got:?}"),
            () = std::future::ready(()) => {}
        }
        // The three bytes are buffered in the connection, not lost with
        // the dropped future.
        assert_eq!(conn.read.head_filled, 3);
        let mut rest = REPLY_V4_WIRE[3..].to_vec();
        rest.extend_from_slice(&2u16.to_be_bytes());
        rest.extend_from_slice(&CRLF);
        rest.extend_from_slice(b"hi");
        server.write_all(&rest).await.unwrap();
        let (dest, payload) = conn.recv().await.unwrap().expect("a datagram");
        assert_eq!(dest, Some("8.8.8.8:53".parse().unwrap()));
        assert_eq!(payload, b"hi");
    }

    /// The reader half reports a clean end-of-stream as `Ok(None)` at a
    /// frame boundary, exactly like [`PacketConn::recv`].
    #[tokio::test]
    async fn split_recv_clean_eof_is_none() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (mut reader, _writer) = PacketConn::new(client, &split_target())
            .unwrap()
            .split()
            .unwrap();
        let mut frame = Vec::new();
        push_frame(&mut frame, &REPLY_V4_WIRE, b"last");
        server.write_all(&frame).await.unwrap();
        drop(server);
        let (dest, payload) = reader.recv().await.unwrap().expect("a datagram");
        assert_eq!(dest, Some("8.8.8.8:53".parse().unwrap()));
        assert_eq!(payload, b"last");
        assert!(
            reader.recv().await.unwrap().is_none(),
            "clean EOF at a frame boundary"
        );
    }

    /// A stream that dies mid-frame is the same error the
    /// `read_exact`-based reader produced, message included: the
    /// accumulating reader did not change the error surface.
    #[tokio::test]
    async fn split_recv_truncated_frame_is_early_eof() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (mut reader, _writer) = PacketConn::new(client, &split_target())
            .unwrap()
            .split()
            .unwrap();
        server.write_all(&REPLY_V4_WIRE[..3]).await.unwrap();
        drop(server);
        let err = reader.recv().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(err.to_string(), "early eof");
    }

    /// The writer half keeps the writer's guard rail: an oversize payload
    /// is rejected with the identical error and nothing reaches the wire,
    /// so the next datagram is the first thing the peer sees.
    #[tokio::test]
    async fn split_send_oversized_rejected_before_writing() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (_reader, mut writer) = PacketConn::new(client, &split_target())
            .unwrap()
            .split()
            .unwrap();
        let big = vec![0u8; MAX_UDP_PAYLOAD + 1];
        let err = writer.send(None, &big).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            err.to_string(),
            format!(
                "trojan udp datagram too large ({}, max {MAX_UDP_PAYLOAD})",
                MAX_UDP_PAYLOAD + 1
            )
        );
        writer.send(None, b"ok").await.unwrap();
        let mut got = vec![0u8; SESSION_WIRE.len() + 2 + 2 + 2];
        server.read_exact(&mut got).await.unwrap();
        let mut expect = Vec::new();
        push_frame(&mut expect, &SESSION_WIRE, b"ok");
        assert_eq!(got, expect);
    }
}
