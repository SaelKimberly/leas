//! VLESS UDP `PacketConn`: the tunnel byte stream wrapped in `[2B BE len]`
//! datagram framing (spec §4.2), with the packetaddr destination codec
//! (§4.3) folded in per mode.
//!
//! Each direction is its own state machine over a transport passed in per
//! call — [`ReadState`] (mode + response-header peel + frame reader) and
//! [`WriteState`] (mode + header destination) — so the combined
//! [`PacketConn`] and the split [`PacketReader`] / [`PacketWriter`] halves
//! run the exact same code, one implementation per direction.

use std::io;
use std::net::SocketAddr;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

use crate::addr::{Host, TargetAddr};
use crate::protocol::vless::packetaddr;
use crate::protocol::vless::stream::Peel;
use crate::protocol::vless::udp::{FrameReader, write_packet};
use crate::transport::mux::UdpSession;

/// Maximum frame payload: the 2-byte length field is u16.
const MAX_FRAME: usize = 65_535;

/// Datagram mode: `Raw` (header-dest, xray-style), `PacketAddr`
/// (per-packet address header `atyp|addr|port`, sing-box-style; spec §4.3),
/// or `XUdp` (datagrams over a mux UDP session — spec §4.1).
///
/// The packetaddr magic fqdn appears only in the header dest, never in the
/// per-packet frame. `XUdp` is not constructible via [`PacketConn::new`]
/// (a stream cannot carry it) — use [`PacketConn::xudp`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketMode {
    Raw,
    PacketAddr,
    XUdp,
}

/// A VLESS UDP connection.
///
/// Datagrams ride `[2B BE len][payload]` frames over the tunnel stream
/// (Raw / `PacketAddr`), or delegate entirely to a mux UDP session
/// (`XUdp` — the mux frames carry the length and the per-packet
/// destination).
///
/// The stream modes own the response-header peel: the server sends
/// `[0x00, 0x00]` before the first downlink frame (spec §4.4), consumed on
/// the first `recv`. `XUdp` needs no peel — the mux tunnel's connect
/// already consumed the header before the session opened.
///
/// Owns its carrier directly: a combined `send`/`recv` never pays for a
/// lock. [`PacketConn::split`] hands the two directions to separate tasks
/// when a caller needs them concurrently.
pub struct PacketConn<S> {
    inner: PacketInner<S>,
    read: ReadState,
    write: WriteState,
}

/// The datagram carrier, selected by the mode: the tunnel byte stream
/// (Raw / `PacketAddr`) or the mux UDP session (`XUdp`).
enum PacketInner<S> {
    Stream(S),
    XUdp(UdpSession),
}

impl<S> PacketInner<S> {
    /// The tunnel stream in the Raw / `PacketAddr` modes — an error in
    /// `XUdp` mode (the state invariant: `XUdp` always carries a
    /// [`UdpSession`], built by [`PacketConn::xudp`]).
    fn stream_mut(&mut self) -> io::Result<&mut S> {
        match self {
            Self::Stream(stream) => Ok(stream),
            Self::XUdp(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vless packet conn: stream modes require a tunnel stream",
            )),
        }
    }

    /// The mux UDP session in `XUdp` mode — an error in the stream modes.
    fn session_mut(&mut self) -> io::Result<&mut UdpSession> {
        match self {
            Self::XUdp(session) => Ok(session),
            Self::Stream(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vless packet conn: XUdp mode requires a UdpSession",
            )),
        }
    }
}

/// The datagram READ direction over a stream carrier: the mode, the
/// response-header peel (spec §4.4) and the resumable frame reader. The
/// transport is a per-call parameter, so [`PacketConn::recv`] and
/// [`PacketReader::recv`] share this one implementation.
struct ReadState {
    mode: PacketMode,
    peel: Peel,
    frames: FrameReader,
}

/// The datagram WRITE direction over a stream carrier: the mode and the
/// request-header destination. Shared by [`PacketConn::send`] and
/// [`PacketWriter::send`].
struct WriteState {
    mode: PacketMode,
    /// The request-header destination in comparable form: `Some(addr)` when
    /// the header carried an IP destination. In `Raw` mode that is the ONLY
    /// place a datagram can land (the frame carries no address), so a `send`
    /// naming a different one is refused instead of silently mis-routed.
    /// `None` when the header destination has no `SocketAddr` form (a domain
    /// target, the packetaddr magic fqdn) or does not exist at all (`XUdp` —
    /// the mux command carries no destination).
    header_dest: Option<SocketAddr>,
}

impl ReadState {
    fn new(mode: PacketMode) -> Self {
        Self {
            mode,
            peel: Peel::new(),
            frames: FrameReader::new(),
        }
    }

    /// Receives one datagram from a stream carrier.
    ///
    /// The response-header peel runs before the first frame read. Returns
    /// `Ok(None)` on a clean EOF at a frame boundary. Raw:
    /// `(None, payload)`. `PacketAddr`: `(Some(dest), payload)` after
    /// validating the address family (atyp) — a malformed destination
    /// header is an error, never delivered as garbage.
    ///
    /// Cancel-safe: every consumed byte is accounted for in `self` (the
    /// peel's own state machine, the frame reader's partial length and
    /// payload), so a dropped future loses nothing and the next call
    /// resumes the same datagram.
    async fn recv_from<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> io::Result<Option<(Option<SocketAddr>, Bytes)>> {
        if !self.peel.is_peeled() {
            self.peel.ensure_peeled(r).await?;
        }
        // A non-vless first byte (REALITY transparent-proxy fallback) has
        // no valid UDP framing; error rather than drop or mis-deliver it.
        if self.peel.take_passthrough().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vless udp: non-vless response byte (REALITY fallback not supported for UDP)",
            ));
        }
        let Some(frame) = self.frames.read_frame(r).await? else {
            return Ok(None);
        };
        match self.mode {
            PacketMode::Raw => Ok(Some((None, frame))),
            PacketMode::PacketAddr => {
                let (dest, payload) = packetaddr::decode_dest(&frame)?;
                Ok(Some((Some(dest), Bytes::copy_from_slice(payload))))
            }
            PacketMode::XUdp => unreachable!("XUdp rides the mux session, not the frame codec"),
        }
    }
}

impl WriteState {
    const fn new(mode: PacketMode, header_dest: Option<SocketAddr>) -> Self {
        Self { mode, header_dest }
    }

    /// Sends one datagram over a stream carrier.
    ///
    /// Raw: one `[len][payload]` frame. The frame carries no address, so
    /// every datagram lands on the request-header destination: `None` names
    /// exactly that (the normal argument) and an explicit destination is
    /// accepted only when it IS the header destination, refused with
    /// `InvalidInput` otherwise (`check_raw_dest`) rather than mis-routed.
    ///
    /// `PacketAddr`: prepends the per-packet address header
    /// (`atyp|addr|port`, spec §4.3) — header and payload go in ONE frame,
    /// mirroring the sing encoder which writes `AddrPortLen + payload` in a
    /// single buffer; the destination is required and the combined length
    /// must fit a u16 frame. Oversized datagrams are rejected before any
    /// byte is written.
    async fn send_to<W: AsyncWrite + Unpin>(
        &self,
        w: &mut W,
        dest: Option<SocketAddr>,
        payload: &[u8],
    ) -> io::Result<()> {
        match self.mode {
            PacketMode::Raw => {
                self.check_raw_dest(dest)?;
                reject_oversized(payload.len())?;
                write_packet(w, payload).await
            }
            PacketMode::PacketAddr => {
                let dest = dest.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "vless packetaddr send requires a destination",
                    )
                })?;
                let encoded = packetaddr::encode_dest(dest);
                let total = encoded.len() + payload.len();
                reject_oversized(total)?;
                // No combined frame `Vec`: the stack prefix plus the address
                // header and payload go out as one vectored write.
                let n = u16::try_from(total).expect("rejected oversized above");
                let prefix = n.to_be_bytes();
                super::udp::write_all_vectored(w, &[&prefix, &encoded, payload]).await
            }
            PacketMode::XUdp => unreachable!("XUdp rides the mux session, not the frame codec"),
        }
    }

    /// Refuses a `Raw` datagram bound for anything but the request-header
    /// destination.
    ///
    /// `Raw` frames carry no address (spec §4.2), so the header destination
    /// is the only one reachable: `None` names it and always succeeds, and
    /// an explicit `Some(dest)` is accepted only when it IS that
    /// destination. A header destination with no `SocketAddr` form (a domain
    /// target) has nothing to compare against, so any explicit destination
    /// is refused — a visible `InvalidInput` beats a datagram silently
    /// delivered to the header destination instead.
    fn check_raw_dest(&self, dest: Option<SocketAddr>) -> io::Result<()> {
        let Some(dest) = dest else { return Ok(()) };
        if self.header_dest == Some(dest) {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "vless raw udp: destination {dest} is not the request-header destination (raw frames carry no per-packet address — use packetaddr or xudp for per-packet destinations)"
            ),
        ))
    }
}

/// The read half of a stream-mode [`PacketConn`], from
/// [`PacketConn::split`]: the read direction's state plus the tunnel's read
/// half.
///
/// Exists so a relay can own the frame reader in a dedicated task instead
/// of racing `recv` against other work in a `select!` — datagram reads are
/// cancel-safe either way ([`ReadState::recv_from`]), but a reader in its
/// own task is never cancelled at all.
pub struct PacketReader<R> {
    state: ReadState,
    inner: R,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    /// Receives one datagram — exactly what [`PacketConn::recv`] returns in
    /// a stream mode: the response-header peel before the first frame,
    /// `Ok(None)` on a clean end-of-stream, `(None, payload)` in Raw mode
    /// and the decoded per-packet address in `PacketAddr` mode.
    pub async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Bytes)>> {
        self.state.recv_from(&mut self.inner).await
    }
}

/// The write half of a stream-mode [`PacketConn`], from
/// [`PacketConn::split`]: the write direction's state (mode + request-header
/// destination) plus the tunnel's write half.
pub struct PacketWriter<W> {
    state: WriteState,
    inner: W,
}

impl<W: AsyncWrite + Unpin> PacketWriter<W> {
    /// Sends one datagram — exactly what [`PacketConn::send`] does in a
    /// stream mode: `dest: None` names the request-header destination, Raw
    /// refuses any other destination, `PacketAddr` requires one and encodes
    /// `atyp|addr|port` ahead of the payload in ONE frame, and an oversized
    /// datagram is refused before a byte reaches the wire.
    pub async fn send(&mut self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        self.state.send_to(&mut self.inner, dest, payload).await
    }
}

/// The halves [`PacketConn::split`] yields: the reader over the tunnel's
/// read half, the writer over its write half.
pub type SplitHalves<S> = (PacketReader<ReadHalf<S>>, PacketWriter<WriteHalf<S>>);

impl<S: AsyncRead + AsyncWrite + Unpin> PacketConn<S> {
    /// Wraps a tunnel stream in datagram framing for the given mode
    /// (`Raw` or `PacketAddr`). `header_dest` is the destination just
    /// written in the request header — in `Raw` mode the only destination
    /// the tunnel can reach. `XUdp` mode is not constructible here — the
    /// `XUdp` carrier is a [`UdpSession`], use [`PacketConn::xudp`].
    pub fn new(inner: S, mode: PacketMode, header_dest: &TargetAddr) -> Self {
        debug_assert!(
            !matches!(mode, PacketMode::XUdp),
            "vless: XUdp mode requires PacketConn::xudp (a UdpSession)"
        );
        Self {
            inner: PacketInner::Stream(inner),
            read: ReadState::new(mode),
            write: WriteState::new(
                mode,
                match &header_dest.host {
                    Host::Ip(ip) => Some(SocketAddr::new(*ip, header_dest.port)),
                    Host::Domain(_) => None,
                },
            ),
        }
    }

    /// Wraps a mux UDP session in the `XUdp` datagram API: `send`/`recv`
    /// delegate to the session — no 2-byte framing, the mux frames carry
    /// the length and the per-packet destination (spec §4.1, §5.2). The mux
    /// command carries no header destination, so there is none to keep.
    pub(crate) fn xudp(session: UdpSession) -> Self {
        Self {
            inner: PacketInner::XUdp(session),
            read: ReadState::new(PacketMode::XUdp),
            write: WriteState::new(PacketMode::XUdp, None),
        }
    }

    /// Sends one datagram.
    ///
    /// The stream modes (Raw / `PacketAddr`) run [`WriteState::send_to`] —
    /// the same body [`PacketWriter::send`] runs.
    ///
    /// `XUdp`: `session.send_to(dest, payload)` — the destination is
    /// required (the mux frame carries it per packet).
    pub async fn send(&mut self, target: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        // XUdp delegates entirely to the mux UDP session.
        if self.write.mode == PacketMode::XUdp {
            let target = target.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vless xudp send requires a destination",
                )
            })?;
            return self.inner.session_mut()?.send_to(target, payload).await;
        }
        let Self { inner, write, .. } = self;
        write.send_to(inner.stream_mut()?, target, payload).await
    }

    /// Receives one datagram.
    ///
    /// The stream modes run [`ReadState::recv_from`] — the same body
    /// [`PacketReader::recv`] runs: the response-header peel before the
    /// first frame, `Ok(None)` on a clean EOF at a frame boundary, Raw
    /// `(None, payload)`, `PacketAddr` the validated per-packet address.
    /// `XUdp`: `session.recv_from()` → `(Some(dest), payload)` — the
    /// destination the server dispatched the packet to.
    pub async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Bytes)>> {
        // XUdp delegates entirely to the mux UDP session.
        if self.read.mode == PacketMode::XUdp {
            let session = self.inner.session_mut()?;
            return Ok(session
                .recv_from()
                .await?
                .map(|(dest, payload)| (Some(dest), payload)));
        }
        let Self { inner, read, .. } = self;
        read.recv_from(inner.stream_mut()?).await
    }

    /// Splits the connection into halves usable concurrently from separate
    /// tasks: the reader keeps the peel + frame state over the tunnel's read
    /// half, the writer keeps the mode + header destination over the write
    /// half. Both behave exactly like the combined [`PacketConn::recv`] /
    /// [`PacketConn::send`] — same code, same wire, same errors.
    ///
    /// Only the stream modes split. `XUdp`'s carrier is a mux
    /// [`UdpSession`], not a byte stream, so there are no halves to hand
    /// out: `InvalidInput`. `split` consumes the connection either way — a
    /// refused `XUdp` split drops the session (its clean close).
    pub fn split(self) -> io::Result<SplitHalves<S>> {
        match self.inner {
            PacketInner::Stream(stream) => {
                let (r, w) = tokio::io::split(stream);
                Ok((
                    PacketReader {
                        state: self.read,
                        inner: r,
                    },
                    PacketWriter {
                        state: self.write,
                        inner: w,
                    },
                ))
            }
            PacketInner::XUdp(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vless xudp packet conn cannot be split: the mux XUDP session carries both directions over the shared mux tunnel, not a stream with halves (only the Raw / PacketAddr stream modes split)",
            )),
        }
    }
}

/// Rejects a frame payload that does not fit the 2-byte length field.
fn reject_oversized(total: usize) -> io::Result<()> {
    if total > MAX_FRAME {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("vless udp datagram too large ({total} bytes, max {MAX_FRAME})"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::vless::MuxTarget;
    use crate::protocol::vless::udp::read_packet;
    use crate::transport::mux::{
        Frame, MuxClient, OPT_DATA, STATUS_END, STATUS_KEEP, STATUS_NEW, read_frame, write_frame,
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The request-header destination the stream-mode tests wrap: an IP
    /// literal, so `Raw` can compare an explicit destination against it.
    fn header_dest() -> TargetAddr {
        TargetAddr::new(Host::new("1.2.3.4"), 53)
    }

    #[tokio::test]
    async fn raw_send_recv() {
        let (client, mut server) = tokio::io::duplex(1024);
        let mut conn = PacketConn::new(client, PacketMode::Raw, &header_dest());

        // send(b"hi") → peer sees the exact frame [0x00,0x02,'h','i'].
        conn.send(None, b"hi").await.unwrap();
        let mut wire = [0u8; 4];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire, [0x00, 0x02, b'h', b'i']);

        // Peer replies with the response header then a frame.
        server.write_all(&[0x00, 0x00]).await.unwrap();
        write_packet(&mut server, b"yo").await.unwrap();

        let (dest, payload) = conn.recv().await.unwrap().unwrap();
        assert_eq!(dest, None);
        assert_eq!(&payload[..], b"yo");
    }

    #[tokio::test]
    async fn packetaddr_send_recv() {
        let (client, mut server) = tokio::io::duplex(1024);
        let mut conn = PacketConn::new(client, PacketMode::PacketAddr, &header_dest());

        // send(Some(127.0.0.1:8080), b"p") → atyp(0x01) + addr + port + 'p'
        // (the per-packet address header; no magic in the frame).
        let target = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
        conn.send(Some(target), b"p").await.unwrap();
        let frame = read_packet(&mut server).await.unwrap().unwrap();
        let mut expected = packetaddr::encode_dest(target);
        expected.push(b'p');
        assert_eq!(frame, expected);

        // Peer replies with a packetaddr address-header frame for a
        // different dest.
        let reply_dest = "[::1]:53".parse::<SocketAddr>().unwrap();
        server.write_all(&[0x00, 0x00]).await.unwrap();
        let mut reply = packetaddr::encode_dest(reply_dest);
        reply.extend_from_slice(b"ok");
        write_packet(&mut server, &reply).await.unwrap();

        let (dest, payload) = conn.recv().await.unwrap().unwrap();
        assert_eq!(dest, Some(reply_dest));
        assert_eq!(&payload[..], b"ok");
    }

    #[tokio::test]
    async fn peel_before_first_recv() {
        // Peer sends [0,0] (response header) then frames: the first recv()
        // consumes the header, both recvs return the frame payloads.
        let (client, mut server) = tokio::io::duplex(1024);
        let mut conn = PacketConn::new(client, PacketMode::Raw, &header_dest());

        server.write_all(&[0x00, 0x00]).await.unwrap();
        write_packet(&mut server, b"first").await.unwrap();
        write_packet(&mut server, b"second").await.unwrap();

        let (dest, payload) = conn.recv().await.unwrap().unwrap();
        assert_eq!(dest, None);
        assert_eq!(&payload[..], b"first");
        let (_, payload) = conn.recv().await.unwrap().unwrap();
        assert_eq!(&payload[..], b"second");
    }

    #[tokio::test]
    async fn eof_returns_none() {
        // Peer sends the response header, then closes at a frame boundary.
        let (client, server) = tokio::io::duplex(1024);
        let mut conn = PacketConn::new(client, PacketMode::Raw, &header_dest());
        let mut server = server;
        server.write_all(&[0x00, 0x00]).await.unwrap();
        drop(server);

        assert!(conn.recv().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_send_is_error() {
        // 70000-byte datagram: rejected in both modes before any write.
        let big = vec![0u8; 70_000];

        let (client, mut server) = tokio::io::duplex(65536);
        let mut raw = PacketConn::new(client, PacketMode::Raw, &header_dest());
        let err = raw.send(None, &big).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        drop(raw);
        // No partial frame reached the peer.
        assert!(read_packet(&mut server).await.unwrap().is_none());

        let (client, mut server) = tokio::io::duplex(65536);
        let mut addr = PacketConn::new(client, PacketMode::PacketAddr, &header_dest());
        let err = addr
            .send(Some("127.0.0.1:1".parse().unwrap()), &big)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        drop(addr);
        assert!(read_packet(&mut server).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn packetaddr_send_requires_dest() {
        // PacketAddr mode needs a per-datagram destination (spec §4.3);
        // send(None) must fail before any byte is written.
        let (client, mut server) = tokio::io::duplex(1024);
        let mut conn = PacketConn::new(client, PacketMode::PacketAddr, &header_dest());

        let err = conn.send(None, b"p").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        drop(conn);
        // No partial frame reached the peer.
        assert!(read_packet(&mut server).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn max_frame_boundary() {
        // The 2-byte length field caps a frame at 65535 payload bytes: that
        // exact size is accepted and delivered; 65536 is rejected before
        // any write.
        let (client, mut server) = tokio::io::duplex(1 << 17);
        let mut conn = PacketConn::new(client, PacketMode::Raw, &header_dest());

        let max = vec![0u8; MAX_FRAME];
        conn.send(None, &max).await.unwrap();
        let frame = read_packet(&mut server).await.unwrap().unwrap();
        assert_eq!(frame, max);

        let over = vec![0u8; MAX_FRAME + 1];
        let err = conn.send(None, &over).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        drop(conn);
        // Nothing more reached the peer.
        assert!(read_packet(&mut server).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn xudp_send_recv_roundtrip() {
        // PacketConn in XUdp mode over a real UdpSession (a MuxClient over
        // a duplex): send(dest, payload) → the New frame (network UDP +
        // dest + GlobalID + payload, no 2-byte framing — the mux frames
        // carry the length); the peer's Keep reply with a per-packet dest
        // → recv() returns (Some(dest), payload).
        let (client, mut server) = tokio::io::duplex(1024);
        let mux = MuxClient::new(client);
        let session = mux.open_udp_session([0xAA; 8]).unwrap();
        // XUdp holds no stream, so S is unconstrained — pin it for the
        // test (production pins it via connect_udp's return type).
        let mut conn: PacketConn<crate::BoxStream> = PacketConn::xudp(session);

        let dest: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        conn.send(Some(dest), b"hi").await.unwrap();
        let frame = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(frame.status, STATUS_NEW);
        assert_eq!(frame.target, Some(MuxTarget::Udp(dest)));
        assert_eq!(frame.global_id, Some([0xAA; 8]));
        assert_eq!(frame.payload.as_ref(), b"hi");

        // The peer replies with a Keep data frame carrying a per-packet dest.
        let reply_dest: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        write_frame(
            &mut server,
            &Frame {
                session_id: 1,
                status: STATUS_KEEP,
                option: OPT_DATA,
                target: Some(MuxTarget::Udp(reply_dest)),
                global_id: None,
                payload: bytes::Bytes::from_static(b"yo"),
            },
        )
        .await
        .unwrap();

        let (dest, payload) = conn.recv().await.unwrap().unwrap();
        assert_eq!(dest, Some(reply_dest));
        assert_eq!(&payload[..], b"yo");
    }

    #[tokio::test]
    async fn xudp_send_requires_dest() {
        // XUdp sends carry the destination per datagram (the mux frame's
        // per-packet dest); send(None) must fail before any frame is queued.
        let (client, mut server) = tokio::io::duplex(1024);
        let mux = MuxClient::new(client);
        let session = mux.open_udp_session([0xAA; 8]).unwrap();
        let mut conn: PacketConn<crate::BoxStream> = PacketConn::xudp(session);

        let err = conn.send(None, b"p").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        drop(conn);
        // The failed send queued nothing (no eager New frame); dropping
        // the session fires the clean close — the peer sees only the End.
        let frame = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(frame.status, STATUS_END);
        assert_eq!(frame.payload.as_ref(), b"");
    }

    #[tokio::test]
    async fn raw_send_refuses_a_foreign_destination() {
        // Raw frames carry no address: every datagram lands on the
        // request-header destination. None names it, an equal explicit
        // destination is accepted, a different one is refused — otherwise
        // the datagram would silently reach the header destination instead.
        let (client, mut server) = tokio::io::duplex(1024);
        let dest: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let mut conn = PacketConn::new(client, PacketMode::Raw, &header_dest());

        conn.send(None, b"a").await.unwrap();
        conn.send(Some(dest), b"b").await.unwrap();
        let err = conn
            .send(Some("9.9.9.9:53".parse().unwrap()), b"c")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // A same-address, different-port destination is foreign too.
        let err = conn
            .send(Some("1.2.3.4:54".parse().unwrap()), b"c")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Both accepted sends are on the wire; the refused ones wrote nothing.
        assert_eq!(
            read_packet(&mut server).await.unwrap().unwrap(),
            Bytes::from_static(b"a")
        );
        assert_eq!(
            read_packet(&mut server).await.unwrap().unwrap(),
            Bytes::from_static(b"b")
        );
        drop(conn);
        assert!(read_packet(&mut server).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn raw_send_with_a_domain_header_dest_refuses_any_destination() {
        // A domain header destination has no SocketAddr form, so nothing an
        // explicit destination could match: None still works, Some cannot.
        let (client, mut server) = tokio::io::duplex(1024);
        let mut conn = PacketConn::new(
            client,
            PacketMode::Raw,
            &TargetAddr::new(Host::Domain("dns.example".into()), 53),
        );

        conn.send(None, b"a").await.unwrap();
        let err = conn
            .send(Some("1.2.3.4:53".parse().unwrap()), b"b")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        assert_eq!(
            read_packet(&mut server).await.unwrap().unwrap(),
            Bytes::from_static(b"a")
        );
        drop(conn);
        assert!(read_packet(&mut server).await.unwrap().is_none());
    }

    /// The stream-mode halves over a duplex peer: `(reader, writer, peer)`.
    /// The peer is the fake server — it reads what the writer sends and
    /// writes what the reader receives.
    type Halves = (
        PacketReader<ReadHalf<tokio::io::DuplexStream>>,
        PacketWriter<WriteHalf<tokio::io::DuplexStream>>,
        tokio::io::DuplexStream,
    );

    /// A [`PacketConn`] over a duplex, split into its halves.
    fn split_pair(mode: PacketMode, capacity: usize) -> Halves {
        let (client, server) = tokio::io::duplex(capacity);
        let (reader, writer) = PacketConn::new(client, mode, &header_dest())
            .split()
            .expect("the stream modes split");
        (reader, writer, server)
    }

    #[tokio::test]
    async fn split_raw_halves_match_the_unsplit_conn() {
        // Same wire in → same values out; same sends → same bytes out. The
        // halves are the combined conn's two directions, nothing else.
        const PAYLOADS: [&[u8]; 3] = [b"one", b"two", b"three"];

        let (client, mut server) = tokio::io::duplex(1024);
        let mut conn = PacketConn::new(client, PacketMode::Raw, &header_dest());
        server.write_all(&[0x00, 0x00]).await.unwrap();
        for p in PAYLOADS {
            write_packet(&mut server, p).await.unwrap();
        }
        let mut want = Vec::new();
        for _ in PAYLOADS {
            want.push(conn.recv().await.unwrap().unwrap());
        }
        for p in PAYLOADS {
            conn.send(None, p).await.unwrap();
        }
        let mut want_wire = Vec::new();
        for _ in PAYLOADS {
            want_wire.push(read_packet(&mut server).await.unwrap().unwrap());
        }

        let (mut reader, mut writer, mut peer) = split_pair(PacketMode::Raw, 1024);
        peer.write_all(&[0x00, 0x00]).await.unwrap();
        for p in PAYLOADS {
            write_packet(&mut peer, p).await.unwrap();
        }
        let mut got = Vec::new();
        for _ in PAYLOADS {
            got.push(reader.recv().await.unwrap().unwrap());
        }
        for p in PAYLOADS {
            writer.send(None, p).await.unwrap();
        }
        let mut got_wire = Vec::new();
        for _ in PAYLOADS {
            got_wire.push(read_packet(&mut peer).await.unwrap().unwrap());
        }

        // Raw yields no per-packet destination — in both shapes.
        assert_eq!(
            want,
            vec![
                (None, Bytes::from_static(b"one")),
                (None, Bytes::from_static(b"two")),
                (None, Bytes::from_static(b"three")),
            ]
        );
        assert_eq!(got, want);
        assert_eq!(got_wire, want_wire);
    }

    #[tokio::test]
    async fn split_packetaddr_halves_match_the_unsplit_conn() {
        // PacketAddr: the halves keep the per-packet address codec — the
        // decoded destinations and the encoded frames are the unsplit
        // conn's, byte for byte.
        let dests: [SocketAddr; 2] = [
            "127.0.0.1:8080".parse().unwrap(),
            "[::1]:53".parse().unwrap(),
        ];
        let reply = |dest: SocketAddr, payload: &[u8]| {
            let mut frame = packetaddr::encode_dest(dest);
            frame.extend_from_slice(payload);
            frame
        };

        let (client, mut server) = tokio::io::duplex(1024);
        let mut conn = PacketConn::new(client, PacketMode::PacketAddr, &header_dest());
        server.write_all(&[0x00, 0x00]).await.unwrap();
        for d in dests {
            write_packet(&mut server, &reply(d, b"in")).await.unwrap();
        }
        let mut want = Vec::new();
        for _ in dests {
            want.push(conn.recv().await.unwrap().unwrap());
        }
        for d in dests {
            conn.send(Some(d), b"out").await.unwrap();
        }
        let mut want_wire = Vec::new();
        for _ in dests {
            want_wire.push(read_packet(&mut server).await.unwrap().unwrap());
        }

        let (mut reader, mut writer, mut peer) = split_pair(PacketMode::PacketAddr, 1024);
        peer.write_all(&[0x00, 0x00]).await.unwrap();
        for d in dests {
            write_packet(&mut peer, &reply(d, b"in")).await.unwrap();
        }
        let mut got = Vec::new();
        for _ in dests {
            got.push(reader.recv().await.unwrap().unwrap());
        }
        for d in dests {
            writer.send(Some(d), b"out").await.unwrap();
        }
        let mut got_wire = Vec::new();
        for _ in dests {
            got_wire.push(read_packet(&mut peer).await.unwrap().unwrap());
        }

        assert_eq!(
            want,
            vec![
                (Some(dests[0]), Bytes::from_static(b"in")),
                (Some(dests[1]), Bytes::from_static(b"in")),
            ]
        );
        assert_eq!(got, want);
        assert_eq!(got_wire, want_wire);
    }

    #[tokio::test]
    async fn split_writer_keeps_the_raw_destination_and_size_guards() {
        // The write state moved into the half intact: None and the header
        // destination are accepted, a foreign one and an oversized datagram
        // are refused before a byte reaches the wire.
        let (reader, mut writer, mut peer) = split_pair(PacketMode::Raw, 1 << 17);

        writer.send(None, b"a").await.unwrap();
        writer
            .send(Some("1.2.3.4:53".parse().unwrap()), b"b")
            .await
            .unwrap();
        let err = writer
            .send(Some("9.9.9.9:53".parse().unwrap()), b"c")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = writer
            .send(None, &vec![0u8; MAX_FRAME + 1])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        assert_eq!(
            read_packet(&mut peer).await.unwrap().unwrap(),
            Bytes::from_static(b"a")
        );
        assert_eq!(
            read_packet(&mut peer).await.unwrap().unwrap(),
            Bytes::from_static(b"b")
        );
        // BOTH halves must go for the split stream to close (tokio::io::split
        // keeps the stream alive while either half lives).
        drop((reader, writer));
        assert!(read_packet(&mut peer).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn split_halves_run_concurrently() {
        // The case the unsplit conn cannot serve: a recv future already
        // pending in its own task while a send goes out on the same session.
        let (mut reader, mut writer, mut peer) = split_pair(PacketMode::Raw, 1024);
        peer.write_all(&[0x00, 0x00]).await.unwrap();

        let pending = tokio::spawn(async move { reader.recv().await });
        tokio::task::yield_now().await;
        assert!(
            !pending.is_finished(),
            "the reader must be parked on a frame"
        );

        writer.send(None, b"ping").await.unwrap();
        assert_eq!(
            read_packet(&mut peer).await.unwrap().unwrap(),
            Bytes::from_static(b"ping")
        );
        write_packet(&mut peer, b"pong").await.unwrap();

        let (dest, payload) = pending.await.unwrap().unwrap().unwrap();
        assert_eq!(dest, None);
        assert_eq!(&payload[..], b"pong");
    }

    #[tokio::test]
    async fn split_reader_resumes_a_cancelled_recv() {
        // Cancel-safety: the framing progress lives in the reader, not in
        // the recv future's locals. Poll a recv once against half a frame
        // (response header + length + one payload byte), DROP it, then recv
        // again — the whole datagram still arrives.
        let (mut reader, _writer, mut peer) = split_pair(PacketMode::Raw, 1024);
        peer.write_all(&[0x00, 0x00, 0x00, 0x05, b'h'])
            .await
            .unwrap();

        // `biased` polls the recv future FIRST: it consumes the peel and the
        // half frame, then parks. The ready branch then wins and drops it.
        tokio::select! {
            biased;
            got = reader.recv() => panic!("recv completed on half a frame: {got:?}"),
            () = std::future::ready(()) => {}
        }
        peer.write_all(b"ello").await.unwrap();

        let (dest, payload) = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("the resumed recv must not hang: the frame is complete")
            .unwrap()
            .unwrap();
        assert_eq!(dest, None);
        assert_eq!(&payload[..], b"hello");
    }

    #[tokio::test]
    async fn unsplit_recv_resumes_a_cancelled_recv() {
        // The combined conn runs the same read state, so it inherits the
        // cancel-safety: racing recv in a select! no longer eats a frame.
        let (client, mut server) = tokio::io::duplex(1024);
        let mut conn = PacketConn::new(client, PacketMode::Raw, &header_dest());
        server
            .write_all(&[0x00, 0x00, 0x00, 0x05, b'h'])
            .await
            .unwrap();

        tokio::select! {
            biased;
            got = conn.recv() => panic!("recv completed on half a frame: {got:?}"),
            () = std::future::ready(()) => {}
        }
        server.write_all(b"ello").await.unwrap();

        let (_, payload) = tokio::time::timeout(Duration::from_secs(5), conn.recv())
            .await
            .expect("the resumed recv must not hang: the frame is complete")
            .unwrap()
            .unwrap();
        assert_eq!(&payload[..], b"hello");
    }

    #[tokio::test]
    async fn split_reader_eof_at_a_frame_boundary_is_none() {
        // The peer closes after a whole frame: the frame is delivered, then
        // the clean end of the tunnel.
        let (mut reader, _writer, mut peer) = split_pair(PacketMode::Raw, 1024);
        peer.write_all(&[0x00, 0x00]).await.unwrap();
        write_packet(&mut peer, b"last").await.unwrap();
        drop(peer);

        let (dest, payload) = reader.recv().await.unwrap().unwrap();
        assert_eq!(dest, None);
        assert_eq!(&payload[..], b"last");
        assert!(reader.recv().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn xudp_conn_cannot_be_split() {
        // XUdp's carrier is a mux UDP session, not a byte stream: there are
        // no halves to hand out. split still consumes the conn, so the
        // session's clean close fires — the peer sees only the End frame.
        let (client, mut server) = tokio::io::duplex(1024);
        let mux = MuxClient::new(client);
        let session = mux.open_udp_session([0xAA; 8]).unwrap();
        let conn: PacketConn<crate::BoxStream> = PacketConn::xudp(session);

        let Err(err) = conn.split() else {
            panic!("the mux XUDP session has no stream halves to split");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("xudp"), "{err}");

        let frame = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(frame.status, STATUS_END);
        assert_eq!(frame.payload.as_ref(), b"");
    }

    #[test]
    fn split_halves_over_the_boxed_tunnel_are_spawnable() {
        // The relay moves the reader into its own task: the halves over the
        // production carrier (`PacketConn<BoxStream>`) must be Send +
        // 'static, or `tokio::spawn` refuses them.
        const fn spawnable<T: Send + 'static>() {}
        spawnable::<PacketReader<ReadHalf<crate::BoxStream>>>();
        spawnable::<PacketWriter<WriteHalf<crate::BoxStream>>>();
    }
}
