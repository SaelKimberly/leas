//! VLESS v1.mux.cool frame codec (SP2 of the parity program).
//!
//! Wire format (xray-core `common/mux/frame.go` + `writer.go`):
//!
//! ```text
//! [2B meta_len BE][2B session_id BE][1B status][1B option]
//! [New: 1B network + port-first addr (+ 8B `GlobalID` for UDP)]
//! [2B data_len][payload]
//! ```
//!
//! The 2-byte `meta_len` covers ONLY the metadata (session id, status,
//! option, and the frame target); `writeMetaWithFrame` appends
//! `[2B data_len][data]` after it. Status: `New` `0x01` / `Keep` `0x02` /
//! `End` `0x03` / `KeepAlive` `0x04`. Option: `Data` `0x01` / `Error`
//! `0x02`. Addresses are port-first (`[2B port][atyp][addr]`, atyp IPv4
//! `0x01` / Domain `0x02` / IPv6 `0x03`) exactly like the VLESS request
//! header. `meta_len` is capped at 512 on the server side (mirrored on
//! read); application data is chunked at 8 KiB by the client. The mux
//! connection itself targets the fixed `v1.mux.cool:9527` destination.
//!
//! New frames carry the session target: network byte TCP `0x01` (stream
//! sessions) or UDP `0x02` (XUDP sessions, spec §4.1), then the
//! port-first address. UDP New frames additionally carry the tunnel's
//! 8-byte `GlobalID` after the address (xray `frame.go` `WriteTo`:
//! `b.Write(f.GlobalID[:])` for user proxy requests). Data frames after
//! the first are `Keep`; **UDP Keep frames carry that packet's own
//! destination** (`[0x02 UDP][port-first addr]` — xray `WriteTo`'s
//! `else if b.UDP != nil`), which the demux threads to the session so
//! `recv_from` can return `(dest, payload)`. TCP Keep frames carry no
//! target. The server's response writer starts at Keep
//! (`NewResponseWriter` sets `followup: true`), so the client never sees
//! New frames in practice.
//!
//! The multiplexer ([`MuxClient`] + [`SessionStream`], spec §5.2) sits on
//! top of the codec: [`MuxClient::new`] splits the tunnel and spawns a
//! demux task (reads frames, routes payloads/End/Error to per-session
//! channels), a writer task (serializes frames onto the tunnel), and a
//! keepalive task (tunnel-level `KeepAlive` every 10s, spec §8 deviation
//! 2). [`MuxClient::open_session`] allocates a session id, registers the
//! channel, and sends an eager `New` frame (deviation 1); the returned
//! [`SessionStream`] reads its channel and writes 8 KiB-chunked `Keep`
//! frames, ending with a meta-only `End` on close/drop.
//! [`MuxClient::open_udp_session`] opens an XUDP datagram session: the
//! first [`UdpSession::send_to`] writes the `New` frame (network UDP +
//! dest + `GlobalID` — not eager, the target is only known with the first
//! packet, spec §8 deviation 3), subsequent sends are `Keep` frames with
//! per-packet destinations, and [`UdpSession::recv_from`] returns each
//! inbound packet's `(dest, payload)`.
//!
//! [`MuxClient`], [`SessionStream`], [`UdpSession`] and [`MuxTarget`] are
//! the public mux API — re-exported from `protocol::vless` and the crate
//! root. The rest of the items are `pub` inside the `pub(crate)` module
//! (effective `pub(crate)`), mirroring `udp.rs`.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context as TaskCx, Poll};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc::OwnedPermit;
use tokio::sync::mpsc::error::{SendError, TrySendError};
use tokio::sync::{mpsc, watch};

use crate::addr::{ADDR_TYPE_DOMAIN, ADDR_TYPE_IPV4, ADDR_TYPE_IPV6, Host, decode_addr};

/// The mux connection's fixed destination inside the VLESS header
/// (`v1.mux.cool:9527` — the VLESS Mux command target).
///
/// Not consumed by the [`MuxClient`] itself (it only sees the byte stream
/// of the already-open tunnel); the `connect_mux` path (this plan's Task
/// 3) writes the `command=0x03` header with this destination.
pub const MUX_DEST: &str = "v1.mux.cool";
pub const MUX_PORT: u16 = 9527;

pub const STATUS_NEW: u8 = 0x01;
pub const STATUS_KEEP: u8 = 0x02;
pub const STATUS_END: u8 = 0x03;
pub const STATUS_KEEPALIVE: u8 = 0x04;

pub const OPT_DATA: u8 = 0x01;
pub const OPT_ERROR: u8 = 0x02;

/// Application data chunk size written per Keep frame (xray
/// `SplitSize(mb, 8*1024)` for stream transfers).
pub const CHUNK_SIZE: usize = 8 * 1024;

/// Server-side `meta_len` rejection cap (`FrameMetadata.Unmarshal`), used
/// to bound the metadata read on the client too.
pub const MAX_META: usize = 512;

/// Network byte for New frames. TCP for stream sessions, UDP for XUDP
/// sessions ([`MuxTarget::Udp`]); UDP is also the network byte on every
/// UDP Keep frame (the per-packet destination).
const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x02;

/// A mux session target (the New frame's `network + port-first addr`;
/// for UDP sessions also the per-packet destination on Keep frames).
///
/// [`MuxTarget::Udp`] is the XUDP form: `open_session` never takes it
/// (stream sessions are TCP-only), it is the target carried by
/// [`UdpSession`] frames — the New frame's session dest and each Keep
/// frame's per-packet dest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MuxTarget {
    /// IP target.
    Tcp(SocketAddr),
    /// Domain target: name + port.
    TcpDomain(String, u16),
    /// UDP target — a datagram destination (XUDP sessions).
    Udp(SocketAddr),
}

/// One decoded v1.mux.cool frame.
#[derive(Debug)]
pub struct Frame {
    pub session_id: u16,
    pub status: u8,
    pub option: u8,
    /// `Some` on New frames (the client's first frame per session) and
    /// on UDP Keep frames (the per-packet destination); the server's
    /// response writer starts at Keep, so `None` on TCP Keep frames.
    pub target: Option<MuxTarget>,
    /// The tunnel `GlobalID`, written after the target on UDP New frames
    /// only (xray `frame.go` `WriteTo`: `b.Write(f.GlobalID[:])`). Read
    /// back from the metadata when present (defensive — the server never
    /// sends New frames to the client).
    pub global_id: Option<[u8; 8]>,
    /// Empty unless the Data option is set.
    pub payload: Bytes,
}

/// Frame and session plumbing for the v1.mux.cool multiplexer.
///
/// The format itself is protocol-independent (spec §7): the same bytes
/// serve a VLESS command-0x03 link and a SIP003 plugin row, which is why this
/// lives under `transport` rather than under a protocol.
/// truncated length/metadata/payload at EOF is `UnexpectedEof`, a
/// `meta_len` over [`MAX_META`] or an unparseable/unsupported New target
/// is `InvalidData`.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut len_buf = [0u8; 2];
    // Byte-by-byte so a clean EOF (0 bytes) is distinguishable from a
    // truncated length (1 byte then EOF).
    let mut filled = 0;
    while filled < len_buf.len() {
        match r.read(&mut len_buf[filled..]).await {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vless mux frame truncated (partial meta length)",
                ));
            }
            Ok(n) => filled += n,
            Err(e) => return Err(e),
        }
    }
    let meta_len = usize::from(u16::from_be_bytes(len_buf));
    if meta_len > MAX_META {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("vless mux invalid metalen {meta_len}"),
        ));
    }
    // The allocation is capped at meta_len (≤ MAX_META) by the check above.
    let mut meta = vec![0u8; meta_len];
    r.read_exact(&mut meta).await?;

    let mut frame = parse_meta(&meta)?;
    if frame.option & OPT_DATA != 0 {
        let mut dlen = [0u8; 2];
        r.read_exact(&mut dlen).await?;
        // Cap the payload allocation to data_len (defensive — the
        // server's frames are ≤ 8 KiB, so 64 KiB is the absolute worst
        // case; a truncated payload then fails the read_exact).
        let n = usize::from(u16::from_be_bytes(dlen));
        let mut payload = vec![0u8; n];
        r.read_exact(&mut payload).await?;
        frame.payload = Bytes::from(payload);
    }
    Ok(Some(frame))
}

/// Parses the metadata body: `[sid 2B][status 1B][option 1B]`, plus the
/// target for New frames (`[network 1B][port-first addr]`, TCP or UDP —
/// UDP New frames add the 8-byte `GlobalID` after the address) and for UDP
/// Keep frames (the per-packet destination, `[0x02 UDP][port-first
/// addr]`).
fn parse_meta(meta: &[u8]) -> io::Result<Frame> {
    if meta.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vless mux metadata too short",
        ));
    }
    let session_id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let option = meta[3];
    let mut rest = &meta[4..];
    let mut target = None;
    let mut global_id = None;
    if status == STATUS_NEW {
        let (network, tail) = rest.split_first().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "vless mux new frame missing network byte",
            )
        })?;
        // port-first: [2B port][atyp][addr] — same wire layout as the
        // VLESS request header (addr.rs `decode_addr`).
        let (addr, tail) = decode_addr(tail).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "vless mux truncated target address",
            )
        })?;
        target = Some(match (*network, addr.host) {
            (NETWORK_TCP, Host::Ip(ip)) => MuxTarget::Tcp(SocketAddr::new(ip, addr.port)),
            (NETWORK_TCP, Host::Domain(domain)) => MuxTarget::TcpDomain(domain, addr.port),
            (NETWORK_UDP, Host::Ip(ip)) => MuxTarget::Udp(SocketAddr::new(ip, addr.port)),
            (NETWORK_UDP, Host::Domain(_)) => {
                // A UDP destination is a socket — domains cannot be
                // represented (and never occur: the server echoes the
                // IP dests the client sent).
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vless mux udp target with a domain address is unsupported",
                ));
            }
            (other, _) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("vless mux unsupported network type {other}"),
                ));
            }
        });
        rest = tail;
        // UDP New frames carry the 8-byte tunnel GlobalID after the
        // target (xray `frame.go` `WriteTo`). The server never sends New
        // frames to the client, so this is defensive: consume the 8 bytes
        // when present, and anything beyond them (or a truncated prefix)
        // is a format violation.
        if matches!(target, Some(MuxTarget::Udp(_))) {
            match rest.len() {
                0 => {}
                n if n >= 8 => {
                    let mut gid = [0u8; 8];
                    gid.copy_from_slice(&rest[..8]);
                    global_id = Some(gid);
                    rest = &rest[8..];
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vless mux truncated global id",
                    ));
                }
            }
        }
    } else if status == STATUS_KEEP && !rest.is_empty() {
        // UDP Keep frames carry the per-packet destination (xray
        // `WriteTo`'s `else if b.UDP != nil`); TCP Keep frames carry no
        // target, so any leading byte other than the UDP network byte is
        // a format violation.
        if rest[0] != NETWORK_UDP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vless mux trailing metadata bytes",
            ));
        }
        let (addr, tail) = decode_addr(&rest[1..]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "vless mux truncated target address",
            )
        })?;
        target = Some(match addr.host {
            Host::Ip(ip) => MuxTarget::Udp(SocketAddr::new(ip, addr.port)),
            Host::Domain(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vless mux udp target with a domain address is unsupported",
                ));
            }
        });
        rest = tail;
    }
    // The metadata is exactly what we parsed; anything left over is a
    // frame format we don't understand (e.g. source/local metadata).
    if !rest.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vless mux trailing metadata bytes",
        ));
    }
    Ok(Frame {
        session_id,
        status,
        option,
        target,
        global_id,
        payload: Bytes::new(),
    })
}

/// A client-side multiplexer: sessions over one underlying stream.
///
/// Each session gets a stream id and a `New` frame carrying its target;
/// data rides `Keep` frames, and a `KeepAlive` tick keeps the tunnel warm
/// (spec §7).
/// plus `[2B data_len][payload]` when the Data option is set. The
/// metadata (sid, status, option, frame target) is what `meta_len`
/// covers; `writeMetaWithFrame` appends the data after it.
///
/// One `BytesMut` out, no `meta`/`out` `Vec`s: the fixed header goes on a
/// `[u8; 4]` stack, the variable target bytes extend the output directly,
/// and `meta_len` is patched into the reserved prefix once known.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> io::Result<()> {
    // meta worst case: sid(2) + status(1) + opt(1) + net(1) + port(2) +
    // atyp(1) + domain(1+255) + GlobalID(8) = 272; data adds 2 + payload.
    let mut out = BytesMut::with_capacity(2 + 272 + 2 + f.payload.len());
    out.extend_from_slice(&[0, 0]); // meta_len placeholder
    out.extend_from_slice(&f.session_id.to_be_bytes());
    out.put_u8(f.status);
    out.put_u8(f.option);
    if f.status == STATUS_NEW {
        let target = f.target.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "vless mux new frame requires a target",
            )
        })?;
        encode_target_meta(&mut out, target)?;
        // UDP New frames carry the tunnel GlobalID after the target
        // (xray `frame.go` `WriteTo`: `b.Write(f.GlobalID[:])` for user
        // proxy requests — the client's TCP sessions have no per-packet
        // dest, so no GlobalID there).
        if matches!(target, MuxTarget::Udp(_))
            && let Some(gid) = f.global_id
        {
            out.extend_from_slice(&gid);
        }
    } else if f.status == STATUS_KEEP {
        // UDP Keep frames carry the per-packet destination (xray
        // `WriteTo`'s `else if b.UDP != nil`); TCP Keep frames carry no
        // target.
        if let Some(target) = &f.target {
            match target {
                MuxTarget::Udp(_) => encode_target_meta(&mut out, target)?,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "vless mux keep frame with a non-udp target",
                    ));
                }
            }
        }
    }
    let meta_len = out.len() - 2;
    let meta_len_u16 = u16::try_from(meta_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "vless mux metadata exceeds the 2-byte meta length",
        )
    })?;
    if meta_len > MAX_META {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("vless mux metadata exceeds the {MAX_META}-byte limit"),
        ));
    }
    out[0..2].copy_from_slice(&meta_len_u16.to_be_bytes());
    if f.option & OPT_DATA != 0 {
        let data_len = u16::try_from(f.payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "vless mux frame payload exceeds the 2-byte data length (65535)",
            )
        })?;
        out.extend_from_slice(&data_len.to_be_bytes());
        out.extend_from_slice(&f.payload);
    } else if !f.payload.is_empty() {
        // Without the Data option the reader never consumes a data_len —
        // the bytes would be misparsed as the next frame's meta_len.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vless mux frame with payload requires the data option",
        ));
    }
    w.write_all(&out).await
}

/// Writes a frame target as the port-first address bytes into any byte
/// buffer: `[2B port][atyp][addr]` (IPv4 4 / Domain 1+len / IPv6 16). A
/// domain longer than the wire's 255-byte length field is `InvalidInput`.
fn write_target(out: &mut impl BufMut, t: &MuxTarget) -> io::Result<()> {
    match t {
        MuxTarget::Tcp(sa) | MuxTarget::Udp(sa) => {
            out.put_slice(&sa.port().to_be_bytes());
            match sa.ip() {
                IpAddr::V4(v4) => {
                    out.put_u8(ADDR_TYPE_IPV4);
                    out.put_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    out.put_u8(ADDR_TYPE_IPV6);
                    out.put_slice(&v6.octets());
                }
            }
        }
        MuxTarget::TcpDomain(domain, port) => {
            out.put_slice(&port.to_be_bytes());
            out.put_u8(ADDR_TYPE_DOMAIN);
            // The wire address caps domain length at 255. The VLESS header
            // encode rejects longer domains before a mux target is ever
            // built (addr.rs `encode_addr` → Config error), so this is
            // defense-in-depth: a panic here would kill the spawned writer
            // task and silently tear down the whole tunnel.
            let len = u8::try_from(domain.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vless mux target domain exceeds the 255-byte wire limit",
                )
            })?;
            out.put_u8(len);
            out.put_slice(domain.as_bytes());
        }
    }
    Ok(())
}

/// Appends a target's `[network byte][port-first addr]` to `meta` (the
/// network byte and address both live inside the frame metadata). Generic
/// over the buffer so `write_frame` extends its single `BytesMut` with no
/// intermediate target `Vec`.
fn encode_target_meta(meta: &mut impl BufMut, t: &MuxTarget) -> io::Result<()> {
    let network = match t {
        MuxTarget::Tcp(_) | MuxTarget::TcpDomain(..) => NETWORK_TCP,
        MuxTarget::Udp(_) => NETWORK_UDP,
    };
    meta.put_u8(network);
    write_target(meta, t)
}

// ---------------------------------------------------------------------
// MuxClient + SessionStream — the multiplexing core (spec §5.2)
// ---------------------------------------------------------------------

/// Tunnel-level `KeepAlive` interval (spec §8 deviation 2): xray sends
/// `KeepAlive` per idle session; a single tunnel-level `KeepAlive` keeps
/// the tunnel alive and is answered/ignored by both cores.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Writer-channel capacity in frames. Frames are ≤ 8 KiB + header, so this
/// bounds the queued-but-unwritten bytes (~256 KiB) between session writes
/// and the tunnel (the app-side backpressure point).
const WRITER_CHANNEL_CAPACITY: usize = 32;

/// Per-session event-channel capacity. Mirrors xray's 64 KiB pipe bound
/// (`pipe.WithSizeLimit(64 * 1024)`): at most 8 × 8 KiB payloads buffer
/// before the demux backpressures (head-of-line, like xray's `buf.Copy`).
const SESSION_CHANNEL_CAPACITY: usize = 8;

/// One event the demux task delivers to a session.
enum SessionEvent {
    /// Application payload bytes (a `Keep`+`Data` frame's payload) with
    /// the per-packet destination for UDP sessions (`Some(addr)` — the
    /// dest parsed from the frame's metadata; TCP streams' Keep frames
    /// carry no target, so `None` there).
    Data {
        dest: Option<SocketAddr>,
        bytes: Bytes,
    },
    /// The peer closed the session (`End` frame) — the reader sees EOF.
    End,
    /// The peer reported an error for the session (`Error` option) — the
    /// reader sees the `io::Error`.
    Error(io::Error),
}

/// Locks the session map, recovering from poisoning (a panicked holder
/// leaves the map intact; the lock is only ever held across short,
/// non-awaiting sections).
fn lock_map(
    map: &Mutex<HashMap<u16, mpsc::Sender<SessionEvent>>>,
) -> MutexGuard<'_, HashMap<u16, mpsc::Sender<SessionEvent>>> {
    map.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Multiplexes app TCP streams and UDP datagram sessions over one
/// v1.mux.cool tunnel (spec §5.2).
///
/// `new` splits the tunnel and spawns three tasks: a **demux** task reads
/// frames off the tunnel and routes payloads/`End`/`Error` to per-session
/// channels (ending every session on tunnel EOF/error); a **writer** task
/// drains the frame channel into the tunnel in order (one writer = no
/// interleaving); a **keepalive** task sends a tunnel-level `KeepAlive`
/// every [`KEEPALIVE_INTERVAL`] while the handle is alive.
///
/// Session ids are allocated from 1. The client itself does not own the
/// tunnel (it lives inside the spawned tasks); dropping the handle stops
/// the keepalive, and the tunnel tears down once the last session drops.
///
/// [`MuxClient`], [`SessionStream`], [`UdpSession`] and [`MuxTarget`] are
/// the public mux API: re-exported from `protocol::vless` and the crate
/// root (the `connect_mux` entry returns a [`MuxClient`] the app opens
/// sessions on).
pub struct MuxClient<S> {
    next_id: AtomicU16,
    sessions: Arc<Mutex<HashMap<u16, mpsc::Sender<SessionEvent>>>>,
    write_tx: mpsc::Sender<Frame>,
    /// Kept alive so dropping the handle stops the keepalive task (the
    /// loop exits when its receiver sees the channel close).
    #[allow(dead_code)] // held for the drop-close semantics, never read
    keepalive_tx: mpsc::Sender<()>,
    /// Set when the demux task exits — `open_session` fails fast after a
    /// dead tunnel instead of waiting on a writer that is gone.
    dead: Arc<AtomicBool>,
    tunnel: PhantomData<fn() -> S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> MuxClient<S> {
    /// Splits `tunnel` into read (demux) + write (writer) halves and
    /// spawns the demux/writer/keepalive tasks.
    pub(crate) fn new(tunnel: S) -> Self {
        let (read_half, write_half) = tokio::io::split(tunnel);
        let (write_tx, write_rx) = mpsc::channel(WRITER_CHANNEL_CAPACITY);
        let (keepalive_tx, keepalive_rx) = mpsc::channel(1);
        let (writer_done_tx, writer_done_rx) = watch::channel(());
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let dead = Arc::new(AtomicBool::new(false));

        tokio::spawn(demux_loop(
            read_half,
            Arc::clone(&sessions),
            Arc::clone(&dead),
            writer_done_rx,
        ));
        tokio::spawn(writer_loop(write_half, write_rx, writer_done_tx));
        tokio::spawn(keepalive_loop(write_tx.clone(), keepalive_rx));

        Self {
            next_id: AtomicU16::new(1),
            sessions,
            write_tx,
            keepalive_tx,
            dead,
            tunnel: PhantomData,
        }
    }

    /// Opens a new TCP session to `target` and returns its byte stream.
    ///
    /// The `New` frame is sent eagerly (spec §8 deviation 1) so the server
    /// allocates the session before any app data; the first app write then
    /// goes out as `Keep`. Fails when the tunnel is dead.
    pub async fn open_session(&self, target: MuxTarget) -> io::Result<SessionStream> {
        if self.dead.load(Ordering::Acquire) {
            return Err(tunnel_closed());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // Reject id 0 — the KeepAlive frames' session id. The counter
        // wraps around only after 65k live sessions (impossible in
        // practice), and a wrap to 0 is caught here.
        if id == 0 {
            return Err(io::Error::other("vless mux session id exhausted"));
        }
        let (tx, rx) = mpsc::channel(SESSION_CHANNEL_CAPACITY);
        lock_map(&self.sessions).insert(id, tx);
        let frame = Frame {
            session_id: id,
            status: STATUS_NEW,
            option: 0,
            target: Some(target),
            global_id: None,
            payload: Bytes::new(),
        };
        if self.write_tx.send(frame).await.is_err() {
            // The writer task is gone — the tunnel is dead.
            lock_map(&self.sessions).remove(&id);
            self.dead.store(true, Ordering::Release);
            return Err(tunnel_closed());
        }
        // Re-check the demux: it may have exited between the first check
        // above and the map insert/send. Its exit clears the session map,
        // so a registration inserted after the clear would never be
        // routed — the session's reads would hang on an empty channel.
        // Unregister and fail cleanly instead.
        if self.dead.load(Ordering::Acquire) {
            lock_map(&self.sessions).remove(&id);
            return Err(tunnel_closed());
        }
        Ok(SessionStream::new(
            id,
            rx,
            self.write_tx.clone(),
            Arc::clone(&self.sessions),
        ))
    }

    /// Opens a new UDP (XUDP) session with the tunnel's `global_id` and
    /// returns its datagram socket.
    ///
    /// Unlike [`MuxClient::open_session`] the `New` frame is NOT eager:
    /// its target is the first packet's destination, so the first
    /// [`UdpSession::send_to`] writes it (with the `GlobalID`, spec §4.1 —
    /// deviation 3). Fails when the tunnel is dead.
    // Sync body: no eager `New` frame is sent — the first packet's
    // destination becomes the session target.
    pub(crate) fn open_udp_session(&self, global_id: [u8; 8]) -> io::Result<UdpSession> {
        if self.dead.load(Ordering::Acquire) {
            return Err(tunnel_closed());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // Reject id 0 — the KeepAlive frames' session id (same wrap guard
        // as open_session).
        if id == 0 {
            return Err(io::Error::other("vless mux session id exhausted"));
        }
        let (tx, rx) = mpsc::channel(SESSION_CHANNEL_CAPACITY);
        lock_map(&self.sessions).insert(id, tx);
        // Re-check the demux (same race as open_session): an entry
        // inserted after its exit-clear would never be routed.
        if self.dead.load(Ordering::Acquire) {
            lock_map(&self.sessions).remove(&id);
            return Err(tunnel_closed());
        }
        Ok(UdpSession {
            id,
            rx,
            write_tx: self.write_tx.clone(),
            sessions: Arc::clone(&self.sessions),
            global_id,
            first: AtomicBool::new(true),
        })
    }
}

/// `BrokenPipe`-style error for a dead tunnel, shared by the session write
/// path and `open_session`.
fn tunnel_closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "vless mux tunnel is closed")
}

/// Reads frames off the tunnel and routes them to per-session channels
/// (spec §4.4). Exits on tunnel EOF/error, an unknown frame status (a
/// protocol violation — mirroring xray's fatal "unknown status"), or when
/// the writer task has died. On exit it marks the client dead and drops
/// every session channel's sender (the receivers see EOF — spec §6 "End
/// all sessions").
async fn demux_loop<R: AsyncRead + Unpin>(
    mut read_half: R,
    sessions: Arc<Mutex<HashMap<u16, mpsc::Sender<SessionEvent>>>>,
    dead: Arc<AtomicBool>,
    mut writer_done: watch::Receiver<()>,
) {
    loop {
        tokio::select! {
            // Resolves (Err) when the writer task exits and drops its
            // sender — the write side of the tunnel is gone.
            _ = writer_done.changed() => break,
            res = read_frame(&mut read_half) => {
                match res {
                    Ok(Some(frame)) => {
                        if !route(frame, &sessions).await {
                            break;
                        }
                    }
                    Ok(None) => break, // tunnel EOF
                    Err(e) => {
                        tracing::debug!(error = %e, "vless mux: tunnel read failed");
                        break;
                    }
                }
            }
        }
    }
    dead.store(true, Ordering::Release);
    lock_map(&sessions).clear();
}

/// Routes one inbound frame to its session. Returns `false` on a fatal
/// protocol error (an unknown status — tear the tunnel down).
async fn route(frame: Frame, sessions: &Mutex<HashMap<u16, mpsc::Sender<SessionEvent>>>) -> bool {
    let event = match frame.status {
        // KeepAlive: consumed (the codec drained any payload). New: a
        // server-initiated New — nothing to route. Both are no-ops.
        STATUS_KEEPALIVE | STATUS_NEW => return true,
        STATUS_END => {
            // The Error option reports a session error (spec §4.4) —
            // surface it rather than a plain EOF. Deviation from xray's
            // client: `handleStatusEnd` closes with EOF regardless of the
            // option (`s.Close(false)`); keeping the Error mapping is
            // arguably more correct, and both cores send session errors
            // as Keep+Error, so End+Error is a defensive branch.
            if frame.option & OPT_ERROR != 0 {
                SessionEvent::Error(session_error())
            } else {
                SessionEvent::End
            }
        }
        STATUS_KEEP => {
            if frame.option & OPT_ERROR != 0 {
                SessionEvent::Error(session_error())
            } else if frame.option & OPT_DATA != 0 {
                // The per-packet destination for UDP sessions (parsed
                // from the frame metadata — frame.target is
                // Some(Udp(addr)) on UDP Keep frames; TCP Keep frames
                // carry no target).
                let dest = match frame.target {
                    Some(MuxTarget::Udp(addr)) => Some(addr),
                    _ => None,
                };
                SessionEvent::Data {
                    dest,
                    bytes: frame.payload,
                }
            } else {
                return true; // meta-only Keep — nothing to deliver
            }
        }
        status => {
            tracing::warn!(status, "vless mux: unknown frame status; closing tunnel");
            return false;
        }
    };
    // Clone the sender out so the await never holds the map lock (a full
    // session channel backpressures the demux, not the map).
    let terminal = matches!(event, SessionEvent::End | SessionEvent::Error(_));
    let tx = lock_map(sessions).get(&frame.session_id).cloned();
    match tx {
        Some(tx) => {
            let delivered = tx.send(event).await.is_ok();
            // A closed session (End/Error delivered, or the receiver
            // dropped) is no longer routable — remove it so stray frames
            // for it can't accumulate in the channel.
            if !delivered || terminal {
                lock_map(sessions).remove(&frame.session_id);
            }
        }
        None => {
            tracing::debug!(
                session_id = frame.session_id,
                "vless mux: frame for unknown session"
            );
        }
    }
    true
}

/// The error surfaced on a session whose peer sent the `Error` option.
fn session_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        "vless mux: session terminated by peer",
    )
}

/// Drains frames from the channel and writes them to the tunnel in order.
/// Exits on a write error or when every sender is gone; dropping the
/// `writer_done` sender tells the demux the write side is dead.
async fn writer_loop<W: AsyncWrite + Unpin>(
    mut write_half: W,
    mut frames: mpsc::Receiver<Frame>,
    writer_done: watch::Sender<()>,
) {
    while let Some(frame) = frames.recv().await {
        if let Err(e) = write_frame(&mut write_half, &frame).await {
            tracing::debug!(error = %e, "vless mux: tunnel write failed");
            break;
        }
    }
    drop(writer_done);
}

/// Sends a tunnel-level `KeepAlive` frame (session id 0) every
/// [`KEEPALIVE_INTERVAL`] while the [`MuxClient`] handle is alive and the
/// writer task is accepting frames (spec §8 deviation 2).
async fn keepalive_loop(write_tx: mpsc::Sender<Frame>, mut stop: mpsc::Receiver<()>) {
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + KEEPALIVE_INTERVAL,
        KEEPALIVE_INTERVAL,
    );
    loop {
        tokio::select! {
            _ = stop.recv() => break, // the MuxClient handle is gone
            _ = interval.tick() => {
                let frame = Frame {
                    session_id: 0,
                    status: STATUS_KEEPALIVE,
                    option: 0,
                    target: None,
                    global_id: None,
                    payload: Bytes::new(),
                };
                if write_tx.send(frame).await.is_err() {
                    break; // the writer task is gone — tunnel dead
                }
            }
        }
    }
}

/// The app-side byte stream for one mux session (spec §4.4/§5.2).
///
/// Reads pull `SessionEvent`s off the session channel (`Data` → bytes,
/// `End` → EOF, `Error` → the `io::Error`); writes chunk the app bytes at
/// [`CHUNK_SIZE`] into `Keep` frames queued on the tunnel's writer
/// channel. The `AsyncWrite` contract holds strictly: bytes are only
/// counted as accepted once their frame is queued, and a full writer
/// channel parks the writer (`Pending`) rather than ever reporting `Ok(0)`
/// for a non-empty buffer.
pub struct SessionStream {
    id: u16,
    rx: mpsc::Receiver<SessionEvent>,
    write_tx: mpsc::Sender<Frame>,
    sessions: Arc<Mutex<HashMap<u16, mpsc::Sender<SessionEvent>>>>,
    /// A `Data` payload split across reads (cancellation-safe buffering).
    read_pending: Option<Bytes>,
    /// Terminal read state after `End`/`Error` — sticky, so every
    /// subsequent read keeps returning the same EOF/error.
    read_end: Option<ReadEnd>,
    /// Items not yet handed to the writer channel (a parked `Data` chunk
    /// or the shutdown `End`), in send order. The front item is the one
    /// with a reservation in flight (if any); an `End` is always queued
    /// strictly behind accepted data. Bytes in queued `Data` items are
    /// not yet counted as accepted.
    write_queue: VecDeque<WriteItem>,
    write_state: WriteState,
    /// The `End` frame was handed over/queued — `Drop` must not send
    /// another.
    end_queued: bool,
}

/// The session's terminal read outcome (peer `End` / peer `Error`).
enum ReadEnd {
    Eof,
    Err(io::Error),
}

/// The unit of queued write work.
enum WriteItem {
    /// A `Keep`-frame payload chunk; its length is the accepted count.
    Data(Bytes),
    /// The meta-only `End` frame (shutdown); accepted count 0.
    End,
}

impl WriteItem {
    /// The accepted-byte count this item contributes (0 for `End`).
    const fn len(&self) -> usize {
        match self {
            Self::Data(bytes) => bytes.len(),
            Self::End => 0,
        }
    }

    /// Borrowing conversion (for the direct `try_send` path).
    fn to_frame(&self, id: u16) -> Frame {
        match self {
            Self::Data(payload) => Frame {
                session_id: id,
                status: STATUS_KEEP,
                option: OPT_DATA,
                target: None,
                global_id: None,
                payload: payload.clone(),
            },
            Self::End => Frame {
                session_id: id,
                status: STATUS_END,
                option: 0,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        }
    }

    /// Owning conversion (for the reservation-completion path).
    fn into_frame(self, id: u16) -> Frame {
        match self {
            Self::Data(payload) => Frame {
                session_id: id,
                status: STATUS_KEEP,
                option: OPT_DATA,
                target: None,
                global_id: None,
                payload,
            },
            Self::End => Frame {
                session_id: id,
                status: STATUS_END,
                option: 0,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        }
    }
}

/// A writer-channel capacity reservation (owns the sender, so the future
/// is `'static` and storable across polls).
type WriteFuture = Pin<Box<dyn Future<Output = Result<OwnedPermit<Frame>, SendError<()>>> + Send>>;

enum WriteState {
    Idle,
    Waiting(WriteFuture),
}

impl SessionStream {
    #[must_use]
    const fn new(
        id: u16,
        rx: mpsc::Receiver<SessionEvent>,
        write_tx: mpsc::Sender<Frame>,
        sessions: Arc<Mutex<HashMap<u16, mpsc::Sender<SessionEvent>>>>,
    ) -> Self {
        Self {
            id,
            rx,
            write_tx,
            sessions,
            read_pending: None,
            read_end: None,
            write_queue: VecDeque::new(),
            write_state: WriteState::Idle,
            end_queued: false,
        }
    }

    /// Sends the front item of the write queue, finishing any in-flight
    /// reservation first, and returns the accepted byte count of the item
    /// that was sent (0 for `End`, 0 when idle). A full writer channel
    /// parks (starts a reservation) rather than reporting `Ok(0)`.
    fn poll_send_front(&mut self, cx: &mut TaskCx<'_>) -> Poll<io::Result<usize>> {
        loop {
            match &mut self.write_state {
                WriteState::Idle => {
                    let Some(item) = self.write_queue.front() else {
                        return Poll::Ready(Ok(0));
                    };
                    let accepted = item.len();
                    match self.write_tx.try_send(item.to_frame(self.id)) {
                        Ok(()) => {
                            self.write_queue.pop_front();
                            return Poll::Ready(Ok(accepted));
                        }
                        Err(TrySendError::Full(_)) => {
                            self.write_state = WriteState::Waiting(Box::pin(
                                self.write_tx.clone().reserve_owned(),
                            ));
                            // Loop to poll the fresh reservation.
                        }
                        Err(TrySendError::Closed(_)) => {
                            return Poll::Ready(Err(tunnel_closed()));
                        }
                    }
                }
                WriteState::Waiting(fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        self.write_state = WriteState::Idle;
                        let item = self
                            .write_queue
                            .pop_front()
                            .expect("a reservation in flight always has a front item");
                        let accepted = item.len();
                        permit.send(item.into_frame(self.id));
                        return Poll::Ready(Ok(accepted));
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(tunnel_closed())),
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }

    /// Removes this session from the demux's routing map. Idempotent.
    fn unregister(&self) {
        lock_map(&self.sessions).remove(&self.id);
    }
}

impl AsyncRead for SessionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // A terminal session (peer End/Error) stays terminal: later reads
        // keep returning the same EOF/error.
        if let Some(end) = &self.read_end {
            return Poll::Ready(match end {
                ReadEnd::Eof => Ok(()),
                ReadEnd::Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
            });
        }
        loop {
            // Deliver any leftover payload before pulling the channel, so a
            // read that filled the caller's buffer is never lost.
            if let Some(payload) = self.read_pending.take() {
                let n = std::cmp::min(payload.len(), buf.remaining());
                buf.put_slice(&payload[..n]);
                if n < payload.len() {
                    self.read_pending = Some(payload.slice(n..));
                }
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(SessionEvent::Data { bytes, .. })) => {
                    if bytes.is_empty() {
                        continue; // empty frames carry nothing
                    }
                    let n = std::cmp::min(bytes.len(), buf.remaining());
                    buf.put_slice(&bytes[..n]);
                    if n < bytes.len() {
                        self.read_pending = Some(bytes.slice(n..));
                    }
                    return Poll::Ready(Ok(()));
                }
                // End frame or a closed channel → EOF (sticky).
                Poll::Ready(Some(SessionEvent::End) | None) => {
                    self.read_end = Some(ReadEnd::Eof);
                    return Poll::Ready(Ok(()));
                }
                // Error → the io::Error (sticky).
                Poll::Ready(Some(SessionEvent::Error(e))) => {
                    self.read_end = Some(ReadEnd::Err(io::Error::new(e.kind(), e.to_string())));
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SessionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.end_queued {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "vless mux: write after shutdown",
            )));
        }
        let mut accepted = 0;
        loop {
            // Drive the queue front first (finishing any parked
            // reservation); its item belongs to the prefix of `buf` (the
            // caller re-polls from where we last returned), so its length
            // counts toward `accepted`.
            match self.poll_send_front(cx) {
                Poll::Ready(Ok(n)) => accepted += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return if accepted > 0 {
                        Poll::Ready(Ok(accepted))
                    } else {
                        Poll::Pending
                    };
                }
            }
            // Queue the next chunk from `buf` only when nothing is pending.
            if self.write_queue.is_empty() {
                if accepted >= buf.len() {
                    return Poll::Ready(Ok(accepted));
                }
                let n = std::cmp::min(CHUNK_SIZE, buf.len() - accepted);
                self.write_queue
                    .push_back(WriteItem::Data(Bytes::copy_from_slice(
                        &buf[accepted..accepted + n],
                    )));
                // loop: hand the chunk to the channel.
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        // Frames are drained by the writer task in order; flush only needs
        // the current write handed to the channel (a no-op when idle).
        match self.poll_send_front(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        // First drive any parked data to the channel: the End must never
        // overtake accepted data (a parked chunk is the current buf's
        // prefix — sending it is a bonus, never a reorder).
        loop {
            match self.poll_send_front(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            if self.write_queue.is_empty() {
                break;
            }
        }
        // Queue the meta-only End (spec §4.3) strictly behind the drained
        // data, then unregister. Drop (below) covers the fire-and-forget
        // path when the app never calls shutdown.
        if !self.end_queued {
            self.end_queued = true;
            self.write_queue.push_back(WriteItem::End);
            self.unregister();
        }
        // Drive the End into the channel.
        loop {
            match self.poll_send_front(cx) {
                Poll::Ready(Ok(_)) => {
                    if self.write_queue.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for SessionStream {
    fn drop(&mut self) {
        // Fire-and-forget End + unregister (spec §4.3). If poll_shutdown
        // parked the End (writer channel full) before the drop, its
        // reservation must be preserved so the peer still sees the close.
        if !self.end_queued {
            self.end_queued = true;
            self.queue_end_fire_and_forget();
        } else if let WriteState::Waiting(fut) =
            std::mem::replace(&mut self.write_state, WriteState::Idle)
        {
            // poll_shutdown queued the End but the writer was blocked when
            // the stream was dropped — hand the reservation to a spawned
            // task so the End is delivered once capacity frees.
            let item = self.write_queue.pop_front().unwrap_or(WriteItem::End);
            let id = self.id;
            tokio::spawn(async move {
                if let Ok(permit) = fut.await {
                    permit.send(item.into_frame(id));
                }
            });
        }
        self.unregister();
    }
}

impl SessionStream {
    /// The Drop-path End: delivered strictly after accepted data, even
    /// when the writer channel is full at drop time. A parked Data chunk
    /// (never accepted) is replaced by the End and its reservation is
    /// handed to a spawned task that sends the End the moment the slot is
    /// acquired; with nothing parked, a one-shot task waits for capacity.
    fn queue_end_fire_and_forget(&mut self) {
        let end = Frame {
            session_id: self.id,
            status: STATUS_END,
            option: 0,
            target: None,
            global_id: None,
            payload: Bytes::new(),
        };
        match self.write_tx.try_send(end) {
            // Handed over, or the tunnel is dead — nothing to queue in
            // either case.
            Ok(()) | Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(_)) => {
                match std::mem::replace(&mut self.write_state, WriteState::Idle) {
                    WriteState::Waiting(fut) => {
                        if let Some(front) = self.write_queue.front_mut() {
                            *front = WriteItem::End;
                        } else {
                            self.write_queue.push_back(WriteItem::End);
                        }
                        let id = self.id;
                        tokio::spawn(async move {
                            if let Ok(permit) = fut.await {
                                permit.send(WriteItem::End.to_frame(id));
                            }
                        });
                    }
                    WriteState::Idle => queue_end_fire_and_forget(self.id, &self.write_tx),
                }
            }
        }
    }
}

/// The Drop-path End for a session with no in-flight writer reservation
/// (a full writer channel): a spawned task sends the meta-only `End`
/// (spec §4.3) the moment a slot frees. The End lands strictly behind
/// data already accepted into the channel (a cancelled `send_to`/`write`
/// never queued its frame, so there is nothing to overtake).
fn queue_end_fire_and_forget(id: u16, write_tx: &mpsc::Sender<Frame>) {
    let end = Frame {
        session_id: id,
        status: STATUS_END,
        option: 0,
        target: None,
        global_id: None,
        payload: Bytes::new(),
    };
    let tx = write_tx.clone();
    tokio::spawn(async move {
        let _ = tx.send(end).await;
    });
}

/// The app-side datagram socket for one mux UDP session (XUDP, spec
/// §4.5).
///
/// Reads pull `SessionEvent`s off the session channel (`Data` → one
/// datagram `(dest, payload)`, `End` → `Ok(None)`, `Error` → the
/// `io::Error`); writes queue `New`/`Keep` frames on the tunnel's writer
/// channel. The first [`UdpSession::send_to`] writes the session's `New`
/// frame (network byte UDP + the destination + the `GlobalID` + the first
/// payload — spec §8 deviation 3: not eager, the target is only known
/// with the first packet); subsequent sends write `Keep` frames carrying
/// that packet's own destination (spec §4.1).
pub struct UdpSession {
    id: u16,
    rx: mpsc::Receiver<SessionEvent>,
    write_tx: mpsc::Sender<Frame>,
    sessions: Arc<Mutex<HashMap<u16, mpsc::Sender<SessionEvent>>>>,
    /// The tunnel's `GlobalID` (xudp, spec §4.2), written in the New frame
    /// only.
    global_id: [u8; 8],
    /// The first `send_to` writes the `New` frame; afterwards `Keep`.
    /// Atomic so `send_to` (&self) is safe to call concurrently — exactly
    /// one caller wins the New (see [`UdpSession::send_to`] for the
    /// serialization invariant that makes the race moot).
    first: AtomicBool,
}

impl UdpSession {
    /// Sends one datagram to `dest`. The first call writes the session's
    /// `New` frame (network UDP + `dest` + the `GlobalID` + the payload);
    /// later calls write `Keep` frames carrying this packet's own
    /// destination (spec §4.1). Fails when the tunnel is dead.
    ///
    /// `&self` (not `&mut self`) because the `XUdp` [`PacketConn`] hands
    /// the session around behind its own `&mut` API: production callers
    /// go through [`PacketConn::send`], which serializes — the session is
    /// never sent to concurrently. The `AtomicBool` first-swap would make
    /// a hypothetical concurrent first-send safe only in the weak sense
    /// of exactly-one `New`: the mpsc channel ordering is otherwise
    /// unconstrained, so a racer could wire its `Keep` before the `New`
    /// and that datagram would be dropped (the server has no session
    /// yet). The serialization invariant is what prevents it.
    pub(crate) async fn send_to(&self, dest: SocketAddr, payload: &[u8]) -> io::Result<()> {
        // Reject datagrams that cannot fit the 2-byte frame length
        // (65535) upfront — queuing one would return a misleading Ok,
        // then the writer task's `u16::try_from` in `write_frame` fails
        // mid-write and kills the whole tunnel (the writer exits on any
        // write error). `PacketConn::send`'s Raw/PacketAddr arms carry
        // the same guard (`reject_oversized`); XUdp delegates here.
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vless mux: udp datagram exceeds the 2-byte data length (65535)",
            ));
        }
        let is_first = self.first.swap(false, Ordering::AcqRel);
        let frame = Frame {
            session_id: self.id,
            status: if is_first { STATUS_NEW } else { STATUS_KEEP },
            option: OPT_DATA,
            target: Some(MuxTarget::Udp(dest)),
            global_id: is_first.then_some(self.global_id),
            payload: Bytes::copy_from_slice(payload),
        };
        self.write_tx.send(frame).await.map_err(|_| tunnel_closed())
    }

    /// Reads one datagram: `(destination, payload)` — the destination the
    /// server dispatched the packet to (the per-packet dest echoed from
    /// the frame's metadata, spec §4.4). `Ok(None)` on a clean close
    /// (`End` frame or the tunnel ending — spec §6). Each `recv` takes
    /// exactly one whole datagram, so cancelling it loses nothing (tokio
    /// `recv` is cancellation-safe).
    pub(crate) async fn recv_from(&mut self) -> io::Result<Option<(SocketAddr, Bytes)>> {
        loop {
            match self.rx.recv().await {
                Some(SessionEvent::Data { dest, bytes }) => {
                    // A UDP packet without a destination is a protocol
                    // violation (xray's packet reader errors on it too) —
                    // surface it, never deliver garbage.
                    let dest = dest.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vless mux: udp packet without a destination",
                        )
                    })?;
                    if bytes.is_empty() {
                        continue; // empty datagrams carry nothing
                    }
                    return Ok(Some((dest, bytes)));
                }
                Some(SessionEvent::End) | None => return Ok(None),
                Some(SessionEvent::Error(e)) => return Err(e),
            }
        }
    }

    /// Removes this session from the demux's routing map. Idempotent.
    fn unregister(&self) {
        lock_map(&self.sessions).remove(&self.id);
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        // Fire-and-forget End + unregister (spec §4.3), mirroring
        // SessionStream: the peer must see the session close even when
        // the app never sends one.
        queue_end_fire_and_forget(self.id, &self.write_tx);
        self.unregister();
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read as _, Write as _};
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use leas_proto::proto_spec::{ProtocolConfig, VlessConfig};

    use bytes::Bytes;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

    use crate::addr::{ADDR_TYPE_DOMAIN, ADDR_TYPE_IPV4, ADDR_TYPE_IPV6, Host, TargetAddr};
    use crate::context::{LinkContext, NativeConnectParams};
    use crate::protocol::vless::{PacketConn, connect_mux, header};
    use crate::security;
    use crate::security::fingerprint;

    use super::*;

    /// Feeds a byte buffer in fixed-size pieces so the codec must
    /// reassemble frames across partial reads (no single read returns a
    /// whole field). Deterministic and non-blocking.
    struct PieceReader {
        data: Vec<u8>,
        pos: usize,
        piece: usize,
    }

    impl AsyncRead for PieceReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = self
                .piece
                .min(self.data.len() - self.pos)
                .min(buf.remaining());
            buf.put_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn new_frame_exact_bytes() {
        // Frame { session_id: 1, status: New, option: 0,
        //         target: Some(Tcp(127.0.0.1:8080)), payload: [] }
        // wire: [0x00,0x0C][0x00,0x01][0x01][0x00][0x01][0x1F,0x90][0x01][127,0,0,1]
        //   meta_len = 0x000C = 12 (2B sid + 1B status + 1B opt + 1B net
        //   + 2B port + 1B atyp + 4B addr)
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(
            &mut a,
            &Frame {
                session_id: 1,
                status: STATUS_NEW,
                option: 0,
                target: Some(MuxTarget::Tcp("127.0.0.1:8080".parse().unwrap())),
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(
            raw,
            [
                0x00, 0x0C, 0x00, 0x01, 0x01, 0x00, 0x01, 0x1F, 0x90, 0x01, 127, 0, 0, 1
            ]
        );
    }

    #[tokio::test]
    async fn keep_data_frame_roundtrip() {
        // Keep frame with payload b"hello":
        // [meta_len 0x0004][sid 7][0x02][0x01][2B data_len 5][payload]
        let frame = Frame {
            session_id: 7,
            status: STATUS_KEEP,
            option: OPT_DATA,
            target: None,
            global_id: None,
            payload: Bytes::from_static(b"hello"),
        };
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, &frame).await.unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(
            raw,
            [
                0x00, 0x04, 0x00, 0x07, 0x02, 0x01, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'
            ]
        );
        // and it reads back to the same frame
        let mut c = std::io::Cursor::new(raw);
        let got = read_frame(&mut c).await.unwrap().unwrap();
        assert_eq!(got.session_id, frame.session_id);
        assert_eq!(got.status, frame.status);
        assert_eq!(got.option, frame.option);
        assert_eq!(got.target, frame.target);
        assert_eq!(&got.payload[..], &frame.payload[..]);
    }

    #[tokio::test]
    async fn end_frame_meta_only() {
        // status End, no data: [meta_len 0x0004][sid 3][0x03][0x00]
        // — no data_len on the wire (xray Close writes meta only).
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(
            &mut a,
            &Frame {
                session_id: 3,
                status: STATUS_END,
                option: 0,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(raw, [0x00, 0x04, 0x00, 0x03, 0x03, 0x00]);
    }

    #[test]
    fn domain_target_encode() {
        // port-first: [port 0x01BB][atyp 0x02][len 0x0B][b"example.com"]
        let mut bytes = Vec::with_capacity(2 + 1 + 16);
        write_target(&mut bytes, &MuxTarget::TcpDomain("example.com".into(), 443)).unwrap();
        let mut expected = vec![0x01, 0xBB, 0x02, 0x0B];
        expected.extend_from_slice(b"example.com");
        assert_eq!(bytes, expected);
    }

    #[test]
    fn domain_target_too_long_is_error() {
        // A 256-byte domain cannot fit the wire's 1-byte length field.
        // The encode returns InvalidInput instead of panicking — a panic
        // inside the spawned writer task would kill the whole tunnel
        // (defense-in-depth; the VLESS header encode rejects long domains
        // before a mux target is ever built).
        let long = "a".repeat(256);
        let mut bytes = Vec::new();
        let err = write_target(&mut bytes, &MuxTarget::TcpDomain(long, 443)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("255"));
    }

    #[tokio::test]
    async fn split_frame_reads() {
        // One Keep+Data frame fed two bytes at a time must reassemble.
        let wire = [
            0x00, 0x04, 0x00, 0x07, 0x02, 0x01, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o',
        ];
        let mut r = PieceReader {
            data: wire.to_vec(),
            pos: 0,
            piece: 2,
        };
        let frame = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(frame.session_id, 7);
        assert_eq!(frame.status, STATUS_KEEP);
        assert_eq!(frame.option, OPT_DATA);
        assert_eq!(frame.target, None);
        assert_eq!(&frame.payload[..], b"hello");
        // clean EOF after the frame
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn eof_at_boundary_none() {
        let mut r = PieceReader {
            data: vec![],
            pos: 0,
            piece: 2,
        };
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_meta_is_error() {
        // meta_len 0x0201 = 513 > 512 cap → InvalidData before any meta
        // body is read (mirrors xray's "invalid metalen").
        let mut r = PieceReader {
            data: vec![0x02, 0x01],
            pos: 0,
            piece: 2,
        };
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("metalen"));
    }

    #[tokio::test]
    async fn error_option_frame() {
        // option Error, status Keep, no data:
        // [meta_len 0x0004][sid 5][0x02][0x02]
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(
            &mut a,
            &Frame {
                session_id: 5,
                status: STATUS_KEEP,
                option: OPT_ERROR,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(raw, [0x00, 0x04, 0x00, 0x05, 0x02, 0x02]);
    }

    #[tokio::test]
    async fn new_frame_with_first_data_chunk() {
        // The client's first write is New + Data (xray writeData with
        // getNextFrameMeta New): target metadata, then [2B data_len][data].
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(
            &mut a,
            &Frame {
                session_id: 9,
                status: STATUS_NEW,
                option: OPT_DATA,
                target: Some(MuxTarget::Tcp("192.0.2.1:443".parse().unwrap())),
                global_id: None,
                payload: Bytes::from_static(b"GET /"),
            },
        )
        .await
        .unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(
            raw,
            [
                0x00, 0x0C, 0x00, 0x09, 0x01, 0x01, 0x01, 0x01, 0xBB, 0x01, 192, 0, 2, 1, 0x00,
                0x05, b'G', b'E', b'T', b' ', b'/'
            ]
        );
        // reads back to the same frame
        let mut c = std::io::Cursor::new(raw);
        let got = read_frame(&mut c).await.unwrap().unwrap();
        assert_eq!(got.session_id, 9);
        assert_eq!(got.status, STATUS_NEW);
        assert_eq!(got.option, OPT_DATA);
        assert_eq!(
            got.target,
            Some(MuxTarget::Tcp("192.0.2.1:443".parse().unwrap()))
        );
        assert_eq!(&got.payload[..], b"GET /");
    }

    #[tokio::test]
    async fn domain_target_full_frame() {
        // New + Domain: meta_len = 2+1+1+1+2+1+1+11 = 20 = 0x0014.
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(
            &mut a,
            &Frame {
                session_id: 2,
                status: STATUS_NEW,
                option: 0,
                target: Some(MuxTarget::TcpDomain("example.com".into(), 443)),
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        let mut expected = vec![
            0x00, 0x14, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0xBB, 0x02, 0x0B,
        ];
        expected.extend_from_slice(b"example.com");
        assert_eq!(raw, expected);
    }

    #[tokio::test]
    async fn ipv6_target_roundtrip() {
        let target = MuxTarget::Tcp("[2001:db8::1]:443".parse().unwrap());
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(
            &mut a,
            &Frame {
                session_id: 1,
                status: STATUS_NEW,
                option: 0,
                target: Some(target.clone()),
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        drop(a);
        let got = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(got.session_id, 1);
        assert_eq!(got.status, STATUS_NEW);
        assert_eq!(got.target, Some(target));
        assert!(got.payload.is_empty());
    }

    #[tokio::test]
    async fn keepalive_frame_meta_only() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(
            &mut a,
            &Frame {
                session_id: 0,
                status: STATUS_KEEPALIVE,
                option: 0,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(raw, [0x00, 0x04, 0x00, 0x00, 0x04, 0x00]);
    }

    #[tokio::test]
    async fn partial_length_eof_is_error() {
        // One length byte then EOF → UnexpectedEof (a clean boundary is 0).
        let mut r = PieceReader {
            data: vec![0x00],
            pos: 0,
            piece: 2,
        };
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn truncated_metadata_is_error() {
        // meta_len 10 but only 3 bytes follow.
        let mut r = PieceReader {
            data: vec![0x00, 0x0A, 0x00, 0x07, 0x02],
            pos: 0,
            piece: 3,
        };
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn truncated_payload_is_error() {
        // meta fine (Keep+Data), data_len 5 but only 2 payload bytes.
        let mut r = PieceReader {
            data: vec![0x00, 0x04, 0x00, 0x07, 0x02, 0x01, 0x00, 0x05, b'h', b'i'],
            pos: 0,
            piece: 2,
        };
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn unknown_network_is_error() {
        // New frame with network byte 0x03: neither TCP nor UDP — the
        // codec only knows the two v1.mux.cool networks (mirrors xray's
        // "unknown network type"; the target cannot be represented, so
        // the whole connection is unrecoverable).
        let mut r = PieceReader {
            data: vec![
                0x00, 0x0C, 0x00, 0x01, 0x01, 0x00, 0x03, 0x1F, 0x90, 0x01, 127, 0, 0, 1,
            ],
            pos: 0,
            piece: 2,
        };
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("network"));
    }

    #[tokio::test]
    async fn udp_new_frame_parses() {
        // A UDP New frame (network byte 0x02) now parses: target = the
        // UDP dest, and the 8-byte GlobalID is read back from the
        // metadata (xray `frame.go` writes it after the target).
        let mut r = PieceReader {
            data: vec![
                0x00, 0x14, 0x00, 0x01, 0x01, 0x01, 0x02, 0x1F, 0x90, 0x01, 127, 0, 0, 1, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x02, b'h', b'i',
            ],
            pos: 0,
            piece: 3,
        };
        let frame = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(frame.session_id, 1);
        assert_eq!(frame.status, STATUS_NEW);
        assert_eq!(frame.option, OPT_DATA);
        assert_eq!(
            frame.target.as_ref(),
            Some(&MuxTarget::Udp("127.0.0.1:8080".parse().unwrap()))
        );
        assert_eq!(frame.global_id, Some([0xAA; 8]));
        assert_eq!(&frame.payload[..], b"hi");
    }

    /// Reads one raw frame's exact wire bytes from the peer (`[2B
    /// meta_len][metadata][2B data_len][payload]`) without decoding it —
    /// for byte-exact wire assertions on frames emitted by the
    /// [`MuxClient`] machinery (the writer task owns the write half).
    async fn read_raw_frame(peer: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let mut ml = [0u8; 2];
        peer.read_exact(&mut ml).await.unwrap();
        let meta_len = usize::from(u16::from_be_bytes(ml));
        let mut meta = vec![0u8; meta_len];
        peer.read_exact(&mut meta).await.unwrap();
        let mut out = ml.to_vec();
        out.extend_from_slice(&meta);
        if meta[3] & OPT_DATA != 0 {
            let mut dl = [0u8; 2];
            peer.read_exact(&mut dl).await.unwrap();
            let n = usize::from(u16::from_be_bytes(dl));
            let mut payload = vec![0u8; n];
            peer.read_exact(&mut payload).await.unwrap();
            out.extend_from_slice(&dl);
            out.extend_from_slice(&payload);
        }
        out
    }

    #[tokio::test]
    async fn udp_session_new_frame_bytes() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let session = mux.open_udp_session([0xAA; 8]).unwrap();
        session
            .send_to("127.0.0.1:8080".parse().unwrap(), b"hi")
            .await
            .unwrap();

        // The first send writes the New frame — exact bytes:
        // [meta_len 0x14][sid 1][0x01 New][0x01 Data][0x02 UDP]
        // [port 0x1F90][atyp 0x01][127,0,0,1][GlobalID 0xAA×8]
        // [data_len 2]'hi'. meta_len = 2+1+1+1+2+1+4+8 = 20.
        let raw = read_raw_frame(&mut peer).await;
        let mut expected = vec![
            0x00, 0x14, 0x00, 0x01, 0x01, 0x01, 0x02, 0x1F, 0x90, 0x01, 127, 0, 0, 1,
        ];
        expected.extend_from_slice(&[0xAA; 8]);
        expected.extend_from_slice(&[0x00, 0x02, b'h', b'i']);
        assert_eq!(raw, expected);

        // And it decodes to the expected frame.
        let frame = read_frame(&mut std::io::Cursor::new(raw))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.session_id, 1);
        assert_eq!(frame.status, STATUS_NEW);
        assert_eq!(frame.option, OPT_DATA);
        assert_eq!(
            frame.target.as_ref(),
            Some(&MuxTarget::Udp("127.0.0.1:8080".parse().unwrap()))
        );
        assert_eq!(frame.global_id, Some([0xAA; 8]));
        assert_eq!(&frame.payload[..], b"hi");
    }

    #[tokio::test]
    async fn udp_session_per_packet_dests() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let session = mux.open_udp_session([0xAA; 8]).unwrap();
        session
            .send_to("127.0.0.1:8080".parse().unwrap(), b"p1")
            .await
            .unwrap();
        session
            .send_to("192.0.2.7:53".parse().unwrap(), b"p2")
            .await
            .unwrap();

        // First packet → New frame carrying dest1 + the GlobalID.
        let new = read_frame(&mut peer).await.unwrap().unwrap();
        assert_eq!(new.session_id, 1);
        assert_eq!(new.status, STATUS_NEW);
        assert_eq!(new.option, OPT_DATA);
        assert_eq!(
            new.target.as_ref(),
            Some(&MuxTarget::Udp("127.0.0.1:8080".parse().unwrap()))
        );
        assert_eq!(new.global_id, Some([0xAA; 8]));
        assert_eq!(&new.payload[..], b"p1");

        // Second packet → Keep frame carrying dest2 (its own per-packet
        // dest), no GlobalID.
        let keep = read_frame(&mut peer).await.unwrap().unwrap();
        assert_eq!(keep.session_id, 1);
        assert_eq!(keep.status, STATUS_KEEP);
        assert_eq!(keep.option, OPT_DATA);
        assert_eq!(
            keep.target.as_ref(),
            Some(&MuxTarget::Udp("192.0.2.7:53".parse().unwrap()))
        );
        assert_eq!(keep.global_id, None);
        assert_eq!(&keep.payload[..], b"p2");
    }

    #[tokio::test]
    async fn udp_session_recv_returns_dest() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut session = mux.open_udp_session([0xAA; 8]).unwrap();
        session
            .send_to("127.0.0.1:8080".parse().unwrap(), b"hello")
            .await
            .unwrap();
        let sid = read_frame(&mut peer).await.unwrap().unwrap().session_id;
        assert_eq!(sid, 1);

        // The peer answers with Keep frames, each carrying its own dest
        // (the server's response writer starts at Keep, spec §4.4); the
        // demux threads the per-packet dest to recv_from.
        for (addr, payload) in [("10.0.0.1:4000", b"a1"), ("10.0.0.2:4001", b"b2")] {
            write_frame(
                &mut peer,
                &Frame {
                    session_id: sid,
                    status: STATUS_KEEP,
                    option: OPT_DATA,
                    target: Some(MuxTarget::Udp(addr.parse().unwrap())),
                    global_id: None,
                    payload: Bytes::from_static(payload),
                },
            )
            .await
            .unwrap();
        }
        let (dest, payload) = session.recv_from().await.unwrap().unwrap();
        assert_eq!(dest, "10.0.0.1:4000".parse::<SocketAddr>().unwrap());
        assert_eq!(&payload[..], b"a1");
        let (dest, payload) = session.recv_from().await.unwrap().unwrap();
        assert_eq!(dest, "10.0.0.2:4001".parse::<SocketAddr>().unwrap());
        assert_eq!(&payload[..], b"b2");
    }

    #[tokio::test]
    async fn udp_session_eof_on_end() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut session = mux.open_udp_session([0xAA; 8]).unwrap();
        session
            .send_to("127.0.0.1:8080".parse().unwrap(), b"ping")
            .await
            .unwrap();
        let sid = read_frame(&mut peer).await.unwrap().unwrap().session_id;

        // The peer ends the session: recv_from sees EOF (sticky).
        write_frame(
            &mut peer,
            &Frame {
                session_id: sid,
                status: STATUS_END,
                option: 0,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        assert!(session.recv_from().await.unwrap().is_none());
        assert!(session.recv_from().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn udp_session_tunnel_death() {
        let (client, peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut session = mux.open_udp_session([0xAA; 8]).unwrap();
        session
            .send_to("127.0.0.1:8080".parse().unwrap(), b"ping")
            .await
            .unwrap();
        drop(peer);

        // Tunnel EOF ends the session (spec §6): recv_from sees EOF.
        assert!(session.recv_from().await.unwrap().is_none());
        // The writer task's next write hits BrokenPipe (the peer half is
        // gone) and it exits, closing the frame channel — sends then fail.
        let mut err = None;
        for _ in 0..64 {
            match session
                .send_to("127.0.0.1:8080".parse().unwrap(), b"x")
                .await
            {
                Ok(()) => tokio::task::yield_now().await,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        let e = err.expect("send_to fails once the tunnel is dead");
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
        // The client itself is dead: no new sessions.
        assert!(mux.open_udp_session([0xAA; 8]).is_err());
        assert!(mux.open_session(echo_target()).await.is_err());
    }

    #[tokio::test]
    async fn udp_session_rejects_oversized_datagram() {
        // A datagram larger than the 2-byte frame length (65535) is
        // rejected upfront with InvalidInput — without the guard it would
        // queue Ok, then the writer task's `u16::try_from` in
        // `write_frame` would fail mid-write and kill the whole tunnel.
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let session = mux.open_udp_session([0xAA; 8]).unwrap();
        let big = vec![0u8; u16::MAX as usize + 1];
        let err = session
            .send_to("127.0.0.1:8080".parse().unwrap(), &big)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // Nothing was queued: the session's New is still pending, so the
        // next valid send writes it and the tunnel survives.
        session
            .send_to("127.0.0.1:8080".parse().unwrap(), b"ok")
            .await
            .unwrap();
        let frame = read_frame(&mut peer).await.unwrap().unwrap();
        assert_eq!(frame.status, STATUS_NEW);
        assert_eq!(&frame.payload[..], b"ok");
    }

    #[tokio::test]
    async fn new_frame_without_target_is_invalid() {
        // A New frame must carry a target on the wire — writing one
        // without it is a client bug (InvalidInput), nothing written.
        let (mut a, mut b) = tokio::io::duplex(64);
        let err = write_frame(
            &mut a,
            &Frame {
                session_id: 1,
                status: STATUS_NEW,
                option: 0,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(raw.len(), 0);
    }

    #[tokio::test]
    async fn payload_without_data_option_is_invalid() {
        // A payload needs the Data option — otherwise the reader would
        // misparse it as the next frame's meta_len.
        let (mut a, mut b) = tokio::io::duplex(64);
        let err = write_frame(
            &mut a,
            &Frame {
                session_id: 1,
                status: STATUS_KEEP,
                option: 0,
                target: None,
                global_id: None,
                payload: Bytes::from_static(b"x"),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(raw.len(), 0);
    }

    // ---- MuxClient + SessionStream ------------------------------------

    fn echo_target() -> MuxTarget {
        MuxTarget::TcpDomain("echo.test".into(), 80)
    }

    /// A stream whose read half immediately errors (write half is a sink)
    /// — for the tunnel-read-error teardown test.
    struct ReadErrStream;

    impl AsyncRead for ReadErrStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "test read error",
            )))
        }
    }

    impl AsyncWrite for ReadErrStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A write/reply round-trip on one session: the peer reads the Keep
    /// frame, answers with `payload`, and the app reads it back.
    async fn echo_roundtrip(
        stream: &mut SessionStream,
        peer: &mut tokio::io::DuplexStream,
        sid: u16,
        out: &[u8],
        reply: &[u8],
    ) {
        stream.write_all(out).await.expect("session write");
        let keep = read_frame(peer)
            .await
            .expect("Keep frame read")
            .expect("Keep frame");
        assert_eq!(keep.session_id, sid);
        assert_eq!(keep.status, STATUS_KEEP);
        assert_eq!(keep.option, OPT_DATA);
        assert_eq!(&keep.payload[..], out);
        write_frame(
            peer,
            &Frame {
                session_id: sid,
                status: STATUS_KEEP,
                option: OPT_DATA,
                target: None,
                global_id: None,
                payload: Bytes::copy_from_slice(reply),
            },
        )
        .await
        .expect("peer reply");
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.expect("session read");
        assert_eq!(&buf[..n], reply);
    }

    #[tokio::test]
    async fn two_concurrent_sessions_independent() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let target_a = MuxTarget::TcpDomain("a.example".into(), 80);
        let target_b = MuxTarget::TcpDomain("b.example".into(), 80);
        let mut a = mux.open_session(target_a.clone()).await.unwrap();
        let mut b = mux.open_session(target_b.clone()).await.unwrap();
        // The eager New frames arrive first, in open order, each carrying
        // its own target.
        let new_a = read_frame(&mut peer).await.unwrap().unwrap();
        let new_b = read_frame(&mut peer).await.unwrap().unwrap();
        assert_eq!(new_a.status, STATUS_NEW);
        assert_eq!(new_a.target.as_ref(), Some(&target_a));
        assert_eq!(new_b.status, STATUS_NEW);
        assert_eq!(new_b.target.as_ref(), Some(&target_b));

        // Interleaved writes on both sessions; the peer reassembles each
        // stream by session id.
        a.write_all(b"aaaa-1").await.unwrap();
        b.write_all(b"bbbb-1").await.unwrap();
        a.write_all(b"aaaa-2").await.unwrap();
        b.write_all(b"bbbb-2").await.unwrap();

        let mut stream_a = Vec::new();
        let mut stream_b = Vec::new();
        for _ in 0..4 {
            let frame = read_frame(&mut peer).await.unwrap().unwrap();
            assert_eq!(frame.status, STATUS_KEEP);
            assert_eq!(frame.option, OPT_DATA);
            if frame.session_id == new_a.session_id {
                stream_a.extend_from_slice(&frame.payload);
            } else {
                assert_eq!(frame.session_id, new_b.session_id);
                stream_b.extend_from_slice(&frame.payload);
            }
        }
        assert_eq!(stream_a, b"aaaa-1aaaa-2");
        assert_eq!(stream_b, b"bbbb-1bbbb-2");

        // Replies routed per session; each SessionStream gets its own data.
        write_frame(
            &mut peer,
            &Frame {
                session_id: new_a.session_id,
                status: STATUS_KEEP,
                option: OPT_DATA,
                target: None,
                global_id: None,
                payload: Bytes::from_static(b"reply-A"),
            },
        )
        .await
        .unwrap();
        write_frame(
            &mut peer,
            &Frame {
                session_id: new_b.session_id,
                status: STATUS_KEEP,
                option: OPT_DATA,
                target: None,
                global_id: None,
                payload: Bytes::from_static(b"reply-B"),
            },
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        let n = a.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply-A");
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply-B");
    }

    #[tokio::test]
    async fn end_closes_one_session_only() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut a = mux
            .open_session(MuxTarget::TcpDomain("a.example".into(), 80))
            .await
            .unwrap();
        let mut b = mux
            .open_session(MuxTarget::TcpDomain("b.example".into(), 80))
            .await
            .unwrap();
        let new_a = read_frame(&mut peer).await.unwrap().unwrap();
        let new_b = read_frame(&mut peer).await.unwrap().unwrap();

        // The peer ends session A; A's read must see EOF, B keeps working.
        write_frame(
            &mut peer,
            &Frame {
                session_id: new_a.session_id,
                status: STATUS_END,
                option: 0,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(a.read(&mut buf).await.unwrap(), 0, "session A sees EOF");

        // B is unaffected: a full write/reply round-trip still works.
        echo_roundtrip(&mut b, &mut peer, new_b.session_id, b"b-data", b"b-reply").await;
        // A stays at EOF.
        assert_eq!(a.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn error_on_session() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut a = mux
            .open_session(MuxTarget::TcpDomain("a.example".into(), 80))
            .await
            .unwrap();
        let mut b = mux
            .open_session(MuxTarget::TcpDomain("b.example".into(), 80))
            .await
            .unwrap();
        let new_a = read_frame(&mut peer).await.unwrap().unwrap();
        let new_b = read_frame(&mut peer).await.unwrap().unwrap();

        // The peer reports an error for A (Keep + Error option; an End +
        // Error frame routes the same way). A's read surfaces it.
        write_frame(
            &mut peer,
            &Frame {
                session_id: new_a.session_id,
                status: STATUS_KEEP,
                option: OPT_ERROR,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        let err = a.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);

        // B is unaffected.
        echo_roundtrip(&mut b, &mut peer, new_b.session_id, b"b-data", b"b-reply").await;
    }

    #[tokio::test]
    async fn end_with_error_option_surfaces_error() {
        // An End frame carrying the Error option reports a session error
        // (spec §4.4) — the read must surface it, NOT return 0 (EOF) as a
        // plain End would. Deviation from xray's client: `handleStatusEnd`
        // closes with EOF regardless of the option; the Error mapping is
        // deliberately kept (the option exists to carry the peer's error).
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut a = mux
            .open_session(MuxTarget::TcpDomain("a.example".into(), 80))
            .await
            .unwrap();
        let new_a = read_frame(&mut peer).await.unwrap().unwrap();

        write_frame(
            &mut peer,
            &Frame {
                session_id: new_a.session_id,
                status: STATUS_END,
                option: OPT_ERROR,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        let err = a.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        // Terminal reads are sticky: the error keeps coming back.
        assert_eq!(
            a.read(&mut buf).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
    }

    #[tokio::test]
    async fn keepalive_consumed() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut a = mux.open_session(echo_target()).await.unwrap();
        let new_a = read_frame(&mut peer).await.unwrap().unwrap();

        // Two KeepAlive frames (one meta-only, one with a payload — the
        // codec reads the payload for the Data option) are consumed, never
        // delivered as session data.
        write_frame(
            &mut peer,
            &Frame {
                session_id: 0,
                status: STATUS_KEEPALIVE,
                option: 0,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        write_frame(
            &mut peer,
            &Frame {
                session_id: 0,
                status: STATUS_KEEPALIVE,
                option: OPT_DATA,
                target: None,
                global_id: None,
                payload: Bytes::from_static(b"tick"),
            },
        )
        .await
        .unwrap();
        write_frame(
            &mut peer,
            &Frame {
                session_id: new_a.session_id,
                status: STATUS_KEEP,
                option: OPT_DATA,
                target: None,
                global_id: None,
                payload: Bytes::from_static(b"real"),
            },
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        let n = a.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"real");

        // And the stream is still healthy afterwards.
        echo_roundtrip(&mut a, &mut peer, new_a.session_id, b"ping", b"pong").await;
    }

    #[tokio::test]
    async fn chunking_at_8kib() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut a = mux.open_session(echo_target()).await.unwrap();
        let _new_a = read_frame(&mut peer).await.unwrap().unwrap();

        #[allow(
            clippy::cast_possible_truncation,
            reason = "i % 97 < 97 fits u8 (test data generator)"
        )]
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2 + 4096))
            .map(|i| (i % 97) as u8)
            .collect();
        a.write_all(&data).await.unwrap();

        let mut total = 0usize;
        let mut frames = 0;
        let mut reassembled = Vec::new();
        while total < data.len() {
            let frame = read_frame(&mut peer).await.unwrap().unwrap();
            assert_eq!(frame.status, STATUS_KEEP);
            assert_eq!(frame.option, OPT_DATA);
            assert!(frame.payload.len() <= CHUNK_SIZE);
            frames += 1;
            total += frame.payload.len();
            reassembled.extend_from_slice(&frame.payload);
        }
        assert_eq!(frames, 3, "20 KiB splits into 8K + 8K + 4K frames");
        assert_eq!(reassembled, data);
    }

    #[tokio::test]
    async fn drop_sends_end() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut a = mux.open_session(echo_target()).await.unwrap();
        let sid = read_frame(&mut peer).await.unwrap().unwrap().session_id;

        a.write_all(b"data").await.unwrap();
        drop(a);

        let keep = read_frame(&mut peer).await.unwrap().unwrap();
        assert_eq!(keep.session_id, sid);
        assert_eq!(keep.status, STATUS_KEEP);
        assert_eq!(&keep.payload[..], b"data");
        let end = read_frame(&mut peer).await.unwrap().unwrap();
        assert_eq!(end.session_id, sid);
        assert_eq!(end.status, STATUS_END);
        assert_eq!(end.option, 0);
        assert!(end.target.is_none());
        assert!(end.payload.is_empty());
    }

    #[tokio::test]
    async fn tunnel_eof_ends_all_sessions() {
        let (client, peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut a = mux
            .open_session(MuxTarget::TcpDomain("a.example".into(), 80))
            .await
            .unwrap();
        let mut b = mux
            .open_session(MuxTarget::TcpDomain("b.example".into(), 80))
            .await
            .unwrap();
        // Dropping the peer: the tunnel read half sees EOF, the demux ends
        // every session (spec §6), and the client marks itself dead.
        drop(peer);
        let mut buf = [0u8; 8];
        assert_eq!(a.read(&mut buf).await.unwrap(), 0);
        assert_eq!(b.read(&mut buf).await.unwrap(), 0);
        // open_session now fails fast instead of queueing into a dead tunnel.
        assert!(mux.open_session(echo_target()).await.is_err());
    }

    #[tokio::test]
    async fn tunnel_read_error_ends_all_sessions() {
        // A transport error on the tunnel read half ends every session
        // (spec §6) and marks the client dead. Both sessions register
        // before the first suspension, so the demux tears them down in
        // one pass.
        let mux = MuxClient::new(ReadErrStream);
        let mut a = mux.open_session(echo_target()).await.unwrap();
        let mut b = mux.open_session(echo_target()).await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(a.read(&mut buf).await.unwrap(), 0);
        assert_eq!(b.read(&mut buf).await.unwrap(), 0);
        assert!(mux.open_session(echo_target()).await.is_err());
    }

    #[tokio::test]
    async fn data_for_closed_session_is_ignored() {
        // After A closes (End delivered), stray Keep frames for A's sid
        // hit the unknown-session path (the demux unregisters closed
        // sessions) instead of filling A's closed channel and stalling
        // the demux head-of-line (8 buffered events would block it).
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut a = mux
            .open_session(MuxTarget::TcpDomain("a.example".into(), 80))
            .await
            .unwrap();
        let mut b = mux
            .open_session(MuxTarget::TcpDomain("b.example".into(), 80))
            .await
            .unwrap();
        let new_a = read_frame(&mut peer).await.unwrap().unwrap();
        let new_b = read_frame(&mut peer).await.unwrap().unwrap();

        // The peer ends A; A reads EOF.
        write_frame(
            &mut peer,
            &Frame {
                session_id: new_a.session_id,
                status: STATUS_END,
                option: 0,
                target: None,
                global_id: None,
                payload: Bytes::new(),
            },
        )
        .await
        .unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(a.read(&mut buf).await.unwrap(), 0);

        // Ten stray data frames for A's closed sid — more than the 8-event
        // channel capacity. Without demux unregistration they would fill
        // the channel and stall the demux head-of-line.
        for _ in 0..10 {
            write_frame(
                &mut peer,
                &Frame {
                    session_id: new_a.session_id,
                    status: STATUS_KEEP,
                    option: OPT_DATA,
                    target: None,
                    global_id: None,
                    payload: Bytes::from_static(b"stray"),
                },
            )
            .await
            .unwrap();
        }
        // A stays EOF and B's round-trip still works.
        assert_eq!(a.read(&mut buf).await.unwrap(), 0);
        echo_roundtrip(&mut b, &mut peer, new_b.session_id, b"b-data", b"b-reply").await;
    }

    #[tokio::test]
    async fn data_for_unknown_session_is_ignored() {
        // A Data frame for a session id that was never opened is dropped
        // (spec §6: unknown session → ignore + log); the tunnel and its
        // siblings keep working.
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut a = mux.open_session(echo_target()).await.unwrap();
        let new_a = read_frame(&mut peer).await.unwrap().unwrap();

        for sid in [0xFEED, 0xFFFE] {
            write_frame(
                &mut peer,
                &Frame {
                    session_id: sid,
                    status: STATUS_KEEP,
                    option: OPT_DATA,
                    target: None,
                    global_id: None,
                    payload: Bytes::from_static(b"ghost"),
                },
            )
            .await
            .unwrap();
        }
        echo_roundtrip(&mut a, &mut peer, new_a.session_id, b"ping", b"pong").await;
    }

    #[tokio::test]
    async fn shutdown_with_parked_write_sends_end_last() {
        // A caller that abandons a partial write (the channel is full, the
        // write parked with Pending) and then drops the session must still
        // deliver the End — strictly after accepted data, with no stray
        // data after it. The parked chunk's bytes were never accepted, so
        // dropping them is legal (AsyncWrite contract untouched).
        let (client, mut peer) = tokio::io::duplex(64);
        let mux = MuxClient::new(client);
        let mut a = mux.open_session(echo_target()).await.unwrap();
        read_frame(&mut peer).await.unwrap().unwrap();
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);

        // Fill the writer channel until a write parks. The peer is not
        // reading, so the writer task blocks on the tiny duplex and the
        // channel stays full.
        let chunk = vec![0xCDu8; CHUNK_SIZE];
        let mut filled = 0usize;
        loop {
            let mut a_pin = Pin::new(&mut a);
            match a_pin.as_mut().poll_write(&mut cx, &chunk) {
                Poll::Ready(Ok(n)) => filled += n,
                Poll::Ready(Err(e)) => panic!("fill write failed: {e}"),
                Poll::Pending => break, // channel full — the chunk is parked
            }
        }
        assert!(
            filled > 0,
            "some data was accepted before the channel filled"
        );

        // The parked chunk must not jump ahead of the End: shutdown first
        // parks (writer blocked), then the drop hands the End to a task
        // that sends it once capacity frees.
        assert!(
            Pin::new(&mut a)
                .as_mut()
                .poll_shutdown(&mut cx)
                .is_pending(),
            "shutdown parks while the channel is full"
        );
        drop(a);

        // Drain the peer: the accepted data frames, then the End — and no
        // data after the End.
        let mut drained = 0usize;
        let mut saw_end = false;
        let mut after_end = 0usize;
        while let Ok(Ok(Some(frame))) =
            tokio::time::timeout(Duration::from_secs(2), read_frame(&mut peer)).await
        {
            if frame.status == STATUS_END {
                saw_end = true;
            } else {
                drained += frame.payload.len();
                if saw_end {
                    after_end += frame.payload.len();
                }
            }
        }
        assert!(
            saw_end,
            "the peer must receive the End for the dropped session"
        );
        assert_eq!(drained, filled, "only accepted data is sent");
        assert_eq!(after_end, 0, "no data after the End");
    }

    #[tokio::test]
    async fn write_backpressure_never_ok_zero() {
        // A 300 KiB write far exceeds the 32-frame × 8 KiB writer channel:
        // poll_write must park (Pending — never Ok(0)) and the whole
        // payload must arrive intact once the peer drains.
        let (client, mut peer) = tokio::io::duplex(8192);
        let mux = MuxClient::new(client);
        let mut a = mux.open_session(echo_target()).await.unwrap();
        #[allow(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "i % 251 < 251 fits u8 (test data generator)"
        )]
        let big: Vec<u8> = (0..(300 * 1024)).map(|i| (i % 251) as u8).collect();
        let big_len = big.len();

        let drainer = tokio::spawn(async move {
            let mut got = 0usize;
            while let Ok(Some(frame)) = read_frame(&mut peer).await {
                got += frame.payload.len();
                if got >= big_len {
                    // Payload complete; drain stragglers still in the
                    // writer channel, then stop on half a second of
                    // silence.
                    while let Ok(Ok(Some(f))) =
                        tokio::time::timeout(Duration::from_millis(500), read_frame(&mut peer))
                            .await
                    {
                        got += f.payload.len();
                    }
                    break;
                }
            }
            got
        });

        let mut written = 0;
        while written < big.len() {
            let n = a.write(&big[written..]).await.expect("session write");
            assert!(n > 0, "AsyncWrite must never report Ok(0)");
            written += n;
        }
        let got = drainer.await.expect("drainer task");
        assert_eq!(got, big.len());
    }

    #[tokio::test(start_paused = true)]
    async fn client_sends_keepalive_frames() {
        let (client, mut peer) = tokio::io::duplex(4096);
        let mux = MuxClient::new(client);
        // With no sessions the tunnel still emits a KeepAlive every
        // interval (deviation 2). Drive the virtual clock forward in
        // steps until the first one arrives.
        let mut first = None;
        for _ in 0..(KEEPALIVE_INTERVAL.as_millis() / 100 * 4) {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
            if let Ok(Ok(Some(frame))) =
                tokio::time::timeout(Duration::ZERO, read_frame(&mut peer)).await
            {
                first = Some(frame);
                break;
            }
        }
        let first = first.expect("keepalive frame within 4 intervals");
        assert_eq!(first.session_id, 0);
        assert_eq!(first.status, STATUS_KEEPALIVE);
        assert_eq!(first.option, 0);
        assert!(first.payload.is_empty());

        // Dropping the client stops the keepalive task. Drain the ready
        // queue first (the stop branch is the only ready one while the
        // clock is still, but multiple tasks may be queued), so the task
        // exits before any advance can make the next interval tick ready.
        drop(mux);
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        // Now prove it: advance the clock past several more intervals and
        // expect silence.
        for _ in 0..(KEEPALIVE_INTERVAL.as_millis() / 100 * 4) {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        // Silence (timeout) or a clean tunnel EOF (the writer task exited
        // once every sender — including the keepalive's — was gone) both
        // prove the keepalive stopped; a frame would not.
        match tokio::time::timeout(Duration::ZERO, read_frame(&mut peer)).await {
            Err(_) | Ok(Ok(None)) => {}
            Ok(Ok(Some(f))) => panic!(
                "no keepalive frames after the client is dropped — got status {} sid {}",
                f.status, f.session_id
            ),
            Ok(Err(e)) => panic!("read error after drop: {e}"),
        }
    }

    // ---- Hermetic: fake mux server over a real outer TLS session ----
    //
    // The raw-TCP fake-server pattern from the SP1 T4 / vision-plan
    // hermetic tests (fake server = the rustls server double + raw
    // socket): one `TcpListener`, the outer TLS handshake as a rustls
    // `ServerConnection`, then the VLESS mux wire spoken exactly — read +
    // assert the request header (cmd 0x03, NO destination bytes — the
    // no-addr fix, spec §4.1), send the `[0,0]` response header, then
    // exchange v1.mux.cool frames (New / Keep / End / KeepAlive) parsed
    // raw, independently of the codec under test. The CLIENT drives the
    // real path: `security::wrap` (engine TLS 1.3) +
    // `protocol::vless::connect_mux` + `MuxClient::open_session`. This is
    // the frame-level gate (brief steps 1-4) before the real-core e2e
    // rows.

    /// A VLESS config for the mux path: no flow, plain TLS to the fake
    /// server. The mux tunnel itself is TCP-only (`params.udp` stays None
    /// — `connect_mux` rejects a UDP mode).
    fn vless_mux_config() -> VlessConfig {
        let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00010203-0405-0607-0809-0a0b0c0d0e0f",
            "transport": { "type": "tcp" },
            "security": { "type": "tls", "sni": "localhost" }
        }))
        .expect("vless mux config parses");
        match protocol {
            ProtocolConfig::Vless(cfg) => cfg,
            _ => panic!("expected a vless config"),
        }
    }

    /// rcgen CA + server cert/key PEM + CA DER (the security-phase fixture).
    fn rcgen_ca_and_server(sni: &str) -> (String, String, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let mut ca_params = CertificateParams::new(vec![sni.to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_params =
            CertificateParams::new(vec![sni.to_string(), "127.0.0.1".to_string()]).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::new(ca_params, &ca_key);
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        (
            server_cert.pem(),
            server_key.serialize_pem(),
            ca_cert.der().to_vec(),
        )
    }

    fn server_config(cert_pem: &str, key_pem: &str) -> rustls::ServerConfig {
        use rustls::pki_types::pem::PemObject;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .map(|c| c.expect("cert pem parses"))
                .collect();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .expect("key pem parses");
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config builds")
    }

    /// Read exactly `out.len()` decrypted bytes, pulling new outer-TLS
    /// records from the socket whenever the rustls plaintext buffer is
    /// empty (rustls 0.23 `Reader::read` signals that with `WouldBlock`).
    fn read_exact_decrypted(
        conn: &mut rustls::ServerConnection,
        sock: &mut std::net::TcpStream,
        out: &mut [u8],
    ) -> std::io::Result<()> {
        let mut filled = 0;
        while filled < out.len() {
            match conn.reader().read(&mut out[filled..]) {
                Ok(n) if n > 0 => {
                    filled += n;
                    continue;
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            // No plaintext buffered. `complete_io` may have pulled the
            // peer's first application-data records into rustls's read
            // buffer together with the final handshake flight — process
            // whatever is buffered before blocking on the socket.
            let state = conn
                .process_new_packets()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            if state.plaintext_bytes_to_read() > 0 {
                continue;
            }
            if conn.read_tls(sock)? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "fake mux server: outer TLS peer closed",
                ));
            }
            conn.process_new_packets()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
        Ok(())
    }

    /// Write `data` as decrypted bytes (buffered into the record layer,
    /// then flushed until nothing is left to send).
    fn write_all_encrypted(
        conn: &mut rustls::ServerConnection,
        sock: &mut std::net::TcpStream,
        data: &[u8],
    ) -> std::io::Result<()> {
        conn.writer().write_all(data)?;
        loop {
            if conn.write_tls(sock)? == 0 {
                return Ok(());
            }
        }
    }

    /// One raw v1.mux.cool frame, decoded independently of the codec
    /// under test — the fake server speaks the wire directly (spec §4.2).
    struct RawMuxFrame {
        session_id: u16,
        status: u8,
        option: u8,
        /// Frame target, parsed as wire bytes: `(network, port, atyp,
        /// addr)` — the New frame's session target (TCP or UDP) or a UDP
        /// Keep frame's per-packet destination; interpreted in the
        /// assertions, never by the parser.
        target: Option<(u8, u16, u8, Vec<u8>)>,
        /// The 8-byte `GlobalID` a UDP New frame carries after the
        /// target; `None` on every other frame (spec §4.1).
        global_id: Option<[u8; 8]>,
        payload: Vec<u8>,
    }

    /// Reads one raw mux frame from the decrypted stream:
    /// `[2B meta_len][sid 2B][status 1B][option 1B][target][2B
    /// data_len][payload]`, exactly as the server would (spec §4.2). The
    /// target is the New frame's session target (TCP or UDP — a UDP New
    /// frame carries the 8-byte `GlobalID` right after the address) or a
    /// UDP Keep frame's per-packet destination; the server's own replies
    /// (TCP `Keep` / `KeepAlive` / `End`) carry no target.
    fn read_mux_frame(
        conn: &mut rustls::ServerConnection,
        sock: &mut std::net::TcpStream,
    ) -> std::io::Result<RawMuxFrame> {
        let mut ml = [0u8; 2];
        read_exact_decrypted(conn, sock, &mut ml)?;
        let meta_len = usize::from(u16::from_be_bytes(ml));
        assert!(meta_len <= MAX_META, "meta_len {meta_len} exceeds the cap");
        let mut meta = vec![0u8; meta_len];
        read_exact_decrypted(conn, sock, &mut meta)?;
        assert!(meta.len() >= 4, "mux metadata too short");
        let session_id = u16::from_be_bytes([meta[0], meta[1]]);
        let status = meta[2];
        let option = meta[3];
        let mut rest = &meta[4..];
        // New frames always carry a target; UDP Keep frames carry the
        // per-packet destination (TCP Keep/KeepAlive/End carry none).
        let mut target = None;
        let mut global_id = None;
        if status == STATUS_NEW || !rest.is_empty() {
            assert!(rest.len() >= 4, "mux frame target metadata too short");
            let network = rest[0];
            let port = u16::from_be_bytes([rest[1], rest[2]]);
            let atyp = rest[3];
            rest = &rest[4..];
            let addr_len = match atyp {
                ADDR_TYPE_IPV4 => 4,
                ADDR_TYPE_IPV6 => 16,
                ADDR_TYPE_DOMAIN => {
                    let (&len, tail) = rest
                        .split_first()
                        .expect("domain mux frame missing the length byte");
                    rest = tail;
                    usize::from(len)
                }
                other => panic!("unknown mux address type {other}"),
            };
            assert!(
                rest.len() >= addr_len,
                "mux frame target truncated ({} < {addr_len})",
                rest.len()
            );
            let addr = rest[..addr_len].to_vec();
            rest = &rest[addr_len..];
            // A UDP New frame carries the tunnel's 8-byte GlobalID after
            // the address (xray `frame.go` `WriteTo`); UDP Keep frames
            // carry nothing further.
            if status == STATUS_NEW && network == NETWORK_UDP {
                assert!(rest.len() >= 8, "udp new frame missing the GlobalID");
                global_id = Some(rest[..8].try_into().expect("8-byte GlobalID"));
                rest = &rest[8..];
            }
            target = Some((network, port, atyp, addr));
        }
        assert!(rest.is_empty(), "trailing mux metadata bytes");
        let payload = if option & OPT_DATA != 0 {
            let mut dl = [0u8; 2];
            read_exact_decrypted(conn, sock, &mut dl)?;
            let n = usize::from(u16::from_be_bytes(dl));
            let mut data = vec![0u8; n];
            read_exact_decrypted(conn, sock, &mut data)?;
            data
        } else {
            Vec::new()
        };
        Ok(RawMuxFrame {
            session_id,
            status,
            option,
            target,
            global_id,
            payload,
        })
    }

    /// Writes one raw mux frame to the decrypted stream, optionally
    /// carrying a target (`[network 1B][port 2B][atyp 1B][addr]`). The
    /// fake server's UDP replies are Keep frames WITH the per-packet
    /// destination (the client threads it to `recv_from`); its TCP
    /// replies (`Keep` / `KeepAlive` / `End`) carry no target (the server-side
    /// response writer starts at Keep — no New target on the wire).
    fn write_mux_frame_full(
        conn: &mut rustls::ServerConnection,
        sock: &mut std::net::TcpStream,
        session_id: u16,
        status: u8,
        option: u8,
        target: Option<(u8, u16, u8, Vec<u8>)>,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let mut meta = Vec::with_capacity(4);
        meta.extend_from_slice(&session_id.to_be_bytes());
        meta.push(status);
        meta.push(option);
        if let Some((network, port, atyp, addr)) = target {
            meta.push(network);
            meta.extend_from_slice(&port.to_be_bytes());
            meta.push(atyp);
            meta.extend_from_slice(&addr);
        }
        let meta_len = u16::try_from(meta.len()).expect("metadata fits the 2-byte length");
        let mut out = Vec::with_capacity(2 + meta.len() + 2 + payload.len());
        out.extend_from_slice(&meta_len.to_be_bytes());
        out.extend_from_slice(&meta);
        if option & OPT_DATA != 0 {
            let data_len = u16::try_from(payload.len()).expect("payload fits the 2-byte length");
            out.extend_from_slice(&data_len.to_be_bytes());
            out.extend_from_slice(payload);
        }
        write_all_encrypted(conn, sock, &out)
    }

    /// Writes one target-less raw mux frame (the fake server's TCP
    /// replies).
    fn write_mux_frame(
        conn: &mut rustls::ServerConnection,
        sock: &mut std::net::TcpStream,
        session_id: u16,
        status: u8,
        option: u8,
        payload: &[u8],
    ) -> std::io::Result<()> {
        write_mux_frame_full(conn, sock, session_id, status, option, None, payload)
    }

    /// Spawn the fake mux server: accept one connection, complete the
    /// outer TLS handshake as the rustls server double, run the wire
    /// `script`. Returns the listener address + the join handle
    /// (server-side assertion failures surface as panics through it).
    fn spawn_mux_server(
        cert_pem: &str,
        key_pem: &str,
        script: impl FnOnce(
            &mut rustls::ServerConnection,
            &mut std::net::TcpStream,
        ) -> std::io::Result<()>
        + Send
        + 'static,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let cfg = server_config(cert_pem, key_pem);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let timeout = Duration::from_secs(15);
            sock.set_read_timeout(Some(timeout)).expect("read timeout");
            sock.set_write_timeout(Some(timeout))
                .expect("write timeout");
            let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).expect("server conn");
            while conn.is_handshaking() {
                conn.complete_io(&mut sock).expect("outer TLS handshake");
            }
            script(&mut conn, &mut sock).expect("fake mux server wire script");
        });
        (addr, handle)
    }

    /// A `LinkContext` pointing the client at the fake server. The mux
    /// command carries no header destination on the wire, so the context
    /// target is the tunnel's semantic `v1.mux.cool:9527` (spec §4.1 —
    /// never encoded).
    fn mux_ctx(addr: SocketAddr, cfg: VlessConfig) -> LinkContext {
        let target = TargetAddr::new(Host::Domain(MUX_DEST.to_string()), MUX_PORT);
        let mut params = NativeConnectParams::new(
            ProtocolConfig::Vless(cfg),
            EndpointEssentials::new("127.0.0.1", 1),
            target.clone(),
        );
        params.server = EndpointEssentials::new(addr.ip().to_string(), addr.port());
        LinkContext::new(params, target)
    }

    /// The hermetic frame-level gate (brief steps 1-3): the real client
    /// path — engine TLS wrap + vless `connect_mux` + `MuxClient` — against
    /// the fake server. Asserts the header's cmd 0x03 with NO destination
    /// bytes (the no-addr fix: the 19-byte header is followed directly by
    /// the first mux frame's `meta_len`), the eager New frame (session 1,
    /// TCP target), Keep data frames in both directions, a second session,
    /// and End closing session 1 only.
    #[tokio::test]
    async fn hermetic_fake_mux_server_frames() {
        // Feature unification enables both rustls backends; the app installs
        // the ring provider at startup (workspace convention), tests do it
        // here (idempotent).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem, ca_der) = rcgen_ca_and_server("localhost");
        // The engine verifies through its thread-local harness CA.
        fingerprint::set_test_ca(&ca_der);
        let uuid = header::uuid_bytes("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap();
        let (addr, server) = spawn_mux_server(&cert_pem, &key_pem, move |conn, sock| {
            // Step 1: the request header — version | uuid | addons_len 0 |
            // command 0x03, exactly 19 bytes. The mux command carries NO
            // destination bytes (the no-addr fix; xray's EncodeRequestHeader
            // skips the address for Mux and the server derives the magic
            // fqdn from the command byte alone). The frame parsed right
            // after is the proof: any destination bytes would be misread as
            // that frame's meta_len and fail the parse/assertions.
            let mut head = [0u8; 19];
            read_exact_decrypted(conn, sock, &mut head)?;
            assert_eq!(head[0], header::VERSION, "vless version byte");
            assert_eq!(&head[1..17], &uuid, "vless user uuid");
            assert_eq!(head[17], 0, "addons_len (no flow on the mux path)");
            assert_eq!(head[18], header::CMD_MUX, "vless command must be MUX 0x03");

            // Step 2: the `[0,0]` response header (consumed by the client's
            // peel on the first tunnel read).
            write_all_encrypted(conn, sock, &[header::VERSION, 0x00])?;

            // Step 3: the client's eager New frame — session 1, TCP target
            // echo.test:80 (spec §8 deviation 1: open_session sends New
            // immediately, before any app data).
            let new1 = read_mux_frame(conn, sock)?;
            assert_eq!(new1.session_id, 1, "first session id is 1");
            assert_eq!(new1.status, STATUS_NEW, "eager New frame");
            assert_eq!(new1.option, 0);
            assert_eq!(new1.payload.len(), 0);
            let (network, port, atyp, addr) = new1.target.expect("New frame carries a target");
            assert_eq!(network, 1, "New network byte is TCP");
            assert_eq!(port, 80, "target port");
            assert_eq!(atyp, ADDR_TYPE_DOMAIN, "target address type");
            assert_eq!(addr, b"echo.test", "target domain");

            // The server's Keep reply on session 1; the client's
            // SessionStream must deliver it.
            write_mux_frame(conn, sock, 1, STATUS_KEEP, OPT_DATA, b"ok")?;

            // The client's app data rides a Keep frame (the New was eager).
            let keep = read_mux_frame(conn, sock)?;
            assert_eq!(keep.session_id, 1);
            assert_eq!(keep.status, STATUS_KEEP);
            assert_eq!(keep.option, OPT_DATA);
            assert_eq!(&keep.payload, b"ping");

            // A second session opens (eager New, session 2, other.test:443).
            let new2 = read_mux_frame(conn, sock)?;
            assert_eq!(new2.session_id, 2, "second session id is 2");
            assert_eq!(new2.status, STATUS_NEW);
            let (_, port2, atyp2, addr2) = new2.target.expect("New frame carries a target");
            assert_eq!(port2, 443);
            assert_eq!(atyp2, ADDR_TYPE_DOMAIN);
            assert_eq!(addr2, b"other.test");

            // Step 4: End closes session 1 only — session 2 keeps working.
            write_mux_frame(conn, sock, 1, STATUS_END, 0, &[])?;

            // The client's session-2 write still flows after session 1's
            // End (session isolation).
            let keep2 = read_mux_frame(conn, sock)?;
            assert_eq!(keep2.session_id, 2);
            assert_eq!(keep2.status, STATUS_KEEP);
            assert_eq!(&keep2.payload, b"pong");
            Ok(())
        });
        let cfg = vless_mux_config();
        let ctx = mux_ctx(addr, cfg.clone());

        tokio::time::timeout(Duration::from_secs(30), async {
            let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
            let wrapped = security::wrap(&ctx, Box::new(sock)).await.unwrap();
            let mux = connect_mux(&ctx, wrapped, &cfg).await.unwrap();
            let mut s1 = mux
                .open_session(MuxTarget::TcpDomain("echo.test".into(), 80))
                .await
                .unwrap();
            let mut buf = [0u8; 2];
            s1.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ok");
            s1.write_all(b"ping").await.unwrap();
            let mut s2 = mux
                .open_session(MuxTarget::TcpDomain("other.test".into(), 443))
                .await
                .unwrap();
            assert_eq!(s1.read(&mut buf).await.unwrap(), 0, "End closes session 1");
            s2.write_all(b"pong").await.unwrap();
        })
        .await
        .expect("hermetic mux flow timed out");
        server.await.expect("fake mux server task failed");
    }

    /// The optional `KeepAlive` round-trip (brief step 4): the client's
    /// tunnel-level `KeepAlive` (session id 0) reaches the server, is
    /// answered with a `KeepAlive` the demux consumes, and the live session
    /// survives untouched. The keepalive fires on the virtual clock (the
    /// interval is 10 s), so the clock is paused and advanced just past
    /// the first tick; the server's socket timeouts (15 s real) bound any
    /// hang.
    #[tokio::test(start_paused = true)]
    async fn hermetic_fake_mux_server_keepalive() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem, ca_der) = rcgen_ca_and_server("localhost");
        fingerprint::set_test_ca(&ca_der);
        let uuid = header::uuid_bytes("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap();
        let (addr, server) = spawn_mux_server(&cert_pem, &key_pem, move |conn, sock| {
            let mut head = [0u8; 19];
            read_exact_decrypted(conn, sock, &mut head)?;
            assert_eq!(head[0], header::VERSION, "vless version byte");
            assert_eq!(&head[1..17], &uuid, "vless user uuid");
            assert_eq!(head[17], 0, "addons_len (no flow on the mux path)");
            assert_eq!(head[18], header::CMD_MUX, "vless command must be MUX 0x03");
            write_all_encrypted(conn, sock, &[header::VERSION, 0x00])?;

            // The eager New + a Keep round-trip, then the client's
            // tunnel-level KeepAlive (the test advances the virtual clock).
            let new1 = read_mux_frame(conn, sock)?;
            assert_eq!(new1.session_id, 1);
            assert_eq!(new1.status, STATUS_NEW);
            write_mux_frame(conn, sock, 1, STATUS_KEEP, OPT_DATA, b"ok")?;
            let keep = read_mux_frame(conn, sock)?;
            assert_eq!(keep.session_id, 1);
            assert_eq!(keep.status, STATUS_KEEP);
            assert_eq!(&keep.payload, b"ping");

            // Step 4: the client's KeepAlive — session id 0, meta-only.
            let ka = read_mux_frame(conn, sock)?;
            assert_eq!(ka.session_id, 0, "keepalive uses session id 0");
            assert_eq!(ka.status, STATUS_KEEPALIVE, "keepalive status");
            assert_eq!(ka.option, 0);
            assert_eq!(ka.payload.len(), 0);
            // Answer it; the client's demux consumes the reply (never a
            // session event — session 1 must stay healthy).
            write_mux_frame(conn, sock, 0, STATUS_KEEPALIVE, 0, &[])?;

            // The live session survives the keepalive round-trip.
            let keep2 = read_mux_frame(conn, sock)?;
            assert_eq!(keep2.session_id, 1);
            assert_eq!(keep2.status, STATUS_KEEP);
            assert_eq!(&keep2.payload, b"still-alive");
            Ok(())
        });
        let cfg = vless_mux_config();
        let ctx = mux_ctx(addr, cfg.clone());

        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let wrapped = security::wrap(&ctx, Box::new(sock)).await.unwrap();
        let mux = connect_mux(&ctx, wrapped, &cfg).await.unwrap();
        let mut s1 = mux
            .open_session(MuxTarget::TcpDomain("echo.test".into(), 80))
            .await
            .unwrap();
        let mut buf = [0u8; 2];
        s1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");
        s1.write_all(b"ping").await.unwrap();

        // Advance the virtual clock just past the first keepalive tick
        // (10 s in 100 ms steps + a little slack): the keepalive task
        // sends the tunnel-level frame, the server reads and answers it,
        // and the demux consumes the reply — all before the next write.
        for _ in 0..(KEEPALIVE_INTERVAL.as_millis() / 100 + 5) {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        s1.write_all(b"still-alive").await.unwrap();
        server.await.expect("fake mux server task failed");
    }

    /// The hermetic XUDP gate (brief): the client opens a UDP mux session
    /// over the fake server — the first `send` writes the New frame with
    /// network=UDP + the destination + the 8-byte `GlobalID` (spec §4.1),
    /// subsequent `send`s are Keep frames carrying their own per-packet
    /// destinations; the server replies per dest (Keep frames carrying
    /// that destination back) and the client's `XUdp` [`PacketConn`] recv
    /// returns the `(dest, payload)` pairs. Asserts the `GlobalID` bytes
    /// (a fixed value drives the byte-exact wire check; the production
    /// path draws one randomly per tunnel) and the per-packet dest
    /// framing on both uplink directions.
    #[tokio::test]
    async fn hermetic_fake_mux_server_udp_session() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem, ca_der) = rcgen_ca_and_server("localhost");
        fingerprint::set_test_ca(&ca_der);
        let uuid = header::uuid_bytes("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap();
        let (addr, server) = spawn_mux_server(&cert_pem, &key_pem, move |conn, sock| {
            // Step 1: the request header — cmd 0x03, NO destination bytes.
            let mut head = [0u8; 19];
            read_exact_decrypted(conn, sock, &mut head)?;
            assert_eq!(head[0], header::VERSION, "vless version byte");
            assert_eq!(&head[1..17], &uuid, "vless user uuid");
            assert_eq!(head[17], 0, "addons_len (no flow on the mux path)");
            assert_eq!(head[18], header::CMD_MUX, "vless command must be MUX 0x03");

            // Step 2: the `[0,0]` response header (consumed by the
            // client's peel on the first tunnel read).
            write_all_encrypted(conn, sock, &[header::VERSION, 0x00])?;

            // Step 3: the client's UDP New frame — network byte UDP, the
            // first packet's destination, and the 8-byte GlobalID right
            // after the address (xray `frame.go` `WriteTo`), payload 'p1'.
            // The GlobalID sits INSIDE the metadata, so meta_len covers
            // it: 2+1+1+1+2+1+4+8 = 20.
            let new = read_mux_frame(conn, sock)?;
            assert_eq!(new.session_id, 1, "first session id is 1");
            assert_eq!(new.status, STATUS_NEW, "UDP session opens with New");
            assert_eq!(new.option, OPT_DATA);
            let (network, port, atyp, addr) = new.target.expect("New frame carries the dest");
            assert_eq!(network, NETWORK_UDP, "New network byte is UDP");
            assert_eq!(port, 8080, "session destination port");
            assert_eq!(atyp, ADDR_TYPE_IPV4, "session destination type");
            assert_eq!(addr, [127, 0, 0, 1], "session destination addr");
            assert_eq!(
                new.global_id,
                Some([0xAA; 8]),
                "GlobalID bytes ride the New frame only"
            );
            assert_eq!(&new.payload, b"p1");

            // Reply per dest 1: a Keep frame carrying that destination
            // (the server's response writer starts at Keep, spec §4.4).
            write_mux_frame_full(
                conn,
                sock,
                1,
                STATUS_KEEP,
                OPT_DATA,
                Some((NETWORK_UDP, 8080, ADDR_TYPE_IPV4, vec![127, 0, 0, 1])),
                b"r1",
            )?;

            // Step 4: the second packet — a Keep frame carrying ITS OWN
            // destination (`[0x02 UDP][port-first addr]`, no GlobalID),
            // payload 'p2'.
            let keep = read_mux_frame(conn, sock)?;
            assert_eq!(keep.session_id, 1);
            assert_eq!(keep.status, STATUS_KEEP, "follow-up packets are Keep");
            assert_eq!(keep.option, OPT_DATA);
            let (network2, port2, atyp2, addr2) =
                keep.target.expect("Keep frame carries the per-packet dest");
            assert_eq!(network2, NETWORK_UDP, "Keep network byte is UDP");
            assert_eq!(port2, 53, "per-packet dest port");
            assert_eq!(atyp2, ADDR_TYPE_IPV4, "per-packet dest type");
            assert_eq!(addr2, [192, 0, 2, 7], "per-packet dest addr");
            assert_eq!(keep.global_id, None, "no GlobalID on Keep frames");
            assert_eq!(&keep.payload, b"p2");

            // Reply per dest 2.
            write_mux_frame_full(
                conn,
                sock,
                1,
                STATUS_KEEP,
                OPT_DATA,
                Some((NETWORK_UDP, 53, ADDR_TYPE_IPV4, vec![192, 0, 2, 7])),
                b"r2",
            )?;

            // Step 5: the server closes the session — the client's recv
            // sees a sticky EOF.
            write_mux_frame(conn, sock, 1, STATUS_END, 0, &[])?;
            Ok(())
        });
        let cfg = vless_mux_config();
        let ctx = mux_ctx(addr, cfg.clone());

        tokio::time::timeout(Duration::from_secs(30), async {
            let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
            let wrapped = security::wrap(&ctx, Box::new(sock)).await.unwrap();
            let mux = connect_mux(&ctx, wrapped, &cfg).await.unwrap();
            // A fixed GlobalID drives the byte-exact wire assertion above.
            let session = mux.open_udp_session([0xAA; 8]).unwrap();
            // XUdp holds no stream, so S is unconstrained — pin it for
            // the test (production pins it via connect_udp's return type).
            let mut conn: PacketConn<crate::BoxStream> = PacketConn::xudp(session);

            conn.send(Some("127.0.0.1:8080".parse().unwrap()), b"p1")
                .await
                .unwrap();
            conn.send(Some("192.0.2.7:53".parse().unwrap()), b"p2")
                .await
                .unwrap();

            // The replies come back per dest, in order.
            let (dest, payload) = conn.recv().await.unwrap().expect("reply 1");
            assert_eq!(dest, Some("127.0.0.1:8080".parse::<SocketAddr>().unwrap()));
            assert_eq!(&payload[..], b"r1");
            let (dest, payload) = conn.recv().await.unwrap().expect("reply 2");
            assert_eq!(dest, Some("192.0.2.7:53".parse::<SocketAddr>().unwrap()));
            assert_eq!(&payload[..], b"r2");
            // The server's End: a sticky EOF on recv.
            assert!(conn.recv().await.unwrap().is_none());
            assert!(conn.recv().await.unwrap().is_none());
        })
        .await
        .expect("hermetic xudp flow timed out");
        server.await.expect("fake mux server task failed");
    }
}
