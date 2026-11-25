//! Hysteria2 QUIC dial + auth + TCP frame handshake.
//!
//! Layering (mirror of the h3 arm + hysteria2 spec §5.2): the QUIC dial
//! replaces dial + security + upgrade entirely (quinn's rustls is internal).
//! Salamander packet obfuscation wraps the UDP socket when configured.
// The send-path `thread_local!` scratch buffer initializer is already a `const`
// block, but `missing_const_for_thread_local` fires on it anyway — the
// windows-gnu false positive in clippy#17566. An `allow` on the macro
// invocation itself is ignored (it produces its own `unused_attributes`
// warning), so the suppression sits at module level, where it reaches the
// expansion.
#![allow(
    clippy::missing_const_for_thread_local,
    reason = "false positive on an already-const initializer: clippy#17566"
)]

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::{BufMut, Bytes};
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use leas_proto::proto_spec::{Hysteria2Config, ObfsSpec};

use crate::addr::TargetAddr;
use crate::context::LinkContext;
use crate::crypto::gecko::{self, GeckoReassembler, Push};
use crate::crypto::salamander::{SALT_LEN, Salamander};
use crate::error::{NativeError, timeouts};
use crate::rand::u32_below;

use super::{ALPN_H3, FRAME_TYPE_TCP_REQUEST, MAX_ADDRESS_LEN, TCP_RESPONSE_OK};

// ── randomness ────────────────────────────────────────────────────────────
//
// Salts and padding are wire-visible filler, not key material, and
// `random_salt` runs once per OUTBOUND DATAGRAM — so both draw from the
// buffered pool (`crate::rand`), which keeps ring's `SystemRandom` as the
// entropy source but amortizes `getrandom(2)` over ~512 salts.

/// A fresh random salt for one salamander packet.
fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    crate::rand::fill_nonsecret(&mut salt);
    salt
}

/// Random alphanumeric padding in `[min, max)` — the wire value is
/// arbitrary, only its length matters. Fills the whole payload with ONE
/// pool draw, not one per character.
fn random_padding(min: usize, max: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut len_bytes = [0u8; 8];
    crate::rand::fill_nonsecret(&mut len_bytes);
    let span = max - min;
    let len = min + (usize::from_le_bytes(len_bytes) % span);
    let mut buf = vec![0u8; len];
    crate::rand::fill_nonsecret(&mut buf);
    buf.iter()
        .map(|b| char::from(CHARS[usize::from(*b) % CHARS.len()]))
        .collect()
}

// ── QUIC varint (RFC 9000 §16) ───────────────────────────────────────────

/// The wire width of `value` as a QUIC varint: 1/2/4/8 bytes by the same
/// range table as [`put_varint`] (`quicvarint.Len`) — the sizing helper,
/// so a header size never has to encode the value first.
#[must_use]
pub(super) const fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Append `value` to `buf` as a QUIC varint: 1/2/4/8 bytes, 2-bit length
/// prefix (hysteria `varintPut`, `internal/protocol/proxy.go:227`). The
/// range guards guarantee the value fits the cast target width.
#[allow(clippy::cast_possible_truncation)]
pub(super) fn put_varint(buf: &mut impl BufMut, value: u64) {
    match value {
        0..=63 => buf.put_u8(value as u8),
        64..=16_383 => buf.put_u16(0x4000 | value as u16),
        16_384..=1_073_741_823 => buf.put_u32(0x8000_0000 | value as u32),
        _ => buf.put_u64(0xc000_0000_0000_0000 | value),
    }
}

/// Encode `value` as a QUIC varint into a fresh buffer — [`put_varint`] for
/// the once-per-connection frame writers.
#[must_use]
fn varint(value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(varint_len(value));
    put_varint(&mut buf, value);
    buf
}

/// Read one QUIC varint from `src`, returning `(value, remaining)`.
pub(super) fn read_varint(src: &[u8]) -> Option<(u64, &[u8])> {
    let first = *src.first()?;
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if src.len() < len {
        return None;
    }
    let mut v = 0u64;
    for b in &src[..len] {
        v = (v << 8) | u64::from(*b);
    }
    let mask = match len {
        1 => 0x3f_u64,
        2 => 0x3fff,
        4 => 0x3fff_ffff,
        _ => 0x3fff_ffff_ffff_ffff,
    };
    Some((v & mask, &src[len..]))
}

/// A destination in the Socksaddr form hysteria2 uses on the wire
/// (`M.Socksaddr.String()`): `host:port` / `[v6]:port`.
pub(super) fn target_string(target: &TargetAddr) -> String {
    use crate::addr::Host;
    match &target.host {
        Host::Domain(d) => format!("{d}:{}", target.port),
        Host::Ip(std::net::IpAddr::V4(ip)) => format!("{ip}:{}", target.port),
        Host::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]:{}", target.port),
    }
}

// ── dial + auth ───────────────────────────────────────────────────────────

/// The established hysteria2 session: the quinn connection plus the h3
/// keep-alive that keeps it alive.
///
/// The server runs the h3 `StreamDispatcher` (quic-go `http3.Server`) over
/// the SAME quinn connection that carried the auth request. Dropping the
/// last `SendRequest` clone closes the h3 session, which sends
/// `CONNECTION_CLOSE` (`H3_NO_ERROR`) and tears the whole quinn connection
/// down — so the h3 handle must outlive the tunnel (mirror of the xhttp h3
/// arm's keepalive).
pub(super) struct H3Keepalive(
    #[allow(dead_code)] // RAII guard: only its Drop matters
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
);

/// Dial the hysteria2 server (QUIC, ALPN `h3`), run the auth exchange and
/// return the live session (quinn connection + h3 keep-alive + the server's
/// UDP-enabled flag).
pub(super) async fn dial(
    ctx: &LinkContext,
    cfg: &Hysteria2Config,
) -> Result<(quinn::Connection, AuthInfo), NativeError> {
    let server_addr = ctx.server_socket().await?;
    let obfs = cfg
        .obfs_spec()
        .map_err(|e| NativeError::Config(e.reason().to_string()))?;
    let endpoint = client_endpoint(server_addr, &obfs)?;
    let tls = crate::transport::quic::quic_tls_config(ctx, ALPN_H3)?;
    let quic_config = crate::transport::quic::quinn_client_config(tls);
    let conn = crate::transport::quic::connect(
        &endpoint,
        quic_config,
        server_addr,
        &ctx.server_name(),
        "hysteria2",
    )
    .await?;

    let auth = match runtime_auth(&conn, &endpoint, &cfg.auth, cc_rx_bps(cfg)).await {
        Ok(auth) => auth,
        Err(error) => {
            // The h3 driver task spawned inside `runtime_auth` holds the
            // endpoint and a connection clone until `poll_close` resolves;
            // without an explicit close that is quinn's 300 s idle timeout.
            // A feed-wide probe hits this path hundreds of times a second.
            conn.close(0_u32.into(), b"hysteria2 auth failed");
            return Err(error);
        }
    };
    Ok((conn, auth))
}

/// The h3 auth exchange result: the keep-alive guard plus the server's
/// response headers (`Hysteria-UDP` — whether UDP relay is enabled).
pub(super) struct AuthInfo {
    /// Keeps the h3 session (and the quinn connection) alive.
    pub keepalive: H3Keepalive,
    /// `Hysteria-UDP` response header: the server enabled UDP relay.
    pub udp_enabled: bool,
}

/// The client's max receive bandwidth (`hysteria-cc-rx`) in bytes/sec from
/// the config's `down` bandwidth string — hysteria `AuthRequest.Rx`. `0`
/// = unknown → the server runs bandwidth detection.
fn cc_rx_bps(cfg: &Hysteria2Config) -> u64 {
    cfg.down
        .as_ref()
        .and_then(|d| super::bandwidth_bps(d.as_str()))
        .unwrap_or(0)
}

/// The h3 auth exchange: login the connection, verify status 233 and read
/// the response headers.
async fn runtime_auth(
    conn: &quinn::Connection,
    endpoint: &quinn::Endpoint,
    auth: &str,
    cc_rx: u64,
) -> Result<AuthInfo, NativeError> {
    let h3_quic = h3_quinn::Connection::new(conn.clone());
    let (mut h3_conn, mut sender) = {
        let limit = timeouts::TRANSPORT;
        tokio::time::timeout(limit, h3::client::new(h3_quic))
            .await
            .map_err(|_| NativeError::Timeout {
                step: "hysteria2 h3 open",
                limit,
            })?
            .map_err(|e| NativeError::Transport(format!("hysteria2 h3 open: {e}")))?
    };
    // Drive the h3 connection in the background; keep the endpoint alive for
    // the tunnel's lifetime.
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| {
            let mut conn = Pin::new(&mut h3_conn);
            conn.as_mut().poll_close(cx)
        })
        .await;
        drop(endpoint);
    });

    let mut req = Request::builder()
        .method(http::method::Method::POST)
        .uri("https://hysteria/auth");
    req = req.header("hysteria-auth", auth);
    // cc-rx: the client's max receive bandwidth in bytes/sec (0 = unknown →
    // the server runs bandwidth detection). hysteria `AuthRequest.Rx`,
    // sing-box `ReceiveBPS`.
    req = req.header("hysteria-cc-rx", cc_rx.to_string());
    req = req.header("hysteria-padding", &random_padding(256, 2048));
    let request = req
        .body(())
        .map_err(|e| NativeError::Transport(format!("hysteria2 auth request: {e}")))?;

    let mut stream = sender
        .send_request(request)
        .await
        .map_err(|e| NativeError::Transport(format!("hysteria2 auth send: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| NativeError::Transport(format!("hysteria2 auth finish: {e}")))?;
    let resp = stream
        .recv_response()
        .await
        .map_err(|e| NativeError::Transport(format!("hysteria2 auth response: {e}")))?;
    drop(stream);

    let status = resp.status();
    if status != http::StatusCode::from_u16(233).expect("233 is a valid status") {
        return Err(NativeError::AuthRejected {
            detail: format!("authentication failed, status code: {status}"),
        });
    }
    // `Hysteria-UDP`: the server announces UDP relay availability
    // (`AuthResponse.UDPEnabled`, header value "true"/"false").
    let udp_enabled = resp
        .headers()
        .get("hysteria-udp")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(false);
    // The h3 connection stays open only while a `SendRequest` clone is
    // alive: return one so the tunnel's lifetime keeps the session (and the
    // underlying quinn connection) alive.
    Ok(AuthInfo {
        keepalive: H3Keepalive(sender),
        udp_enabled,
    })
}

/// Bind the QUIC client endpoint for the resolved obfs shape.
///
/// No obfs keeps the shared per-address-family endpoint. Any obfs binds a
/// per-dial socket: Salamander wraps the runtime socket, and Gecko wraps the
/// Salamander socket (frames are shaped before each one is salt-wrapped).
fn client_endpoint(
    server_addr: SocketAddr,
    obfs: &ObfsSpec<'_>,
) -> Result<quinn::Endpoint, NativeError> {
    let bind: SocketAddr = if server_addr.is_ipv6() {
        "[::]:0".parse().expect("static ipv6 bind addr")
    } else {
        "0.0.0.0:0".parse().expect("static ipv4 bind addr")
    };

    let (psk, gecko) = match *obfs {
        ObfsSpec::None => return Ok(crate::transport::quic::client_endpoint(server_addr)),
        ObfsSpec::Salamander { psk } => (psk, None),
        ObfsSpec::Gecko { psk, min, max } => (psk, Some((min, max))),
    };
    let sal = Salamander::new(psk)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| NativeError::Dial("no quinn runtime configured".into()))?;
    let inner_u8 = std::net::UdpSocket::bind(bind)?;
    let inner = runtime.wrap_udp_socket(inner_u8)?;
    let salamander: Arc<dyn quinn::AsyncUdpSocket> = Arc::new(SalamanderSocket { inner, sal });
    let sock: Arc<dyn quinn::AsyncUdpSocket> = match gecko {
        Some((min, max)) => Arc::new(GeckoSocket::new(salamander, min, max)),
        None => salamander,
    };
    Ok(quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        sock,
        runtime,
    )?)
}

/// A UDP socket that obfuscates every QUIC datagram with Salamander.
struct SalamanderSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    sal: Salamander,
}

impl std::fmt::Debug for SalamanderSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SalamanderSocket")
            .field("sal", &"<salamander obfuscator>")
            .finish_non_exhaustive()
    }
}

impl quinn::AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        // Reuse a thread-local scratch buffer to avoid per-datagram
        // allocation on the hot path (QUIC datagrams are sent frequently).
        thread_local! {
            static SEND_SCRATCH: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
        }
        let len = SALT_LEN + transmit.contents.len();
        SEND_SCRATCH.with(|scratch| {
            let mut buf = scratch.borrow_mut();
            buf.resize(len, 0);
            let salt = random_salt();
            self.sal.obfuscate_into(&salt, transmit.contents, &mut buf);
            let ob = quinn::udp::Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &buf[..len],
                segment_size: transmit.segment_size,
                src_ip: transmit.src_ip,
            };
            self.inner.try_send(&ob)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let ready = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(n)) = ready {
            for i in 0..n {
                let len = meta[i].len;
                // Salt, move the payload left by 8, XOR in place: no scratch
                // copy on the receive path.
                match self.sal.deobfuscate_in_place(&mut bufs[i][..len]) {
                    Some(plain) => meta[i].len = plain,
                    None => meta[i].len = 0,
                }
            }
        }
        ready
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// Shapes QUIC long-header datagrams into Gecko fragments above a Salamander
/// socket; short headers (data phase) pass straight through.
///
/// Send: a long header becomes `2..=8` padded frames, each handed to the
/// inner socket separately so every frame gets its own Salamander salt.
/// Receive: unframed datagrams pass through; frames are reassembled by
/// `(peer, msgID)` until one completes.
struct GeckoSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    min: u16,
    max: u16,
    next_msg: AtomicU8,
    reassembler: Mutex<GeckoReassembler>,
}

impl std::fmt::Debug for GeckoSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeckoSocket")
            .field("inner", &self.inner)
            .field("min", &self.min)
            .field("max", &self.max)
            .field("next_msg", &self.next_msg.load(Ordering::Relaxed))
            .field("in_flight", &self.reassembler.lock().map(|r| r.in_flight()))
            .finish()
    }
}

impl GeckoSocket {
    fn new(inner: Arc<dyn quinn::AsyncUdpSocket>, min: u16, max: u16) -> Self {
        Self {
            inner,
            min,
            max,
            next_msg: AtomicU8::new(0),
            reassembler: Mutex::new(GeckoReassembler::new()),
        }
    }
}

impl quinn::AsyncUdpSocket for GeckoSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let Some(&first) = transmit.contents.first() else {
            return Ok(());
        };
        if first & gecko::FLAG_FRAGMENT == 0 {
            // Short header (data phase): Salamander alone, as upstream.
            return self.inner.try_send(transmit);
        }
        let total = gecko::fragment_count(u32_below(u32::from(
            gecko::MAX_CHUNKS - gecko::MIN_CHUNKS + 1,
        )));
        // A fresh id per transmit attempt: a partial burst retransmits under a
        // new id, and the orphan expires at the receiver's TTL.
        let msg_id = self.next_msg.fetch_add(1, Ordering::Relaxed);
        thread_local! {
            static FRAME_SCRATCH: std::cell::RefCell<Vec<u8>> =
                const { std::cell::RefCell::new(Vec::new()) };
        }
        FRAME_SCRATCH.with(|scratch| {
            let mut buf = scratch.borrow_mut();
            for idx in 0..total {
                let chunk =
                    &transmit.contents[gecko::chunk_range(transmit.contents.len(), total, idx)];
                let pad = gecko::pad_len(chunk.len(), self.min, self.max, u32_below(u32::MAX));
                let header = gecko::FrameHeader {
                    pad_len: pad,
                    msg_id,
                    chunk_idx: idx,
                    total_chunks: total,
                };
                buf.resize(gecko::FRAME_HEADER_LEN + usize::from(pad) + chunk.len(), 0);
                let frame_len = gecko::encode_frame_into(header, chunk, &mut buf, |pad| {
                    crate::rand::fill_nonsecret(pad);
                })
                .map_err(|e| io::Error::other(format!("gecko frame: {e:?}")))?;
                let frame = quinn::udp::Transmit {
                    destination: transmit.destination,
                    ecn: transmit.ecn,
                    contents: &buf[..frame_len],
                    // One datagram per transmit: the inner socket reports one
                    // segment, so no GSO coalescing exists to split.
                    segment_size: None,
                    src_ip: transmit.src_ip,
                };
                self.inner.try_send(&frame)?;
            }
            Ok(())
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                Poll::Ready(Ok(n)) => {
                    let kept = self.filter_batch(bufs, meta, n);
                    if kept > 0 {
                        return Poll::Ready(Ok(kept));
                    }
                    // Every datagram was consumed into reassembly; read on.
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

impl GeckoSocket {
    /// Keep pass-through and completed datagrams, drop buffered fragments,
    /// compacting in place so no extra buffer is needed.
    // The reassembler lock is held for the whole batch on purpose: chunks
    // complete in arrival order, so dropping and retaking it between datagrams
    // could reorder a message against itself.
    #[allow(clippy::significant_drop_tightening)]
    fn filter_batch(
        &self,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
        n: usize,
    ) -> usize {
        let mut reassembler = self.reassembler.lock().expect("gecko reassembler lock");
        let now = Instant::now();
        let mut kept = 0;
        let mut assembled = [0_u8; gecko::MAX_PACKET];
        for i in 0..n {
            let len = meta[i].len;
            if len == 0 {
                continue;
            }
            if bufs[i][0] & gecko::FLAG_FRAGMENT == 0 {
                if kept != i {
                    let (dst, src) = bufs.split_at_mut(i);
                    if dst[kept].len() < len {
                        // The earlier slot cannot hold this datagram; drop it
                        // rather than panic. quinn's buffers are uniform, so
                        // this is a defensive branch.
                        continue;
                    }
                    dst[kept][..len].copy_from_slice(&src[0][..len]);
                    meta[kept] = meta[i];
                }
                kept += 1;
                continue;
            }
            let Ok((header, payload)) = gecko::decode_frame(&bufs[i][..len]) else {
                continue;
            };
            let Push::Complete(plain_len) =
                reassembler.push(meta[i].addr, header, payload, now, &mut assembled)
            else {
                continue;
            };
            if plain_len > bufs[kept].len() {
                // The destination cannot hold a reassembled packet; QUIC's
                // read buffer stays the ceiling.
                continue;
            }
            bufs[kept][..plain_len].copy_from_slice(&assembled[..plain_len]);
            meta[kept] = meta[i];
            meta[kept].len = plain_len;
            meta[kept].stride = plain_len;
            kept += 1;
        }
        kept
    }
}

// ── TCP tunnel ────────────────────────────────────────────────────────────

/// Open one TCP tunnel over a fresh QUIC bidi stream: write the `TCPRequest`
/// frame, read + validate the `TCPResponse`, then return the relay stream.
pub(super) async fn open_tcp_tunnel(
    conn: &quinn::Connection,
    keepalive: H3Keepalive,
    target: &TargetAddr,
) -> Result<H2Stream, NativeError> {
    let (send, recv) = {
        let limit = timeouts::PROTOCOL;
        tokio::time::timeout(limit, conn.open_bi())
            .await
            .map_err(|_| NativeError::Timeout {
                step: "hysteria2 open stream",
                limit,
            })?
            .map_err(|e| NativeError::Protocol {
                kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
                detail: format!("open stream: {e}"),
            })?
    };

    // TCPRequest: `0x401 | addrLen | addr | padLen | padding`.
    let addr = target_string(target);
    let padding = random_padding(64, 512);
    let mut frame = varint(FRAME_TYPE_TCP_REQUEST);
    frame.extend_from_slice(&varint(addr.len() as u64));
    frame.extend_from_slice(addr.as_bytes());
    frame.extend_from_slice(&varint(padding.len() as u64));
    frame.extend_from_slice(padding.as_bytes());

    let mut send = send;
    let limit = timeouts::PROTOCOL;
    tokio::time::timeout(
        limit,
        tokio::io::AsyncWriteExt::write_all(&mut send, &frame),
    )
    .await
    .map_err(|_| NativeError::Timeout {
        step: "hysteria2 tcp request write",
        limit,
    })?
    .map_err(|e| NativeError::Protocol {
        kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
        detail: format!("write tcp request: {e}"),
    })?;

    // TCPResponse: `status byte | msgLen | msg | padLen | padding`.
    //
    // ONE deadline for the whole response. The parse makes up to 19 reads
    // (status, two varints of up to 8 bytes, two payloads); a timer per read
    // would hand each of them a fresh `PROTOCOL` budget, so a stalling peer
    // could hold the connect open for ~19x the intended limit.
    let mut recv = recv;
    let limit = timeouts::PROTOCOL;
    let (status, msg) = tokio::time::timeout(limit, async {
        let mut head = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut head)
            .await
            .map_err(|e| NativeError::Protocol {
                kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
                detail: format!("read tcp response status: {e}"),
            })?;
        // Message + padding are always present, on both the OK and error paths
        // (`WriteTCPResponse` emits `status | msgLen | msg | padLen | padding`).
        let msg = read_vstring(&mut recv, "hysteria2 tcp response").await?;
        read_vstring(&mut recv, "hysteria2 tcp response padding").await?;
        Ok::<_, NativeError>((head[0], msg))
    })
    .await
    .map_err(|_| NativeError::Timeout {
        step: "hysteria2 tcp response read",
        limit,
    })??;

    if status != TCP_RESPONSE_OK {
        return Err(NativeError::Protocol {
            kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
            detail: format!("remote error: {msg}"),
        });
    }

    Ok(H2Stream::new(conn.clone(), keepalive, send, recv))
}

/// Read a single byte from the stream, EOF-mapped.
///
/// Deliberately untimed: every caller runs inside one `timeout` per protocol
/// message (see [`open_tcp_tunnel`]), so a per-byte timer would multiply the
/// effective deadline by the number of bytes read.
async fn read_exact_u8(
    recv: &mut quinn::RecvStream,
    step: &'static str,
) -> Result<u8, NativeError> {
    let mut b = [0u8; 1];
    tokio::io::AsyncReadExt::read_exact(recv, &mut b)
        .await
        .map_err(|e| NativeError::Protocol {
            kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
            detail: format!("{step}: {e}"),
        })?;
    Ok(b[0])
}

/// Read a QUIC varint from the stream: one leading byte selects the width
/// (1/2/4/8 by the top two bits), then the remaining bytes complete it in a
/// single read into a fixed 8-byte buffer.
async fn read_varint_stream(
    recv: &mut quinn::RecvStream,
    step: &'static str,
) -> Result<u64, NativeError> {
    let first = read_exact_u8(recv, step).await?;
    let width = match first >> 6 {
        0 => 1usize,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut raw = [0u8; 8];
    raw[0] = first;
    if width > 1 {
        tokio::io::AsyncReadExt::read_exact(recv, &mut raw[1..width])
            .await
            .map_err(|e| NativeError::Protocol {
                kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
                detail: format!("{step}: {e}"),
            })?;
    }
    read_varint(&raw[..width])
        .map(|(v, _)| v)
        .ok_or_else(|| NativeError::Protocol {
            kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
            detail: format!("{step}: malformed length"),
        })
}

/// Read a varint-length-prefixed string (message or padding) and return it
/// as owned bytes. Bounded by the protocol overflow guards and by the
/// caller's single per-message deadline (see [`read_exact_u8`]).
async fn read_vstring(
    recv: &mut quinn::RecvStream,
    step: &'static str,
) -> Result<String, NativeError> {
    let len_u64 = read_varint_stream(recv, step).await?;
    let len = usize::try_from(len_u64).map_err(|_| NativeError::Protocol {
        kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
        detail: format!("{step}: length overflow"),
    })?;
    if len > MAX_ADDRESS_LEN {
        return Err(NativeError::Protocol {
            kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
            detail: format!("{step}: invalid length {len}"),
        });
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        tokio::io::AsyncReadExt::read_exact(recv, &mut buf)
            .await
            .map_err(|e| NativeError::Protocol {
                kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
                detail: format!("{step}: {e}"),
            })?;
    }
    String::from_utf8(buf).map_err(|_| NativeError::Protocol {
        kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
        detail: format!("{step}: non-utf8 payload"),
    })
}

/// The hysteria2 TCP tunnel: a raw quinn bidi stream, kept alive by the
/// connection and h3-session handles it carries (dropping either closes the
/// underlying quinn connection).
pub(super) struct H2Stream {
    _conn: quinn::Connection,
    /// Keeps the h3 session alive (dropping it closes the quinn connection).
    _h3: H3Keepalive,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl H2Stream {
    const fn new(
        conn: quinn::Connection,
        keepalive: H3Keepalive,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Self {
        Self {
            _conn: conn,
            _h3: keepalive,
            send,
            recv,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        tokio::io::AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Host;
    use quinn::AsyncUdpSocket;

    #[test]
    fn varint_encoding() {
        assert_eq!(varint(0), vec![0]);
        assert_eq!(varint(63), vec![63]);
        assert_eq!(varint(64), vec![0x40, 0x40]);
        assert_eq!(varint(16_383), vec![0x7f, 0xff]);
        assert_eq!(varint(16_384), vec![0x80, 0x00, 0x40, 0x00]);
        // 0x401 = 1025: 2-byte form, high byte 0x40 | (1025 >> 8) = 0x44.
        assert_eq!(varint(FRAME_TYPE_TCP_REQUEST), vec![0x44, 0x01]);
    }

    #[test]
    fn varint_roundtrip() {
        for v in [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            0x3fff_ffff_ffff_ffff, // 2^62 - 1, the varint max
        ] {
            let enc = varint(v);
            let (got, rest) = read_varint(&enc).expect("decodes");
            assert_eq!(got, v);
            assert_eq!(rest.len(), 0);
        }
    }

    #[test]
    fn varint_len_matches_encoded_width() {
        // The sizing table must not drift from the encoder: a header sized
        // with the wrong varint width writes the payload at the wrong offset.
        for v in [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            0x3fff_ffff_ffff_ffff, // 2^62 - 1, the varint max
        ] {
            assert_eq!(varint_len(v), varint(v).len(), "width of {v}");
        }
    }

    #[test]
    fn target_string_formats() {
        assert_eq!(
            target_string(&TargetAddr::new(Host::Domain("example.com".into()), 443)),
            "example.com:443"
        );
        assert_eq!(
            target_string(&TargetAddr::new(Host::Ip("1.2.3.4".parse().unwrap()), 80)),
            "1.2.3.4:80"
        );
        assert_eq!(
            target_string(&TargetAddr::new(Host::Ip("::1".parse().unwrap()), 443)),
            "[::1]:443"
        );
    }

    /// A minimal hysteria2 config; `down` is what feeds `hysteria-cc-rx`.
    fn cfg_down(down: Option<&str>) -> Hysteria2Config {
        let mut obj = serde_json::json!({ "auth": "pw" });
        if let Some(d) = down {
            obj["down"] = serde_json::json!(d);
        }
        serde_json::from_value(obj).expect("hysteria2 config parses")
    }

    #[test]
    fn cc_rx_bps_from_down_bandwidth() {
        // 100 mbps = 12.5 MB/s on the wire (`AuthRequest.Rx` is bytes/sec).
        assert_eq!(cc_rx_bps(&cfg_down(Some("100mbps"))), 12_500_000);
        // Absent or unparsable = unknown, which the wire spells 0 (the
        // server then runs its own bandwidth detection).
        assert_eq!(cc_rx_bps(&cfg_down(None)), 0);
        assert_eq!(cc_rx_bps(&cfg_down(Some("fast"))), 0);
    }

    #[test]
    fn padding_len_in_range() {
        let p = random_padding(256, 2048);
        assert!((256..2048).contains(&p.len()), "len {}", p.len());
        assert!(p.bytes().all(|b| b.is_ascii_alphanumeric()));
        let p = random_padding(64, 512);
        assert!((64..512).contains(&p.len()));
    }

    // ── Gecko adapter (fake AsyncUdpSocket; no runtime, no sockets) ────────

    #[derive(Debug)]
    struct ReadyPoller;

    impl quinn::UdpPoller for ReadyPoller {
        fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Default)]
    struct FakeSocket {
        sent: Mutex<Vec<Vec<u8>>>,
        queued: Mutex<std::collections::VecDeque<(SocketAddr, Vec<u8>)>>,
        sends_left: std::sync::atomic::AtomicUsize,
    }

    impl FakeSocket {
        fn armed() -> Self {
            Self {
                sends_left: std::sync::atomic::AtomicUsize::new(usize::MAX),
                ..Self::default()
            }
        }
    }

    impl quinn::AsyncUdpSocket for FakeSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
            Box::pin(ReadyPoller)
        }

        fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
            if self
                .sends_left
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed)
                == 0
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.sent.lock().unwrap().push(transmit.contents.to_vec());
            Ok(())
        }

        // The queue lock is held across the drain on purpose: the fake has no
        // producer, so tightening it would only add churn.
        #[allow(clippy::significant_drop_tightening)]
        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            bufs: &mut [io::IoSliceMut<'_>],
            meta: &mut [quinn::udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let n = {
                let mut queued = self.queued.lock().unwrap();
                let mut n = 0;
                while let Some((addr, bytes)) = queued.pop_front() {
                    if n == bufs.len() || bytes.len() > bufs[n].len() {
                        queued.push_front((addr, bytes));
                        break;
                    }
                    bufs[n][..bytes.len()].copy_from_slice(&bytes);
                    meta[n] = quinn::udp::RecvMeta {
                        addr,
                        len: bytes.len(),
                        stride: bytes.len(),
                        ecn: None,
                        dst_ip: None,
                    };
                    n += 1;
                }
                n
            };
            if n == 0 {
                Poll::Pending
            } else {
                Poll::Ready(Ok(n))
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 443)))
        }

        fn max_transmit_segments(&self) -> usize {
            1
        }

        fn max_receive_segments(&self) -> usize {
            1
        }

        fn may_fragment(&self) -> bool {
            false
        }
    }

    const PEER: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);

    fn transmit(contents: &[u8]) -> quinn::udp::Transmit<'_> {
        quinn::udp::Transmit {
            destination: PEER,
            ecn: None,
            contents,
            segment_size: None,
            src_ip: None,
        }
    }

    #[test]
    fn gecko_short_header_sends_one_datagram() {
        let fake = Arc::new(FakeSocket::armed());
        let geo = GeckoSocket::new(fake.clone(), 512, 1200);
        let data = [0x40_u8, 1, 2, 3, 4];
        geo.try_send(&transmit(&data)).expect("send");
        let sent = fake.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], data, "short header is not framed");
    }

    fn reassemble_sent(sent: &[Vec<u8>]) -> Vec<u8> {
        let mut total: Option<u8> = None;
        let mut msg: Option<u8> = None;
        let mut chunks: Vec<(u8, Vec<u8>)> = Vec::new();
        for frame in sent {
            let (h, body) = gecko::decode_frame(frame).expect("frame decodes");
            assert_eq!(
                h.total_chunks,
                u8::try_from(sent.len()).expect("frame count fits u8")
            );
            assert_eq!(h.msg_id, *msg.get_or_insert(h.msg_id));
            assert_eq!(*total.get_or_insert(h.total_chunks), h.total_chunks);
            chunks.push((h.chunk_idx, body.to_vec()));
        }
        chunks.sort_by_key(|(idx, _)| *idx);
        chunks.iter().flat_map(|(_, b)| b.iter().copied()).collect()
    }

    #[test]
    fn gecko_long_header_fragments_within_bounds() {
        let fake = Arc::new(FakeSocket::armed());
        let geo = GeckoSocket::new(fake.clone(), 512, 1200);
        let mut packet = vec![0xc0_u8; 1200];
        packet[1..5].copy_from_slice(&1_u32.to_be_bytes());
        for (i, byte) in packet.iter_mut().enumerate().skip(5) {
            *byte = u8::try_from(i % 251).expect("mod 251 fits u8");
        }
        geo.try_send(&transmit(&packet)).expect("send");
        let sent: Vec<Vec<u8>> = fake.sent.lock().unwrap().clone();
        assert!(
            (usize::from(gecko::MIN_CHUNKS)..=usize::from(gecko::MAX_CHUNKS)).contains(&sent.len()),
            "frames {}",
            sent.len()
        );
        for frame in &sent {
            let (h, body) = gecko::decode_frame(frame).expect("frame decodes");
            assert_eq!(
                gecko::FRAME_HEADER_LEN + usize::from(h.pad_len) + body.len(),
                frame.len()
            );
            let base = 8 + gecko::FRAME_HEADER_LEN + body.len();
            if base <= 1200 {
                // The simulated salted size (the fake sits under Gecko, so
                // the 8-byte salt is not on these bytes).
                assert!(
                    (512..=1200).contains(&(8 + frame.len())),
                    "salted size {}",
                    8 + frame.len()
                );
            }
        }
        let joined = reassemble_sent(&sent);
        assert_eq!(joined, packet, "chunks reassemble to the original packet");

        // A second transmit uses a fresh msgID.
        geo.try_send(&transmit(&packet)).expect("send");
        let second_msg = {
            let all = fake.sent.lock().unwrap();
            gecko::decode_frame(&all[sent.len()])
                .expect("second burst decodes")
                .0
                .msg_id
        };
        assert_ne!(gecko::decode_frame(&sent[0]).unwrap().0.msg_id, second_msg);
    }

    #[test]
    fn gecko_send_would_block_propagates() {
        let fake = Arc::new(FakeSocket::armed());
        fake.sends_left
            .store(1, std::sync::atomic::Ordering::Relaxed);
        let geo = GeckoSocket::new(fake.clone(), 512, 1200);
        let mut packet = vec![0xc0_u8; 1200];
        packet[0] = 0xc0;
        let err = geo.try_send(&transmit(&packet)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(fake.sent.lock().unwrap().len(), 1, "one frame landed");
    }

    fn poll_once(
        geo: &GeckoSocket,
        buf: &mut [u8],
        meta: &mut quinn::udp::RecvMeta,
    ) -> Poll<io::Result<usize>> {
        let mut bufs = [io::IoSliceMut::new(buf)];
        let metas = std::slice::from_mut(meta);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        geo.poll_recv(&mut cx, &mut bufs, metas)
    }

    #[test]
    fn gecko_recv_passes_short_headers_and_reassembles_frames() {
        let fake = Arc::new(FakeSocket::armed());
        let geo = GeckoSocket::new(fake.clone(), 512, 1200);
        // Out-of-order three-chunk message, then an unframed datagram.
        let mut frames = Vec::new();
        for (idx, payload) in [
            (0_u8, b"aa".to_vec()),
            (1, b"bb".to_vec()),
            (2, b"cc".to_vec()),
        ] {
            let mut frame = [0u8; 16];
            let h = gecko::FrameHeader {
                pad_len: 0,
                msg_id: 9,
                chunk_idx: idx,
                total_chunks: 3,
            };
            let n = gecko::encode_frame_into(h, &payload, &mut frame, |_| {}).unwrap();
            frames.push(frame[..n].to_vec());
        }
        {
            let mut q = fake.queued.lock().unwrap();
            q.push_back((PEER, frames[2].clone()));
            q.push_back((PEER, frames[0].clone()));
            q.push_back((PEER, frames[1].clone()));
            q.push_back((PEER, vec![0x40, 9, 9]));
        }
        let mut buf = [0u8; 2048];
        let mut meta = quinn::udp::RecvMeta::default();
        let n = match poll_once(&geo, &mut buf, &mut meta) {
            Poll::Ready(Ok(n)) => n,
            other => panic!("poll: {other:?}"),
        };
        assert_eq!(n, 1, "only the completed packet is delivered");
        assert_eq!(&buf[..6], b"aabbcc");
        assert_eq!(meta.len, 6);
        // The unframed datagram follows on the next poll.
        let n = match poll_once(&geo, &mut buf, &mut meta) {
            Poll::Ready(Ok(n)) => n,
            other => panic!("poll: {other:?}"),
        };
        assert_eq!(n, 1);
        assert_eq!(&buf[..3], &[0x40, 9, 9]);
    }

    #[test]
    fn gecko_recv_drops_malformed_frames_and_reports_pending() {
        let fake = Arc::new(FakeSocket::armed());
        let geo = GeckoSocket::new(fake.clone(), 512, 1200);
        fake.queued
            .lock()
            .unwrap()
            .push_back((PEER, vec![0x80, 0, 0, 0, 0]));
        let mut buf = [0u8; 2048];
        let mut meta = quinn::udp::RecvMeta::default();
        assert!(matches!(
            poll_once(&geo, &mut buf, &mut meta),
            Poll::Pending
        ));
    }
}
