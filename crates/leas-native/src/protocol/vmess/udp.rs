//! `VMess` UDP packet connection (command 0x02).
//!
//! `VMess` UDP rides the AEAD record tunnel with NO per-packet address: the
//! request-header destination is the session target and each datagram is
//! one AEAD record (`2B ciphertext-length | AES-128-GCM(...)`) — xray
//! `EncodeRequestBody` chunk writer (`crypto.NewChunkWriter`), sing-vmess
//! `DialEarlyPacketConn`. The [`super::stream::VmessClientStream`] already
//! peels the AEAD response header and codes records in both directions; the
//! record boundary IS the datagram boundary, so this wrapper is just a
//! datagram view over it: one record = one datagram, and one `recv` serves
//! exactly one record's plaintext.
//!
//! The send side goes through
//! [`super::stream::VmessClientStream::write_datagram`] rather than the
//! `AsyncWrite` byte contract: a datagram must never inherit the record — or
//! the reported length — of a cancelled write.
//!
//! The read side returns `Ok(None)` on the end markers xray writes to close
//! a stream (`field == 0` / `field == 16`, Go `size == auth.Overhead()`) or
//! a clean EOF at a record boundary.

use std::io;
use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadHalf, WriteHalf};

use crate::addr::{Host, TargetAddr};
use crate::protocol::vmess::stream::{
    MAX_RECORD_PLAINTEXT, VmessClientStream, VmessReadHalf, VmessWriteHalf,
};

/// Send cap — xray's CHUNK cap, not the u16 framing limit: the chunk sealer
/// refuses a record whose full wire size overflows one 8192-byte buffer,
/// `sizeBytes + encryptedSize + paddingSize <= buf.Size` (Xray-core
/// `common/crypto/auth.go:249-262`, `common/buf/buffer.go:13`). Our request
/// option byte is 0, so the size parser is `PlainChunkSizeParser` (2 bytes)
/// and padding is nil (`proxy/vmess/encoding/client.go:104-137`):
/// `2 + (len + 16) + 0 <= 8192`, i.e. `len <= 8174`.
///
/// A larger record would not reach the target as ONE datagram either: the
/// peer's reader takes the oversize branch, where `MergeBytes` splits the
/// plaintext into `buf.Size` buffers (`common/crypto/auth.go:179-202`,
/// `common/buf/multi_buffer.go:39-54`), and the outbound writes one datagram
/// per buffer (`proxy/freedom/freedom.go:586-593`) — the datagram boundary is
/// silently lost. Same 8192 rationale as the trojan sibling's
/// `MAX_UDP_PAYLOAD`.
const MAX_SEND_PAYLOAD: usize = 8192 - 2 - 16;

/// Receive-direction state: the staging buffer one record's plaintext lands
/// in, grown once to the record ceiling and reused — the caller gets a
/// `Bytes` slice of the datagram, never a freshly zeroed 64 KiB buffer plus
/// an exact-size copy.
struct RecvState {
    scratch: BytesMut,
}

impl RecvState {
    /// The ONE receive implementation, over the combined tunnel or its read
    /// half: one record's plaintext per call, `Ok(None)` on a clean
    /// end-of-stream (the record end markers or EOF — the tunnel reports both
    /// as a 0-byte read). The destination is `None`: the header target is the
    /// session destination (no per-packet address on the `VMess` UDP wire).
    async fn recv_from<R: AsyncRead + Unpin>(
        &mut self,
        inner: &mut R,
    ) -> io::Result<Option<(Option<SocketAddr>, Bytes)>> {
        if self.scratch.len() < MAX_RECORD_PLAINTEXT {
            // Grown once, on the first datagram: a peer may legitimately
            // fill a whole record, and one read serves exactly one record.
            // The consumed prefix is re-zeroed here on regrow (memset, no
            // allocation) — the buffer itself is never reallocated.
            self.scratch.resize(MAX_RECORD_PLAINTEXT, 0);
        }
        let n = inner.read(&mut self.scratch).await?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some((None, self.scratch.split_to(n).freeze())))
    }
}

/// Send-direction state: the destination every datagram of this session
/// lands on.
struct SendState {
    /// The request-header destination in comparable form: `Some(addr)` when
    /// the header carried an IP destination. A record carries no address, so
    /// that destination is the ONLY one this tunnel reaches and a `send`
    /// naming a different one is refused instead of silently mis-routed.
    /// `None` when the header destination has no `SocketAddr` form (a domain
    /// target) — then there is nothing an explicit destination could match.
    header_dest: Option<SocketAddr>,
}

impl SendState {
    /// Vet a datagram before a byte is sealed — the ONE send precondition,
    /// shared by the combined conn and the write half: the destination must
    /// be reachable (`check_dest`) and the payload must fit xray's chunk cap
    /// (`MAX_SEND_PAYLOAD`).
    fn check(&self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        self.check_dest(dest)?;
        if payload.len() > MAX_SEND_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "vmess udp datagram too large ({} bytes, max {MAX_SEND_PAYLOAD})",
                    payload.len()
                ),
            ));
        }
        Ok(())
    }

    /// Refuses a datagram bound for anything but the request-header
    /// destination.
    ///
    /// A `VMess` UDP record carries no address, so the header destination is
    /// the only one reachable: `None` names it and always succeeds, and an
    /// explicit `Some(dest)` is accepted only when it IS that destination. A
    /// domain header destination has no `SocketAddr` form to compare against,
    /// so any explicit destination is refused — a visible `InvalidInput`
    /// beats a datagram silently delivered to the header destination instead.
    fn check_dest(&self, dest: Option<SocketAddr>) -> io::Result<()> {
        let Some(dest) = dest else { return Ok(()) };
        if self.header_dest == Some(dest) {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "vmess udp: destination {dest} is not the request-header destination (vmess records carry no per-packet address)"
            ),
        ))
    }
}

/// A `VMess` UDP connection over the AEAD record tunnel (command 0x02).
///
/// Datagrams are the record stream itself — no additional framing, no
/// per-packet address (the header destination is the session target).
pub struct PacketConn<S> {
    inner: VmessClientStream<S>,
    read: RecvState,
    write: SendState,
}

/// The halves [`PacketConn::split`] hands out: the record decoder over the
/// transport's read half, the record sealer over its write half.
pub type SplitHalves<S> = (PacketReader<ReadHalf<S>>, PacketWriter<WriteHalf<S>>);

impl<S: AsyncRead + AsyncWrite + Unpin> PacketConn<S> {
    /// Wrap the record tunnel (the command-0x02 request header already
    /// written and the AEAD response header peeled on first read by
    /// [`super::stream::VmessClientStream`]). `header_dest` is the
    /// destination that request header carried — the session target.
    #[must_use]
    pub fn new(inner: VmessClientStream<S>, header_dest: &TargetAddr) -> Self {
        Self {
            inner,
            read: RecvState {
                scratch: BytesMut::new(),
            },
            write: SendState {
                header_dest: match &header_dest.host {
                    Host::Ip(ip) => Some(SocketAddr::new(*ip, header_dest.port)),
                    Host::Domain(_) => None,
                },
            },
        }
    }

    /// Send one datagram: exactly one sealed record on the wire.
    ///
    /// `dest: None` names the request-header destination — where every
    /// `VMess` UDP datagram lands, since the record carries no address.
    /// `Some(addr)` is accepted only when it IS that destination, and refused
    /// with `InvalidInput` otherwise (`check_dest`).
    ///
    /// The payload must fit xray's chunk cap (`MAX_SEND_PAYLOAD`); a larger
    /// datagram is refused before a byte is written.
    pub async fn send(&mut self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        self.write.check(dest, payload)?;
        // One record = one datagram. `write_datagram` (not the `AsyncWrite`
        // byte contract) reports success only for the record it sealed here,
        // so a cancelled send cannot truncate this one.
        self.inner.write_datagram(payload).await
    }

    /// Receive one datagram — one record's plaintext, sliced out of the
    /// reused staging buffer at exactly its size. `Ok(None)` on a clean
    /// end-of-stream (the record end markers or EOF). The destination is
    /// `None`: the header target is the session destination (no per-packet
    /// address on the `VMess` UDP wire).
    pub async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Bytes)>> {
        self.read.recv_from(&mut self.inner).await
    }

    /// Split into halves that may be used concurrently from separate tasks —
    /// a dedicated reader task can hold a `recv` across polls while sends
    /// keep going, which the combined conn cannot serve.
    ///
    /// Always `Ok` for `VMess`: the record tunnel has a counter, a cipher and
    /// its own staging per direction, so the two directions separate without
    /// sharing anything but the transport.
    pub fn split(self) -> io::Result<SplitHalves<S>> {
        let (read_half, write_half) = self.inner.split();
        Ok((
            PacketReader {
                inner: read_half,
                read: self.read,
            },
            PacketWriter {
                inner: write_half,
                write: self.write,
            },
        ))
    }
}

/// The receive half of a split [`PacketConn`]: the record decoder over the
/// read half of the transport, driven independently of any send.
pub struct PacketReader<R> {
    inner: VmessReadHalf<R>,
    read: RecvState,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    /// Receive one datagram — identical to [`PacketConn::recv`]: one record's
    /// plaintext at exactly its size, `Ok(None)` on a clean end-of-stream,
    /// and `None` as the destination.
    ///
    /// Cancel-safe: every partial fill lives in the read half's state, so a
    /// dropped `recv` future leaves a half-arrived record exactly where it
    /// was and the next call finishes it.
    pub async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Bytes)>> {
        self.read.recv_from(&mut self.inner).await
    }
}

/// The send half of a split [`PacketConn`]: the record sealer over the write
/// half of the transport.
pub struct PacketWriter<W> {
    inner: VmessWriteHalf<W>,
    write: SendState,
}

impl<W: AsyncWrite + Unpin> PacketWriter<W> {
    /// Send one datagram — identical to [`PacketConn::send`]: the same
    /// destination check, the same `MAX_SEND_PAYLOAD` refusal, and the same
    /// datagram write path (never the `AsyncWrite` byte contract), so a
    /// datagram cannot inherit a cancelled write's record.
    pub async fn send(&mut self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        self.write.check(dest, payload)?;
        self.inner.write_datagram(payload).await
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use parking_lot::Mutex;
    use tokio::io::{AsyncWriteExt, ReadBuf};

    use super::*;
    use crate::protocol::vmess::header::{SECURITY_AES128_GCM, Session};
    use crate::protocol::vmess::keys::kdf16_bytes_path;

    /// The destination the request header carried in these tests.
    fn session_target() -> TargetAddr {
        TargetAddr::new("127.0.0.1", 1080)
    }

    /// The same destination in the form `send` takes.
    fn session_dest() -> SocketAddr {
        "127.0.0.1:1080".parse().expect("a literal socket address")
    }

    /// A session plus a field-identical copy (`Session` is not `Clone`): one
    /// for the stream under test, one for the fake server to seal with.
    fn twin_session() -> (Session, Session) {
        let mut session = Session::new();
        session.security = SECURITY_AES128_GCM;
        session.response_header = 0x33;
        let mut twin = Session::new();
        twin.request_body_iv = session.request_body_iv;
        twin.request_body_key = session.request_body_key;
        twin.response_header = session.response_header;
        twin.response_body_key = session.response_body_key;
        twin.response_body_iv = session.response_body_iv;
        twin.security = session.security;
        (session, twin)
    }

    /// Server-side response header seal (mirrors the `stream.rs` test
    /// helper): `lenAEAD(18) + payloadAEAD(len+16)`, AES-128-GCM, nonce =
    /// KDF [:12], payload = `[echo byte][option]`.
    fn seal_response_header(key: &[u8; 16], iv: &[u8; 16], payload: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes128Gcm, KeyInit};
        fn ae(key: &[u8; 16], iv: &[u8; 16], key_salt: &str, iv_salt: &str, msg: &[u8]) -> Vec<u8> {
            let k = kdf16_bytes_path(key, &[key_salt.as_bytes()]);
            let v = kdf16_bytes_path(iv, &[iv_salt.as_bytes()]);
            Aes128Gcm::new_from_slice(&k)
                .unwrap()
                .encrypt((&v[..12]).try_into().unwrap(), Payload { msg, aad: &[] })
                .unwrap()
        }
        let mut wire = ae(
            key,
            iv,
            "AEAD Resp Header Len Key",
            "AEAD Resp Header Len IV",
            &u16::try_from(payload.len()).unwrap().to_be_bytes(),
        );
        wire.extend_from_slice(&ae(
            key,
            iv,
            "AEAD Resp Header Key",
            "AEAD Resp Header IV",
            payload,
        ));
        wire
    }

    /// Server-side record seal: `[2B BE ciphertext len][AES-128-GCM]` with
    /// the counter nonce.
    fn seal_record(key: &[u8; 16], iv: &[u8; 16], counter: u16, data: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes128Gcm, KeyInit};
        let mut nonce = *iv;
        nonce[..2].copy_from_slice(&counter.to_be_bytes());
        let ct = Aes128Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(
                (&nonce[..12]).try_into().unwrap(),
                Payload {
                    msg: data,
                    aad: &[],
                },
            )
            .unwrap();
        let field = u16::try_from(data.len() + 16).unwrap();
        let mut wire = field.to_be_bytes().to_vec();
        wire.extend_from_slice(&ct);
        wire
    }

    /// Inverse of [`seal_record`] over raw wire bytes: opens the record at
    /// the start of `wire` with `counter`, returning its plaintext and the
    /// number of wire bytes the record occupied.
    fn open_record(key: &[u8; 16], iv: &[u8; 16], counter: u16, wire: &[u8]) -> (Vec<u8>, usize) {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes128Gcm, KeyInit};
        let field = usize::from(u16::from_be_bytes([wire[0], wire[1]]));
        let mut nonce = *iv;
        nonce[..2].copy_from_slice(&counter.to_be_bytes());
        let plain = Aes128Gcm::new_from_slice(key)
            .unwrap()
            .decrypt(
                (&nonce[..12]).try_into().unwrap(),
                Payload {
                    msg: &wire[2..2 + field],
                    aad: &[],
                },
            )
            .expect("the record opens with the request keys at this counter");
        (plain, 2 + field)
    }

    /// A record tunnel whose peer is a duplex the test drives. Returns the
    /// `PacketConn`, the server half, and the server's view of the session
    /// (for sealing/opening records).
    fn record_stream(
        capacity: usize,
    ) -> (
        PacketConn<crate::BoxStream>,
        tokio::io::DuplexStream,
        Session,
    ) {
        let (client, server) = tokio::io::duplex(capacity);
        let (session, server_view) = twin_session();
        let client: crate::BoxStream = Box::new(client);
        (
            PacketConn::new(VmessClientStream::new(client, session), &session_target()),
            server,
            server_view,
        )
    }

    /// A writer with a byte budget: `poll_write` accepts at most `budget`
    /// bytes, then parks WITHOUT registering a waker. The test's
    /// `tokio::time::timeout` is the only other event, so the parked `send`
    /// is dropped exactly where the cancel-safety bug lives — record sealed,
    /// flush unfinished.
    struct BudgetWriter {
        budget: Arc<AtomicUsize>,
        wire: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for BudgetWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let budget = self.budget.load(Ordering::SeqCst);
            if budget == 0 {
                return Poll::Pending;
            }
            let n = buf.len().min(budget);
            self.budget.store(budget - n, Ordering::SeqCst);
            self.wire.lock().extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for BudgetWriter {
        /// Nothing ever arrives: these tests drive the write side only.
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// A `PacketConn` over a [`BudgetWriter`]: the conn, the budget handle,
    /// the wire bytes it accepted, and the session view to open records with.
    type BudgetedConn = (
        PacketConn<BudgetWriter>,
        Arc<AtomicUsize>,
        Arc<Mutex<Vec<u8>>>,
        Session,
    );

    fn budgeted_conn(budget: usize) -> BudgetedConn {
        let budget = Arc::new(AtomicUsize::new(budget));
        let wire = Arc::new(Mutex::new(Vec::new()));
        let (session, server_view) = twin_session();
        let writer = BudgetWriter {
            budget: Arc::clone(&budget),
            wire: Arc::clone(&wire),
        };
        (
            PacketConn::new(VmessClientStream::new(writer, session), &session_target()),
            budget,
            wire,
            server_view,
        )
    }

    #[tokio::test]
    async fn send_writes_one_record() {
        let (mut conn, mut server, view) = record_stream(4096);
        conn.send(None, b"hi").await.unwrap();
        // The peer sees ONE `[2B len][AEAD]` record, sealed with the request
        // keys at counter 0, whose plaintext is the datagram.
        let mut got = vec![0u8; 64];
        let n = server.read(&mut got).await.unwrap();
        let (payload, used) = open_record(&view.request_body_key, &view.request_body_iv, 0, &got);
        assert_eq!(payload, b"hi");
        assert_eq!(n, used, "exactly one record per send");
    }

    #[tokio::test]
    async fn recv_yields_one_datagram_per_record() {
        let (mut conn, mut server, view) = record_stream(4096);
        // ONE flight: the AEAD response header (echo byte 0x33 + option 0),
        // then TWO records whose counters increment (Go `GenerateChunkNonce`).
        let mut flight =
            seal_response_header(&view.response_body_key, &view.response_body_iv, &[0x33, 0]);
        flight.extend_from_slice(&seal_record(
            &view.response_body_key,
            &view.response_body_iv,
            0,
            b"hey",
        ));
        flight.extend_from_slice(&seal_record(
            &view.response_body_key,
            &view.response_body_iv,
            1,
            b"and again",
        ));
        server.write_all(&flight).await.unwrap();

        // The record boundary IS the datagram boundary: two records buffered
        // in one flight come back as two datagrams, never concatenated.
        let (dest, first) = conn.recv().await.unwrap().expect("the first datagram");
        assert_eq!(dest, None);
        assert_eq!(&first[..], b"hey");
        // No exact-size copy anymore: the datagram is a slice of the reused
        // staging buffer, so capacity stays at the record ceiling.
        assert_eq!(first.len(), b"hey".len());
        let (dest, second) = conn.recv().await.unwrap().expect("the second datagram");
        assert_eq!(dest, None);
        assert_eq!(&second[..], b"and again");
    }

    #[tokio::test]
    async fn recv_clean_eof_is_none() {
        let (mut conn, mut server, view) = record_stream(4096);
        // The peer must finish the AEAD response header first (a clean EOF
        // mid-peel is an error, not end-of-stream); then closing yields
        // `Ok(None)` at the first record boundary.
        let header =
            seal_response_header(&view.response_body_key, &view.response_body_iv, &[0x33, 0]);
        server.write_all(&header).await.unwrap();
        drop(server);
        assert!(conn.recv().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn send_cap_is_xrays_chunk_cap() {
        // `sizeBytes(2) + encryptedSize(len + 16) + paddingSize(0) <=
        // buf.Size(8192)` (auth.go `seal`) — the largest record xray will
        // seal must go out, one byte more must not.
        assert_eq!(MAX_SEND_PAYLOAD, 8174);
        let wire_len = 2 + MAX_SEND_PAYLOAD + 16;
        let (mut conn, mut server, view) = record_stream(wire_len);

        let err = conn
            .send(None, &vec![0u8; MAX_SEND_PAYLOAD + 1])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // The refusal wrote nothing and consumed no record counter, so the
        // next datagram is still record 0 — and the cap itself is allowed.
        conn.send(None, &vec![0xAB; MAX_SEND_PAYLOAD])
            .await
            .unwrap();
        let mut wire = vec![0u8; wire_len];
        server.read_exact(&mut wire).await.unwrap();
        let (payload, used) = open_record(&view.request_body_key, &view.request_body_iv, 0, &wire);
        assert_eq!(used, wire_len, "the cap fits one 8192-byte chunk exactly");
        assert_eq!(payload, vec![0xAB; MAX_SEND_PAYLOAD]);
    }

    #[tokio::test]
    async fn send_takes_none_or_the_header_destination_only() {
        let (mut conn, mut server, view) = record_stream(4096);
        // `None` names the request-header destination.
        conn.send(None, b"header-dest").await.unwrap();
        // The same destination spelled out is that destination.
        conn.send(Some(session_dest()), b"explicit").await.unwrap();
        // Anything else is unreachable — a record carries no address.
        let elsewhere = conn
            .send(Some("10.0.0.1:1080".parse().unwrap()), b"nope")
            .await
            .unwrap_err();
        assert_eq!(elsewhere.kind(), io::ErrorKind::InvalidInput);
        // ... including the same host on another port.
        let other_port = conn
            .send(Some(SocketAddr::new(session_dest().ip(), 1081)), b"nope")
            .await
            .unwrap_err();
        assert_eq!(other_port.kind(), io::ErrorKind::InvalidInput);

        // Only the two accepted datagrams reached the wire, in counter order.
        drop(conn);
        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        let (first, used) = open_record(&view.request_body_key, &view.request_body_iv, 0, &wire);
        assert_eq!(first, b"header-dest");
        let (second, used2) = open_record(
            &view.request_body_key,
            &view.request_body_iv,
            1,
            &wire[used..],
        );
        assert_eq!(second, b"explicit");
        assert_eq!(used + used2, wire.len(), "the refusals wrote nothing");
    }

    #[tokio::test]
    async fn send_refuses_an_explicit_destination_for_a_domain_target() {
        let (client, _server) = tokio::io::duplex(4096);
        let (session, _view) = twin_session();
        let client: crate::BoxStream = Box::new(client);
        let mut conn = PacketConn::new(
            VmessClientStream::new(client, session),
            &TargetAddr::new("example.com", 443),
        );
        // A domain header destination has no `SocketAddr` form, so an
        // explicit destination cannot be proven to be it.
        let err = conn
            .send(Some("93.184.216.34:443".parse().unwrap()), b"x")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // `None` still names the header destination and works.
        conn.send(None, b"x").await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_send_is_not_resurrected_by_the_next_one() {
        let (mut conn, budget, wire, view) = budgeted_conn(0);
        // The writer accepts nothing: this `send` seals its record, parks
        // mid-flush, and the timeout drops the future.
        assert!(
            tokio::time::timeout(Duration::from_secs(1), conn.send(None, b"cancelled"))
                .await
                .is_err(),
            "the stalled writer must park the send"
        );
        assert!(
            wire.lock().is_empty(),
            "not a byte of the cancelled datagram reached the wire"
        );

        // The wire opens. The abandoned record never travelled, so the next
        // datagram is the ONLY record on the wire and still carries counter 0
        // — the record stream stays in sync with the peer. (The `write_all`
        // path instead flushed the abandoned record and reported ITS length
        // for this payload, truncating the datagram.)
        budget.store(usize::MAX, Ordering::SeqCst);
        conn.send(None, b"fresh").await.unwrap();
        let raw = wire.lock().clone();
        let (payload, used) = open_record(&view.request_body_key, &view.request_body_iv, 0, &raw);
        assert_eq!(payload, b"fresh");
        assert_eq!(used, raw.len(), "exactly one record on the wire");
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_send_already_on_the_wire_is_completed_once() {
        // 5 bytes of budget: the record (2 + 9 + 16 = 27 bytes) is partly on
        // the wire when the writer parks, so the peer is mid-record when the
        // timeout drops the future.
        let (mut conn, budget, wire, view) = budgeted_conn(5);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), conn.send(None, b"first-one"))
                .await
                .is_err(),
            "the budgeted writer must park the send mid-record"
        );
        assert_eq!(
            wire.lock().len(),
            5,
            "a fragment of the record is on the wire"
        );

        // A half-written record cannot be dropped — the peer is inside it —
        // so it is completed first and this payload becomes its own record
        // with the next counter. Neither is duplicated or truncated.
        budget.store(usize::MAX, Ordering::SeqCst);
        conn.send(None, b"second").await.unwrap();
        let raw = wire.lock().clone();
        let (first, used) = open_record(&view.request_body_key, &view.request_body_iv, 0, &raw);
        assert_eq!(first, b"first-one");
        let (second, used2) = open_record(
            &view.request_body_key,
            &view.request_body_iv,
            1,
            &raw[used..],
        );
        assert_eq!(second, b"second");
        assert_eq!(used + used2, raw.len(), "two records, nothing duplicated");
    }

    /// The datagrams every split-vs-unsplit comparison replays.
    const DATAGRAMS: [&[u8]; 3] = [b"one", b"two-two", b"three-three-three"];

    /// The peer's whole response flight for [`DATAGRAMS`]: the AEAD response
    /// header, then one record per datagram with incrementing counters.
    fn response_flight(view: &Session) -> Vec<u8> {
        let mut flight =
            seal_response_header(&view.response_body_key, &view.response_body_iv, &[0x33, 0]);
        for (counter, payload) in DATAGRAMS.iter().enumerate() {
            flight.extend_from_slice(&seal_record(
                &view.response_body_key,
                &view.response_body_iv,
                u16::try_from(counter).expect("three records"),
                payload,
            ));
        }
        flight
    }

    /// Every request record on `wire`, opened in counter order — the peer's
    /// view of what a sender put out.
    fn open_flight(view: &Session, wire: &[u8]) -> Vec<Vec<u8>> {
        let mut rest = wire;
        let mut counter = 0u16;
        let mut records = Vec::new();
        while !rest.is_empty() {
            let (payload, used) =
                open_record(&view.request_body_key, &view.request_body_iv, counter, rest);
            records.push(payload);
            rest = &rest[used..];
            counter += 1;
        }
        records
    }

    #[tokio::test]
    async fn split_halves_round_trip_like_the_unsplit_conn() {
        // Reference run: the unsplit conn receives the flight and sends back.
        let (mut conn, mut server, unsplit_view) = record_stream(8192);
        server
            .write_all(&response_flight(&unsplit_view))
            .await
            .unwrap();
        let mut unsplit_recv = Vec::new();
        for _ in DATAGRAMS {
            unsplit_recv.push(conn.recv().await.unwrap().expect("a datagram"));
        }
        for payload in DATAGRAMS {
            conn.send(None, payload).await.unwrap();
        }
        drop(conn);
        let mut unsplit_wire = Vec::new();
        server.read_to_end(&mut unsplit_wire).await.unwrap();

        // The same traffic over the split halves.
        let (conn, mut server, split_view) = record_stream(8192);
        let (mut reader, mut writer) = conn.split().unwrap();
        server
            .write_all(&response_flight(&split_view))
            .await
            .unwrap();
        let mut split_recv = Vec::new();
        for _ in DATAGRAMS {
            split_recv.push(reader.recv().await.unwrap().expect("a datagram"));
        }
        for payload in DATAGRAMS {
            writer.send(None, payload).await.unwrap();
        }
        drop(writer);
        drop(reader);
        let mut split_wire = Vec::new();
        server.read_to_end(&mut split_wire).await.unwrap();

        // Identical payloads AND identical destinations, datagram for
        // datagram — the halves are the same view of the record stream.
        assert_eq!(split_recv, unsplit_recv);
        assert_eq!(
            split_recv
                .iter()
                .map(|(_, payload)| &payload[..])
                .collect::<Vec<_>>(),
            DATAGRAMS.to_vec()
        );
        // The sessions carry different random keys, so compare the records
        // the peer opens rather than the ciphertext: same plaintexts, same
        // counters, same framing sizes.
        assert_eq!(
            open_flight(&split_view, &split_wire),
            open_flight(&unsplit_view, &unsplit_wire)
        );
        assert_eq!(split_wire.len(), unsplit_wire.len());
    }

    #[tokio::test]
    async fn split_reader_receives_while_the_writer_sends() {
        let (conn, mut server, view) = record_stream(4096);
        let (mut reader, mut writer) = conn.split().unwrap();

        // The reader parks on an empty wire, mid-peel: nothing has arrived.
        let pending_recv = tokio::spawn(async move { reader.recv().await });
        tokio::task::yield_now().await;
        assert!(
            !pending_recv.is_finished(),
            "the reader must be parked on the empty wire"
        );

        // A datagram goes out while that read is still pending — the case the
        // unsplit conn cannot serve, since its `recv` future would have to be
        // dropped to reach `send`.
        writer.send(None, b"outbound").await.unwrap();
        let mut sent = vec![0u8; 2 + b"outbound".len() + 16];
        server.read_exact(&mut sent).await.unwrap();
        let (payload, used) = open_record(&view.request_body_key, &view.request_body_iv, 0, &sent);
        assert_eq!(payload, b"outbound");
        assert_eq!(used, sent.len(), "one record, whole and alone");

        // The peer answers: the read that was already pending completes.
        let mut flight =
            seal_response_header(&view.response_body_key, &view.response_body_iv, &[0x33, 0]);
        flight.extend_from_slice(&seal_record(
            &view.response_body_key,
            &view.response_body_iv,
            0,
            b"inbound",
        ));
        server.write_all(&flight).await.unwrap();
        let received = pending_recv
            .await
            .unwrap()
            .unwrap()
            .expect("the pending read completes");
        assert_eq!(received, (None, Bytes::from_static(b"inbound")));
    }

    /// A transport that counts the bytes it has handed to the tunnel — the
    /// evidence that a cancelled `recv` really did take a record's first
    /// chunk off the wire (and therefore had to keep it to stay in sync).
    struct CountingTransport {
        inner: tokio::io::DuplexStream,
        consumed: Arc<AtomicUsize>,
    }

    impl AsyncRead for CountingTransport {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buf.filled().len();
            let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
            if polled.is_ready() {
                self.consumed
                    .fetch_add(buf.filled().len() - before, Ordering::SeqCst);
            }
            polled
        }
    }

    impl AsyncWrite for CountingTransport {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn split_reader_recv_is_cancel_safe_mid_record() {
        let (client, mut server) = tokio::io::duplex(4096);
        let (session, view) = twin_session();
        let consumed = Arc::new(AtomicUsize::new(0));
        let transport = CountingTransport {
            inner: client,
            consumed: Arc::clone(&consumed),
        };
        let conn = PacketConn::new(
            VmessClientStream::new(transport, session),
            &session_target(),
        );
        let (mut reader, _writer) = conn.split().unwrap();

        // The response header, then a record cut in half: the first chunk
        // stops inside the record's ciphertext.
        let mut first_chunk =
            seal_response_header(&view.response_body_key, &view.response_body_iv, &[0x33, 0]);
        let record = seal_record(
            &view.response_body_key,
            &view.response_body_iv,
            0,
            b"one datagram, two chunks",
        );
        let cut = record.len() / 2;
        first_chunk.extend_from_slice(&record[..cut]);
        server.write_all(&first_chunk).await.unwrap();

        // Two cancelled `recv`s on the half-arrived record: each parks, so
        // the zero timeout drops it mid-frame.
        for _ in 0..2 {
            assert!(
                tokio::time::timeout(Duration::ZERO, reader.recv())
                    .await
                    .is_err(),
                "an incomplete record must park the recv, so the timeout drops it"
            );
        }
        // The dropped futures had already pulled the peel and the record's
        // first chunk off the wire — those bytes are unrecoverable from the
        // transport, so only the read half's own state can still hold them.
        assert_eq!(
            consumed.load(Ordering::SeqCst),
            first_chunk.len(),
            "the cancelled recvs consumed the whole first chunk"
        );

        // The rest arrives and the datagram comes back WHOLE — the regression
        // the split exists to prevent (a mid-frame cancellation losing bytes
        // and desynchronising the record stream).
        server.write_all(&record[cut..]).await.unwrap();
        let (dest, payload) = reader.recv().await.unwrap().expect("the whole datagram");
        assert_eq!(dest, None);
        assert_eq!(&payload[..], b"one datagram, two chunks");
        assert_eq!(
            consumed.load(Ordering::SeqCst),
            first_chunk.len() + record.len() - cut,
            "the completing recv read only the remainder — nothing was re-read"
        );
    }

    #[tokio::test]
    async fn split_reader_clean_eof_is_none() {
        let (conn, mut server, view) = record_stream(4096);
        let (mut reader, _writer) = conn.split().unwrap();
        // The peer finishes the AEAD response header, then closes at the
        // first record boundary.
        let header =
            seal_response_header(&view.response_body_key, &view.response_body_iv, &[0x33, 0]);
        server.write_all(&header).await.unwrap();
        drop(server);
        assert!(reader.recv().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn split_writer_keeps_the_destination_and_cap_refusals() {
        let (conn, mut server, view) = record_stream(4096);
        let (reader, mut writer) = conn.split().unwrap();

        let elsewhere = writer
            .send(Some("10.0.0.1:1080".parse().unwrap()), b"nope")
            .await
            .unwrap_err();
        assert_eq!(elsewhere.kind(), io::ErrorKind::InvalidInput);
        let oversize = writer
            .send(None, &vec![0u8; MAX_SEND_PAYLOAD + 1])
            .await
            .unwrap_err();
        assert_eq!(oversize.kind(), io::ErrorKind::InvalidInput);

        // The header destination spelled out is still accepted, and the
        // refusals wrote nothing — this is still record 0.
        writer
            .send(Some(session_dest()), b"accepted")
            .await
            .unwrap();
        drop(writer);
        drop(reader);
        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        let (payload, used) = open_record(&view.request_body_key, &view.request_body_iv, 0, &wire);
        assert_eq!(payload, b"accepted");
        assert_eq!(used, wire.len(), "the refusals wrote nothing");
    }
}
