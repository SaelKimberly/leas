//! Classic Shadowsocks AEAD (2017) TCP codec — client side.
//!
//! Wire (shadowsocks-rust `relay/tcprelay/aead.rs` — the source of the
//! diagram below — and mihomo `transport/shadowsocks/shadowaead/stream.go`):
//!
//! ```text
//! request : [salt][ [2B BE len][16B tag] [ct(payload)][16B tag] ]*
//! response: [salt][ [2B BE len][16B tag] [ct(payload)][16B tag] ]*
//! ```
//!
//! Each chunk is TWO AEAD seals under two consecutive counter nonces — the
//! 2-byte big-endian length first, then the payload — with `len ≤ 0x3FFF`
//! ([`MAX_CHUNK`]; the field's top two bits are reserved). Request and
//! response carry independent salt, subkey and counter: the client writes its
//! salt before the first chunk and reads the server's salt before the first
//! response chunk. The client's first payload is the target address in
//! Shadowsocks' SOCKS5-ATYP form — [`crate::addr::encode_addr_port_last`],
//! port last, which is NOT the VLESS/VMess port-first [`crate::addr::encode_addr`].
//!
//! A zero-length chunk is not a legal frame (mihomo `ErrZeroChunk`): this
//! codec never writes one and rejects one on read.
//!
//! The codec is a byte-stream transform over an already transport- and
//! security-wrapped stream, so every partial-read state (the salt, the open
//! length, the arriving payload) lives in [`SsStream`]: a cancelled
//! `poll_read` resumes where it stopped and never replays a counter nonce.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use leas_proto::proto_spec::{ProtocolKind, SsConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::BoxStream;
use crate::addr::TargetAddr;
use crate::addr::encode_addr_port_last;
use crate::context::LinkContext;
use crate::crypto::aead::{NonceCounter, SsAead};
use crate::error::{NativeError, timeouts};
use crate::protocol::ss::method::{SsFamily, SsMethod, password_key, stream_subkey};

/// Classic AEAD's payload cap: the length field's two top bits are reserved,
/// so one chunk carries at most this many plaintext bytes
/// (shadowsocks-rust `MAX_PACKET_SIZE`, mihomo `payloadSizeMask`).
pub const MAX_CHUNK: usize = 0x3FFF;

/// The BE length field that opens every chunk.
const LEN_FIELD: usize = 2;

/// The widest single chunk on the wire: `[2B len][tag][ct][tag]`.
const fn wire_chunk_len(aead: SsAead) -> usize {
    LEN_FIELD + aead.tag_len() + MAX_CHUNK + aead.tag_len()
}

/// Wire failures are the Shadowsocks [`ProtocolKind`]; the `AsyncRead`/
/// `AsyncWrite` seam can only carry `io::Error`, which wraps this as its
/// source so nothing above loses the classification.
fn chunk_error(detail: &str) -> NativeError {
    NativeError::Protocol {
        kind: ProtocolKind::Shadowsocks,
        detail: detail.to_owned(),
    }
}

/// Wrap a wire error for the byte-stream seam.
fn wire_error(error: NativeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// The error for a response that ends inside a frame.
///
/// Truncation is a wire failure like any other, so it carries the same
/// classification as the chunk failures: the seam's `io::Error` keeps the
/// `UnexpectedEof` kind the stream layer already relies on, and the
/// [`NativeError`] rides as its source.
fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        chunk_error("response stream truncated mid-chunk"),
    )
}

/// One direction's AEAD state: the subkey its own salt derived and the
/// little-endian counter every seal or open of that direction draws from.
///
/// The two directions share nothing but the cipher ([`SsStream::aead`]) — that
/// independence is the protocol's replay defence, so a salt/counter is never
/// carried across.
struct Half {
    subkey: Zeroizing<Vec<u8>>,
    counter: NonceCounter,
}

impl Half {
    fn new(method: SsMethod, key: &[u8], salt: &[u8]) -> Self {
        Self {
            subkey: stream_subkey(method, key, salt),
            counter: NonceCounter::new(method.aead.nonce_len()),
        }
    }
}

/// How far the read direction's current wire step has to arrive before it can
/// be opened.
#[derive(Debug, Clone, Copy)]
enum ReadStep {
    /// The server's salt — read once, then the reader [`Half`] exists.
    Salt,
    /// The `[2B len][tag]` length seal of the next chunk. Also the only state
    /// an end-of-stream may land on: a chunk boundary.
    Length,
    /// The `[ct(payload)][tag]` seal of a chunk whose length is already open.
    /// The length nonce is spent, so this survives a cancelled read.
    Body(usize),
}

/// A classic-AEAD Shadowsocks stream: the request direction seals chunks,
/// the response direction opens them, over one wrapped byte stream.
///
/// The first read consumes the server's salt and derives the reader half; the
/// salt given to the constructor leads the request stream. Both halves and
/// every partial-read step are struct state, so a cancelled `poll_read`
/// resumes on the byte it stopped at — no nonce is ever replayed.
pub struct SsStream<S> {
    inner: S,
    /// Cipher of both directions; only the key and nonce state differ.
    aead: SsAead,
    /// Method of the request direction, kept to derive the reader half once
    /// the server's salt arrives.
    method: SsMethod,
    /// Master key — needed until the server salt derives the reader subkey,
    /// then dropped (zeroized). `None` once both halves exist.
    key: Option<Zeroizing<Vec<u8>>>,
    write: Half,
    read: Option<Half>,
    /// Sealed bytes waiting for the transport; the salt leads them.
    out: Vec<u8>,
    out_pos: usize,
    /// Caller bytes whose chunk is already in `out` and not yet reported as
    /// consumed.
    ///
    /// The count is only correct for a retry with the SAME buffer (`tokio`'s
    /// `poll_write` contract): the chunk was sealed from that buffer's
    /// prefix, and a retry re-supplies it. Dropping a `write_all` future
    /// mid-flush leaves both the half-flushed chunk and this count behind, so
    /// the next write — possibly an unrelated buffer — completes the flush
    /// and is credited with `sealed` bytes it never supplied. The write
    /// direction therefore has no cancel safety; the read direction does (all
    /// of its partial state is in [`ReadStep`]).
    sealed: usize,
    /// Read direction: how much of the current step has arrived.
    step: ReadStep,
    staging: Vec<u8>,
    filled: usize,
    /// Decoded plaintext of the chunk being handed to the caller.
    pending: Vec<u8>,
    pending_pos: usize,
    salt_len: usize,
    /// The transport reported end-of-stream.
    eof: bool,
}

impl<S> SsStream<S> {
    /// Wrap `inner`: `salt` leads the request stream and `first` (the encoded
    /// target address) is sealed into the first chunk.
    fn new(
        inner: S,
        method: SsMethod,
        key: Zeroizing<Vec<u8>>,
        salt: &[u8],
        first: Option<Vec<u8>>,
    ) -> Self {
        let write = Half::new(method, &key, salt);
        let mut stream = Self {
            inner,
            aead: method.aead,
            method,
            key: Some(key),
            write,
            read: None,
            out: Vec::with_capacity(wire_chunk_len(method.aead) + method.aead.salt_len()),
            out_pos: 0,
            sealed: 0,
            step: ReadStep::Salt,
            staging: Vec::new(),
            filled: 0,
            pending: Vec::new(),
            pending_pos: 0,
            salt_len: method.aead.salt_len(),
            eof: false,
        };
        stream.out.extend_from_slice(salt);
        if let Some(first) = first {
            stream.push_chunks(&first);
        }
        stream
    }

    /// Seal `plaintext` into `out` as `[2B len + tag][ct + tag]` per
    /// ≤ [`MAX_CHUNK`] slice — TWO seals and TWO counter nonces per chunk.
    ///
    /// An empty `plaintext` seals nothing: a zero-length chunk is not a legal
    /// classic-AEAD frame, so this function never emits one.
    ///
    /// # Panics
    ///
    /// Panics if the AEAD rejects our own key/nonce/length — a programmer
    /// error, never a wire condition (the key and nonce widths come from the
    /// method, the plaintext is capped at [`MAX_CHUNK`]).
    fn push_chunks(&mut self, plaintext: &[u8]) {
        for slice in plaintext.chunks(MAX_CHUNK) {
            // `chunks` caps the slice at MAX_CHUNK, so the u16 holds it.
            #[allow(clippy::cast_possible_truncation)]
            let len = (slice.len() as u16).to_be_bytes();
            // Sealed straight into `out`: the nonce borrow and the buffer
            // borrow are disjoint fields, so each seal is one append with no
            // temporary `Vec` and no copy of the result.
            self.aead
                .seal_into(
                    &self.write.subkey,
                    self.write.counter.next_nonce(),
                    b"",
                    &len,
                    &mut self.out,
                )
                .expect("seal");
            self.aead
                .seal_into(
                    &self.write.subkey,
                    self.write.counter.next_nonce(),
                    b"",
                    slice,
                    &mut self.out,
                )
                .expect("seal");
        }
    }
}

impl<S: AsyncWrite + Unpin> SsStream<S> {
    /// Drain `out` into the transport.
    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let written =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "shadowsocks: transport accepted no bytes",
                )));
            }
            self.out_pos += written;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Put everything sealed so far on the wire — the handshake write path,
    /// where the salt and the first chunk go out in one pass.
    async fn flush_out(&mut self) -> Result<(), NativeError> {
        std::future::poll_fn(|cx| self.poll_flush_out(cx))
            .await
            .map_err(NativeError::from)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SsStream<S> {
    /// Seal at most one chunk (≤ [`MAX_CHUNK`] plaintext) and report the
    /// caller's bytes once that chunk is on the wire; `write_all` loops for
    /// larger buffers.
    ///
    /// This is NOT cancel-safe — unlike [`AsyncRead::poll_read`], whose
    /// partial state is entirely in the struct. A `write_all` future dropped
    /// mid-flush leaves the sealed chunk and its count in `out`/`sealed`, and
    /// the next write finishes that flush: re-issued with the SAME buffer the
    /// retry is exact, while a mismatched (shorter) buffer can only lose the
    /// difference — the returned count is clamped to the supplied buffer, so
    /// an oversized one never reaches `tokio::io::WriteAll`'s `split_at` (a
    /// panic). The write side is only ever driven to completion (the
    /// handshake write in [`connect`], then `tokio::io::copy`, which never
    /// drops a half-finished `poll_write`).
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // An empty write is not a frame: classic AEAD has no zero-length
        // chunk, so it consumes nothing and seals nothing.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.sealed == 0 {
            // One chunk per call, capped at MAX_CHUNK, so `out` never grows
            // past one chunk and the caller never sees an oversized pending
            // buffer.
            let take = buf.len().min(MAX_CHUNK);
            this.push_chunks(&buf[..take]);
            this.sealed = take;
        }
        // A retry with the same buffer only owes the flush: `sealed` bytes
        // are already on their way.
        ready!(this.poll_flush_out(cx))?;
        // Never report more than this call supplied: a `write_all` dropped
        // mid-flush and re-issued with a shorter buffer must not see a count
        // past its end — tokio's `WriteAll` would `split_at` out of bounds.
        let written = this.sealed.min(buf.len());
        this.sealed = 0;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_out(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_out(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> SsStream<S> {
    /// Bytes the current read step must have in `staging` before it can open.
    const fn step_len(&self) -> usize {
        match self.step {
            ReadStep::Salt => self.salt_len,
            ReadStep::Length => LEN_FIELD + self.aead.tag_len(),
            ReadStep::Body(len) => len + self.aead.tag_len(),
        }
    }

    /// Pull one transport read into `staging`; a zero-length read is the end
    /// of the stream.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let need = self.step_len();
        if self.staging.len() < need {
            self.staging.resize(need, 0);
        }
        let mut read_buf = ReadBuf::new(&mut self.staging[self.filled..need]);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
        let got = read_buf.filled().len();
        if got == 0 {
            self.eof = true;
        } else {
            self.filled += got;
        }
        Poll::Ready(Ok(()))
    }

    /// Open the current step if all of its bytes have arrived, advancing the
    /// state machine by one step. No I/O and no `await`: called in a loop by
    /// `poll_read`, so a cancelled read leaves the same state behind.
    fn decode_step(&mut self) -> Result<bool, NativeError> {
        if self.filled < self.step_len() {
            return Ok(false);
        }
        let tag = self.aead.tag_len();
        match self.step {
            ReadStep::Salt => {
                let key = self
                    .key
                    .as_ref()
                    .expect("the master key outlives the server salt");
                let half = Half::new(self.method, key, &self.staging[..self.salt_len]);
                self.read = Some(half);
                // Both subkeys exist now; the master key has no further use,
                // so it is zeroized from here on.
                self.key = None;
                self.step = ReadStep::Length;
            }
            ReadStep::Length => {
                let read = self
                    .read
                    .as_mut()
                    .expect("the reader half exists once the salt is in");
                // The length seal opens to exactly its 2-byte plaintext: the
                // tag authenticates the field, and AEAD is length-preserving.
                // `pending` is the read path's one reusable plaintext buffer;
                // poll_read drains a chunk out of it before decoding, so the
                // open always appends to an empty buffer.
                self.pending.clear();
                self.pending_pos = 0;
                self.aead.open_into(
                    &read.subkey,
                    read.counter.next_nonce(),
                    b"",
                    &self.staging[..LEN_FIELD + tag],
                    &mut self.pending,
                )?;
                let len = usize::from(u16::from_be_bytes([self.pending[0], self.pending[1]]));
                self.pending.clear();
                // A zero-length chunk is not EOF and not a no-op: mihomo
                // rejects it (`ErrZeroChunk`), and so does this reader.
                if len == 0 {
                    return Err(chunk_error("zero-length chunk"));
                }
                if len > MAX_CHUNK {
                    return Err(chunk_error("chunk length above the 0x3FFF cap"));
                }
                self.step = ReadStep::Body(len);
            }
            ReadStep::Body(len) => {
                let read = self
                    .read
                    .as_mut()
                    .expect("the reader half exists once the salt is in");
                // One append into the reusable buffer — no `Vec` per chunk.
                self.aead.open_into(
                    &read.subkey,
                    read.counter.next_nonce(),
                    b"",
                    &self.staging[..len + tag],
                    &mut self.pending,
                )?;
                self.pending_pos = 0;
                self.step = ReadStep::Length;
            }
        }
        self.filled = 0;
        Ok(true)
    }

    /// The transport ended: a clean end-of-stream only when no frame is
    /// half-arrived — before the server ever wrote, or exactly between chunks.
    fn eof_result(&self) -> io::Result<()> {
        if self.filled == 0 && matches!(self.step, ReadStep::Salt | ReadStep::Length) {
            Ok(())
        } else {
            Err(truncated())
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            // Hand out decoded plaintext before touching the transport, so a
            // chunk already in hand never waits on a read.
            if this.pending_pos < this.pending.len() {
                let take = buf.remaining().min(this.pending.len() - this.pending_pos);
                buf.put_slice(&this.pending[this.pending_pos..this.pending_pos + take]);
                this.pending_pos += take;
                if this.pending_pos == this.pending.len() {
                    this.pending.clear();
                    this.pending_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            this.pending.clear();
            this.pending_pos = 0;
            match this.decode_step() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return Poll::Ready(Err(wire_error(error))),
            }
            if this.eof {
                return Poll::Ready(this.eof_result());
            }
            ready!(this.poll_fill(cx))?;
        }
    }
}

/// Connect through a classic-AEAD Shadowsocks server: write the target
/// address as the first chunk (`salt ‖ length seal ‖ payload seal`, one pass)
/// and hand back the framing tunnel.
pub async fn connect(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &SsConfig,
    method: SsMethod,
) -> Result<BoxStream, NativeError> {
    connect_to(&ctx.target, stream, cfg, method).await
}

/// The same handshake against an **explicit** target.
///
/// The mux path needs this: a v2ray-plugin session's real destination is not
/// `ctx.target` (the New frame carries a dummy, §7), so the per-session codec
/// cannot read the link's target. One implementation, two callers.
pub async fn connect_to(
    target: &TargetAddr,
    stream: BoxStream,
    cfg: &SsConfig,
    method: SsMethod,
) -> Result<BoxStream, NativeError> {
    if method.family != SsFamily::Classic {
        return Err(NativeError::Config(format!(
            "shadowsocks classic AEAD codec requires a classic method, got {:?}",
            cfg.method
        )));
    }
    let key = password_key(method, &cfg.password)?;
    let mut salt = Zeroizing::new(vec![0u8; method.aead.salt_len()]);
    crate::rand::fill_nonsecret(&mut salt);
    let first = encode_addr_port_last(target)?;
    let mut stream = SsStream::new(stream, method, key, &salt, Some(first));
    let timeout = timeouts::PROTOCOL;
    tokio::time::timeout(timeout, stream.flush_out())
        .await
        .map_err(|_| NativeError::Timeout {
            step: "shadowsocks request write",
            limit: timeout,
        })??;
    Ok(Box::new(stream))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use leas_proto::proto_spec::ProtocolConfig;
    use leas_proto::proto_spec::common::SecurityConfig;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;
    use crate::addr::{Host, TargetAddr};
    use crate::context::NativeConnectParams;

    /// Byte-exact first request chunk for `key = 0x20..0x30`, `salt =
    /// 0x10..0x20`, target `127.0.0.1:8080` under `aes-128-gcm`, produced by
    /// two implementations that share no code with this crate (Bun
    /// `WebCrypto` and Python `cryptography` + a hand-rolled RFC 5869
    /// HKDF-SHA1) from the spec: `salt ‖ seal(len = 7) ‖ seal(addr)` with
    /// nonces 0 then 1 little-endian over subkey `HKDF-SHA1(key, salt,
    /// "ss-subkey") = 964da017a310705a9fd8e01fbb3b2ba0`. Pins seal order,
    /// empty AAD, nonce progression and the port-last address at once.
    const GOLDEN_CHUNK: &str = "101112131415161718191a1b1c1d1e1f6737d7db1d153fb7bedc1336c805b97df7540df6aaea0037e186b9912c52690d26454bdcf3ecf4bd27";

    /// The golden's key and salt (`stream_subkey` needs both to read it).
    fn golden_material() -> (Vec<u8>, Vec<u8>) {
        ((0x20u8..0x30).collect(), (0x10u8..0x20).collect())
    }

    /// The wire error a codec failure carries: the byte-stream seam only has
    /// `io::Error`, so the `NativeError` classification rides as its source.
    /// Both the zero-length and the tamper path must land there with the
    /// Shadowsocks protocol kind, never as a bare `Io`.
    fn codec_error(err: &io::Error) -> &NativeError {
        err.get_ref()
            .and_then(|inner| inner.downcast_ref::<NativeError>())
            .expect("a codec error wraps its NativeError")
    }

    fn hex_encode(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            })
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// The client's first write through the real [`SsStream`] writer: a fresh
    /// salt, then the target address as the first chunk. Returns the wire
    /// error so the test's spawned task can report it.
    async fn connect_chunked(
        method: SsMethod,
        key: &[u8; 16],
        target: TargetAddr,
        client: &mut DuplexStream,
    ) -> Result<(), NativeError> {
        let mut salt = Zeroizing::new(vec![0u8; method.aead.salt_len()]);
        crate::rand::fill_nonsecret(&mut salt);
        let first = encode_addr_port_last(&target)?;
        let mut stream = SsStream::new(
            client,
            method,
            Zeroizing::new(key.to_vec()),
            &salt,
            Some(first),
        );
        stream.flush_out().await
    }

    /// Read exactly `buf.len()` bytes; `None` when the peer closed before the
    /// first one (a chunk boundary), panicking on a truncation mid-frame.
    async fn read_exact_or_eof(stream: &mut DuplexStream, buf: &mut [u8]) -> Option<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let got = stream.read(&mut buf[filled..]).await.unwrap();
            if got == 0 {
                assert_eq!(filled, 0, "the wire ended inside a chunk");
                return None;
            }
            filled += got;
        }
        Some(())
    }

    /// Decrypt a whole response direction from the primitives, one layer
    /// below [`SsStream`]: the salt that leads the stream, then
    /// `[2B len + tag][ct + tag]` per chunk until the peer closes. Returns
    /// the plaintext and the per-chunk plaintext lengths — the wire structure
    /// the writer produced, checked without the reader under test.
    async fn read_all_chunks(
        mut server: DuplexStream,
        method: SsMethod,
        key: [u8; 32],
        salt: [u8; 32],
    ) -> (Vec<u8>, Vec<usize>) {
        const TAG: usize = 16;
        const LEN_FIELD: usize = 2;
        let mut got_salt = vec![0u8; method.aead.salt_len()];
        server.read_exact(&mut got_salt).await.unwrap();
        assert_eq!(got_salt, salt, "the stream leads with the writer's salt");
        let subkey = stream_subkey(method, &key, &got_salt);
        let mut counter = NonceCounter::new(method.aead.nonce_len());
        let mut plain = Vec::new();
        let mut lens = Vec::new();
        loop {
            let mut head = [0u8; LEN_FIELD + TAG];
            if read_exact_or_eof(&mut server, &mut head).await.is_none() {
                return (plain, lens);
            }
            let len = method
                .aead
                .open(&subkey, counter.next_nonce(), b"", &head)
                .expect("the length seal authenticates");
            let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
            assert!(
                len > 0 && len <= MAX_CHUNK,
                "chunk length {len} outside 1..=0x3FFF"
            );
            let mut body = vec![0u8; len + TAG];
            read_exact_or_eof(&mut server, &mut body)
                .await
                .expect("a declared length arrives in full");
            plain.extend_from_slice(
                &method
                    .aead
                    .open(&subkey, counter.next_nonce(), b"", &body)
                    .expect("the payload seal authenticates"),
            );
            lens.push(len);
        }
    }

    /// The first request chunk on the wire is
    /// `[salt][2B len + tag][ct(addr || data) + tag]` — two seals, counter +2.
    #[tokio::test]
    async fn first_chunk_is_length_seal_then_payload_seal() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let key = [0x11u8; 16];
        let (mut client, mut server) = duplex(64 * 1024);
        let target = TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 8080);
        let expected_addr = encode_addr_port_last(&target).unwrap();
        let task = tokio::spawn(async move {
            connect_chunked(method, &key, target, &mut client)
                .await
                .unwrap();
        });
        let mut wire = vec![0u8; 16 + 2 + 16 + 7 + 16];
        server.read_exact(&mut wire).await.unwrap();
        // salt is the first 16 bytes and is NOT a constant.
        assert_ne!(&wire[..16], &[0u8; 16]);
        let sub = stream_subkey(method, &key, &wire[..16]);
        let mut counter = NonceCounter::new(12);
        let len_pt = method
            .aead
            .open(&sub, counter.next_nonce(), b"", &wire[16..34])
            .unwrap();
        assert_eq!(len_pt, vec![0x00, 0x07]);
        let payload = method
            .aead
            .open(&sub, counter.next_nonce(), b"", &wire[34..57])
            .unwrap();
        assert_eq!(payload, expected_addr);
        task.await.unwrap();
    }

    /// The writer emits [`GOLDEN_CHUNK`] byte for byte.
    #[tokio::test]
    async fn first_chunk_matches_an_independent_golden() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let (key, salt) = golden_material();
        let target = TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 8080);
        let (client, mut server) = duplex(4096);
        let mut s = SsStream::new(
            client,
            method,
            Zeroizing::new(key),
            &salt,
            Some(encode_addr_port_last(&target).unwrap()),
        );
        s.flush_out().await.unwrap();
        let mut wire = vec![0u8; salt.len() + 2 + 16 + 7 + 16];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(hex_encode(&wire), GOLDEN_CHUNK);
    }

    /// The reader opens that same independently framed response: the address
    /// plaintext, then a clean end-of-stream at the chunk boundary.
    #[tokio::test]
    async fn reader_opens_an_independent_golden() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let (key, salt) = golden_material();
        let (client, mut server) = duplex(4096);
        let mut s = SsStream::new(client, method, Zeroizing::new(key), &salt, None);
        server.write_all(&hex_decode(GOLDEN_CHUNK)).await.unwrap();
        drop(server);
        let mut buf = [0u8; 16];
        let read = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..read], &[0x01, 127, 0, 0, 1, 0x1f, 0x90]);
        assert_eq!(
            s.read(&mut buf).await.unwrap(),
            0,
            "a closed stream ends cleanly at the chunk boundary"
        );
    }

    /// A 0x3FFF-byte write is one length seal + one payload seal spanning two
    /// chunks' worth of stream, and a >0x3FFF write splits into two chunks.
    #[tokio::test]
    async fn writes_are_split_at_the_3fff_cap() {
        let method = SsMethod::from_method("chacha20-ietf-poly1305").unwrap();
        let (client, server) = tokio::io::duplex(1 << 20);
        let key = [0x22u8; 32];
        let salt = [0x33u8; 32];
        let mut s = SsStream::new(client, method, Zeroizing::new(key.to_vec()), &salt, None);
        let payload = vec![0xABu8; 0x4000 + 5];
        let expected = payload.clone();
        let reader = tokio::spawn(async move { read_all_chunks(server, method, key, salt).await });
        s.write_all(&payload).await.unwrap();
        drop(s); // close: the reader stops on EOF
        let (plain, lens) = reader.await.unwrap();
        assert_eq!(plain, expected);
        // The write really crossed the cap: the wire carries two chunks, the
        // full 0x3FFF one and the 6-byte tail.
        assert_eq!(lens, vec![MAX_CHUNK, payload.len() - MAX_CHUNK]);
    }

    /// A `write_all` dropped mid-flush leaves `sealed` set; the next write is
    /// credited at most its own length. The transport (an 8-byte duplex) is
    /// too small to swallow the 1 KiB chunk, so the first poll really does
    /// stop with the chunk sealed but unflushed. A shorter retry must not see
    /// the stale 1024 — `tokio::io::WriteAll` would `split_at` the count and
    /// panic on a 4-byte buffer.
    #[tokio::test]
    async fn dropped_write_does_not_overstate_a_shorter_retry() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let key = [0xAAu8; 16];
        let salt = [0xBBu8; 16];
        let (client, mut server) = duplex(8);
        let mut s = SsStream::new(client, method, Zeroizing::new(key.to_vec()), &salt, None);
        let payload = vec![0x11u8; 1024];
        let mut fut = Box::pin(s.write_all(&payload));
        let first = std::future::poll_fn(|cx| Poll::Ready(fut.as_mut().poll(cx))).await;
        assert!(
            first.is_pending(),
            "an 8-byte duplex cannot flush the sealed 1 KiB chunk"
        );
        drop(fut);

        // Drain the transport so the stale chunk's flush can finish.
        let drain = tokio::spawn(async move {
            let mut sink = Vec::new();
            let _ = server.read_to_end(&mut sink).await;
        });
        let short = vec![0x22u8; 4];
        s.write_all(&short)
            .await
            .expect("a shorter retry must complete, not panic");
        drop(s);
        drain.await.unwrap();
    }

    /// Every chunk boundary the writer can land on: 1 byte, exactly
    /// `MAX_CHUNK`, one over, and a multi-chunk payload — the decrypted
    /// length fields must match `chunks(MAX_CHUNK)` exactly.
    #[tokio::test]
    async fn chunk_boundaries_split_exactly_at_the_cap() {
        let method = SsMethod::from_method("aes-256-gcm").unwrap();
        let key = [0x44u8; 32];
        let salt = [0x55u8; 32];
        for size in [1usize, MAX_CHUNK, MAX_CHUNK + 1, 3 * MAX_CHUNK + 2] {
            let (client, server) = duplex(1 << 20);
            let mut s = SsStream::new(client, method, Zeroizing::new(key.to_vec()), &salt, None);
            let payload = vec![0x5Au8; size];
            let reader =
                tokio::spawn(async move { read_all_chunks(server, method, key, salt).await });
            s.write_all(&payload).await.unwrap();
            drop(s);
            let (plain, lens) = reader.await.unwrap();
            assert_eq!(plain, payload, "{size} bytes round-trip");
            let expected: Vec<usize> = payload.chunks(MAX_CHUNK).map(<[u8]>::len).collect();
            assert_eq!(lens, expected, "{size} bytes split at the cap");
        }
    }

    /// An empty write seals no chunk: the wire carries the salt and stops
    /// there — never the zero-length chunk classic AEAD has no room for.
    #[tokio::test]
    async fn empty_write_emits_no_chunk() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let key = [0x66u8; 16];
        let salt = [0x77u8; 16];
        let (client, mut server) = duplex(64);
        let mut s = SsStream::new(client, method, Zeroizing::new(key.to_vec()), &salt, None);
        s.write_all(&[]).await.unwrap();
        s.flush().await.unwrap();
        drop(s);
        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        assert_eq!(wire, salt, "an empty write must not seal a chunk");
    }

    /// A 0-length length-field is neither EOF nor a no-op: the reader refuses
    /// it (mihomo `ErrZeroChunk`), carrying the protocol error as its source.
    #[tokio::test]
    async fn zero_length_chunk_is_rejected() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let key = [0x88u8; 16];
        let salt = [0x99u8; 16];
        let (client, mut server) = duplex(4096);
        let subkey = stream_subkey(method, &key, &salt);
        let mut counter = NonceCounter::new(method.aead.nonce_len());
        server.write_all(&salt).await.unwrap();
        for plain in [&0u16.to_be_bytes()[..], &[]] {
            let sealed = method
                .aead
                .seal(&subkey, counter.next_nonce(), b"", plain)
                .unwrap();
            server.write_all(&sealed).await.unwrap();
        }
        let mut s = SsStream::new(client, method, Zeroizing::new(key.to_vec()), &salt, None);
        let mut buf = [0u8; 16];
        let err = s.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(matches!(
            codec_error(&err),
            NativeError::Protocol {
                kind: ProtocolKind::Shadowsocks,
                ..
            }
        ));
    }

    /// A tampered chunk fails its tag before a single plaintext byte is
    /// delivered, and the failure keeps its `Protocol` classification (the
    /// `?` in `decode_step` must not double-wrap it into a bare `Io`).
    #[tokio::test]
    async fn tampered_chunk_fails_the_tag() {
        let method = SsMethod::from_method("chacha20-ietf-poly1305").unwrap();
        let key = [0xAAu8; 32];
        let salt = [0xBBu8; 32];
        let (client, mut server) = duplex(4096);
        let subkey = stream_subkey(method, &key, &salt);
        let mut counter = NonceCounter::new(method.aead.nonce_len());
        server.write_all(&salt).await.unwrap();
        let head = method
            .aead
            .seal(&subkey, counter.next_nonce(), b"", &5u16.to_be_bytes())
            .unwrap();
        let mut body = method
            .aead
            .seal(&subkey, counter.next_nonce(), b"", b"hello")
            .unwrap();
        let last = body.len() - 1;
        body[last] ^= 0x01; // flip one ciphertext byte of the payload seal
        server.write_all(&head).await.unwrap();
        server.write_all(&body).await.unwrap();
        let mut s = SsStream::new(client, method, Zeroizing::new(key.to_vec()), &salt, None);
        let mut buf = [0u8; 16];
        let err = s.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            matches!(
                codec_error(&err),
                NativeError::Protocol {
                    kind: ProtocolKind::Shadowsocks,
                    ..
                }
            ),
            "a tampered chunk must stay a Shadowsocks protocol error: {err}"
        );
    }

    /// A tampered LENGTH seal takes the same classified path.
    #[tokio::test]
    async fn tampered_length_seal_fails_the_tag() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let key = [0xCCu8; 16];
        let salt = [0xDDu8; 16];
        let (client, mut server) = duplex(4096);
        let subkey = stream_subkey(method, &key, &salt);
        let mut counter = NonceCounter::new(method.aead.nonce_len());
        server.write_all(&salt).await.unwrap();
        let mut head = method
            .aead
            .seal(&subkey, counter.next_nonce(), b"", &5u16.to_be_bytes())
            .unwrap();
        let last = head.len() - 1;
        head[last] ^= 0x01;
        server.write_all(&head).await.unwrap();
        let mut s = SsStream::new(client, method, Zeroizing::new(key.to_vec()), &salt, None);
        let mut buf = [0u8; 16];
        let err = s.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(matches!(
            codec_error(&err),
            NativeError::Protocol {
                kind: ProtocolKind::Shadowsocks,
                ..
            }
        ));
    }

    /// A response truncated mid-chunk — a length seal that arrives, then EOF
    /// before the payload it announced — is a wire failure like any other and
    /// keeps the Shadowsocks classification: `UnexpectedEof` at the seam,
    /// `Protocol` in its source. Without that classification this is the one
    /// failure class a caller cannot classify at all.
    #[tokio::test]
    async fn truncated_response_keeps_its_classification() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let key = [0xEEu8; 16];
        let salt = [0xFFu8; 16];
        let (client, mut server) = duplex(4096);
        let subkey = stream_subkey(method, &key, &salt);
        server.write_all(&salt).await.unwrap();
        // A full length seal announcing 5 bytes at the all-zero first nonce,
        // then EOF: the body never arrives.
        let head = method
            .aead
            .seal(&subkey, &[0u8; 12], b"", &5u16.to_be_bytes())
            .unwrap();
        server.write_all(&head).await.unwrap();
        drop(server);
        let mut s = SsStream::new(client, method, Zeroizing::new(key.to_vec()), &salt, None);
        let mut buf = [0u8; 16];
        let err = s.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        // Written out rather than routed through `codec_error`: a missing (or
        // double-wrapped) classification must fail with THIS message.
        let source = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<NativeError>());
        assert!(
            matches!(
                source,
                Some(NativeError::Protocol {
                    kind: ProtocolKind::Shadowsocks,
                    ..
                })
            ),
            "a truncated response must stay a Shadowsocks protocol error: {err}"
        );
    }

    fn ss_config(method: &str, password: &str) -> SsConfig {
        SsConfig {
            method: method.into(),
            password: password.to_owned(),
            security: SecurityConfig::default(),
            remarks: None,
            plugin: None,
        }
    }

    fn ctx_for(cfg: SsConfig, target: TargetAddr) -> LinkContext {
        let params = NativeConnectParams::new(
            ProtocolConfig::Ss(cfg),
            EndpointEssentials::new("127.0.0.1", 8388),
            target.clone(),
        );
        LinkContext::new(params, target)
    }

    fn assert_send_static<T: Send + 'static>(_: &T) {}

    /// `connect` end to end over a real duplex: the password-derived key seals
    /// the target address as the first chunk, the tunnel that comes back is
    /// `Send + 'static`, and its later writes continue the same counter.
    #[tokio::test]
    async fn connect_seals_the_target_address_and_returns_a_usable_tunnel() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let cfg = ss_config("aes-128-gcm", "hunter2");
        let target = TargetAddr::new(Host::Domain("example.com".into()), 443);
        let ctx = ctx_for(cfg.clone(), target.clone());
        let key = password_key(method, &cfg.password).unwrap();
        let (client, mut server) = duplex(64 * 1024);
        let mut tunnel = connect(&ctx, Box::new(client), &cfg, method).await.unwrap();
        assert_send_static(&tunnel);

        let mut salt = [0u8; 16];
        server.read_exact(&mut salt).await.unwrap();
        let subkey = stream_subkey(method, &key, &salt);
        let mut counter = NonceCounter::new(method.aead.nonce_len());
        let addr = encode_addr_port_last(&target).unwrap();
        let mut body = vec![0u8; addr.len() + 16];
        let mut head = [0u8; 2 + 16];
        server.read_exact(&mut head).await.unwrap();
        assert_eq!(
            method
                .aead
                .open(&subkey, counter.next_nonce(), b"", &head)
                .unwrap(),
            u16::try_from(addr.len()).unwrap().to_be_bytes()
        );
        server.read_exact(&mut body).await.unwrap();
        assert_eq!(
            method
                .aead
                .open(&subkey, counter.next_nonce(), b"", &body)
                .unwrap(),
            addr
        );

        // The tunnel keeps sealing: request chunk 2 uses the next two nonces.
        tunnel.write_all(b"hello").await.unwrap();
        tunnel.flush().await.unwrap();
        let mut next_body = vec![0u8; 5 + 16];
        server.read_exact(&mut head).await.unwrap();
        assert_eq!(
            method
                .aead
                .open(&subkey, counter.next_nonce(), b"", &head)
                .unwrap(),
            vec![0x00, 0x05]
        );
        server.read_exact(&mut next_body).await.unwrap();
        assert_eq!(
            method
                .aead
                .open(&subkey, counter.next_nonce(), b"", &next_body)
                .unwrap(),
            b"hello"
        );
    }

    /// The steady-state chunk path allocates nothing: once one full-size chunk
    /// has grown each buffer, a second chunk of the same size re-runs with the
    /// same capacities on BOTH directions — `out`, `staging` and `pending` are
    /// reused rather than rebuilt. (A capacity that stops growing is the cheap
    /// proxy for "no `Vec` allocation"; an exact count would need a global
    /// allocator, which a unit test cannot install without hijacking the whole
    /// test binary.)
    #[tokio::test]
    async fn steady_state_chunks_grow_no_buffer() {
        let method = SsMethod::from_method("aes-256-gcm").unwrap();
        let key: Vec<u8> = (0x30u8..0x50).collect();
        let salt: Vec<u8> = (0x60u8..0x80).collect();
        let chunk = vec![0xC3u8; MAX_CHUNK];
        let (client, mut server) = duplex(1 << 21);
        let mut s = SsStream::new(client, method, Zeroizing::new(key.clone()), &salt, None);

        // Write direction: the first chunk sizes `out`, the second reuses it.
        s.write_all(&chunk).await.unwrap();
        let out_capacity = s.out.capacity();
        s.write_all(&chunk).await.unwrap();
        assert_eq!(
            s.out.capacity(),
            out_capacity,
            "the write path regrew `out`"
        );
        // Exactly two full chunks on the wire behind the salt.
        let wire_len = salt.len() + 2 * (2 + 16 + MAX_CHUNK + 16);
        let mut sink = vec![0u8; wire_len];
        server.read_exact(&mut sink).await.unwrap();

        // Read direction: the peer seals two chunks of that same size; the
        // first sizes `staging`/`pending`, the second must reuse them.
        let subkey = stream_subkey(method, &key, &salt);
        let mut counter = NonceCounter::new(method.aead.nonce_len());
        let mut wire = Vec::new();
        wire.extend_from_slice(&salt);
        for _ in 0..2 {
            let len = u16::try_from(MAX_CHUNK).unwrap().to_be_bytes();
            method
                .aead
                .seal_into(&subkey, counter.next_nonce(), b"", &len, &mut wire)
                .unwrap();
            method
                .aead
                .seal_into(&subkey, counter.next_nonce(), b"", &chunk, &mut wire)
                .unwrap();
        }
        server.write_all(&wire).await.unwrap();
        drop(server);
        let mut got = vec![0u8; MAX_CHUNK];
        s.read_exact(&mut got).await.unwrap();
        let (staging_len, pending_capacity) = (s.staging.len(), s.pending.capacity());
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(
            s.staging.len(),
            staging_len,
            "the read path regrew `staging`"
        );
        assert_eq!(
            s.pending.capacity(),
            pending_capacity,
            "the read path regrew `pending`"
        );
        assert_eq!(got, chunk);
    }
}
