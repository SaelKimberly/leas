//! Shadowsocks 2022 (blake3) TCP codec — client side.
//!
//! Wire (2022 edition spec §3.1; shadowsocks-rust
//! `relay/tcprelay/aead_2022.rs` — its header diagram is the source of the
//! one below):
//!
//! ```text
//! request : [salt][seal(11B: type=0 | ts u64be | len u16be)]
//!                 [seal(varlen: ATYP|addr|port | pad_len u16be | padding | initial payload)]
//!                 [seal(2B len)][seal(payload)]…
//! response: [salt][seal(27/43B: type=1 | ts u64be | request_salt | len u16be)]
//!                 [seal(payload)][seal(2B len)][seal(payload)]…
//! ```
//!
//! The subkey is `blake3::derive_key("shadowsocks 2022 session subkey",
//! psk ‖ salt)` truncated to the method's key length ([`stream_subkey`]), and
//! the nonce is a little-endian counter advanced by EVERY seal/open (spec
//! §3.1.1).
//!
//! Counter sequence — an off-by-one here breaks interop silently. Request:
//! fixed header 0, variable header 1, then len 2 / payload 3, len 4 /
//! payload 5… Response: fixed header 0 (it doubles as the first length
//! chunk), payload 1, len 2, payload 3… so the reader keeps ONE [`Half`]
//! across the response header and the chunks that follow. Payload chunks cap
//! at 0xFFFF ([`MAX_PAYLOAD`]); the request's `len` field counts the whole
//! variable-length header (address and padding included), not just a payload.
//!
//! Three client-side rules, each easy to break and invisible until interop
//! fails: the response header's `request_salt` must equal the salt this
//! client sent; the salt and BOTH request header chunks must leave in ONE
//! write (anti-DPI); and a request with no initial payload MUST carry
//! non-zero random padding, at most `MaxPaddingLength` (spec §3.1.3) — this
//! client never sends an initial payload, so it always pads. There is no
//! extensible identity header: single-user PSK only.
//!
//! As in `protocol::ss::stream`, every partial-read state lives in
//! [`Ss2022Stream`], so a cancelled `poll_read` resumes on the byte it
//! stopped at and never replays a counter nonce.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use leas_proto::proto_spec::{ProtocolKind, SsConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::BoxStream;
use crate::addr::{TargetAddr, encode_addr_port_last};
use crate::context::LinkContext;
use crate::crypto::aead::{NonceCounter, SsAead};
use crate::error::{NativeError, timeouts};
use crate::protocol::ss::consts::{
    MAX_PADDING, TIMESTAMP_TOLERANCE_SECS, now_unix_secs, s2022_error,
};
use crate::protocol::ss::method::{SsFamily, SsMethod, password_key, stream_subkey};

/// Request header type: client → server stream.
const HEADER_TYPE_CLIENT_STREAM: u8 = 0;

/// Response header type: server → client stream.
const HEADER_TYPE_SERVER_STREAM: u8 = 1;

/// 2022's payload cap: the length field is a full `u16`, unlike classic AEAD's
/// 0x3FFF. Reading is bounded by the same field — a decrypted `u16` can never
/// exceed this, so the reader's staging buffer is structurally capped and a
/// hostile length cannot make it allocate more than 0xFFFF + tag.
const MAX_PAYLOAD: usize = 0xFFFF;

/// Request fixed header: `type(1) + timestamp(8 BE) + length(2 BE)`.
const REQUEST_FIXED_LEN: usize = 11;

/// The BE length field that opens every payload chunk.
const LEN_FIELD: usize = 2;

/// Longest variable-length header this client writes: the
/// `ATYP|addr|port` prefix tops out at 259 bytes (a 255-byte domain), then
/// the 2-byte padding length and up to [`MAX_PADDING`] padding bytes.
const MAX_VARIABLE_HEADER: usize = 1 + 1 + 255 + 2 + 2 + MAX_PADDING as usize;

/// The response header's plaintext length: the request fixed header with the
/// echoed `request_salt` inserted before the length field.
const fn response_fixed_len(salt_len: usize) -> usize {
    REQUEST_FIXED_LEN + salt_len
}

/// Re-label a failure from the shared cipher layer for this codec's kind.
///
/// `crypto::aead` reports every AEAD failure as the classic `Shadowsocks`
/// kind, which is the same message text with the wrong classification here;
/// `Protocol { kind, detail }` carries nothing else, so the re-label loses
/// nothing.
fn reclassify(error: NativeError) -> NativeError {
    match error {
        NativeError::Protocol { detail, .. } => NativeError::Protocol {
            kind: ProtocolKind::Shadowsocks2022,
            detail,
        },
        other => other,
    }
}

/// Wrap a wire error for the byte-stream seam.
fn wire_error(error: NativeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// The error for a response that ends inside a frame.
///
/// Truncation is a wire failure like any other, so it carries the same
/// classification as the seal failures: the seam's `io::Error` keeps the
/// `UnexpectedEof` kind the stream layer already relies on, and the
/// [`NativeError`] rides as its source.
fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        s2022_error("response stream truncated mid-frame"),
    )
}

/// Random padding length for a request with no initial payload.
///
/// `u32_below` is half-open, so this is `1..=MAX_PADDING`: the spec requires a
/// non-zero padding length exactly when there is no initial payload.
fn random_padding_len() -> usize {
    crate::rand::u32_below(MAX_PADDING) as usize + 1
}

/// Request fixed-length header: `type | timestamp u64be | length u16be`.
///
/// `len` is the length of the ENTIRE variable-length header that follows
/// (address, padding length field, padding and any initial payload) — not just
/// a payload.
fn request_fixed_header(timestamp: u64, len: u16) -> [u8; REQUEST_FIXED_LEN] {
    let mut header = [0u8; REQUEST_FIXED_LEN];
    header[0] = HEADER_TYPE_CLIENT_STREAM;
    header[1..9].copy_from_slice(&timestamp.to_be_bytes());
    header[9..11].copy_from_slice(&len.to_be_bytes());
    header
}

/// Request variable-length header:
/// `ATYP|addr|port | pad_len u16be | padding | initial payload`.
///
/// The padding is non-zero (and random) when there is no initial payload, and
/// absent otherwise (spec §3.1.3). This client only ever calls it with an
/// empty `initial`, so it always pads.
fn request_variable_header(target: &TargetAddr, initial: &[u8]) -> Result<Vec<u8>, NativeError> {
    let addr = encode_addr_port_last(target)?;
    let pad_len = if initial.is_empty() {
        random_padding_len()
    } else {
        0
    };
    let mut out = Vec::with_capacity(addr.len() + LEN_FIELD + pad_len + initial.len());
    out.extend_from_slice(&addr);
    // `pad_len <= MAX_PADDING` by construction, so the u16 holds it.
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(pad_len as u16).to_be_bytes());
    let pad_start = out.len();
    out.resize(pad_start + pad_len, 0);
    crate::rand::fill_nonsecret(&mut out[pad_start..]);
    out.extend_from_slice(initial);
    Ok(out)
}

/// Validate a decrypted response header and return its first payload length.
///
/// The header echoes the salt this client sent: a mismatch means the reply
/// belongs to another session, so it is rejected. That comparison is a plain
/// `==` — the salt travels in the clear and is no secret, so nothing here
/// needs a constant-time comparison.
fn validate_response_header(plain: &[u8], request_salt: &[u8]) -> Result<u16, NativeError> {
    let expected = response_fixed_len(request_salt.len());
    if plain.len() != expected {
        return Err(s2022_error(&format!(
            "response header opened to {} bytes, expected {expected}",
            plain.len()
        )));
    }
    if plain[0] != HEADER_TYPE_SERVER_STREAM {
        return Err(s2022_error(&format!(
            "response header type is {:#04x}, expected {HEADER_TYPE_SERVER_STREAM:#04x}",
            plain[0]
        )));
    }
    let timestamp = u64::from_be_bytes(plain[1..9].try_into().expect("8-byte timestamp"));
    let now = now_unix_secs()?;
    let skew = now.abs_diff(timestamp);
    if skew > TIMESTAMP_TOLERANCE_SECS {
        return Err(s2022_error(&format!(
            "response timestamp {timestamp} is {skew}s from our {now} (tolerance {TIMESTAMP_TOLERANCE_SECS}s)"
        )));
    }
    if &plain[9..9 + request_salt.len()] != request_salt {
        return Err(s2022_error(
            "response header carries a request salt that is not ours",
        ));
    }
    Ok(u16::from_be_bytes([
        plain[expected - 2],
        plain[expected - 1],
    ]))
}

/// Open a server response header and hand back the reader [`Half`] it starts.
///
/// The server seals the header with counter 0 under a subkey derived from ITS
/// salt, and that same counter rule makes the returned half land on 1 — where
/// the response's first payload chunk picks up.
fn open_response_header(
    method: SsMethod,
    key: &[u8],
    request_salt: &[u8],
    fixed_ct: &[u8],
    salt: &[u8],
) -> Result<(u16, Half), NativeError> {
    let mut half = Half::new(method, key, salt);
    let plain = method
        .aead
        .open(&half.subkey, half.counter.next_nonce(), b"", fixed_ct)
        .map_err(reclassify)?;
    let len = validate_response_header(&plain, request_salt)?;
    Ok((len, half))
}

/// Seal a response header exactly as a server would — test support.
///
/// Produces `salt ‖ seal(type | timestamp | request_salt | length)`, drawing a
/// fresh salt: the caller must open it with `&header[..salt_len]` as the salt.
#[cfg(test)]
fn sealed_response_header(
    method: SsMethod,
    key: &[u8],
    request_salt: &[u8],
    len: u16,
    timestamp: u64,
) -> Vec<u8> {
    sealed_response_header_with(
        method,
        key,
        request_salt,
        HEADER_TYPE_SERVER_STREAM,
        len,
        timestamp,
    )
}

/// [`sealed_response_header`] with the type field spelled out, so a test can
/// pin the reader's `type == 1` check — test support.
#[cfg(test)]
fn sealed_response_header_with(
    method: SsMethod,
    key: &[u8],
    request_salt: &[u8],
    ty: u8,
    len: u16,
    timestamp: u64,
) -> Vec<u8> {
    let mut salt = vec![0u8; method.aead.salt_len()];
    crate::rand::fill_nonsecret(&mut salt);
    let mut header = Vec::with_capacity(response_fixed_len(request_salt.len()));
    header.push(ty);
    header.extend_from_slice(&timestamp.to_be_bytes());
    header.extend_from_slice(request_salt);
    header.extend_from_slice(&len.to_be_bytes());
    let subkey = stream_subkey(method, key, &salt);
    let mut out = salt;
    method
        .aead
        .seal_into(
            &subkey,
            NonceCounter::new(method.aead.nonce_len()).next_nonce(),
            b"",
            &header,
            &mut out,
        )
        .expect("seal");
    out
}

/// One direction's AEAD state: the subkey its own salt derived and the
/// little-endian counter every seal or open of that direction draws from.
///
/// The two directions share nothing but the cipher — that independence is the
/// protocol's replay defence, so a salt/counter is never carried across. The
/// 2022 response direction keeps ONE half across the response header and the
/// chunks after it: the header doubles as the first length chunk.
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
    /// The server's salt — read once, then the reader [`Half`] derives from it.
    Salt,
    /// The response fixed header, sealed by the server at counter 0.
    Header,
    /// The `[2B len][tag]` length seal of the next chunk. Also the only state
    /// an end-of-stream may land on: a chunk boundary.
    Length,
    /// The `[ct(payload)][tag]` seal of a chunk whose length is already open.
    /// The length nonce is spent, so this survives a cancelled read.
    Body(usize),
}

/// A 2022-blake3 Shadowsocks stream: the request direction seals the header
/// chunks and the payload chunks, the response direction opens them.
///
/// The first read consumes the server's salt and opens its header (validated:
/// type, timestamp, `request_salt`), which leaves the reader [`Half`] at
/// counter 1. The salt given to the constructor leads the request stream, and
/// [`Ss2022Stream::write_handshake`] spends counters 0 and 1, so the first
/// caller write continues at 2.
pub struct Ss2022Stream<S> {
    inner: S,
    /// Cipher of both directions; only the key and nonce state differ.
    aead: SsAead,
    /// Method of both directions, kept to derive the reader half once the
    /// server's salt arrives.
    method: SsMethod,
    /// Master key — needed until the server salt derives the reader half,
    /// then dropped (zeroized). `None` once both halves exist.
    key: Option<Zeroizing<Vec<u8>>>,
    write: Half,
    read: Option<Half>,
    /// Sealed bytes waiting for the transport; the salt leads them.
    out: Vec<u8>,
    out_pos: usize,
    /// Caller bytes whose chunk is already in `out` and not yet reported as
    /// consumed. As in `protocol::ss::stream`, the count is only correct for
    /// a retry with the SAME buffer, so the write direction has no cancel
    /// safety (the read direction does: all of its partial state is in
    /// [`ReadStep`]).
    sealed: usize,
    /// Read direction: how much of the current step has arrived.
    step: ReadStep,
    staging: Vec<u8>,
    filled: usize,
    /// Decoded plaintext of the chunk being handed to the caller.
    pending: Vec<u8>,
    pending_pos: usize,
    salt_len: usize,
    /// The server's salt, held between the salt read and the header open.
    server_salt: Vec<u8>,
    /// The salt this client sent; the response header must echo it.
    request_salt: Vec<u8>,
    /// Handshake destination — the chain's per-link next hop, not the
    /// profile's target.
    target: TargetAddr,
    /// The transport reported end-of-stream.
    eof: bool,
}

impl<S> Ss2022Stream<S> {
    /// Wrap `inner`: `salt` leads the request stream and `target` is the
    /// destination the request header will carry. `write_handshake` must
    /// follow before any write.
    ///
    /// `pub(crate)`: the constructor and [`Self::write_handshake`] are a
    /// pair — calling the handshake twice reuses counters 0 and 1 under the
    /// same subkey, so neither escapes the crate.
    #[must_use]
    pub(crate) fn new(
        inner: S,
        method: SsMethod,
        key: Zeroizing<Vec<u8>>,
        salt: Vec<u8>,
        target: TargetAddr,
    ) -> Self {
        let write = Half::new(method, &key, &salt);
        // The handshake is the only write whose size is known up front;
        // sizing `out` for it avoids an early realloc without reserving a
        // 0xFFFF chunk (~65 KiB) for every connection that never sends one.
        let capacity =
            salt.len() + REQUEST_FIXED_LEN + MAX_VARIABLE_HEADER + 2 * method.aead.tag_len();
        Self {
            inner,
            aead: method.aead,
            method,
            key: Some(key),
            write,
            read: None,
            out: Vec::with_capacity(capacity),
            out_pos: 0,
            sealed: 0,
            step: ReadStep::Salt,
            staging: Vec::new(),
            filled: 0,
            pending: Vec::new(),
            pending_pos: 0,
            salt_len: method.aead.salt_len(),
            server_salt: Vec::new(),
            request_salt: salt,
            target,
            eof: false,
        }
    }

    /// Seal `plaintext` into `out` as `[2B len + tag][ct + tag]` per
    /// ≤ [`MAX_PAYLOAD`] slice — TWO seals and TWO counter nonces per chunk.
    ///
    /// An empty `plaintext` seals nothing: the caller's zero-length write is
    /// not a frame, so this never emits the zero-length chunk a peer would
    /// have to special-case.
    ///
    /// # Panics
    ///
    /// Panics if the AEAD rejects our own key/nonce/length — a programmer
    /// error, never a wire condition (the key and nonce widths come from the
    /// method, the plaintext is capped at [`MAX_PAYLOAD`]).
    fn push_chunks(&mut self, plaintext: &[u8]) {
        for slice in plaintext.chunks(MAX_PAYLOAD) {
            // `chunks` caps the slice at MAX_PAYLOAD, so the u16 holds it.
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

impl<S: AsyncWrite + Unpin> Ss2022Stream<S> {
    /// Drain `out` into the transport.
    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let written =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "shadowsocks-2022: transport accepted no bytes",
                )));
            }
            self.out_pos += written;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Put everything sealed so far on the wire in one pass.
    async fn flush_out(&mut self) -> Result<(), NativeError> {
        std::future::poll_fn(|cx| self.poll_flush_out(cx))
            .await
            .map_err(NativeError::from)
    }

    /// Write the request handshake — `salt ‖ seal(fixed header) ‖ seal(variable
    /// header)` — in ONE pass: `out` is assembled in full and flushed with a
    /// single `poll_write`, which on a socket is one `write(2)`. That is the
    /// anti-DPI requirement: the salt and both header chunks are one burst, so
    /// a passive observer cannot see the protocol's frame shape in a split.
    ///
    /// Call exactly once, before the first [`AsyncWrite::poll_write`]: the two
    /// seals spend counters 0 and 1, so the first caller chunk continues at 2.
    /// A second call would reuse those nonces under the same subkey, which is
    /// why this is `pub(crate)` — nothing outside the module may call it.
    /// This client never sends an initial payload, so the variable-length
    /// header always carries `1..=MAX_PADDING` bytes of random padding.
    pub(crate) async fn write_handshake(&mut self) -> Result<(), NativeError> {
        let timestamp = now_unix_secs()?;
        let variable = request_variable_header(&self.target, &[])?;
        let len = u16::try_from(variable.len()).map_err(|_| {
            s2022_error("variable-length header does not fit the 0xFFFF length field")
        })?;
        let fixed = request_fixed_header(timestamp, len);
        self.out.clear();
        self.out_pos = 0;
        self.out.extend_from_slice(&self.request_salt);
        // Our own key, nonce and plaintext widths: a seal failure is a
        // programmer error, never a wire condition.
        self.aead
            .seal_into(
                &self.write.subkey,
                self.write.counter.next_nonce(),
                b"",
                &fixed,
                &mut self.out,
            )
            .expect("seal");
        self.aead
            .seal_into(
                &self.write.subkey,
                self.write.counter.next_nonce(),
                b"",
                &variable,
                &mut self.out,
            )
            .expect("seal");
        self.flush_out().await
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Ss2022Stream<S> {
    /// Seal at most one chunk (≤ [`MAX_PAYLOAD`] plaintext) and report the
    /// caller's bytes once that chunk is on the wire; `write_all` loops for
    /// larger buffers.
    ///
    /// This is NOT cancel-safe — the write direction's `sealed` count only
    /// survives a retry with the same buffer, as in `protocol::ss::stream`.
    /// Re-issued with the SAME buffer the retry is exact; a mismatched
    /// (shorter) buffer can only lose the difference, and the count is clamped
    /// to the supplied buffer so `tokio::io::WriteAll`'s `split_at` can never
    /// see an oversized one. The write side is only ever driven to completion
    /// (the handshake write in [`connect`], then `tokio::io::copy`).
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // An empty write is not a frame: no zero-length chunk is sealed.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.sealed == 0 {
            // One chunk per call, capped at MAX_PAYLOAD, so `out` never grows
            // past one chunk and the caller never sees an oversized pending
            // buffer.
            let take = buf.len().min(MAX_PAYLOAD);
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

impl<S: AsyncRead + Unpin> Ss2022Stream<S> {
    /// Bytes the current read step must have in `staging` before it can open.
    const fn step_len(&self) -> usize {
        match self.step {
            ReadStep::Salt => self.salt_len,
            ReadStep::Header => response_fixed_len(self.salt_len) + self.aead.tag_len(),
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
                // The header open derives the reader half, so the salt is
                // kept for one more step rather than derived twice.
                self.server_salt.clear();
                self.server_salt
                    .extend_from_slice(&self.staging[..self.salt_len]);
                self.step = ReadStep::Header;
            }
            ReadStep::Header => {
                let key = self
                    .key
                    .as_ref()
                    .expect("the master key outlives the server salt");
                let (len, half) = open_response_header(
                    self.method,
                    key,
                    &self.request_salt,
                    &self.staging[..self.step_len()],
                    &self.server_salt,
                )?;
                self.read = Some(half);
                // Both subkeys exist now; the master key has no further use,
                // so it is zeroized from here on.
                self.key = None;
                // The header chunk IS the first length chunk: its `len` is the
                // length of the payload seal that follows at counter 1. A zero
                // length is legal (a server with nothing to send yet) and is
                // consumed as an empty chunk, exactly as the reference reader
                // does.
                self.step = ReadStep::Body(usize::from(len));
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
                self.aead
                    .open_into(
                        &read.subkey,
                        read.counter.next_nonce(),
                        b"",
                        &self.staging[..LEN_FIELD + tag],
                        &mut self.pending,
                    )
                    .map_err(reclassify)?;
                let len = usize::from(u16::from_be_bytes([self.pending[0], self.pending[1]]));
                self.pending.clear();
                self.step = ReadStep::Body(len);
            }
            ReadStep::Body(len) => {
                let read = self
                    .read
                    .as_mut()
                    .expect("the reader half exists once the salt is in");
                // One append into the reusable buffer — no `Vec` per chunk.
                self.aead
                    .open_into(
                        &read.subkey,
                        read.counter.next_nonce(),
                        b"",
                        &self.staging[..len + tag],
                        &mut self.pending,
                    )
                    .map_err(reclassify)?;
                self.pending_pos = 0;
                self.step = ReadStep::Length;
            }
        }
        self.filled = 0;
        Ok(true)
    }

    /// The transport ended: a clean end-of-stream only when no frame is
    /// half-arrived — before the server ever wrote, or exactly between chunks.
    /// A server that closes before its header is a truncation, not an EOF.
    fn eof_result(&self) -> io::Result<()> {
        if self.filled == 0 && matches!(self.step, ReadStep::Salt | ReadStep::Length) {
            Ok(())
        } else {
            Err(truncated())
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Ss2022Stream<S> {
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

/// Connect through a 2022-blake3 Shadowsocks server: write the handshake
/// (`salt ‖ fixed header seal ‖ variable header seal`, one pass) and hand back
/// the framing tunnel.
///
/// The destination is [`LinkContext::target`] — the chain's per-link next hop
/// — never the profile's own target, which is what a chain's intermediate
/// links must reach.
pub async fn connect(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &SsConfig,
    method: SsMethod,
) -> Result<BoxStream, NativeError> {
    connect_to(&ctx.target, stream, cfg, method).await
}

/// The same handshake against an **explicit** target — the mux path's
/// per-session entry (see `stream::connect_to`).
pub async fn connect_to(
    target: &TargetAddr,
    stream: BoxStream,
    cfg: &SsConfig,
    method: SsMethod,
) -> Result<BoxStream, NativeError> {
    if method.family != SsFamily::Blake3_2022 {
        return Err(NativeError::Config(format!(
            "shadowsocks-2022 codec requires a 2022-blake3 method, got {}",
            cfg.method
        )));
    }
    let key = password_key(method, &cfg.password)?;
    let mut salt = Zeroizing::new(vec![0u8; method.aead.salt_len()]);
    crate::rand::fill_nonsecret(&mut salt);
    let mut stream = Ss2022Stream::new(stream, method, key, salt.to_vec(), target.clone());
    let timeout = timeouts::PROTOCOL;
    tokio::time::timeout(timeout, stream.write_handshake())
        .await
        .map_err(|_| NativeError::Timeout {
            step: "shadowsocks-2022 request write",
            limit: timeout,
        })??;
    Ok(Box::new(stream))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::Engine as _;
    use leas_proto::proto_spec::ProtocolConfig;
    use leas_proto::proto_spec::common::SecurityConfig;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;
    use crate::addr::Host;
    use crate::context::NativeConnectParams;

    #[test]
    fn request_fixed_header_layout_is_type_timestamp_length() {
        let h = request_fixed_header(0x0102_0304_0506_0708, 0x0011);
        assert_eq!(h.len(), REQUEST_FIXED_LEN);
        assert_eq!(h[0], HEADER_TYPE_CLIENT_STREAM);
        assert_eq!(&h[1..9], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&h[9..11], &0x0011u16.to_be_bytes());
    }

    #[test]
    fn variable_header_carries_addr_padding_length_and_padding() {
        let target = TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 443);
        let v = request_variable_header(&target, &[0xAA, 0xBB]).unwrap();
        let addr = encode_addr_port_last(&target).unwrap();
        assert_eq!(&v[..addr.len()], &addr[..]);
        let pad_len = u16::from_be_bytes([v[addr.len()], v[addr.len() + 1]]) as usize;
        assert_eq!(v.len(), addr.len() + 2 + pad_len + 2);
        assert_eq!(&v[addr.len() + 2 + pad_len..], &[0xAA, 0xBB]);
    }

    /// A request header MUST carry payload or non-zero padding (spec §3.1.3).
    #[test]
    fn request_variable_header_always_pads_when_no_initial_payload() {
        let target = TargetAddr::new(Host::Ip(IpAddr::from([10, 0, 0, 1])), 80);
        let v = request_variable_header(&target, &[]).unwrap();
        let addr = encode_addr_port_last(&target).unwrap();
        let pad_len = u16::from_be_bytes([v[addr.len()], v[addr.len() + 1]]) as usize;
        assert!(
            (1..=900).contains(&pad_len),
            "padding length {pad_len} outside 1..=900"
        );
    }

    /// The client MUST reject a response whose `request_salt` differs.
    #[test]
    fn response_header_request_salt_mismatch_is_rejected() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let key = [0x01u8; 32];
        let req_salt = [0xAAu8; 32];
        let resp = sealed_response_header(method, &key, &[0xBBu8; 32], 0x1234, 0);
        assert!(matches!(
            open_response_header(method, &key, &req_salt, &resp[32..], &resp[..32]),
            Err(NativeError::Protocol {
                kind: ProtocolKind::Shadowsocks2022,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn salt_and_header_go_out_in_one_write() {
        let (client, server) = RecordingStream::paired();
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let target = TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 8080);
        let mut s = Ss2022Stream::new(
            Box::new(client),
            method,
            Zeroizing::new(vec![0x05u8; 32]),
            vec![0x07u8; 32], // fixed salt so the assertion is deterministic
            target,
        );
        s.write_handshake().await.unwrap();
        assert_eq!(
            server.write_calls(),
            1,
            "salt + both header chunks must be one write"
        );
    }

    /// A `write_all` dropped mid-flush leaves `sealed` set; a shorter retry
    /// after it is credited at most its own length, never the stale chunk's —
    /// `tokio::io::WriteAll` would `split_at` the count and panic. The 8-byte
    /// duplex cannot flush the sealed 1 KiB chunk, so the first poll really
    /// does stop with the chunk pending.
    #[tokio::test]
    async fn dropped_write_does_not_overstate_a_shorter_retry() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let target = TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 8080);
        let (client, mut server) = duplex(8);
        let mut s = Ss2022Stream::new(
            client,
            method,
            Zeroizing::new(vec![0x1Au8; 32]),
            vec![0x2Bu8; 32],
            target,
        );
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

    /// A test-local transport that counts [`AsyncWrite::poll_write`] calls, so
    /// a test can pin that salt + both request header chunks leave as ONE
    /// write. It accepts every byte, so the count is the codec's call count,
    /// not the transport's partial writes.
    struct RecordingStream {
        writes: Arc<AtomicUsize>,
    }

    impl RecordingStream {
        /// A writer and the counter the test asserts on.
        fn paired() -> (Self, Self) {
            let writes = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    writes: Arc::clone(&writes),
                },
                Self { writes },
            )
        }

        fn write_calls(&self) -> usize {
            self.writes.load(Ordering::Relaxed)
        }
    }

    impl AsyncWrite for RecordingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for RecordingStream {
        /// Nothing to read: the peer never writes in these tests.
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Every rejection the header validation can make, each with a CURRENT
    /// timestamp so the check under test is the one that fires: a wrong type,
    /// a stale timestamp, and a salt that is not the one we sent. The matching
    /// header is the positive control — it opens and yields its length.
    #[test]
    fn response_header_rejects_wrong_type_stale_timestamp_and_foreign_salt() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let key = [0x01u8; 32];
        let ours = [0xAAu8; 32];
        let now = now_unix_secs().unwrap();
        let cases = [
            (
                "wrong type",
                sealed_response_header_with(
                    method,
                    &key,
                    &ours,
                    HEADER_TYPE_CLIENT_STREAM,
                    0x1234,
                    now,
                ),
            ),
            (
                "stale timestamp",
                sealed_response_header(
                    method,
                    &key,
                    &ours,
                    0x1234,
                    now - TIMESTAMP_TOLERANCE_SECS - 1,
                ),
            ),
            (
                "foreign salt",
                sealed_response_header(method, &key, &[0xBBu8; 32], 0x1234, now),
            ),
        ];
        for (label, wire) in cases {
            assert!(
                matches!(
                    open_response_header(method, &key, &ours, &wire[32..], &wire[..32]),
                    Err(NativeError::Protocol {
                        kind: ProtocolKind::Shadowsocks2022,
                        ..
                    })
                ),
                "{label} must be rejected"
            );
        }
        let good = sealed_response_header(method, &key, &ours, 0x1234, now);
        let (len, _half) = open_response_header(method, &key, &ours, &good[32..], &good[..32])
            .expect("a matching header opens");
        assert_eq!(len, 0x1234, "the header's length field comes back");
    }

    /// The reader frames a whole response: salt, the header (validated at
    /// counter 0), the header's payload chunk (counter 1) and then `[len]
    /// [payload]` pairs (counters 2 and 3) — the sequence the header's dual
    /// role as first length chunk dictates. The server side is framed here
    /// from the primitives with hand-written counter nonces, so the reader's
    /// own bookkeeping is not what proves it. A clean end-of-stream lands on
    /// the chunk boundary.
    #[tokio::test]
    async fn reader_opens_the_response_header_then_payload_chunks() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let key = [0x42u8; 32];
        let ours = [0x43u8; 32];
        let (client, mut server) = duplex(4096);
        let mut stream = Ss2022Stream::new(
            client,
            method,
            Zeroizing::new(key.to_vec()),
            ours.to_vec(),
            TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 443),
        );

        // The server's own salt leads its header; the header's length field
        // covers the 5-byte first payload that follows.
        let salt = [0x44u8; 32];
        let subkey = reference_subkey(method, &key, &salt);
        let mut header = vec![HEADER_TYPE_SERVER_STREAM];
        header.extend_from_slice(&now_unix_secs().unwrap().to_be_bytes());
        header.extend_from_slice(&ours);
        header.extend_from_slice(&5u16.to_be_bytes());
        let mut wire = salt.to_vec();
        for (index, chunk) in [&header[..], b"hello", &6u16.to_be_bytes(), b" world"]
            .into_iter()
            .enumerate()
        {
            let index = u64::try_from(index).expect("four chunks");
            method
                .aead
                .seal_into(&subkey, &nonce(index), b"", chunk, &mut wire)
                .unwrap();
        }
        server.write_all(&wire).await.unwrap();
        drop(server);

        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello world");
    }

    /// A tampered seal must reach the caller as a `Shadowsocks2022` protocol
    /// error riding the `io::Error` source — not a bare `Io`, and not the
    /// classic kind `crypto::aead` labels its own failures with. `reclassify`
    /// plus the single wrap at the byte-stream seam are the only things
    /// standing between the two, so both code paths are driven: the header's
    /// payload chunk (counter 1) and a `[len]` seal (counter 2).
    #[tokio::test]
    async fn tampered_seals_stay_2022_protocol_errors() {
        let (method, key, ours) = response_material();
        let salt = [0x26u8; 32];
        let subkey = reference_subkey(method, &key, &salt);
        for tamper in [1u64, 2] {
            let mut wire = salt.to_vec();
            for (index, chunk) in [
                &response_header(&ours, 5)[..],
                b"hello",
                &5u16.to_be_bytes(),
            ]
            .into_iter()
            .enumerate()
            {
                let index = u64::try_from(index).expect("three chunks");
                method
                    .aead
                    .seal_into(&subkey, &nonce(index), b"", chunk, &mut wire)
                    .unwrap();
                if index == tamper {
                    let last = wire.len() - 1;
                    wire[last] ^= 0x01;
                }
            }
            let err = read_response_to_failure(method, &key, &ours, wire).await;
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "counter {tamper}");
            assert_2022_protocol_error(&err, &format!("a tampered seal at counter {tamper}"));
        }
    }

    /// A response the peer cuts short — after its salt (the mandatory header
    /// never arrives) and between a declared length and its payload — is a wire
    /// failure like any other: `UnexpectedEof` at the seam, with this codec's
    /// classification in the source. This is the one class `eof_result` raises
    /// rather than the AEAD, and it must not downcast to nothing.
    #[tokio::test]
    async fn truncated_responses_stay_2022_protocol_errors() {
        let (method, key, ours) = response_material();
        let salt = [0x27u8; 32];
        let subkey = reference_subkey(method, &key, &salt);

        // EOF after the salt: the response header — and so the reader half —
        // never arrives.
        let err = read_response_to_failure(method, &key, &ours, salt.to_vec()).await;
        assert_eq!(
            err.kind(),
            io::ErrorKind::UnexpectedEof,
            "EOF after the salt"
        );
        assert_2022_protocol_error(&err, "EOF after the salt");

        // EOF after a declared length: the payload it announced never arrives.
        let mut wire = salt.to_vec();
        for (index, chunk) in [
            &response_header(&ours, 5)[..],
            b"hello",
            &6u16.to_be_bytes(),
        ]
        .into_iter()
        .enumerate()
        {
            let index = u64::try_from(index).expect("three chunks");
            method
                .aead
                .seal_into(&subkey, &nonce(index), b"", chunk, &mut wire)
                .unwrap();
        }
        let err = read_response_to_failure(method, &key, &ours, wire).await;
        assert_eq!(
            err.kind(),
            io::ErrorKind::UnexpectedEof,
            "EOF after a declared length"
        );
        assert_2022_protocol_error(&err, "EOF after a declared length");
    }

    /// The method/key/request-salt trio the response tests share.
    fn response_material() -> (SsMethod, [u8; 32], [u8; 32]) {
        (
            SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap(),
            [0x24u8; 32],
            [0x25u8; 32],
        )
    }

    /// A server response header (`type=1 | ts | request_salt | len`) with a
    /// current timestamp, unsealed.
    fn response_header(request_salt: &[u8], len: u16) -> Vec<u8> {
        let mut header = vec![HEADER_TYPE_SERVER_STREAM];
        header.extend_from_slice(&now_unix_secs().unwrap().to_be_bytes());
        header.extend_from_slice(request_salt);
        header.extend_from_slice(&len.to_be_bytes());
        header
    }

    /// Write `wire` from the server side of a fresh stream, close, and read
    /// until the failure the caller would see.
    async fn read_response_to_failure(
        method: SsMethod,
        key: &[u8],
        request_salt: &[u8],
        wire: Vec<u8>,
    ) -> io::Error {
        let (client, mut server) = duplex(4096);
        let mut stream = Ss2022Stream::new(
            client,
            method,
            Zeroizing::new(key.to_vec()),
            request_salt.to_vec(),
            TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 443),
        );
        server.write_all(&wire).await.unwrap();
        drop(server);
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap_err()
    }

    /// The classification every wire failure of this codec must carry: the
    /// `NativeError` riding the seam's `io::Error` source is this codec's own
    /// protocol kind. The downcast is written out rather than hidden behind an
    /// `expect`, so a missing (or double-wrapped) classification fails with
    /// THIS message instead of a helper's panic.
    fn assert_2022_protocol_error(err: &io::Error, what: &str) {
        let source = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<NativeError>());
        assert!(
            matches!(
                source,
                Some(NativeError::Protocol {
                    kind: ProtocolKind::Shadowsocks2022,
                    ..
                })
            ),
            "{what} must stay a Shadowsocks2022 protocol error: {err}"
        );
    }

    /// The request direction end to end, decrypted one layer below
    /// [`Ss2022Stream`]: `salt ‖ fixed header ‖ variable header` at counters
    /// 0/1 and one data write at 2/3, with the target address and a non-zero
    /// padding length in the variable header.
    #[tokio::test]
    async fn request_handshake_then_a_data_write_continue_the_counter() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let key = vec![0x55u8; 32];
        let salt = vec![0x66u8; 32];
        let target = TargetAddr::new(Host::Domain("example.com".into()), 443);
        let now = now_unix_secs().unwrap();
        let (client, server) = duplex(1 << 20);
        let mut s = Ss2022Stream::new(
            client,
            method,
            Zeroizing::new(key.clone()),
            salt.clone(),
            target.clone(),
        );
        s.write_handshake().await.unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        drop(s);

        let (got_salt, variable, plain, lens) = read_request_all(server, method, &key, now).await;
        assert_eq!(got_salt, salt, "the stream leads with the writer's salt");
        assert_eq!(plain, b"hello");
        assert_eq!(lens, vec![5], "one chunk, no split");
        let addr = encode_addr_port_last(&target).unwrap();
        assert_eq!(
            &variable[..addr.len()],
            &addr[..],
            "the variable header leads with the target address, port last"
        );
        let pad_len = usize::from(u16::from_be_bytes([
            variable[addr.len()],
            variable[addr.len() + 1],
        ]));
        assert!(
            (1..=MAX_PADDING as usize).contains(&pad_len),
            "without an initial payload the header must pad: {pad_len}"
        );
        assert_eq!(variable.len(), addr.len() + 2 + pad_len);
    }

    /// A write above the cap splits into a full 0xFFFF chunk and the tail —
    /// the 2022 length field is a whole `u16`, not classic AEAD's 0x3FFF.
    #[tokio::test]
    async fn writes_split_at_the_ffff_cap() {
        let method = SsMethod::from_method("2022-blake3-chacha20-poly1305").unwrap();
        let key = vec![0x88u8; 32];
        let salt = vec![0x99u8; 32];
        let target = TargetAddr::new(Host::Ip(IpAddr::from([10, 1, 2, 3])), 8443);
        let now = now_unix_secs().unwrap();
        let payload = vec![0xABu8; MAX_PAYLOAD + 5];
        let (client, server) = duplex(1 << 21);
        let mut s = Ss2022Stream::new(
            client,
            method,
            Zeroizing::new(key.clone()),
            salt.clone(),
            target,
        );
        s.write_handshake().await.unwrap();
        s.write_all(&payload).await.unwrap();
        s.flush().await.unwrap();
        drop(s);

        let (_, _, plain, lens) = read_request_all(server, method, &key, now).await;
        assert_eq!(plain, payload, "every byte round-trips");
        assert_eq!(lens, vec![MAX_PAYLOAD, 5], "split at the 0xFFFF cap");
    }

    /// `connect` takes the destination from [`LinkContext::target`] (the
    /// chain's per-link next hop, NOT the profile target in
    /// `ctx.params.target`), derives the key from the base64 PSK and returns a
    /// `Send + 'static` tunnel that keeps sealing after the handshake.
    #[tokio::test]
    async fn connect_seals_the_link_target_after_a_base64_psk_handshake() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let psk = [0x77u8; 32];
        let password = base64::engine::general_purpose::STANDARD.encode(psk);
        let cfg = SsConfig {
            method: "2022-blake3-aes-256-gcm".into(),
            password,
            security: SecurityConfig::default(),
            remarks: None,
            plugin: None,
        };
        // The link target and the profile target differ on purpose: the wire
        // must carry the LINK one.
        let profile_target = TargetAddr::new(Host::Domain("profile.example".into()), 80);
        let link_target = TargetAddr::new(Host::Domain("link.example".into()), 443);
        let params = NativeConnectParams::new(
            ProtocolConfig::Ss(cfg.clone()),
            EndpointEssentials::new("127.0.0.1", 8388),
            profile_target,
        );
        let ctx = LinkContext::new(params, link_target.clone());
        let now = now_unix_secs().unwrap();

        let (client, server) = duplex(1 << 20);
        let mut tunnel = connect(&ctx, Box::new(client), &cfg, method).await.unwrap();
        assert_send_static(&tunnel);
        tunnel.write_all(b"ping").await.unwrap();
        tunnel.flush().await.unwrap();
        drop(tunnel);

        let (_, variable, plain, lens) = read_request_all(server, method, &psk, now).await;
        let addr = encode_addr_port_last(&link_target).unwrap();
        assert_eq!(
            &variable[..addr.len()],
            &addr[..],
            "the handshake destination is ctx.target"
        );
        assert_eq!(plain, b"ping");
        assert_eq!(lens, vec![4]);
    }

    /// Compile-time proof that the tunnel [`connect`] returns is `Send +
    /// 'static`, i.e. usable as the chain's boxed stream.
    fn assert_send_static<T: Send + 'static>(_: &T) {}

    /// The 2022 session subkey straight from the spec, through the hand-rolled
    /// BLAKE3 in `protocol/vless/encryption` — an implementation independent
    /// of the `blake3` crate `method::stream_subkey` delegates to, so the tests
    /// verify the derivation instead of restating it.
    fn reference_subkey(method: SsMethod, key: &[u8], salt: &[u8]) -> Vec<u8> {
        let material = [key, salt].concat();
        crate::protocol::vless::encryption::derive_key_bytes(
            b"shadowsocks 2022 session subkey",
            &material,
        )[..method.key_len()]
            .to_vec()
    }

    /// The `index`-th little-endian counter nonce, written out by hand so
    /// these tests do not lean on the counter object the codec uses: an
    /// off-by-one in the codec's counter sequence has to fail here.
    fn nonce(index: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&index.to_le_bytes());
        nonce
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

    /// Decrypt a whole request direction from the primitives, one layer below
    /// [`Ss2022Stream`]: the salt, the fixed header (counter 0), the variable
    /// header (counter 1) and then `[2B len][ct + tag]` pairs (counters 2/3,
    /// 4/5…). Every nonce is written out by hand and the subkey comes from the
    /// independent BLAKE3, so the counter sequence and the framing are pinned
    /// against something other than the codec's own state. Returns
    /// `(salt, variable header, payload plaintext, per-chunk lengths)`; the
    /// fixed header's `len` is asserted against the header it counts.
    async fn read_request_all(
        mut server: DuplexStream,
        method: SsMethod,
        key: &[u8],
        now: u64,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<usize>) {
        let tag = method.aead.tag_len();
        let mut salt = vec![0u8; method.aead.salt_len()];
        server.read_exact(&mut salt).await.unwrap();
        let subkey = reference_subkey(method, key, &salt);
        let mut fixed = vec![0u8; REQUEST_FIXED_LEN + tag];
        server.read_exact(&mut fixed).await.unwrap();
        let fixed = method
            .aead
            .open(&subkey, &nonce(0), b"", &fixed)
            .expect("the fixed header seal opens at counter 0");
        assert_eq!(fixed[0], HEADER_TYPE_CLIENT_STREAM, "request type");
        let timestamp = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
        assert!(
            timestamp.abs_diff(now) <= 1,
            "timestamp {timestamp} is not the one we stamped ({now})"
        );
        let var_len = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
        let mut var = vec![0u8; var_len + tag];
        server.read_exact(&mut var).await.unwrap();
        let variable = method
            .aead
            .open(&subkey, &nonce(1), b"", &var)
            .expect("the variable header seal opens at counter 1");
        assert_eq!(
            variable.len(),
            var_len,
            "the fixed header's length counts the whole variable header"
        );
        let mut plain = Vec::new();
        let mut lens = Vec::new();
        loop {
            let index = u64::try_from(lens.len()).expect("a test writes few chunks");
            let mut head = vec![0u8; LEN_FIELD + tag];
            if read_exact_or_eof(&mut server, &mut head).await.is_none() {
                return (salt, variable, plain, lens);
            }
            let len = method
                .aead
                .open(&subkey, &nonce(2 + 2 * index), b"", &head)
                .expect("the length seal opens at its own counter");
            let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
            let mut body = vec![0u8; len + tag];
            read_exact_or_eof(&mut server, &mut body)
                .await
                .expect("a declared length arrives in full");
            plain.extend_from_slice(
                &method
                    .aead
                    .open(&subkey, &nonce(3 + 2 * index), b"", &body)
                    .expect("the payload seal opens at its own counter"),
            );
            lens.push(len);
        }
    }
}
