//! Record-framed `AsyncRead`/`AsyncWrite` stream: TLS 1.3 application data
//! over any duplex transport.
//!
//! This is the layer `thirdparty/tls-fingerprint` LACKED — its
//! `TlsConnection` was `TcpStream`-bound with sync read/write helpers. Here
//! the same decryption (`strip_padding`) and framing (`make_app_data_record`)
//! logic is implemented as a poll-based stream: buffered plaintext on read
//! (handles TLS record fragmentation), 16 KiB plaintext split and
//! partial-write buffering on write. Post-handshake `NewSessionTicket`
//! records (encrypted handshake content, message type 0x04) are consumed and
//! dropped;
//! any other inner handshake message is a protocol error (no renegotiation).

use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::AeadKey;
use crate::error::{Result, TlsError};

/// TLS record content types (RFC 8446 §5.1).
use super::{
    AEAD_TAG_LEN, CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_CHANGE_CIPHER_SPEC,
    CONTENT_HANDSHAKE, HS_NEW_SESSION_TICKET, MAX_RECORD_PAYLOAD, aead_aad, aead_aad_12,
};

/// Maximum plaintext bytes per TLS 1.3 record: 2^14 (RFC 8446 §5.2).
const MAX_RECORD_PLAINTEXT: usize = 16_384;

/// TLS record header length: `content_type(1) || version(2) || length(2)`.
const RECORD_HEADER_LEN: usize = 5;

/// Key material plus per-direction sequence counters for a TLS 1.3
/// or TLS 1.2 connection.
///
/// Deliberately NOT `Clone`: the TLS 1.2 record nonce is derived from
/// `write_seq`, so two streams sharing cloned keys would seal distinct
/// plaintexts under the same (key, nonce) pair — catastrophic for both
/// AES-GCM and ChaCha20-Poly1305.
pub struct AppKeys {
    pub read: RecordCipher,
    pub write: RecordCipher,
    pub read_seq: u64,
    pub write_seq: u64,
}

impl AppKeys {
    /// TLS 1.3 record keys (implicit `IV XOR seq` nonce).
    #[must_use]
    pub const fn tls13(read_key: AeadKey, write_key: AeadKey) -> Self {
        Self {
            read: RecordCipher::Tls13(read_key),
            write: RecordCipher::Tls13(write_key),
            read_seq: 0,
            write_seq: 0,
        }
    }

    /// TLS 1.2 record keys. `read_aead` and `write_aead` carry the
    /// per-direction fixed IVs.
    #[must_use]
    pub const fn tls12(
        read_key: AeadKey,
        write_key: AeadKey,
        read_aead: Tls12Aead,
        write_aead: Tls12Aead,
    ) -> Self {
        // The TLS 1.2 handshake already consumed sequence number 0 in both
        // directions (the encrypted Finished records), so application data
        // starts at seq 1 — unlike TLS 1.3, where `AppKeys` are created
        // before any encrypted record and start at 0.
        Self {
            read: RecordCipher::Tls12(read_key, read_aead),
            write: RecordCipher::Tls12(write_key, write_aead),
            read_seq: 1,
            write_seq: 1,
        }
    }
}

/// Advance a record sequence number, refusing to wrap.
///
/// TLS has no automatic rekey in either version supported here, so a
/// wrapped counter would reuse a nonce under the same key (RFC 8446 §5.5
/// requires terminating the connection instead).
fn advance_seq(seq: &mut u64) -> io::Result<u64> {
    let current = *seq;
    *seq = current.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS record sequence number exhausted — refusing to reuse a nonce",
        )
    })?;
    Ok(current)
}

/// The record-protection cipher for a connection direction.
pub enum RecordCipher {
    /// TLS 1.3: implicit nonce = IV XOR seq, padded inner plaintext.
    Tls13(AeadKey),
    /// TLS 1.2 AEAD: per-suite nonce construction (see [`Tls12Aead`]).
    Tls12(AeadKey, Tls12Aead),
}

impl RecordCipher {
    /// Whether this cipher is TLS 1.3 (the plain-text alert and
    /// non-application-data skip logic applies).
    #[must_use]
    pub const fn is_tls13(&self) -> bool {
        matches!(self, Self::Tls13(_))
    }
}

/// TLS 1.2 AEAD nonce construction. Sole owner of the per-record nonce
/// geometry; the matching key-block geometry lives in
/// [`crate::crypto::tls12::Tls12Suite::fixed_iv_len`].
#[derive(Debug, Clone, Copy)]
pub enum Tls12Aead {
    /// AES-GCM (RFC 5288 §3): 4-byte fixed IV plus an 8-byte explicit
    /// nonce carried in every record.
    AesGcm { fixed_iv: [u8; 4] },
    /// ChaCha20-Poly1305 (RFC 7905 §2): 12-byte fixed IV XOR the padded
    /// 64-bit sequence number, with NO explicit nonce on the wire — the
    /// same construction TLS 1.3 uses.
    Chacha20Poly1305 { fixed_iv: [u8; 12] },
}

/// The explicit nonce bytes a TLS 1.2 record carries: at most 8 (AES-GCM),
/// none for ChaCha20-Poly1305. Fixed-size to keep the record loop
/// allocation-free and length mismatches unrepresentable.
pub(crate) struct ExplicitNonce {
    bytes: [u8; 8],
    len: usize,
}

impl ExplicitNonce {
    /// The bytes to place in (or read from) the record.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Tls12Aead {
    /// Explicit nonce length in bytes: 8 for AES-GCM, 0 for `ChaCha`.
    #[must_use]
    pub const fn explicit_nonce_len(self) -> usize {
        match self {
            Self::AesGcm { .. } => 8,
            Self::Chacha20Poly1305 { .. } => 0,
        }
    }

    /// The explicit nonce this scheme puts on the wire for record `seq`.
    ///
    /// RFC 5288 §3 permits any unique value; the sequence number is the
    /// standard choice (and what OpenSSL/rustls emit), which keeps the
    /// on-wire nonce and the AAD sequence number in lockstep by
    /// construction rather than by a second counter.
    pub(crate) const fn explicit_nonce(self, seq: u64) -> ExplicitNonce {
        ExplicitNonce {
            bytes: seq.to_be_bytes(),
            len: self.explicit_nonce_len(),
        }
    }

    /// Build the 12-byte AEAD nonce for record `seq`.
    ///
    /// AES-GCM: `fixed_iv(4) || explicit(8)` — the fixed IV FIRST. RFC 5288
    /// §3 writes the formula as `explicit_nonce || fixed_iv`, but the
    /// interoperable wire order (OpenSSL, rustls) is fixed-iv-first.
    /// ChaCha20-Poly1305: `fixed_iv(12) XOR left-padded seq` (RFC 7905 §2).
    ///
    /// `explicit` must be exactly [`Self::explicit_nonce_len`] bytes; a
    /// mismatch is a caller bug and is reported, never panicked on.
    pub(crate) fn nonce(self, seq: u64, explicit: &[u8]) -> io::Result<[u8; 12]> {
        if explicit.len() != self.explicit_nonce_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS 1.2 explicit nonce length mismatch",
            ));
        }
        let mut n = [0u8; 12];
        match self {
            Self::AesGcm { fixed_iv } => {
                n[..4].copy_from_slice(&fixed_iv);
                n[4..].copy_from_slice(explicit);
            }
            Self::Chacha20Poly1305 { fixed_iv } => {
                n = fixed_iv;
                for (dst, src) in n[4..].iter_mut().zip(seq.to_be_bytes()) {
                    *dst ^= src;
                }
            }
        }
        Ok(n)
    }
}

/// A TLS 1.3 application-data stream: decrypts records on read, encrypts and
/// frames plaintext on write.
///
/// # EOF semantics (deliberate deviation from RFC 8446 §6.1)
///
/// Transport EOF *without* `close_notify` is surfaced as a clean EOF
/// (`Ready(Ok(()))` with zero bytes), deliberately: this stream is a proxy
/// tunnel whose servers close with TCP FIN and do not guarantee `close_notify`
/// (RST arrives as an `io::Error` before the record layer observes EOF).
/// Truncation attacks per RFC 8446 §6.1 are out of scope for this tunnel
/// semantic; a `close_notify` is still honored as EOF when present.
#[allow(
    clippy::struct_excessive_bools,
    reason = "TLS record-layer I/O state is a handful of independent mode booleans; sub-structuring would spread every access across structs"
)]
pub struct TlsStream<S> {
    inner: S,
    keys: AppKeys,
    /// The record currently being read: wire bytes on the way in, decrypted
    /// plaintext in place afterwards. Sized once to a full record and reused
    /// for every record after, so the data path never allocates per record.
    rec_buf: Vec<u8>,
    /// Plaintext still owed to the caller, as a range inside `rec_buf`.
    plain: Range<usize>,
    /// The 5-byte record header being filled.
    hdr: [u8; 5],
    /// EOF reached (`close_notify` or clean inner close); reads return 0.
    closed: bool,
    /// The record being written: header, body and tag framed in one buffer,
    /// reused for every record.
    pending: Vec<u8>,
    /// How much of `pending` has already reached `inner`. A cursor instead of
    /// `drain(..n)`, which memmoves the remainder on every partial write.
    pending_pos: usize,
    /// Record-read state machine (header, then payload).
    rec: RecordState,
    /// Write side switched to raw passthrough: `poll_write`/`poll_flush`/
    /// `poll_shutdown` forward to `inner` without record framing.
    write_direct: bool,
    /// Read side switched to raw passthrough: `poll_read` reads from
    /// `inner` directly (no record parsing, no decryption).
    read_direct: bool,
    /// The server selected a hybrid (post-quantum) key-share group in its
    /// `ServerHello` — the key schedule consumed `pq || classical` shared
    /// material. `false` = classical-only key exchange.
    negotiated_hybrid: bool,
}

/// Incremental state of reading one TLS record off the wire. The bytes live
/// in [`TlsStream::hdr`] and [`TlsStream::rec_buf`]; this only tracks how
/// much of the current header or payload has arrived.
enum RecordState {
    Header {
        filled: usize,
    },
    Payload {
        content_type: u8,
        len: usize,
        filled: usize,
    },
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TlsStream<S> {
    pub const fn new(inner: S, keys: AppKeys) -> Self {
        Self {
            inner,
            keys,
            rec_buf: Vec::new(),
            plain: 0..0,
            hdr: [0; 5],
            closed: false,
            pending: Vec::new(),
            pending_pos: 0,
            rec: RecordState::Header { filled: 0 },
            write_direct: false,
            read_direct: false,
            negotiated_hybrid: false,
        }
    }

    /// Whether the handshake negotiated a hybrid (post-quantum) key-share
    /// group (`X25519MLKEM768` & co). Set by the handshake driver from the
    /// `ServerHello`'s key share; e2e rows assert it so a PQ row that
    /// silently fell back to classical fails.
    #[must_use]
    pub const fn negotiated_hybrid(&self) -> bool {
        self.negotiated_hybrid
    }

    /// Record the negotiated key-exchange shape (handshake-driver internal).
    pub(crate) const fn set_negotiated_hybrid(&mut self, hybrid: bool) {
        self.negotiated_hybrid = hybrid;
    }

    /// Switch the write side to direct raw writes to the underlying stream.
    ///
    /// Caller must have fully written and flushed the last TLS record first:
    /// once direct, `poll_write` no longer drains `pending`, so any
    /// buffered record ciphertext would be bypassed (and reordered).
    pub const fn set_write_direct(&mut self) {
        self.write_direct = true;
    }

    /// Switch the read side to direct raw reads from the underlying stream.
    ///
    /// Caller must have consumed all decrypted bytes and be at a clean
    /// record boundary (no plaintext owed, `rec` back in `Header` state);
    /// the record layer performs no read-ahead, so any bytes already in the
    /// transport buffer are preserved for the direct reader.
    pub const fn set_read_direct(&mut self) {
        self.read_direct = true;
    }

    /// Read the next complete raw record off `inner` into `self.rec_buf`.
    ///
    /// Returns `Ok(None)` on a clean EOF at a record boundary, or
    /// `Ok(Some((content_type, len)))` once the full header + payload have
    /// arrived — the payload is then `self.rec_buf[..len]`. Partial progress
    /// across polls is preserved in `self.rec`.
    fn poll_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<(u8, usize)>>> {
        loop {
            let step = match &mut self.rec {
                RecordState::Header { filled } => {
                    while *filled < self.hdr.len() {
                        let mut rb = ReadBuf::new(&mut self.hdr[*filled..]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    if *filled == 0 {
                                        return Poll::Ready(Ok(None));
                                    }
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "truncated TLS record header",
                                    )));
                                }
                                *filled += n;
                            }
                        }
                    }
                    let content_type = self.hdr[0];
                    let len = usize::from(u16::from_be_bytes([self.hdr[3], self.hdr[4]]));
                    if let Some(cleartext) = super::cleartext_hello_answer(self.hdr) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "peer does not speak TLS: it answered in cleartext ({cleartext:?}) — \
                                 the endpoint's port or its `security` setting is wrong"
                            ),
                        )));
                    }
                    if len > MAX_RECORD_PAYLOAD {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("TLS record too large: {len} bytes"),
                        )));
                    }
                    Step::HeaderComplete { content_type, len }
                }
                RecordState::Payload {
                    content_type,
                    len,
                    filled,
                } => {
                    while *filled < *len {
                        let mut rb = ReadBuf::new(&mut self.rec_buf[*filled..*len]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "truncated TLS record payload",
                                    )));
                                }
                                *filled += n;
                            }
                        }
                    }
                    Step::RecordReady {
                        content_type: *content_type,
                        len: *len,
                    }
                }
            };
            match step {
                Step::HeaderComplete { content_type, len } => {
                    // One buffer per stream, sized for the largest legal
                    // record: grown once, then reused for every record.
                    if self.rec_buf.len() < MAX_RECORD_PAYLOAD {
                        self.rec_buf.resize(MAX_RECORD_PAYLOAD, 0);
                    }
                    self.rec = RecordState::Payload {
                        content_type,
                        len,
                        filled: 0,
                    };
                }
                Step::RecordReady { content_type, len } => {
                    self.rec = RecordState::Header { filled: 0 };
                    return Poll::Ready(Ok(Some((content_type, len))));
                }
            }
        }
    }

    /// Write as much of `pending` to `inner` as possible.
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                // Ok(0) with a non-empty buffer means "would block" —
                // wait for writability instead of spinning.
                Poll::Pending | Poll::Ready(Ok(0)) => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => {
                    self.pending_pos += n;
                }
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

/// Decrypt the record held in `buf` in place, dispatching to the
/// version-specific path. Takes the keys and the buffer as separate borrows
/// so both can be fields of the same stream.
///
/// The key is borrowed, never cloned: cloning a `RecordCipher` copies a
/// ring `LessSafeKey` (expanded AES key schedule + GHASH tables) per
/// record and duplicates key material on the heap.
fn decrypt_record(
    keys: &mut AppKeys,
    content_type: u8,
    buf: &mut [u8],
) -> io::Result<DecryptedRecord> {
    let AppKeys { read, read_seq, .. } = keys;
    match read {
        RecordCipher::Tls13(key) => process_record_13(key, read_seq, buf),
        RecordCipher::Tls12(key, aead) => {
            process_record_12(key, *aead, read_seq, content_type, buf)
        }
    }
}

/// TLS 1.3: decrypt an `Application Data` record in place (inner content
/// type at the end of the padded plaintext, RFC 8446 §5.4).
fn process_record_13(key: &AeadKey, seq: &mut u64, buf: &mut [u8]) -> io::Result<DecryptedRecord> {
    let n = advance_seq(seq)?;
    let plain_len = key
        .open_in_place(n, &aead_aad(buf.len()), buf)
        .map_err(to_io_error)?;
    let (inner_type, content) = strip_padding(&buf[..plain_len]).map_err(to_io_error)?;
    // The plaintext starts at offset 0, so its length is the whole range.
    let content_len = content.len();
    match inner_type {
        CONTENT_APPLICATION_DATA => Ok(DecryptedRecord::Data(0..content_len)),
        CONTENT_ALERT => alert_to_record(content),
        CONTENT_HANDSHAKE => post_handshake_message(content),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected inner TLS content type {other:#04x}"),
        )),
    }
}

/// TLS 1.2: decrypt a record in place (content type in the outer record
/// header, explicit nonce, no padding, RFC 5246 §6.2.3.3).
fn process_record_12(
    key: &AeadKey,
    aead: Tls12Aead,
    seq: &mut u64,
    content_type: u8,
    buf: &mut [u8],
) -> io::Result<DecryptedRecord> {
    // Every post-handshake record is AEAD-protected. A plaintext
    // ChangeCipherSpec here is an injected record (RFC 5246 §7.4.1 makes it
    // `unexpected_message`): accepting it would let any off-path party feed
    // the read loop records that never yield application bytes.
    if content_type == CONTENT_CHANGE_CIPHER_SPEC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unauthenticated ChangeCipherSpec record after the TLS 1.2 handshake",
        ));
    }
    let explicit_len = aead.explicit_nonce_len();
    if buf.len() < explicit_len + AEAD_TAG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS 1.2 record too short for explicit nonce + tag",
        ));
    }
    let mut explicit = [0u8; 8];
    explicit[..explicit_len].copy_from_slice(&buf[..explicit_len]);
    let n = advance_seq(seq)?;
    let nonce = aead.nonce(n, &explicit[..explicit_len])?;
    let plaintext_len = buf.len() - explicit_len - AEAD_TAG_LEN;
    let additional = aead_aad_12(n, content_type, plaintext_len);
    let opened = key
        .open_in_place_with_nonce(nonce, &additional, &mut buf[explicit_len..])
        .map_err(to_io_error)?;
    let plain = explicit_len..explicit_len + opened;
    match content_type {
        CONTENT_APPLICATION_DATA => Ok(DecryptedRecord::Data(plain)),
        CONTENT_ALERT => alert_to_record(&buf[plain]),
        CONTENT_HANDSHAKE => post_handshake_message(&buf[plain]),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected TLS content type {other:#04x}"),
        )),
    }
}

/// Map an authenticated alert body to a stream event: `close_notify` is a
/// clean EOF, anything else terminates the stream (RFC 8446 §6).
fn alert_to_record(body: &[u8]) -> io::Result<DecryptedRecord> {
    if body.len() >= 2 && body[1] == 0 {
        return Ok(DecryptedRecord::CloseNotify);
    }
    let level = body.first().copied().unwrap_or(2);
    let desc = body.get(1).copied().unwrap_or(0);
    Err(io::Error::new(
        io::ErrorKind::ConnectionReset,
        format!("TLS alert: level {level} description {desc}"),
    ))
}

/// Classify an authenticated handshake record seen after the handshake:
/// only `NewSessionTicket` is legal (no renegotiation in either version).
fn post_handshake_message(body: &[u8]) -> io::Result<DecryptedRecord> {
    match body.first() {
        Some(&HS_NEW_SESSION_TICKET) => Ok(DecryptedRecord::Skip),
        Some(&msg_type) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected handshake message type {msg_type} after handshake"),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty handshake record during application data",
        )),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_direct {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        loop {
            // Serve decrypted plaintext from the current record before
            // touching the wire.
            if this.plain.start < this.plain.end {
                let n = (this.plain.end - this.plain.start).min(buf.remaining());
                buf.put_slice(&this.rec_buf[this.plain.start..this.plain.start + n]);
                this.plain.start += n;
                if this.plain.start == this.plain.end {
                    this.plain = 0..0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            let (content_type, len) = match this.poll_record(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(None)) => {
                    // Transport EOF without close_notify: clean EOF by design
                    // (tunnel semantics — see the type-level docs).
                    this.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(rec))) => rec,
            };
            // TLS 1.3 (RFC 8446 §5.4): raw records other than application data
            // are invalid post handshake — but mirror `read_record`'s
            // leniency for CCS middlebox-compat records (skip). Alerts are
            // exactly 2 bytes (`level || description`, RFC 8446 §6); a
            // truncated raw alert is a protocol error, never silently
            // skipped. TLS 1.2 protects every record type (alerts/handshake/
            // CCS) and dispatches them inside `decrypt_record`.
            if this.keys.read.is_tls13() {
                if content_type == CONTENT_ALERT {
                    if len >= 2 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("TLS alert: {} {}", this.rec_buf[0], this.rec_buf[1]),
                        )));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("truncated TLS alert record ({len} payload byte(s))"),
                    )));
                }
                if content_type != CONTENT_APPLICATION_DATA {
                    continue;
                }
            }
            match decrypt_record(&mut this.keys, content_type, &mut this.rec_buf[..len]) {
                Ok(DecryptedRecord::Data(plain)) => {
                    this.plain = plain;
                }
                Ok(DecryptedRecord::CloseNotify) => {
                    this.closed = true;
                    return Poll::Ready(Ok(()));
                }
                // NewSessionTicket: consumed, nothing to deliver — read on.
                Ok(DecryptedRecord::Skip) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_direct {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        // A partial record from a previous call must drain first.
        if this.pending_pos < this.pending.len() {
            match this.flush_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Split at 2^14 plaintext bytes (RFC 8446 §5.2); the inner content
        // type byte rides at the end of the TLSInnerPlaintext (TLS 1.3).
        // TLS 1.2 frames the plaintext directly, with the explicit nonce
        // (AES-GCM) or nothing (ChaCha20-Poly1305) ahead of the ciphertext.
        let take = buf.len().min(MAX_RECORD_PLAINTEXT);
        // The record is framed in place: header placeholder, body, tag — one
        // buffer, one copy of the caller's bytes, no per-record allocation
        // after the first (`pending` keeps its capacity across records).
        this.pending.clear();
        this.pending_pos = 0;
        this.pending
            .reserve(RECORD_HEADER_LEN + MAX_RECORD_PLAINTEXT + 1 + AEAD_TAG_LEN);
        this.pending
            .extend_from_slice(&[CONTENT_APPLICATION_DATA, 0x03, 0x03, 0, 0]);
        let AppKeys {
            write, write_seq, ..
        } = &mut this.keys;
        let seq = *write_seq;
        // The sequence number is advanced only after a successful seal:
        // a failed seal must not leave the counter — and therefore the
        // next record's nonce — ahead of the AAD the peer will reconstruct.
        let sealed = match write {
            RecordCipher::Tls13(key) => {
                this.pending.extend_from_slice(&buf[..take]);
                this.pending.push(CONTENT_APPLICATION_DATA);
                let body_len = this.pending.len() - RECORD_HEADER_LEN;
                key.seal_in_place(
                    seq,
                    &aead_aad(body_len + AEAD_TAG_LEN),
                    &mut this.pending,
                    RECORD_HEADER_LEN,
                )
            }
            RecordCipher::Tls12(key, aead) => {
                let explicit = aead.explicit_nonce(seq);
                let nonce = match aead.nonce(seq, explicit.as_slice()) {
                    Ok(nonce) => nonce,
                    Err(e) => {
                        this.pending.clear();
                        this.pending_pos = 0;
                        return Poll::Ready(Err(e));
                    }
                };
                let additional = aead_aad_12(seq, CONTENT_APPLICATION_DATA, take);
                // RFC 5246 §6.2.3.3: the explicit nonce is part of the record
                // body but not of the AEAD input (mirrors `make_record_12`).
                this.pending.extend_from_slice(explicit.as_slice());
                let body_start = RECORD_HEADER_LEN + explicit.as_slice().len();
                this.pending.extend_from_slice(&buf[..take]);
                key.seal_in_place_with_nonce(nonce, &additional, &mut this.pending, body_start)
            }
        };
        if let Err(e) = sealed {
            // Never leave a half-framed record behind for `poll_flush`.
            this.pending.clear();
            this.pending_pos = 0;
            return Poll::Ready(Err(to_io_error(e)));
        }
        advance_seq(write_seq)?;
        let body_len = u16::try_from(this.pending.len() - RECORD_HEADER_LEN).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "framed TLS record exceeds the record length field",
            )
        })?;
        this.pending[3..RECORD_HEADER_LEN].copy_from_slice(&body_len.to_be_bytes());
        match this.flush_pending(cx) {
            // Data stays buffered in `pending`; a later poll drains it.
            Poll::Pending | Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_direct {
            return Pin::new(&mut this.inner).poll_flush(cx);
        }
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_direct {
            return Pin::new(&mut this.inner).poll_shutdown(cx);
        }
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Result of advancing the record state machine, resolved outside the
/// `self.rec` borrow so the state can be reassigned.
enum Step {
    HeaderComplete { content_type: u8, len: usize },
    RecordReady { content_type: u8, len: usize },
}

/// What a decrypted record contributes to the application byte stream.
enum DecryptedRecord {
    /// Plaintext to serve, as a range inside [`TlsStream::rec_buf`].
    Data(Range<usize>),
    /// `close_notify` — subsequent reads are EOF.
    CloseNotify,
    /// Record consumed with nothing to deliver (`NewSessionTicket`).
    Skip,
}

/// Remove TLS 1.3 record padding and extract the inner content type (port of
/// `tls-fingerprint/src/handshake.rs::strip_padding`).
///
/// Plaintext layout: `actual_content` || `content_type_byte` || optional
/// zero padding (RFC 8446 §5.4).
fn strip_padding(plaintext: &[u8]) -> Result<(u8, &[u8])> {
    let mut end = plaintext.len();
    while end > 0 && plaintext[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(TlsError::Handshake("all-zero TLSInnerPlaintext".into()));
    }
    let content_type = plaintext[end - 1];
    Ok((content_type, &plaintext[..end - 1]))
}

/// Convert a crate error into an I/O error for the stream traits (the
/// `AsyncRead`/`AsyncWrite` surface speaks `std::io`).
fn to_io_error(e: TlsError) -> io::Error {
    match e {
        TlsError::Io(io) => io,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

#[cfg(test)]
impl AppKeys {
    /// Duplicate the key state for a two-endpoint test over one `duplex`.
    ///
    /// Test-only on purpose: two live writers sharing key material would
    /// reuse nonces (see the type-level note on `Clone`). Tests drive the
    /// two halves in lockstep, so the duplication is safe there.
    fn duplicate(&self) -> Self {
        let dup = |c: &RecordCipher| match c {
            RecordCipher::Tls13(k) => RecordCipher::Tls13(k.clone_key()),
            RecordCipher::Tls12(k, a) => RecordCipher::Tls12(k.clone_key(), *a),
        };
        Self {
            read: dup(&self.read),
            write: dup(&self.write),
            read_seq: self.read_seq,
            write_seq: self.write_seq,
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::crypto::CipherSuiteId;
    use crate::record::{aead_aad, make_app_data_record, read_record};

    /// Extract the inner `AeadKey` from a TLS 1.3 `AppKeys` (test helper).
    fn tls13_key(key: &RecordCipher) -> &AeadKey {
        match key {
            RecordCipher::Tls13(k) => k,
            RecordCipher::Tls12(..) => panic!("not a TLS 1.3 key"),
        }
    }

    fn test_keys() -> AppKeys {
        let key = AeadKey::new(CipherSuiteId::Aes128GcmSha256, &[0x11; 16]).unwrap();
        AppKeys::tls13(key.clone_key(), key.clone_key())
    }

    /// Build a raw application-data record whose `TLSInnerPlaintext` is
    /// `content || inner_type`, sealed under `keys.read_key` with `seq`.
    fn raw_record(keys: &AppKeys, seq: u64, inner_type: u8, content: &[u8]) -> Vec<u8> {
        let mut inner = content.to_vec();
        inner.push(inner_type);
        let ct = tls13_key(&keys.read)
            .seal(seq, &aead_aad(inner.len() + AEAD_TAG_LEN), &inner)
            .unwrap();
        make_app_data_record(&ct)
    }

    #[tokio::test]
    async fn encrypted_duplex_roundtrip() {
        let (a, b) = tokio::io::duplex(4096);
        let key = AeadKey::new(CipherSuiteId::Aes128GcmSha256, &[0x11; 16]).unwrap();
        let keys = AppKeys::tls13(key.clone_key(), key.clone_key());
        let mut client = TlsStream::new(a, keys.duplicate());
        let mut server = TlsStream::new(b, keys);
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        // and the reverse direction (independent per-direction sequences)
        server.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn roundtrip_with_explicit_key_iv() {
        // from_key_iv keys: non-zero write IV must round-trip through the
        // record stream (nonce = IV XOR seq).
        let (a, b) = duplex(4096);
        let key =
            AeadKey::from_key_iv(CipherSuiteId::Aes128GcmSha256, &[0x22; 16], [0x01; 12]).unwrap();
        let keys = AppKeys::tls13(key.clone_key(), key.clone_key());
        let mut client = TlsStream::new(a, keys.duplicate());
        let mut server = TlsStream::new(b, keys);
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn fragmented_records_reassemble_across_records() {
        // "hello" and " world" arrive as two separate TLS records; the reader
        // must present them as one continuous byte stream.
        let (a, b) = duplex(4096);
        let keys = test_keys();
        let mut writer = TlsStream::new(a, keys.duplicate());
        let mut reader = TlsStream::new(b, keys);
        writer.write_all(b"hello").await.unwrap();
        writer.write_all(b" world").await.unwrap();
        let mut buf = [0u8; 11];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello world");
    }

    #[tokio::test]
    async fn one_write_frames_exactly_one_record() {
        // A full 2^14 plaintext write must leave exactly one record on the
        // wire — `17 03 03 || len`, then plaintext + inner type + AEAD tag —
        // and a following smaller write must start its own record instead of
        // extending the first (in-place framing must patch the length field
        // of the record it just built, and only that one).
        let (a, mut b) = duplex(256 * 1024);
        let mut client = TlsStream::new(a, test_keys());
        client
            .write_all(&[0x5a; MAX_RECORD_PLAINTEXT])
            .await
            .unwrap();
        client.write_all(b"12345678").await.unwrap();
        client.flush().await.unwrap();

        let first_body = MAX_RECORD_PLAINTEXT + 1 + AEAD_TAG_LEN;
        let second_body = 8 + 1 + AEAD_TAG_LEN;
        assert_eq!(first_body, 16_401, "16 KiB plaintext + type byte + tag");
        let mut wire = vec![0u8; RECORD_HEADER_LEN * 2 + first_body + second_body];
        b.read_exact(&mut wire).await.unwrap();

        assert_eq!(&wire[..3], &[CONTENT_APPLICATION_DATA, 0x03, 0x03]);
        assert_eq!(
            usize::from(u16::from_be_bytes([wire[3], wire[4]])),
            first_body
        );
        let second = &wire[RECORD_HEADER_LEN + first_body..];
        assert_eq!(&second[..3], &[CONTENT_APPLICATION_DATA, 0x03, 0x03]);
        assert_eq!(
            usize::from(u16::from_be_bytes([second[3], second[4]])),
            second_body
        );
    }

    #[tokio::test]
    async fn record_split_across_inner_reads() {
        // Feed a single record one byte per write through a tiny duplex so the
        // reader's header/payload state machine must survive partial reads.
        let (a, b) = duplex(8);
        let keys = test_keys();
        let rec = raw_record(&keys, 0, CONTENT_APPLICATION_DATA, b"fragmented");
        let writer = tokio::spawn(async move {
            let mut b = b;
            for chunk in rec.chunks(1) {
                b.write_all(chunk).await.unwrap();
            }
        });
        let mut reader = TlsStream::new(a, keys);
        let mut buf = [0u8; 10];
        reader.read_exact(&mut buf).await.unwrap();
        writer.await.unwrap();
        assert_eq!(&buf, b"fragmented");
    }

    #[tokio::test]
    async fn close_notify_returns_eof_after_buffered_data() {
        // Buffered plaintext is served first; close_notify then surfaces as
        // EOF (0 bytes), not as an error.
        let (a, mut b) = duplex(4096);
        let keys = test_keys();
        let data_rec = raw_record(&keys, 0, CONTENT_APPLICATION_DATA, b"bye");
        let cn_rec = raw_record(&keys, 1, CONTENT_ALERT, &[1, 0]);
        tokio::spawn(async move {
            b.write_all(&data_rec).await.unwrap();
            b.write_all(&cn_rec).await.unwrap();
        });
        let mut reader = TlsStream::new(a, keys);
        let mut buf = [0u8; 8];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"bye");
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "close_notify must surface as EOF");
        // EOF is sticky
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn non_close_alerts_error() {
        let (a, mut b) = duplex(4096);
        let keys = test_keys();
        let rec = raw_record(&keys, 0, CONTENT_ALERT, &[2, 40]); // fatal handshake_failure
        tokio::spawn(async move {
            b.write_all(&rec).await.unwrap();
        });
        let mut reader = TlsStream::new(a, keys);
        let mut buf = [0u8; 8];
        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn new_session_ticket_records_are_skipped() {
        // TLS 1.3 servers send NewSessionTicket as encrypted handshake
        // records right after the handshake; they must be consumed and
        // dropped so the following application data is delivered.
        let (a, mut b) = duplex(4096);
        let keys = test_keys();
        let nst = raw_record(
            &keys,
            0,
            CONTENT_HANDSHAKE,
            &[HS_NEW_SESSION_TICKET, 0, 0, 0],
        );
        let data = raw_record(&keys, 1, CONTENT_APPLICATION_DATA, b"ticket?");
        tokio::spawn(async move {
            b.write_all(&nst).await.unwrap();
            b.write_all(&data).await.unwrap();
        });
        let mut reader = TlsStream::new(a, keys);
        let mut buf = [0u8; 7];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ticket?");
    }

    #[tokio::test]
    async fn non_ticket_handshake_inner_content_is_rejected() {
        // Post-handshake handshake records other than NewSessionTicket (e.g.
        // a ServerHello — renegotiation) are refused.
        let (a, mut b) = duplex(4096);
        let keys = test_keys();
        let rec = raw_record(&keys, 0, CONTENT_HANDSHAKE, &[0x02, 0, 0, 0]);
        tokio::spawn(async move {
            b.write_all(&rec).await.unwrap();
        });
        let mut reader = TlsStream::new(a, keys);
        let mut buf = [0u8; 8];
        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("after handshake"),
            "unexpected error message: {err}"
        );
    }

    #[tokio::test]
    async fn large_write_is_split_into_16kib_records() {
        // 20 000 bytes must leave as 2 records: 16 KiB + remainder, each
        // carrying at most 2^14 plaintext bytes.
        let (a, mut b) = duplex(1 << 16);
        let keys = test_keys();
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let mut writer = TlsStream::new(a, keys.duplicate());
        writer.write_all(&payload).await.unwrap();
        drop(writer);

        let mut read_keys = keys;
        let mut got = Vec::new();
        let mut lens = Vec::new();
        for _ in 0..2 {
            let rec = read_record(&mut b).await.unwrap();
            assert_eq!(rec.content_type, CONTENT_APPLICATION_DATA);
            let mut ct = rec.payload;
            let pt = tls13_key(&read_keys.read)
                .open(read_keys.read_seq, &aead_aad(ct.len()), &mut ct)
                .unwrap();
            read_keys.read_seq += 1;
            let (inner_type, content) = strip_padding(&pt).unwrap();
            assert_eq!(inner_type, CONTENT_APPLICATION_DATA);
            lens.push(content.len());
            got.extend_from_slice(content);
        }
        assert_eq!(
            lens,
            vec![MAX_RECORD_PLAINTEXT, 20_000 - MAX_RECORD_PLAINTEXT]
        );
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn direct_write_bypasses_record_layer() {
        // The server half of the duplex is kept raw so the wire bytes are
        // directly observable.
        let (a, mut b) = duplex(4096);
        let keys = test_keys();
        let mut client = TlsStream::new(a, keys.duplicate());

        // 1. Encrypted phase: the client's write leaves the wire as a real
        // TLS record; decrypt it manually on the raw side.
        client.write_all(b"hello").await.unwrap();
        let rec = read_record(&mut b).await.unwrap();
        assert_eq!(rec.content_type, CONTENT_APPLICATION_DATA);
        let mut ct = rec.payload;
        let pt = tls13_key(&keys.read)
            .open(keys.read_seq, &aead_aad(ct.len()), &mut ct)
            .unwrap();
        let (inner_type, content) = strip_padding(&pt).unwrap();
        assert_eq!(inner_type, CONTENT_APPLICATION_DATA);
        assert_eq!(content, b"hello");

        // 2+3. Direct mode: the next bytes go out unframed and unencrypted.
        client.set_write_direct();
        client.write_all(b"RAW-BYTES").await.unwrap();

        // 4. The raw half sees the literal bytes. (A record-layer reader
        // would misparse them: the 5-byte header would be 0x52 0x41 0x57
        // 0x2D 0x42 — 0x52 is not a valid content type and the length
        // field (bytes 3-4, 0x2D42) would frame a bogus 11,586-byte
        // payload read.)
        let mut raw = [0u8; 9];
        b.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"RAW-BYTES");
    }

    #[tokio::test]
    async fn direct_read_bypasses_record_layer() {
        // The server half of the duplex is raw: it writes an encrypted
        // record first, then, after the client switches, literal bytes.
        let (a, mut b) = duplex(4096);
        let keys = test_keys();
        let mut client = TlsStream::new(a, keys.duplicate());

        // 1. Encrypted phase: "hello" arrives as a record and the client's
        // record layer decrypts it.
        b.write_all(&raw_record(&keys, 0, CONTENT_APPLICATION_DATA, b"hello"))
            .await
            .unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // 2+3. Direct mode: raw bytes after the boundary are served with no
        // record parsing or decryption.
        client.set_read_direct();
        b.write_all(b"RAW").await.unwrap();
        let mut raw = [0u8; 3];
        client.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"RAW");
    }

    #[tokio::test]
    async fn direct_transition_at_record_boundary_loses_nothing() {
        let (a, b) = duplex(4096);
        let keys = test_keys();
        let mut client = TlsStream::new(a, keys.duplicate());
        let mut server = TlsStream::new(b, keys);

        // Encrypted record, then a raw payload pipelined immediately behind
        // it in one burst.
        server.write_all(b"encrypted").await.unwrap();
        server.set_write_direct();
        server.write_all(b"+RAW").await.unwrap();

        // The client drains the record fully, then switches to direct and
        // still finds the pipelined raw payload in the transport buffer —
        // no read-ahead loss at the boundary.
        let mut buf = [0u8; 9];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"encrypted");
        client.set_read_direct();
        let mut raw = [0u8; 4];
        client.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"+RAW");
    }

    #[tokio::test]
    async fn write_direct_requires_flush_first() {
        // A small duplex forces the partial-write path: the 20 000-byte
        // payload cannot be written in one poll, and the final record's
        // ciphertext can still be buffered in `pending` when `write_all`
        // returns. `flush()` pushes it out; only then may the raw phase
        // start, or the raw bytes would overtake the unflushed record.
        let (a, mut b) = duplex(256);
        let mut keys = test_keys();
        let mut client = TlsStream::new(a, keys.duplicate());
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();

        // Drain the raw server side concurrently so the client's large
        // write can complete through the tiny duplex.
        let server = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut lens = Vec::new();
            for _ in 0..2 {
                let rec = read_record(&mut b).await.unwrap();
                assert_eq!(rec.content_type, CONTENT_APPLICATION_DATA);
                let mut ct = rec.payload;
                let pt = tls13_key(&keys.read)
                    .open(keys.read_seq, &aead_aad(ct.len()), &mut ct)
                    .unwrap();
                keys.read_seq += 1;
                let (inner_type, content) = strip_padding(&pt).unwrap();
                assert_eq!(inner_type, CONTENT_APPLICATION_DATA);
                lens.push(content.len());
                got.extend_from_slice(content);
            }
            let mut tail = Vec::new();
            b.read_to_end(&mut tail).await.unwrap();
            (lens, got, tail)
        });

        client.write_all(&payload).await.unwrap();
        // The last record may still be in `pending`; flush completes it.
        client.flush().await.unwrap();
        client.set_write_direct();
        client.write_all(b"RAW-TAIL").await.unwrap();
        drop(client);

        // The server sees the two encrypted records in order, then the raw
        // tail — nothing reordered by the mode switch.
        let (lens, got, tail) = server.await.unwrap();
        assert_eq!(
            lens,
            vec![MAX_RECORD_PLAINTEXT, 20_000 - MAX_RECORD_PLAINTEXT]
        );
        assert_eq!(got, payload);
        assert_eq!(tail, b"RAW-TAIL");
    }
}
