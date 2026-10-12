//! `VMess` record tunnel stream: peels the AEAD response header on the first
//! read, then transparently decodes response records (read side) and encodes
//! request records (write side).
//!
//! Mirrors Xray-core
//! `proxy/vmess/encoding/client.go` (`DecodeResponseHeader`,
//! `DecodeResponseBody`, `EncodeRequestBody`) with the request option byte 0
//! — the server chunk-decodes AEAD bodies regardless
//! (`crypto.PlainChunkSizeParser`), so no ChunkStream/ChunkMasking option bit
//! is ever set.
//!
//! Record framing (both directions): `2B BE ciphertext-length | AES-128-GCM(
//! key = session.{request,response}_body_key, nonce = IV-with-first-2-bytes-
//! overwritten-by-BE-counter)` — the length field is the FULL wire size
//! (plaintext + 16-byte GCM tag, Go `AuthenticationWriter.seal`); a record
//! carrying only the tag (field == 16) or a zero field marks end of stream.
//! The counter starts 0 and increments per record (Go `GenerateChunkNonce`);
//! the nonce is the first 12 bytes of the modified IV. The request direction
//! uses the request keys + its own counter, the response direction the
//! response keys + its own counter.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use aes_gcm::aead::{Aead, AeadInOut};
use aes_gcm::{Aes128Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::BoxStream;
use crate::protocol::vmess::header::{SECURITY_AES128_GCM, SECURITY_CHACHA20_POLY1305, Session};
use crate::protocol::vmess::keys;

/// Peel salt paths (Go `aead.KDFSaltConstAEADRespHeader*`), as byte slices for
/// [`keys::kdf16_bytes_path`].
const RESP_LEN_KEY_SALT: &[u8] = b"AEAD Resp Header Len Key";
const RESP_LEN_IV_SALT: &[u8] = b"AEAD Resp Header Len IV";
const RESP_PAYLOAD_KEY_SALT: &[u8] = b"AEAD Resp Header Key";
const RESP_PAYLOAD_IV_SALT: &[u8] = b"AEAD Resp Header IV";

/// The largest plaintext ONE record can carry: the 2-byte BE field is the
/// FULL wire size (plaintext + 16-byte GCM tag), so the u16 framing limit is
/// `65535 - 16`. This is the ceiling a peer may legitimately fill — the send
/// side is capped far lower by xray's chunk sealer (see
/// `udp::MAX_SEND_PAYLOAD`).
pub(super) const MAX_RECORD_PLAINTEXT: usize = u16::MAX as usize - 16;

/// Read-side state machine (Copy so no borrow of `self` is held across
/// awaits; buffers live on the struct, fill counters in the state).
#[derive(Clone, Copy)]
enum ReadState {
    /// Filling the 18-byte AEAD response-header length ciphertext.
    PeelLen { filled: usize },
    /// Filling the (len+16)-byte AEAD response-header payload ciphertext.
    PeelPayload { total: usize, filled: usize },
    /// Filling the 2-byte BE record field (ciphertext size, plaintext+tag).
    RecordLen { filled: usize },
    /// Filling the `field`-byte record ciphertext.
    RecordData { total: usize, filled: usize },
    /// Terminal error: every subsequent poll returns the same error.
    Dead(&'static str),
}

/// Record cipher selected by the payload security byte. The response-header
/// peel is ALWAYS AES-128-GCM; only the body records dispatch here.
enum Cipher {
    Aes128Gcm(Box<Aes128Gcm>),
    Chacha20Poly1305(Box<ChaCha20Poly1305>),
}

impl Cipher {
    /// Build from the header security byte; the 16-byte `VMess` session key is
    /// expanded to 32 bytes for chacha (md5 chain) inside.
    fn new(security: u8, key16: &[u8; 16]) -> Self {
        match security {
            SECURITY_AES128_GCM => Self::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(key16).expect("16-byte key"),
            )),
            SECURITY_CHACHA20_POLY1305 => {
                let key32 = keys::chacha20_key_32(key16);
                Self::Chacha20Poly1305(Box::new(
                    ChaCha20Poly1305::new_from_slice(key32.as_slice()).expect("32-byte key"),
                ))
            }
            other => panic!("vmess payload security {other} not validated"),
        }
    }

    fn encrypt_into(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> Result<(), ()> {
        let res = match self {
            Self::Aes128Gcm(c) => c.encrypt_in_place(nonce.into(), b"", buf),
            Self::Chacha20Poly1305(c) => c.encrypt_in_place(nonce.into(), b"", buf),
        };
        res.map_err(|_| ())
    }

    fn decrypt_inplace(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> Result<(), ()> {
        let res = match self {
            Self::Aes128Gcm(c) => c.decrypt_in_place(nonce.into(), b"", buf),
            Self::Chacha20Poly1305(c) => c.decrypt_in_place(nonce.into(), b"", buf),
        };
        res.map_err(|_| ())
    }
}
/// Record nonce: response/request IV with the first two bytes replaced by
/// the BE counter (Go `GenerateChunkNonce`), truncated to 12 bytes.
fn record_nonce(iv12: &[u8; 12], counter: u16) -> [u8; 12] {
    let mut nonce = *iv12;
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Read-direction state: the record state machine, its staging buffers and
/// the response-direction AEAD progression.
///
/// Every partial fill lives HERE rather than in a future — that is what
/// makes the read path resumable, so a dropped `poll_read` (or a cancelled
/// `recv` above it) loses nothing, and what lets the read direction move
/// wholesale into its own half.
struct VmessRead {
    /// Session material the one-shot response-header peel derives its AEAD
    /// keys from; the record cipher is pre-expanded below.
    session: Session,
    read_state: ReadState,
    /// Decrypted record data awaiting the caller (also the ciphertext staging
    /// buffer during `RecordData`; the state distinguishes the two roles).
    pending: Vec<u8>,
    pending_pos: usize,
    /// Staging for the 18-byte peel length AEAD.
    peel_len: [u8; 18],
    /// Staging for the (len+16)-byte peel payload AEAD (one-shot).
    peel_buf: Vec<u8>,
    /// Staging for the 2-byte record length.
    len_buf: [u8; 2],
    /// Expanded response record cipher (selected by the payload security
    /// byte) so the record codec never re-derives a key schedule.
    resp_cipher: Cipher,
    resp_nonce: [u8; 12],
    resp_counter: u16,
}

impl VmessRead {
    fn new(session: Session) -> Self {
        let mut resp_nonce = [0u8; 12];
        resp_nonce.copy_from_slice(&session.response_body_iv[..12]);
        let resp_cipher = Cipher::new(session.security, &session.response_body_key);
        Self {
            session,
            read_state: ReadState::PeelLen { filled: 0 },
            pending: Vec::new(),
            pending_pos: 0,
            peel_len: [0u8; 18],
            peel_buf: Vec::new(),
            len_buf: [0u8; 2],
            resp_cipher,
            resp_nonce,
            resp_counter: 0,
        }
    }

    /// The ONE read implementation, over any transport: peels the AEAD
    /// response header on the first call, then serves decoded record data.
    /// Both [`VmessClientStream`] and [`VmessReadHalf`] delegate here.
    fn poll_read<R: AsyncRead + Unpin>(
        &mut self,
        inner: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            // Serve already-decrypted record data first (`RecordData` staging
            // also uses `pending`, so only drain outside it).
            if matches!(self.read_state, ReadState::RecordLen { filled: 0 })
                && self.pending_pos < self.pending.len()
            {
                let n = buf.remaining().min(self.pending.len() - self.pending_pos);
                buf.put_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
                self.pending_pos += n;
                if self.pending_pos == self.pending.len() {
                    self.pending.clear();
                    self.pending_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            let state = self.read_state; // Copy — no borrow held across awaits
            match state {
                ReadState::Dead(msg) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, msg)));
                }
                ReadState::PeelLen { filled } => {
                    let mut rb = ReadBuf::new(&mut self.peel_len[filled..]);
                    ready!(Pin::new(&mut *inner).poll_read(cx, &mut rb))?;
                    let got = rb.filled().len();
                    if got == 0 {
                        self.read_state = ReadState::Dead("vmess response header truncated (EOF)");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vmess response header truncated (EOF)",
                        )));
                    }
                    let filled = filled + got;
                    if filled < 18 {
                        self.read_state = ReadState::PeelLen { filled };
                        continue;
                    }
                    // Decrypt the 2-byte plaintext length.
                    let len_key = keys::kdf16_bytes_path(
                        &self.session.response_body_key,
                        &[RESP_LEN_KEY_SALT],
                    );
                    let len_iv =
                        keys::kdf16_bytes_path(&self.session.response_body_iv, &[RESP_LEN_IV_SALT]);
                    let Ok(pt) = Aes128Gcm::new_from_slice(&len_key)
                        .expect("16-byte KDF output")
                        .decrypt((&len_iv[..12]).try_into().unwrap(), &self.peel_len[..])
                    else {
                        self.read_state =
                            ReadState::Dead("vmess response header length decrypt failed");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vmess response header length decrypt failed",
                        )));
                    };
                    if pt.len() != 2 {
                        self.read_state = ReadState::Dead("vmess response header length corrupt");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vmess response header length corrupt",
                        )));
                    }
                    let total = u16::from_be_bytes([pt[0], pt[1]]) as usize + 16;
                    self.peel_buf.resize(total, 0);
                    self.read_state = ReadState::PeelPayload { total, filled: 0 };
                }
                ReadState::PeelPayload { total, filled } => {
                    let mut rb = ReadBuf::new(&mut self.peel_buf[filled..total]);
                    ready!(Pin::new(&mut *inner).poll_read(cx, &mut rb))?;
                    let got = rb.filled().len();
                    if got == 0 {
                        self.read_state =
                            ReadState::Dead("vmess response header payload truncated (EOF)");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vmess response header payload truncated (EOF)",
                        )));
                    }
                    let filled = filled + got;
                    if filled < total {
                        self.read_state = ReadState::PeelPayload { total, filled };
                        continue;
                    }
                    let payload_key = keys::kdf16_bytes_path(
                        &self.session.response_body_key,
                        &[RESP_PAYLOAD_KEY_SALT],
                    );
                    let payload_iv = keys::kdf16_bytes_path(
                        &self.session.response_body_iv,
                        &[RESP_PAYLOAD_IV_SALT],
                    );
                    let Ok(pt) = Aes128Gcm::new_from_slice(&payload_key)
                        .expect("16-byte KDF output")
                        .decrypt(
                            (&payload_iv[..12]).try_into().unwrap(),
                            &self.peel_buf[..total],
                        )
                    else {
                        self.peel_buf = Vec::new();
                        self.read_state = ReadState::Dead("vmess response header decrypt failed");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vmess response header decrypt failed",
                        )));
                    };
                    self.peel_buf = Vec::new(); // one-shot peel; drop staging
                    if pt.is_empty() {
                        self.read_state =
                            ReadState::Dead("vmess response header payload too short");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vmess response header payload too short",
                        )));
                    }
                    // Echo check: payload[0] must equal the request's random
                    // response header byte.
                    if pt[0] != self.session.response_header {
                        self.read_state = ReadState::Dead("vmess response header echo mismatch");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vmess response header echo mismatch",
                        )));
                    }
                    self.read_state = ReadState::RecordLen { filled: 0 };
                }
                ReadState::RecordLen { filled } => {
                    let mut rb = ReadBuf::new(&mut self.len_buf[filled..]);
                    ready!(Pin::new(&mut *inner).poll_read(cx, &mut rb))?;
                    let got = rb.filled().len();
                    if got == 0 {
                        // Clean EOF at a record boundary (Go `io.ReadFull` on
                        // the size bytes returns `io.EOF`) — read_to_end
                        // finishes normally.
                        if filled > 0 {
                            self.read_state =
                                ReadState::Dead("vmess response record header truncated (EOF)");
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "vmess response record header truncated (EOF)",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    let filled = filled + got;
                    if filled < 2 {
                        self.read_state = ReadState::RecordLen { filled };
                        continue;
                    }
                    let field = u16::from_be_bytes(self.len_buf);
                    // End-of-stream markers: a record carrying only the GCM
                    // tag (field == 16) or a zero field (Go: `size ==
                    // auth.Overhead()` -> io.EOF).
                    if field == 0 || field == 16 {
                        return Poll::Ready(Ok(()));
                    }
                    // The field is the full wire size (plaintext + tag).
                    let total = field as usize;
                    self.pending.resize(total, 0);
                    self.pending_pos = 0;
                    self.read_state = ReadState::RecordData { total, filled: 0 };
                }
                ReadState::RecordData { total, filled } => {
                    let mut rb = ReadBuf::new(&mut self.pending[filled..total]);
                    ready!(Pin::new(&mut *inner).poll_read(cx, &mut rb))?;
                    let got = rb.filled().len();
                    if got == 0 {
                        self.read_state = ReadState::Dead("vmess response record truncated (EOF)");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vmess response record truncated (EOF)",
                        )));
                    }
                    let filled = filled + got;
                    if filled < total {
                        self.read_state = ReadState::RecordData { total, filled };
                        continue;
                    }
                    let nonce = record_nonce(&self.resp_nonce, self.resp_counter);
                    self.resp_counter = self.resp_counter.wrapping_add(1);
                    // Decrypt in place: the staging buffer already holds the
                    // full ciphertext, so the plaintext lands with no fresh
                    // `Vec` — the tag is stripped by truncation.
                    if self
                        .resp_cipher
                        .decrypt_inplace(&nonce, &mut self.pending)
                        .is_ok()
                    {
                        self.pending_pos = 0;
                        self.read_state = ReadState::RecordLen { filled: 0 };
                        continue;
                    }
                    self.read_state = ReadState::Dead("vmess response record decrypt failed");
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vmess response record decrypt failed",
                    )));
                }
            }
        }
    }
}

/// Write-direction state: the one pending request record, its flush position
/// and the request-direction AEAD progression. Never reads a byte, so it
struct VmessWrite {
    /// The one pending request record: `[2B BE wire size][AEAD]`, sealed in
    /// place into this reusable buffer. Empty = no pending record.
    seal: Vec<u8>,
    write_pos: usize,
    /// Original caller length the pending record was sealed from — the
    /// byte-stream path's bookkeeping only: [`Self::poll_write`] reports it
    /// once the record has flushed, while the datagram path
    /// ([`Self::write_datagram`]) never reports another payload's length.
    write_len: usize,
    /// Expanded request record cipher (selected by the payload security
    /// byte) so the record codec never re-derives a key schedule.
    req_cipher: Cipher,
    req_nonce: [u8; 12],
    req_counter: u16,
}

impl VmessWrite {
    fn new(session: &Session) -> Self {
        let mut req_nonce = [0u8; 12];
        req_nonce.copy_from_slice(&session.request_body_iv[..12]);
        Self {
            seal: Vec::new(),
            write_pos: 0,
            write_len: 0,
            req_cipher: Cipher::new(session.security, &session.request_body_key),
            req_nonce,
            req_counter: 0,
        }
    }

    /// Seal `payload` into the pending-record slot: `[2B BE wire size][AEAD]`
    /// under the request counter's nonce (Go
    /// `AuthenticationWriter.seal`). The counter is consumed here, so the
    /// caller MUST have cleared any previous record first.
    fn seal_pending(&mut self, payload: &[u8]) -> io::Result<()> {
        debug_assert!(
            self.seal.is_empty(),
            "exactly one record is sealed at a time"
        );
        if payload.len() > MAX_RECORD_PLAINTEXT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("vmess record too large (max {MAX_RECORD_PLAINTEXT} bytes per record)"),
            ));
        }
        let nonce = record_nonce(&self.req_nonce, self.req_counter);
        // Seal in place into the reusable buffer: the plaintext goes in,
        // the tag is appended — no per-record `Vec`s, only the AEAD's own
        // internal block work.
        self.seal.clear();
        self.seal.extend_from_slice(payload);
        if self
            .req_cipher
            .encrypt_into(&nonce, &mut self.seal)
            .is_err()
        {
            self.seal.clear();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vmess request record seal failed",
            ));
        }
        let field =
            u16::try_from(payload.len() + 16).expect("record size bounded by the guard above");
        self.seal.splice(0..0, field.to_be_bytes());
        self.write_pos = 0;
        self.req_counter = self.req_counter.wrapping_add(1);
        Ok(())
    }

    /// Flush the pending write record to `inner`. Returns `Ok(())` once the
    /// record is fully written (and clears it).
    fn flush_pending<W: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.seal.is_empty() {
                return Poll::Ready(Ok(()));
            }
            if self.write_pos >= self.seal.len() {
                // Record fully written: clear (keeping the allocation for
                // the next record) instead of dropping the buffer.
                self.seal.clear();
                self.write_pos = 0;
                return Poll::Ready(Ok(()));
            }
            let n = ready!(Pin::new(&mut *inner).poll_write(cx, &self.seal[self.write_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "vmess tunnel inner write accepted 0 bytes",
                )));
            }
            self.write_pos += n;
        }
    }

    /// The ONE byte-stream write implementation: seal up to one record's
    /// worth of the caller's buffer and report the sealed length once
    /// flushed (`write_all` loops for larger buffers — a single record tops
    /// out at `MAX_RECORD_PLAINTEXT`, so sealing the whole buffer would
    /// reject any write over ~64 KiB).
    fn poll_write<W: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut W,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            // Empty writes are skipped (mirror xray: no zero-length record).
            return Poll::Ready(Ok(0));
        }
        // Seal at most one record. If a previous record is still being
        // flushed, the caller is retrying with the same buffer (tokio poll
        // contract) — the pending record was built from its prefix.
        if self.seal.is_empty() {
            let take = buf.len().min(MAX_RECORD_PLAINTEXT);
            if let Err(e) = self.seal_pending(&buf[..take]) {
                return Poll::Ready(Err(e));
            }
            self.write_len = take;
        }
        // Flush the pending record; return the sealed length once fully
        // written (partial inner writes resume on subsequent polls).
        match self.flush_pending(inner, cx) {
            Poll::Ready(Ok(())) => {
                let sealed = self.write_len;
                self.write_len = 0;
                Poll::Ready(Ok(sealed))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// The ONE datagram write implementation: seal `payload` into exactly ONE
    /// record and put that record on the wire — the datagram entry point of
    /// the tunnel (`udp::PacketConn::send` calls it instead of `write_all`),
    /// and unlike [`Self::poll_write`] it is CANCEL-SAFE at the record
    /// boundary.
    ///
    /// `poll_write` owes the byte-stream contract: it seals the caller's
    /// buffer, then reports that buffer's ORIGINAL length once the record has
    /// flushed, and a retry with the same buffer reuses the record already
    /// sealed. Dropping a `write_all` future mid-flush therefore leaves both
    /// the half-written record and the stale length behind, and the next,
    /// unrelated buffer inherits them — a truncated datagram on the wire.
    /// This method reports success only for the payload it sealed itself.
    ///
    /// Leftover resolution, when a previous `write_datagram` was dropped:
    /// - bytes already on the wire (`write_pos > 0`): the peer is mid-record,
    ///   so that record MUST be completed before a new one starts.
    /// - nothing written yet: the record never reached the wire, so it is
    ///   dropped and its counter given back (sealing is the counter's only
    ///   consumer and at most one record is ever pending) — the abandoned
    ///   datagram is not resurrected ahead of this one.
    async fn write_datagram<W: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut W,
        payload: &[u8],
    ) -> io::Result<()> {
        if payload.is_empty() {
            // A record with no plaintext is xray's end-of-stream marker
            // (field == 16, Go `size == auth.Overhead()`), never a datagram.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vmess udp: an empty record is the end-of-stream marker",
            ));
        }
        let mut sealed = false;
        std::future::poll_fn(move |cx| -> Poll<io::Result<()>> {
            if !sealed {
                if self.write_pos > 0 {
                    ready!(self.flush_pending(&mut *inner, cx))?;
                } else if !self.seal.is_empty() {
                    self.seal.clear();
                    self.req_counter = self.req_counter.wrapping_sub(1);
                }
                self.write_len = 0;
                self.seal_pending(payload)?;
                sealed = true;
            }
            let flushed = ready!(self.flush_pending(&mut *inner, cx));
            self.write_len = 0;
            Poll::Ready(flushed)
        })
        .await
    }
}

/// `VMess` client tunnel stream: response-header peel + record codec over the
/// secured connection.
///
/// Transport plus one state struct per direction: the read and write
/// directions share nothing but the byte stream, which is what lets
/// [`Self::split`] hand them to separate tasks — and why the combined path
/// keeps owning `inner` outright, with no lock.
pub struct VmessClientStream<S = BoxStream> {
    inner: S,
    read: VmessRead,
    write: VmessWrite,
}

impl<S> VmessClientStream<S> {
    /// Wrap `inner` with a `VMess` session: peels the response header on the
    /// first read, then codes AEAD records.
    #[must_use]
    pub fn new(inner: S, session: Session) -> Self {
        // The write direction only needs the request key material; the
        // response-header peel needs the session itself, so it takes it.
        let write = VmessWrite::new(&session);
        let read = VmessRead::new(session);
        Self { inner, read, write }
    }

    /// The secured connection behind the record codec (crate-internal; the
    /// e2e PQ assertion recovers the engine `TlsStream` through it).
    #[cfg_attr(not(feature = "native-e2e"), allow(dead_code))] // e2e PQ assertion only
    pub(crate) const fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncWrite + Unpin> VmessClientStream<S> {
    /// Seal `payload` into exactly ONE record and put that record on the
    /// wire — the datagram entry point of the tunnel (`udp::PacketConn::send`
    /// calls it instead of `write_all`), and unlike [`AsyncWrite::poll_write`]
    /// it is CANCEL-SAFE at the record boundary: it reports success only for
    /// the payload it sealed itself, and resolves a dropped predecessor's
    /// leftovers (complete it if any of it reached the wire, drop it and give
    /// its counter back otherwise).
    pub async fn write_datagram(&mut self, payload: &[u8]) -> io::Result<()> {
        self.write.write_datagram(&mut self.inner, payload).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VmessClientStream<S> {
    /// Split into halves that may be used concurrently from separate tasks:
    /// the record decoder can then live in a reader task of its own, where no
    /// `select!` arm can cancel it mid-record.
    ///
    /// Each direction's state moves wholesale (counter, cipher, staging), so
    /// the halves resume exactly where the combined stream left off. Only the
    /// transport gains [`tokio::io::split`]'s lock, and only here — the
    /// combined stream keeps owning it directly.
    #[must_use]
    pub fn split(self) -> (VmessReadHalf<ReadHalf<S>>, VmessWriteHalf<WriteHalf<S>>) {
        let (read_half, write_half) = tokio::io::split(self.inner);
        (
            VmessReadHalf {
                inner: read_half,
                read: self.read,
            },
            VmessWriteHalf {
                inner: write_half,
                write: self.write,
            },
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VmessClientStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.read.poll_read(&mut this.inner, cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VmessClientStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.write.poll_write(&mut this.inner, cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The read direction of a split [`VmessClientStream`]: the response-header
/// peel and the record decoder over the read half of the transport.
///
/// Owns the read state outright, so a `poll_read` dropped mid-record is
/// resumed by the next one — the reason a reader task can be driven
/// independently of the writer.
pub struct VmessReadHalf<R> {
    inner: R,
    read: VmessRead,
}

impl<R: AsyncRead + Unpin> AsyncRead for VmessReadHalf<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.read.poll_read(&mut this.inner, cx, buf)
    }
}

/// The write direction of a split [`VmessClientStream`]: the record sealer
/// over the write half of the transport.
///
/// Keeps both entry points the combined stream has —
/// [`Self::write_datagram`] and [`AsyncWrite`].
pub struct VmessWriteHalf<W> {
    inner: W,
    write: VmessWrite,
}

impl<W: AsyncWrite + Unpin> VmessWriteHalf<W> {
    /// Seal `payload` into exactly ONE record and put that record on the
    /// wire, cancel-safe at the record boundary — the same datagram path
    /// [`VmessClientStream::write_datagram`] takes.
    pub async fn write_datagram(&mut self, payload: &[u8]) -> io::Result<()> {
        self.write.write_datagram(&mut self.inner, payload).await
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for VmessWriteHalf<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.write.poll_write(&mut this.inner, cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes128Gcm, KeyInit};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::protocol::vmess::header::{SECURITY_CHACHA20_POLY1305, Session};
    use crate::protocol::vmess::keys::{kdf16_bytes_path, sha256_first16};

    /// Server-side response header seal (mirrors Go `EncodeResponseHeader`):
    /// lenAEAD(18) + payloadAEAD(len+16), both AES-128-GCM, AAD nil, nonce = KDF [:12].
    fn seal_response_header(key: &[u8; 16], iv: &[u8; 16], payload: &[u8]) -> Vec<u8> {
        fn ae(key: &[u8; 16], iv: &[u8; 16], key_salt: &str, iv_salt: &str, msg: &[u8]) -> Vec<u8> {
            let k = kdf16_bytes_path(key, &[key_salt.as_bytes()]);
            let v = kdf16_bytes_path(iv, &[iv_salt.as_bytes()]);
            Aes128Gcm::new_from_slice(&k)
                .unwrap()
                .encrypt((&v[..12]).try_into().unwrap(), msg)
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

    /// Server-side response record (mirrors Go `EncodeResponseBody` chunk):
    /// 2B BE ciphertext length (plaintext + GCM tag) + AES-128-GCM data,
    /// counter nonce from the response IV.
    fn seal_record(key: &[u8; 16], iv: &[u8; 16], counter: u16, data: &[u8]) -> Vec<u8> {
        let mut nonce = *iv;
        nonce[..2].copy_from_slice(&counter.to_be_bytes());
        let ct = Aes128Gcm::new_from_slice(key)
            .unwrap()
            .encrypt((&nonce[..12]).try_into().unwrap(), data)
            .unwrap();
        u16::try_from(data.len() + 16)
            .unwrap()
            .to_be_bytes()
            .into_iter()
            .chain(ct)
            .collect()
    }

    /// Server-side chacha20-poly1305 response record (Go `EncodeResponseBody`
    /// with security 4): 2B BE ciphertext length + chacha20poly1305 data.
    fn seal_record_chacha(key16: &[u8; 16], iv: &[u8; 16], counter: u16, data: &[u8]) -> Vec<u8> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
        let mut nonce = *iv;
        nonce[..2].copy_from_slice(&counter.to_be_bytes());
        let key32 = keys::chacha20_key_32(key16);
        let ct = ChaCha20Poly1305::new_from_slice(key32.as_slice())
            .unwrap()
            .encrypt((&nonce[..12]).try_into().unwrap(), data)
            .unwrap();
        u16::try_from(data.len() + 16)
            .unwrap()
            .to_be_bytes()
            .into_iter()
            .chain(ct)
            .collect()
    }

    #[test]
    fn records_roundtrip_with_peel() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (client_side, mut server_side) = tokio::io::duplex(8192);
            let mut session = Session::new();
            session.request_body_iv = [0x11; 16];
            session.request_body_key = [0x22; 16];
            session.response_header = 0x99;
            session.response_body_key = sha256_first16(&session.request_body_key);
            session.response_body_iv = sha256_first16(&session.request_body_iv);

            // fake server: response header ([resp_header, option 0, cmd 0, len 0])
            // then one data record with counter 0.
            let mut wire = seal_response_header(
                &session.response_body_key,
                &session.response_body_iv,
                &[0x99, 0, 0, 0],
            );
            wire.extend_from_slice(&seal_record(
                &session.response_body_key,
                &session.response_body_iv,
                0,
                b"hello",
            ));
            server_side.write_all(&wire).await.unwrap();
            drop(server_side); // EOF after the data — read_to_end can finish

            let mut tunnel = VmessClientStream::new(Box::new(client_side), session);
            let mut got = Vec::new();
            tunnel.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"hello");
        });
    }

    #[test]
    fn chacha20_records_roundtrip_with_peel() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (client_side, mut server_side) = tokio::io::duplex(8192);
            let mut session = Session::new();
            session.security = SECURITY_CHACHA20_POLY1305;
            session.request_body_iv = [0x11; 16];
            session.request_body_key = [0x22; 16];
            session.response_header = 0x99;
            session.response_body_key = sha256_first16(&session.request_body_key);
            session.response_body_iv = sha256_first16(&session.request_body_iv);

            // Response HEADER seal is always AES-128-GCM (Go OpenVMessAEADHeader);
            // only the body record uses the chacha cipher.
            let mut wire = seal_response_header(
                &session.response_body_key,
                &session.response_body_iv,
                &[0x99, 0, 0, 0],
            );
            wire.extend_from_slice(&seal_record_chacha(
                &session.response_body_key,
                &session.response_body_iv,
                0,
                b"chacha body",
            ));
            server_side.write_all(&wire).await.unwrap();
            drop(server_side);

            let mut tunnel = VmessClientStream::new(Box::new(client_side), session);
            let mut got = Vec::new();
            tunnel.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"chacha body");
        });
    }

    #[test]
    fn response_eof_marker_ends_stream() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (client_side, mut server_side) = tokio::io::duplex(8192);
            let mut session = Session::new();
            session.request_body_iv = [0x11; 16];
            session.request_body_key = [0x22; 16];
            session.response_header = 0x99;
            session.response_body_key = sha256_first16(&session.request_body_key);
            session.response_body_iv = sha256_first16(&session.request_body_iv);

            // A record carrying only the GCM tag (field == 16) terminates the
            // stream cleanly (Go: `size == auth.Overhead()` -> io.EOF).
            let mut wire = seal_response_header(
                &session.response_body_key,
                &session.response_body_iv,
                &[0x99, 0, 0, 0],
            );
            wire.extend_from_slice(&seal_record(
                &session.response_body_key,
                &session.response_body_iv,
                0,
                b"",
            ));
            server_side.write_all(&wire).await.unwrap();
            drop(server_side);

            let mut tunnel = VmessClientStream::new(Box::new(client_side), session);
            let mut got = Vec::new();
            tunnel.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"");
        });
    }

    #[test]
    fn peel_rejects_wrong_echo_byte() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (client_side, mut server_side) = tokio::io::duplex(8192);
            let mut session = Session::new();
            session.request_body_iv = [0x11; 16];
            session.request_body_key = [0x22; 16];
            session.response_header = 0x99;
            session.response_body_key = sha256_first16(&session.request_body_key);
            session.response_body_iv = sha256_first16(&session.request_body_iv);

            // wrong echo byte 0x98 -> must error, not stream garbage
            let wire = seal_response_header(
                &session.response_body_key,
                &session.response_body_iv,
                &[0x98, 0, 0, 0],
            );
            server_side.write_all(&wire).await.unwrap();
            drop(server_side);

            let mut tunnel = VmessClientStream::new(Box::new(client_side), session);
            let mut got = Vec::new();
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tunnel.read_to_end(&mut got),
            )
            .await;
            assert!(
                res.is_err() || res.unwrap().is_err(),
                "must fail, got {got:?}"
            );
        });
    }

    /// Client-side inverse of [`seal_record`]: reads one record off `stream`
    /// and returns its plaintext (2B BE ciphertext length, then that many
    /// bytes).
    async fn read_record(
        stream: &mut tokio::io::DuplexStream,
        key: &[u8; 16],
        iv: &[u8; 16],
        counter: u16,
    ) -> Vec<u8> {
        use aes_gcm::aead::Aead;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let field = u16::from_be_bytes(len_buf) as usize;
        let mut ct = vec![0u8; field];
        stream.read_exact(&mut ct).await.unwrap();
        let mut nonce = *iv;
        nonce[..2].copy_from_slice(&counter.to_be_bytes());
        Aes128Gcm::new_from_slice(key)
            .unwrap()
            .decrypt((&nonce[..12]).try_into().unwrap(), &ct[..])
            .unwrap()
    }

    #[test]
    fn write_seals_request_records_with_counters() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (client_side, mut server_side) = tokio::io::duplex(8192);
            let mut session = Session::new();
            session.request_body_iv = [0x11; 16];
            session.request_body_key = [0x22; 16];
            session.response_header = 0x99;
            session.response_body_key = sha256_first16(&session.request_body_key);
            session.response_body_iv = sha256_first16(&session.request_body_iv);
            let (req_key, req_iv) = (session.request_body_key, session.request_body_iv);

            let mut tunnel = VmessClientStream::new(Box::new(client_side), session);
            tunnel.write_all(b"first").await.unwrap();
            tunnel.write_all(b"second-payload").await.unwrap();
            tunnel.flush().await.unwrap();

            // Each write_all produced exactly one record with its own counter.
            assert_eq!(
                read_record(&mut server_side, &req_key, &req_iv, 0).await,
                b"first"
            );
            assert_eq!(
                read_record(&mut server_side, &req_key, &req_iv, 1).await,
                b"second-payload"
            );
        });
    }

    #[test]
    fn write_resumes_partial_record_flush() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // 1-byte duplex: the inner write accepts a byte per poll, so the
            // record flush must resume across polls and still report the
            // ORIGINAL length to write_all.
            let (client_side, mut server_side) = tokio::io::duplex(1);
            let mut session = Session::new();
            session.request_body_iv = [0x11; 16];
            session.request_body_key = [0x22; 16];
            session.response_header = 0x99;
            session.response_body_key = sha256_first16(&session.request_body_key);
            session.response_body_iv = sha256_first16(&session.request_body_iv);
            let (req_key, req_iv) = (session.request_body_key, session.request_body_iv);

            // Drain the wire concurrently so the writer never blocks on the
            // full 1-byte buffer.
            let reader =
                tokio::spawn(
                    async move { read_record(&mut server_side, &req_key, &req_iv, 0).await },
                );

            let mut tunnel = VmessClientStream::new(Box::new(client_side), session);
            tunnel
                .write_all(b"payload-larger-than-one-byte")
                .await
                .unwrap();
            tunnel.flush().await.unwrap();
            drop(tunnel);

            assert_eq!(reader.await.unwrap(), b"payload-larger-than-one-byte");
        });
    }

    #[test]
    fn write_chunks_buffers_over_record_ceiling() {
        // Regression: a single write larger than one AEAD record must split
        // across records (the throughput bench's 1 MiB `write_all` hit
        // `InvalidInput: vmess record too large`). Counters advance per
        // record; the reassembled payload is byte-identical.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (client_side, mut server_side) = tokio::io::duplex(1 << 20);
            let mut session = Session::new();
            session.request_body_iv = [0x11; 16];
            session.request_body_key = [0x22; 16];
            session.response_header = 0x99;
            session.response_body_key = sha256_first16(&session.request_body_key);
            session.response_body_iv = sha256_first16(&session.request_body_iv);
            let (req_key, req_iv) = (session.request_body_key, session.request_body_iv);

            let mut tunnel = VmessClientStream::new(Box::new(client_side), session);
            let payload: Vec<u8> = (0..=255u8).cycle().take(200_000).collect();
            tunnel.write_all(&payload).await.unwrap();
            tunnel.flush().await.unwrap();
            drop(tunnel);
            let mut got = Vec::new();
            let mut counter = 0u16;
            while got.len() < payload.len() {
                got.extend_from_slice(
                    &read_record(&mut server_side, &req_key, &req_iv, counter).await,
                );
                counter = counter.wrapping_add(1);
            }
            assert_eq!(got, payload);
            assert!(counter > 1, "oversize write must span several records");
        });
    }

    #[test]
    fn split_halves_code_both_directions() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (client_side, mut server_side) = tokio::io::duplex(8192);
            let mut session = Session::new();
            session.request_body_iv = [0x11; 16];
            session.request_body_key = [0x22; 16];
            session.response_header = 0x99;
            session.response_body_key = sha256_first16(&session.request_body_key);
            session.response_body_iv = sha256_first16(&session.request_body_iv);
            let (req_key, req_iv) = (session.request_body_key, session.request_body_iv);
            let (resp_key, resp_iv) = (session.response_body_key, session.response_body_iv);

            let mut wire = seal_response_header(&resp_key, &resp_iv, &[0x99, 0, 0, 0]);
            wire.extend_from_slice(&seal_record(&resp_key, &resp_iv, 0, b"peeled and decoded"));
            server_side.write_all(&wire).await.unwrap();

            let (mut reader, mut writer) =
                VmessClientStream::new(Box::new(client_side), session).split();

            // The write half keeps BOTH entry points and one counter run
            // across them: the datagram path, then the byte-stream path.
            writer.write_datagram(b"datagram").await.unwrap();
            writer.write_all(b"bytes").await.unwrap();
            writer.flush().await.unwrap();
            assert_eq!(
                read_record(&mut server_side, &req_key, &req_iv, 0).await,
                b"datagram"
            );
            assert_eq!(
                read_record(&mut server_side, &req_key, &req_iv, 1).await,
                b"bytes"
            );

            // The read half still peels the response header, then decodes.
            let mut got = vec![0u8; b"peeled and decoded".len()];
            reader.read_exact(&mut got).await.unwrap();
            assert_eq!(got, b"peeled and decoded");
        });
    }
}
