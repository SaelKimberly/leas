//! Sans-I/O TLS record engine: bytes in, events out, no `tokio` types.
//!
//! The async [`TlsStream`](super::stream::TlsStream) is an adapter over this:
//! it moves bytes between the transport and `feed`/`poll_transmit`, and turns
//! [`RecordEvent`]s into `AsyncRead`/`AsyncWrite` results. Keeping the record
//! protocol here makes it replayable, fuzzable and reusable by a second
//! transport without a reactor.
//!
//! The input buffer is caller-owned: `feed` consumes complete records from the
//! front of a `Vec<u8>` and memmoves only the incomplete tail, so the adapter
//! reads straight into the buffer the engine parses. Decrypted application
//! data is copied once into the engine's reused plaintext window.

use crate::crypto::CipherSuiteId;
use crate::error::{Result, TlsError};

use super::stream::{AppKeys, AppSecrets, RecordCipher};
use super::{
    AEAD_TAG_LEN, CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_CHANGE_CIPHER_SPEC,
    CONTENT_HANDSHAKE, HS_KEY_UPDATE, HS_NEW_SESSION_TICKET, MAX_RECORD_PAYLOAD, aead_aad,
    aead_aad_12,
};

/// One authenticated record outcome the adapter must surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordEvent {
    /// A peer alert other than `close_notify` (level, description).
    Alert { level: u8, description: u8 },
    /// `close_notify` or a clean transport EOF at a record boundary.
    Closed,
}

/// Maximum plaintext bytes per TLS 1.3 record: 2^14 (RFC 8446 §5.2).
pub(crate) const MAX_RECORD_PLAINTEXT: usize = 16_384;
/// TLS record header length: `content_type(1) || version(2) || length(2)`.
pub(crate) const RECORD_HEADER_LEN: usize = 5;
/// Consecutive `KeyUpdate` messages without an application-data record.
pub(crate) const MAX_CONSECUTIVE_KEY_UPDATES: u16 = 128;

/// RFC 8446 §5.5 per-key record limits, kept well inside the published bounds.
pub(crate) const fn record_limit(suite: CipherSuiteId) -> u64 {
    match suite {
        CipherSuiteId::Aes128GcmSha256 | CipherSuiteId::Aes256GcmSha384 => 1 << 24,
        CipherSuiteId::Chacha20Poly1305Sha256 => 1 << 25,
    }
}

/// Whether a direction that has sealed `seq` records must rekey.
pub(crate) const fn should_update(seq: u64, suite: CipherSuiteId) -> bool {
    seq >= record_limit(suite)
}

/// Encrypt-then-frame state for one TLS connection.
pub struct Engine {
    keys: AppKeys,
    /// Decrypted application bytes not yet consumed by the adapter.
    plain: Vec<u8>,
    plain_pos: usize,
    /// Wire bytes waiting for the transport.
    out: Vec<u8>,
    out_pos: usize,
    /// Wire bytes received but not yet a complete record.
    inbuf: Vec<u8>,
    events: Vec<RecordEvent>,
    closed: bool,
    close_sent: bool,
    consecutive_key_updates: u16,
    secrets: Option<AppSecrets>,
}

impl Engine {
    /// Wrap the negotiated key state.
    #[must_use]
    pub const fn new(keys: AppKeys) -> Self {
        Self {
            keys,
            plain: Vec::new(),
            plain_pos: 0,
            out: Vec::new(),
            out_pos: 0,
            inbuf: Vec::new(),
            events: Vec::new(),
            closed: false,
            close_sent: false,
            consecutive_key_updates: 0,
            secrets: None,
        }
    }

    /// Install the application traffic secrets that `KeyUpdate` advances.
    pub fn set_app_secrets(&mut self, secrets: AppSecrets) {
        self.secrets = Some(secrets);
    }

    /// Test seam: put the write counter at a record limit.
    #[cfg(test)]
    pub(crate) const fn set_write_seq(&mut self, seq: u64) {
        self.keys.write_seq = seq;
    }

    /// Test seam: the current write counter.
    #[cfg(test)]
    pub(crate) const fn write_seq(&self) -> u64 {
        self.keys.write_seq
    }

    /// Whether the peer closed the record stream.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Bytes buffered for the next complete record.
    #[must_use]
    pub const fn leftover(&self) -> usize {
        self.inbuf.len()
    }

    /// The next decrypted application bytes, if any.
    #[must_use]
    pub fn poll_data(&self) -> Option<&[u8]> {
        (self.plain_pos < self.plain.len()).then(|| &self.plain[self.plain_pos..])
    }

    /// Consume `n` bytes returned by [`Self::poll_data`].
    pub fn consume(&mut self, n: usize) {
        self.plain_pos = (self.plain_pos + n).min(self.plain.len());
        if self.plain_pos == self.plain.len() {
            self.plain.clear();
            self.plain_pos = 0;
        }
    }

    /// The next non-data event, if any.
    pub fn poll_event(&mut self) -> Option<RecordEvent> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }

    /// Drain sealed bytes into `out`; returns whether any were moved.
    pub fn poll_transmit(&mut self, out: &mut Vec<u8>) -> bool {
        if self.out_pos >= self.out.len() {
            self.out.clear();
            self.out_pos = 0;
            return false;
        }
        out.extend_from_slice(&self.out[self.out_pos..]);
        self.out.clear();
        self.out_pos = 0;
        true
    }

    /// Append wire bytes and consume every complete record.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        let mut buf = std::mem::take(&mut self.inbuf);
        buf.extend_from_slice(bytes);
        let mut pos = 0usize;
        while buf.len() - pos >= RECORD_HEADER_LEN {
            let content_type = buf[pos];
            let len = usize::from(u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]));
            if len > MAX_RECORD_PAYLOAD {
                self.inbuf = buf;
                return Err(TlsError::Handshake(format!(
                    "TLS record too large: {len} bytes"
                )));
            }
            if buf.len() - pos - RECORD_HEADER_LEN < len {
                break;
            }
            let body = pos + RECORD_HEADER_LEN;
            let record = &mut buf[body..body + len];
            if let Err(e) = self.record(content_type, record) {
                self.inbuf = buf;
                return Err(e);
            }
            pos = body + len;
            if self.closed {
                break;
            }
        }
        if pos > 0 {
            buf.drain(..pos);
        }
        self.inbuf = buf;
        Ok(())
    }

    /// Deliver one already-framed record body (the adapter reads the exact
    /// header+payload so a later direct-mode switch cannot lose transport
    /// bytes).
    pub fn feed_record(&mut self, content_type: u8, payload: &mut [u8]) -> Result<()> {
        self.record(content_type, payload)
    }

    /// Report a transport EOF. A partial record makes it a truncation, not a
    /// clean close (RFC 8446 §6.1).
    pub fn feed_eof(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        if !self.inbuf.is_empty() {
            return Err(TlsError::Handshake(format!(
                "transport EOF with {} byte(s) of a partial TLS record",
                self.inbuf.len()
            )));
        }
        self.closed = true;
        self.events.push(RecordEvent::Closed);
        Ok(())
    }

    /// Seal one application-data record from `plaintext` (split by the
    /// adapter at 16 KiB) into the output buffer.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<usize> {
        if self.close_sent {
            return Err(TlsError::Handshake(
                "application data after close_notify (RFC 8446 §6.1)".into(),
            ));
        }
        if self.keys.write.is_tls13() && self.needs_key_update() {
            // Our own limit: ask the peer to rotate too, then switch our
            // sending generation after the KeyUpdate record is sealed.
            self.queue_key_update(true)?;
            self.rotate_write()?;
        }
        let take = plaintext.len().min(MAX_RECORD_PLAINTEXT);
        let start = self.out.len();
        self.out
            .extend_from_slice(&[CONTENT_APPLICATION_DATA, 0x03, 0x03, 0, 0]);
        let AppKeys {
            write, write_seq, ..
        } = &mut self.keys;
        let seq = *write_seq;
        match write {
            RecordCipher::Tls13(key) => {
                self.out.extend_from_slice(&plaintext[..take]);
                self.out.push(CONTENT_APPLICATION_DATA);
                let body_len = self.out.len() - start - RECORD_HEADER_LEN;
                key.seal_in_place(
                    seq,
                    &aead_aad(body_len + AEAD_TAG_LEN),
                    &mut self.out,
                    start + RECORD_HEADER_LEN,
                )?;
            }
            RecordCipher::Tls12(key, aead) => {
                let explicit = aead.explicit_nonce(seq);
                let nonce = aead.nonce(seq, explicit.as_slice())?;
                let additional = aead_aad_12(seq, CONTENT_APPLICATION_DATA, take);
                self.out.extend_from_slice(explicit.as_slice());
                let body_start = start + RECORD_HEADER_LEN + explicit.as_slice().len();
                self.out.extend_from_slice(&plaintext[..take]);
                key.seal_in_place_with_nonce(nonce, &additional, &mut self.out, body_start)?;
            }
        }
        *write_seq = seq
            .checked_add(1)
            .ok_or_else(|| TlsError::Handshake("write sequence exhausted".into()))?;
        let body_len = u16::try_from(self.out.len() - start - RECORD_HEADER_LEN)
            .map_err(|_| TlsError::Handshake("framed TLS record exceeds u16".into()))?;
        self.out[start + 3..start + RECORD_HEADER_LEN].copy_from_slice(&body_len.to_be_bytes());
        Ok(take)
    }

    /// Seal up to 32 KiB of plaintext as consecutive records in one call,
    /// so a 64 KiB relay write costs two transport writes instead of four.
    /// A lone small write still produces exactly one record.
    pub fn seal_batch(&mut self, plaintext: &[u8]) -> Result<usize> {
        const BATCH: usize = 32 * 1024;
        let mut consumed = 0usize;
        while consumed < plaintext.len() && consumed < BATCH {
            let n = self.seal(&plaintext[consumed..])?;
            if n == 0 {
                break;
            }
            consumed += n;
        }
        Ok(consumed)
    }

    /// Queue a `close_notify` alert if one has not been sent.
    pub fn queue_close_notify(&mut self) -> Result<()> {
        self.queue_alert(0)
    }

    const fn needs_key_update(&self) -> bool {
        match (self.secrets.as_ref(), &self.keys.write) {
            (Some(secrets), RecordCipher::Tls13(_)) => {
                should_update(self.keys.write_seq, secrets.suite())
            }
            _ => false,
        }
    }

    /// Append decrypted application bytes without discarding any earlier
    /// record still owed to the adapter.
    fn append_plain(&mut self, bytes: &[u8]) {
        if self.plain_pos == self.plain.len() {
            self.plain.clear();
            self.plain_pos = 0;
        }
        self.plain.extend_from_slice(bytes);
    }

    fn record(&mut self, content_type: u8, body: &mut [u8]) -> Result<()> {
        if content_type == CONTENT_CHANGE_CIPHER_SPEC {
            return Err(TlsError::Handshake(
                "unexpected ChangeCipherSpec after the handshake".into(),
            ));
        }
        if self.keys.read.is_tls13() {
            if content_type == CONTENT_ALERT {
                let level = body.first().copied().unwrap_or(2);
                let Some(&description) = body.get(1) else {
                    return Err(TlsError::Handshake(
                        "truncated plaintext TLS alert record".into(),
                    ));
                };
                if description == 0 {
                    self.closed = true;
                    self.events.push(RecordEvent::Closed);
                } else {
                    self.events.push(RecordEvent::Alert { level, description });
                }
                return Ok(());
            }
            if content_type != CONTENT_APPLICATION_DATA {
                return Ok(());
            }
            let plain_len = self.open_tls13(body)?;
            let (inner_type, content) = strip_padding(&body[..plain_len])?;
            let content_len = content.len();
            match inner_type {
                CONTENT_APPLICATION_DATA => {
                    self.consecutive_key_updates = 0;
                    self.append_plain(&body[..content_len]);
                }
                CONTENT_ALERT => {
                    let [level, description, ..] = content else {
                        return Err(TlsError::Handshake(
                            "TLS alert body must be level || description (RFC 8446 §6)".into(),
                        ));
                    };
                    if *description == 0 {
                        self.closed = true;
                        self.events.push(RecordEvent::Closed);
                    } else {
                        self.events.push(RecordEvent::Alert {
                            level: *level,
                            description: *description,
                        });
                    }
                }
                CONTENT_HANDSHAKE => {
                    let messages = post_handshake_messages(&body[..content_len])?;
                    for message in messages {
                        match message {
                            PostHandshake::NewSessionTicket => {}
                            PostHandshake::KeyUpdate { request_update } => {
                                self.apply_key_update(request_update)?;
                            }
                        }
                    }
                }
                other => {
                    return Err(TlsError::Handshake(format!(
                        "unexpected inner TLS content type {other:#04x}"
                    )));
                }
            }
            return Ok(());
        }
        // TLS 1.2: every post-handshake record is AEAD-protected and the
        // content type is in the outer header.
        let plain_len = self.open_tls12(content_type, body)?;
        match content_type {
            CONTENT_APPLICATION_DATA => {
                self.consecutive_key_updates = 0;
                self.append_plain(&body[..plain_len]);
            }
            CONTENT_ALERT => {
                if plain_len >= 2 && body[1] == 0 {
                    self.closed = true;
                    self.events.push(RecordEvent::Closed);
                } else {
                    self.events.push(RecordEvent::Alert {
                        level: body.first().copied().unwrap_or(2),
                        description: body.get(1).copied().unwrap_or(0),
                    });
                }
            }
            _ => {
                return Err(TlsError::Handshake(
                    "post-handshake TLS 1.2 handshake message (renegotiation) is refused".into(),
                ));
            }
        }
        Ok(())
    }

    fn open_tls13(&mut self, body: &mut [u8]) -> Result<usize> {
        let seq = advance_seq(&mut self.keys.read_seq)?;
        let RecordCipher::Tls13(key) = &self.keys.read else {
            return Err(TlsError::Handshake("read key is not TLS 1.3".into()));
        };
        key.open_in_place(seq, &aead_aad(body.len()), body)
    }

    fn open_tls12(&mut self, content_type: u8, body: &mut [u8]) -> Result<usize> {
        let seq = advance_seq(&mut self.keys.read_seq)?;
        let RecordCipher::Tls12(key, aead) = &self.keys.read else {
            return Err(TlsError::Handshake("read key is not TLS 1.2".into()));
        };
        let explicit_len = aead.explicit_nonce_len();
        if body.len() < explicit_len + AEAD_TAG_LEN {
            return Err(TlsError::Handshake("TLS 1.2 record too short".into()));
        }
        let explicit = &body[..explicit_len];
        let nonce = aead.nonce(seq, explicit)?;
        let additional = aead_aad_12(seq, content_type, body.len() - explicit_len - AEAD_TAG_LEN);
        let plain_len =
            key.open_in_place_with_nonce(nonce, &additional, &mut body[explicit_len..])?;
        body.copy_within(explicit_len..explicit_len + plain_len, 0);
        Ok(plain_len)
    }

    fn apply_key_update(&mut self, request_update: bool) -> Result<()> {
        if !self.keys.read.is_tls13() {
            return Err(TlsError::Handshake(
                "KeyUpdate in a TLS 1.2 session is illegal".into(),
            ));
        }
        self.consecutive_key_updates = self.consecutive_key_updates.saturating_add(1);
        if self.consecutive_key_updates > MAX_CONSECUTIVE_KEY_UPDATES {
            return Err(TlsError::Handshake(format!(
                "peer sent more than {MAX_CONSECUTIVE_KEY_UPDATES} consecutive TLS KeyUpdate messages"
            )));
        }
        let next = self
            .secrets
            .as_mut()
            .ok_or_else(|| TlsError::Handshake("KeyUpdate without app secrets".into()))?
            .advance(true)?;
        self.keys.read = RecordCipher::Tls13(next);
        self.keys.read_seq = 0;
        if request_update {
            // The ACK is sealed with the OLD write key, then the sender
            // advances to the next generation (RFC 8446 §4.6.3).
            self.queue_key_update(false)?;
            self.rotate_write()?;
        }
        Ok(())
    }

    fn queue_key_update(&mut self, request_update: bool) -> Result<()> {
        let msg = [HS_KEY_UPDATE, 0x00, 0x00, 0x01, u8::from(request_update)];
        let start = self.out.len();
        let AppKeys {
            write, write_seq, ..
        } = &mut self.keys;
        let RecordCipher::Tls13(key) = &*write else {
            return Err(TlsError::Handshake(
                "KeyUpdate in a TLS 1.2 session is illegal".into(),
            ));
        };
        let seq = *write_seq;
        self.out
            .extend_from_slice(&[CONTENT_APPLICATION_DATA, 0x03, 0x03, 0, 0]);
        self.out.extend_from_slice(&msg);
        self.out.push(CONTENT_HANDSHAKE);
        let record_len = self.out.len() - start - RECORD_HEADER_LEN + AEAD_TAG_LEN;
        let len = u16::try_from(record_len)
            .map_err(|_| TlsError::Handshake("KeyUpdate record too long".into()))?;
        self.out[start + 3..start + RECORD_HEADER_LEN].copy_from_slice(&len.to_be_bytes());
        key.seal_in_place(
            seq,
            &aead_aad(record_len),
            &mut self.out,
            start + RECORD_HEADER_LEN,
        )?;
        *write_seq = seq + 1;
        Ok(())
    }

    fn rotate_write(&mut self) -> Result<()> {
        let secret = self
            .secrets
            .as_mut()
            .ok_or_else(|| TlsError::Handshake("cannot rotate a write key".into()))?
            .advance(false)?;
        self.keys.write = RecordCipher::Tls13(secret);
        self.keys.write_seq = 0;
        Ok(())
    }

    fn queue_alert(&mut self, description: u8) -> Result<()> {
        if self.close_sent {
            return Ok(());
        }
        let start = self.out.len();
        let AppKeys {
            write, write_seq, ..
        } = &mut self.keys;
        let seq = *write_seq;
        match write {
            RecordCipher::Tls13(key) => {
                self.out
                    .extend_from_slice(&[CONTENT_APPLICATION_DATA, 0x03, 0x03, 0, 0]);
                self.out.extend_from_slice(&[1, description, CONTENT_ALERT]);
                let record_len = self.out.len() - start - RECORD_HEADER_LEN + AEAD_TAG_LEN;
                let len = u16::try_from(record_len)
                    .map_err(|_| TlsError::Handshake("close_notify record too long".into()))?;
                self.out[start + 3..start + RECORD_HEADER_LEN].copy_from_slice(&len.to_be_bytes());
                key.seal_in_place(
                    seq,
                    &aead_aad(record_len),
                    &mut self.out,
                    start + RECORD_HEADER_LEN,
                )?;
            }
            RecordCipher::Tls12(key, aead) => {
                let explicit = aead.explicit_nonce(seq);
                let nonce = aead.nonce(seq, explicit.as_slice())?;
                let plaintext_len = 2usize;
                let record_len = explicit.as_slice().len() + plaintext_len + AEAD_TAG_LEN;
                let len = u16::try_from(record_len)
                    .map_err(|_| TlsError::Handshake("close_notify record too long".into()))?;
                self.out.extend_from_slice(&[CONTENT_ALERT, 0x03, 0x03]);
                self.out.extend_from_slice(&len.to_be_bytes());
                self.out.extend_from_slice(explicit.as_slice());
                let seal_start = self.out.len();
                self.out.extend_from_slice(&[1, description]);
                let additional = aead_aad_12(seq, CONTENT_ALERT, plaintext_len);
                key.seal_in_place_with_nonce(nonce, &additional, &mut self.out, seal_start)?;
            }
        }
        *write_seq = seq + 1;
        self.close_sent = true;
        Ok(())
    }
}

fn advance_seq(seq: &mut u64) -> Result<u64> {
    let current = *seq;
    *seq = current
        .checked_add(1)
        .ok_or_else(|| TlsError::Handshake("read sequence exhausted".into()))?;
    Ok(current)
}

pub(crate) fn strip_padding(plaintext: &[u8]) -> Result<(u8, &[u8])> {
    let mut end = plaintext.len();
    while end > 0 && plaintext[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(TlsError::Handshake("all-zero TLSInnerPlaintext".into()));
    }
    Ok((plaintext[end - 1], &plaintext[..end - 1]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PostHandshake {
    NewSessionTicket,
    KeyUpdate { request_update: bool },
}

pub(crate) fn post_handshake_messages(body: &[u8]) -> Result<Vec<PostHandshake>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        let Some(header) = body.get(pos..pos + 4) else {
            return Err(TlsError::Handshake(
                "post-handshake message is fragmented across records".into(),
            ));
        };
        let msg_type = header[0];
        let len =
            usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
        let Some(message) = body.get(pos + 4..pos + 4 + len) else {
            return Err(TlsError::Handshake(
                "post-handshake message is fragmented across records".into(),
            ));
        };
        pos += 4 + len;
        match msg_type {
            HS_NEW_SESSION_TICKET => out.push(PostHandshake::NewSessionTicket),
            HS_KEY_UPDATE => {
                let request_update = match message {
                    [0] => false,
                    [1] => true,
                    _ => {
                        return Err(TlsError::Handshake(
                            "KeyUpdate has a malformed body (RFC 8446 §4.6.3)".into(),
                        ));
                    }
                };
                out.push(PostHandshake::KeyUpdate { request_update });
            }
            other => {
                return Err(TlsError::Handshake(format!(
                    "unexpected post-handshake message type {other:#04x} after handshake"
                )));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AeadKey;
    use crate::crypto::CipherSuiteId;
    use crate::record::stream::Tls12Aead;

    fn tls13_pair() -> (Engine, Engine) {
        let key = AeadKey::from_key_bytes(CipherSuiteId::Aes128GcmSha256, &[0x11; 16]).unwrap();
        (
            Engine::new(AppKeys::tls13(key.clone_key(), key.clone_key())),
            Engine::new(AppKeys::tls13(key.clone_key(), key)),
        )
    }

    fn tls12_pair(aead: Tls12Aead) -> (Engine, Engine) {
        let suite = CipherSuiteId::Aes128GcmSha256;
        let key = AeadKey::from_key_bytes(suite, &[0x22; 16]).unwrap();
        (
            Engine::new(AppKeys::tls12(key.clone_key(), key.clone_key(), aead, aead)),
            Engine::new(AppKeys::tls12(key.clone_key(), key, aead, aead)),
        )
    }

    fn transmit(engine: &mut Engine) -> Vec<u8> {
        let mut out = Vec::new();
        engine.poll_transmit(&mut out);
        out
    }

    #[test]
    fn tls13_roundtrip_and_close_notify() {
        let (mut sender, mut receiver) = tls13_pair();
        sender.seal(b"hello").unwrap();
        let wire = transmit(&mut sender);
        receiver.feed(&wire).unwrap();
        assert_eq!(receiver.poll_data(), Some(b"hello".as_slice()));
        receiver.consume(5);
        assert_eq!(receiver.poll_data(), None);

        sender.queue_close_notify().unwrap();
        let wire = transmit(&mut sender);
        receiver.feed(&wire).unwrap();
        assert!(receiver.is_closed());
        assert_eq!(receiver.poll_event(), Some(RecordEvent::Closed));
    }

    #[test]
    fn tls12_close_notify_is_an_authenticated_eof() {
        let (mut sender, mut receiver) = tls12_pair(Tls12Aead::AesGcm { fixed_iv: [1; 4] });
        sender.queue_close_notify().unwrap();
        let wire = transmit(&mut sender);
        receiver.feed(&wire).unwrap();
        assert!(receiver.is_closed());
        assert_eq!(receiver.poll_event(), Some(RecordEvent::Closed));
        assert!(sender.seal(b"after").is_err());
    }

    #[test]
    fn tls12_roundtrip_both_aeads() {
        for aead in [
            Tls12Aead::AesGcm { fixed_iv: [1; 4] },
            Tls12Aead::Chacha20Poly1305 { fixed_iv: [2; 12] },
        ] {
            let (mut sender, mut receiver) = tls12_pair(aead);
            sender.seal(b"tls12").unwrap();
            let wire = transmit(&mut sender);
            receiver.feed(&wire).unwrap();
            assert_eq!(receiver.poll_data(), Some(b"tls12".as_slice()));
        }
    }

    #[test]
    fn partial_records_survive_feed() {
        let (mut sender, mut receiver) = tls13_pair();
        sender.seal(b"fragment").unwrap();
        let wire = transmit(&mut sender);
        let (first, rest) = wire.split_at(7);
        receiver.feed(first).unwrap();
        assert_eq!(receiver.poll_data(), None);
        assert_eq!(receiver.leftover(), first.len());
        receiver.feed(rest).unwrap();
        assert_eq!(receiver.poll_data(), Some(b"fragment".as_slice()));
        assert_eq!(receiver.leftover(), 0);
    }

    #[test]
    fn one_feed_keeps_every_record_it_carried() {
        let (mut sender, mut receiver) = tls13_pair();
        sender.seal(b"first").unwrap();
        sender.seal(b"second").unwrap();
        let wire = transmit(&mut sender);
        receiver.feed(&wire).unwrap();
        assert_eq!(receiver.poll_data(), Some(b"firstsecond".as_slice()));
        receiver.consume(5);
        assert_eq!(receiver.poll_data(), Some(b"second".as_slice()));
    }

    #[test]
    fn eof_with_a_partial_record_is_truncation() {
        let (mut sender, mut receiver) = tls13_pair();
        sender.seal(b"partial").unwrap();
        let wire = transmit(&mut sender);
        receiver.feed(&wire[..7]).unwrap();
        let err = receiver.feed_eof().unwrap_err();
        assert!(err.to_string().contains("partial TLS record"));
    }

    #[test]
    fn malformed_key_update_is_rejected() {
        for body in [
            vec![HS_KEY_UPDATE, 0, 0, 1, 2],
            vec![HS_KEY_UPDATE, 0, 0, 0],
            vec![HS_KEY_UPDATE, 0, 0, 2, 0, 0],
        ] {
            assert!(
                post_handshake_messages(&body).is_err(),
                "malformed KeyUpdate must fail: {body:?}"
            );
        }
        assert_eq!(
            post_handshake_messages(&[HS_KEY_UPDATE, 0, 0, 1, 1]).unwrap(),
            vec![PostHandshake::KeyUpdate {
                request_update: true
            }]
        );
    }

    #[test]
    fn rekey_threshold_is_the_record_limit() {
        let limit = record_limit(CipherSuiteId::Aes128GcmSha256);
        assert!(!should_update(limit - 1, CipherSuiteId::Aes128GcmSha256));
        assert!(should_update(limit, CipherSuiteId::Aes128GcmSha256));
        assert!(!should_update(
            record_limit(CipherSuiteId::Chacha20Poly1305Sha256) - 1,
            CipherSuiteId::Chacha20Poly1305Sha256
        ));
    }

    #[test]
    fn consecutive_key_updates_are_bounded() {
        let (mut sender, _receiver) = tls13_pair();
        sender.set_app_secrets(AppSecrets::new(
            CipherSuiteId::Aes128GcmSha256,
            &[0x33; 32],
            &[0x44; 32],
        ));
        sender.consecutive_key_updates = MAX_CONSECUTIVE_KEY_UPDATES;
        let err = sender.apply_key_update(false).unwrap_err();
        assert!(err.to_string().contains("consecutive TLS KeyUpdate"));
    }
}
