//! Record-framed `AsyncRead`/`AsyncWrite` stream: TLS 1.3 application data
//! over any duplex transport.
//!
//! This is the layer `thirdparty/tls-fingerprint` LACKED — its
//! `TlsConnection` was `TcpStream`-bound with sync read/write helpers. Here
//! the same decryption (`strip_padding`) and framing (`make_app_data_record`)
//! logic is implemented as a poll-based stream: buffered plaintext on read
//! (handles TLS record fragmentation), 16 KiB plaintext split and
//! partial-write buffering on write.
//!
//! # Post-handshake policy (TLS 1.3)
//!
//! A record may carry SEVERAL handshake messages (RFC 8446 §5.1); every one is
//! walked, not just the first.
//!
//! - `NewSessionTicket` (0x04) is consumed and DISCARDED: resumption is not
//!   implemented, so the ticket has no consumer and is never replayed.
//! - `KeyUpdate` (0x18) rotates the read key (RFC 8446 §4.6.3) and, when the
//!   peer set `request_update`, queues a reciprocal `update_not_requested`
//!   acknowledgement on the write side. `poll_write` also sends one
//!   proactively at the per-key record limit (RFC 8446 §5.5) — the AEAD
//!   bounds would otherwise be reached after ~24 GB under one key.
//! - Any other inner handshake message is a protocol error: neither version
//!   allows renegotiation. A handshake message split ACROSS records is also an
//!   error (the engine reassembles only during the handshake flight).
//! - Alerts: `close_notify` is a clean EOF; every other alert ends the stream
//!   with `ConnectionReset`. TLS 1.2 rejects a `KeyUpdate` outright (it does
//!   not exist there, RFC 5246 §7.4.1).
//!
//! Direct mode (`set_read_direct`/`set_write_direct`, used by the Vision
//! splice) bypasses this entire policy: the record layer is not parsed at all,
//! so post-handshake messages are the tunnel's problem, not ours.

use std::io;

use zeroize::Zeroizing;

use crate::crypto::{AeadKey, CipherSuiteId, KeySchedule, MAX_HASH_LEN};
use crate::error::TlsError;

pub use super::adapter::TlsStream;
#[cfg(test)]
pub(crate) use super::engine::{MAX_RECORD_PLAINTEXT, RECORD_HEADER_LEN, record_limit};

/// TLS record content types (RFC 8446 §5.1).
#[cfg(test)]
use super::{
    AEAD_TAG_LEN, CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE, HS_KEY_UPDATE,
    HS_NEW_SESSION_TICKET,
};

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

/// TLS 1.3 application traffic secrets, kept ONLY so `KeyUpdate` can derive
/// the next generation (RFC 8446 §7.2, §4.6.3).
///
/// Zeroized on drop: every later generation is derived from these, so a live
/// `TlsStream` holds the client's and server's current application secrets.
/// Deliberately NOT `Clone` — two copies would fork the key-update stream and
/// silently desynchronise from the peer.
pub struct AppSecrets {
    suite: CipherSuiteId,
    client: Zeroizing<[u8; MAX_HASH_LEN]>,
    server: Zeroizing<[u8; MAX_HASH_LEN]>,
}

impl AppSecrets {
    /// Copies the two application traffic secrets (`hash_len` bytes each;
    /// the tail of the arrays is zero padding and never used).
    #[must_use]
    pub fn new(suite: CipherSuiteId, client: &[u8], server: &[u8]) -> Self {
        let hash_len = suite.hash_len();
        let mut out = Self {
            suite,
            client: Zeroizing::new([0u8; MAX_HASH_LEN]),
            server: Zeroizing::new([0u8; MAX_HASH_LEN]),
        };
        out.client[..hash_len.min(client.len())]
            .copy_from_slice(&client[..hash_len.min(client.len())]);
        out.server[..hash_len.min(server.len())]
            .copy_from_slice(&server[..hash_len.min(server.len())]);
        out
    }

    /// Advances one direction's secret (`server = true` for the read side) and
    /// returns the AEAD key for the new generation.
    pub(crate) fn advance(&mut self, server: bool) -> std::result::Result<AeadKey, TlsError> {
        let hash_len = self.suite.hash_len();
        let schedule = KeySchedule::new(self.suite);
        let secret = if server {
            &mut self.server
        } else {
            &mut self.client
        };
        let next = schedule.update_traffic_secret(&secret[..hash_len])?;
        *secret = next;
        AeadKey::new(self.suite, &secret[..hash_len])
    }

    /// The suite these secrets belong to.
    #[must_use]
    pub const fn suite(&self) -> CipherSuiteId {
        self.suite
    }
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

#[cfg(test)]
impl AppKeys {
    /// Duplicate the key state for a two-endpoint test over one `duplex`.
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
    use crate::record::engine::strip_padding;
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

    fn key_update_msg(request_update: bool) -> Vec<u8> {
        vec![HS_KEY_UPDATE, 0x00, 0x00, 0x01, u8::from(request_update)]
    }

    /// The TLS 1.3 secret generations for one direction (SHA-256 suite →
    /// `hash_len` = 32), plus the AEAD key each one yields.
    fn generations(suite: CipherSuiteId, secret: &[u8; 32]) -> (AeadKey, AeadKey) {
        let hash_len = suite.hash_len();
        let schedule = KeySchedule::new(suite);
        let first = AeadKey::new(suite, secret).unwrap();
        let next = schedule.update_traffic_secret(secret).unwrap();
        let second = AeadKey::new(suite, &next[..hash_len]).unwrap();
        (first, second)
    }

    /// RFC 8446 §4.6.3: a peer `KeyUpdate` rotates the READ key, and the
    /// application data that follows is sealed with the next generation — so
    /// this only passes if the rotation happened.
    #[rstest::rstest]
    #[case::not_requested(false)]
    #[case::requested(true)]
    #[tokio::test]
    async fn key_update_rotates_the_read_key(#[case] request_update: bool) {
        let suite = CipherSuiteId::Aes128GcmSha256;
        let server_ts = [0x33u8; 32];
        let client_ts = [0x22u8; 32];
        let (first, second) = generations(suite, &server_ts);

        let keys = AppKeys::tls13(first.clone_key(), first.clone_key());
        let update = raw_record(&keys, 0, CONTENT_HANDSHAKE, &key_update_msg(request_update));
        let next_keys = AppKeys::tls13(second.clone_key(), second);
        let data = raw_record(&next_keys, 0, CONTENT_APPLICATION_DATA, b"after-update");

        let (a, b) = duplex(4096);
        tokio::spawn(async move {
            let mut b = b;
            b.write_all(&update).await.unwrap();
            b.write_all(&data).await.unwrap();
        });
        let mut reader = TlsStream::new(a, keys);
        reader.set_app_secrets(AppSecrets::new(suite, &client_ts, &server_ts));
        let mut buf = [0u8; 12];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"after-update");

        // The ACK policy: queued iff the peer asked for an update, and it
        // always says `update_not_requested` so the exchange terminates.
        if request_update {
            let mut rec = reader.pending.clone();
            assert!(!rec.is_empty(), "a requested update must be acknowledged");
            assert_eq!(rec[0], CONTENT_APPLICATION_DATA);
            let body = &mut rec[RECORD_HEADER_LEN..];
            let aad = aead_aad(body.len());
            let n = first
                .clone_key()
                .open_in_place(0, &aad, body)
                .expect("the ACK is sealed with the pre-update write key");
            assert_eq!(
                &body[..n],
                &[HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x00, CONTENT_HANDSHAKE],
                "the ACK carries request_update = 0"
            );
        } else {
            assert!(
                reader.pending.is_empty(),
                "a KeyUpdate that requested nothing must not be acknowledged"
            );
        }
    }

    /// The write path sends a `KeyUpdate` sealed with the OLD key, then seals
    /// application data with the next generation — the peer's two records must
    /// decode under exactly those keys.
    #[tokio::test]
    async fn write_side_rekeys_at_the_record_limit() {
        let suite = CipherSuiteId::Aes128GcmSha256;
        let client_ts = [0x22u8; 32];
        let server_ts = [0x33u8; 32];
        let (first, second) = generations(suite, &client_ts);

        let (a, mut b) = duplex(8192);
        let mut writer = TlsStream::new(
            a,
            AppKeys::tls13(AeadKey::new(suite, &[0x44; 32]).unwrap(), first.clone_key()),
        );
        writer.set_app_secrets(AppSecrets::new(suite, &client_ts, &server_ts));
        let limit = record_limit(suite);
        writer.set_write_seq(limit);
        writer.write_all(b"hi").await.unwrap();
        writer.flush().await.unwrap();
        assert_eq!(
            writer.write_seq(),
            1,
            "the counter restarts after the rekey"
        );

        let mut wire = vec![0u8; 4096];
        let n = b.read(&mut wire).await.unwrap();
        let wire = &mut wire[..n];

        let first_len = usize::from(u16::from_be_bytes([wire[3], wire[4]])) + RECORD_HEADER_LEN;
        let (ku_record, data_record) = wire.split_at_mut(first_len);
        let ku_body = &mut ku_record[RECORD_HEADER_LEN..];
        let aad = aead_aad(ku_body.len());
        let n = first
            .clone_key()
            .open_in_place(limit, &aad, ku_body)
            .expect("the KeyUpdate is sealed with the pre-rekey key at the old seq");
        assert_eq!(
            &ku_body[..n],
            &[HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x01, CONTENT_HANDSHAKE],
            "we request an update from the peer"
        );

        let data_body = &mut data_record[RECORD_HEADER_LEN..];
        let aad = aead_aad(data_body.len());
        let n = second
            .clone_key()
            .open_in_place(0, &aad, data_body)
            .expect("application data uses the next generation at seq 0");
        assert_eq!(&data_body[..n], &[b'h', b'i', CONTENT_APPLICATION_DATA]);
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

    /// RFC 8446 §6.1: a graceful shutdown sends `close_notify` before the
    /// transport close, so the peer can distinguish an ending from a
    /// truncation.
    #[tokio::test]
    async fn shutdown_sends_close_notify() {
        let (a, mut peer) = duplex(4096);
        let keys = test_keys();
        let mut client = TlsStream::new(a, keys.duplicate());
        client.shutdown().await.unwrap();

        let mut hdr = [0u8; 5];
        peer.read_exact(&mut hdr).await.unwrap();
        assert_eq!(&hdr[..3], &[CONTENT_APPLICATION_DATA, 0x03, 0x03]);
        let len = usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
        let mut body = vec![0u8; len];
        peer.read_exact(&mut body).await.unwrap();
        let plain = tls13_key(&keys.write)
            .open_in_place(0, &aead_aad(len), &mut body)
            .unwrap();
        assert_eq!(&body[..plain], &[1, 0, CONTENT_ALERT]);
    }
}
