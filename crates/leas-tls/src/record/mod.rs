//! TLS record layer primitives.
//!
//! Port of `thirdparty/tls-fingerprint/src/record.rs`, generalized from
//! `&mut TcpStream` to any `AsyncRead + Unpin` stream so the engine can run
//! over the crate's generic `Stream` seam.

pub mod stream;

use tokio::io::AsyncReadExt;

use crate::error::{Result, TlsError};

/// TLS `ContentType` values (RFC 8446 §5.1).
pub const CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const CONTENT_ALERT: u8 = 0x15;
pub const CONTENT_HANDSHAKE: u8 = 0x16;
pub const CONTENT_APPLICATION_DATA: u8 = 0x17;

/// TLS Handshake message types (RFC 8446 §4).
pub const HS_CLIENT_HELLO: u8 = 0x01;
pub const HS_SERVER_HELLO: u8 = 0x02;
pub const HS_NEW_SESSION_TICKET: u8 = 0x04;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 0x08;
pub const HS_CERTIFICATE: u8 = 0x0B;
pub const HS_CERTIFICATE_VERIFY: u8 = 0x0F;
pub const HS_FINISHED: u8 = 0x14;
/// RFC 8879 §7.2 `compressed_certificate`, sent in place of `Certificate`
/// when the client offered `compress_certificate`.
pub const HS_COMPRESSED_CERTIFICATE: u8 = 0x19;

/// Maximum acceptable record payload: 2^14 plaintext plus 272 slack — the
/// TLS 1.3 `TLSInnerPlaintext` type byte (1), the maximum record padding
/// (255), and the 16-byte AEAD tag (RFC 8446 §5.2, §5.4). 16,384 + 272 =
/// 16,656 is the largest legal ciphertext for a full-size record.
pub(crate) const MAX_RECORD_PAYLOAD: usize = 16_384 + 272;

/// AEAD tag length for every AEAD in this engine (AES-GCM and
/// ChaCha20-Poly1305 both use 16-byte tags), in bytes.
pub const AEAD_TAG_LEN: usize = 16;

/// A raw TLS record off the wire.
#[derive(Debug)]
pub struct TlsRecord {
    pub content_type: u8,
    pub payload: Vec<u8>,
}

/// Recognise a peer that answered a `ClientHello` in cleartext.
///
/// A TLS record's first byte is a content type (0x14..=0x17) and bytes 1-2 are
/// the legacy version (0x03 0x0x), so a 5-byte header made entirely of
/// printable ASCII cannot be a record. The common shape is a plaintext HTTP
/// answer: `HTTP/1.1 400 Bad Request` puts `'P' '/'` in the length field, which
/// a length check reports as the fixed, uninformative
/// `record too large: 20527 bytes` (0x502F) on every such link.
///
/// Returns the printable header text when the peer is speaking cleartext.
fn cleartext_hello_answer(header: [u8; 5]) -> Option<String> {
    let printable = |b: u8| (0x20..0x7f).contains(&b) || matches!(b, b'\r' | b'\n' | b'\t');
    if !header.iter().copied().all(printable) {
        return None;
    }
    Some(
        header
            .iter()
            .map(|&b| {
                if b.is_ascii_whitespace() {
                    ' '
                } else {
                    b as char
                }
            })
            .collect::<String>()
            .trim_end()
            .to_string(),
    )
}

/// Read a single TLS record header + payload with a caller-reused buffer.
///
/// The allocation-free counterpart of [`read_record`]: `payload` is cleared
/// and refilled in place, so a handshake loop reading N records allocates
/// once (when the buffer first grows) instead of once per record. Returns
/// the record's content type; the payload is `payload[..len]`.
pub async fn read_record_into<S>(stream: &mut S, payload: &mut Vec<u8>) -> Result<u8>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    let content_type = header[0];
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));

    if let Some(cleartext) = cleartext_hello_answer(header) {
        return Err(TlsError::CleartextPeer(format!("{cleartext:?}")));
    }

    if length > MAX_RECORD_PAYLOAD {
        return Err(TlsError::Handshake(format!(
            "record too large: {length} bytes"
        )));
    }

    // Reuse the buffer: `resize` only allocates when the record exceeds
    // current capacity (zeroing is one pass over bytes the read fills
    // right after).
    payload.clear();
    payload.resize(length, 0);
    stream.read_exact(payload).await?;

    if content_type == CONTENT_ALERT && payload.len() >= 2 {
        return Err(TlsError::Handshake(format!(
            "alert: {} {}",
            payload[0], payload[1]
        )));
    }

    Ok(content_type)
}

/// Read a single TLS record (5-byte header, then payload) from the stream.
///
/// Alert records are rejected with a [`TlsError::Handshake`] carrying the
/// alert's `level` and `description`; oversized records are rejected too.
pub async fn read_record<S>(stream: &mut S) -> Result<TlsRecord>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut payload = Vec::new();
    let content_type = read_record_into(stream, &mut payload).await?;
    Ok(TlsRecord {
        content_type,
        payload,
    })
}

/// Read records, skipping any Change-Cipher-Spec records (TLS 1.3 middlebox
/// compatibility, RFC 8446 §5). Returns the first non-CCS record.
pub async fn skip_ccs<S>(stream: &mut S) -> Result<TlsRecord>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        let rec = read_record(stream).await?;
        if rec.content_type == CONTENT_CHANGE_CIPHER_SPEC {
            continue;
        }
        return Ok(rec);
    }
}

/// Parse one or more handshake messages from a raw record payload.
///
/// Each message is `type(1) || length(3) || body` (RFC 8446 §4); returns a
/// `Vec` of `(msg_type, body)` pairs borrowing the payload — no per-message
/// copy. Callers needing owned messages (transcript, flight) copy the one
/// range they keep.
pub fn parse_handshake_messages(payload: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut msgs = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        if payload.len() - pos < 4 {
            return Err(TlsError::Handshake("truncated handshake message".into()));
        }
        let msg_type = payload[pos];
        let length = (usize::from(payload[pos + 1]) << 16)
            | (usize::from(payload[pos + 2]) << 8)
            | usize::from(payload[pos + 3]);
        pos += 4;
        if pos + length > payload.len() {
            return Err(TlsError::Handshake(format!(
                "handshake message body truncated: need {length} have {}",
                payload.len() - pos
            )));
        }
        msgs.push((msg_type, &payload[pos..pos + length]));
        pos += length;
    }
    Ok(msgs)
}

/// Build a TLS Handshake record: `0x16 0x0303 <len16> <msg_type len24 body>`.
#[must_use]
pub fn make_handshake_record(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut hs_msg = Vec::with_capacity(4 + body.len());
    hs_msg.push(msg_type);
    let hs_len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    hs_msg.extend_from_slice(&hs_len.to_be_bytes()[1..]);
    hs_msg.extend_from_slice(body);

    let mut rec = Vec::with_capacity(5 + hs_msg.len());
    rec.push(CONTENT_HANDSHAKE);
    rec.extend_from_slice(&0x0303u16.to_be_bytes());
    let rec_len = u16::try_from(hs_msg.len()).unwrap_or(u16::MAX);
    rec.extend_from_slice(&rec_len.to_be_bytes());
    rec.extend_from_slice(&hs_msg);
    rec
}

/// Frame ciphertext as a TLS 1.3 Application Data record: `0x17 0x0303 <len16>`.
#[must_use]
pub fn make_app_data_record(ciphertext: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(5 + ciphertext.len());
    rec.push(CONTENT_APPLICATION_DATA);
    rec.extend_from_slice(&0x0303u16.to_be_bytes());
    let len = u16::try_from(ciphertext.len()).unwrap_or(u16::MAX);
    rec.extend_from_slice(&len.to_be_bytes());
    rec.extend_from_slice(ciphertext);
    rec
}

/// Build the AEAD additional data for a TLS 1.3 record (RFC 8446 §5.2):
/// `opaque_type || legacy_record_version || length` of the ciphertext.
#[must_use]
pub fn aead_aad(ciphertext_len: usize) -> [u8; 5] {
    let len = u16::try_from(ciphertext_len).unwrap_or(u16::MAX);
    let bytes = len.to_be_bytes();
    [CONTENT_APPLICATION_DATA, 0x03, 0x03, bytes[0], bytes[1]]
}

/// Build the TLS 1.2 AEAD additional data (RFC 5246 §6.2.3.3, RFC 5288 §3,
/// RFC 7905 §2).
///
/// Layout `seq_num(8) || type(1) || version(2) || length(2)`, where `length`
/// is the *plaintext* (`TLSCompressed.fragment`) length.
///
/// # Panics
///
/// Debug-asserts that `plaintext_len` fits a TLS record. A longer fragment
/// would produce AAD that disagrees with the record body and surface at the
/// peer as an authentication failure (indistinguishable from a MITM), so
/// callers must split first; the release path saturates rather than wraps.
#[must_use]
pub fn aead_aad_12(seq: u64, content_type: u8, plaintext_len: usize) -> [u8; 13] {
    debug_assert!(
        u16::try_from(plaintext_len).is_ok(),
        "TLS 1.2 AAD plaintext length {plaintext_len} exceeds a record"
    );
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = content_type;
    aad[9] = 0x03;
    aad[10] = 0x03;
    let len = u16::try_from(plaintext_len).unwrap_or(u16::MAX);
    aad[11..13].copy_from_slice(&len.to_be_bytes());
    aad
}

/// Frame ciphertext as a TLS 1.2 AEAD record (RFC 5246 §6.2.3.3):
/// `content_type(1) || 0x0303(2) || length(2) || explicit_nonce ||
/// ciphertext`, where `length` covers `explicit_nonce + ciphertext + tag`.
///
/// # Panics
///
/// Debug-asserts that the framed body fits a record length field; see
/// [`aead_aad_12`].
#[must_use]
pub fn make_record_12(content_type: u8, explicit_nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let body_len = explicit_nonce.len() + ciphertext.len();
    debug_assert!(
        u16::try_from(body_len).is_ok(),
        "TLS 1.2 record body {body_len} exceeds the record length field"
    );
    let mut rec = Vec::with_capacity(5 + body_len);
    rec.push(content_type);
    rec.extend_from_slice(&0x0303u16.to_be_bytes());
    let len = u16::try_from(body_len).unwrap_or(u16::MAX);
    rec.extend_from_slice(&len.to_be_bytes());
    rec.extend_from_slice(explicit_nonce);
    rec.extend_from_slice(ciphertext);
    rec
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn read_record_parses_header_and_payload() {
        let (mut stream, mut w) = tokio::io::duplex(1024);
        // Build: 16 03 03 00 05 01 02 03 04 05
        w.write_all(&[0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05])
            .await
            .unwrap();

        let rec = read_record(&mut stream).await.unwrap();
        assert_eq!(rec.content_type, CONTENT_HANDSHAKE);
        assert_eq!(rec.payload, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn parse_multi_handshake_messages() {
        let payload = [0x02, 0x00, 0x00, 0x02, 0xaa, 0xbb, 0x08, 0x00, 0x00, 0x00]; // SH + EE
        let msgs = parse_handshake_messages(&payload).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0], (0x02, &[0xaa, 0xbb][..]));
    }

    #[test]
    fn aad_matches_tls13_rule() {
        assert_eq!(aead_aad(0x0010), [0x17, 0x03, 0x03, 0x00, 0x10]);
    }

    /// A peer that answers a `ClientHello` in cleartext is named, not reported
    /// as a bogus record size: `HTTP/1.1 …` puts `'P' '/'` (0x502F = 20527) in
    /// the length field, which is the fixed number every such link logged.
    #[tokio::test]
    async fn read_record_names_a_cleartext_peer() {
        let (mut stream, mut w) = tokio::io::duplex(1024);
        w.write_all(b"HTTP/1.1 400 Bad Request\r\n").await.unwrap();

        let err = read_record(&mut stream).await.unwrap_err();
        assert!(
            matches!(err, TlsError::CleartextPeer(_)),
            "a cleartext answer is its own typed cause, got: {err}"
        );
        let text = err.to_string();
        assert!(
            text.contains("does not speak TLS") && text.contains("HTTP/"),
            "expected the cleartext-peer diagnosis, got: {text}"
        );

        // A real record header (content type < 0x20) is never mistaken for
        // cleartext, even when its length field is oversized.
        let mut header_only = [0x16, 0x03, 0x03, 0x50, 0x2f]; // length 20527
        assert_eq!(cleartext_hello_answer(header_only), None);
        header_only[0] = 0x15; // alert
        assert_eq!(cleartext_hello_answer(header_only), None);
    }

    #[test]
    fn cleartext_detection_accepts_only_fully_printable_headers() {
        assert_eq!(cleartext_hello_answer(*b"HTTP/").as_deref(), Some("HTTP/"));
        assert_eq!(cleartext_hello_answer(*b"<html").as_deref(), Some("<html"));
        assert_eq!(cleartext_hello_answer([0x15, 0x03, 0x03, 0x00, 0x02]), None);
        assert_eq!(cleartext_hello_answer(*b"GET \x01"), None);
    }

    #[tokio::test]
    async fn alert_record_is_rejected_with_level_and_description() {
        let (mut stream, mut w) = tokio::io::duplex(1024);
        // level 2 (fatal), description 40 (handshake_failure)
        w.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
            .await
            .unwrap();

        let err = read_record(&mut stream).await.unwrap_err();
        assert!(
            matches!(&err, TlsError::Handshake(msg) if msg.as_str() == "alert: 2 40"),
            "expected alert Handshake error, got {err:?}"
        );
    }
}
