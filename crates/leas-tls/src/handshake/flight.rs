//! The encrypted server flight: `EncryptedExtensions`, `Certificate`,
//! `CertificateVerify`, `Finished`, and RFC 8879 certificate decompression.

use super::{
    AeadKey, AsyncRead, CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE, EXT_ALPN,
    EXT_SUPPORTED_VERSIONS, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY, HS_COMPRESSED_CERTIFICATE,
    HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, MAX_FLIGHT_BUFFER, MAX_RECORD_PAYLOAD, Result, TlsError,
    aead_aad, make_hs_msg, skip_ccs, strip_padding, u24,
};

// ── Encrypted server flight ────────────────────────────────────────────────

/// The parsed server flight: raw messages for the transcript plus the values
/// the verifier seam and client `Finished` need.
pub struct ServerFlight {
    pub ee_raw: Vec<u8>,
    pub cert_raw: Vec<u8>,
    pub cv_raw: Vec<u8>,
    pub sf_verify_data: Vec<u8>,
    /// DER certificates, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// The `signature_scheme` from `CertificateVerify`.
    pub signature_scheme: u16,
    /// The raw `CertificateVerify` body (scheme + signature).
    pub cert_verify_body: Vec<u8>,
    /// The protocol the server selected in `EncryptedExtensions` (RFC 7301),
    /// if it sent ALPN at all.
    pub negotiated_alpn: Option<Vec<u8>>,
}

/// Read and decrypt the encrypted server handshake records
/// (`EncryptedExtensions` … `Finished`) with `server_hs_key`, sequencing
/// from zero.
///
/// RFC 8446 §5.1 allows a handshake message to span records (rustls
/// fragments plaintext at 16 KiB, so a certificate chain larger than one
/// record is split) and a single record to carry several complete messages.
/// Decrypted plaintext is therefore accumulated into a buffer and each
/// message is consumed only once its full `type(1) || length(3) || body` is
/// present; a record may hold a partial message, several complete messages,
/// or a message continuing into the next record.
pub async fn read_server_hs_messages<S>(
    stream: &mut S,
    server_hs_key: &AeadKey,
    // RFC 8879 `compress_certificate` algorithms the ClientHello offered.
    offered_compress: &[u16],
) -> Result<ServerFlight>
where
    S: AsyncRead + Unpin,
{
    let mut ee_raw: Option<Vec<u8>> = None;
    let mut negotiated_alpn: Option<Vec<u8>> = None;
    let mut cert_raw: Option<Vec<u8>> = None;
    let mut cv_raw: Option<Vec<u8>> = None;
    let mut finished_data: Option<Vec<u8>> = None;
    let mut chain: Option<Vec<Vec<u8>>> = None;
    let mut signature_scheme = 0u16;
    let mut cert_verify_body = Vec::new();
    let mut seq = 0u64;
    // The reassembly buffer is pre-sized to one full record (like
    // `TlsStream::rec_buf`): single-record flights never regrow it, and
    // multi-record flights amortize into the same allocation.
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_RECORD_PAYLOAD);

    loop {
        // Consume every complete handshake message buffered so far.
        let mut consumed = 0usize;
        while buf.len() >= consumed + 4 {
            let msg_len = u24(&buf[consumed + 1..consumed + 4]);
            let total = 4 + msg_len;
            if buf.len() < consumed + total {
                break; // body incomplete — wait for the next record
            }
            let msg_type = buf[consumed];
            // One copy: the raw message already sits contiguous in `buf`
            // (`type || len || body`), so slice it out directly instead of
            // copying the body and re-encoding the header.
            let raw = buf[consumed..consumed + total].to_vec();
            let body = &raw[4..];
            consumed += total;
            match msg_type {
                HS_ENCRYPTED_EXTENSIONS => {
                    negotiated_alpn = parse_encrypted_extensions(body)?;
                    ee_raw = Some(raw);
                }
                HS_CERTIFICATE => {
                    chain = Some(parse_certificate_message(body)?);
                    cert_raw = Some(raw);
                }
                HS_COMPRESSED_CERTIFICATE => {
                    // RFC 8879 §4: the compressed Certificate replaces the
                    // plain one; the decompressed payload is the Certificate
                    // BODY (rustls parses it the same way — no 4-byte
                    // handshake header inside).
                    let cert_body = decompress_certificate_message(body, offered_compress)?;
                    chain = Some(parse_certificate_message(&cert_body)?);
                    // The transcript carries the message AS SENT: the server
                    // hashed the `CompressedCertificate`, not a re-built
                    // `Certificate` (hashing a rebuilt one fails its Finished
                    // MAC — verified against Cloudflare's edge).
                    cert_raw = Some(raw);
                }
                HS_CERTIFICATE_VERIFY => {
                    signature_scheme = parse_certificate_verify(body)?;
                    cert_verify_body = body.to_vec();
                    cv_raw = Some(raw);
                }
                HS_FINISHED => finished_data = Some(body.to_vec()),
                _ => {} // unknown handshake messages are skipped
            }

            if finished_data.is_some() {
                // The server flight ends with Finished; any later messages
                // (e.g. NewSessionTicket) are not part of the flight, and a
                // buffered remainder is intentionally left unconsumed.
                return Ok(ServerFlight {
                    ee_raw: ee_raw
                        .ok_or_else(|| TlsError::Handshake("missing EncryptedExtensions".into()))?,
                    cert_raw: cert_raw.unwrap_or_else(|| make_hs_msg(HS_CERTIFICATE, &[])),
                    cv_raw: cv_raw.unwrap_or_else(|| make_hs_msg(HS_CERTIFICATE_VERIFY, &[])),
                    sf_verify_data: finished_data
                        .ok_or_else(|| TlsError::Handshake("missing server Finished".into()))?,
                    chain: chain.unwrap_or_default(),
                    signature_scheme,
                    cert_verify_body,
                    negotiated_alpn,
                });
            }
        }
        buf.drain(..consumed);

        let rec = skip_ccs(stream).await?;
        if rec.content_type != CONTENT_APPLICATION_DATA {
            return Err(TlsError::Handshake(format!(
                "expected encrypted record (0x17), got 0x{:02X}",
                rec.content_type
            )));
        }

        let aad = aead_aad(rec.payload.len());
        let mut payload = rec.payload;
        let plain_len = server_hs_key.open_in_place(seq, &aad, &mut payload)?;
        seq += 1;

        let (content_type, hs_data) = strip_padding(&payload[..plain_len])?;
        if content_type != CONTENT_HANDSHAKE {
            continue;
        }
        if buf.len() + hs_data.len() > MAX_FLIGHT_BUFFER {
            return Err(TlsError::Handshake(
                "server flight exceeds the 16 MiB reassembly bound".into(),
            ));
        }
        buf.extend_from_slice(hs_data);
    }
}

/// Parse an `EncryptedExtensions` body:
/// `ext_list_len(2) || extensions`.
///
/// The `supported_versions` extension (when present) must be TLS 1.3, and
/// the ALPN extension must be well-formed; neither value has a consumer in
/// the Task-8 seams yet, so both are validated and discarded.
pub fn parse_encrypted_extensions(body: &[u8]) -> Result<Option<Vec<u8>>> {
    if body.len() < 2 {
        return Err(TlsError::Handshake("EncryptedExtensions too short".into()));
    }
    let ext_list_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let ext_end = 2 + ext_list_len;
    if ext_end > body.len() {
        return Err(TlsError::Handshake("EncryptedExtensions truncated".into()));
    }
    let mut selected_alpn = None;
    let mut pos = 2;
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([body[pos + 2], body[pos + 3]]));
        pos += 4;
        if pos + ext_len > ext_end {
            return Err(TlsError::Handshake(
                "EncryptedExtensions extension overruns list".into(),
            ));
        }
        let ext_data = &body[pos..pos + ext_len];
        pos += ext_len;
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                // uint8 length (always 2) || uint16 version.
                if ext_data.len() != 3 || usize::from(ext_data[0]) != 2 {
                    return Err(TlsError::Handshake(
                        "malformed supported_versions in EncryptedExtensions".into(),
                    ));
                }
                let version = u16::from_be_bytes([ext_data[1], ext_data[2]]);
                if version != 0x0304 {
                    return Err(TlsError::Handshake(format!(
                        "server negotiated TLS version 0x{version:04X}, expected 0x0304"
                    )));
                }
            }
            EXT_ALPN => {
                // uint16 list length || (uint8 len || protocol)*.
                if ext_data.len() < 2 {
                    return Err(TlsError::Handshake(
                        "malformed ALPN in EncryptedExtensions".into(),
                    ));
                }
                let list_len = usize::from(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                if ext_data.len() != 2 + list_len {
                    return Err(TlsError::Handshake(
                        "ALPN protocol list length mismatch".into(),
                    ));
                }
                // RFC 7301 §3.1: the server selects exactly ONE protocol.
                let mut p = 2;
                let mut protos = 0;
                while p < ext_data.len() {
                    let proto_len = usize::from(ext_data[p]);
                    p += 1;
                    if p + proto_len > ext_data.len() {
                        return Err(TlsError::Handshake(
                            "ALPN protocol entry overruns list".into(),
                        ));
                    }
                    if protos == 0 {
                        selected_alpn = Some(ext_data[p..p + proto_len].to_vec());
                    }
                    protos += 1;
                    p += proto_len;
                }
                if protos != 1 {
                    return Err(TlsError::Handshake(format!(
                        "server selected {protos} ALPN protocols; RFC 7301 §3.1 allows exactly one"
                    )));
                }
            }
            _ => {}
        }
    }
    if pos != ext_end {
        return Err(TlsError::Handshake(
            "trailing garbage in EncryptedExtensions extension list".into(),
        ));
    }
    Ok(selected_alpn)
}

/// Parse a `Certificate` body:
/// `cert_req_ctx_len(1) || ctx || certificate_list_len(3) || certificate_list`.
///
/// Each list entry is `cert_data_len(3) || cert_data || extensions_len(2) ||
/// extensions`; returns the DER chain, leaf first. This is the body of a
/// `Certificate` message (or of the payload a `CompressedCertificate`
/// decompressed to — RFC 8879 §4 compresses this very body, so there is no
/// per-entry compression to undo here).
pub fn parse_certificate_message(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    if body.len() < 4 {
        return Err(TlsError::Handshake("Certificate message too short".into()));
    }
    let ctx_len = usize::from(body[0]);
    let mut pos = 1 + ctx_len;
    if pos + 3 > body.len() {
        return Err(TlsError::Handshake(
            "Certificate list length truncated".into(),
        ));
    }
    let list_len = u24(&body[pos..pos + 3]);
    pos += 3;
    let list_end = pos + list_len;
    if list_end > body.len() {
        return Err(TlsError::Handshake("Certificate list truncated".into()));
    }

    let mut chain = Vec::new();
    while pos < list_end {
        if pos + 3 > list_end {
            return Err(TlsError::Handshake(
                "certificate entry length truncated".into(),
            ));
        }
        let cert_len = u24(&body[pos..pos + 3]);
        pos += 3;
        if pos + cert_len > list_end {
            return Err(TlsError::Handshake("certificate data truncated".into()));
        }
        chain.push(body[pos..pos + cert_len].to_vec());
        pos += cert_len;
        if pos + 2 > list_end {
            return Err(TlsError::Handshake(
                "certificate extensions length truncated".into(),
            ));
        }
        let ext_len = usize::from(u16::from_be_bytes([body[pos], body[pos + 1]]));
        pos += 2 + ext_len;
        if pos > list_end {
            return Err(TlsError::Handshake(
                "certificate extensions overrun list".into(),
            ));
        }
    }
    Ok(chain)
}

/// Decompress one RFC 8879 `CompressedCertificate` payload.
///
/// `offered` is the `ClientHello`'s `compress_certificate` algorithm list (RFC
/// 8879 §7.3: 1 zlib, 2 brotli, 3 zstd); a server that selects anything else
/// is misbehaving and the message is rejected, as rustls does with
/// `bad_certificate`. Decompression is bounded ([`MAX_CERT_BYTES`]): a
/// server-supplied blob may not expand without limit.
pub fn decompress_certificate_message(body: &[u8], offered: &[u16]) -> Result<Vec<u8>> {
    // algorithm(2) || uncompressed_length(3) || compressed<1..2^24-1>
    if body.len() < 8 {
        return Err(TlsError::Handshake(
            "CompressedCertificate too short".into(),
        ));
    }
    let algorithm = u16::from_be_bytes([body[0], body[1]]);
    let uncompressed_len = u24(&body[2..5]);
    let compressed_len = u24(&body[5..8]);
    if body.len() != 8 + compressed_len {
        return Err(TlsError::Handshake(format!(
            "CompressedCertificate declares {compressed_len} compressed bytes, got {}",
            body.len() - 8
        )));
    }
    if !offered.contains(&algorithm) {
        return Err(TlsError::Handshake(format!(
            "server compressed the Certificate with algorithm 0x{algorithm:04X}, which the \
             ClientHello did not offer"
        )));
    }
    let data = &body[8..];
    let decompressed = match algorithm {
        0x0001 => decompress_bounded(flate2::read::ZlibDecoder::new(data))?,
        0x0002 => decompress_bounded(brotli::Decompressor::new(data, 4096))?,
        0x0003 => match zstd::stream::read::Decoder::new(data) {
            Ok(decoder) => decompress_bounded(decoder)?,
            Err(_) => None,
        },
        _ => None,
    }
    .ok_or_else(|| {
        TlsError::Handshake(format!(
            "CompressedCertificate algorithm 0x{algorithm:04X} did not decode"
        ))
    })?;
    if decompressed.len() != uncompressed_len {
        return Err(TlsError::Handshake(format!(
            "CompressedCertificate declares {uncompressed_len} uncompressed bytes, got {}",
            decompressed.len()
        )));
    }
    Ok(decompressed)
}

/// Maximum decompressed size of one RFC 8879 Certificate payload.
const MAX_CERT_BYTES: u64 = 1 << 20;

/// Decompress `reader` into at most [`MAX_CERT_BYTES`] bytes.
///
/// `Ok(None)` when the input is not a valid stream for the selected
/// algorithm; `Err` when the stream inflates past the bound (decompression
/// bomb).
pub fn decompress_bounded<R: std::io::Read>(mut reader: R) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let mut out = Vec::new();
    if reader
        .by_ref()
        .take(MAX_CERT_BYTES + 1)
        .read_to_end(&mut out)
        .is_err()
    {
        return Ok(None);
    }
    if out.len() as u64 > MAX_CERT_BYTES {
        return Err(TlsError::Handshake(
            "certificate decompression exceeds the 1 MiB bound (decompression bomb)".into(),
        ));
    }
    Ok(Some(out))
}

/// Parse a `CertificateVerify` body: `signature_scheme(2) ||
/// signature_len(2) || signature`; returns the signature scheme.
pub fn parse_certificate_verify(body: &[u8]) -> Result<u16> {
    if body.len() < 4 {
        return Err(TlsError::Handshake("CertificateVerify too short".into()));
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = usize::from(u16::from_be_bytes([body[2], body[3]]));
    if body.len() != 4 + sig_len {
        return Err(TlsError::Handshake(
            "CertificateVerify signature length mismatch".into(),
        ));
    }
    Ok(scheme)
}
