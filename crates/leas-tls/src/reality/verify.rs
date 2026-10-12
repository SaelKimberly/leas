//! REALITY server authentication (ring port of
//! `thirdparty/shoes/src/reality/reality_client_verify.rs`).
//!
//! The certificate's `signatureValue` must equal
//! `HMAC-SHA512(auth_key, ed25519_public_key)` and the Ed25519
//! `CertificateVerify` must verify over the handshake transcript. No PKI
//! chain check — a REALITY server is authenticated purely by the HMAC +
//! Ed25519 pair.

use ring::{digest, hmac, signature};
use subtle::ConstantTimeEq as _;

use crate::error::{Result, TlsError};

/// `signature_algorithms` scheme for Ed25519 (RFC 8446 §4.2.3).
const SIG_ED25519: u16 = 0x0807;
/// `HMAC-SHA512` output length.
const HMAC_SHA512_LEN: usize = 64;

/// Extracts the first DER certificate from a TLS 1.3 `Certificate` message
/// (handshake header + body).
pub fn extract_certificate_der(certificate_message: &[u8]) -> Result<&[u8]> {
    // Skip the handshake header (type + 3-byte length).
    if certificate_message.len() < 4 {
        return Err(TlsError::Handshake("Certificate message too short".into()));
    }
    let mut pos = 4;

    // certificate_request_context: u8 length + data.
    if pos >= certificate_message.len() {
        return Err(TlsError::Handshake(
            "Certificate message truncated at context length".into(),
        ));
    }
    let context_len = usize::from(certificate_message[pos]);
    pos += 1 + context_len;

    // certificate_list length (3 bytes).
    if pos + 3 > certificate_message.len() {
        return Err(TlsError::Handshake(
            "Certificate message truncated at list length".into(),
        ));
    }
    pos += 3;

    // First certificate entry: cert_data length (3 bytes).
    if pos + 3 > certificate_message.len() {
        return Err(TlsError::Handshake(
            "Certificate message truncated at cert length".into(),
        ));
    }
    let cert_len = u24(&certificate_message[pos..pos + 3]);
    pos += 3;

    if pos + cert_len > certificate_message.len() {
        return Err(TlsError::Handshake(
            "Certificate message truncated at cert data".into(),
        ));
    }
    Ok(&certificate_message[pos..pos + cert_len])
}

/// Verifies the REALITY certificate HMAC: the certificate's `signatureValue`
/// must equal `HMAC-SHA512(auth_key, ed25519_public_key)`.
pub fn verify_certificate_hmac(cert_der: &[u8], auth_key: &[u8; 32]) -> Result<()> {
    let pubkey = extract_ed25519_public_key(cert_der)?;
    let signature = extract_certificate_signature(cert_der)?;
    if signature.len() != HMAC_SHA512_LEN {
        return Err(TlsError::Verify(format!(
            "certificate signature is {} bytes, expected 64 (HMAC-SHA512)",
            signature.len()
        )));
    }
    let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let expected = hmac::sign(&key, &pubkey);
    // Constant-time: `subtle`'s slice comparison (both sides are fixed-size
    // HMAC-SHA512 tags). ring's `verify_slices_are_equal` is deprecated.
    if expected.as_ref().ct_eq(signature).unwrap_u8() != 1 {
        return Err(TlsError::Verify(
            "certificate signature is not HMAC-SHA512(auth_key, ed25519_pub) — not a REALITY server"
                .into(),
        ));
    }
    Ok(())
}

/// Extracts the raw Ed25519 public key (32 bytes) from a DER-encoded X.509
/// certificate's `SubjectPublicKeyInfo` BIT STRING.
pub fn extract_ed25519_public_key(cert_der: &[u8]) -> Result<[u8; 32]> {
    let spki = extract_spki(cert_der)?;
    let mut pos = 0;
    let (tag, _algid) = read_tlv(spki, &mut pos)?;
    if tag != 0x30 {
        return Err(TlsError::Verify(
            "SPKI algorithmIdentifier is not a SEQUENCE".into(),
        ));
    }
    let (tag, bit_string) = read_tlv(spki, &mut pos)?;
    if tag != 0x03 {
        return Err(TlsError::Verify(
            "SPKI subjectPublicKey is not a BIT STRING".into(),
        ));
    }
    let key = split_bit_string(bit_string)?;
    if key.len() != 32 {
        return Err(TlsError::Verify(format!(
            "expected an Ed25519 public key (32 bytes), got {}",
            key.len()
        )));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(key);
    Ok(public_key)
}

/// Extracts the certificate's outer `signatureValue` (the last BIT STRING of
/// the DER certificate), payload without the unused-bits byte.
///
/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
/// signatureValue }` — the three siblings live *inside* the outer value.
pub fn extract_certificate_signature(cert_der: &[u8]) -> Result<&[u8]> {
    let mut pos = 0;
    let (tag, cert) = read_tlv(cert_der, &mut pos)?;
    if tag != 0x30 {
        return Err(TlsError::Verify("certificate is not a DER SEQUENCE".into()));
    }
    let mut inner = 0;
    let (tag, _tbs) = read_tlv(cert, &mut inner)?;
    if tag != 0x30 {
        return Err(TlsError::Verify("tbsCertificate is not a SEQUENCE".into()));
    }
    let (tag, _sigalg) = read_tlv(cert, &mut inner)?;
    if tag != 0x30 {
        return Err(TlsError::Verify(
            "certificate signatureAlgorithm is not a SEQUENCE".into(),
        ));
    }
    let (tag, sig) = read_tlv(cert, &mut inner)?;
    if tag != 0x03 {
        return Err(TlsError::Verify(
            "certificate signatureValue is not a BIT STRING".into(),
        ));
    }
    split_bit_string(sig)
}

/// Parses a `CertificateVerify` message and extracts the signature.
///
/// `CertificateVerify` structure: handshake type `0x0f` (1) + length (3) +
/// `signature_algorithm` (2) + `signature_length` (2) + signature. Only
/// Ed25519 (0x0807) with a 64-byte signature is supported — the REALITY
/// pair.
pub fn extract_certificate_verify_signature(cert_verify_message: &[u8]) -> Result<Vec<u8>> {
    if cert_verify_message.len() < 72 {
        return Err(TlsError::Handshake(format!(
            "CertificateVerify message too short: {} bytes",
            cert_verify_message.len()
        )));
    }
    if cert_verify_message[0] != 0x0f {
        return Err(TlsError::Handshake(format!(
            "expected CertificateVerify type (0x0f), got 0x{:02x}",
            cert_verify_message[0]
        )));
    }
    let pos = 4;
    let sig_alg = u16::from_be_bytes([cert_verify_message[pos], cert_verify_message[pos + 1]]);
    if sig_alg != SIG_ED25519 {
        return Err(TlsError::Handshake(format!(
            "unsupported signature algorithm 0x{sig_alg:04x}, expected Ed25519 (0x0807)"
        )));
    }
    let sig_len = usize::from(u16::from_be_bytes([
        cert_verify_message[pos + 2],
        cert_verify_message[pos + 3],
    ]));
    if sig_len != 64 {
        return Err(TlsError::Handshake(format!(
            "invalid Ed25519 signature length {sig_len}, expected 64"
        )));
    }
    let sig_start = pos + 4;
    if sig_start + sig_len > cert_verify_message.len() {
        return Err(TlsError::Handshake(
            "CertificateVerify message truncated".into(),
        ));
    }
    Ok(cert_verify_message[sig_start..sig_start + sig_len].to_vec())
}

/// Verifies the Ed25519 `CertificateVerify` signature over
/// `64 spaces || "TLS 1.3, server CertificateVerify" || 0x00 ||
/// transcript_hash` (RFC 8446 §4.4.3).
pub fn verify_certificate_verify_signature(
    public_key: &[u8; 32],
    signature: &[u8],
    transcript_hash: &[u8],
) -> Result<()> {
    if signature.len() != 64 {
        return Err(TlsError::Verify(format!(
            "invalid Ed25519 signature length {}, expected 64",
            signature.len()
        )));
    }
    // Stack-signed content: `64 spaces || "TLS 1.3, server CertificateVerify"
    // || 0x00 || transcript_hash`. Sized to 64 + 33 + 1 + 48 so every suite
    // fits (SHA-384's 48-byte hash is the max); the brief's 145 would
    // truncate it, so this uses 146.
    let mut signed_content = [0u8; 64 + 33 + 1 + 48];
    signed_content[..64].copy_from_slice(&[0x20u8; 64]);
    signed_content[64..64 + 33].copy_from_slice(b"TLS 1.3, server CertificateVerify");
    signed_content[64 + 33] = 0x00;
    if transcript_hash.len() > 48 {
        return Err(TlsError::Verify(
            "transcript hash exceeds SHA-384 length".into(),
        ));
    }
    let content_len = 64 + 33 + 1 + transcript_hash.len();
    signed_content[64 + 33 + 1..content_len].copy_from_slice(transcript_hash);

    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
    public_key
        .verify(&signed_content[..content_len], signature)
        .map_err(|_| TlsError::Verify("CertificateVerify signature verification failed".into()))
}

/// Full REALITY server authentication: certificate HMAC + Ed25519
/// `CertificateVerify` over the transcript up to (excluding) the
/// `CertificateVerify` message.
pub fn verify_server(
    cert_der: &[u8],
    cv_message: &[u8],
    auth_key: &[u8; 32],
    transcript: &[u8],
    digest_alg: &'static digest::Algorithm,
) -> Result<()> {
    verify_certificate_hmac(cert_der, auth_key)?;
    let public_key = extract_ed25519_public_key(cert_der)?;
    let signature = extract_certificate_verify_signature(cv_message)?;
    let transcript_hash = digest::digest(digest_alg, transcript);
    verify_certificate_verify_signature(&public_key, &signature, transcript_hash.as_ref())
}

// ── DER helpers ────────────────────────────────────────────────────────────

/// Reads one DER TLV (tag + definite length) at `*pos`, advancing `*pos`
/// past the value. Returns `(tag, value)`.
fn read_tlv<'a>(der: &'a [u8], pos: &mut usize) -> Result<(u8, &'a [u8])> {
    if *pos >= der.len() {
        return Err(TlsError::Verify("DER truncated at tag".into()));
    }
    let tag = der[*pos];
    *pos += 1;
    if *pos >= der.len() {
        return Err(TlsError::Verify("DER truncated at length".into()));
    }
    let first = der[*pos];
    *pos += 1;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return Err(TlsError::Verify("unsupported DER length encoding".into()));
        }
        if *pos + n > der.len() {
            return Err(TlsError::Verify("DER length overruns input".into()));
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | usize::from(der[*pos]);
            *pos += 1;
        }
        l
    };
    let end = pos
        .checked_add(len)
        .ok_or_else(|| TlsError::Verify("DER length overflows usize".into()))?;
    if end > der.len() {
        return Err(TlsError::Verify("DER value overruns input".into()));
    }
    let value = &der[*pos..end];
    *pos = end;
    Ok((tag, value))
}

/// Walks a certificate's TBS `Certificate` (its first child) to the
/// `SubjectPublicKeyInfo` — the fifth SEQUENCE child (signature, issuer,
/// validity, subject, SPKI); the optional `[0]` version and `INTEGER`
/// serial are not SEQUENCEs.
fn extract_spki(cert_der: &[u8]) -> Result<&[u8]> {
    let mut pos = 0;
    let (tag, cert) = read_tlv(cert_der, &mut pos)?;
    if tag != 0x30 {
        return Err(TlsError::Verify("certificate is not a DER SEQUENCE".into()));
    }
    let mut inner = 0;
    let (tag, tbs) = read_tlv(cert, &mut inner)?;
    if tag != 0x30 {
        return Err(TlsError::Verify("tbsCertificate is not a SEQUENCE".into()));
    }
    let mut seq_count = 0usize;
    let mut pos2 = 0usize;
    while pos2 < tbs.len() {
        let (tag, value) = read_tlv(tbs, &mut pos2)?;
        if tag == 0x30 {
            seq_count += 1;
            if seq_count == 5 {
                return Ok(value);
            }
        }
    }
    Err(TlsError::Verify(
        "no SubjectPublicKeyInfo found in certificate".into(),
    ))
}

/// Splits a BIT STRING *value* (`unused_bits(1) || payload`) into its
/// payload, rejecting any unused bits.
fn split_bit_string(value: &[u8]) -> Result<&[u8]> {
    match value.split_first() {
        Some((0, payload)) => Ok(payload),
        Some((unused, _)) => Err(TlsError::Verify(format!(
            "BIT STRING has {unused} unused bits"
        ))),
        None => Err(TlsError::Verify("empty BIT STRING".into())),
    }
}

/// Read a 3-byte big-endian length.
fn u24(b: &[u8]) -> usize {
    (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// Builds a minimal TLS 1.3 `Certificate` message containing one DER
    /// certificate.
    fn certificate_message(cert_der: &[u8]) -> Vec<u8> {
        let cert_len = cert_der.len();
        let entry_len = 3 + cert_len + 2;
        let body_len = 1 + 3 + entry_len;
        let mut message = Vec::new();
        message.push(0x0b);
        message.extend_from_slice(&u32::try_from(body_len).unwrap().to_be_bytes()[1..]);
        message.push(0x00); // certificate_request_context length
        message.extend_from_slice(&u32::try_from(entry_len).unwrap().to_be_bytes()[1..]);
        message.extend_from_slice(&u32::try_from(cert_len).unwrap().to_be_bytes()[1..]);
        message.extend_from_slice(cert_der);
        message.extend_from_slice(&[0x00, 0x00]); // per-cert extensions
        message
    }

    /// Builds the RFC 8446 §4.4.3 signed content over a 32-byte transcript
    /// hash on the stack (test fixture signer).
    fn signed_fixture(transcript_hash: &[u8; 32]) -> [u8; 64 + 33 + 1 + 32] {
        let mut out = [0u8; 64 + 33 + 1 + 32];
        out[..64].copy_from_slice(&[0x20u8; 64]);
        out[64..64 + 33].copy_from_slice(b"TLS 1.3, server CertificateVerify");
        out[64 + 33] = 0x00;
        out[64 + 33 + 1..].copy_from_slice(transcript_hash);
        out
    }

    /// A self-signed Ed25519 certificate (rcgen) and its signing key pair.
    fn ed25519_cert() -> (Vec<u8>, Ed25519KeyPair) {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("Failed to generate Ed25519 key pair");
        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()])
            .expect("Failed to create certificate params");
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to create self-signed certificate");
        let signing_key =
            Ed25519KeyPair::from_pkcs8(key_pair.serialized_der()).expect("Failed to parse key");
        (cert.der().to_vec(), signing_key)
    }

    #[test]
    fn extract_certificate_der_valid() {
        let cert_data = b"fake_certificate_der_data";
        let message = certificate_message(cert_data);
        assert_eq!(extract_certificate_der(&message).unwrap(), cert_data);
    }

    #[test]
    fn extract_certificate_der_too_short() {
        let message = vec![0x0b, 0x00, 0x00];
        assert!(extract_certificate_der(&message).is_err());
    }

    #[test]
    fn extract_certificate_der_truncated() {
        // Claims a 16-byte body but has none.
        let message = vec![0x0b, 0x00, 0x00, 0x10];
        assert!(extract_certificate_der(&message).is_err());
    }

    /// HMAC verification succeeds when the certificate's signature field is
    /// replaced with `HMAC-SHA512(auth_key, ed25519_pub)`.
    #[test]
    fn verify_certificate_hmac_with_real_cert() {
        let (mut cert_der, signing_key) = ed25519_cert();
        let auth_key = [0x42; 32];

        let sig_offset = extract_certificate_signature(&cert_der).unwrap().as_ptr() as usize
            - cert_der.as_ptr() as usize;
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let hmac_tag = hmac::sign(&hmac_key, signing_key.public_key().as_ref());
        cert_der[sig_offset..sig_offset + 64].copy_from_slice(hmac_tag.as_ref());

        verify_certificate_hmac(&cert_der, &auth_key).unwrap();
    }

    /// A real (unmodified) certificate signature fails the HMAC check.
    #[test]
    fn verify_certificate_hmac_invalid_signature() {
        let (cert_der, _) = ed25519_cert();
        let auth_key = [0x42; 32];
        assert!(verify_certificate_hmac(&cert_der, &auth_key).is_err());
    }

    #[test]
    fn verify_certificate_hmac_invalid_der() {
        let auth_key = [0x11; 32];
        assert!(verify_certificate_hmac(&[0x30, 0x00], &auth_key).is_err());
    }

    /// The extracted Ed25519 key matches the signing key's public half.
    #[test]
    fn extract_ed25519_public_key_matches_signing_key() {
        let (cert_der, signing_key) = ed25519_cert();
        let public_key = extract_ed25519_public_key(&cert_der).unwrap();
        assert_eq!(&public_key, signing_key.public_key().as_ref());
    }

    #[test]
    fn extract_certificate_verify_signature_valid() {
        let signature = [0xAB; 64];
        let mut message = vec![0x0f, 0x00, 0x00, 0x44, 0x08, 0x07, 0x00, 0x40];
        message.extend_from_slice(&signature);
        assert_eq!(
            extract_certificate_verify_signature(&message).unwrap(),
            signature.to_vec()
        );
    }

    #[test]
    fn extract_certificate_verify_signature_rejects_wrong_type() {
        let mut message = vec![0x0b; 72];
        message[4] = 0x08;
        message[5] = 0x07;
        message[6] = 0x00;
        message[7] = 0x40;
        assert!(extract_certificate_verify_signature(&message).is_err());
    }

    #[test]
    fn extract_certificate_verify_signature_rejects_unsupported_algorithm() {
        let mut message = vec![0x00; 72];
        message[0] = 0x0f;
        message[4] = 0x04; // RSA-PKCS1-SHA256
        message[5] = 0x01;
        assert!(extract_certificate_verify_signature(&message).is_err());
    }

    #[test]
    fn verify_certificate_verify_signature_valid() {
        let key_pair = ed25519_cert().1;
        let public_key: [u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
        let transcript_hash = [0x42; 32];

        let signed_content = signed_fixture(&transcript_hash);
        let signature = key_pair.sign(&signed_content);

        verify_certificate_verify_signature(&public_key, signature.as_ref(), &transcript_hash)
            .unwrap();
    }

    #[test]
    fn verify_certificate_verify_signature_wrong_key() {
        let key_pair1 = ed25519_cert().1;
        let key_pair2 = ed25519_cert().1;
        let public_key2: [u8; 32] = key_pair2.public_key().as_ref().try_into().unwrap();
        let transcript_hash = [0x42; 32];

        let signed_content = signed_fixture(&transcript_hash);
        let signature = key_pair1.sign(&signed_content);

        assert!(
            verify_certificate_verify_signature(&public_key2, signature.as_ref(), &transcript_hash)
                .is_err()
        );
    }

    #[test]
    fn verify_certificate_verify_signature_wrong_transcript() {
        let key_pair = ed25519_cert().1;
        let public_key: [u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
        let transcript_hash1 = [0x42; 32];

        let signed_content = signed_fixture(&transcript_hash1);
        let signature = key_pair.sign(&signed_content);

        assert!(
            verify_certificate_verify_signature(&public_key, signature.as_ref(), &[0x43; 32])
                .is_err()
        );
    }

    #[test]
    fn verify_certificate_verify_signature_invalid_length() {
        let public_key = [0x00; 32];
        assert!(
            verify_certificate_verify_signature(&public_key, &[0x00; 32], &[0x42; 32]).is_err()
        );
    }

    /// End to end: HMAC-stamped certificate + a `CertificateVerify` signed
    /// over the transcript both verify.
    #[test]
    fn verify_server_end_to_end() {
        let (mut cert_der, signing_key) = ed25519_cert();
        let auth_key = [0x42; 32];

        // Stamp the certificate with the REALITY HMAC.
        let sig_offset = extract_certificate_signature(&cert_der).unwrap().as_ptr() as usize
            - cert_der.as_ptr() as usize;
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let hmac_tag = hmac::sign(&hmac_key, signing_key.public_key().as_ref());
        cert_der[sig_offset..sig_offset + 64].copy_from_slice(hmac_tag.as_ref());

        // A transcript and the CertificateVerify message over it.
        let transcript = b"ClientHello..Certificate bytes";
        let transcript_hash = digest::digest(&digest::SHA256, transcript);
        let th: [u8; 32] = transcript_hash.as_ref().try_into().unwrap();
        let signed_content = signed_fixture(&th);
        let signature = signing_key.sign(&signed_content);
        let mut cv = vec![0x0f, 0x00, 0x00, 0x44, 0x08, 0x07, 0x00, 0x40];
        cv.extend_from_slice(signature.as_ref());

        verify_server(&cert_der, &cv, &auth_key, transcript, &digest::SHA256).unwrap();

        // A wrong auth_key fails the whole chain.
        assert!(verify_server(&cert_der, &cv, &[0x43; 32], transcript, &digest::SHA256).is_err());
    }
}
