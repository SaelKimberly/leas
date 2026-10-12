//! REALITY authentication crypto (ring port of
//! `thirdparty/shoes/src/reality/reality_auth.rs`): ECDH → `HKDF-SHA256`
//! `auth_key` and the `AES-256-GCM` seal/unseal of the `SessionId` payload.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use zeroize::Zeroizing;

use crate::error::{Result, TlsError};

/// Output length for `Prk::expand` — required by ring's `KeyType`.
struct ExpandLen(usize);

impl hkdf::KeyType for ExpandLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derives the REALITY `auth_key`:
/// `HKDF-SHA256(shared_secret, salt, b"REALITY")` (RFC 5869), 32 bytes.
///
/// The protocol fixes `salt` = `ClientHello.Random[0..20]` and `info` =
/// `b"REALITY"`; HKDF itself accepts any salt length.
///
/// The key wipes on drop: it is the whole REALITY authentication secret for
/// the connection (it both seals the `SessionId` and gates the server's
/// `CertificateVerify` check).
pub fn derive_auth_key(
    shared_secret: &[u8; 32],
    salt: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(shared_secret);
    let info_pieces = [info];
    let okm = prk
        .expand(&info_pieces, ExpandLen(32))
        .map_err(|_| TlsError::Crypto("REALITY auth_key HKDF expand failed".into()))?;
    let mut auth_key = Zeroizing::new([0u8; 32]);
    okm.fill(&mut *auth_key)
        .map_err(|_| TlsError::Crypto("REALITY auth_key fill failed".into()))?;
    Ok(auth_key)
}

/// Seals the 16-byte `SessionId` plaintext under
/// `AES-256-GCM(auth_key, nonce, aad)`, returning `ciphertext || tag`
/// (32 bytes).
pub fn encrypt_session_id(
    plaintext: &[u8; 16],
    auth_key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
) -> Result<[u8; 32]> {
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| TlsError::Crypto("REALITY session-id nonce must be 12 bytes".into()))?;
    let unbound = UnboundKey::new(&ring::aead::AES_256_GCM, auth_key)
        .map_err(|_| TlsError::Crypto("REALITY session-id key setup failed".into()))?;
    let key = LessSafeKey::new(unbound);
    // `seal_in_place_append_tag` needs a `Vec` to push the tag into;
    // `separate_tag` seals the stack array and hands the tag back.
    let mut in_out = *plaintext;
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| TlsError::Crypto("REALITY session-id seal failed".into()))?;
    let mut sealed = [0u8; 32];
    sealed[..16].copy_from_slice(&in_out);
    sealed[16..].copy_from_slice(tag.as_ref());
    Ok(sealed)
}

/// Opens a sealed `SessionId` (`ciphertext || tag`, 32 bytes) under the same
/// `(auth_key, nonce, aad)`, returning the 16-byte plaintext.
pub fn decrypt_session_id(
    ciphertext_and_tag: &[u8; 32],
    auth_key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
) -> Result<[u8; 16]> {
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| TlsError::Crypto("REALITY session-id nonce must be 12 bytes".into()))?;
    let unbound = UnboundKey::new(&ring::aead::AES_256_GCM, auth_key)
        .map_err(|_| TlsError::Crypto("REALITY session-id key setup failed".into()))?;
    let key = LessSafeKey::new(unbound);
    let mut in_out = *ciphertext_and_tag;
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| {
            TlsError::Crypto(
                "REALITY session-id open failed — wrong auth_key or tampered hello".into(),
            )
        })?;
    let mut result = [0u8; 16];
    result
        .get_mut(..plaintext.len())
        .ok_or_else(|| {
            TlsError::Crypto("REALITY session-id open produced unexpected length".into())
        })?
        .copy_from_slice(plaintext);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string into bytes (test helper).
    fn decode_hex(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let mut hi = None;
        for b in s.bytes() {
            let v = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex digit: {b:#x}"),
            };
            match hi {
                None => hi = Some(v),
                Some(h) => {
                    out.push((h << 4) | v);
                    hi = None;
                }
            }
        }
        assert_eq!(hi, None, "hex string must have even length");
        out
    }

    /// `decode_hex` then hex-encode back (assert helper).
    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Auth-key derivation known-answer. IKM is the RFC 7748 §6.1 X25519
    /// shared secret `K` (`X25519(a, B) = X25519(b, A)` for the vector's
    /// fixed keys); salt = `random[0..20]` = `0x00..0x13`; info = `"REALITY"`.
    ///
    /// Expected value computed with an independent HKDF-SHA256 (RFC 5869)
    /// implementation and validated against the RFC 5869 A.1 vectors.
    #[test]
    fn auth_key_derivation_matches_rfc7748_known_answer() {
        // RFC 7748 §6.1: Alice a → A, Bob b → B, shared K.
        let shared: [u8; 32] =
            decode_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .try_into()
                .unwrap();
        let salt: [u8; 20] = (0..20u8).collect::<Vec<_>>().try_into().unwrap();

        let auth_key = derive_auth_key(&shared, &salt, b"REALITY").unwrap();
        assert_eq!(
            hex(auth_key.as_slice()),
            "68e5a4d6fbfc0f93477d737fbdd45bd5f81578fbd172327b6db8e963e2ba4a3c"
        );

        // Deterministic for identical inputs.
        assert_eq!(
            derive_auth_key(&shared, &salt, b"REALITY").unwrap(),
            auth_key
        );
        // A different salt (i.e. client random) must produce a different key.
        let other_salt = [0xAA; 20];
        assert_ne!(
            derive_auth_key(&shared, &other_salt, b"REALITY").unwrap(),
            auth_key
        );
    }

    /// Seal/unseal round-trip of the `SessionId` payload with fixed
    /// `(auth_key, nonce, aad)`.
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = [0x55; 16];
        let auth_key = [0x66; 32];
        let nonce = [0x77; 12];
        let aad = b"test additional authenticated data";

        let sealed = encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap();
        assert_eq!(sealed.len(), 32);
        assert_eq!(
            decrypt_session_id(&sealed, &auth_key, &nonce, aad).unwrap(),
            plaintext
        );
    }

    /// AES-256-GCM authenticates the key, nonce and AAD: any deviation
    /// fails the open.
    #[test]
    fn decrypt_rejects_wrong_material() {
        let plaintext = [0x55; 16];
        let auth_key = [0x66; 32];
        let nonce = [0x77; 12];
        let aad = b"additional authenticated data";

        let sealed = encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap();
        let wrong_key = [0x67; 32];
        assert!(decrypt_session_id(&sealed, &wrong_key, &nonce, aad).is_err());
        assert!(decrypt_session_id(&sealed, &auth_key, &[0x78; 12], aad).is_err());
        assert!(decrypt_session_id(&sealed, &auth_key, &nonce, b"wrong aad").is_err());
    }

    /// Sealing is deterministic: identical inputs produce identical output.
    #[test]
    fn seal_is_deterministic() {
        let plaintext = [0x55; 16];
        let auth_key = [0x66; 32];
        let nonce = [0x77; 12];
        let aad = b"aad";
        assert_eq!(
            encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap(),
            encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap()
        );
    }
}
