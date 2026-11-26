//! Static key material: decoding, clamping, and the two X25519 agreements the
//! handshake needs.
//!
//! `WireGuard` keys travel as standard base64 in share links and Clash YAML, and
//! as hex in xray's JSON dialect; both decode to 32 bytes. A decoded key of all
//! zeros is a config error, never a usable key — the reference's
//! `NoisePrivateKey::FromHex` rejects it and `errInvalidPublicKey` guards the
//! static-static precomputation, because a tunnel with one side zeroed
//! "would handshake with nobody" (`ferrox` `wireguard.rs` says the same).

use base64::Engine as _;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// A 32-byte private key that wipes itself when dropped.
pub type Secret = Zeroizing<[u8; 32]>;

/// Why a key string cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    /// The text is neither 64 hex characters nor standard base64.
    #[error("wireguard key is not 64 hex characters or base64")]
    NotAKey,
    /// The decoded key is 32 zero bytes.
    #[error("wireguard key is all zeros")]
    ZeroKey,
    /// X25519 produced the all-zero shared secret (a low-order public key).
    #[error("wireguard peer public key is a low-order point")]
    LowOrder,
}

/// Decode a 32-byte key from hex (xray's dialect) or standard base64 (share
/// links, Clash). Whitespace around the value is ignored; anything that
/// decodes to a length other than 32 is [`KeyError::NotAKey`].
pub fn decode_key(text: &str) -> Result<[u8; 32], KeyError> {
    let text = text.trim();
    let bytes = if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (i, pair) in text.as_bytes().chunks(2).enumerate() {
            let hi = hex_val(pair[0]).ok_or(KeyError::NotAKey)?;
            let lo = hex_val(pair[1]).ok_or(KeyError::NotAKey)?;
            out[i] = hi << 4 | lo;
        }
        return if out == [0u8; 32] {
            Err(KeyError::ZeroKey)
        } else {
            Ok(out)
        };
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|_| KeyError::NotAKey)?
    };
    let key: [u8; 32] = bytes.try_into().map_err(|_| KeyError::NotAKey)?;
    if key == [0u8; 32] {
        return Err(KeyError::ZeroKey);
    }
    Ok(key)
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// X25519 scalar clamping (RFC 7748 §5). The reference clamps a private key on
/// load (`NoisePrivateKey::FromHex` → `clamp`), so the stored form and the
/// public key agree with every other implementation.
#[must_use]
pub const fn clamp(mut key: [u8; 32]) -> [u8; 32] {
    key[0] &= 0xF8;
    key[31] &= 0x7F;
    key[31] |= 0x40;
    key
}

/// Decode a *private* key: base64 or hex, clamped, zero rejected, wiped on
/// drop.
pub fn decode_private(text: &str) -> Result<Secret, KeyError> {
    Ok(Zeroizing::new(clamp(decode_key(text)?)))
}

/// Decode a *peer public* key. A public key that is all zeros is rejected by
/// [`shared`] at use time; here only the encoding is validated.
pub fn decode_public(text: &str) -> Result<[u8; 32], KeyError> {
    decode_key(text)
}

/// A `WireGuard` pre-shared key: base64 or hex.
pub fn decode_preshared(text: &str) -> Result<Secret, KeyError> {
    let key = decode_key(text)?;
    Ok(Zeroizing::new(key))
}

/// The public key for a clamped private key.
#[must_use]
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// `X25519(secret, peer_public)`, refusing the all-zero result a low-order
/// point produces (the reference's `sharedSecret` error).
pub fn shared(secret: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32], KeyError> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*peer_public));
    if !shared.was_contributory() {
        return Err(KeyError::LowOrder);
    }
    Ok(shared.to_bytes())
}

/// Fill a private key from the system CSPRNG, clamped.
///
/// Key material never touches the shared buffer in `crate::rand`; this is the
/// same direct `SystemRandom::fill` the TLS engine uses for X25519 seeds.
pub fn fill_secret(out: &mut [u8; 32]) {
    use ring::rand::SecureRandom as _;
    ring::rand::SystemRandom::new()
        .fill(out)
        .expect("the system CSPRNG must produce key material");
    *out = clamp(*out);
}

#[cfg(test)]
mod tests {
    use super::{KeyError, clamp, decode_key, decode_private, public_key, shared};
    fn unhex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, p) in s.as_bytes().chunks(2).enumerate() {
            let t = std::str::from_utf8(p).unwrap();
            out[i] = u8::from_str_radix(t, 16).unwrap();
        }
        out
    }

    /// RFC 7748 §6.1: Alice and Bob agree, and each public key is the derived
    /// one. dalek clamps at use, so the raw scalar bytes are the RFC's.
    #[test]
    fn rfc7748_agreement_and_public_keys() {
        let alice = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let alice_pub = unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_pub = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let want = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(public_key(&alice), alice_pub);
        assert_eq!(public_key(&bob), bob_pub);
        assert_eq!(shared(&alice, &bob_pub).unwrap(), want);
        assert_eq!(shared(&bob, &alice_pub).unwrap(), want);
    }

    #[test]
    fn clamping_is_the_rfc_mask() {
        assert_eq!(clamp([0xff; 32])[0], 0xf8);
        assert_eq!(clamp([0xff; 32])[31], 0x7f);
        assert_eq!(clamp([0x00; 32])[31], 0x40);
    }

    #[test]
    fn rejects_a_wrong_length() {
        // A 32-byte base64 key is 44 characters; 43 decodes short.
        assert_eq!(decode_key(&"A".repeat(43)), Err(KeyError::NotAKey));
        assert_eq!(decode_key("not a key"), Err(KeyError::NotAKey));
    }

    #[test]
    fn rejects_zero_keys_in_both_encodings() {
        assert_eq!(decode_key(&"0".repeat(64)), Err(KeyError::ZeroKey));
        assert_eq!(
            decode_key(&base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [0u8; 32]
            )),
            Err(KeyError::ZeroKey)
        );
    }

    #[test]
    fn hex_and_base64_decode_to_the_same_key() {
        let raw = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw);
        assert_eq!(decode_key(hex).unwrap(), raw);
        assert_eq!(decode_key(&b64).unwrap(), raw);
        // The private form clamps the same bytes.
        assert_eq!(*decode_private(&b64).unwrap(), clamp(raw));
    }

    #[test]
    fn a_low_order_peer_is_refused() {
        let secret = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        assert_eq!(shared(&secret, &[0u8; 32]), Err(KeyError::LowOrder));
    }
}
