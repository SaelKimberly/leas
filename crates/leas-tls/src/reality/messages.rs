//! REALITY `ClientHello`-level helpers: the `SessionId` plaintext, the
//! client random, and the auth-payload seal/splice.
//!
//! This is a ring port of the client-side pieces of shoes'
//! `reality_tls13_messages.rs` and `reality_util.rs`; the `ClientHello` is
//! built by [`crate::hello::build_hello`] through [`super::HelloProvisioner`].
//!

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, TlsError};
use crate::reality::{ProvisionedHello, auth};

/// REALITY protocol version carried in the `SessionId` plaintext.
pub const REALITY_VERSION: [u8; 3] = [1, 8, 0];

/// Builds the 16-byte `SessionId` plaintext:
/// `version(1,8,0) || pad(0x00) || timestamp u32 BE || short_id (≤8 bytes,
/// zero-padded)`.
///
/// `short_id` longer than 8 bytes is rejected — truncating an
/// authentication ID silently would be a protocol bug.
pub fn build_session_id_plaintext(timestamp: u32, short_id: &[u8]) -> Result<[u8; 16]> {
    if short_id.len() > 8 {
        return Err(TlsError::Protocol(format!(
            "REALITY short_id is {} bytes, max 8",
            short_id.len()
        )));
    }
    let mut plaintext = [0u8; 16];
    plaintext[..3].copy_from_slice(&REALITY_VERSION);
    // plaintext[3] stays 0 (padding byte).
    plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..8 + short_id.len()].copy_from_slice(short_id);
    Ok(plaintext)
}

/// Current Unix time in whole seconds (the REALITY `SessionId` timestamp).
pub fn now_timestamp() -> Result<u32> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TlsError::Handshake("system clock is before the UNIX epoch".into()))?
        .as_secs();
    Ok(u32::try_from(secs).unwrap_or(u32::MAX))
}

/// The `ClientHello.random` of a handshake message.
///
/// The position is fixed by RFC 8446 §4.1.2: handshake header (4) +
/// `legacy_version` (2) + random. In REALITY these 32 bytes are the
/// protocol random: `[0..20]` is the HKDF salt and `[20..32]` the AES-GCM
/// nonce.
pub fn extract_client_random(handshake_bytes: &[u8]) -> Result<[u8; 32]> {
    let random = handshake_bytes
        .get(6..38)
        .ok_or_else(|| TlsError::Protocol("ClientHello too short for random".into()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(random);
    Ok(out)
}

/// Seals the 16-byte `SessionId` plaintext into a provisioned hello's
/// `AuthPayload` slot.
///
/// The AAD is the hello exactly as provisioned (slot zeroed); the 32-byte
/// `ciphertext || tag` is written into the builder-returned
/// `session_id_range` — never a hardcoded offset.
pub fn seal_and_splice(
    hello: &mut ProvisionedHello,
    plaintext: &[u8; 16],
    auth_key: &[u8; 32],
    nonce: &[u8],
) -> Result<()> {
    if hello.session_id_range.len() != 32 {
        return Err(TlsError::Protocol(format!(
            "AuthPayload slot must be 32 bytes, got {}",
            hello.session_id_range.len()
        )));
    }
    let sealed = auth::encrypt_session_id(plaintext, auth_key, nonce, &hello.handshake_bytes)?;
    let range = hello.session_id_range.clone();
    let slot = hello
        .handshake_bytes
        .get_mut(range)
        .ok_or_else(|| TlsError::Protocol("session_id_range out of bounds".into()))?;
    slot.copy_from_slice(&sealed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::X25519KeyPair;
    use crate::crypto::mlkem::Mlkem768;
    use crate::hello::parse::parse_hello;
    use crate::reality::auth::{decrypt_session_id, derive_auth_key};
    use crate::reality::{FixedChrome133, HelloProvisionParams, HelloProvisioner};

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

    /// `SessionId` plaintext structure: `[1,8,0,0] + timestamp BE +
    /// short_id` (zero-padded to 8).
    #[test]
    fn session_id_plaintext_structure() {
        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let plaintext = build_session_id_plaintext(1_234_567_890, &short_id).unwrap();

        assert_eq!(&plaintext[..4], &[1, 8, 0, 0]);
        assert_eq!(
            u32::from_be_bytes(plaintext[4..8].try_into().unwrap()),
            1_234_567_890
        );
        assert_eq!(&plaintext[8..16], &short_id);

        // Short ids are zero-padded to the right.
        let short = build_session_id_plaintext(0, &[0xAB, 0xCD]).unwrap();
        assert_eq!(&short[8..10], &[0xAB, 0xCD]);
        assert_eq!(&short[10..16], &[0; 6]);

        // Over-long ids are rejected, not truncated.
        assert!(build_session_id_plaintext(0, &[0; 9]).is_err());
    }

    /// The brief's named test: fixed server pub (the RFC 7748 §6.1 vector's
    /// Bob public key), a client keypair, random bytes `[0..32]`. Derive
    /// Derive shared + `auth_key`; seal the plaintext into a hello built
    /// with `AuthPayload`; unseal with the same `auth_key`; assert the
    /// plaintext round-trips as `[1,8,0,0, ts_be, short_id...]`.
    #[test]
    fn session_id_seal_roundtrip() {
        // Server public key: RFC 7748 §6.1 Bob's public key B.
        let server_pub: [u8; 32] =
            decode_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .try_into()
                .unwrap();
        let rng = ring::rand::SystemRandom::new();
        let keypair = X25519KeyPair::generate(&rng).unwrap();
        let (mlkem_pk, _) = Mlkem768::generate_keypair();
        let shared = keypair.agree(&server_pub).unwrap();

        // Fixed random bytes [0..32]: salt = [0..20], nonce = [20..32].
        let random: [u8; 32] = (0..32u8).collect::<Vec<_>>().try_into().unwrap();
        let auth_key = derive_auth_key(&shared, &random[..20], b"REALITY").unwrap();

        let timestamp = 1_700_000_000u32;
        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let plaintext = build_session_id_plaintext(timestamp, &short_id).unwrap();

        // A hello built with AuthPayload (slot zeroed) via the provisioner.
        let mut hello = FixedChrome133
            .provision(&HelloProvisionParams {
                server_name: "www.microsoft.com",
                alpn: Some(&["h2", "http/1.1"]),
                x25519_pub: &keypair.public_key(),
                mlkem768_pub: Some(mlkem_pk.as_bytes()),
                rng: &rng,
            })
            .unwrap();
        assert_eq!(hello.session_id_range.len(), 32);

        // Seal into the slot.
        seal_and_splice(&mut hello, &plaintext, &auth_key, &random[20..]).unwrap();
        assert_ne!(
            &hello.handshake_bytes[hello.session_id_range.clone()],
            &[0u8; 32][..],
            "sealed slot must not stay zeroed"
        );

        // Unseal with the same auth_key; the AAD is the hello with the slot
        // zeroed (the exact bytes that were sealed over).
        let mut zeroed_hello = hello.handshake_bytes.clone();
        zeroed_hello[hello.session_id_range.clone()].fill(0);
        let sealed: [u8; 32] = hello.handshake_bytes[hello.session_id_range.clone()]
            .try_into()
            .unwrap();
        let opened = decrypt_session_id(&sealed, &auth_key, &random[20..], &zeroed_hello).unwrap();

        assert_eq!(&opened[..4], &[1, 8, 0, 0]);
        assert_eq!(
            u32::from_be_bytes(opened[4..8].try_into().unwrap()),
            timestamp
        );
        assert_eq!(&opened[8..16], &short_id);

        // Wrong auth_key or a tampered hello fails authentication.
        assert!(decrypt_session_id(&sealed, &[0x42; 32], &random[20..], &zeroed_hello).is_err());
        assert!(
            decrypt_session_id(&sealed, &auth_key, &random[20..], &hello.handshake_bytes).is_err()
        );
    }

    /// The client random rides at the protocol-fixed offset of the built
    /// hello and is 32 bytes.
    #[test]
    fn extract_client_random_from_provisioned_hello() {
        let rng = ring::rand::SystemRandom::new();
        let (mlkem_pk, _) = Mlkem768::generate_keypair();
        let hello = FixedChrome133
            .provision(&HelloProvisionParams {
                server_name: "www.microsoft.com",
                alpn: Some(&["h2", "http/1.1"]),
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: Some(mlkem_pk.as_bytes()),
                rng: &rng,
            })
            .unwrap();
        let random = extract_client_random(&hello.handshake_bytes).unwrap();
        let parsed = parse_hello(&hello.handshake_bytes).unwrap();
        assert_eq!(parsed.random, random);
    }
}
