//! Shadowsocks 2022 extensible identity headers — client side.
//!
//! Spec: `2022-2-shadowsocks-2022-extensible-identity-headers.md`.
//! A password is `iPSK1:iPSK2:…:uPSK`; the first PSK is the server's identity
//! key, the last is the user's session key. Every iPSK emits one header that
//! names the NEXT key's hash:
//!
//! ```text
//! TCP: identity_subkey = blake3::derive_key("shadowsocks 2022 identity subkey",
//!                                          iPSK ‖ salt)
//!      header = AES-ECB(identity_subkey, blake3(next)[0..16])
//! UDP: header = AES-ECB(iPSK, blake3(next)[0..16] XOR [session_id ‖ packet_id])
//! ```
//!
//! Only the AES methods carry EIH; a `ChaCha` list is refused upstream by
//! [`super::method::password_chain`]. The single-key case emits nothing.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use zeroize::Zeroizing;

use crate::crypto::aead::SsAead;
use crate::crypto::kdf::blake3_derive_key;
use crate::error::NativeError;

/// Spec §2.2's identity-subkey context — distinct from the session context so
/// an EIH key can never equal the session key.
pub(super) const IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";

/// AES block size: one EIH is exactly one block.
pub(super) const EIH_LEN: usize = 16;

/// AES-ECB encrypt one 16-byte block. The key is the method's key length, so
/// a non-AES method is a config error rather than a silent fallback.
pub(super) fn aes_ecb_encrypt(
    aead: SsAead,
    key: &[u8],
    block: &mut [u8; EIH_LEN],
) -> Result<(), NativeError> {
    let out = match aead {
        SsAead::Aes128Gcm => {
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| NativeError::Config("AES-128 PSK must be 16 bytes".into()))?;
            let mut out = [0u8; EIH_LEN];
            cipher.encrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        SsAead::Aes256Gcm => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| NativeError::Config("AES-256 PSK must be 32 bytes".into()))?;
            let mut out = [0u8; EIH_LEN];
            cipher.encrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        other => {
            return Err(NativeError::Config(format!(
                "{other:?} has no Shadowsocks-2022 identity header (AES methods only)"
            )));
        }
    };
    *block = out;
    Ok(())
}

/// [`aes_ecb_encrypt`]'s inverse — used by the UDP reader and by tests.
pub(super) fn aes_ecb_decrypt(
    aead: SsAead,
    key: &[u8],
    block: &mut [u8; EIH_LEN],
) -> Result<(), NativeError> {
    let out = match aead {
        SsAead::Aes128Gcm => {
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| NativeError::Config("AES-128 PSK must be 16 bytes".into()))?;
            let mut out = [0u8; EIH_LEN];
            cipher.decrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        SsAead::Aes256Gcm => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| NativeError::Config("AES-256 PSK must be 32 bytes".into()))?;
            let mut out = [0u8; EIH_LEN];
            cipher.decrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        other => {
            return Err(NativeError::Config(format!(
                "{other:?} has no Shadowsocks-2022 identity header (AES methods only)"
            )));
        }
    };
    *block = out;
    Ok(())
}

/// `blake3(psk)[0..16]` — the identity hash a previous layer names.
///
/// BLAKE3's XOF is prefix-consistent, so this equals the first 16 bytes of the
/// 64-byte digest xray's `DeriveUserPSKHash` uses.
fn psk_hash(psk: &[u8]) -> [u8; EIH_LEN] {
    let hash = blake3::hash(psk);
    let mut out = [0u8; EIH_LEN];
    out.copy_from_slice(&hash.as_bytes()[..EIH_LEN]);
    out
}

/// Append the TCP identity headers for `keys` — one per iPSK, none for a
/// single-key row. `salt` is the request salt already on the wire.
pub(super) fn write_tcp_headers(
    out: &mut Vec<u8>,
    aead: SsAead,
    keys: &[Zeroizing<Vec<u8>>],
    salt: &[u8],
) -> Result<(), NativeError> {
    for pair in keys.windows(2) {
        let mut material = Zeroizing::new(Vec::with_capacity(pair[0].len() + salt.len()));
        material.extend_from_slice(&pair[0]);
        material.extend_from_slice(salt);
        let subkey = Zeroizing::new(blake3_derive_key(IDENTITY_SUBKEY_CONTEXT, &material));
        let mut block = psk_hash(&pair[1]);
        aes_ecb_encrypt(aead, &subkey[..aead.key_len()], &mut block)?;
        out.extend_from_slice(&block);
    }
    Ok(())
}

/// Append the UDP identity headers for `keys` — one per iPSK. `session_id`
/// and `packet_id` are the PLAINTEXT separate header the first layer encrypts.
pub(super) fn write_udp_headers(
    out: &mut Vec<u8>,
    aead: SsAead,
    keys: &[Zeroizing<Vec<u8>>],
    session_id: u64,
    packet_id: u64,
) -> Result<(), NativeError> {
    let mut raw = [0u8; EIH_LEN];
    raw[..8].copy_from_slice(&session_id.to_be_bytes());
    raw[8..].copy_from_slice(&packet_id.to_be_bytes());
    for pair in keys.windows(2) {
        let mut block = psk_hash(&pair[1]);
        for (byte, mask) in block.iter_mut().zip(raw) {
            *byte ^= mask;
        }
        aes_ecb_encrypt(aead, &pair[0], &mut block)?;
        out.extend_from_slice(&block);
    }
    Ok(())
}
