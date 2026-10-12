//! Hysteria2 Salamander packet obfuscation.
//!
//! A DATAGRAM transform, not a byte stream. Each UDP packet is emitted as
//! `[8-byte random salt][payload XOR blake2b256(psk || salt)]`; the receiver
//! strips the salt, re-derives the same keystream from `(psk, salt)` and
//! XORs the payload back.
//! Reference: thirdparty/hysteria `extras/obfs/salamander.go` (MIT) — the
//! exact salt layout and key derivation sing-box also implements. The
//! payload XOR is SIMD-vectorized with the `wide` crate (`u8x32`), mirroring
//! the reference `thirdparty/xray-rs-tls/src/obfuscation/salamander.rs`.

use blake2::Blake2b256;
use blake2::digest::Digest;
use wide::u8x32;
use zeroize::ZeroizeOnDrop;

/// Salt length prepended to every obfuscated packet (`smSaltLen`).
pub const SALT_LEN: usize = 8;
/// BLAKE2b-256 keystream block size.
const KEY_LEN: usize = 32;

/// Minimum obfuscation pre-shared key length (`smPSKMinLen`).
pub const PSK_MIN_LEN: usize = 4;

/// Hysteria2 Salamander obfuscator: XOR a payload with the BLAKE2b-256
/// keystream derived from `psk || salt`.
///
/// `&self` — the keystream is derived per packet into an owned key, so no
/// interior mutability or embedded RNG is needed (the caller supplies the
/// salt via [`Self::obfuscate_into`], enabling deterministic tests).
///
/// The PSK wipes on drop, and `Debug` prints its length only — the derive
/// would put the obfuscation pre-shared key into any log line.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Salamander {
    psk: Vec<u8>,
}

impl core::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Salamander")
            .field("psk", &format_args!("<{} bytes redacted>", self.psk.len()))
            .finish()
    }
}

impl Salamander {
    /// Build the obfuscator from a pre-shared key (`smPSKMinLen` minimum).
    ///
    /// # Errors
    ///
    /// `NativeError::Config` when the PSK is shorter than
    /// [`PSK_MIN_LEN`] (`errPSKTooShort`-equivalent).
    pub fn new(psk: &[u8]) -> Result<Self, crate::error::NativeError> {
        if psk.len() < PSK_MIN_LEN {
            return Err(crate::error::NativeError::Config(format!(
                "salamander PSK must be at least {PSK_MIN_LEN} bytes"
            )));
        }
        Ok(Self { psk: psk.to_vec() })
    }

    /// The 32-byte keystream key for one packet: `blake2b256(psk || salt)`.
    ///
    /// `salt` must be exactly [`SALT_LEN`] bytes.
    #[inline]
    fn key(&self, salt: &[u8]) -> u8x32 {
        let digest = Blake2b256::new()
            .chain_update(&self.psk)
            .chain_update(salt)
            .finalize();
        u8x32::new(digest.into())
    }

    /// Obfuscate `payload` into `out` (`out.len() >= len + SALT_LEN`):
    /// salt first, then `payload XOR keystream`. Returns the number of bytes
    /// written.
    ///
    /// `salt_bytes` supplies the 8-byte random salt (separated for
    /// deterministic tests).
    pub fn obfuscate_into(
        &self,
        salt_bytes: &[u8; SALT_LEN],
        payload: &[u8],
        out: &mut [u8],
    ) -> usize {
        debug_assert!(out.len() >= payload.len() + SALT_LEN);
        out[..SALT_LEN].copy_from_slice(salt_bytes);
        let key = self.key(salt_bytes);
        xor_wide(key, payload, &mut out[SALT_LEN..]);
        payload.len() + SALT_LEN
    }

    /// Deobfuscate `packet` (salt-prefixed) into `out`
    /// (`out.len() >= packet.len() - SALT_LEN`). Returns the plaintext
    /// length, or `0` when the packet is shorter than the salt (a malformed
    /// short datagram — the wire drops it, matching Go's `Deobfuscate`).
    pub fn deobfuscate_into(&self, packet: &[u8], out: &mut [u8]) -> usize {
        if packet.len() <= SALT_LEN {
            return 0;
        }
        let salt: [u8; SALT_LEN] = packet[..SALT_LEN].try_into().expect("length checked");
        let plain_len = packet.len() - SALT_LEN;
        debug_assert!(out.len() >= plain_len);
        let key = self.key(&salt);
        xor_wide(key, &packet[SALT_LEN..], &mut out[..plain_len]);
        plain_len
    }
}

/// XOR `input` with the keystream `key` into `out`, 32 bytes at a time
/// (SIMD via `wide::u8x32`), then the trailing sub-block byte-wise.
#[inline]
fn xor_wide(key: u8x32, input: &[u8], out: &mut [u8]) {
    let (full, tail) = input.split_at(input.len() / KEY_LEN * KEY_LEN);
    let (out_full, out_tail) = out.split_at_mut(full.len());
    for (chunk, dst) in full
        .as_chunks::<32>()
        .0
        .iter()
        .zip(out_full.as_chunks_mut::<32>().0.iter_mut())
    {
        let src = u8x32::new(*chunk);
        dst.copy_from_slice(&(src ^ key).to_array());
    }
    for ((i, o), k) in tail
        .iter()
        .zip(out_tail.iter_mut())
        .zip(key.to_array().iter())
    {
        *o = *i ^ *k;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_too_short_rejected() {
        assert!(Salamander::new(&[0u8; 3]).is_err());
        assert!(Salamander::new(&[0u8; 4]).is_ok());
    }

    #[test]
    fn roundtrip() {
        let ob = Salamander::new(b"psk-password-1234").unwrap();
        let payload = b"hello salamander world";
        let mut wire = [0u8; 128];
        let n = ob.obfuscate_into(&[0xaa; 8], payload, &mut wire);
        assert_eq!(n, SALT_LEN + payload.len());
        // Salt is preserved on the wire.
        assert_eq!(&wire[..SALT_LEN], &[0xaa; 8]);
        // Payload is not plaintext.
        assert_ne!(&wire[SALT_LEN..n], payload);
        // Deobfuscate recovers the original.
        let mut plain = [0u8; 128];
        let m = ob.deobfuscate_into(&wire[..n], &mut plain);
        assert_eq!(m, payload.len());
        assert_eq!(&plain[..m], payload);
    }

    /// Exercising the SIMD tail path: payload larger than 32 bytes AND a
    /// non-multiple of 32.
    #[test]
    fn roundtrip_spanning_blocks() {
        let ob = Salamander::new(b"valid-psk").unwrap();
        let payload = vec![0x11u8; 100]; // 3 full blocks + 4 tail bytes
        let mut wire = vec![0u8; SALT_LEN + payload.len()];
        let n = ob.obfuscate_into(&[7; 8], &payload, &mut wire);
        assert_eq!(n, wire.len());
        let mut plain = vec![0u8; payload.len()];
        let m = ob.deobfuscate_into(&wire, &mut plain);
        assert_eq!(m, payload.len());
        assert_eq!(plain, payload);
    }

    #[test]
    fn different_salt_gives_different_wire() {
        let ob = Salamander::new(b"psk-long-enough").unwrap();
        let payload = b"same";
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        ob.obfuscate_into(&[1; 8], payload, &mut a);
        ob.obfuscate_into(&[2; 8], payload, &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn short_packet_deobfuscates_to_nothing() {
        let ob = Salamander::new(b"valid-psk").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(ob.deobfuscate_into(&[0u8; 4], &mut out), 0);
    }

    /// Known-answer test: `blake2b256("psk" || 01*8)` keystream, first 8
    /// bytes, checked against a runtime computation with the reference
    /// hasher so a regression in the construction (wrong input order, wrong
    /// salt copy) is caught.
    #[test]
    fn keystream_matches_reference_blake2b() {
        let ob = Salamander::new(b"psk-password").unwrap();
        let salt = [1u8; 8];
        let key = ob.key(&salt);
        let mut hasher = Blake2b256::new();
        hasher.update(b"psk-password");
        hasher.update(salt);
        let expect: [u8; KEY_LEN] = hasher.finalize().into();
        assert_eq!(key.to_array(), expect);
    }
}
