//! AEAD body ciphers: AES-128/192/256-GCM and ChaCha20/XChaCha20-Poly1305.
//!
//! Consumers: `protocol/ss` (classic AEAD + 2022-blake3, Tasks 3/4/6). The
//! `VMess` record codec (`protocol/vmess/stream.rs`) drives the same
//! `RustCrypto` primitives directly for its own record framing.
//! Backend: `RustCrypto` (`aes-gcm`, `chacha20poly1305`) — not ring: both are
//! already in the tree with the `zeroize` feature, and their explicit-nonce
//! APIs are what the Shadowsocks counters need. References: RFC 8439,
//! NIST SP 800-38D, draft-irtf-cfrg-xchacha.

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::NativeError;
use leas_proto::proto_spec::ProtocolKind;

/// AES-192-GCM. `aes-gcm` 0.11 exports only the 128/256-bit aliases, so the
/// 192-bit key size is spelled out from `AesGcm<Aes, NonceSize, TagSize>`.
type Aes192Gcm = aes_gcm::AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>;

/// The Shadowsocks cipher set native implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsAead {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl SsAead {
    /// AEAD key length (16/24/32) — the method's "key size".
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes192Gcm => 24,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::XChaCha20Poly1305 => 32,
        }
    }

    /// Stream/packet salt length: `max(16, key_len)` (mihomo `SaltSize`).
    #[must_use]
    pub const fn salt_len(self) -> usize {
        if self.key_len() > 16 {
            self.key_len()
        } else {
            16
        }
    }

    /// Nonce length: 24 for XChaCha20-Poly1305, 12 for every other method.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }

    /// Poly1305/GCM tag length — 16 bytes for the whole Shadowsocks set.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        16
    }

    /// Seal `plaintext` under `key`/`nonce`, authenticating `aad`; the tag is
    /// appended to the returned ciphertext.
    ///
    /// Thin wrapper over [`Self::seal_into`]: the Shadowsocks chunk codec
    /// needs several seals in one buffer, everything else wants one `Vec`.
    pub fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, NativeError> {
        let mut out = Vec::with_capacity(plaintext.len() + self.tag_len());
        self.seal_into(key, nonce, aad, plaintext, &mut out)?;
        Ok(out)
    }

    /// Open `ciphertext` (tag trailing) under `key`/`nonce`, requiring `aad`
    /// to match the value sealed with it.
    ///
    /// Thin wrapper over [`Self::open_into`].
    pub fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NativeError> {
        let mut out = Vec::with_capacity(ciphertext.len().saturating_sub(self.tag_len()));
        self.open_into(key, nonce, aad, ciphertext, &mut out)?;
        Ok(out)
    }

    /// [`Self::seal`] into the caller's buffer: `plaintext`'s ciphertext and
    /// tag are APPENDED to `out`, leaving whatever it already held untouched
    /// — no per-call `Vec` and no copy of the result, which is what the
    /// Shadowsocks chunk codec's `[len seal][payload seal]` batching needs.
    ///
    /// On failure `out` is left exactly as it was.
    pub fn seal_into(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), NativeError> {
        match self {
            Self::Aes128Gcm => seal_into_with::<Aes128Gcm>(key, nonce, aad, plaintext, out),
            Self::Aes192Gcm => seal_into_with::<Aes192Gcm>(key, nonce, aad, plaintext, out),
            Self::Aes256Gcm => seal_into_with::<Aes256Gcm>(key, nonce, aad, plaintext, out),
            Self::ChaCha20Poly1305 => {
                seal_into_with::<ChaCha20Poly1305>(key, nonce, aad, plaintext, out)
            }
            Self::XChaCha20Poly1305 => {
                seal_into_with::<XChaCha20Poly1305>(key, nonce, aad, plaintext, out)
            }
        }
    }

    /// [`Self::open`] into the caller's buffer: the authenticated plaintext of
    /// `ciphertext` (trailing tag included) is APPENDED to `out`.
    ///
    /// On failure `out` is left exactly as it was — `decrypt` works in place
    /// and verifies afterwards, so the half-decrypted bytes are truncated off
    /// rather than handed to the caller unauthenticated.
    pub fn open_into(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), NativeError> {
        match self {
            Self::Aes128Gcm => open_into_with::<Aes128Gcm>(key, nonce, aad, ciphertext, out),
            Self::Aes192Gcm => open_into_with::<Aes192Gcm>(key, nonce, aad, ciphertext, out),
            Self::Aes256Gcm => open_into_with::<Aes256Gcm>(key, nonce, aad, ciphertext, out),
            Self::ChaCha20Poly1305 => {
                open_into_with::<ChaCha20Poly1305>(key, nonce, aad, ciphertext, out)
            }
            Self::XChaCha20Poly1305 => {
                open_into_with::<XChaCha20Poly1305>(key, nonce, aad, ciphertext, out)
            }
        }
    }
}

/// Every cipher here is a `RustCrypto` `aead::AeadInOut` (`aes-gcm` and
/// `chacha20poly1305` share the 0.6 traits), so one generic pair covers all
/// five — key/nonce widths come from the algorithm's own `KeyInit`/`AeadCore`.
///
/// The detached in-place form (tag returned, not appended) is what lets the
/// caller seal straight into a shared buffer: `protocol/vmess/stream.rs`
/// seals one record per `Vec`, the Shadowsocks chunk codec appends two seals
/// per chunk.
fn seal_into_with<C>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), NativeError>
where
    C: aes_gcm::aead::AeadInOut + aes_gcm::aead::KeyInit,
{
    let cipher = C::new_from_slice(key).map_err(|_| bad_key())?;
    let nonce: &aes_gcm::aead::Nonce<C> = nonce.try_into().map_err(|_| bad_nonce())?;
    let start = out.len();
    out.extend_from_slice(plaintext);
    // The detached tag is owned by the caller of the in-place API: append it
    // after the ciphertext, which is what the wire expects.
    let sealed = cipher.encrypt_inout_detached(nonce, aad, (&mut out[start..]).into());
    let Ok(tag) = sealed else {
        out.truncate(start);
        return Err(cipher_error("AEAD seal failed"));
    };
    out.extend_from_slice(tag.as_slice());
    Ok(())
}

fn open_into_with<C>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), NativeError>
where
    C: aes_gcm::aead::AeadInOut + aes_gcm::aead::KeyInit,
{
    let cipher = C::new_from_slice(key).map_err(|_| bad_key())?;
    let nonce: &aes_gcm::aead::Nonce<C> = nonce.try_into().map_err(|_| bad_nonce())?;
    let tag_len = core::mem::size_of::<aes_gcm::aead::Tag<C>>();
    let Some(split) = ciphertext.len().checked_sub(tag_len) else {
        return Err(cipher_error("AEAD open failed (tampered or wrong key)"));
    };
    let (body, tag) = ciphertext.split_at(split);
    let start = out.len();
    out.extend_from_slice(body);
    // Exact width by the split above, so the conversion cannot fail.
    let tag: &aes_gcm::aead::Tag<C> = tag
        .try_into()
        .map_err(|_| cipher_error("AEAD open failed (tampered or wrong key)"))?;
    if cipher
        .decrypt_inout_detached(nonce, aad, (&mut out[start..]).into(), tag)
        .is_err()
    {
        out.truncate(start);
        return Err(cipher_error("AEAD open failed (tampered or wrong key)"));
    }
    Ok(())
}

fn bad_key() -> NativeError {
    cipher_error("bad AEAD key length")
}

fn bad_nonce() -> NativeError {
    cipher_error("bad AEAD nonce length")
}

fn cipher_error(detail: &str) -> NativeError {
    NativeError::Protocol {
        kind: ProtocolKind::Shadowsocks,
        detail: detail.to_owned(),
    }
}

/// Little-endian counter over a fixed-width nonce, handed out once per AEAD
/// operation — the classic-AEAD and 2022 TCP/stream nonce.
///
/// `next` yields the all-zero nonce first and bumps the counter after each
/// hand-out, wrapping at the top byte. Widths used in the tree are 12 (GCM,
/// ChaCha20-Poly1305) and 24 (XChaCha20-Poly1305).
pub struct NonceCounter {
    buf: Zeroizing<[u8; 24]>,
    len: usize,
    /// Set once the initial all-zero nonce has been handed out: from then on
    /// every `next` bumps the counter before returning it.
    handed_out: bool,
}

impl NonceCounter {
    #[must_use]
    pub fn new(len: usize) -> Self {
        // `assert!`, not `debug_assert!`: an over-wide nonce would otherwise
        // panic on the first hand-out, far from the constructor that accepted
        // it — and only in release builds.
        assert!(
            len <= 24,
            "NonceCounter width must be <= 24 bytes, got {len}"
        );
        Self {
            buf: Zeroizing::new([0u8; 24]),
            len,
            handed_out: false,
        }
    }

    /// The nonce for the next AEAD operation, advancing the counter.
    ///
    /// `next_nonce`, not `next`: this is not an iterator and a bare `next`
    /// beside an `Iterator` in scope reads like one
    /// (`clippy::should_implement_trait`).
    #[must_use]
    pub fn next_nonce(&mut self) -> &[u8] {
        let nonce = &mut self.buf[..self.len];
        if self.handed_out {
            bump(nonce);
        }
        self.handed_out = true;
        nonce
    }
}

/// Little-endian increment over the whole buffer; the carry out of the top
/// byte is dropped, so the counter wraps.
fn bump(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        let (bumped, carry) = byte.overflowing_add(1);
        *byte = bumped;
        if !carry {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_the_wire() {
        assert_eq!(SsAead::Aes128Gcm.key_len(), 16);
        assert_eq!(SsAead::Aes192Gcm.key_len(), 24);
        assert_eq!(SsAead::Aes256Gcm.key_len(), 32);
        assert_eq!(SsAead::ChaCha20Poly1305.key_len(), 32);
        assert_eq!(SsAead::XChaCha20Poly1305.key_len(), 32);
        // salt = max(16, key_len); nonce = 12 (XChaCha 24); tag = 16.
        assert_eq!(SsAead::Aes128Gcm.salt_len(), 16);
        assert_eq!(SsAead::Aes192Gcm.salt_len(), 24);
        assert_eq!(SsAead::XChaCha20Poly1305.salt_len(), 32);
        assert_eq!(SsAead::XChaCha20Poly1305.nonce_len(), 24);
        assert_eq!(SsAead::ChaCha20Poly1305.nonce_len(), 12);
        for aead in [
            SsAead::Aes128Gcm,
            SsAead::Aes192Gcm,
            SsAead::Aes256Gcm,
            SsAead::ChaCha20Poly1305,
            SsAead::XChaCha20Poly1305,
        ] {
            assert_eq!(aead.tag_len(), 16);
        }
    }

    #[test]
    fn seal_open_round_trip_every_cipher() {
        for aead in [
            SsAead::Aes128Gcm,
            SsAead::Aes192Gcm,
            SsAead::Aes256Gcm,
            SsAead::ChaCha20Poly1305,
            SsAead::XChaCha20Poly1305,
        ] {
            let key = vec![0x42u8; aead.key_len()];
            let nonce = vec![0x07u8; aead.nonce_len()];
            let ct = aead.seal(&key, &nonce, b"aad", b"hello").unwrap();
            assert_eq!(ct.len(), 5 + aead.tag_len());
            assert_eq!(aead.open(&key, &nonce, b"aad", &ct).unwrap(), b"hello");
        }
    }

    #[test]
    fn tamper_and_wrong_aad_are_rejected() {
        let aead = SsAead::Aes256Gcm;
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        // Wrong AAD against an INTACT ciphertext (isolates AAD authentication
        // from tamper detection).
        let ct = aead.seal(&key, &nonce, b"", b"payload").unwrap();
        assert!(aead.open(&key, &nonce, b"other", &ct).is_err());
        // Tampered ciphertext with the right AAD.
        let mut ct = aead.seal(&key, &nonce, b"", b"payload").unwrap();
        ct[0] ^= 1;
        assert!(aead.open(&key, &nonce, b"", &ct).is_err());
    }

    /// The `*_into` siblings append to the caller's buffer (the Shadowsocks
    /// chunk codec batches two seals per chunk) and leave it untouched when
    /// the AEAD refuses — a failed open must never hand back the bytes it
    /// decrypted before verifying.
    #[test]
    fn into_variants_append_and_leave_out_untouched_on_failure() {
        for aead in [
            SsAead::Aes128Gcm,
            SsAead::Aes256Gcm,
            SsAead::ChaCha20Poly1305,
            SsAead::XChaCha20Poly1305,
        ] {
            let key = vec![0x2Bu8; aead.key_len()];
            let nonce = vec![0u8; aead.nonce_len()];
            let mut out = b"prefix".to_vec();
            aead.seal_into(&key, &nonce, b"", b"hello", &mut out)
                .unwrap();
            // Byte-identical to the one-shot sibling, appended in place.
            let one_shot = aead.seal(&key, &nonce, b"", b"hello").unwrap();
            assert_eq!(&out[..6], b"prefix");
            assert_eq!(&out[6..], &one_shot[..]);

            let mut back = b"kept".to_vec();
            aead.open_into(&key, &nonce, b"", &out[6..], &mut back)
                .unwrap();
            assert_eq!(&back[..4], b"kept");
            assert_eq!(&back[4..], b"hello");

            // Tampered: rejected, and the destination is exactly as it was.
            let mut tampered = out[6..].to_vec();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            let mut sink = b"kept".to_vec();
            assert!(
                aead.open_into(&key, &nonce, b"", &tampered, &mut sink)
                    .is_err()
            );
            assert_eq!(sink, b"kept");
            // Too short to even hold a tag: rejected without growing `sink`.
            assert!(
                aead.open_into(&key, &nonce, b"", &[0u8; 4], &mut sink)
                    .is_err()
            );
            assert_eq!(sink, b"kept");
        }
    }

    /// The classic/2022 TCP nonce is a little-endian counter over the whole
    /// nonce buffer. Guards the increment width (`XChaCha`'s 24 bytes).
    #[test]
    fn nonce_counter_is_little_endian_and_wraps() {
        let mut c = NonceCounter::new(12);
        assert_eq!(c.next_nonce(), &[0u8; 12]);
        assert_eq!(c.next_nonce(), &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut c = NonceCounter::new(0);
        assert_eq!(c.next_nonce(), &[] as &[u8]);
        // Width: the XChaCha path hands out 24 bytes.
        let mut wide = NonceCounter::new(24);
        assert_eq!(wide.next_nonce().len(), 24);
        let mut expected = [0u8; 24];
        expected[0] = 1;
        assert_eq!(wide.next_nonce(), &expected[..]);
        // Carry chain + wrap: byte 0 carries into byte 1, and the top byte's
        // carry is dropped rather than panicking.
        let mut c = NonceCounter::new(2);
        for _ in 0..256 {
            let _ = c.next_nonce();
        }
        assert_eq!(c.next_nonce(), &[0x00, 0x01]); // 256 as u16 LE
        let mut c = NonceCounter::new(1);
        for _ in 0..256 {
            let _ = c.next_nonce();
        }
        assert_eq!(c.next_nonce(), &[0x00]); // 256 truncated to one byte
    }
}
