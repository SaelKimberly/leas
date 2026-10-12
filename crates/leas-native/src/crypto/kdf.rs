//! HKDF / SHA helpers shared by protocol crypto.
//!
//! Consumers: `protocol/vmess` (`VMess` KDF64/KDF16), `security/reality` (auth
//! key derivation: HKDF-SHA256 with salt = ClientHello.Random[0..20], info
//! `b"REALITY"`), future HPKE (Reality target crypto).
//! Reference: `thirdparty/v2ray-core/proxy/vmess/encoding/aead/kdf.go`,
//! `thirdparty/Xray-core/transport/internet/reality` (spec only).
//!
//! Shadowsocks consumers: classic AEAD derives its per-salt stream subkey with
//! `HKDF-SHA1(psk, salt, b"ss-subkey")` (xray `config.go::hkdfSHA1`, mihomo
//! `shadowaead/cipher.go::hkdfSHA1`), and the classic password→key step is
//! OpenSSL's `EVP_BytesToKey` with MD5 (xray `passwordToCipherKey`).
//! 2022-blake3 derives session subkeys with BLAKE3's key-derivation mode
//! (2022 edition spec §2.2) — an ASCII context, so the `blake3` crate is used
//! directly (unlike VLESS's binary-context derive-key in
//! `protocol/vless/encryption/b3.rs`).
//!
//! Backends: REALITY auth-key derivation uses ring (workspace standard); the
//! Shadowsocks helpers above use `RustCrypto` `hkdf`/`sha1`, `md-5`, and the
//! `blake3` crate.

use hkdf::Hkdf;
use sha1::Sha1;
use zeroize::Zeroizing;

/// `HKDF-SHA1(psk, salt, info)` → `out` (classic Shadowsocks AEAD subkey).
pub fn hkdf_sha1(psk: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha1>::new(Some(salt), psk)
        .expand(info, out)
        .expect("HKDF-SHA1 output length is bounded by callers (< 255*20)");
}

/// The 2022 session-subkey context (2022 edition spec §2.2) — the ONE owner
/// of this string; `protocol/ss/method.rs` imports it.
pub(crate) const SS2022_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// `blake3::derive_key(context, material)` — the 2022 session-subkey KDF.
#[must_use]
pub fn blake3_derive_key(context: &str, material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, material)
}

/// OpenSSL `EVP_BytesToKey` (MD5, no salt, count 1): `d_i = MD5(d_{i-1} || password)`,
/// `d_0 = MD5(password)`; the key is the concatenation truncated to `key_len`.
///
/// Shadowsocks applies this to the password **unconditionally** — a 32-char
/// password for aes-256-gcm is still KDF'd (xray `passwordToCipherKey`,
/// mihomo `PickCipher`'s `Kdf(password, …)`, ss-rust `make_derived_key`).
#[must_use]
pub fn evp_bytes_to_key_md5(password: &[u8], key_len: usize) -> Zeroizing<Vec<u8>> {
    use md5::{Digest as _, Md5};
    let mut key = Zeroizing::new(Vec::with_capacity(key_len + 16));
    let mut prev: Option<Zeroizing<[u8; 16]>> = None;
    while key.len() < key_len {
        let mut hasher = Md5::new();
        if let Some(prev) = &prev {
            hasher.update(prev.as_slice());
        }
        hasher.update(password);
        let digest = Zeroizing::new(<[u8; 16]>::from(hasher.finalize()));
        key.extend_from_slice(digest.as_slice());
        prev = Some(digest);
    }
    key.truncate(key_len);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HKDF-SHA1 pinned to vectors computed with an INDEPENDENT
    /// implementation (Python `hmac`/`hashlib`, HMAC-SHA1 extract/expand per
    /// RFC 5869) — not with the crate under test. First case: IKM = 0x0b×22,
    /// salt = 0x00..0x0c, info = 0xf0..0xf9, L = 42.
    #[test]
    fn hkdf_sha1_matches_independent_vectors() {
        let ikm = [0x0b_u8; 22];
        let salt: Vec<u8> = (0..13u8).collect();
        let info: Vec<u8> = (0xf0..0xfa).collect();
        let mut okm = [0u8; 42];
        hkdf_sha1(&ikm, &salt, &info, &mut okm);
        assert_eq!(
            okm,
            [
                0xd6, 0x00, 0x0f, 0xfb, 0x5b, 0x50, 0xbd, 0x39, 0x70, 0xb2, 0x60, 0x01, 0x77, 0x98,
                0xfb, 0x9c, 0x8d, 0xf9, 0xce, 0x2e, 0x2c, 0x16, 0xb6, 0xcd, 0x70, 0x9c, 0xca, 0x07,
                0xdc, 0x3c, 0xf9, 0xcf, 0x26, 0xd6, 0xc6, 0xd7, 0x50, 0xd0, 0xaa, 0xf5, 0xac, 0x94,
            ]
        );
    }

    /// The exact classic-SS call: subkey = HKDF-SHA1(psk, salt, "ss-subkey").
    #[test]
    fn ss_subkey_matches_independent_vector() {
        let mut out = [0u8; 16];
        hkdf_sha1(b"password", &[0x11_u8; 16], b"ss-subkey", &mut out);
        assert_eq!(
            out,
            [
                0x8e, 0x2b, 0x1a, 0x61, 0x11, 0x23, 0x92, 0x29, 0x40, 0x0b, 0x5d, 0xd6, 0x12, 0x77,
                0x19, 0x31,
            ]
        );
    }

    /// The 2022 helper must delegate to the crate with the spec's ASCII
    /// context. (The derive-key primitive's independence is pinned in
    /// `protocol/vless/encryption/b3.rs`; the caller's `key ‖ salt` material
    /// order is pinned in `protocol/ss/method.rs`'s tests, against that same
    /// hand-rolled implementation.)
    #[test]
    fn blake3_helper_uses_the_spec_context() {
        assert_eq!(SS2022_SUBKEY_CONTEXT, "shadowsocks 2022 session subkey");
        let key = [0x22_u8; 32];
        let salt = [0x33_u8; 32];
        let material = [key.as_slice(), salt.as_slice()].concat();
        assert_eq!(
            blake3_derive_key(SS2022_SUBKEY_CONTEXT, &material),
            blake3::derive_key("shadowsocks 2022 session subkey", &material)
        );
        assert_ne!(
            blake3_derive_key(SS2022_SUBKEY_CONTEXT, &material),
            blake3_derive_key(SS2022_SUBKEY_CONTEXT, &{
                let mut swapped = salt.to_vec();
                swapped.extend_from_slice(&key);
                swapped
            }),
            "the underlying KDF is order-sensitive (the caller's `key ‖ salt` \
             concatenation is pinned in protocol/ss/method.rs's tests against \
             the hand-rolled BLAKE3)"
        );
    }

    /// Classic password → key: MD5 `EVP_BytesToKey`, ALWAYS (xray
    /// `passwordToCipherKey` — no raw-password shortcut). Second block =
    /// MD5(digest ‖ password).
    #[test]
    fn evp_bytes_to_key_md5_vectors() {
        assert_eq!(
            &*evp_bytes_to_key_md5(b"password", 16),
            &[
                0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6, 0x1d, 0x83, 0x27, 0xde, 0xb8, 0x82,
                0xcf, 0x99,
            ]
        );
        assert_eq!(
            &*evp_bytes_to_key_md5(b"password", 32),
            &[
                0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6, 0x1d, 0x83, 0x27, 0xde, 0xb8, 0x82,
                0xcf, 0x99, 0x2b, 0x95, 0x99, 0x0a, 0x91, 0x51, 0x37, 0x4a, 0xbd, 0x8f, 0xf8, 0xc5,
                0xa7, 0xa0, 0xfe, 0x08,
            ]
        );
        // 24 (aes-192-gcm) is the only non-multiple-of-16 key length in the
        // classic cipher table — the only case exercising the final truncate.
        assert_eq!(
            &*evp_bytes_to_key_md5(b"password", 24),
            &[
                0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6, 0x1d, 0x83, 0x27, 0xde, 0xb8, 0x82,
                0xcf, 0x99, 0x2b, 0x95, 0x99, 0x0a, 0x91, 0x51, 0x37, 0x4a,
            ]
        );
    }
}
