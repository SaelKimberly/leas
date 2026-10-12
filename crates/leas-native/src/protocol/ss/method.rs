//! Shadowsocks method table + key derivation.
//!
//! Native covers the AEAD set (2017 edition) and the 2022-blake3 family; the
//! legacy stream ciphers (`aes-*-cfb/ctr`, `rc4-md5`, `chacha20-ietf`,
//! `xchacha20`, `none`) stay on sing-box and are deliberately absent here.

use base64::Engine as _;
use leas_proto::proto_spec::ProtocolKind;
use zeroize::Zeroizing;

use crate::crypto::aead::SsAead;
use crate::crypto::kdf::{
    SS2022_SUBKEY_CONTEXT, blake3_derive_key, evp_bytes_to_key_md5, hkdf_sha1,
};
use crate::error::NativeError;

/// The KDF family a method belongs to — it selects the subkey derivation and
/// the wire codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsFamily {
    /// 2017 AEAD: HKDF-SHA1 subkey, `[salt][2B len][tag][ct][tag]` chunks.
    Classic,
    /// 2022-blake3: BLAKE3 subkey, standalone header chunks, `[salt][header]…`.
    Blake3_2022,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsMethod {
    pub aead: SsAead,
    pub family: SsFamily,
}

impl SsMethod {
    /// Resolve a method string (case-insensitive), aliases included.
    #[must_use]
    pub fn from_method(method: &str) -> Option<Self> {
        let method = method.trim().to_ascii_lowercase();
        let (aead, family) = match method.as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => (SsAead::Aes128Gcm, SsFamily::Classic),
            "aes-192-gcm" | "aead_aes_192_gcm" => (SsAead::Aes192Gcm, SsFamily::Classic),
            "aes-256-gcm" | "aead_aes_256_gcm" => (SsAead::Aes256Gcm, SsFamily::Classic),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" => {
                (SsAead::ChaCha20Poly1305, SsFamily::Classic)
            }
            "xchacha20-poly1305" | "xchacha20-ietf-poly1305" | "aead_xchacha20_poly1305" => {
                (SsAead::XChaCha20Poly1305, SsFamily::Classic)
            }
            "2022-blake3-aes-128-gcm" => (SsAead::Aes128Gcm, SsFamily::Blake3_2022),
            "2022-blake3-aes-256-gcm" => (SsAead::Aes256Gcm, SsFamily::Blake3_2022),
            "2022-blake3-chacha20-poly1305" => (SsAead::ChaCha20Poly1305, SsFamily::Blake3_2022),
            _ => return None,
        };
        Some(Self { aead, family })
    }

    #[must_use]
    pub const fn key_len(self) -> usize {
        self.aead.key_len()
    }

    #[must_use]
    pub const fn kind(self) -> ProtocolKind {
        match self.family {
            SsFamily::Classic => ProtocolKind::Shadowsocks,
            SsFamily::Blake3_2022 => ProtocolKind::Shadowsocks2022,
        }
    }
}

/// Per-stream/-session subkey.
///
/// Classic: `HKDF-SHA1(key, salt, "ss-subkey")`, output = `key_len`.
/// 2022: `blake3::derive_key("shadowsocks 2022 session subkey", key ‖ salt)`.
#[must_use]
pub fn stream_subkey(method: SsMethod, key: &[u8], salt: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; method.key_len()]);
    stream_subkey_into(method, key, salt, &mut out);
    out
}

/// [`stream_subkey`] into a caller-owned buffer of `method.key_len()` bytes —
/// the UDP datagram path derives a fresh subkey for EVERY classic packet and
/// must not allocate on that hot path.
///
/// The one owner of both derivations: [`stream_subkey`] is this function plus
/// the buffer.
pub(crate) fn stream_subkey_into(method: SsMethod, key: &[u8], salt: &[u8], out: &mut [u8]) {
    assert_eq!(
        out.len(),
        method.key_len(),
        "the subkey buffer must hold key_len bytes"
    );
    match method.family {
        SsFamily::Classic => hkdf_sha1(key, salt, b"ss-subkey", out),
        SsFamily::Blake3_2022 => {
            let mut material = Zeroizing::new(Vec::with_capacity(key.len() + salt.len()));
            material.extend_from_slice(key);
            material.extend_from_slice(salt);
            let sub = Zeroizing::new(blake3_derive_key(SS2022_SUBKEY_CONTEXT, &material));
            // BLAKE3's XOF is prefix-consistent, so the first `key_len` bytes of
            // the 32-byte root are the session subkey for the 16-byte methods
            // too (`Blake3Key` fills `cipher.algorithm().key_len()` bytes).
            out.copy_from_slice(&sub[..method.key_len()]);
        }
    }
}

/// Master key from the profile's password.
///
/// Classic: OpenSSL `EVP_BytesToKey` (MD5) — unconditional.
/// 2022: the password IS a base64 PSK; wrong length is a config error.
pub fn password_key(method: SsMethod, password: &str) -> Result<Zeroizing<Vec<u8>>, NativeError> {
    match method.family {
        SsFamily::Classic => Ok(evp_bytes_to_key_md5(password.as_bytes(), method.key_len())),
        SsFamily::Blake3_2022 => {
            // `Zeroizing` BEFORE the length check: a wrong-length PSK is
            // still real key material and must not be dropped unwiped.
            let decoded = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(password.trim())
                    .map_err(|e| {
                        NativeError::Config(format!("shadowsocks-2022 password is not base64: {e}"))
                    })?,
            );
            if decoded.len() != method.key_len() {
                return Err(NativeError::Config(format!(
                    "shadowsocks-2022 key is {} bytes, method needs {}",
                    decoded.len(),
                    method.key_len()
                )));
            }
            Ok(decoded)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::SsAead;

    #[test]
    fn method_table_covers_the_native_set_including_aliases() {
        let cases: &[(&str, SsAead, SsFamily)] = &[
            ("aes-128-gcm", SsAead::Aes128Gcm, SsFamily::Classic),
            ("aead_aes_128_gcm", SsAead::Aes128Gcm, SsFamily::Classic),
            ("aes-192-gcm", SsAead::Aes192Gcm, SsFamily::Classic),
            ("aead_aes_192_gcm", SsAead::Aes192Gcm, SsFamily::Classic),
            ("aes-256-gcm", SsAead::Aes256Gcm, SsFamily::Classic),
            ("aead_aes_256_gcm", SsAead::Aes256Gcm, SsFamily::Classic),
            (
                "chacha20-ietf-poly1305",
                SsAead::ChaCha20Poly1305,
                SsFamily::Classic,
            ),
            (
                "chacha20-poly1305",
                SsAead::ChaCha20Poly1305,
                SsFamily::Classic,
            ),
            (
                "aead_chacha20_poly1305",
                SsAead::ChaCha20Poly1305,
                SsFamily::Classic,
            ),
            (
                "xchacha20-ietf-poly1305",
                SsAead::XChaCha20Poly1305,
                SsFamily::Classic,
            ),
            (
                "xchacha20-poly1305",
                SsAead::XChaCha20Poly1305,
                SsFamily::Classic,
            ),
            (
                "aead_xchacha20_poly1305",
                SsAead::XChaCha20Poly1305,
                SsFamily::Classic,
            ),
            (
                "2022-blake3-aes-128-gcm",
                SsAead::Aes128Gcm,
                SsFamily::Blake3_2022,
            ),
            (
                "2022-blake3-aes-256-gcm",
                SsAead::Aes256Gcm,
                SsFamily::Blake3_2022,
            ),
            (
                "2022-blake3-chacha20-poly1305",
                SsAead::ChaCha20Poly1305,
                SsFamily::Blake3_2022,
            ),
        ];
        for (name, aead, family) in cases {
            let m = SsMethod::from_method(name).unwrap_or_else(|| panic!("{name} resolves"));
            assert_eq!(m.aead, *aead, "{name}");
            assert_eq!(m.family, *family, "{name}");
        }
        // Legacy stream ciphers and unknown names stay unresolved (defer to sing-box).
        for name in ["aes-256-cfb", "rc4-md5", "chacha20-ietf", "none", "bogus"] {
            assert!(SsMethod::from_method(name).is_none(), "{name}");
        }
    }

    #[test]
    fn method_names_are_case_insensitive() {
        assert!(SsMethod::from_method("AES-256-GCM").is_some());
    }

    #[test]
    fn classic_password_key_is_md5_evp_bytes_to_key() {
        let m = SsMethod::from_method("aes-128-gcm").unwrap();
        let key = password_key(m, "password").unwrap();
        assert_eq!(key.len(), 16);
        assert_eq!(
            &*key,
            &hex("5f4dcc3b5aa765d61d8327deb882cf99"),
            "MD5(password) is the first EVP_BytesToKey block"
        );
    }

    /// A 32-char password for aes-256-gcm is STILL KDF'd (no raw shortcut).
    #[test]
    fn classic_password_of_key_length_is_still_kdfed() {
        let m = SsMethod::from_method("aes-256-gcm").unwrap();
        let pwd = "0123456789abcdef0123456789abcdef";
        assert_eq!(password_key(m, pwd).unwrap().len(), 32);
        assert_ne!(&*password_key(m, pwd).unwrap(), pwd.as_bytes());
    }

    #[test]
    fn c2022_password_is_base64_psk_of_exact_key_length() {
        let m = SsMethod::from_method("2022-blake3-aes-128-gcm").unwrap();
        // 16 zero bytes, base64.
        let key = password_key(m, "AAAAAAAAAAAAAAAAAAAAAA==").unwrap();
        assert_eq!(&*key, &[0u8; 16]);
        assert!(matches!(
            password_key(m, "c2hvcnQ="),
            Err(NativeError::Config(_))
        ));
        assert!(matches!(
            password_key(m, "not base64!"),
            Err(NativeError::Config(_))
        ));
    }

    /// Classic KAT through the PUBLIC API: pins the `key`/`salt` argument
    /// positions (`hkdf_sha1(psk, salt, b"ss-subkey")`) — the primitive's own
    /// vector cannot catch a transposition at this call site.
    #[test]
    fn classic_subkey_is_hkdf_sha1_of_key_and_salt() {
        let m = SsMethod::from_method("aes-128-gcm").unwrap();
        assert_eq!(
            &*stream_subkey(m, b"password", &[0x11u8; 16]),
            &hex("8e2b1a6111239229400b5dd612771931")
        );
    }

    /// Classic subkey = HKDF-SHA1; 2022 subkey = blake3 `derive_key` over key ‖ salt.
    #[test]
    fn stream_subkeys_differ_per_family_and_track_the_salt() {
        let classic = SsMethod::from_method("aes-128-gcm").unwrap();
        let a = stream_subkey(classic, b"password", &[1u8; 16]);
        let b = stream_subkey(classic, b"password", &[2u8; 16]);
        assert_eq!(a.len(), 16);
        assert_ne!(&*a, &*b);

        let s2022 = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let key = [9u8; 32];
        let c = stream_subkey(s2022, &key, &[3u8; 32]);
        let d = stream_subkey(s2022, &key, &[4u8; 32]);
        assert_eq!(c.len(), 32);
        assert_ne!(&*c, &*d);
    }

    /// 2022 subkeys are the `key_len`-byte XOF prefix: 16 bytes for
    /// `2022-blake3-aes-128-gcm`, whose AEAD rejects a 32-byte key outright.
    #[test]
    fn c2022_subkey_is_key_len_even_for_the_128_bit_method() {
        let m = SsMethod::from_method("2022-blake3-aes-128-gcm").unwrap();
        let key = [0x11u8; 16];
        let salt = [0x22u8; 16];
        let sub = stream_subkey(m, &key, &salt);
        assert_eq!(sub.len(), 16);
        let material = [key.as_slice(), salt.as_slice()].concat();
        assert_eq!(
            &*sub,
            &crate::protocol::vless::encryption::derive_key_bytes(
                b"shadowsocks 2022 session subkey",
                &material
            )[..16]
        );
    }

    /// The `key ‖ salt` material order is pinned against the hand-rolled
    /// BLAKE3 (an implementation independent of the `blake3` crate the helper
    /// delegates to), reached through the test-only re-export
    /// `protocol::vless::encryption::derive_key_bytes` — production builds
    /// keep `b3` private and expose nothing new.
    #[test]
    fn blake3_subkey_material_order_is_key_then_salt() {
        let s2022 = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let key = [0x11u8; 32];
        let salt = [0x22u8; 32];
        let material = [key.as_slice(), salt.as_slice()].concat();
        assert_eq!(
            &*stream_subkey(s2022, &key, &salt),
            &crate::protocol::vless::encryption::derive_key_bytes(
                b"shadowsocks 2022 session subkey",
                &material
            )[..]
        );
        // …and the subkey advances with the salt (per-connection freshness).
        assert_ne!(
            &*stream_subkey(s2022, &key, &salt),
            &*stream_subkey(s2022, &key, &[0x23u8; 32])
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
