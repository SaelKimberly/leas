//! Shadowsocks method table + key derivation.
//!
//! Native covers the AEAD set (2017 edition), the 2022-blake3 family, and the
//! legacy stream ciphers (`aes-*-cfb/ctr`, `rc4-md5`, `chacha20-ietf`,
//! `xchacha20`, `none`) — sing-box's outbound roster minus the AEAD entries.
//! The cipher is the single stored truth ([`SsCipher`]); [`SsFamily`] is
//! derived from it and only selects the codec.

use base64::Engine as _;
use leas_proto::proto_spec::ProtocolKind;
use zeroize::Zeroizing;

use crate::crypto::aead::SsAead;
use crate::crypto::kdf::{
    SS2022_SUBKEY_CONTEXT, blake3_derive_key, evp_bytes_to_key_md5, hkdf_sha1,
};
use crate::error::NativeError;

/// The KDF family a method belongs to — it selects the subkey derivation and
/// the wire codec. **Derived** from [`SsCipher`], never stored: one field can
/// not disagree with the primitive it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsFamily {
    /// 2017 AEAD: HKDF-SHA1 subkey, `[salt][2B len][tag][ct][tag]` chunks.
    Classic,
    /// 2022-blake3: BLAKE3 subkey, standalone header chunks, `[salt][header]…`.
    Blake3_2022,
    /// Legacy stream cipher: one keystream per direction behind an IV, no
    /// chunk framing and no subkey derivation (`stream_legacy`).
    Stream,
}

/// A legacy (pre-AEAD) Shadowsocks stream cipher.
///
/// Key and IV lengths are the cipher's own; the master key comes from the same
/// `EVP_BytesToKey` path the 2017 AEAD set uses, and `None` has neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCipher {
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    /// RC4 keyed by `MD5(master_key ‖ IV)` — a per-session key, not the master.
    Rc4Md5,
    Chacha20Ietf,
    XChacha20,
    None,
}

impl StreamCipher {
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Cfb | Self::Aes128Ctr | Self::Rc4Md5 => 16,
            Self::Aes192Cfb | Self::Aes192Ctr => 24,
            Self::Aes256Cfb | Self::Aes256Ctr | Self::Chacha20Ietf | Self::XChacha20 => 32,
            Self::None => 0,
        }
    }

    #[must_use]
    pub const fn iv_len(self) -> usize {
        match self {
            Self::Aes128Cfb
            | Self::Aes192Cfb
            | Self::Aes256Cfb
            | Self::Aes128Ctr
            | Self::Aes192Ctr
            | Self::Aes256Ctr
            | Self::Rc4Md5 => 16,
            Self::Chacha20Ietf => 12,
            Self::XChacha20 => 24,
            Self::None => 0,
        }
    }
}

/// The stored truth of a method: the primitive plus the codec it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsCipher {
    /// 2017 AEAD (HKDF-SHA1 subkey).
    Aead2017(SsAead),
    /// 2022-blake3 (BLAKE3 subkey, PSK password).
    Blake3_2022(SsAead),
    /// Legacy stream cipher.
    Stream(StreamCipher),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsMethod {
    pub cipher: SsCipher,
}

impl SsCipher {
    /// The codec/KDF family this cipher selects.
    #[must_use]
    pub const fn family(self) -> SsFamily {
        match self {
            Self::Aead2017(_) => SsFamily::Classic,
            Self::Blake3_2022(_) => SsFamily::Blake3_2022,
            Self::Stream(_) => SsFamily::Stream,
        }
    }

    /// The AEAD primitive, or `None` for a legacy stream cipher.
    #[must_use]
    pub const fn aead(self) -> Option<SsAead> {
        match self {
            Self::Aead2017(aead) | Self::Blake3_2022(aead) => Some(aead),
            Self::Stream(_) => None,
        }
    }

    /// The stream cipher, or `None` for an AEAD method.
    #[must_use]
    pub const fn stream(self) -> Option<StreamCipher> {
        match self {
            Self::Stream(stream) => Some(stream),
            Self::Aead2017(_) | Self::Blake3_2022(_) => None,
        }
    }

    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aead2017(aead) | Self::Blake3_2022(aead) => aead.key_len(),
            Self::Stream(stream) => stream.key_len(),
        }
    }

    #[must_use]
    pub const fn iv_len(self) -> usize {
        match self {
            Self::Stream(stream) => stream.iv_len(),
            // AEAD methods call their field a salt; the codec reads it there.
            Self::Aead2017(aead) | Self::Blake3_2022(aead) => aead.salt_len(),
        }
    }
}

impl SsMethod {
    /// Resolve a method string (case-insensitive), aliases included.
    #[must_use]
    pub fn from_method(method: &str) -> Option<Self> {
        let method = method.trim().to_ascii_lowercase();
        let cipher = match method.as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => SsCipher::Aead2017(SsAead::Aes128Gcm),
            "aes-192-gcm" | "aead_aes_192_gcm" => SsCipher::Aead2017(SsAead::Aes192Gcm),
            "aes-256-gcm" | "aead_aes_256_gcm" => SsCipher::Aead2017(SsAead::Aes256Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" => {
                SsCipher::Aead2017(SsAead::ChaCha20Poly1305)
            }
            "xchacha20-poly1305" | "xchacha20-ietf-poly1305" | "aead_xchacha20_poly1305" => {
                SsCipher::Aead2017(SsAead::XChaCha20Poly1305)
            }
            "2022-blake3-aes-128-gcm" => SsCipher::Blake3_2022(SsAead::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => SsCipher::Blake3_2022(SsAead::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => SsCipher::Blake3_2022(SsAead::ChaCha20Poly1305),
            // Legacy stream ciphers: sing-box's outbound roster, no aliases.
            "aes-128-cfb" => SsCipher::Stream(StreamCipher::Aes128Cfb),
            "aes-192-cfb" => SsCipher::Stream(StreamCipher::Aes192Cfb),
            "aes-256-cfb" => SsCipher::Stream(StreamCipher::Aes256Cfb),
            "aes-128-ctr" => SsCipher::Stream(StreamCipher::Aes128Ctr),
            "aes-192-ctr" => SsCipher::Stream(StreamCipher::Aes192Ctr),
            "aes-256-ctr" => SsCipher::Stream(StreamCipher::Aes256Ctr),
            "rc4-md5" => SsCipher::Stream(StreamCipher::Rc4Md5),
            "chacha20-ietf" => SsCipher::Stream(StreamCipher::Chacha20Ietf),
            "xchacha20" => SsCipher::Stream(StreamCipher::XChacha20),
            "none" => SsCipher::Stream(StreamCipher::None),
            _ => return None,
        };
        Some(Self { cipher })
    }

    #[must_use]
    pub const fn family(self) -> SsFamily {
        self.cipher.family()
    }

    #[must_use]
    pub const fn key_len(self) -> usize {
        self.cipher.key_len()
    }

    #[must_use]
    pub const fn iv_len(self) -> usize {
        self.cipher.iv_len()
    }

    /// The AEAD primitive.
    ///
    /// Panics for a legacy stream cipher. Every AEAD codec entry point
    /// (`stream::connect_to`, `stream2022::connect_to`, the UDP carrier)
    /// validates the family before it touches this accessor, so the panic is
    /// unreachable through any public path — use [`SsCipher::aead`] (the
    /// `Option` form) where the family is not already known.
    #[must_use]
    pub const fn aead(self) -> SsAead {
        match self.cipher.aead() {
            Some(aead) => aead,
            None => panic!("legacy stream ciphers have no AEAD primitive"),
        }
    }

    #[must_use]
    pub const fn stream(self) -> Option<StreamCipher> {
        self.cipher.stream()
    }

    #[must_use]
    pub const fn kind(self) -> ProtocolKind {
        match self.family() {
            SsFamily::Classic | SsFamily::Stream => ProtocolKind::Shadowsocks,
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
    match method.family() {
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
        // Legacy stream ciphers have no subkey derivation: the codec keeps one
        // keystream per direction behind the IV. Every AEAD codec entry point
        // rejects this family before it can reach here.
        SsFamily::Stream => panic!("legacy stream ciphers have no subkey derivation"),
    }
}

/// Master key from the profile's password.
///
/// Classic: OpenSSL `EVP_BytesToKey` (MD5) — unconditional.
/// 2022: the password IS a PSK; the shape rule is [`leas_proto::proto_spec::ss2022_key`]
/// (xray's `ParseKey`: standard base64, else the literal bytes), so a raw key
/// xray serves is not refused here.
pub fn password_key(method: SsMethod, password: &str) -> Result<Zeroizing<Vec<u8>>, NativeError> {
    match method.family() {
        // Legacy stream ciphers use the same `EVP_BytesToKey` key as the 2017
        // AEAD set, at their own key length; `none` has a zero-length key.
        SsFamily::Classic | SsFamily::Stream => {
            Ok(evp_bytes_to_key_md5(password.as_bytes(), method.key_len()))
        }
        SsFamily::Blake3_2022 => {
            use leas_proto::proto_spec::Ss2022Key;
            let key_len = method.key_len();
            let Some(shape) = leas_proto::proto_spec::ss2022_key(password, key_len) else {
                return Err(NativeError::Config(format!(
                    "shadowsocks-2022 key is neither base64 nor {key_len} raw bytes"
                )));
            };
            match shape {
                Ss2022Key::Raw(raw) => Ok(Zeroizing::new(raw.as_bytes().to_vec())),
                // `Zeroizing` BEFORE the length check: a wrong-length PSK is
                // still real key material and must not be dropped unwiped.
                Ss2022Key::Base64(text) => Ok(Zeroizing::new(
                    base64::engine::general_purpose::STANDARD
                        .decode(text)
                        .map_err(|e| {
                            NativeError::Config(format!(
                                "shadowsocks-2022 password is not base64: {e}"
                            ))
                        })?,
                )),
            }
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
            assert_eq!(m.aead(), *aead, "{name}");
            assert_eq!(m.family(), *family, "{name}");
        }
        // Unknown names stay unresolved (defer to the subprocess).
        assert!(SsMethod::from_method("bogus").is_none());
    }

    /// The legacy stream set is sing-box's outbound roster; `none` is the
    /// zero-key, zero-IV passthrough.
    #[test]
    fn stream_table_covers_the_legacy_set_with_its_key_and_iv_lengths() {
        let cases: &[(&str, StreamCipher, usize, usize)] = &[
            ("aes-128-cfb", StreamCipher::Aes128Cfb, 16, 16),
            ("aes-192-cfb", StreamCipher::Aes192Cfb, 24, 16),
            ("aes-256-cfb", StreamCipher::Aes256Cfb, 32, 16),
            ("aes-128-ctr", StreamCipher::Aes128Ctr, 16, 16),
            ("aes-192-ctr", StreamCipher::Aes192Ctr, 24, 16),
            ("aes-256-ctr", StreamCipher::Aes256Ctr, 32, 16),
            ("rc4-md5", StreamCipher::Rc4Md5, 16, 16),
            ("chacha20-ietf", StreamCipher::Chacha20Ietf, 32, 12),
            ("xchacha20", StreamCipher::XChacha20, 32, 24),
            ("none", StreamCipher::None, 0, 0),
            // case-insensitive, like every other consumer of the method string
            ("AES-256-CFB", StreamCipher::Aes256Cfb, 32, 16),
        ];
        for (name, stream, key_len, iv_len) in cases {
            let m = SsMethod::from_method(name).unwrap_or_else(|| panic!("{name} resolves"));
            assert_eq!(m.stream(), Some(*stream), "{name}");
            assert_eq!(m.family(), SsFamily::Stream, "{name}");
            assert_eq!(m.kind(), ProtocolKind::Shadowsocks, "{name}");
            assert_eq!(m.key_len(), *key_len, "{name}");
            assert_eq!(m.iv_len(), *iv_len, "{name}");
        }
    }

    /// `none` has no key at all; every other stream cipher runs the 2017
    /// `EVP_BytesToKey` KDF at its own length.
    #[test]
    fn stream_password_keys_are_evp_bytes_to_key_at_the_cipher_length() {
        for (name, len) in [
            ("aes-128-cfb", 16),
            ("aes-192-cfb", 24),
            ("aes-256-ctr", 32),
            ("rc4-md5", 16),
            ("chacha20-ietf", 32),
        ] {
            let m = SsMethod::from_method(name).unwrap();
            assert_eq!(password_key(m, "password").unwrap().len(), len, "{name}");
        }
        let none = SsMethod::from_method("none").unwrap();
        assert!(password_key(none, "password").unwrap().is_empty());
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
        // xray's `ParseKey` falls back to the LITERAL bytes when base64 fails,
        // so a raw 16-byte key is served instead of refused.
        assert_eq!(
            &*password_key(m, "r@w-key-01234567").unwrap(),
            b"r@w-key-01234567"
        );
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
