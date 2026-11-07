//! Shadowsocks cipher capability per proxy core — protocol-level facts used by
//! the per-protocol injector to refuse a cipher the target core cannot build.
//!
//! The core *choice* (`resolve_core`) moved to `leas-oracles` with the
//! `CoreType` enum; these lists stay here because the injector validates
//! against them at config-build time.

/// Shadowsocks ciphers xray-core accepts, case-insensitive.
///
/// The AEAD set from `CipherType` (proxy/shadowsocks/config.proto) plus the
/// `aead_*` and `chacha20-poly1305` name aliases of `cipherFromString`
/// (infra/conf/shadowsocks.go), plus the 2022-blake3 family
/// (`shadowaead_2022.List`).
pub const XRAY_SS_METHODS: &[&str] = &[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "aead_aes_128_gcm",
    "aead_aes_256_gcm",
    "aead_chacha20_poly1305",
    "aead_xchacha20_poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

/// Shadowsocks methods sing-box accepts (docs/configuration/outbound/
/// shadowsocks.md — modern + legacy).
pub const SINGBOX_SS_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
];

/// True when xray-core can build a shadowsocks outbound for `method`.
#[must_use]
pub fn xray_supports_ss_method(method: &str) -> bool {
    XRAY_SS_METHODS
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
}

/// True when sing-box can build a shadowsocks outbound for `method`.
#[must_use]
pub fn singbox_supports_ss_method(method: &str) -> bool {
    SINGBOX_SS_METHODS
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
}

/// True when at least one core can build a shadowsocks outbound for `method`.
#[must_use]
pub fn ss_method_supported(method: &str) -> bool {
    xray_supports_ss_method(method) || singbox_supports_ss_method(method)
}
