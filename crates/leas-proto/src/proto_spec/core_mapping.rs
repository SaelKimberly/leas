//! Core resolution for protocol kinds — canonical logic.
//!
//! The core crate's `protocol_core_mapping.rs` adapter shim (which converted
//! core's `Protocol`/`CoreType` types) was deleted in T23; `leas-core`
//! now re-exports this module verbatim.

use crate::proto_spec::{CoreType, ProtocolKind};

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

/// Protocol kinds that only sing-box implements.
///
/// The canonical sing-box-only set (the core crate's `SINGBOX_ONLY_PROTOCOLS`
/// was deleted with the legacy `Protocol` enum in T23; consumers use this
/// list over [`ProtocolKind`]).
pub const SINGBOX_ONLY_KINDS: &[ProtocolKind] = &[
    ProtocolKind::Tuic,
    ProtocolKind::Hysteria,
    ProtocolKind::Naive,
    ProtocolKind::AnyTls,
    ProtocolKind::ShadowTls,
    ProtocolKind::Tor,
    ProtocolKind::Ssh,
    ProtocolKind::Tailscale,
    ProtocolKind::ShadowsocksR,
    ProtocolKind::Redirect,
    ProtocolKind::TProxy,
    ProtocolKind::Mixed,
];

/// Resolves which core a given protocol kind should use.
///
/// - `None` → auto-detect from the protocol
/// - `Some(core_type)` → forced override (user chose explicitly)
///
/// Shadowsocks core depends on the cipher: xray-core supports only AEAD +
/// 2022-blake3, so legacy ciphers (cfb/ctr/rc4-md5/none/...) route to
/// sing-box, which implements the full legacy set. `ss_method` is the
/// profile's method string for Shadowsocks/Shadowsocks2022 (other protocols
/// ignore it). A forced override always wins — the config builder then
/// validates the cipher against that core.
#[must_use]
pub fn resolve_core(
    kind: ProtocolKind,
    profile_override: Option<CoreType>,
    ss_method: Option<&str>,
) -> CoreType {
    profile_override.unwrap_or_else(|| core_for_protocol(kind, ss_method))
}

fn core_for_protocol(kind: ProtocolKind, ss_method: Option<&str>) -> CoreType {
    if matches!(
        kind,
        ProtocolKind::Shadowsocks | ProtocolKind::Shadowsocks2022
    ) {
        return match ss_method {
            Some(method) if xray_supports_ss_method(method) => CoreType::Xray,
            // Legacy/unknown ciphers: sing-box covers the legacy set; the
            // builder rejects what neither core can build.
            Some(_) => CoreType::SingBox,
            // Method unknown: keep the historical default; the config
            // builder validates before any core is launched.
            None => CoreType::Xray,
        };
    }
    if SINGBOX_ONLY_KINDS.contains(&kind) {
        CoreType::SingBox
    } else {
        CoreType::Xray
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::tuic(ProtocolKind::Tuic, CoreType::SingBox)]
    #[case::hysteria(ProtocolKind::Hysteria, CoreType::SingBox)]
    #[case::naive(ProtocolKind::Naive, CoreType::SingBox)]
    #[case::anytls(ProtocolKind::AnyTls, CoreType::SingBox)]
    #[case::shadowtls(ProtocolKind::ShadowTls, CoreType::SingBox)]
    #[case::tor(ProtocolKind::Tor, CoreType::SingBox)]
    #[case::ssh(ProtocolKind::Ssh, CoreType::SingBox)]
    #[case::tailscale(ProtocolKind::Tailscale, CoreType::SingBox)]
    #[case::shadowsocksr(ProtocolKind::ShadowsocksR, CoreType::SingBox)]
    #[case::redirect(ProtocolKind::Redirect, CoreType::SingBox)]
    #[case::tproxy(ProtocolKind::TProxy, CoreType::SingBox)]
    #[case::mixed(ProtocolKind::Mixed, CoreType::SingBox)]
    #[case::vmess(ProtocolKind::Vmess, CoreType::Xray)]
    #[case::vless(ProtocolKind::Vless, CoreType::Xray)]
    #[case::socks(ProtocolKind::Socks, CoreType::Xray)]
    #[case::http(ProtocolKind::Http, CoreType::Xray)]
    #[case::trojan(ProtocolKind::Trojan, CoreType::Xray)]
    #[case::wireguard(ProtocolKind::WireGuard, CoreType::Xray)]
    #[case::hysteria2(ProtocolKind::Hysteria2, CoreType::Xray)]
    #[case::dokodemodoor(ProtocolKind::DokodemoDoor, CoreType::Xray)]
    #[case::freedom(ProtocolKind::Freedom, CoreType::Xray)]
    #[case::blackhole(ProtocolKind::Blackhole, CoreType::Xray)]
    #[case::dns(ProtocolKind::Dns, CoreType::Xray)]
    #[case::loopback(ProtocolKind::Loopback, CoreType::Xray)]
    #[case::custom(ProtocolKind::Custom, CoreType::Xray)]
    fn kind_resolves_to_expected_core(#[case] kind: ProtocolKind, #[case] expected: CoreType) {
        assert_eq!(
            resolve_core(kind, None, None),
            expected,
            "{kind:?} should resolve to {expected:?}"
        );
    }

    #[rstest]
    #[case::aead_aes_128_gcm("aes-128-gcm", CoreType::Xray)]
    #[case::aead_aes_256_gcm("aes-256-gcm", CoreType::Xray)]
    #[case::aead_chacha20_poly1305("chacha20-poly1305", CoreType::Xray)]
    #[case::aead_chacha20_ietf_poly1305("chacha20-ietf-poly1305", CoreType::Xray)]
    #[case::aead_xchacha20_poly1305("xchacha20-poly1305", CoreType::Xray)]
    #[case::aead_xchacha20_ietf_poly1305("xchacha20-ietf-poly1305", CoreType::Xray)]
    // case-insensitive, like xray's cipherFromString
    #[case::aead_uppercase("AES-256-GCM", CoreType::Xray)]
    #[case::aead_2022_blake3_aes_128_gcm("2022-blake3-aes-128-gcm", CoreType::Xray)]
    #[case::aead_2022_blake3_aes_256_gcm("2022-blake3-aes-256-gcm", CoreType::Xray)]
    #[case::aead_2022_blake3_chacha20_poly1305("2022-blake3-chacha20-poly1305", CoreType::Xray)]
    // xray-core's CipherType enum has no CFB/CTR/rc4/none — sing-box does.
    #[case::legacy_aes_128_cfb("aes-128-cfb", CoreType::SingBox)]
    #[case::legacy_aes_192_cfb("aes-192-cfb", CoreType::SingBox)]
    #[case::legacy_aes_256_cfb("aes-256-cfb", CoreType::SingBox)]
    #[case::legacy_aes_128_ctr("aes-128-ctr", CoreType::SingBox)]
    #[case::legacy_aes_192_ctr("aes-192-ctr", CoreType::SingBox)]
    #[case::legacy_aes_256_ctr("aes-256-ctr", CoreType::SingBox)]
    #[case::legacy_rc4_md5("rc4-md5", CoreType::SingBox)]
    #[case::legacy_chacha20_ietf("chacha20-ietf", CoreType::SingBox)]
    #[case::legacy_xchacha20("xchacha20", CoreType::SingBox)]
    #[case::legacy_none("none", CoreType::SingBox)]
    fn shadowsocks_cipher_resolves_to_expected_core(
        #[case] method: &str,
        #[case] expected: CoreType,
    ) {
        assert_eq!(
            resolve_core(ProtocolKind::Shadowsocks, None, Some(method)),
            expected,
            "method {method} should resolve to {expected:?}"
        );
    }

    #[test]
    fn shadowsocks_unknown_cipher_resolves_to_singbox() {
        // Unsupported everywhere: sing-box chosen so the builder's clearer
        // error ("not supported by sing-box") surfaces, never a core crash.
        assert_eq!(
            resolve_core(ProtocolKind::Shadowsocks, None, Some("salsa20")),
            CoreType::SingBox,
        );
    }

    #[test]
    fn shadowsocks_2022_method_resolves_to_xray() {
        assert_eq!(
            resolve_core(
                ProtocolKind::Shadowsocks2022,
                None,
                Some("2022-blake3-aes-128-gcm")
            ),
            CoreType::Xray,
        );
    }

    #[test]
    fn shadowsocks_without_method_keeps_xray_default() {
        assert_eq!(
            resolve_core(ProtocolKind::Shadowsocks, None, None),
            CoreType::Xray,
        );
    }

    #[test]
    fn forced_override_wins_over_cipher_routing() {
        // Explicit user choice beats auto-routing; the builder then validates
        // the cipher against that core and errors clearly.
        assert_eq!(
            resolve_core(
                ProtocolKind::Shadowsocks,
                Some(CoreType::Xray),
                Some("aes-256-cfb")
            ),
            CoreType::Xray,
        );
        assert_eq!(
            resolve_core(
                ProtocolKind::Shadowsocks,
                Some(CoreType::SingBox),
                Some("aes-256-gcm")
            ),
            CoreType::SingBox,
        );
    }

    #[test]
    fn xray_supports_only_aead_and_2022() {
        assert!(xray_supports_ss_method("aes-256-gcm"));
        assert!(xray_supports_ss_method("aead_aes_128_gcm"));
        assert!(xray_supports_ss_method("2022-blake3-chacha20-poly1305"));
        assert!(!xray_supports_ss_method("aes-256-cfb"));
        assert!(!xray_supports_ss_method("none"));
        assert!(!xray_supports_ss_method("salsa20"));
    }

    #[test]
    fn singbox_supports_modern_and_legacy() {
        assert!(singbox_supports_ss_method("aes-256-cfb"));
        assert!(singbox_supports_ss_method("none"));
        assert!(singbox_supports_ss_method("aes-192-gcm"));
        assert!(singbox_supports_ss_method("2022-blake3-aes-256-gcm"));
        assert!(!singbox_supports_ss_method("salsa20"));
        assert!(!singbox_supports_ss_method("chacha20")); // bare, non-ietf
    }

    #[test]
    fn override_forced_wins() {
        for kind in [ProtocolKind::Vmess, ProtocolKind::Tuic] {
            assert_eq!(
                resolve_core(kind, Some(CoreType::Xray), None),
                CoreType::Xray,
                "forced Xray should win for {kind:?}"
            );
            assert_eq!(
                resolve_core(kind, Some(CoreType::SingBox), None),
                CoreType::SingBox,
                "forced SingBox should win for {kind:?}"
            );
        }
    }
}
