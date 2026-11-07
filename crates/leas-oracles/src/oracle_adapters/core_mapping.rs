//! Core resolution for protocol kinds — oracle-side policy.
//!
//! The protocol-level cipher capability lists stay in
//! [`leas_proto::proto_spec::ss_method_support`] because the per-protocol
//! injector validates against them; the *choice* of which core should dial a
//! kind lives here, with the oracle adapters.

pub use leas_proto::proto_spec::ss_method_support::{
    SINGBOX_SS_METHODS, XRAY_SS_METHODS, singbox_supports_ss_method, ss_method_supported,
    xray_supports_ss_method,
};

use leas_proto::proto_spec::ProtocolKind;

use crate::oracle_adapters::core_type::CoreType;

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
