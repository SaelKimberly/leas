//! E2E: native Shadowsocks matrix — classic AEAD (`aes-128-gcm`,
//! `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`) and 2022-blake3
//! (`2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`,
//! `2022-blake3-chacha20-poly1305`) against both cores, plus a TLS row and
//! four UDP relay rows.
//!
//! `SsConfig` has no transport field, so every SS row is a plain TCP dial
//! (+ the optional TLS `security` layer the chain applies); there is no
//! ws/grpc SS row to write. The server configs differ per dialect: xray takes
//! `settings.method/password` and widens `network` to `tcp,udp` for the UDP
//! rows, sing-box a top-level `method`/`password` and serves both networks by
//! default.
//!
//! `clippy::future_not_send` is allowed file-wide (rstest, see `vmess.rs`).
#![allow(clippy::future_not_send)]
#![cfg(feature = "native-e2e")]

mod common;

use common::{certs, cores, echo, fp, no_tls, pick, tls_echo};
use leas_native::PacketMode;
use leas_native::e2e::AppKind;
use leas_native::e2e::{
    CaseSpec, Certs, CoreKind, CoreUnderTest, E2eCase, EchoServer, TlsEchoServer, run_against,
};
use rstest::rstest;

/// A genuinely plain SS row (`NoTls`): server `streamSettings` without
/// `tlsSettings` / no `tls` object, client params without `security`.
fn ss(method: &'static str) -> CaseSpec {
    CaseSpec::shadowsocks(method).with_tls(no_tls())
}

#[rstest]
#[case::aead_aes128(ss("aes-128-gcm"))]
#[case::aead_chacha20(ss("chacha20-ietf-poly1305"))]
#[case::aead_xchacha20(ss("xchacha20-ietf-poly1305"))]
#[case::ss2022_aes256(ss("2022-blake3-aes-256-gcm"))]
// 2022 with the 16-byte key length: the 2022 subkey is a BLAKE3 XOF truncated
// to the method's `key_len`, so this row is the wire proof of the truncation
// rule the aes-256/chacha20 rows cannot give (both are 32-byte methods).
#[case::ss2022_aes128(ss("2022-blake3-aes-128-gcm"))]
#[case::ss2022_chacha20(ss("2022-blake3-chacha20-poly1305"))]
// TLS row: cert TLS through the engine with the chrome fingerprint. XRAY-ONLY:
// sing-box 1.13.16's shadowsocks inbound has no `tls` field at all
// (`FATAL[0000] decode config: inbounds[0].tls: json: unknown field "tls"` —
// `option/shadowsocks.go` embeds only `ListenOptions`, which carries no TLS
// container), so there is no sing-box server config to dial. xray serves the
// layer through the ordinary `streamSettings`.
#[case::aead_tls_chrome(ss("aes-128-gcm").with_tls(fp("chrome")).with_single_core(CoreKind::Xray))]
// SS UDP relay: the client sends datagrams to the server's own UDP port (the
// dial IS a UDP socket, see `ss::udp::connect_udp`), so the row carries
// `PacketMode::Raw` and no security layer. xray needs `network: "tcp,udp"`;
// sing-box serves both by default.
#[case::udp_aead(ss("aes-128-gcm").with_app(AppKind::Udp).with_udp(PacketMode::Raw))]
#[case::udp_2022(ss("2022-blake3-aes-256-gcm").with_app(AppKind::Udp).with_udp(PacketMode::Raw))]
// The 16-byte 2022 key length on the UDP carrier too: its session subkey is
// the same BLAKE3 XOF truncation (`udp_session_subkey`), so both key lengths
// are proven on both carriers.
#[case::udp_2022_aes128(
    ss("2022-blake3-aes-128-gcm").with_app(AppKind::Udp).with_udp(PacketMode::Raw)
)]
// The 2022 `ChaCha` datagram shape: XChaCha20-Poly1305 with the 24-byte random
// nonce and the session/packet ids merged into the main header. The only 2022
// datagram row whose cipher and id header differ from the AES rows.
#[case::udp_2022_chacha20(
    ss("2022-blake3-chacha20-poly1305").with_app(AppKind::Udp).with_udp(PacketMode::Raw)
)]
#[tokio::test]
async fn shadowsocks_against_cores(
    #[case] case: CaseSpec,
    #[values(CoreKind::Xray, CoreKind::SingBox)] core: CoreKind,
    cores: &(CoreUnderTest, CoreUnderTest),
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    // Single-cored rows (the SS TLS row) are gated by `with_single_core`; the
    // excluded combination is reported, never silently counted as green.
    if !case.cores().contains(&core) {
        eprintln!("[e2e] skipped: {} is not served by {core:?}", case.label());
        return;
    }
    let label = case.label();
    run_against(&case, pick(cores, core), certs, &echo, &tls_echo)
        .await
        .unwrap_or_else(|e| panic!("{label}: e2e failed: {e}"));
}
