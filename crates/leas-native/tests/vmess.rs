//! E2E: native `VMess` matrix — security {aes-128-gcm, chacha20-poly1305} ×
//! network {tcp, ws, grpc, httpupgrade} × TLS {standard, chrome, reality} ×
//! core {xray, sing-box}, plus single-core rows (ws-reality sing-box, xhttp
//! xray-only, v2rayhttp/h2 sing-box-only). One generated test per (case, core).
//!
//! `clippy::future_not_send` is allowed file-wide: rstest 0.27.0 clears the
//! source fn's attributes when embedding it beside the generated tests, so no
//! fn-/statement-level `#[allow]` reaches the nested async fn that holds the
//! non-`Send` `CaseSpec` across the runner await. No narrower scope works.
//! Re-verified on rstest 0.27.0 (2026-09-28 bump): the lint still fires, so the
//! allow is still required under the gate's `-D warnings`.
#![allow(
    clippy::future_not_send,
    reason = "rstest-generated futures lose their Send bound; they run on one local tokio runtime"
)]
#![cfg(feature = "native-e2e")]

mod common;

use common::{certs, cores, echo, fp, pick, pq_tls, reality, tls_echo};
use leas_native::PacketMode;
use leas_native::e2e::AppKind;
use leas_native::e2e::{
    Aes128GcmVariant, CaseSpec, Certs, Chacha20Poly1305Variant, CoreKind, CoreUnderTest,
    EchoServer, SecurityVariant, TlsEchoServer, TlsVariant, run_against,
};
use rstest::rstest;

/// `CaseSpec::vmess` takes the security variant by value; these helpers keep
/// the `#[case]` rows one-liners (mirror of the vless matrix helpers).
fn vmess(sec: impl SecurityVariant + 'static, net: &'static str) -> CaseSpec {
    CaseSpec::vmess(sec).with_network(net)
}

fn vmess_tls(
    sec: impl SecurityVariant + 'static,
    net: &'static str,
    tls: Box<dyn TlsVariant>,
) -> CaseSpec {
    vmess(sec, net).with_tls(tls)
}

/// xhttp row with an explicit client-side mode (the client's
/// `XHttpConfig.mode` selects the dialect on the wire; the server runs auto
/// and accepts both) — mirror of the vless `vless_xhttp_tls` helper.
fn vmess_xhttp_tls(
    sec: impl SecurityVariant + 'static,
    mode: &'static str,
    tls: Box<dyn TlsVariant>,
) -> CaseSpec {
    vmess_tls(sec, "xhttp", tls).with_xhttp_mode(mode)
}

#[rstest]
#[case::tcp_aes128gcm(vmess(Aes128GcmVariant, "tcp"))]
#[case::tcp_chacha20(vmess(Chacha20Poly1305Variant, "tcp"))]
#[case::tcp_aes128gcm_chrome(vmess_tls(Aes128GcmVariant, "tcp", fp("chrome")))]
#[case::tcp_chacha20_chrome(vmess_tls(Chacha20Poly1305Variant, "tcp", fp("chrome")))]
#[case::tcp_aes128gcm_reality(vmess_tls(Aes128GcmVariant, "tcp", reality()))]
#[case::tcp_chacha20_reality(vmess_tls(Chacha20Poly1305Variant, "tcp", reality()))]
#[case::ws_aes128gcm(vmess(Aes128GcmVariant, "ws"))]
#[case::ws_chacha20(vmess(Chacha20Poly1305Variant, "ws"))]
#[case::ws_aes128gcm_chrome(vmess_tls(Aes128GcmVariant, "ws", fp("chrome")))]
#[case::ws_chacha20_chrome(vmess_tls(Chacha20Poly1305Variant, "ws", fp("chrome")))]
#[case::grpc_aes128gcm(vmess(Aes128GcmVariant, "grpc"))]
#[case::grpc_chacha20(vmess(Chacha20Poly1305Variant, "grpc"))]
#[case::grpc_aes128gcm_chrome(vmess_tls(Aes128GcmVariant, "grpc", fp("chrome")))]
#[case::grpc_chacha20_chrome(vmess_tls(Chacha20Poly1305Variant, "grpc", fp("chrome")))]
#[case::grpc_aes128gcm_reality(vmess_tls(Aes128GcmVariant, "grpc", reality()))]
#[case::grpc_chacha20_reality(vmess_tls(Chacha20Poly1305Variant, "grpc", reality()))]
#[case::httpupgrade_aes128gcm(vmess(Aes128GcmVariant, "httpupgrade"))]
#[case::httpupgrade_chacha20(vmess(Chacha20Poly1305Variant, "httpupgrade"))]
#[case::httpupgrade_aes128gcm_chrome(vmess_tls(Aes128GcmVariant, "httpupgrade", fp("chrome")))]
#[case::httpupgrade_chacha20_chrome(vmess_tls(
    Chacha20Poly1305Variant,
    "httpupgrade",
    fp("chrome")
))]
// SP7 (VLESS ML-KEM spec §7.3): vmess tls-pq — the hybrid curve pinned on
// BOTH ends (client `curves: "x25519mlkem768"`, server
// tlsSettings.curvePreferences), so a green row is a negotiated ML-KEM-768
// exchange; the runner asserts the engine's negotiated-hybrid flag. Both
// cores accept curve_preferences (sing-box 1.13.16 verified empirically).
#[case::tcp_aes128gcm_tls_pq(vmess_tls(Aes128GcmVariant, "tcp", pq_tls()).with_pq_assert())]
#[tokio::test]
async fn vmess_against_cores(
    #[case] case: CaseSpec,
    #[values(CoreKind::Xray, CoreKind::SingBox)] core: CoreKind,
    cores: &(CoreUnderTest, CoreUnderTest),
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    // `#[once]` fixtures inject as `&T` (cores, certs); per-test fixtures
    // inject as OWNED `T` (echo, tls_echo) — borrow them for the runner.
    run_against(&case, pick(cores, core), certs, &echo, &tls_echo)
        .await
        .expect("vmess e2e failed");
}

/// Single-core cases: the named core accepts the configuration, the other
/// rejects it at startup. The ws-reality rows move here from the both-core
/// matrix (xray-core 26.3.27 refuses REALITY-over-WebSocket inbounds —
/// "REALITY only supports RAW, XHTTP and gRPC"; sing-box serves it). xhttp
/// (splithttp) is xray-only; v2rayhttp (h2) is sing-box-only (xray-core
/// removed the h2 transport in 26.x).
#[rstest]
#[case::ws_aes128gcm_reality_singbox(
    vmess_tls(Aes128GcmVariant, "ws", reality()),
    CoreKind::SingBox
)]
#[case::ws_chacha20_reality_singbox(
    vmess_tls(Chacha20Poly1305Variant, "ws", reality()),
    CoreKind::SingBox
)]
// xhttp packet-up: every vmess row is TLS, so the client negotiates the h2
// arm (h2 ALPN); the h1 arm is exercised only by the xhttp.rs hermetic unit
// test.
#[case::xhttp_packet_aes128gcm(vmess(Aes128GcmVariant, "xhttp"), CoreKind::Xray)]
#[case::xhttp_packet_chacha20(vmess(Chacha20Poly1305Variant, "xhttp"), CoreKind::Xray)]
#[case::xhttp_packet_aes128gcm_chrome(
    vmess_tls(Aes128GcmVariant, "xhttp", fp("chrome")),
    CoreKind::Xray
)]
#[case::xhttp_packet_chacha20_chrome(
    vmess_tls(Chacha20Poly1305Variant, "xhttp", fp("chrome")),
    CoreKind::Xray
)]
// stream-up: the client config carries mode "stream-up" (the client-side
// mode drives the dialect), over h2.
#[case::xhttp_stream_aes128gcm_chrome(
    vmess_xhttp_tls(Aes128GcmVariant, "stream-up", fp("chrome")),
    CoreKind::Xray
)]
// xhttp/h3 (SP5): the exactly-one `h3` ALPN flips xray's splithttp listener
// to the QUIC/HTTP-3 mode. The client's h3 arm (`connect_quic`, quinn + h3)
// runs the v3 protocol over HTTP/3; the row rides the DEFAULT verify path
// (webpki-roots chain walk with the harness CA as trust anchor). One row per
// payload security: reality is impossible (decideHTTPVersion returns "2" when
// a reality config is present) and h3 requires TLS (no plain row); sing-box
// has no xhttp-over-QUIC.
#[case::xhttp_h3_aes128gcm(vmess(Aes128GcmVariant, "xhttp3"), CoreKind::Xray)]
#[case::xhttp_h3_chacha20(vmess(Chacha20Poly1305Variant, "xhttp3"), CoreKind::Xray)]
// v2rayhttp (sing-box `type: http`) over h2 + the chrome fingerprint.
#[case::v2rayhttp_aes128gcm_chrome(
    vmess_tls(Aes128GcmVariant, "h2", fp("chrome")),
    CoreKind::SingBox
)]
// VMess UDP (command 0x02) is xray-single-core: sing-box 1.13.16 rejects our
// AEAD-record datagram tunnel at the first packet (`inbound/vmess[0]: bad
// packet connection` → client sees a truncated response header). xray-core
// serves the same bytes. Client fix needs sing-box 1.13's exact packet
// framing — tracked separately; the row stays to pin the xray path.
#[case::tcp_aes128gcm_udp(
    vmess(Aes128GcmVariant, "tcp").with_app(AppKind::Udp).with_udp(PacketMode::Raw),
    CoreKind::Xray
)]
#[tokio::test]
async fn vmess_single_core(
    #[case] case: CaseSpec,
    #[case] core: CoreKind,
    cores: &(CoreUnderTest, CoreUnderTest),
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    run_against(&case, pick(cores, core), certs, &echo, &tls_echo)
        .await
        .expect("vmess single-core e2e failed");
}
