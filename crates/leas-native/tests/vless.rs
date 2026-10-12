//! E2E: native VLESS matrix — network {tcp, ws, grpc, httpupgrade} × TLS
//! variant × core {xray, sing-box}, plus xray-only xhttp (splithttp) rows.
//! One generated test per (case, core).
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

use common::{
    certs, cores, echo, fp, no_tls, pick, plain_server_reality_client, pq_tls, reality,
    reality_server_plain_client, reality_wrong_pbk, reality_wrong_sid, tls_echo,
};
use leas_native::e2e::{
    AppKind, CaseSpec, Certs, CoreKind, CoreUnderTest, EchoServer, Flow, TlsEchoServer, TlsVariant,
    XRAY_HEAD_BIN_DIR, XRAY_HEAD_VERSION, run_against,
};
use leas_native::protocol::vless::PacketMode;
use rstest::rstest;

/// `CaseSpec::vless()` plus the network axis; these helpers keep the
/// `#[case]` rows one-liners (mirror of the vmess matrix helpers).
fn vless(net: &'static str) -> CaseSpec {
    CaseSpec::vless().with_network(net)
}

fn vless_tls(net: &'static str, tls: Box<dyn TlsVariant>) -> CaseSpec {
    vless(net).with_tls(tls)
}

/// xhttp row with an explicit client-side mode (the client's
/// `XHttpConfig.mode` selects the dialect on the wire; the server runs auto
/// and accepts both).
fn vless_xhttp(mode: &'static str) -> CaseSpec {
    vless("xhttp").with_xhttp_mode(mode)
}

fn vless_xhttp_tls(mode: &'static str, tls: Box<dyn TlsVariant>) -> CaseSpec {
    vless_tls("xhttp", tls).with_xhttp_mode(mode)
}

/// VLESS vision rows (spec §7.4): `flow = xtls-rprx-vision`, tcp network,
/// the default certificate TLS. `app` selects the app-side probe: plain
/// HTTP over the tunnel, or an inner TLS session through the tunnel.
fn vision(app: AppKind) -> CaseSpec {
    CaseSpec::vless().with_flow(Flow::Vision).with_app(app)
}

/// VLESS vision rows with an explicit TLS variant (REALITY etc.).
fn vision_tls(app: AppKind, tls: Box<dyn TlsVariant>) -> CaseSpec {
    vision(app).with_tls(tls)
}

/// VLESS UDP rows (spec §7.3): datagrams through the tunnel over tcp.
/// `mode` selects the packet wire: `Raw` = the header destination serves
/// every datagram (both cores); `PacketAddr` = per-datagram
/// `atyp|addr|port` frames to the magic-fqdn header destination (the
/// sing-vmess dialect — xray-core does not register the packetaddr magic
/// address, so that row is sing-box single-core).
fn vless_udp(mode: PacketMode) -> CaseSpec {
    CaseSpec::vless().with_app(AppKind::Udp).with_udp(mode)
}

/// VLESS UDP row with an explicit TLS variant (REALITY etc.).
fn vless_udp_tls(mode: PacketMode, tls: Box<dyn TlsVariant>) -> CaseSpec {
    vless_udp(mode).with_tls(tls)
}

#[rstest]
#[case::tcp_plain(vless("tcp"))]
#[case::tcp_chrome(vless_tls("tcp", fp("chrome")))]
// The 2026-09-17 roster fix: `chrome` resolves to the hand-declared,
// unchanged `chrome_130`, so these three are the presets whose generated
// hellos carried the malformed `encrypted_client_hello` /
// `compress_certificate` / `delegated_credentials` bodies. Each runs against
// real xray-core and sing-box, which is the interop proof the tier-1 sweep
// and the tier-2 strict-peer test cannot give.
#[case::tcp_firefox(vless_tls("tcp", fp("firefox")))]
#[case::tcp_safari(vless_tls("tcp", fp("safari")))]
#[case::tcp_ios(vless_tls("tcp", fp("ios")))]
#[case::tcp_reality(vless_tls("tcp", reality()))]
#[case::tcp_reality_wrong_pbk(vless_tls("tcp", reality_wrong_pbk()))]
#[case::tcp_reality_wrong_sid(vless_tls("tcp", reality_wrong_sid()))]
#[case::tcp_plain_into_reality_server(vless_tls("tcp", reality_server_plain_client()))]
#[case::tcp_reality_into_plain_server(vless_tls("tcp", plain_server_reality_client()))]
#[case::ws_plain(vless("ws"))]
#[case::ws_chrome(vless_tls("ws", fp("chrome")))]
#[case::ws_reality_wrong_pbk(vless_tls("ws", reality_wrong_pbk()))]
#[case::ws_reality_wrong_sid(vless_tls("ws", reality_wrong_sid()))]
#[ignore = "plain client into reality server: dest sees ws framing, not HTTP (transport unreachable pre-proxy)"]
#[case::ws_plain_into_reality_server(vless_tls("ws", reality_server_plain_client()))]
#[case::ws_reality_into_plain_server(vless_tls("ws", plain_server_reality_client()))]
#[case::grpc_plain(vless("grpc"))]
#[case::grpc_chrome(vless_tls("grpc", fp("chrome")))]
#[case::grpc_reality(vless_tls("grpc", reality()))]
#[case::grpc_reality_wrong_pbk(vless_tls("grpc", reality_wrong_pbk()))]
#[case::grpc_reality_wrong_sid(vless_tls("grpc", reality_wrong_sid()))]
#[ignore = "plain client into reality server: dest sees grpc framing, not HTTP (transport unreachable pre-proxy)"]
#[case::grpc_plain_into_reality_server(vless_tls("grpc", reality_server_plain_client()))]
#[case::grpc_reality_into_plain_server(vless_tls("grpc", plain_server_reality_client()))]
#[case::httpupgrade_plain(vless("httpupgrade"))]
#[case::httpupgrade_chrome(vless_tls("httpupgrade", fp("chrome")))]
// VLESS vision flow axis (spec §7.4): `xtls-rprx-vision` × {tls, reality} ×
// {inner-tls, plain} — the inner-tls rows drive the Direct-splice path (the
// app establishes a real TLS 1.3 session through the tunnel to a rustls
// echo target); the plain rows exercise the End (non-TLS) path.
#[case::vision_tls_plain(vision(AppKind::Plain))]
#[case::vision_tls_inner(vision(AppKind::InnerTls))]
#[case::vision_reality_plain(vision_tls(AppKind::Plain, reality()))]
#[case::vision_reality_inner(vision_tls(AppKind::InnerTls, reality()))]
// VLESS UDP axis (spec §7.3): the UDP command (0x02) over the tunnel, Raw
// mode — every datagram goes to the header destination; both cores serve
// it over tls and reality.
#[case::udp_tls_plain(vless_udp(PacketMode::Raw))]
#[case::udp_reality_plain(vless_udp_tls(PacketMode::Raw, reality()))]
// VLESS mux axis (spec §7.3): one `connect_mux` tunnel (command 0x03 to
// v1.mux.cool:9527) carrying MUX_SESSION_COUNT concurrent sessions to the
// echo target — each session a distinct HTTP GET, every response asserted
// (order-independent). Over tls and reality, both cores (the probe
// smoke-passed 4/4 real-core in Task 5).
#[case::mux_tls(vless("tcp").with_mux(true))]
#[case::mux_reality(vless_tls("tcp", reality()).with_mux(true))]
// VLESS XUDP axis (spec §7.3): UDP over the mux tunnel — the probe's
// `connect_udp` dispatches XUDP on `params.mux`, carrying each datagram
// as a mux UDP session packet (per-packet destination, `PacketMode::XUdp`)
// to the UDP echo target; the runner routes the mux+UDP row to
// `probe_udp_mux`. Over tls and reality, both cores (the probe
// smoke-passed 5/5 real-core in Task 5).
#[case::xudp_tls(vless("tcp").with_app(AppKind::Udp).with_udp(PacketMode::XUdp).with_mux(true))]
#[case::xudp_reality(
    vless_tls("tcp", reality())
        .with_app(AppKind::Udp)
        .with_udp(PacketMode::XUdp)
        .with_mux(true)
)]
// vision_udp443 (spec §7.3): the udp443 flow — the client carries the
// full `xtls-rprx-vision-udp443` name (selects the XUDP path client-side:
// mux-forced via `case.mux()`, guard lifted), the wire addon truncates to
// `xtls-rprx-vision`, and the server config emits that truncated name
// (`Flow::server_str` — both cores validate the request's addon against
// it). Both cores serve vision+mux+UDP: xray's inbound sets
// `AllowedNetwork = UDP` for mux under flow XRV (inbound.go — vision+mux
// is the XUDP path; the SP2 TCP rejection does NOT apply to UDP) and
// sing-box terminates the XUDP session the same way — verified interop on
// both cores (final-review fix wave).
#[case::vision_udp443(
    vless("tcp")
        .with_flow(Flow::Udp443)
        .with_app(AppKind::Udp)
        .with_udp(PacketMode::XUdp)
)]
// SP7 (VLESS ML-KEM) tls-pq row (spec §7.3): the hybrid curve pinned on
// BOTH ends — the client offers only the X25519MLKEM768 key share
// (`curves: "x25519mlkem768"`) and the server's tlsSettings.curvePreferences
// accepts nothing else, so a green row is a negotiated ML-KEM-768 exchange,
// never a classical fallback; the runner additionally asserts the engine's
// negotiated-hybrid flag. Both cores accept curve_preferences (sing-box
// 1.13.16 verified empirically).
#[case::tcp_tls_pq(vless_tls("tcp", pq_tls()).with_pq_assert())]
#[tokio::test]
async fn vless_against_cores(
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
        .expect("vless e2e failed");
}

/// Single-core cases: the named core accepts the configuration, the other
/// rejects it at startup (xray-core 26.3.27 refuses REALITY-over-WebSocket
/// inbounds — "REALITY only supports RAW, XHTTP and gRPC"; sing-box serves
/// it). Each row names its core explicitly instead of `#[values]`.
#[rstest]
#[case::ws_reality_singbox(vless_tls("ws", reality()), CoreKind::SingBox)]
// xray-core refuses REALITY over httpupgrade inbounds — "REALITY only
// supports RAW, XHTTP and gRPC" — so the reality row runs on sing-box only.
#[case::httpupgrade_reality_singbox(vless_tls("httpupgrade", reality()), CoreKind::SingBox)]
// xhttp (splithttp) is xray-only: sing-box's own dialect is the v2rayhttp
// transport (a different plan task). The plain/chrome rows carry no mode →
// the native dial auto-selects packet-up (no reality); the reality row also
// carries no mode and auto-selects STREAM-ONE (xray `dialer.go` spec §4.1 —
// the pre-SP6 packet-up-over-REALITY deviation is gone; the server accepts
// all modes). The explicit stream-up/stream-one rows exercise those arms
// directly. Packet-up over h1 (no TLS) is covered by the hermetic unit
// test; these rows exercise the h2 arm (TLS) + the REALITY path.
#[case::xhttp_packet_plain(vless("xhttp"), CoreKind::Xray)]
#[case::xhttp_packet_chrome(vless_tls("xhttp", fp("chrome")), CoreKind::Xray)]
#[case::xhttp_stream_one_reality(vless_tls("xhttp", reality()), CoreKind::Xray)]
// stream-up: the client config carries mode "stream-up" (the client-side
// mode drives the dialect); both rows run over h2 (TLS → h2). The h1 arm
// is covered by the hermetic unit test.
#[case::xhttp_stream_plain(vless_xhttp("stream-up"), CoreKind::Xray)]
#[case::xhttp_stream_chrome(vless_xhttp_tls("stream-up", fp("chrome")), CoreKind::Xray)]
// stream-one explicit + standard TLS (the legacy XHTTP v1 full-duplex
// tunnel — no session id; h2 since TLS → h2; the auto-derived reality
// row above covers the same arm via the §4.1 default).
#[case::xhttp_stream_one_tls(vless_xhttp("stream-one"), CoreKind::Xray)]
// xhttp/h3 (SP5): the exactly-one `h3` ALPN flips xray's splithttp listener
// to the QUIC/HTTP-3 mode (hub.go `isH3` — the row's server config emits
// tlsSettings.alpn ["h3"], no quic_settings needed: the server's quic-go
// defaults + the client's 10s keepalive hold the tunnel). The client's h3
// arm (`connect_quic`, quinn + h3 — the engine TLS never wraps QUIC, spec
// §5.2) runs the v3 protocol over HTTP/3; the row rides the DEFAULT verify
// path (webpki-roots chain walk with the harness CA as trust anchor —
// `StandardTls::client_trust` installs it; the T3-insecure-only cert gap).
// Packet-up (the default dialect). One row: reality is impossible
// (decideHTTPVersion returns "2" when a reality config is present) and h3
// requires TLS (no plain row); sing-box has no xhttp-over-QUIC.
#[case::xhttp_h3_tls(vless("xhttp3"), CoreKind::Xray)]
// v2rayhttp (sing-box `type: http`) is sing-box-only: xray-core removed the
// h2 transport in 26.x. One row over h2 + the chrome fingerprint (the
// client JSON carries the fp so the engine fingerprints; ALPN h2 comes from
// the context's transport-implied alpn arm).
#[case::v2rayhttp_chrome(vless_tls("h2", fp("chrome")), CoreKind::SingBox)]
// PacketAddr mode: per-datagram `atyp|addr|port` frames to the magic-fqdn
// header destination (`sp.packet-addr.v2fly.arpa`). The sing-box server
// unwraps automatically (inbound magic-fqdn detection); xray-core's VLESS
// has no packetaddr registration (verified — no packetaddr symbols in
// thirdparty/Xray-core/proxy/vless), so the row is sing-box single-core.
#[case::udp_packetaddr_tls(vless_udp(PacketMode::PacketAddr), CoreKind::SingBox)]
// Optional mux+vision row (spec §5.3): the vision flow over the mux
// tunnel — the header carries the flow addon + camouflage frame, then mux
// frames ride the vision-padded stream. The server's TLS filter sees the
// mux New frame (2-byte length prefix) as non-TLS and stays on the End
// path (no splice), so the mux sessions flow over the padded tunnel —
// verified interop with sing-box 1.13.16. xray-core 26.3.27 rejects the
// combination BY DESIGN: for command=mux under flow XRV it sets
// AllowedNetwork=UDP (inbound.go — vision+mux is the XUDP path), so a TCP
// New frame fails with "unexpected network TCP" and breaks the whole mux
// connection ("we will break Mux connections that contain TCP requests").
// Hence sing-box single-core.
#[case::mux_vision_singbox(vless("tcp").with_flow(Flow::Vision).with_mux(true), CoreKind::SingBox)]
// mKCP (SP4) is xray-single-core: sing-box has no kcp transport. Spec §7.3
// asked for three arms (plain/tls/reality) — the reality arm is dropped by
// controller ruling: xray-core 26.3.27's StreamConfig.Build() rejects
// security=reality over any protocol but tcp/splithttp/grpc
// (transport_internet.go: "REALITY only supports RAW, XHTTP and gRPC for
// now."), so the server config dies at startup; no core can serve
// reality-over-kcp (sing-box has no kcp). The native client's
// reality-over-kcp dial stays implemented (unreachable server-side, like
// xray itself). Rows: plain (NO TLS — the NoTls variant: server
// streamSettings without tlsSettings, client security none, the suite's
// first genuinely plain row) + tls (chrome fingerprint engine) — the kcp
// dial + security-wrap composition arms.
#[case::kcp_plain(vless_tls("kcp", no_tls()), CoreKind::Xray)]
#[case::kcp_chrome(vless_tls("kcp", fp("chrome")), CoreKind::Xray)]
// SP7 (VLESS ML-KEM) PQ rows (spec §7.3) — xray-single-core: sing-box
// 1.13.16 has no VLESS account encryption, so pq-enc pins xray; reality-pq
// is blocked by the harness dest regardless of core.
//
// reality-pq: BLOCKED by the harness dest, not by the client. The xray
// REALITY server replays the DEST's ServerHello flight as camouflage
// (xtls/reality tls.go s2cSaved — the share group check at :359 accepts
// X25519 or X25519MLKEM768, but the group is whatever the DEST negotiated),
// and the harness dest (rustls tls_echo) has no PQ key exchange — so the
// tunnel is structurally classical regardless of the client's hybrid offer.
// A PQ reality row needs a PQ-capable dest (Go 1.24+ / OpenSSL 3.5 echo);
// the client's REALITY 4588 support itself is proven hermetically (T4 fake
// REALITY PQ server) and the plain reality rows stay green.
#[ignore = "reality replays the dest's ServerHello; the rustls tls_echo dest has no PQ — needs a PQ-capable dest"]
#[case::tcp_reality_pq(vless_tls("tcp", reality()).with_pq_assert(), CoreKind::Xray)]
// pq-enc: the VLESS `mlkem768x25519plus` account encryption end to end —
// the client outbound `encryption` carries the server's PUBLIC halves
// (X25519 pub + ML-KEM-768 encapsulation key), the xray inbound
// `settings.decryption` the PRIVATE halves (X25519 priv + the 64-B seed);
// the PQ handshake wraps the whole session before the request header.
//
// GREEN since 2026-09-23. The three "passes" above localized the symptom
// correctly but their conclusion ("the fault is our wire") was wrong: the
// PQ wire was byte-correct ALL ALONG (server decoded the request —
// `firstLen = 26` — and dialed the echo on every attempt, and the client
// received the full `200 OK` body). The real defect was the RECORD LAYER's
// EOF classification: `CommonConn::poll_read` raised `UnexpectedEof` on a
// CLEAN end of stream at a record/padding-field boundary, so the probe's
// `read_to_end` threw away an already-complete response and reported
// `status 0 body ""`. Go's `io.ReadFull` (xray's framing) yields bare
// `io.EOF` when zero bytes were read into a field and `ErrUnexpectedEOF`
// only mid-field; the reader now mirrors that. See `mlkem.rs` `poll_read`.
#[case::tcp_pq_enc(vless("tcp").with_pq_enc(), CoreKind::Xray)]
#[tokio::test]
async fn vless_single_core(
    #[case] case: CaseSpec,
    #[case] core: CoreKind,
    cores: &(CoreUnderTest, CoreUnderTest),
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    run_against(&case, pick(cores, core), certs, &echo, &tls_echo)
        .await
        .expect("vless single-core e2e failed");
}

/// T9's first differential: the pq-enc case against the SECOND pinned peer — an
/// `xray` built from `thirdparty/Xray-core` HEAD — while `XRAY_VERSION` stays
/// the suite's baseline.
///
/// It answers the question the ignored row could not: is the pre-response EOF a
/// VERSION DELTA (our client implements a revision newer than the release) or
/// OUR CLIENT? A green HEAD row with a red baseline row would mean the pin is
/// behind the implementation, not that the client is wrong. Measured: both fail
/// identically, so it is not a version delta.
#[ignore = "needs a HEAD-built peer: LEAS_CORE_HEAD_BIN_DIR"]
#[rstest]
#[tokio::test]
async fn vless_pq_enc_against_head(certs: &Certs, echo: EchoServer, tls_echo: TlsEchoServer) {
    let Ok(head) =
        CoreUnderTest::resolve_from(CoreKind::Xray, XRAY_HEAD_VERSION, XRAY_HEAD_BIN_DIR)
    else {
        eprintln!("SKIP: set {XRAY_HEAD_BIN_DIR} to a directory holding the HEAD-built `xray`");
        return;
    };
    let case = vless("tcp").with_pq_enc();
    run_against(&case, &head, certs, &echo, &tls_echo)
        .await
        .expect("pq-enc against the HEAD peer");
}

/// T9's second differential, and the one that removes the last hedge: does OUR
/// client work with a pair the REFERENCE generated?
///
/// The first differential left *"our client's wire **or this case's server
/// config**"*, and that alternative had a concrete form — the case's keypair
/// comes from `mlkem_enc_pair`, which expands a 64-byte seed through OUR
/// `Mlkem768::keypair_from_seed` where the server's decryption string expects
/// Go's `mlkem.NewDecapsulationKey768` to do it. If the two expansions differed,
/// the client's `ek` would target a key the server never holds, and the symptom
/// would be exactly the one observed.
///
/// A `vlessenc`-generated pair is self-consistent on the server side (and a real
/// HEAD client demonstrably works with one), so a GREEN row here would indict
/// `mlkem_enc_pair` rather than the client, and a RED one indicts the client's
/// sealing/framing. Measured: RED.
#[rstest]
#[ignore = "differential: needs LEAS_CORE_BIN_DIR (26.3.27) plus LEAS_PQ_ENC / LEAS_PQ_DEC from `xray vlessenc`"]
#[tokio::test]
async fn vless_pq_enc_with_a_reference_pair(
    cores: &(CoreUnderTest, CoreUnderTest),
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    let (Ok(enc), Ok(dec)) = (std::env::var("LEAS_PQ_ENC"), std::env::var("LEAS_PQ_DEC")) else {
        eprintln!("SKIP: set LEAS_PQ_ENC / LEAS_PQ_DEC from `xray vlessenc`");
        return;
    };
    let case = vless("tcp").with_pq_enc_pair(enc, dec);
    run_against(&case, pick(cores, CoreKind::Xray), certs, &echo, &tls_echo)
        .await
        .expect("pq-enc with a reference-generated pair");
}
