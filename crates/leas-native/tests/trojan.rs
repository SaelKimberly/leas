//! E2E: native `Trojan` matrix — network {tcp, ws, grpc} × TLS {standard,
//! chrome fingerprint} × core {xray, sing-box}. One generated test per
//! (case, core). The wire protocol is identical on either side; the cert-TLS
//! server config is the same for the standard and fingerprint rows (only the
//! client hello differs — `with_tls`).
//!
//! `clippy::future_not_send` is allowed file-wide: rstest 0.27.0 clears the
//! source fn's attributes when embedding it beside the generated tests (see
//! `vmess.rs`).
#![allow(clippy::future_not_send)]
#![cfg(feature = "native-e2e")]

mod common;

use common::{certs, cores, echo, fp, pick, tls_echo};
use leas_native::PacketMode;
use leas_native::e2e::AppKind;
use leas_native::e2e::{
    CaseSpec, Certs, CoreKind, CoreUnderTest, E2eCase, EchoServer, TlsEchoServer, run_against,
};
use rstest::rstest;

fn trojan(net: &'static str) -> CaseSpec {
    CaseSpec::trojan().with_network(net)
}

fn trojan_chrome(net: &'static str) -> CaseSpec {
    trojan(net).with_tls(fp("chrome"))
}

#[rstest]
#[case::tcp(trojan("tcp"))]
#[case::tcp_chrome(trojan_chrome("tcp"))]
#[case::ws(trojan("ws"))]
#[case::ws_chrome(trojan_chrome("ws"))]
#[case::grpc(trojan("grpc"))]
#[case::grpc_chrome(trojan_chrome("grpc"))]
// Trojan UDP (command 3): the address-framed datagram tunnel over the
// stream — the `connect_udp` probe dispatches `PacketMode::Raw` to the
// trojan `PacketConn`. Both cores relay trojan UDP natively.
#[case::udp(trojan("tcp").with_app(AppKind::Udp).with_udp(PacketMode::Raw))]
#[tokio::test]
async fn trojan_against_cores(
    #[case] case: CaseSpec,
    #[values(CoreKind::Xray, CoreKind::SingBox)] core: CoreKind,
    cores: &(CoreUnderTest, CoreUnderTest),
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    let label = case.label();
    run_against(&case, pick(cores, core), certs, &echo, &tls_echo)
        .await
        .unwrap_or_else(|e| panic!("{label}: e2e failed: {e}"));
}
