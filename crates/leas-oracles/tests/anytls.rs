//! E2E: native `AnyTLS` client against the reference servers.
//!
//! xray-core has no AnyTLS inbound (verified against `thirdparty/Xray-core`,
//! `proxy/` has no anytls arm), so the only oracles are sing-box and mihomo —
//! both ship a server AND a client for the protocol. Rows: TCP against each
//! core, and the uot v2 UDP carrier against each core.
//!
//! `clippy::future_not_send` is allowed file-wide (rstest, see `vmess.rs`).
#![allow(clippy::future_not_send)]

mod common;

use common::{Cores, certs, cores, echo, pick, tls_echo};
use leas_oracles::e2e::{
    AppKind, CaseSpec, Certs, CoreKind, E2eCase, EchoServer, TlsEchoServer, run_against,
};
use rstest::rstest;

#[rstest]
#[case::tcp_singbox(CaseSpec::anytls(), CoreKind::SingBox)]
#[case::tcp_mihomo(CaseSpec::anytls(), CoreKind::Mihomo)]
// UDP rides sing-box's uot v2 (`sp.v2.udp-over-tcp.arpa`) over an AnyTLS
// stream — the server side translates it back to datagrams.
#[case::udp_singbox(CaseSpec::anytls().with_app(AppKind::Udp), CoreKind::SingBox)]
#[case::udp_mihomo(CaseSpec::anytls().with_app(AppKind::Udp), CoreKind::Mihomo)]
#[tokio::test]
async fn anytls_against_reference_cores(
    #[case] case: CaseSpec,
    #[case] core: CoreKind,
    cores: &Cores,
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    run_against(&case, pick(cores, core), certs, &echo, &tls_echo)
        .await
        .unwrap_or_else(|e| panic!("{}: e2e failed: {e}", case.label()));
}
