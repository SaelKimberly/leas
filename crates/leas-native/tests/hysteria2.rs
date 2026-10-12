//! E2E: native `Hysteria2` matrix — sing-box single-core (xray-core has no
//! hysteria2 inbound), QUIC dial, ALPN `h3`. Rows: {default-tls, salamander
//! obfs}. The hysteria2 QUIC TLS is rustls-internal (`spec §5.2`), so no
//! fingerprint row exists (the engine never shapes `QUIC` `ClientHellos`).
//!
//! `clippy::future_not_send` is allowed file-wide (rstest, see `vmess.rs`).
#![allow(clippy::future_not_send)]
#![cfg(feature = "native-e2e")]

mod common;

use common::{certs, cores, echo, pick, tls_echo};
use leas_native::PacketMode;
use leas_native::e2e::AppKind;
use leas_native::e2e::{
    CaseSpec, Certs, CoreKind, CoreUnderTest, E2eCase, EchoServer, TlsEchoServer, config,
    run_against,
};
use rstest::rstest;

#[rstest]
#[case::tls_plain(CaseSpec::hysteria2(None))]
#[case::obfs_salamander(CaseSpec::hysteria2(Some(config::HYSTERIA2_OBFS_PSK)))]
// Hysteria2 UDP: QUIC DATAGRAM relay (`UDPMessage` framing) — the
// `connect_udp` probe dispatches the QUIC dial + datagram tunnel (the
// server's `Hysteria-UDP` response header must be true). sing-box single
// core.
#[case::udp(CaseSpec::hysteria2(None).with_app(AppKind::Udp).with_udp(PacketMode::Raw))]
#[tokio::test]
async fn hysteria2_against_singbox(
    #[case] case: CaseSpec,
    cores: &(CoreUnderTest, CoreUnderTest),
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    run_against(
        &case,
        pick(cores, CoreKind::SingBox),
        certs,
        &echo,
        &tls_echo,
    )
    .await
    .unwrap_or_else(|e| panic!("{}: e2e failed: {e}", case.label()));
}
