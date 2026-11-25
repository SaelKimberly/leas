//! E2E: native `Hysteria2` matrix — sing-box single-core (xray-core has no
//! hysteria2 inbound), QUIC dial, ALPN `h3`. Rows: {default-tls, salamander,
//! gecko default sizes, gecko custom sizes}. The hysteria2 QUIC TLS is
//! rustls-internal (`spec §5.2`), so no fingerprint row exists (the engine
//! never shapes `QUIC` `ClientHellos`).
//!
//! `clippy::future_not_send` is allowed file-wide (rstest, see `vmess.rs`).
#![allow(clippy::future_not_send)]

mod common;

use common::{Cores, certs, cores, echo, pick, tls_echo};
use leas_native::PacketMode;
use leas_oracles::e2e::AppKind;
use leas_oracles::e2e::config::Hy2Obfs;
use leas_oracles::e2e::{
    CaseSpec, Certs, CoreKind, E2eCase, EchoServer, TlsEchoServer, config, run_against,
};
use rstest::rstest;

#[rstest]
#[case::tls_plain(CaseSpec::hysteria2(Hy2Obfs::None))]
#[case::obfs_salamander(CaseSpec::hysteria2(Hy2Obfs::Salamander(config::HYSTERIA2_OBFS_PSK)))]
#[case::obfs_gecko(CaseSpec::hysteria2(Hy2Obfs::Gecko {
    psk: config::HYSTERIA2_OBFS_PSK,
    min: leas_proto::proto_spec::GECKO_DEFAULT_MIN_PACKET_SIZE,
    max: leas_proto::proto_spec::GECKO_DEFAULT_MAX_PACKET_SIZE,
}))]
#[case::obfs_gecko_custom_sizes(CaseSpec::hysteria2(Hy2Obfs::Gecko {
    psk: config::HYSTERIA2_OBFS_PSK,
    min: 600,
    max: 1300,
}))]
// Hysteria2 UDP: QUIC DATAGRAM relay (`UDPMessage` framing) — the
// `connect_udp` probe dispatches the QUIC dial + datagram tunnel (the
// server's `Hysteria-UDP` response header must be true). sing-box single
// core.
#[case::udp(CaseSpec::hysteria2(Hy2Obfs::None).with_app(AppKind::Udp).with_udp(PacketMode::Raw))]
#[tokio::test]
async fn hysteria2_against_singbox(
    #[case] case: CaseSpec,
    cores: &Cores,
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
