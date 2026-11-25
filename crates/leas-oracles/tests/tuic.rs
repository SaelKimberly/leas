//! E2E: native TUIC v5 against the pinned sing-box and mihomo servers.
//! Rows: TCP, UDP native, UDP quic, 0-RTT resume (sing-box only).
//!
//! `clippy::future_not_send` is allowed file-wide (rstest, see `vmess.rs`).
#![allow(clippy::future_not_send)]

mod common;

use common::{Cores, certs, cores, echo, pick, tls_echo};
use leas_native::PacketMode;
use leas_oracles::e2e::AppKind;
use leas_oracles::e2e::{
    CaseSpec, Certs, CoreKind, E2eCase, EchoServer, ServerEnv, TlsEchoServer, config, free_port,
    probe, run_against, spawn_core, spawn_udp_echo,
};
use leas_proto::proto_spec::ProtocolConfig;
use rstest::rstest;

#[rstest]
#[case::tcp(CaseSpec::tuic("native", false))]
#[case::udp_native(CaseSpec::tuic("native", false)
    .with_app(AppKind::Udp)
    .with_udp(PacketMode::Raw))]
#[case::udp_quic(CaseSpec::tuic("quic", false)
    .with_app(AppKind::Udp)
    .with_udp(PacketMode::Raw))]
#[case::zero_rtt(CaseSpec::tuic("native", true))]
#[tokio::test]
async fn tuic_against_singbox(
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

#[rstest]
#[case::tcp(CaseSpec::tuic("native", false).with_single_core(CoreKind::Mihomo))]
#[case::udp_native(CaseSpec::tuic("native", false)
    .with_app(AppKind::Udp)
    .with_udp(PacketMode::Raw)
    .with_single_core(CoreKind::Mihomo))]
#[case::udp_quic(CaseSpec::tuic("quic", false)
    .with_app(AppKind::Udp)
    .with_udp(PacketMode::Raw)
    .with_single_core(CoreKind::Mihomo))]
#[tokio::test]
async fn tuic_against_mihomo(
    #[case] case: CaseSpec,
    cores: &Cores,
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    run_against(
        &case,
        pick(cores, CoreKind::Mihomo),
        certs,
        &echo,
        &tls_echo,
    )
    .await
    .unwrap_or_else(|e| panic!("{}: e2e failed: {e}", case.label()));
}

/// Two dials on one server: the first stores a TLS ticket, the second attempts
/// 0-RTT. When the server accepts early data the staged CONNECT rides it; when
/// the server rejects it the stream wrapper retries on a fresh stream. Both
/// dials must carry HTTP. A wrong password never reaches the echo.
#[rstest]
#[tokio::test]
async fn tuic_zero_rtt_and_wrong_password(
    cores: &Cores,
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("server.crt"), &certs.cert_pem).expect("cert");
    std::fs::write(dir.path().join("server.key"), &certs.key_pem).expect("key");
    let port = free_port();
    let env = ServerEnv {
        port,
        certs,
        tmp: dir.path(),
        echo: echo.addr,
        tls_echo: tls_echo.addr,
        inner_tls_echo: None,
        udp_echo: None,
    };
    let config_path = dir.path().join("config.json");
    std::fs::write(
        &config_path,
        config::tuic_inbound(CoreKind::SingBox, &env, true),
    )
    .expect("server config");
    let _core = spawn_core(
        &cores.singbox.bin,
        CoreKind::SingBox,
        &config_path,
        port,
        true,
    );
    leas_native::transport::quic::set_test_ca(&certs.ca_der);
    let params = config::client_params_tuic(port, echo.addr, "native");

    let mut first = leas_native::connect(params.clone())
        .await
        .expect("first TUIC dial");
    assert_eq!(probe(&mut first).await.0, 200, "first TUIC dial");
    drop(first);

    let base = leas_native::protocol::tuic::early_stats();
    let mut second = leas_native::connect(params.clone())
        .await
        .expect("resumed TUIC dial");
    assert_eq!(probe(&mut second).await.0, 200, "resumed TUIC dial");
    let after = leas_native::protocol::tuic::early_stats();
    assert!(
        after.0 > base.0,
        "the second dial must attempt 0-RTT: {base:?} -> {after:?}"
    );
    assert!(
        after.1 > base.1,
        "the zero_rtt_handshake server must accept early data: {base:?} -> {after:?}"
    );

    let mut bad = params;
    let ProtocolConfig::Tuic(cfg) = &mut bad.protocol else {
        panic!("tuic params");
    };
    cfg.password = "wrong-password".into();
    let (status, _) = match leas_native::connect(bad).await {
        Ok(mut tunnel) => probe(&mut tunnel).await,
        Err(_) => (0, String::new()),
    };
    assert_eq!(status, 0, "a wrong TUIC password must not reach the echo");
}

/// A UDP payload above the path DATAGRAM budget exercises native fragmentation
/// and reassembly; a 15 s idle window exercises the 10 s TUIC heartbeat before
/// a fresh TCP dial.
#[rstest]
#[tokio::test]
async fn tuic_udp_fragments_and_idle_heartbeat(
    cores: &Cores,
    certs: &Certs,
    echo: EchoServer,
    tls_echo: TlsEchoServer,
) {
    let udp_echo = spawn_udp_echo();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("server.crt"), &certs.cert_pem).expect("cert");
    std::fs::write(dir.path().join("server.key"), &certs.key_pem).expect("key");
    let port = free_port();
    let env = ServerEnv {
        port,
        certs,
        tmp: dir.path(),
        echo: echo.addr,
        tls_echo: tls_echo.addr,
        inner_tls_echo: None,
        udp_echo: Some(udp_echo.addr),
    };
    let config_path = dir.path().join("config.json");
    std::fs::write(
        &config_path,
        config::tuic_inbound(CoreKind::SingBox, &env, false),
    )
    .expect("server config");
    let _core = spawn_core(
        &cores.singbox.bin,
        CoreKind::SingBox,
        &config_path,
        port,
        true,
    );
    leas_native::transport::quic::set_test_ca(&certs.ca_der);

    let payload = vec![0xab; 4000];
    for mode in ["native", "quic"] {
        let params = config::client_params_tuic(port, udp_echo.addr, mode);
        let mut tunnel = leas_native::connect_udp(&params)
            .await
            .unwrap_or_else(|e| panic!("{mode} udp dial: {e}"));
        tunnel
            .send(None, &payload)
            .await
            .unwrap_or_else(|e| panic!("{mode} udp send: {e}"));
        let echoed = tokio::time::timeout(std::time::Duration::from_secs(10), tunnel.recv())
            .await
            .unwrap_or_else(|_| panic!("{mode} udp echo timed out"))
            .unwrap_or_else(|e| panic!("{mode} udp recv: {e}"))
            .unwrap_or_else(|| panic!("{mode} udp echo closed the tunnel"));
        assert_eq!(
            echoed.1.as_ref(),
            payload.as_slice(),
            "{mode} fragmented echo"
        );
    }

    let params = config::client_params_tuic(port, echo.addr, "native");
    let mut tunnel = leas_native::connect(params)
        .await
        .expect("TCP dial before idle");
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    let (status, _) = probe(&mut tunnel).await;
    assert_eq!(status, 200, "heartbeat keeps the idle TUIC tunnel alive");
}
