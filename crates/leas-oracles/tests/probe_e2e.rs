//! Real-core smoke for the native probe: one HTTP request through a real
//! xray-core VLESS server to a local HTTP target.
//!
//! This is the only check that exercises the whole probe path against a real
//! core: dial → VLESS handshake → tunnel → HTTP request → response. It needs
//! the xray-core binary (`LEAS_CORE_BIN_DIR` or `~/.config/leas/bin`),
//! so it is `#[ignore]`d — a machine without binaries stays green. Run it with
//!
//! ```text
//! cargo test -p leas-oracles --test probe_e2e -- --ignored
//! ```

use std::process::{Child, Command};
use std::time::Duration;

use leas_native::addr::TargetAddr;
use leas_native::context::NativeConnectParams;
use leas_native::probe::{self, ProbeMethod, ProbeRequest};
use leas_oracles::e2e::config;
use leas_oracles::e2e::{
    CaseSpec, Certs, CoreKind, CoreUnderTest, E2eCase, SINGBOX_VERSION, ServerEnv, generate_certs,
    spawn_core,
};
use leas_proto::proto_spec::common::TransportConfig;
use leas_proto::proto_spec::endpoint::EndpointEssentials;
use leas_proto::proto_spec::{HostKind, ProtocolConfig, SecurityConfig, VlessConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// A free loopback port (bound then released — fine for a test).
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

/// Serve one small HTTP response per connection, forever.
fn spawn_http_target() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind target");
    let port = listener.local_addr().expect("target addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let mut head = [0u8; 2048];
            let _ = sock.read(&mut head).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await;
            let _ = sock.shutdown().await;
        }
    });
    (port, handle)
}

/// Resolve the pinned xray-core: `LEAS_CORE_BIN_DIR` when set, else the
/// directory `build.rs` fetched into, version-checked against `XRAY_VERSION`.
fn xray_binary() -> Option<leas_oracles::e2e::CoreUnderTest> {
    match leas_oracles::e2e::CoreUnderTest::resolve(
        leas_oracles::e2e::CoreKind::Xray,
        leas_oracles::e2e::XRAY_VERSION,
    ) {
        Ok(core) => Some(core),
        Err(e) => {
            eprintln!("SKIP: {e}");
            None
        }
    }
}

/// Start a real xray-core VLESS server on `port`; returns the child, the
/// config path and the log path (the caller removes them).
fn spawn_xray_server(
    bin: &std::path::Path,
    port: u16,
) -> (Child, std::path::PathBuf, std::path::PathBuf) {
    let config = serde_json::json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": UUID }],
                "decryption": "none"
            }
        }],
        // freedom blocks private targets by default since 26.10.31.
        "outbounds": [{ "protocol": "freedom", "settings": { "finalRules": [{ "action": "allow", "ip": ["127.0.0.0/8", "::1/128"] }] } }]
    });
    let config_path = std::env::temp_dir().join(format!("leas-probe-e2e-{port}.json"));
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("serialize config"),
    )
    .expect("write config");
    // Keep the server's own output: a failed start must explain itself.
    let log_path = std::env::temp_dir().join(format!("leas-probe-e2e-{port}.log"));
    let log = std::fs::File::create(&log_path).expect("create log");
    let child = Command::new(bin)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .expect("spawn xray");
    (child, config_path, log_path)
}

/// Poll the server port until it accepts, bounded. `false` on timeout.
async fn wait_for_port(port: u16) -> bool {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
#[ignore = "needs the pinned xray-core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn probe_through_real_xray_vless_server() {
    let Some(bin) = xray_binary() else {
        panic!("no xray binary found");
    };
    let (target_port, target) = spawn_http_target();
    let server_port = free_port();
    let (mut child, config_path, log_path) = spawn_xray_server(&bin.bin, server_port);
    if !wait_for_port(server_port).await {
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        let _ = child.kill();
        let _ = child.wait();
        panic!("xray-core did not listen on {server_port}; log:\n{log}");
    }

    let params = NativeConnectParams::new(
        ProtocolConfig::Vless(VlessConfig {
            uuid: UUID.to_string(),
            uuid_origin: None,
            security: SecurityConfig::default(),
            transport: TransportConfig::Tcp,
            encryption: None,
            flow: None,
            path: None,
            splice: None,
            remarks: None,
            mux: None,
        }),
        EndpointEssentials {
            host: "127.0.0.1".to_string(),
            host_type: HostKind::Ipv4,
            port: server_port,
            ports: Vec::new(),
        },
        TargetAddr::new("127.0.0.1", target_port),
    );
    let request = ProbeRequest {
        host: "127.0.0.1",
        port: target_port,
        https: false,
        method: ProbeMethod::Get,
        path: "/",
        timeout: Duration::from_secs(5),
        transport_timeout: Duration::from_secs(5),
    };

    let response = probe::fetch(params, &request)
        .await
        .expect("probe through xray");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello");
    assert!(response.elapsed > Duration::ZERO);

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(config_path);
    let _ = std::fs::remove_file(log_path);
    target.abort();
}

/// The pinned sing-box, when present (the ignored rows below only run with it).
fn singbox_binary() -> Option<CoreUnderTest> {
    match CoreUnderTest::resolve(CoreKind::SingBox, SINGBOX_VERSION) {
        Ok(core) => Some(core),
        Err(e) => {
            eprintln!("SKIP: {e}");
            None
        }
    }
}

/// The cert/key files a sing-box TLS inbound references, plus the env its
/// config builder takes. The echo addresses are irrelevant to a probe row (the
/// probe carries its own HTTP request), so both point at the target.
fn stage_singbox_server<'a>(
    dir: &'a std::path::Path,
    certs: &'a Certs,
    port: u16,
    target: std::net::SocketAddr,
) -> ServerEnv<'a> {
    std::fs::write(dir.join("server.crt"), &certs.cert_pem).expect("cert");
    std::fs::write(dir.join("server.key"), &certs.key_pem).expect("key");
    ServerEnv {
        port,
        certs,
        tmp: dir,
        echo: target,
        tls_echo: target,
        inner_tls_echo: None,
        udp_echo: None,
    }
}

/// One plain HTTP request through the tunnel to the local target.
fn probe_request(target_port: u16) -> ProbeRequest<'static> {
    ProbeRequest {
        host: "127.0.0.1",
        port: target_port,
        https: false,
        method: ProbeMethod::Get,
        path: "/",
        timeout: Duration::from_secs(5),
        transport_timeout: Duration::from_secs(5),
    }
}

/// AnyTLS (spec amendment D8/D9, sing-box): the credential verdict is
/// observed on the wire, and a target failure does NOT look like one.
///
/// - right password → `cmdServerSettings` → `Ok`;
/// - wrong password → the server closes before any session frame → `Failed`
///   (the one shape a rejected secret produces: auth is the first 32 bytes);
/// - right password + a refusing target → `cmdServerSettings` still arrived,
///   so the secret is ACCEPTED (`Ok`); the failure is the target's and no
///   `[cred]` verdict can come from it.
#[tokio::test]
#[ignore = "needs the pinned sing-box (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn anytls_probe_reports_the_credential_verdict() {
    let Some(bin) = singbox_binary() else {
        panic!("no sing-box binary found");
    };
    let certs = generate_certs();
    let case = CaseSpec::anytls();
    case.client_trust(&certs);
    let dir = tempfile::tempdir().expect("tempdir");
    let (target_port, _target) = spawn_http_target();
    let target = std::net::SocketAddr::from(([127, 0, 0, 1], target_port));
    let port = free_port();
    let env = stage_singbox_server(dir.path(), &certs, port, target);
    let config_path = dir.path().join("anytls.json");
    std::fs::write(
        &config_path,
        config::anytls_inbound(CoreKind::SingBox, &env),
    )
    .expect("anytls config");
    let _core = spawn_core(&bin.bin, CoreKind::SingBox, &config_path, port, false);

    let params = config::client_params_anytls(port, target);
    let ok = probe::fetch(params, &probe_request(target_port))
        .await
        .expect("probe through a correct anytls password");
    assert_eq!(ok.status, 200);
    assert_eq!(ok.auth_ack, leas_native::protocol::AuthAck::Ok);

    let mut params = config::client_params_anytls(port, target);
    if let ProtocolConfig::AnyTls(cfg) = &mut params.protocol {
        cfg.password = Some("definitely-not-the-password".into());
    }
    let err = probe::fetch(params, &probe_request(target_port))
        .await
        .expect_err("a wrong password must fail");
    assert_eq!(
        err.auth_ack,
        leas_native::protocol::AuthAck::Failed,
        "a close before any session frame is the credential verdict"
    );

    let refused = free_port();
    let params = config::client_params_anytls(port, target);
    let err = probe::fetch(params, &probe_request(refused))
        .await
        .expect_err("a refusing target must fail");
    assert_eq!(
        err.auth_ack,
        leas_native::protocol::AuthAck::Ok,
        "the server had already accepted the secret; the target failed afterwards"
    );
}

/// Hysteria2 (D9, sing-box): the h3 auth answer is a TYPED rejection —
/// the one family whose refusal is a value, not a close.
#[tokio::test]
#[ignore = "needs the pinned sing-box (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn hysteria2_probe_auth_failure_carries_credential_evidence() {
    let Some(bin) = singbox_binary() else {
        panic!("no sing-box binary found");
    };
    let certs = generate_certs();
    CaseSpec::hysteria2(None).client_trust(&certs);
    let dir = tempfile::tempdir().expect("tempdir");
    let (target_port, _target) = spawn_http_target();
    let target = std::net::SocketAddr::from(([127, 0, 0, 1], target_port));
    let port = free_port();
    let env = stage_singbox_server(dir.path(), &certs, port, target);
    let config_path = dir.path().join("hysteria2.json");
    std::fs::write(&config_path, config::hysteria2_inbound(&env, None)).expect("hysteria2 config");
    let _core = spawn_core(&bin.bin, CoreKind::SingBox, &config_path, port, true);

    let mut params = config::client_params_hysteria2(port, target, None);
    if let ProtocolConfig::Hysteria2(cfg) = &mut params.protocol {
        cfg.auth = "definitely-not-the-password".into();
    }
    let err = probe::fetch(params, &probe_request(target_port))
        .await
        .expect_err("a wrong hysteria2 auth must fail");
    assert_eq!(
        err.error.evidence(),
        Some(leas_native::error::FailureEvidence::CredentialsRejected),
        "the h3 status is the peer's own answer"
    );
}

/// VLESS on sing-box (D8): the response header is written lazily on the first
/// uplink, so a close before it is ALSO a target failure. It must never be
/// `Failed` — a wrong UUID on a working target stays `Unknown`.
#[tokio::test]
#[ignore = "needs the pinned sing-box (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn vless_singbox_silent_close_is_not_credential_evidence() {
    let Some(bin) = singbox_binary() else {
        panic!("no sing-box binary found");
    };
    let certs = generate_certs();
    let dir = tempfile::tempdir().expect("tempdir");
    let (target_port, _target) = spawn_http_target();
    let target = std::net::SocketAddr::from(([127, 0, 0, 1], target_port));
    let port = free_port();
    let case = CaseSpec::vless();
    case.client_trust(&certs);
    let env = stage_singbox_server(dir.path(), &certs, port, target);
    let config_path = dir.path().join("vless.json");
    std::fs::write(&config_path, case.server_config(CoreKind::SingBox, &env))
        .expect("vless config");
    let _core = spawn_core(&bin.bin, CoreKind::SingBox, &config_path, port, false);

    let params = case.client_params(port, target);
    let ok = probe::fetch(params, &probe_request(target_port))
        .await
        .expect("probe through a correct VLESS UUID");
    assert_eq!(
        ok.auth_ack,
        leas_native::protocol::AuthAck::Ok,
        "the peeled response header is the acceptance"
    );

    let mut params = case.client_params(port, target);
    if let ProtocolConfig::Vless(cfg) = &mut params.protocol {
        cfg.uuid = "1c1c1c1c-1c1c-1c1c-1c1c-1c1c1c1c1c1c".into();
    }
    let err = probe::fetch(params, &probe_request(target_port))
        .await
        .expect_err("a wrong UUID must fail");
    assert_eq!(
        err.auth_ack,
        leas_native::protocol::AuthAck::Unknown,
        "a lazy header close is ambiguous: no credential verdict"
    );
}
