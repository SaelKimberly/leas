//! E2E: the native SOCKS5 CLIENT through a real sing-box SOCKS5 inbound.
//!
//! The SOCKS5 client (`protocol/socks/mod.rs`) shipped long before the
//! capability gate admitted the kind, so this row is what turns "the code
//! exists" into "the wire works": dial → RFC 1928 greeting → CONNECT → HTTP
//! request → response. It is the oracle the gate flip cites (spec
//! `2026-11-19-probe-truth-and-ingest-boundary` S8).
//!
//! Needs the pinned sing-box binary (`LEAS_CORE_BIN_DIR` or the build.rs
//! fetch), so it is `#[ignore]`d; a machine without binaries stays green. Run
//! it with
//!
//! ```text
//! cargo test -p leas-oracles --test socks5_client_oracle -- --ignored
//! ```

use std::process::{Child, Command};
use std::time::Duration;

use leas_native::addr::TargetAddr;
use leas_native::context::NativeConnectParams;
use leas_native::probe::{self, ProbeMethod, ProbeRequest};
use leas_oracles::e2e::{CoreKind, CoreUnderTest, SINGBOX_VERSION};
use leas_proto::proto_spec::endpoint::EndpointEssentials;
use leas_proto::proto_spec::{HostKind, ProtocolConfig, Socks5Config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// A sing-box SOCKS5 server on `port`, forwarding directly.
fn spawn_singbox_socks_server(bin: &std::path::Path, port: u16) -> (Child, std::path::PathBuf) {
    let config = serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": [{
            "type": "socks",
            "listen": "127.0.0.1",
            "listen_port": port
        }],
        "outbounds": [{ "type": "direct" }]
    });
    let config_path = std::env::temp_dir().join(format!("leas-socks-oracle-{port}.json"));
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("serialize config"),
    )
    .expect("write config");
    let child = Command::new(bin)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("spawn sing-box");
    (child, config_path)
}

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
#[ignore = "needs the pinned sing-box core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn the_native_socks5_client_carries_an_http_request() {
    let bin = CoreUnderTest::resolve(CoreKind::SingBox, SINGBOX_VERSION)
        .expect("resolve sing-box; run with --ignored and LEAS_CORE_BIN_DIR set");
    let (target_port, target) = spawn_http_target();
    let server_port = free_port();
    let (mut child, config_path) = spawn_singbox_socks_server(&bin.bin, server_port);
    if !wait_for_port(server_port).await {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&config_path);
        panic!("sing-box did not listen on {server_port}");
    }

    let params = NativeConnectParams::new(
        ProtocolConfig::Socks(Socks5Config {
            username: None,
            password: None,
            security: Default::default(),
            remarks: None,
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
        .expect("the SOCKS5 client must carry the request end to end");

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&config_path);
    target.abort();

    assert_eq!(
        response.status, 200,
        "the target answered through the tunnel"
    );
    assert!(
        response.body.windows(5).any(|w| w == b"hello"),
        "the target's body came back through the SOCKS5 tunnel"
    );
}
