//! Real-core smoke for the native probe: one HTTP request through a real
//! xray-core VLESS server to a local HTTP target.
//!
//! This is the only check that exercises the whole probe path against a real
//! core: dial → VLESS handshake → tunnel → HTTP request → response. It needs
//! the xray-core binary (`LEAS_CORE_BIN_DIR` or `~/.config/leas/bin`),
//! so it is `#[ignore]`d — a machine without binaries stays green. Run it with
//!
//! ```text
//! cargo test -p leas-native --test probe_e2e -- --ignored
//! ```

use std::process::{Child, Command};
use std::time::Duration;

use leas_native::addr::TargetAddr;
use leas_native::context::NativeConnectParams;
use leas_native::probe::{self, ProbeMethod, ProbeRequest};
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

/// Resolve a REAL xray-core binary: the managed layout
/// (`bin_dir/<core>/<exe>`, then the dir itself) and PATH are both probed, and
/// each candidate must answer `-version` with an `Xray` banner — a same-named
/// binary from another project must not be mistaken for the core.
fn xray_binary() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let mut dirs: Vec<String> = Vec::new();
    if let Ok(dir) = std::env::var("LEAS_CORE_BIN_DIR") {
        dirs.push(dir);
    }
    // The managed layout the app itself uses (`.cargo/config.toml` exports
    // `LEAS_CORE_BIN_DIR` for the benches, and it may be unpopulated).
    dirs.push(format!("{home}/.config/leas/bin"));
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    for dir in dirs {
        candidates.push(std::path::PathBuf::from(format!("{dir}/xray/xray")));
        candidates.push(std::path::PathBuf::from(format!("{dir}/xray-core/xray")));
        candidates.push(std::path::PathBuf::from(format!("{dir}/xray")));
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|p| p.join("xray")));
    }
    candidates.into_iter().find(|p| is_xray_core(p))
}

/// The `-version` banner is the discriminator: another tool named `xray`
/// (a container-image scanner, say) answers with its own usage text. The core
/// prints its banner on stderr, so both streams are checked.
fn is_xray_core(bin: &std::path::Path) -> bool {
    if !bin.is_file() {
        return false;
    }
    std::process::Command::new(bin)
        .arg("-version")
        .output()
        .is_ok_and(|out| {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            text.contains("Xray")
        })
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
        "outbounds": [{ "protocol": "freedom" }]
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
#[ignore = "needs a real xray-core binary (LEAS_CORE_BIN_DIR or ~/.config/leas/bin)"]
async fn probe_through_real_xray_vless_server() {
    let Some(bin) = xray_binary() else {
        panic!("no xray binary found");
    };
    let (target_port, target) = spawn_http_target();
    let server_port = free_port();
    let (mut child, config_path, log_path) = spawn_xray_server(&bin, server_port);
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
