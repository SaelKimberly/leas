//! E2E: a ws path that needs canonicalization must still complete the upgrade
//! against a REAL xray-core server.
//!
//! Why this file exists rather than a `CaseSpec` row: `CaseSpec::client_params`
//! builds its client config through `config::client_params_*`, which reaches no
//! parser — a ws-path knob there would set `WebSocketConfig.path` directly and
//! bypass the canonicalizer entirely, so the row would stay red for the wrong
//! reason (or pass trivially on a canonical input). These rows therefore build
//! the client config by **parsing a share URL** and routing the result through
//! `normalize_transport` — the same owner the app uses.
//!
//! The invariant being pinned is the server's own comparison
//! (`websocket/hub.go:47`): the DECODED `request.URL.Path` must equal the
//! server's configured path. A green upgrade here is the reference's answer, not
//! a self-consistent unit test's.
//!
//! Needs the xray-core binary (`LEAS_CORE_BIN_DIR` or
//! `~/.config/leas/bin`), so it is `#[ignore]`d — a machine without
//! binaries stays green. Run it with
//!
//! ```text
//! cargo test -p leas-native --test ws_paths -- --ignored
//! ```
//!
//! See `docs/aegis/specs/2026-09-23-ws-path-canonicalization-design.md` §7.5.

use std::process::{Child, Command};
use std::time::Duration;

use leas_native::addr::TargetAddr;
use leas_native::context::NativeConnectParams;
use leas_native::probe::{self, ProbeMethod, ProbeRequest};
use leas_proto::proto_spec::common::TransportConfig;
use leas_proto::proto_spec::endpoint::EndpointEssentials;
use leas_proto::proto_spec::{HostKind, ProtocolConfig};
use leas_proto::urlx::RawUrlX;
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

/// Resolve a REAL xray-core binary (`-version` must answer with an `Xray`
/// banner, so a same-named binary from another project is not mistaken for it).
fn xray_binary() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let mut dirs: Vec<String> = Vec::new();
    if let Ok(dir) = std::env::var("LEAS_CORE_BIN_DIR") {
        dirs.push(dir);
    }
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

/// Start a real xray-core VLESS-over-ws server on `port` with `server_path`
/// configured; returns the child, the config path and the log path.
fn spawn_xray_ws_server(
    bin: &std::path::Path,
    port: u16,
    server_path: &str,
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
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": { "path": server_path }
            }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    });
    let config_path = std::env::temp_dir().join(format!("leas-wspaths-{port}.json"));
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("serialize config"),
    )
    .expect("write config");
    let log_path = std::env::temp_dir().join(format!("leas-wspaths-{port}.log"));
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

/// The stored ws path a share URL yields, after the canonicalizer.
fn canonical_path_of(url: &str) -> Option<String> {
    let mut config = ProtocolConfig::try_parse_proto(&RawUrlX::from(url))
        .expect("share url parses")
        .protocol
        .config;
    config.normalize_transport();
    match config {
        ProtocolConfig::Vless(c) => {
            let transport = match c.transport {
                TransportConfig::Ws(ws) => ws.path.as_deref().map(str::to_owned),
                other => panic!("expected ws transport, got {other:?}"),
            };
            // The mirror `reconstruct_proto` emits must agree with the path the
            // identity hashes: canonicalizing only the transport was the bug
            // this row now covers.
            assert_eq!(
                c.path.as_deref(),
                transport.as_deref(),
                "exported mirror must equal the hashed transport path"
            );
            transport
        }
        other => panic!("expected vless config, got {other:?}"),
    }
}

/// One row: a server configured with `server_path`, dialled by a client whose
/// config is PARSED from a share URL carrying `client_query_path`.
async fn run_row(
    bin: &std::path::Path,
    server_path: &str,
    client_query_path: &str,
    canonical: &str,
) {
    let (target_port, target) = spawn_http_target();
    let server_port = free_port();
    let (mut child, config_path, log_path) = spawn_xray_ws_server(bin, server_port, server_path);
    if !wait_for_port(server_port).await {
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        let _ = child.kill();
        let _ = child.wait();
        panic!("xray-core did not listen on {server_port} (path {server_path:?}); log:\n{log}");
    }

    // The client config comes from the PARSER, not a struct literal — that is
    // the whole point of the row (see the module doc).
    let url = format!(
        "vless://{UUID}@127.0.0.1:{server_port}?type=ws&security=none&path={client_query_path}"
    );
    assert_eq!(
        canonical_path_of(&url).as_deref(),
        Some(canonical),
        "canonicalizer output for server_path {server_path:?}"
    );

    let mut config = ProtocolConfig::try_parse_proto(&RawUrlX::from(url.as_str()))
        .expect("share url parses")
        .protocol
        .config;
    config.normalize_transport();

    let params = NativeConnectParams::new(
        config,
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

    let outcome = probe::fetch(params, &request).await;
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&log_path);
    target.abort();

    let response = outcome.unwrap_or_else(|e| {
        panic!(
            "ws upgrade failed for server_path {server_path:?} (client {client_query_path:?}): {e}"
        )
    });
    assert_eq!(response.status, 200, "server_path {server_path:?}");
    assert_eq!(response.body, b"hello", "server_path {server_path:?}");
}

#[tokio::test]
#[ignore = "needs a real xray-core binary (LEAS_CORE_BIN_DIR or ~/.config/leas/bin)"]
async fn ws_upgrade_survives_a_path_that_needs_canonicalization() {
    let Some(bin) = xray_binary() else {
        panic!("no xray binary found");
    };

    // (server's configured path, the share-url path value as the feed carries
    // it, the canonical form the client must send)
    let rows: &[(&str, &str, &str)] = &[
        // A double-encoded source: RawUrlX decodes the query value once, so the
        // escapes survive into the stored path (the measured feed shape).
        ("/a b", "%252Fa%2520b", "/a%20b"),
        // The single-encoded form of the same path.
        ("/a b", "/a%20b", "/a%20b"),
        // The raw space / emoji the single-encoded source actually leaves.
        (
            "/trTelegram🇨🇳 x",
            "/trTelegram🇨🇳 x",
            "/trTelegram%F0%9F%87%A8%F0%9F%87%B3%20x",
        ),
        // No leading slash: the server's `GetNormalizedPath` prepends it, and
        // so must we, or the two disagree.
        ("trNoSlash", "trNoSlash", "/trNoSlash"),
    ];

    for (server_path, client_path, canonical) in rows {
        run_row(&bin, server_path, client_path, canonical).await;
    }
}
