//! E2E: the native WireGuard client against **real** server cores.
//!
//! The hermetic rows in `tests/wireguard.rs` use a `boringtun` peer. These rows
//! answer the other question: does a pinned production core accept our
//! handshake and carry a request? Each core runs a *userspace* WireGuard
//! endpoint (no TUN, no `CAP_NET_ADMIN`), routes the peer's connection to a
//! `direct`/`freedom` outbound, and that outbound dials a loopback HTTP target
//! on the host — so the destination the client names is `127.0.0.1:port`.
//!
//! Needs the pinned cores (`LEAS_CORE_BIN_DIR` or the build.rs fetch), so the
//! rows are `#[ignore]`d; a machine without binaries stays green. Run with
//!
//! ```text
//! cargo test -p leas-oracles --test wireguard_oracle -- --ignored
//! ```

use std::process::{Child, Command};
use std::time::Duration;

use base64::Engine as _;
use leas_native::addr::TargetAddr;
use leas_native::context::NativeConnectParams;
use leas_native::probe::{self, ProbeMethod, ProbeRequest};
use leas_native::protocol::wireguard::keys::public_key;
use leas_oracles::e2e::{CoreKind, CoreUnderTest, SINGBOX_VERSION, XRAY_VERSION};
use leas_proto::proto_spec::endpoint::EndpointEssentials;
use leas_proto::proto_spec::{HostKind, ProtocolConfig, WireguardConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CLIENT_PRIVATE: [u8; 32] = [0x11; 32];
const SERVER_PRIVATE: [u8; 32] = [0x22; 32];
const CLIENT_ADDRESS: &str = "10.66.0.2/32";
const SERVER_ADDRESS: &str = "10.66.0.1/32";

fn b64(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

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

/// A SOCKS5 server that accepts any CONNECT and then speaks HTTP: xray's
/// `freedom` outbound applies a default "block private IPs" final rule to
/// traffic from a `wireguard` inbound (`proxy/freedom/freedom.go`), so the
/// oracle routes into a SOCKS outbound instead of dialing loopback itself.
fn spawn_socks_stub() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind socks stub");
    let port = listener.local_addr().expect("stub addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let mut buf = [0u8; 512];
            // Greeting: version, methods.
            let Ok(n) = sock.read(&mut buf).await else {
                continue;
            };
            if n < 2 {
                continue;
            }
            let _ = sock.write_all(&[0x05, 0x00]).await;
            // Request: version, cmd, rsv, atyp(len), host, port.
            let Ok(n) = sock.read(&mut buf).await else {
                continue;
            };
            if n < 7 {
                continue;
            }
            let atyp = buf[3];
            let host_len = match atyp {
                0x01 => 4,
                0x03 => usize::from(buf.get(4).copied().unwrap_or(0)) + 1,
                0x04 => 16,
                _ => continue,
            };
            let port_offset = 4 + host_len;
            if n < port_offset + 2 {
                continue;
            }
            let _ = sock
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            // HTTP 200, then close.
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await;
            let _ = sock.shutdown().await;
        }
    });
    (port, handle)
}

fn spawn(
    bin: &std::path::Path,
    args: &[&str],
    config: &serde_json::Value,
) -> (Child, std::path::PathBuf, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("leas-wg-oracle-{}.json", free_port()));
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(config).expect("serialize config"),
    )
    .expect("write config");
    let log = std::env::temp_dir().join(format!("leas-wg-core-{}.log", free_port()));
    let out = std::fs::File::create(&log).expect("core log");
    // xray logs to stdout, sing-box to stderr: both go to the same file.
    let err = out.try_clone().expect("clone log handle");
    let child = Command::new(bin)
        .args(args)
        .arg(&path)
        .stdout(std::process::Stdio::from(out))
        .stderr(std::process::Stdio::from(err))
        .spawn()
        .expect("spawn core");
    eprintln!("core log: {}", log.display());
    (child, path, log)
}

/// The address the client dials. It must be the endpoint's OWN tunnel address,
/// or the server's userspace netstack drops the packet instead of terminating
/// it; the server then redirects that connection to a loopback echo (neither
/// core can dial 10.66.0.1 on the host without a TUN).
const TUNNEL_TARGET: &str = "10.66.0.1";

fn client_params(server_port: u16) -> NativeConnectParams {
    let cfg = WireguardConfig {
        private_key: b64(&CLIENT_PRIVATE),
        security: Default::default(),
        address: CLIENT_ADDRESS.into(),
        public_key: b64(&public_key(&SERVER_PRIVATE)),
        preshared_key: None,
        reserved: None,
        mtu: Some("1420".into()),
        persistent_keepalive: None,
        dns: None,
        remote_dns_resolve: None,
        remarks: None,
    };
    NativeConnectParams::new(
        ProtocolConfig::Wireguard(cfg),
        EndpointEssentials {
            host: "127.0.0.1".to_string(),
            host_type: HostKind::Ipv4,
            port: server_port,
            ports: Vec::new(),
        },
        TargetAddr::new(TUNNEL_TARGET, 80),
    )
}

fn request() -> ProbeRequest<'static> {
    ProbeRequest {
        host: TUNNEL_TARGET,
        port: 80,
        https: false,
        method: ProbeMethod::Get,
        path: "/",
        timeout: Duration::from_secs(8),
        transport_timeout: Duration::from_secs(8),
    }
}

/// The server's userspace WireGuard endpoint routes the peer's connection to
/// `direct`; the retry loop covers the core's startup without a UDP readiness
/// probe (a TCP connect cannot see a WireGuard listener).
async fn fetch_with_retries(params: &NativeConnectParams) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..20 {
        match probe::fetch(params.clone(), &request()).await {
            Ok(_) => return Ok(()),
            Err(error) => {
                last = error.to_string();
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    Err(last)
}

#[tokio::test]
#[ignore = "needs the pinned sing-box core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn sing_box_wireguard_endpoint_carries_a_request() {
    let bin = CoreUnderTest::resolve(CoreKind::SingBox, SINGBOX_VERSION)
        .expect("resolve sing-box; run with --ignored");
    let (target_port, _target) = spawn_http_target();
    let server_port = free_port();
    // `endpoints` (not `inbounds`) is sing-box's WireGuard server shape;
    // `system: false` keeps it in gVisor, so no TUN and no privileges.
    let config = serde_json::json!({
        "log": { "level": "debug", "timestamp": true },
        "endpoints": [{
            "type": "wireguard",
            "tag": "wg",
            "system": false,
            "address": [SERVER_ADDRESS],
            "private_key": b64(&SERVER_PRIVATE),
            "listen_port": server_port,
            "peers": [{
                "public_key": b64(&public_key(&CLIENT_PRIVATE)),
                "allowed_ips": [CLIENT_ADDRESS],
            }],
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        // 1.11+ spelling: the per-connection redirect is a route action, not a
        // direct-outbound field (removed in 1.13).
        "route": { "rules": [{
            "action": "route",
            "outbound": "direct",
            "override_address": "127.0.0.1",
            "override_port": target_port,
        }] },
    });
    let (mut child, config_path, log) = spawn(&bin.bin, &["run", "-c"], &config);

    let result = fetch_with_retries(&client_params(server_port)).await;

    let _ = child.kill();
    let _ = child.wait();
    if let Ok(text) = std::fs::read_to_string(&log) {
        eprintln!("--- core log ---\n{text}");
    }
    let _ = std::fs::remove_file(&config_path);
    result.expect("a real sing-box WireGuard endpoint must carry the request");
}

#[tokio::test]
#[ignore = "needs the pinned xray-core binary (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn xray_wireguard_inbound_carries_a_request() {
    let bin = CoreUnderTest::resolve(CoreKind::Xray, XRAY_VERSION)
        .expect("resolve xray; run with --ignored");
    let (socks_port, _stub) = spawn_socks_stub();
    let server_port = free_port();
    // xray registers `wireguard` as an inbound protocol too (`IsClient: false`);
    // `noKernelTun` keeps it on the userspace netstack.
    let config = serde_json::json!({
        "log": { "loglevel": "debug" },
        "inbounds": [{
            "protocol": "wireguard",
            "port": server_port,
            "settings": {
                "noKernelTun": true,
                "secretKey": b64(&SERVER_PRIVATE),
                "address": [SERVER_ADDRESS],
                "mtu": 1420,
                "peers": [{
                    "publicKey": b64(&public_key(&CLIENT_PRIVATE)),
                    "allowedIPs": [CLIENT_ADDRESS],
                }],
            },
        }],
        // freedom blocks a wireguard inbound's private targets by default
        // (`defaultBlockPrivateRule`), and the loopback echo is private; a SOCKS
        // outbound dials its own server without that rule.
        "outbounds": [{
            "protocol": "socks",
            "settings": { "servers": [{ "address": "127.0.0.1", "port": socks_port }] },
        }],
    });
    let (mut child, config_path, log) = spawn(&bin.bin, &["-c"], &config);

    let result = fetch_with_retries(&client_params(server_port)).await;

    let _ = child.kill();
    let _ = child.wait();
    if let Ok(text) = std::fs::read_to_string(&log) {
        eprintln!("--- core log ---\n{text}");
    }
    let _ = std::fs::remove_file(&config_path);
    result.expect("a real xray WireGuard inbound must carry the request");
}
