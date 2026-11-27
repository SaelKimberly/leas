//! E2E: the native WireGuard stack against the pinned **sing-box** endpoint.
//!
//! These rows replaced a `boringtun` test peer once the real-core oracle
//! proved interop: the server is sing-box's userspace WireGuard endpoint
//! (`system: false`, gVisor netstack — no TUN, no `CAP_NET_ADMIN`), and a 1.11
//! route action overrides the peer's destination onto a loopback echo. They
//! cover the driver — TCP/UDP flows, transfers, backpressure, half-close, loss
//! recovery and keepalives — which the core-independent unit rows cannot.
//!
//! Needs the pinned core (`LEAS_CORE_BIN_DIR` or the build.rs fetch), so every
//! row is `#[ignore]`d; a machine without binaries stays green. Run with
//!
//! ```text
//! cargo test -p leas-oracles --test wireguard -- --ignored
//! ```

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use leas_native::protocol::wireguard::core::device::Tunnel as ClientTunnel;
use leas_native::protocol::wireguard::keys::public_key;
use leas_native::protocol::wireguard::stack::{PacketLink, StackConfig, WgLink, WgStack};
use leas_oracles::e2e::{CoreKind, CoreUnderTest, SINGBOX_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const CLIENT_PRIVATE: [u8; 32] = [0x11; 32];
const SERVER_PRIVATE: [u8; 32] = [0x22; 32];
const CLIENT_ADDRESS: &str = "10.66.0.2/32";
const SERVER_ADDRESS: &str = "10.66.0.1/32";
// The destination the client names is the endpoint's OWN tunnel address
// (`target()` below): any other address is dropped by the userspace netstack.

fn b64(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// A sing-box WireGuard endpoint plus a loopback echo on the override port.
struct Server {
    port: u16,
    echo_port: u16,
    child: Child,
    config: std::path::PathBuf,
    #[expect(dead_code, reason = "kept for post-mortem; Drop reaps the process")]
    log: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            // Keep the evidence for a red row: config + core log.
            eprintln!(
                "--- config {}\n{}",
                self.config.display(),
                std::fs::read_to_string(&self.config).unwrap_or_default()
            );
            eprintln!(
                "--- core log {}\n{}",
                self.log.display(),
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
        } else {
            let _ = std::fs::remove_file(&self.config);
        }
    }
}

/// TCP echo: repeat what arrives until EOF, close. `half_close` closes the
/// server's write side after the first payload (a remote FIN).
async fn tcp_echo(listener: TcpListener, half_close: bool) {
    loop {
        let Ok((mut sock, peer)) = listener.accept().await else {
            break;
        };
        eprintln!("echo: accepted {peer}");
        tokio::spawn(async move {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let Ok(n) = sock.read(&mut buf).await else {
                    break;
                };
                if n == 0 {
                    break;
                }
                if sock.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                if half_close {
                    // Remote FIN after the first payload: the client must see
                    // EOF on the read side while its write side stays usable.
                    let _ = sock.shutdown().await;
                    let _ = sock.read(&mut buf).await;
                    break;
                }
            }
        });
    }
}

async fn udp_echo(socket: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else {
            break;
        };
        let _ = socket.send_to(&buf[..n], from).await;
    }
}

/// Echo listeners on one free port (TCP and UDP share the number, because the
/// route override names a single port). Rows run concurrently, so the port is
/// picked per test.
fn spawn_echoes(half_close: bool) -> u16 {
    for _ in 0..32 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp echo");
        let port = listener.local_addr().expect("tcp echo addr").port();
        let Ok(udp) = std::net::UdpSocket::bind(("127.0.0.1", port)) else {
            continue;
        };
        listener.set_nonblocking(true).expect("nonblocking");
        udp.set_nonblocking(true).expect("nonblocking");
        let tcp = TcpListener::from_std(listener).expect("tokio listener");
        tokio::spawn(tcp_echo(tcp, half_close));
        let udp = Arc::new(UdpSocket::from_std(udp).expect("tokio udp"));
        tokio::spawn(udp_echo(udp));
        return port;
    }
    panic!("no free TCP+UDP echo port");
}

async fn start_singbox(half_close: bool) -> Server {
    let bin = CoreUnderTest::resolve(CoreKind::SingBox, SINGBOX_VERSION)
        .expect("resolve sing-box; run with --ignored");
    let echo_port = spawn_echoes(half_close);
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral");
        probe.local_addr().expect("addr").port()
    };
    let config = serde_json::json!({
        "log": { "level": "debug" },
        "endpoints": [{
            "type": "wireguard",
            "tag": "wg",
            "system": false,
            "address": [SERVER_ADDRESS],
            "private_key": b64(&SERVER_PRIVATE),
            "listen_port": port,
            "peers": [{
                "public_key": b64(&public_key(&CLIENT_PRIVATE)),
                "allowed_ips": [CLIENT_ADDRESS],
            }],
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "rules": [{
            "action": "route",
            "outbound": "direct",
            "override_address": "127.0.0.1",
            "override_port": echo_port,
        }] },
    });
    let config_path = std::env::temp_dir().join(format!("leas-wg-peer-{port}.json"));
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("serialize"),
    )
    .expect("write config");
    let log_path = std::env::temp_dir().join(format!("leas-wg-peer-{port}.log"));
    let log = std::fs::File::create(&log_path).expect("log");
    let err = log.try_clone().expect("clone log");
    let child = Command::new(&bin.bin)
        .args(["run", "-c"])
        .arg(&config_path)
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(err))
        .spawn()
        .expect("spawn sing-box");
    let server = Server {
        port,
        echo_port,
        child,
        config: config_path,
        log: log_path,
    };
    // A connected UDP socket sees ICMP port-unreachable until the endpoint
    // binds its port; wait for the core's own start line so a row never races
    // the boot.
    for _ in 0..200 {
        if std::fs::read_to_string(&server.log)
            .is_ok_and(|text| text.contains("sing-box started") || text.contains("started"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    server
}

impl Server {
    fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    #[expect(dead_code, reason = "diagnostic on a red row; the log path is kept")]
    fn dump_log(&self) {
        if let Ok(text) = std::fs::read_to_string(&self.log) {
            eprintln!("--- sing-box log ({}):\n{text}", self.log.display());
        }
    }
}

/// A UDP relay in front of the core: counts datagrams in both directions and
/// can drop every Nth one (loss) or all server→client ones (a silent peer).
struct RelayStats {
    from_client: AtomicUsize,
    from_server: AtomicUsize,
}

struct Relay {
    stats: Arc<RelayStats>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_relay(
    core: SocketAddr,
    drop_every: Option<usize>,
    mute_server: bool,
) -> (SocketAddr, Relay) {
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind relay");
    let local = listener.local_addr().expect("relay addr");
    listener.set_nonblocking(true).expect("nonblocking");
    let socket = Arc::new(UdpSocket::from_std(listener).expect("tokio relay"));
    let stats = Arc::new(RelayStats {
        from_client: AtomicUsize::new(0),
        from_server: AtomicUsize::new(0),
    });
    let up = Arc::clone(&socket);
    let core_up = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("relay up socket");
    core_up.connect(core).await.expect("relay upstream connect");
    let stats_up = Arc::clone(&stats);
    let task = tokio::spawn(async move {
        let mut client: Option<SocketAddr> = None;
        let mut from_client_buf = vec![0u8; 64 * 1024];
        let mut from_server_buf = vec![0u8; 64 * 1024];
        let mut seen = 0usize;
        loop {
            tokio::select! {
                received = up.recv_from(&mut from_client_buf) => {
                    let Ok((n, from)) = received else { break };
                    client = Some(from);
                    seen += 1;
                    let dropped = drop_every.is_some_and(|every| seen.is_multiple_of(every));
                    if !dropped {
                        let _ = core_up.send(&from_client_buf[..n]).await;
                        stats_up.from_client.fetch_add(1, Ordering::Relaxed);
                    }
                }
                received = core_up.recv(&mut from_server_buf) => {
                    let Ok(n) = received else { break };
                    if !mute_server
                        && let Some(to) = client
                    {
                        let _ = up.send_to(&from_server_buf[..n], to).await;
                        stats_up.from_server.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    });
    (local, Relay { stats, task })
}

fn client_tunnel(keepalive: u16) -> ClientTunnel {
    ClientTunnel::new(
        zeroize::Zeroizing::new(CLIENT_PRIVATE),
        public_key(&SERVER_PRIVATE),
        None,
        1420,
        [0u8; 3],
        7,
        keepalive,
    )
    .expect("client tunnel")
}

async fn client_link(server: SocketAddr, keepalive: u16) -> WgLink {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    socket.connect(server).await.expect("connect client");
    WgLink::new(socket, client_tunnel(keepalive))
}

fn stack(link: impl PacketLink) -> Arc<WgStack> {
    let addresses = vec![CLIENT_ADDRESS.parse().expect("client cidr")];
    Arc::new(WgStack::start(link, StackConfig::new(addresses, 1420)).expect("stack"))
}

/// A client stack attached to `server`, with a short readiness retry (a TCP
/// connect cannot see the core's UDP listener).
async fn stack_for(server: &Server, keepalive: u16) -> Arc<WgStack> {
    let link = client_link(server.addr(), keepalive).await;
    stack(link)
}

/// Port 80 on the endpoint's own address: the route action's `override_port`
/// is what lands the connection on the echo, so the original port is nominal.
fn target() -> SocketAddr {
    SocketAddr::from(([10, 66, 0, 1], 80))
}

async fn connect(stack: &Arc<WgStack>) -> leas_native::protocol::wireguard::stack::TcpFlow {
    stack
        .connect_tcp(target())
        .await
        .expect("connect through the tunnel")
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the pinned sing-box core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn tcp_echo_round_trips_through_a_real_core() {
    let server = start_singbox(false).await;
    let stack = stack_for(&server, 0).await;
    let mut flow = connect(&stack).await;
    flow.write_all(b"hello wireguard").await.expect("write");
    let mut echo = [0u8; 15];
    tokio::time::timeout(Duration::from_secs(10), flow.read_exact(&mut echo))
        .await
        .expect("the echo arrives")
        .expect("read");
    assert_eq!(&echo, b"hello wireguard");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the pinned sing-box core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn a_large_transfer_arrives_intact() {
    let server = start_singbox(false).await;
    let stack = stack_for(&server, 0).await;
    let flow = connect(&stack).await;
    let (mut read_half, mut write_half) = tokio::io::split(flow);
    let payload: Vec<u8> = (0..128 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let writer = tokio::spawn(async move {
        write_half.write_all(&payload).await.expect("write");
        write_half.shutdown().await.expect("shutdown");
    });
    let mut echo = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(30), read_half.read_exact(&mut echo))
        .await
        .expect("the echo arrives")
        .expect("read");
    writer.await.expect("writer");
    assert_eq!(echo, expected);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the pinned sing-box core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn udp_datagrams_round_trip() {
    let server = start_singbox(false).await;
    let stack = stack_for(&server, 0).await;
    let flow = stack.open_udp().await.expect("open an association");
    let (mut reader, writer) = flow.split();
    const COUNT: u8 = 8;
    for i in 0..COUNT {
        writer.send_to(target(), &[i; 16]).expect("queue datagram");
    }
    let mut seen = 0usize;
    while seen < usize::from(COUNT) {
        let datagram = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("a reply arrives")
            .expect("the association is open");
        assert_eq!(datagram.1, vec![seen as u8; 16], "reply {seen} content");
        seen += 1;
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the pinned sing-box core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn tcp_echo_survives_packet_loss() {
    let server = start_singbox(false).await;
    let (relay, _guard) = spawn_relay(server.addr(), Some(5), false).await;
    let stack = stack(client_link(relay, 0).await);
    let flow = connect(&stack).await;
    let payload: Vec<u8> = (0..32 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let (mut read_half, mut write_half) = tokio::io::split(flow);
    let writer = tokio::spawn(async move {
        write_half.write_all(&payload).await.expect("write");
        write_half.shutdown().await.expect("shutdown");
    });
    let mut echo = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(30), read_half.read_exact(&mut echo))
        .await
        .expect("the echo arrives despite loss")
        .expect("read");
    writer.await.expect("writer");
    assert_eq!(echo, expected);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the pinned sing-box core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn keepalives_leave_an_idle_tunnel() {
    let server = start_singbox(false).await;
    let (relay, guard) = spawn_relay(server.addr(), None, false).await;
    let stack = stack(client_link(relay, 1).await);
    let mut flow = connect(&stack).await;
    flow.write_all(b"x").await.expect("write");
    let mut byte = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), flow.read_exact(&mut byte))
        .await
        .expect("the echo arrives")
        .expect("read");
    drop(flow);
    let before = guard.stats.from_client.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let after = guard.stats.from_client.load(Ordering::Relaxed);
    assert!(
        after > before,
        "persistent_keepalive=1 must put datagrams on the wire while idle (before={before}, after={after})"
    );
}

/// The passive keepalive (`KEEPALIVE_TIMEOUT`, 10 s after a receive) must reach
/// the wire with no periodic keepalive configured: the tunnel's own timer is
/// the only wake, so a driver that does not flush after `poll` strands it.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the pinned sing-box core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn a_passive_keepalive_leaves_an_idle_tunnel() {
    let server = start_singbox(false).await;
    let (relay, guard) = spawn_relay(server.addr(), None, false).await;
    let stack = stack(client_link(relay, 0).await);
    let mut flow = connect(&stack).await;
    flow.write_all(b"x").await.expect("write");
    let mut byte = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), flow.read_exact(&mut byte))
        .await
        .expect("the echo arrives")
        .expect("read");
    drop(flow);
    let before = guard.stats.from_client.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(11)).await;
    let after = guard.stats.from_client.load(Ordering::Relaxed);
    assert!(
        after > before,
        "the 10 s passive keepalive must leave the link (before={before}, after={after})"
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the pinned sing-box core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn a_handshake_retransmit_leaves_a_silent_tunnel() {
    let server = start_singbox(false).await;
    // The relay drops every server→client datagram: only the client's own
    // timers can produce the second initiation.
    let (relay, guard) = spawn_relay(server.addr(), None, true).await;
    let stack = stack(client_link(relay, 0).await);
    let _flow = stack.connect_tcp(target()).await.expect("socket opens");
    tokio::time::sleep(Duration::from_millis(6500)).await;
    let sent = guard.stats.from_client.load(Ordering::Relaxed);
    assert!(
        sent >= 2,
        "the 5 s retransmit must leave the client (sent={sent})"
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the pinned sing-box core (build.rs fetch or LEAS_CORE_BIN_DIR)"]
async fn a_remote_fin_ends_reads_but_not_writes() {
    let server = start_singbox(true).await;
    let stack = stack_for(&server, 0).await;
    let mut flow = connect(&stack).await;
    flow.write_all(b"hi").await.expect("write");
    let mut echo = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), flow.read_exact(&mut echo))
        .await
        .expect("the echo arrives")
        .expect("read");
    let mut eof = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), flow.read(&mut eof))
        .await
        .expect("EOF arrives");
    assert!(matches!(read, Ok(0)), "remote FIN is EOF, got {read:?}");
    tokio::time::timeout(Duration::from_secs(2), flow.write_all(b"tail"))
        .await
        .expect("the write is accepted")
        .expect("no broken pipe");
}
