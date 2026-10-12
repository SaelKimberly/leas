//! Integration tests for the SOCKS5 inbound: full accept → route → outbound
//! flows over real TCP.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use leas_route::ir::{
    Action, Cond, DefaultRoute, MatchItem, RejectMethod, ResolveStrategy, Rule, RuleSet,
};
use leas_route::{Engine, NetAddr, NetHost};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::outbound::OutboundKind;
use super::{Outbound, Socks5Inbound, Socks5InboundConfig};
use crate::addr::{Host, TargetAddr};

// Helpers
// *****************************************************************************

fn engine(rules: Vec<Rule>, default: DefaultRoute) -> Arc<Engine> {
    Arc::new(
        Engine::build(RuleSet {
            rules,
            default,
            resolve_strategy: ResolveStrategy::AsIs,
            probes: Vec::new(),
        })
        .expect("engine builds"),
    )
}

fn route_default(tag: &str) -> DefaultRoute {
    DefaultRoute::Route {
        tag: tag.to_owned(),
    }
}

fn block_domain(domain: &str) -> Rule {
    Rule {
        name: None,
        cond: Cond::All(vec![MatchItem::Domain {
            exact: vec![domain.to_owned()],
            suffix: Vec::new(),
            keywords: Vec::new(),
            regexes: Vec::new(),
        }]),
        action: Action::Route {
            tag: "block".to_owned(),
            override_addr: None,
        },
    }
}

async fn spawn_inbound(config: Socks5InboundConfig) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let inbound = Socks5Inbound::bind(config).await.expect("bind inbound");
    let addr = inbound.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = inbound.serve().await;
    });
    (addr, handle)
}

/// A TCP echo server; returns its bound address.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo listener");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Outcome of a test SOCKS5 client connection attempt.
enum ClientResult {
    /// The server refused authentication (RFC 1929 status ≠ 0).
    AuthRejected,
    /// The server replied to the CONNECT request with `code`.
    Connected { code: u8, stream: TcpStream },
}

/// A minimal SOCKS5 client: greeting, optional RFC 1929 auth, CONNECT.
async fn client_connect(
    addr: SocketAddr,
    auth: Option<(&str, &str)>,
    target: &TargetAddr,
) -> ClientResult {
    let mut stream = TcpStream::connect(addr).await.expect("connect to inbound");
    let mut methods = vec![0x00u8];
    if auth.is_some() {
        methods.push(0x02);
    }
    stream
        .write_all(&[0x05, u8::try_from(methods.len()).expect("methods ≤ 255")])
        .await
        .expect("greeting header");
    stream.write_all(&methods).await.expect("greeting methods");
    let mut selection = [0u8; 2];
    stream
        .read_exact(&mut selection)
        .await
        .expect("method selection");
    assert_eq!(selection[0], 0x05, "method selection version");

    if selection[1] == 0x02 {
        let (user, pass) = auth.expect("auth offered but no credentials given");
        stream
            .write_all(&[0x01, u8::try_from(user.len()).expect("user ≤ 255")])
            .await
            .expect("auth header");
        stream.write_all(user.as_bytes()).await.expect("auth user");
        stream
            .write_all(&[u8::try_from(pass.len()).expect("pass ≤ 255")])
            .await
            .expect("auth pass len");
        stream.write_all(pass.as_bytes()).await.expect("auth pass");
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).await.expect("auth status");
        assert_eq!(status[0], 0x01, "auth subnegotiation version");
        if status[1] != 0 {
            return ClientResult::AuthRejected;
        }
    }

    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("request head");
    write_target(&mut stream, target).await;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.expect("reply head");
    assert_eq!(head[0], 0x05, "reply version");
    assert_eq!(head[2], 0x00, "reply reserved");
    skip_reply_addr(&mut stream, head[3]).await;
    ClientResult::Connected {
        code: head[1],
        stream,
    }
}

async fn write_target<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S, target: &TargetAddr) {
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            stream.write_all(&[0x01]).await.expect("atyp v4");
            stream.write_all(&ip.octets()).await.expect("ipv4");
        }
        Host::Ip(IpAddr::V6(ip)) => {
            stream.write_all(&[0x04]).await.expect("atyp v6");
            stream.write_all(&ip.octets()).await.expect("ipv6");
        }
        Host::Domain(domain) => {
            stream
                .write_all(&[0x03, u8::try_from(domain.len()).expect("domain ≤ 255")])
                .await
                .expect("atyp domain");
            stream.write_all(domain.as_bytes()).await.expect("domain");
        }
    }
    stream
        .write_all(&target.port.to_be_bytes())
        .await
        .expect("port");
}

async fn skip_reply_addr<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, atyp: u8) {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 4 + 2];
            stream.read_exact(&mut buf).await.expect("bnd v4");
        }
        0x04 => {
            let mut buf = [0u8; 16 + 2];
            stream.read_exact(&mut buf).await.expect("bnd v6");
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.expect("bnd domain len");
            let mut buf = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut buf).await.expect("bnd domain");
        }
        other => panic!("unexpected reply atyp {other}"),
    }
}

// Tests
// *****************************************************************************

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_relay_echoes() {
    let echo = spawn_echo().await;
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    );
    let (addr, handle) = spawn_inbound(config).await;

    let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
    let ClientResult::Connected { code, mut stream } = client_connect(addr, None, &target).await
    else {
        panic!("expected CONNECT success");
    };
    assert_eq!(code, 0x00, "reply code");

    stream.write_all(b"hello socks5").await.expect("write");
    let mut buf = [0u8; 12];
    stream.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, b"hello socks5");

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_outbound_replies_not_allowed() {
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("block")),
        vec![Outbound {
            tag: "block".into(),
            kind: OutboundKind::Block,
        }],
    );
    let (addr, handle) = spawn_inbound(config).await;

    let target = TargetAddr::new(Host::new("93.184.216.34"), 80);
    let ClientResult::Connected { code, .. } = client_connect(addr, None, &target).await else {
        panic!("expected a reply");
    };
    assert_eq!(code, 0x02, "ConnectionNotAllowed");

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_rule_routes_block_and_direct() {
    let echo = spawn_echo().await;
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(
            vec![block_domain("blocked.example")],
            route_default("direct"),
        ),
        vec![
            Outbound {
                tag: "direct".into(),
                kind: OutboundKind::Direct,
            },
            Outbound {
                tag: "block".into(),
                kind: OutboundKind::Block,
            },
        ],
    );
    let (addr, handle) = spawn_inbound(config).await;

    let blocked = TargetAddr::new(Host::Domain("blocked.example".into()), 80);
    let ClientResult::Connected { code, .. } = client_connect(addr, None, &blocked).await else {
        panic!("expected a reply for blocked domain");
    };
    assert_eq!(code, 0x02, "blocked domain");

    let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
    let ClientResult::Connected { code, mut stream } = client_connect(addr, None, &target).await
    else {
        panic!("expected CONNECT success for unblocked target");
    };
    assert_eq!(code, 0x00, "unblocked target");
    stream.write_all(b"ping").await.expect("write");
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, b"ping");

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reject_rule_replies_not_allowed() {
    let rule = Rule {
        name: None,
        cond: Cond::All(vec![MatchItem::Ports(vec![leas_route::addr::PortRange {
            start: 80,
            end: 80,
        }])]),
        action: Action::Reject {
            method: RejectMethod::Drop,
        },
    };
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(vec![rule], route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    );
    let (addr, handle) = spawn_inbound(config).await;

    let target = TargetAddr::new(Host::new("93.184.216.34"), 80);
    let ClientResult::Connected { code, .. } = client_connect(addr, None, &target).await else {
        panic!("expected a reply");
    };
    assert_eq!(code, 0x02, "ConnectionNotAllowed");

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn override_addr_rewrites_target() {
    let echo = spawn_echo().await;
    let rule = Rule {
        name: None,
        cond: Cond::All(vec![MatchItem::Domain {
            exact: vec!["rewritten.example".into()],
            suffix: Vec::new(),
            keywords: Vec::new(),
            regexes: Vec::new(),
        }]),
        action: Action::Route {
            tag: "direct".into(),
            override_addr: Some(NetAddr {
                host: NetHost::Ip("127.0.0.1".parse().expect("ip")),
                port: echo.port(),
            }),
        },
    };
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(vec![rule], route_default("block")),
        vec![
            Outbound {
                tag: "direct".into(),
                kind: OutboundKind::Direct,
            },
            Outbound {
                tag: "block".into(),
                kind: OutboundKind::Block,
            },
        ],
    );
    let (addr, handle) = spawn_inbound(config).await;

    // The request asks for rewritten.example:9999, but the rule rewrites the
    // target to the local echo server before dialing.
    let target = TargetAddr::new(Host::Domain("rewritten.example".into()), 9999);
    let ClientResult::Connected { code, mut stream } = client_connect(addr, None, &target).await
    else {
        panic!("expected CONNECT success");
    };
    assert_eq!(code, 0x00, "rewritten target dialed");
    stream.write_all(b"rewrite").await.expect("write");
    let mut buf = [0u8; 7];
    stream.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, b"rewrite");

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_outbound_tag_replies_general_failure() {
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("missing")),
        Vec::new(), // no outbound tagged "missing"
    );
    let (addr, handle) = spawn_inbound(config).await;

    let target = TargetAddr::new(Host::new("127.0.0.1"), 1);
    let ClientResult::Connected { code, .. } = client_connect(addr, None, &target).await else {
        panic!("expected a reply");
    };
    assert_eq!(code, 0x01, "GeneralFailure");

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_required_accepts_good_credentials() {
    let echo = spawn_echo().await;
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    )
    .with_auth("user", "pass");
    let (addr, handle) = spawn_inbound(config).await;

    let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
    let ClientResult::Connected { code, mut stream } =
        client_connect(addr, Some(("user", "pass")), &target).await
    else {
        panic!("expected CONNECT success");
    };
    assert_eq!(code, 0x00, "authenticated connect");
    stream.write_all(b"hi").await.expect("write");
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, b"hi");

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_required_rejects_bad_credentials() {
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    )
    .with_auth("user", "pass");
    let (addr, handle) = spawn_inbound(config).await;

    let target = TargetAddr::new(Host::new("127.0.0.1"), 1);
    let result = client_connect(addr, Some(("user", "wrong")), &target).await;
    assert!(
        matches!(result, ClientResult::AuthRejected),
        "bad credentials must be refused"
    );

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bind_command_is_unsupported() {
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    );
    let (addr, handle) = spawn_inbound(config).await;

    let mut stream = TcpStream::connect(addr).await.expect("connect to inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await.expect("selection");
    assert_eq!(selection, [0x05, 0x00]);

    // BIND command to 127.0.0.1:0.
    stream
        .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
        .await
        .expect("bind request");
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.expect("reply head");
    assert_eq!(head[0], 0x05, "reply version");
    assert_eq!(head[1], 0x07, "CommandNotSupported");
    skip_reply_addr(&mut stream, head[3]).await;

    handle.abort();
}

// UDP ASSOCIATE tests
// *****************************************************************************

use std::time::Duration;
use tokio::net::UdpSocket;

use super::socks5;

/// A UDP echo server; returns its bound address.
async fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let addr = sock.local_addr().expect("udp echo addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// Open a no-auth SOCKS5 UDP ASSOCIATE with the inbound. Returns the
/// controlling TCP stream and the reply (client-facing) UDP address.
async fn udp_associate(inbound: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut stream = TcpStream::connect(inbound)
        .await
        .expect("connect to inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await.expect("selection");
    assert_eq!(selection, [0x05, 0x00], "no-auth selected");
    // UDP ASSOCIATE with an all-zero DST (the server ignores it).
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate request");
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.expect("reply head");
    assert_eq!(head[0], 0x05, "reply version");
    assert_eq!(head[1], 0x00, "associate succeeded");
    assert_eq!(head[3], 0x01, "v4 bind address");
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await.expect("bnd addr");
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(bnd[0], bnd[1], bnd[2], bnd[3]));
    let port = u16::from_be_bytes([bnd[4], bnd[5]]);
    assert_ne!(port, 0, "BND.PORT is the bound relay port");
    (stream, SocketAddr::new(ip, port))
}

/// The datagram wire bytes for one UDP datagram to `target`.
fn udp_datagram(target: &TargetAddr, frag: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = socks5::new_udp_header(target);
    packet[2] = frag;
    packet.extend_from_slice(payload);
    packet
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_associate_relays_datagrams_direct() {
    let echo = spawn_udp_echo().await;
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    );
    let (addr, handle) = spawn_inbound(config).await;
    let (stream, reply) = udp_associate(addr).await;

    let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");
    let packet = udp_datagram(&target, 0, b"ping udp");
    sock.send_to(&packet, reply).await.expect("send datagram");

    let mut buf = vec![0u8; 2048];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .expect("echo reply timed out")
        .expect("recv reply");
    let (frag, rtarget, payload) = socks5::parse_udp_request(&buf[..n]).expect("reply header");
    assert_eq!(frag, 0);
    assert_eq!(
        rtarget.port,
        echo.port(),
        "reply header names the echo server"
    );
    assert_eq!(payload, b"ping udp");

    drop(stream);
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_fragmented_datagram_is_dropped() {
    let echo = spawn_udp_echo().await;
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    );
    let (addr, handle) = spawn_inbound(config).await;
    let (stream, reply) = udp_associate(addr).await;
    let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");

    // A fragmented datagram must be discarded, not forwarded.
    let packet = udp_datagram(&target, 1, b"drop me");
    sock.send_to(&packet, reply)
        .await
        .expect("send frag datagram");
    // Give a wrong-path forward time to surface; then a clean datagram still
    // relays (association is unaffected by the dropped fragment).
    let mut probe = vec![0u8; 64];
    let wrong = tokio::time::timeout(Duration::from_millis(150), sock.recv_from(&mut probe)).await;
    assert!(
        wrong.is_err(),
        "fragmented datagram must not produce a reply"
    );

    let clean = udp_datagram(&target, 0, b"ping");
    sock.send_to(&clean, reply)
        .await
        .expect("send clean datagram");
    let mut buf = vec![0u8; 2048];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .expect("echo reply timed out")
        .expect("recv reply");
    let (_, _, payload) = socks5::parse_udp_request(&buf[..n]).expect("reply header");
    assert_eq!(payload, b"ping");

    drop(stream);
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_blocked_datagram_is_dropped_and_association_survives() {
    let echo = spawn_udp_echo().await;
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(
            vec![block_domain("blocked.example")],
            route_default("direct"),
        ),
        vec![
            Outbound {
                tag: "direct".into(),
                kind: OutboundKind::Direct,
            },
            Outbound {
                tag: "block".into(),
                kind: OutboundKind::Block,
            },
        ],
    );
    let (addr, handle) = spawn_inbound(config).await;
    let (stream, reply) = udp_associate(addr).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");

    // A datagram to the blocked domain is dropped.
    let blocked = TargetAddr::new(Host::Domain("blocked.example".into()), 53);
    let packet = udp_datagram(&blocked, 0, b"blocked query");
    sock.send_to(&packet, reply)
        .await
        .expect("send blocked datagram");
    let mut probe = vec![0u8; 64];
    let nothing =
        tokio::time::timeout(Duration::from_millis(150), sock.recv_from(&mut probe)).await;
    assert!(
        nothing.is_err(),
        "blocked datagram must not produce a reply"
    );

    // The association is still alive for a routed destination.
    let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
    sock.send_to(&udp_datagram(&target, 0, b"ping"), reply)
        .await
        .expect("send datagram");
    let mut buf = vec![0u8; 2048];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .expect("echo reply timed out")
        .expect("recv reply");
    let (_, _, payload) = socks5::parse_udp_request(&buf[..n]).expect("reply header");
    assert_eq!(payload, b"ping");

    drop(stream);
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_associate_ends_when_control_connection_closes() {
    let echo = spawn_udp_echo().await;
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    );
    let (addr, handle) = spawn_inbound(config).await;
    let (stream, reply) = udp_associate(addr).await;
    let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");

    // Sanity: the association relays before the control connection closes.
    sock.send_to(&udp_datagram(&target, 0, b"ping"), reply)
        .await
        .expect("send datagram");
    let mut buf = vec![0u8; 2048];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .expect("echo reply timed out")
        .expect("recv reply");
    let (_, _, payload) = socks5::parse_udp_request(&buf[..n]).expect("reply header");
    assert_eq!(payload, b"ping");

    // Close the controlling TCP connection: the relay must end and release
    // its client-facing socket. Waiting for the port to become bindable is
    // deterministic (no SO_REUSEADDR on a tokio `UdpSocket`) and a stronger
    // claim than "no reply arrived within N ms".
    drop(stream);
    assert!(
        wait_for_port_release(reply).await,
        "relay must release its udp socket after the control connection closes"
    );

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_off_keeps_command_not_supported_refusal() {
    let mut config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    );
    config.udp = false;
    let (addr, handle) = spawn_inbound(config).await;

    let mut stream = TcpStream::connect(addr).await.expect("connect to inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await.expect("selection");
    assert_eq!(selection, [0x05, 0x00]);
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate request");
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.expect("reply head");
    assert_eq!(head[1], 0x07, "CommandNotSupported when udp is off");
    skip_reply_addr(&mut stream, head[3]).await;

    handle.abort();
}

/// Poll until `addr` can be bound again (the relay released it) or a deadline
/// passes. `true` = released.
async fn wait_for_port_release(addr: SocketAddr) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if UdpSocket::bind(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// An association whose client never sends a datagram must still be released
/// when the control connection closes — otherwise its TCP and UDP sockets leak
/// per association until the process runs out of descriptors.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_association_without_a_datagram_is_released_on_control_close() {
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    );
    let (addr, handle) = spawn_inbound(config).await;
    let (stream, reply) = udp_associate(addr).await;

    // No datagram was ever sent; closing the control connection must end the
    // relay anyway.
    drop(stream);
    assert!(
        wait_for_port_release(reply).await,
        "relay must not park waiting for a first datagram that never comes"
    );

    handle.abort();
}

/// Only the control connection's peer may drive the association: a datagram
/// from another source is ignored, and it does not steal the pin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_datagrams_from_other_sources_are_ignored() {
    let echo = spawn_udp_echo().await;
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    );
    let (addr, handle) = spawn_inbound(config).await;
    let (stream, reply) = udp_associate(addr).await;
    let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());

    // Pin the association to this socket.
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");
    client
        .send_to(&udp_datagram(&target, 0, b"first"), reply)
        .await
        .expect("send datagram");
    let mut buf = vec![0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("echo reply timed out")
        .expect("recv reply");
    let (_, _, payload) = socks5::parse_udp_request(&buf[..n]).expect("reply header");
    assert_eq!(payload, b"first");

    // A different local socket (same host, different port) must be ignored.
    let intruder = UdpSocket::bind("127.0.0.1:0").await.expect("intruder udp");
    intruder
        .send_to(&udp_datagram(&target, 0, b"intruder"), reply)
        .await
        .expect("send intruder datagram");
    let mut probe = vec![0u8; 2048];
    let stolen =
        tokio::time::timeout(Duration::from_millis(200), intruder.recv_from(&mut probe)).await;
    assert!(stolen.is_err(), "an unpinned source must get no reply");

    // The pinned client still works.
    client
        .send_to(&udp_datagram(&target, 0, b"again"), reply)
        .await
        .expect("send datagram");
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("echo reply timed out")
        .expect("recv reply");
    let (_, _, payload) = socks5::parse_udp_request(&buf[..n]).expect("reply header");
    assert_eq!(payload, b"again");

    drop(stream);
    handle.abort();
}

/// One association fans out per datagram: two destinations both receive their
/// traffic and both replies carry the right source address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_association_fans_out_to_multiple_destinations() {
    let echo_a = spawn_udp_echo().await;
    let echo_b = spawn_udp_echo().await;
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".into(),
            kind: OutboundKind::Direct,
        }],
    );
    let (addr, handle) = spawn_inbound(config).await;
    let (stream, reply) = udp_associate(addr).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");

    let mut seen = Vec::new();
    for (echo, payload) in [(echo_a, b"to-a".as_slice()), (echo_b, b"to-b".as_slice())] {
        let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
        client
            .send_to(&udp_datagram(&target, 0, payload), reply)
            .await
            .expect("send datagram");
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("echo reply timed out")
            .expect("recv reply");
        let (_, src, body) = socks5::parse_udp_request(&buf[..n]).expect("reply header");
        assert_eq!(body, payload);
        seen.push(src.port);
    }
    assert_eq!(
        seen,
        vec![echo_a.port(), echo_b.port()],
        "each reply names the destination it came from"
    );

    drop(stream);
    handle.abort();
}

#[test]
fn v4_mapped_reply_addresses_are_unmapped() {
    let mapped: SocketAddr = "[::ffff:127.0.0.1]:53".parse().expect("mapped addr");
    let unmapped = super::unmap_v6(mapped);
    assert_eq!(unmapped, "127.0.0.1:53".parse::<SocketAddr>().unwrap());
    // A genuine v6 address is untouched.
    let v6: SocketAddr = "[2001:db8::1]:53".parse().expect("v6 addr");
    assert_eq!(super::unmap_v6(v6), v6);
    // v4 passes through.
    let v4: SocketAddr = "127.0.0.1:9".parse().expect("v4 addr");
    assert_eq!(super::unmap_v6(v4), v4);
}

/// Every mapped kind, including the ones whose verdict is a judgement call:
/// `0x02` is reserved for a policy refusal, so a reset or a local socket
/// problem must NOT claim it.
#[test]
fn reply_code_maps_io_kinds() {
    use crate::error::NativeError;
    use socks5::ReplyCode;
    use std::io::ErrorKind;

    for (kind, want) in [
        (ErrorKind::ConnectionRefused, ReplyCode::ConnectionRefused),
        (ErrorKind::ConnectionReset, ReplyCode::ConnectionRefused),
        (ErrorKind::PermissionDenied, ReplyCode::ConnectionNotAllowed),
        (ErrorKind::NetworkUnreachable, ReplyCode::NetworkUnreachable),
        (ErrorKind::HostUnreachable, ReplyCode::HostUnreachable),
        (ErrorKind::TimedOut, ReplyCode::HostUnreachable),
        (ErrorKind::AddrNotAvailable, ReplyCode::GeneralFailure),
        (ErrorKind::NotConnected, ReplyCode::GeneralFailure),
        (ErrorKind::Other, ReplyCode::GeneralFailure),
    ] {
        let error = NativeError::Io(std::io::Error::from(kind));
        assert_eq!(super::reply_for(&error), want, "{kind:?}");
    }

    let dial = NativeError::Dial("boom".into());
    assert_eq!(super::reply_for(&dial), ReplyCode::HostUnreachable);
    let timeout = NativeError::Timeout {
        step: "direct connect",
        limit: Duration::from_secs(1),
    };
    assert_eq!(super::reply_for(&timeout), ReplyCode::HostUnreachable);
    let unsupported = NativeError::NotImplemented {
        feature: "socks5 udp".into(),
    };
    assert_eq!(
        super::reply_for(&unsupported),
        ReplyCode::CommandNotSupported
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_dial_disables_nagle() {
    use std::any::Any;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let target = TargetAddr::new(Host::new("127.0.0.1"), addr.port());
    let stream = super::outbound::dial(&OutboundKind::Direct, &target)
        .await
        .expect("dial direct");
    let any = &*stream as &dyn Any;
    let tcp = any
        .downcast_ref::<TcpStream>()
        .expect("direct dial returns a TcpStream");
    assert!(tcp.nodelay().expect("nodelay getter"), "TCP_NODELAY set");
    server.abort();
}

/// A TCP server that answers every connection with `reply`, whatever it was
/// sent: the asymmetric counterpart to [`spawn_echo`], so a relayed leg has
/// `up != down` and a swapped direction cannot pass as correct.
async fn spawn_amplifier(reply: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind amplifier listener");
    let addr = listener.local_addr().expect("amplifier addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                if sock.read(&mut buf).await.is_ok() {
                    let _ = sock.write_all(reply).await;
                    let _ = sock.flush().await;
                }
                // Stay open until the client hangs up, so the test can read
                // the live counters while the leg is still running.
                let _ = sock.read(&mut buf).await;
            });
        }
    });
    addr
}

/// Telemetry: a relayed leg emits exactly one open/close trace pair, its close
/// row carries this leg's own per-direction totals, and the shared traffic
/// counters see those bytes AS THEY FLOW (not once the leg ends).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relayed_leg_emits_trace_events_and_traffic() {
    use super::TraceCtx;
    use crate::telemetry::{NativeEvent, Telemetry, TraceEvent, TraceKind, TraceSecurity};

    /// Longer than the request, so up and down can never be confused.
    const REPLY: &[u8] = b"asymmetric-reply-from-the-destination";

    let dest = spawn_amplifier(REPLY).await;
    let (telemetry, mut events) = Telemetry::new(64);

    let mut config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".to_owned(),
            kind: OutboundKind::Direct,
        }],
    );
    config.trace = Some(TraceCtx {
        telemetry: telemetry.clone(),
        kind: TraceKind::Tcp,
        protocol: "direct".into(),
        transport: "-".into(),
        security: TraceSecurity::Plain,
    });
    let (addr, handle) = spawn_inbound(config).await;

    let target = TargetAddr::new(Host::new("127.0.0.1"), dest.port());
    let ClientResult::Connected { code, mut stream } = client_connect(addr, None, &target).await
    else {
        panic!("connect refused");
    };
    assert_eq!(code, 0x00, "socks connect succeeds");
    let payload = b"up";
    stream.write_all(payload).await.expect("write payload");
    let mut back = vec![0u8; REPLY.len()];
    stream.read_exact(&mut back).await.expect("read reply");
    assert_eq!(back, REPLY, "destination answered");

    let opened = match events.recv().await.expect("event") {
        NativeEvent::Trace(TraceEvent::Opened(o)) => {
            assert_eq!(o.kind, TraceKind::Tcp);
            assert_eq!(&o.protocol[..], "direct");
            assert!(o.dest.contains(&dest.port().to_string()));
            o.conn_id
        }
        other => panic!("unexpected event before opened: {other:?}"),
    };

    // The leg is STILL OPEN: the shared counters must already hold both
    // directions. The old trailing `add_traffic` reported nothing until close,
    // so a long-running transfer looked idle for its whole lifetime.
    let live = telemetry.drain_traffic();
    assert_eq!(
        live,
        (payload.len() as u64, REPLY.len() as u64),
        "shared counters see both directions mid-leg"
    );

    drop(stream);
    match tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("closed row within 5s")
        .expect("event")
    {
        NativeEvent::Trace(TraceEvent::Closed(c)) => {
            assert_eq!(c.conn_id, opened);
            assert!(c.error.is_none(), "relay succeeded: {:?}", c.error);
            assert_eq!(
                (c.up_bytes, c.down_bytes),
                (payload.len() as u64, REPLY.len() as u64),
                "the close row reports this leg's own asymmetric totals"
            );
        }
        other => panic!("unexpected event before closed: {other:?}"),
    }

    // Exactly one pair per leg: the drop guard must not double-emit.
    let extra = tokio::time::timeout(Duration::from_millis(200), events.recv()).await;
    assert!(extra.is_err(), "channel is empty after the pair: {extra:?}");
    // And the close row must not re-add the leg totals to the shared counters.
    assert_eq!(
        telemetry.drain_traffic(),
        (0, 0),
        "no second accounting of the same bytes"
    );

    handle.abort();
}

/// A leg cancelled by shutdown still reports its close row: an unmatched
/// `Opened` would sit in the TUI's connection table forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_during_a_live_leg_emits_closed() {
    use super::TraceCtx;
    use crate::telemetry::{NativeEvent, Telemetry, TraceEvent, TraceKind, TraceSecurity};

    let echo = spawn_echo().await;
    let (telemetry, mut events) = Telemetry::new(64);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let mut config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".to_owned(),
            kind: OutboundKind::Direct,
        }],
    );
    config.trace = Some(TraceCtx {
        telemetry: telemetry.clone(),
        kind: TraceKind::Tcp,
        protocol: "direct".into(),
        transport: "-".into(),
        security: TraceSecurity::Plain,
    });
    config.shutdown = Some(shutdown_rx);
    let (addr, handle) = spawn_inbound(config).await;

    let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
    let ClientResult::Connected { code, mut stream } = client_connect(addr, None, &target).await
    else {
        panic!("connect refused");
    };
    assert_eq!(code, 0x00, "socks connect succeeds");
    stream.write_all(b"live").await.expect("write payload");
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).await.expect("read echo");

    let opened = match events.recv().await.expect("event") {
        NativeEvent::Trace(TraceEvent::Opened(o)) => o.conn_id,
        other => panic!("unexpected event before opened: {other:?}"),
    };

    // Both ends are still connected, so the relay is parked mid-leg: only the
    // shutdown signal ends it, by DROPPING the relay future.
    shutdown_tx.send(true).expect("shutdown");
    match tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("closed row within 5s")
        .expect("event")
    {
        NativeEvent::Trace(TraceEvent::Closed(c)) => {
            assert_eq!(c.conn_id, opened);
            assert_eq!(
                c.error.as_deref(),
                Some("cancelled"),
                "the row says why the leg ended"
            );
            assert_eq!(
                (c.up_bytes, c.down_bytes),
                (4, 4),
                "a cancelled leg still reports the bytes it moved"
            );
        }
        other => panic!("expected the cancelled leg's Closed row: {other:?}"),
    }

    handle.abort();
}

/// Shutdown must end LIVE UDP associations. The association outlives its
/// accept-loop future (`run_udp_associate` spawns the relay and returns), so
/// without a shutdown arm of its own it kept forwarding datagrams through the
/// previous profile's outbound after a disconnect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_ends_a_live_udp_association() {
    let echo = spawn_udp_echo().await;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let mut config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound {
            tag: "direct".to_owned(),
            kind: OutboundKind::Direct,
        }],
    );
    config.shutdown = Some(shutdown_rx);
    let (addr, handle) = spawn_inbound(config).await;
    let (control, reply) = udp_associate(addr).await;

    // Pin the association with a real round-trip.
    let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");
    sock.send_to(&udp_datagram(&target, 0, b"ping udp"), reply)
        .await
        .expect("send datagram");
    let mut buf = vec![0u8; 2048];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("echo reply timed out")
        .expect("recv reply");
    assert!(n > 0, "the association is live");

    // The control connection stays OPEN: only shutdown may end this.
    shutdown_tx.send(true).expect("shutdown");
    assert!(
        wait_for_port_release(reply).await,
        "shutdown must release the association's client-facing socket"
    );

    drop(control);
    handle.abort();
}
