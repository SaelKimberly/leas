//! `WireGuard` end to end: leas's client against a real `boringtun` peer.
//!
//! `boringtun` is a test-only dependency here (ADR 0019): it gives a real
//! responder without `CAP_NET_ADMIN`, a TUN device or a downloaded core binary.
//! The responder owns a `smoltcp` interface with a TCP echo listener, so a
//! passing row proves the handshake, the transport records, the userspace
//! stack and the relay's byte path together.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use leas_native::protocol::wireguard::core::device::Tunnel as ClientTunnel;
use leas_native::protocol::wireguard::stack::{PacketLink, StackConfig, WgLink, WgStack};

const CLIENT_PRIVATE: [u8; 32] = [0x11; 32];
const SERVER_PRIVATE: [u8; 32] = [0x22; 32];
const CLIENT_ADDRESS: &str = "10.66.0.2/32";
const ECHO_PORT: u16 = 7;
const MTU: usize = 1420;

/// A pair of keys both sides derive the same way.
fn client_public() -> PublicKey {
    PublicKey::from(&StaticSecret::from(CLIENT_PRIVATE))
}

fn server_public() -> PublicKey {
    PublicKey::from(&StaticSecret::from(SERVER_PRIVATE))
}

// ---------------------------------------------------------------- server side

struct QueueDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    mtu: usize,
}

struct Rx(Vec<u8>);
struct Tx(Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>);

impl smoltcp::phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl smoltcp::phy::TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0u8; len];
        let out = f(&mut buffer);
        if let Ok(mut queue) = self.0.lock() {
            queue.push_back(buffer);
        }
        out
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx;

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((Rx(packet), Tx(self.outbound.clone())))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(Tx(self.outbound.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// Run the responder until the client drops: handshake, transport, and a TCP
/// echo on `ECHO_PORT`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Echo,
    /// Echo one payload, then close the server's write side (remote FIN).
    HalfClose,
}

async fn serve(socket: Arc<UdpSocket>, datagrams: Arc<std::sync::atomic::AtomicUsize>, mode: Mode) {
    let mut tunnel = Tunn::new(
        StaticSecret::from(SERVER_PRIVATE),
        client_public(),
        None,
        None,
        1,
        None,
    );
    let tx_queue = Arc::new(std::sync::Mutex::new(VecDeque::new()));
    let mut device = QueueDevice {
        inbound: VecDeque::new(),
        outbound: Arc::clone(&tx_queue),
        mtu: MTU,
    };
    let mut iface = Interface::new(
        IfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(10, 66, 0, 1)),
                32,
            ))
            .expect("server address");
    });
    let mut sockets = SocketSet::new(Vec::new());
    let listener: SocketHandle = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
    ));
    sockets
        .get_mut::<tcp::Socket>(listener)
        .listen(ECHO_PORT)
        .expect("listen");
    let udp_echo = sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; 64 * 1024]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; 64 * 1024]),
    ));
    sockets
        .get_mut::<udp::Socket>(udp_echo)
        .bind(ECHO_PORT)
        .expect("bind udp echo");

    let mut scratch_in = vec![0u8; MTU + 128];
    let mut scratch_out = vec![0u8; MTU + 128];
    let mut echo_backlog: Vec<u8> = Vec::new();
    let mut half_close_pending = false;
    let start = std::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(5));
    // The responder socket is unconnected: every reply goes to the peer the
    // last datagram came from (`try_send` on an unconnected socket fails).
    let mut peer: Option<SocketAddr> = None;

    loop {
        let now =
            Instant::from_micros(i64::try_from(start.elapsed().as_micros()).unwrap_or(i64::MAX));
        iface.poll(now, &mut device, &mut sockets);
        let frames: Vec<Vec<u8>> = tx_queue
            .lock()
            .map_or_else(|_| Vec::new(), |mut queue| queue.drain(..).collect());
        for frame in frames {
            if let TunnResult::WriteToNetwork(record) = tunnel.encapsulate(&frame, &mut scratch_out)
                && let Some(peer) = peer
            {
                let _ = socket.send_to(record, peer).await;
            }
        }

        tokio::select! {
            received = socket.recv_from(&mut scratch_in) => {
                let Ok((len, from)) = received else { return };
                peer = Some(from);
                datagrams.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                match tunnel.decapsulate(None, &scratch_in[..len], &mut scratch_out) {
                    TunnResult::WriteToTunnelV4(packet, _) => {
                        device.inbound.push_back(packet.to_vec());
                    }
                    TunnResult::WriteToNetwork(reply) => {
                        let _ = socket.send_to(reply, from).await;
                    }
                    TunnResult::Done
                    | TunnResult::Err(_)
                    | TunnResult::WriteToTunnelV6(_, _) => {}
                }
            }
            _ = tick.tick() => {
                if let TunnResult::WriteToNetwork(record) = tunnel.update_timers(&mut scratch_out)
                    && let Some(peer) = peer
                {
                    let _ = socket.send_to(record, peer).await;
                }
            }
        }

        // The listening socket itself becomes the echo once a SYN arrives.
        // `send_slice` can accept fewer bytes than it is given (the tx ring is
        // 64 KiB): the remainder is carried in `echo_backlog` and retried, or
        // the transfer silently loses bytes.
        let echo = sockets.get_mut::<tcp::Socket>(listener);
        if !echo_backlog.is_empty() && echo.can_send() {
            let accepted = echo.send_slice(&echo_backlog).unwrap_or(0);
            echo_backlog.drain(..accepted);
        }
        let mut echoed = false;
        while echo.can_recv() && echo_backlog.len() < 64 * 1024 {
            let Ok(chunk) = echo.recv(|data| (data.len(), data.to_vec())) else {
                break;
            };
            if chunk.is_empty() {
                break;
            }
            echo_backlog.extend_from_slice(&chunk);
            echoed = true;
        }
        if echoed {
            half_close_pending = true;
        }
        if mode == Mode::HalfClose && half_close_pending && echo_backlog.is_empty() {
            // Remote FIN: the client must see EOF on the read side while its
            // own write side stays usable.
            echo.close();
            half_close_pending = false;
        }
        if !echo.is_open() {
            echo.listen(ECHO_PORT).ok();
        }

        // Datagram echo (the UDP association path).
        let datagrams_socket = sockets.get_mut::<udp::Socket>(udp_echo);
        while datagrams_socket.can_recv() {
            let Ok((data, meta)) = datagrams_socket.recv() else {
                break;
            };
            let payload = data.to_vec();
            datagrams_socket.send_slice(&payload, meta.endpoint).ok();
        }
    }
}

// ----------------------------------------------------------------- client side

fn client_tunnel() -> ClientTunnel {
    client_tunnel_keepalive(0)
}

fn client_tunnel_keepalive(keepalive: u16) -> ClientTunnel {
    ClientTunnel::new(
        zeroize::Zeroizing::new(CLIENT_PRIVATE),
        server_public().to_bytes(),
        None,
        MTU,
        [0u8; 3],
        7,
        keepalive,
    )
    .expect("client tunnel")
}

fn client_stack(link: impl PacketLink) -> Arc<WgStack> {
    let addresses = vec![CLIENT_ADDRESS.parse().expect("client cidr")];
    Arc::new(WgStack::start(link, StackConfig::new(addresses, MTU)).expect("stack"))
}

async fn start_server() -> (
    Arc<UdpSocket>,
    SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    start_server_mode(Mode::Echo).await
}

async fn start_server_mode(
    mode: Mode,
) -> (
    Arc<UdpSocket>,
    SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let socket = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind the responder"),
    );
    let addr = socket.local_addr().expect("responder address");
    let datagrams = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    tokio::spawn(serve(Arc::clone(&socket), Arc::clone(&datagrams), mode));
    (socket, addr, datagrams)
}

async fn client_link(server: SocketAddr) -> WgLink {
    client_link_keepalive(server, 0).await
}

async fn client_link_keepalive(server: SocketAddr, keepalive: u16) -> WgLink {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    socket.connect(server).await.expect("connect client");
    WgLink::new(socket, client_tunnel_keepalive(keepalive))
}

/// The handshake itself, without a stack: `boringtun` must answer our
/// initiation with a response (a wrong transcript or MAC shows up here).
#[test]
fn boringtun_accepts_our_initiation() {
    let mut server = Tunn::new(
        StaticSecret::from(SERVER_PRIVATE),
        client_public(),
        None,
        None,
        1,
        None,
    );
    let mut client = client_tunnel();
    let mut events = Vec::new();
    client.send(1_700_000_000, &[0u8; 40], &mut events);
    let datagram = events
        .into_iter()
        .find_map(|event| match event {
            leas_native::protocol::wireguard::core::device::Event::Send(bytes) => Some(bytes),
            _ => None,
        })
        .expect("an initiation");
    let mut out = vec![0u8; 2048];
    match server.decapsulate(None, &datagram, &mut out) {
        TunnResult::WriteToNetwork(response) => {
            assert_eq!(response.len(), 92, "a handshake response");
            let mut reply = response.to_vec();
            let mut events = Vec::new();
            client.receive(1_700_000_000, &mut reply, &mut events);
            assert!(
                events.iter().any(|event| matches!(
                    event,
                    leas_native::protocol::wireguard::core::device::Event::Established
                )),
                "the client accepts the response: {events:?}"
            );
        }
        other => panic!("boringtun refused the initiation: {other:?}"),
    }
}

/// A TCP echo through the tunnel: handshake, transport, netstack, relay.
#[tokio::test(flavor = "current_thread")]
async fn tcp_echo_round_trips_through_the_tunnel() {
    let (_server, addr, _datagrams) = start_server().await;
    let stack = client_stack(client_link(addr).await);
    let mut flow = stack
        .connect_tcp(SocketAddr::from(([10, 66, 0, 1], ECHO_PORT)))
        .await
        .expect("connect through the tunnel");

    flow.write_all(b"hello wireguard").await.expect("write");
    let mut echo = [0u8; 15];
    tokio::time::timeout(Duration::from_secs(10), flow.read_exact(&mut echo))
        .await
        .expect("the echo arrives")
        .expect("read");
    assert_eq!(&echo, b"hello wireguard");
}

/// A chunked transfer that queues many `TcpWrite` commands: this is the row
/// that distinguishes "append the pending bytes" from "replace them" (a
/// single big `poll_write` cannot, because it produces one chunk).
#[tokio::test(flavor = "current_thread")]
async fn a_chunked_transfer_arrives_in_order() {
    let (_server, addr, _datagrams) = start_server().await;
    let stack = client_stack(client_link(addr).await);
    let flow = stack
        .connect_tcp(SocketAddr::from(([10, 66, 0, 1], ECHO_PORT)))
        .await
        .expect("connect through the tunnel");

    let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let (mut read_half, mut write_half) = tokio::io::split(flow);
    let writer = tokio::spawn(async move {
        for chunk in payload.chunks(4 * 1024) {
            write_half.write_all(chunk).await.expect("write");
            write_half.flush().await.expect("flush");
        }
        write_half.shutdown().await.expect("shutdown");
    });
    let mut echo = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(30), read_half.read_exact(&mut echo))
        .await
        .expect("the echo arrives")
        .expect("read");
    writer.await.expect("writer task");
    assert_eq!(echo, expected);
}

/// `persistent_keepalive` must put datagrams on the wire while the tunnel is
/// idle — the driver has to flush what `poll` produced before it sleeps.
#[tokio::test(flavor = "current_thread")]
async fn an_idle_tunnel_sends_keepalives() {
    let (_server, addr, datagrams) = start_server().await;
    let stack = client_stack(client_link_keepalive(addr, 1).await);
    let mut flow = stack
        .connect_tcp(SocketAddr::from(([10, 66, 0, 1], ECHO_PORT)))
        .await
        .expect("connect through the tunnel");
    flow.write_all(b"x").await.expect("write");
    let mut byte = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), flow.read_exact(&mut byte))
        .await
        .expect("the echo arrives")
        .expect("read");
    drop(flow);

    let before = datagrams.load(std::sync::atomic::Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let after = datagrams.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        after > before,
        "an idle tunnel with persistent_keepalive=1 must keep sending (before={before}, after={after})"
    );
}

/// UDP datagrams round-trip through the device, and more than the 16-slot
/// channel are delivered: this exercises the split reader's `read_wake`
/// (without it the driver parks after the first channel-full burst).
#[tokio::test(flavor = "current_thread")]
async fn udp_datagrams_round_trip_and_drain_the_ring() {
    const COUNT: u8 = 40;
    let (_server, addr, _datagrams) = start_server().await;
    let stack = client_stack(client_link(addr).await);
    let flow = stack.open_udp().await.expect("open an association");
    let (mut reader, writer) = flow.split();
    let destination = SocketAddr::from(([10, 66, 0, 1], ECHO_PORT));
    for i in 0..COUNT {
        let payload = [i % 251; 16];
        writer
            .send_to(destination, &payload)
            .expect("queue datagram");
    }
    let mut seen = Vec::new();
    while seen.len() < usize::from(COUNT) {
        let datagram = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("a reply arrives")
            .expect("the association is open");
        assert_eq!(datagram.0, destination);
        seen.push(datagram.1);
    }
    assert_eq!(seen.len(), usize::from(COUNT));
    for (i, payload) in seen.iter().enumerate() {
        let byte = u8::try_from(i).expect("fewer than 40 replies") % 251;
        assert_eq!(payload, &vec![byte; 16], "reply {i} order");
    }
}

/// A remote FIN closes the read side; the write half stays usable (the driver
/// must not abort a `CloseWait` socket).
#[tokio::test(flavor = "current_thread")]
async fn a_remote_fin_ends_reads_but_not_writes() {
    let (_server, addr, _datagrams) = start_server_mode(Mode::HalfClose).await;
    let stack = client_stack(client_link(addr).await);
    let mut flow = stack
        .connect_tcp(SocketAddr::from(([10, 66, 0, 1], ECHO_PORT)))
        .await
        .expect("connect through the tunnel");
    flow.write_all(b"hi").await.expect("write");
    let mut echo = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), flow.read_exact(&mut echo))
        .await
        .expect("the echo arrives")
        .expect("read");
    // The server closed its side: the next read is EOF.
    let mut eof = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), flow.read(&mut eof))
        .await
        .expect("EOF arrives");
    assert!(matches!(read, Ok(0)), "remote FIN is EOF, got {read:?}");

    // The write half survives: no broken pipe, no reset.
    tokio::time::timeout(Duration::from_secs(2), flow.write_all(b"tail"))
        .await
        .expect("the write is accepted")
        .expect("no broken pipe");
}

/// A handshake retransmission is produced by `Tunnel::poll` with **no** inbound
/// traffic to wake the loop: the driver must flush it before sleeping, or the
/// retransmit sits in the outbox forever. Counted at the peer socket, which is
/// the only place that sees every datagram the link actually put on the wire.
#[tokio::test(flavor = "current_thread")]
async fn a_handshake_retransmit_leaves_a_silent_tunnel() {
    // A peer that never answers: no inbound datagram can wake the driver.
    let peer = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind peer"));
    let peer_addr = peer.local_addr().expect("peer address");
    let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    let peer_read = Arc::clone(&peer);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok(len) = peer_read.recv(&mut buf).await {
            if len > 0 {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    socket.connect(peer_addr).await.expect("connect client");
    let stack = client_stack(WgLink::new(socket, client_tunnel()));
    let _flow = stack
        .connect_tcp(SocketAddr::from(([10, 66, 0, 1], ECHO_PORT)))
        .await
        .expect("the socket opens");

    // The initiation goes out at once; the 5 s retransmit is timer-only.
    tokio::time::sleep(Duration::from_millis(6500)).await;
    let count = received.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        count >= 2,
        "the 5 s retransmit must leave a silent tunnel (peer saw {count})"
    );
}

/// The passive keepalive (`KEEPALIVE_TIMEOUT`, 10 s after a receive) must reach
/// the wire with NO other traffic and NO periodic keepalive: the only wake left
/// is the tunnel's own timer, so a driver that flushes before `poll` strands it.
#[tokio::test(flavor = "current_thread")]
async fn a_passive_keepalive_leaves_an_otherwise_idle_tunnel() {
    let (_server, addr, datagrams) = start_server().await;
    let stack = client_stack(client_link(addr).await);
    let mut flow = stack
        .connect_tcp(SocketAddr::from(([10, 66, 0, 1], ECHO_PORT)))
        .await
        .expect("connect through the tunnel");
    flow.write_all(b"y").await.expect("write");
    let mut byte = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), flow.read_exact(&mut byte))
        .await
        .expect("the echo arrives")
        .expect("read");
    drop(flow);

    let before = datagrams.load(std::sync::atomic::Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(11)).await;
    let after = datagrams.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        after > before,
        "the 10 s passive keepalive must leave the link (before={before}, after={after})"
    );
}

/// A transfer larger than the 64 KiB tx ring: this is the row that catches a
/// driver which drops a partial `send_slice` or overwrites a pending chunk
/// (the byte stream would arrive truncated but the call would still succeed).
#[tokio::test(flavor = "current_thread")]
async fn a_large_transfer_arrives_intact() {
    let (_server, addr, _datagrams) = start_server().await;
    let stack = client_stack(client_link(addr).await);
    let flow = stack
        .connect_tcp(SocketAddr::from(([10, 66, 0, 1], ECHO_PORT)))
        .await
        .expect("connect through the tunnel");

    let payload: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let (mut read_half, mut write_half) = tokio::io::split(flow);
    let writer = tokio::spawn(async move {
        write_half.write_all(&payload).await.expect("write");
        write_half.shutdown().await.expect("shutdown");
    });
    let mut echo = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(30), read_half.read_exact(&mut echo))
        .await
        .expect("the echo arrives")
        .expect("read");
    writer.await.expect("writer task");
    assert_eq!(echo, expected, "no byte may be dropped or reordered");
}

/// The same round trip while every fourth datagram is dropped in each
/// direction: the acceptance row for `smoltcp`'s loss recovery (ADR 0019).
#[tokio::test(flavor = "current_thread")]
async fn tcp_echo_survives_packet_loss() {
    const DROP_EVERY: usize = 5;

    struct Lossy {
        inner: WgLink,
        seen: usize,
    }

    impl PacketLink for Lossy {
        async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            loop {
                let len = self.inner.recv(buf).await?;
                self.seen += 1;
                if !self.seen.is_multiple_of(DROP_EVERY) {
                    return Ok(len);
                }
            }
        }

        async fn send(&mut self, packet: &[u8]) -> std::io::Result<()> {
            self.seen += 1;
            if self.seen.is_multiple_of(DROP_EVERY) {
                return Ok(());
            }
            self.inner.send(packet).await
        }
    }

    let (_server, addr, _datagrams) = start_server().await;
    let stack = client_stack(Lossy {
        inner: client_link(addr).await,
        seen: 0,
    });
    let flow = stack
        .connect_tcp(SocketAddr::from(([10, 66, 0, 1], ECHO_PORT)))
        .await
        .expect("connect through a lossy tunnel");

    // Let the handshake settle before the transfer: this row is about TCP
    // loss recovery on an established tunnel, not about the pre-established
    // write path (which the no-loss row already exercises).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let payload: Vec<u8> = (0..8 * 1024u32).map(|i| (i % 251) as u8).collect();
    let (mut read_half, mut write_half) = tokio::io::split(flow);
    let expected = payload.clone();
    let writer = tokio::spawn(async move {
        write_half.write_all(&payload).await.expect("write");
        write_half.shutdown().await.expect("shutdown");
    });
    let mut echo = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(60), read_half.read_exact(&mut echo))
        .await
        .expect("the echo arrives despite loss")
        .expect("read");
    writer.await.expect("writer task");
    assert_eq!(echo, expected);
}
