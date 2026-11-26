//! The smoltcp device and the one driver task per tunnel.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use tokio::sync::{mpsc, oneshot};

use super::flow::{TcpFlow, UdpFlow};
use super::{PacketLink, StackConfig, StackError};

/// A TCP flow that never reaches `Established` fails after this long.
const CONNECT_TIMEOUT_SECS: u64 = 12;
/// Bytes one flow may have queued (accepted by the driver, not yet written
/// into the socket) before its writer parks on its own credit.
pub(crate) const WRITE_HIGH_WATER: usize = 128 * 1024;

/// What a successful TCP open hands back.
pub(crate) struct TcpOpen {
    pub(crate) handle: SocketHandle,
    pub(crate) token: u64,
    pub(crate) dead: Arc<std::sync::atomic::AtomicBool>,
    /// The flow's own credit signal; the driver keeps it so a device exit can
    /// wake a writer parked on credit whose command is still queued.
    pub(crate) wake: Arc<tokio::sync::Notify>,
    pub(crate) rx: mpsc::Receiver<Vec<u8>>,
}

/// The UDP read side.
pub(crate) type UdpRead = mpsc::Receiver<(SocketAddr, Vec<u8>)>;
/// One open UDP socket: its identity token and the flow's read channel.
type UdpChannel = (u64, mpsc::Sender<(SocketAddr, Vec<u8>)>);

/// Commands a flow may send to the driver.
///
/// Every command carries the flow's open `token`: smoltcp handles are slot
/// indices that get reused, so a late command from a dropped flow must be
/// dropped rather than applied to the socket a new flow now owns.
pub(crate) enum Command {
    TcpOpen {
        remote: SocketAddr,
        reply: oneshot::Sender<Result<TcpOpen, StackError>>,
    },
    TcpWrite {
        handle: SocketHandle,
        token: u64,
        data: Vec<u8>,
        credit: Arc<std::sync::atomic::AtomicUsize>,
        wake: Arc<tokio::sync::Notify>,
    },
    TcpShutdown {
        handle: SocketHandle,
        token: u64,
    },
    TcpClose {
        handle: SocketHandle,
        token: u64,
    },
    UdpOpen {
        reply: oneshot::Sender<Result<(SocketHandle, u64, UdpRead), StackError>>,
    },
    UdpSend {
        handle: SocketHandle,
        token: u64,
        to: SocketAddr,
        data: Vec<u8>,
    },
    UdpClose {
        handle: SocketHandle,
        token: u64,
    },
}

/// The flow-facing handle.
#[derive(Clone)]
pub(crate) struct StackHandle {
    pub(crate) cmd: mpsc::Sender<Command>,
    /// Fired after every command the driver pops: a flow whose command could
    /// not be queued parks here and retries.
    pub(crate) space: Arc<tokio::sync::Notify>,
}

/// A running stack: the driver task plus its command channel.
pub struct WgStack {
    pub(crate) handle: StackHandle,
    /// Signals the driver that a flow drained its channel; `select!` waits on
    /// it beside the link and the command queue.
    read_wake: Arc<tokio::sync::Notify>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for WgStack {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl WgStack {
    /// Start the driver over `link` with `config`.
    ///
    /// # Errors
    ///
    /// Fails when the config names no address (smoltcp would accept an empty
    /// interface and then route nothing, which is a silent black hole).
    pub fn start<L: PacketLink>(link: L, config: StackConfig) -> Result<Self, StackError> {
        if config.addresses.is_empty() {
            return Err(StackError::RefusedRequest(
                "wireguard config has no tunnel address".into(),
            ));
        }
        let (cmd, rx) = mpsc::channel(64);
        let space = Arc::new(tokio::sync::Notify::new());
        let handle = StackHandle {
            cmd,
            space: Arc::clone(&space),
        };
        let read_wake = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(run(
            link,
            config,
            rx,
            Arc::clone(&read_wake),
            Arc::clone(&space),
        ));
        Ok(Self {
            handle,
            read_wake,
            tasks: vec![task],
        })
    }

    /// Open a TCP flow to `remote`. The address must be numeric: a
    /// `WireGuard` profile resolves names through the tunnel before dialling.
    pub async fn connect_tcp(self: &Arc<Self>, remote: SocketAddr) -> Result<TcpFlow, StackError> {
        let (reply, wait) = oneshot::channel();
        self.handle
            .cmd
            .send(Command::TcpOpen { remote, reply })
            .await
            .map_err(|_| StackError::Closed)?;
        let open = wait.await.map_err(|_| StackError::Closed)??;
        Ok(TcpFlow::new(
            self.handle.clone(),
            open.handle,
            open.token,
            open.dead,
            open.wake,
            open.rx,
            Arc::clone(&self.read_wake),
            Some(Arc::clone(self)),
        ))
    }

    /// Open a UDP socket bound to an ephemeral port.
    pub async fn open_udp(self: &Arc<Self>) -> Result<UdpFlow, StackError> {
        let (reply, wait) = oneshot::channel();
        self.handle
            .cmd
            .send(Command::UdpOpen { reply })
            .await
            .map_err(|_| StackError::Closed)?;
        let (handle, token, rx) = wait.await.map_err(|_| StackError::Closed)??;
        Ok(UdpFlow::new(
            self.handle.clone(),
            handle,
            token,
            rx,
            Arc::clone(&self.read_wake),
            Some(Arc::clone(self)),
        ))
    }
}

/// The device the interface drives: decrypted IP packets in, sealed or queued
/// IP packets out.
pub(crate) struct PacketDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    mtu: usize,
}

impl PacketDevice {
    const fn new(mtu: usize, outbound: Arc<Mutex<VecDeque<Vec<u8>>>>) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound,
            mtu,
        }
    }

    fn push(&mut self, packet: Vec<u8>) {
        if self.inbound.len() < 64 {
            self.inbound.push_back(packet);
        }
    }
}

pub(crate) struct RxTokenImpl(Vec<u8>);
pub(crate) struct TxTokenImpl(Arc<Mutex<VecDeque<Vec<u8>>>>);

impl smoltcp::phy::RxToken for RxTokenImpl {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl smoltcp::phy::TxToken for TxTokenImpl {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0u8; len];
        let out = f(&mut buffer);
        if let Ok(mut queue) = self.0.lock()
            && queue.len() < 64
        {
            queue.push_back(buffer);
        }
        out
    }
}

impl Device for PacketDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl;

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((RxTokenImpl(packet), TxTokenImpl(self.outbound.clone())))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTokenImpl(self.outbound.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

fn endpoint(address: SocketAddr) -> IpEndpoint {
    match address.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpEndpoint::new(
                IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3])),
                address.port(),
            )
        }
        IpAddr::V6(v6) => IpEndpoint::new(
            IpAddress::Ipv6(Ipv6Address::from(v6.octets())),
            address.port(),
        ),
    }
}

fn endpoint_to_socket(endpoint: IpEndpoint) -> SocketAddr {
    match endpoint.addr {
        IpAddress::Ipv4(v4) => SocketAddr::from((v4.octets(), endpoint.port)),
        IpAddress::Ipv6(v6) => SocketAddr::from((v6.octets(), endpoint.port)),
    }
}

/// Ephemeral source ports the stack allocates, wrapping inside the IANA
/// dynamic range so a long-lived tunnel does not collide with itself.
const fn fresh_port(next: &mut u16) -> u16 {
    let port = *next;
    *next = if *next == u16::MAX { 49_152 } else { *next + 1 };
    port
}

/// One open TCP flow: its identity token and the bookkeeping the driver needs.
struct OpenFlow {
    token: u64,
    /// Set when the socket is retired or the driver exits: the writer must
    /// fail instead of parking on credit that will never come back.
    dead: Arc<std::sync::atomic::AtomicBool>,
    /// The flow's credit signal, notified whenever the driver stops.
    wake: Arc<tokio::sync::Notify>,
    opened_at: Instant,
    orphaned_at: Option<Instant>,
}

/// Bytes a flow queued that the socket has not taken yet, with the credit the
/// driver must return (and the flow to wake) as they are written.
struct PendingWrite {
    data: Vec<u8>,
    credit: Arc<std::sync::atomic::AtomicUsize>,
    wake: Arc<tokio::sync::Notify>,
}

/// Write as much of `data` as the socket takes, draining what it accepted.
fn write_pending(socket: &mut tcp::Socket<'_>, data: &mut Vec<u8>) -> usize {
    let mut written = 0;
    while !data.is_empty() && socket.can_send() {
        match socket.send_slice(data) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                data.drain(..n);
                written += n;
            }
        }
    }
    written
}

async fn sleep_optional(duration: Option<Duration>) {
    match duration {
        Some(duration) if !duration.is_zero() => tokio::time::sleep(duration).await,
        _ => std::future::pending().await,
    }
}

async fn run<L: PacketLink>(
    mut link: L,
    config: StackConfig,
    mut cmds: mpsc::Receiver<Command>,
    read_wake: Arc<tokio::sync::Notify>,
    space: Arc<tokio::sync::Notify>,
) {
    let outbound = Arc::new(Mutex::new(VecDeque::new()));
    let mut device = PacketDevice::new(config.mtu, outbound.clone());
    let mut iface = Interface::new(
        IfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    for address in &config.addresses {
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(*address);
        });
    }
    // WireGuard's cryptokey routing sends every destination to the peer, so
    // the interface needs a default route; the gateway is the tunnel address
    // itself (`ferrox-app/src/wg_stack.rs::add_default_routes`). Without it a
    // `/32` interface address cannot emit a single packet: the destination is
    // neither on-link nor routed.
    if let Some(IpCidr::Ipv4(v4)) = config
        .addresses
        .iter()
        .find(|address| matches!(address, IpCidr::Ipv4(_)))
    {
        let _ = iface.routes_mut().add_default_ipv4_route(v4.address());
    }
    if let Some(IpCidr::Ipv6(v6)) = config
        .addresses
        .iter()
        .find(|address| matches!(address, IpCidr::Ipv6(_)))
    {
        let _ = iface.routes_mut().add_default_ipv6_route(v6.address());
    }

    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_channels: HashMap<SocketHandle, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut udp_channels: HashMap<SocketHandle, UdpChannel> = HashMap::new();
    let mut flows: HashMap<SocketHandle, OpenFlow> = HashMap::new();
    let mut pending: HashMap<SocketHandle, PendingWrite> = HashMap::new();
    let mut pending_shutdown: HashSet<SocketHandle> = HashSet::new();
    let mut rx_buf = vec![0u8; config.mtu + 128];
    let start = std::time::Instant::now();
    let mut next_port: u16 = 49_152;
    let mut next_token: u64 = 0;

    loop {
        let now =
            Instant::from_micros(i64::try_from(start.elapsed().as_micros()).unwrap_or(i64::MAX));
        iface.poll(now, &mut device, &mut sockets);

        // Frames the interface produced this round.
        let frames: Vec<Vec<u8>> = outbound
            .lock()
            .map_or_else(|_| Vec::new(), |mut queue| queue.drain(..).collect());
        for frame in frames {
            if link.send(&frame).await.is_err() {
                fail_device(&flows, &pending, &space);
                return;
            }
        }

        // Retry writes the sockets could not take last round.
        let mut wrote = false;
        for (handle, pending_write) in &mut pending {
            if !flows.contains_key(handle) {
                continue;
            }
            let socket = sockets.get_mut::<tcp::Socket>(*handle);
            let before = pending_write.data.len();
            let written = write_pending(socket, &mut pending_write.data);
            if written > 0 {
                pending_write
                    .credit
                    .fetch_sub(written, std::sync::atomic::Ordering::Relaxed);
                pending_write.wake.notify_one();
                wrote = true;
            }
            let _ = before;
        }
        pending.retain(|_, write| !write.data.is_empty());
        if wrote {
            // The bytes just queued need one `poll` to become frames; without
            // this the loop would sleep with a full socket buffer.
            continue;
        }

        // Hand data to the flow channels; a full channel leaves the bytes in
        // the socket, which closes the TCP window instead of growing memory.
        for (handle, channel) in &tcp_channels {
            if channel.capacity() == 0 {
                continue;
            }
            let socket = sockets.get_mut::<tcp::Socket>(*handle);
            while socket.can_recv() && channel.capacity() > 0 && !channel.is_closed() {
                let Ok(chunk) = socket.recv(|data| (data.len(), data.to_vec())) else {
                    break;
                };
                if chunk.is_empty() {
                    break;
                }
                if channel.try_send(chunk).is_err() {
                    break;
                }
            }
        }
        for (handle, (_, channel)) in &udp_channels {
            if channel.capacity() == 0 {
                continue;
            }
            let socket = sockets.get_mut::<udp::Socket>(*handle);
            while socket.can_recv() && channel.capacity() > 0 && !channel.is_closed() {
                let Ok((data, meta)) = socket.recv() else {
                    break;
                };
                let remote = endpoint_to_socket(meta.endpoint);
                if channel.try_send((remote, data.to_vec())).is_err() {
                    break;
                }
            }
        }

        // Finish queued half-closes once their data is in the socket and the
        // connection can carry a FIN.
        let shutdowns: Vec<SocketHandle> = pending_shutdown
            .iter()
            .filter(|handle| !pending.contains_key(handle))
            .copied()
            .collect();
        for handle in shutdowns {
            if !flows.contains_key(&handle) {
                pending_shutdown.remove(&handle);
                continue;
            }
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            if socket.can_send() {
                socket.close();
                pending_shutdown.remove(&handle);
            } else if matches!(socket.state(), tcp::State::Closed) {
                pending_shutdown.remove(&handle);
            }
        }

        // A flow whose guard dropped (`is_closed`) has gone away even if its
        // `Drop` could not enqueue the close command: TCP starts its orphan
        // linger, UDP retires the socket at once (nothing else would free it).
        for (handle, channel) in &tcp_channels {
            if channel.is_closed()
                && let Some(flow) = flows.get_mut(handle)
            {
                flow.orphaned_at.get_or_insert(now);
            }
        }
        let closed_udp: Vec<SocketHandle> = udp_channels
            .iter()
            .filter(|(_, (_, channel))| channel.is_closed())
            .map(|(handle, _)| *handle)
            .collect();
        for handle in closed_udp {
            udp_channels.remove(&handle);
            sockets.remove(handle);
        }

        // Housekeeping: a socket that never connected, finished (remote FIN or
        // RST), was orphaned by its flow, or never completed its handshake
        // gives its slot back — reset AND retired, so a flow cannot hold a
        // channel (and ~192 KB of buffers) for the life of the device.
        let mut reclaim = Vec::new();
        for (handle, flow) in &flows {
            let idle = (now - flow.opened_at).total_micros() / 1_000_000;
            let socket = sockets.get::<tcp::Socket>(*handle);
            let state = socket.state();
            let connecting = matches!(
                state,
                tcp::State::SynSent | tcp::State::SynReceived | tcp::State::Listen
            );
            let refused = connecting && idle > CONNECT_TIMEOUT_SECS;
            let stuck = connecting && idle > config.handshake_linger_secs;
            // A remote FIN ends the READ side, not the socket: close the
            // flow's channel (its EOF) while the write half — and any pending
            // bytes — stays usable until the flow drops.
            if state == tcp::State::CloseWait && !socket.can_recv() {
                tcp_channels.remove(handle);
            }
            // A dead socket must be reclaimed even with bytes still pending:
            // `write_pending` can never drain them once `can_send()` is false,
            // so requiring an empty pending buffer would leak the slot.
            let finished =
                matches!(state, tcp::State::Closed | tcp::State::TimeWait) && !socket.can_recv();
            let orphan = flow.orphaned_at.is_some_and(|at| {
                (now - at).total_micros() / 1_000_000 > config.orphan_linger_secs
            });
            if refused || stuck || finished || orphan {
                reclaim.push(*handle);
            }
        }
        for handle in reclaim {
            if let Some(flow) = flows.get(&handle) {
                flow.dead.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            sockets.get_mut::<tcp::Socket>(handle).abort();
            // Return the credit and close the flow's read side (EOF).
            if let Some(write) = pending.remove(&handle) {
                write
                    .credit
                    .fetch_sub(write.data.len(), std::sync::atomic::Ordering::Relaxed);
                write.wake.notify_one();
            }
            tcp_channels.remove(&handle);
            flows.remove(&handle);
            pending_shutdown.remove(&handle);
            sockets.remove(handle);
        }

        let delay = iface.poll_delay(now, &sockets);
        let sleep_for = delay.map(|d| Duration::from_micros(d.total_micros()));

        tokio::select! {
            received = link.recv(&mut rx_buf) => {
                match received {
                    Ok(0) => {}
                    Ok(len) => device.push(rx_buf[..len].to_vec()),
                    Err(_) => {
                        fail_device(&flows, &pending, &space);
                        return;
                    }
                }
            }
            () = read_wake.notified() => {
                // A flow drained its channel: the loop top re-polls and moves
                // the bytes still sitting in the socket's receive ring.
            }
            command = cmds.recv() => {
                let Some(command) = command else {
                    fail_device(&flows, &pending, &space);
                    return;
                };
                // Space freed for a flow that could not enqueue its command.
                space.notify_waiters();
                match command {
                    Command::TcpOpen { remote, reply } => {
                        if tcp_channels.len() >= config.max_sockets {
                            let _ = reply.send(Err(StackError::RefusedRequest(
                                "too many live connections".into(),
                            )));
                            continue;
                        }
                        let handle = sockets.add(tcp::Socket::new(
                            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
                            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
                        ));
                        let (channel_tx, channel_rx) = mpsc::channel(8);
                        tcp_channels.insert(handle, channel_tx);
                        next_token = next_token.wrapping_add(1);
                        let token = next_token;
                        let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let wake = Arc::new(tokio::sync::Notify::new());
                        flows.insert(handle, OpenFlow {
                            token,
                            dead: Arc::clone(&dead),
                            wake: Arc::clone(&wake),
                            opened_at: now,
                            orphaned_at: None,
                        });
                        let port = fresh_port(&mut next_port);
                        if sockets
                            .get_mut::<tcp::Socket>(handle)
                            .connect(iface.context(), endpoint(remote), port)
                            .is_ok()
                        {
                            let _ = reply.send(Ok(TcpOpen {
                                handle,
                                token,
                                dead,
                                wake,
                                rx: channel_rx,
                            }));
                        } else {
                            tcp_channels.remove(&handle);
                            flows.remove(&handle);
                            sockets.remove(handle);
                            let _ = reply.send(Err(StackError::RefusedRequest(
                                "tcp connect refused".into(),
                            )));
                        }
                    }
                    Command::TcpWrite { handle, token, data, credit, wake } => {
                        let live = flows
                            .get(&handle)
                            .is_some_and(|flow| flow.token == token);
                        if !live {
                            // The flow was reclaimed: return the credit the
                            // writer reserved so it fails rather than parking.
                            credit
                                .fetch_sub(data.len(), std::sync::atomic::Ordering::Relaxed);
                            wake.notify_one();
                            continue;
                        }
                        let mut data = data;
                        let socket = sockets.get_mut::<tcp::Socket>(handle);
                        let written = write_pending(socket, &mut data);
                        if written > 0 {
                            credit.fetch_sub(written, std::sync::atomic::Ordering::Relaxed);
                            wake.notify_one();
                        }
                        if !data.is_empty() {
                            pending
                                .entry(handle)
                                .and_modify(|write| {
                                    // Append, never replace: a second chunk must
                                    // not overwrite bytes the socket has not
                                    // taken yet.
                                    write.data.extend_from_slice(&data);
                                })
                                .or_insert(PendingWrite {
                                    data,
                                    credit,
                                    wake,
                                });
                        }
                    }
                    Command::TcpShutdown { handle, token } => {
                        if flows
                            .get(&handle)
                            .is_some_and(|flow| flow.token == token)
                        {
                            pending_shutdown.insert(handle);
                        }
                    }
                    Command::TcpClose { handle, token } => {
                        if flows
                            .get_mut(&handle)
                            .is_some_and(|flow| flow.token == token)
                        {
                            flow_mark_orphan(&mut flows, handle, now);
                        }
                    }
                    Command::UdpOpen { reply } => {
                        if udp_channels.len() >= config.max_sockets {
                            let _ = reply.send(Err(StackError::RefusedRequest(
                                "too many live udp associations".into(),
                            )));
                            continue;
                        }
                        let handle = sockets.add(udp::Socket::new(
                            udp::PacketBuffer::new(
                                vec![udp::PacketMetadata::EMPTY; 64],
                                vec![0u8; 64 * 1024],
                            ),
                            udp::PacketBuffer::new(
                                vec![udp::PacketMetadata::EMPTY; 64],
                                vec![0u8; 64 * 1024],
                            ),
                        ));
                        let port = fresh_port(&mut next_port);
                        if sockets.get_mut::<udp::Socket>(handle).bind(port).is_err() {
                            // A socket that cannot bind must not look usable:
                            // every later send would be dropped silently.
                            sockets.remove(handle);
                            let _ = reply.send(Err(StackError::RefusedRequest(
                                "udp socket could not bind".into(),
                            )));
                            continue;
                        }
                        let (channel_tx, channel_rx) = mpsc::channel(16);
                        next_token = next_token.wrapping_add(1);
                        let token = next_token;
                        udp_channels.insert(handle, (token, channel_tx));
                        let _ = reply.send(Ok((handle, token, channel_rx)));
                    }
                    Command::UdpSend { handle, token, to, data } => {
                        if udp_channels
                            .get(&handle)
                            .is_some_and(|(open, _)| *open == token)
                        {
                            let _ = sockets
                                .get_mut::<udp::Socket>(handle)
                                .send_slice(&data, endpoint(to));
                        }
                    }
                    Command::UdpClose { handle, token } => {
                        // The implicit retire above may already have freed the
                        // socket; smoltcp's `remove` panics on a freed handle,
                        // so the map removal is the gate.
                        if udp_channels
                            .get(&handle)
                            .is_some_and(|(open, _)| *open == token)
                            && udp_channels.remove(&handle).is_some()
                        {
                            sockets.remove(handle);
                        }
                    }
                }
            }
            () = sleep_optional(sleep_for) => {}
        }
    }
}

/// The driver is going away: mark every flow dead and wake its writer, so no
/// parked `poll_write`/`poll_shutdown` waits for credit that will never come.
fn fail_device(
    flows: &HashMap<SocketHandle, OpenFlow>,
    pending: &HashMap<SocketHandle, PendingWrite>,
    space: &tokio::sync::Notify,
) {
    for flow in flows.values() {
        flow.dead.store(true, std::sync::atomic::Ordering::Relaxed);
        // A writer parked on credit may have its command still in the channel,
        // so no `PendingWrite` exists to notify: notify the flow itself.
        flow.wake.notify_one();
    }
    for write in pending.values() {
        write.wake.notify_one();
    }
    space.notify_waiters();
}

/// Mark a flow orphaned by its own close command (the socket lingers for the
/// configured window, then the housekeeping reclaims it).
fn flow_mark_orphan(
    flows: &mut HashMap<SocketHandle, OpenFlow>,
    handle: SocketHandle,
    now: Instant,
) {
    if let Some(flow) = flows.get_mut(&handle) {
        flow.orphaned_at.get_or_insert(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link that wakes the driver with an empty read on every third call
    /// (no datagram), and otherwise never delivers one. The empty wake is what
    /// lets the implicit-retire scan run before a queued `UdpClose` is popped.
    struct WakeLink {
        calls: usize,
    }

    impl PacketLink for WakeLink {
        async fn recv(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.calls.is_multiple_of(3) {
                return Ok(0);
            }
            tokio::task::yield_now().await;
            Ok(0)
        }

        async fn send(&mut self, _packet: &[u8]) -> std::io::Result<()> {
            tokio::task::yield_now().await;
            Ok(())
        }
    }

    /// The implicit retire (a dropped flow's channel) and the explicit
    /// `UdpClose` both free the socket, and smoltcp's `remove` panics on a
    /// freed handle. The driver must survive the race; a panic closes the
    /// command channel and the next `open_udp` fails.
    #[tokio::test]
    async fn a_repeated_udp_close_never_frees_a_live_socket() {
        let stack = Arc::new(
            WgStack::start(
                WakeLink { calls: 0 },
                StackConfig::new(vec!["10.66.0.2/32".parse().expect("cidr")], 1420),
            )
            .expect("stack"),
        );
        for _ in 0..64 {
            let flow = stack.open_udp().await.expect("the driver is alive");
            drop(flow);
            tokio::task::yield_now().await;
        }
        assert!(
            stack.open_udp().await.is_ok(),
            "the driver must survive UdpClose racing the implicit retire"
        );
    }
}

#[cfg(test)]
mod dead_tests {
    use super::*;

    /// A link that serves one read and then fails, killing the driver.
    struct FailingLink {
        served: bool,
    }

    impl PacketLink for FailingLink {
        async fn recv(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            if self.served {
                return Err(std::io::Error::other("link down"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            self.served = true;
            Ok(0)
        }

        async fn send(&mut self, _packet: &[u8]) -> std::io::Result<()> {
            tokio::task::yield_now().await;
            Ok(())
        }
    }

    /// A writer parked on credit whose command never reached the driver must
    /// still fail: the driver keeps the flow's wake and notifies it on exit.
    #[tokio::test]
    async fn a_credit_parked_writer_fails_when_the_driver_dies() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let stack = Arc::new(
            WgStack::start(
                FailingLink { served: false },
                StackConfig::new(vec!["10.66.0.2/32".parse().expect("cidr")], 1420),
            )
            .expect("stack"),
        );
        let flow = stack
            .connect_tcp(SocketAddr::from(([10, 66, 0, 1], 7)))
            .await
            .expect("the socket opens");
        let (mut read_half, mut write_half) = tokio::io::split(flow);
        // Exhaust the credit: this write is admitted (nothing outstanding yet)
        // and the next one parks on the flow's own wake.
        write_half
            .write_all(&vec![0u8; 128 * 1024])
            .await
            .expect("the first write is admitted");
        let parked = tokio::spawn(async move { write_half.write_all(b"x").await });
        // The link fails on its second read; the driver exits and notifies.
        let mut byte = [0u8; 1];
        let eof = tokio::time::timeout(Duration::from_secs(2), read_half.read(&mut byte)).await;
        let result = tokio::time::timeout(Duration::from_secs(2), parked)
            .await
            .expect("the parked writer must not hang")
            .expect("the writer task");
        assert!(
            result.is_err(),
            "a parked writer must fail when the device dies (read={eof:?})"
        );
    }

    /// When the driver exits, every flow's writer fails (`BrokenPipe`) instead of
    /// parking on credit that will never return; the reader sees EOF.
    #[tokio::test]
    async fn a_driver_exit_fails_every_open_flow() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let stack = Arc::new(
            WgStack::start(
                FailingLink { served: false },
                StackConfig::new(vec!["10.66.0.2/32".parse().expect("cidr")], 1420),
            )
            .expect("stack"),
        );
        let mut flow = stack
            .connect_tcp(SocketAddr::from(([10, 66, 0, 1], 7)))
            .await
            .expect("the socket opens");

        // The link fails on its second read; the driver exits and marks the
        // flow dead.
        let write = tokio::time::timeout(Duration::from_secs(2), async {
            let mut buf = [0u8; 1];
            // First the read side: EOF once the driver is gone.
            let _ = flow.read(&mut buf).await;
            flow.write_all(b"x").await
        })
        .await
        .expect("the writer must not hang");
        assert!(
            write.is_err(),
            "a dead device must fail the write, not park it"
        );
    }
}
