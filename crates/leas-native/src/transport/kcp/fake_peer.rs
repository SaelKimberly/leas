//! Hermetic fake mKCP peer + end-to-end session tests (spec §7.2).
//!
//! The peer is an INDEPENDENT minimal server-side implementation on
//! [`super::wire`] only ([`parse_datagram`] / [`encode_segment`]) — it
//! deliberately does NOT reuse [`KcpSession`], so a symmetric bug (the same
//! wrong wire assumption in both the client's encode and its parse) cannot
//! cancel out. The two sides talk over real UDP on loopback (one ephemeral
//! socket each, conv adopted from the client's first datagram) with the
//! client's own driver task running the §4.4 timers — the same hermetic
//! shape as the mux/vision fake servers, but with no TLS and no cores.
//!
//! The peer mirrors the server side minimally, wire-correct per §4.1:
//! parse via [`parse_datagram`], its own receive window (`sn → payload`)
//! with consecutive advance, Ack segments carrying `rcv_wnd`/`rcv_nxt`/
//! the echoed data `ts`/acked numbers, received payloads echoed back as
//! Data segments, a `CmdOnly` reply to the client's Ping, and the close
//! handshake: a Close option is recorded (the peer keeps serving, like Go's
//! `PeerClosed`), a Terminate closes the peer's side with repeated
//! Terminate replies (Go servers send them every ping tick during the
//! handshake) so the client's state machine reaches `Terminated`.
//!
//! Injection is deterministic — no RNG: loss is an explicit drop count
//! (the first N client datagrams), out-of-order delivery holds one client
//! datagram for a bounded number of peer ticks (later segments reach the
//! client first). Assertions are event-based (peer observations polled
//! under a deadline, client reads under a timeout) — never sleep-then-
//! assert; the client's initial RTO (100ms) and tti (50ms) bound the
//! retransmit path.
//!
//! The 30s idle guard is NOT hermetic-tested here: `IDLE_CLOSE_MS` is a
//! fixed `30_000ms` constant (not tti-scaled), so a real test would need 30s
//! of wall time; the unit tests `idle_30s_closes` / `incoming_updates_idle_timer`
//! already cover the transition with the injected clock.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::transport::kcp::wire::{
    Command, Segment, SegmentOption, encode_segment, parse_datagram,
};
use crate::transport::kcp::{KcpSession, KcpSettings, State};

/// Conversation id used by every test (the client picks it; the peer adopts
/// it from the first datagram).
const CONV: u16 = 7;
/// The peer's advertised receive window (the client's `remote_rcv_nxt` only
/// takes the max, so the exact value is not interop-relevant).
const RCV_WINDOW: u32 = 1024;
/// One peer-loop tick: the recv timeout, so the loop wakes ~100×/s and the
/// delay/terminate countdowns advance.
const TICK_MS: u32 = 10;

/// Deterministic injection knobs for the fake peer.
#[derive(Debug, Clone, Default)]
pub struct PeerConfig {
    /// Drop the first `drop_first` datagrams received from the client
    /// (simulates loss before the client's timeout retransmit).
    pub drop_first: usize,
    /// Hold the echo of client datagram `index` (0-based, counted AFTER
    /// drops) for `ticks` peer-loop ticks before sending it, so the client
    /// receives later echoes first (out-of-order delivery, exercising its
    /// recv-window reassembly).
    pub delay: Option<(usize, u32)>,
    /// Do not reply to the client's Terminate (keeps serving): the client's
    /// terminate-handshake state transitions then depend on its own timers
    /// alone (T4 driver-timer regression).
    pub ignore_terminate: bool,
}

/// Observations the tests assert on (shared with the test task).
#[derive(Debug, Default)]
pub struct PeerObs {
    /// `CmdOnly Ping` segments received from the client (conv-matched).
    pub pings: u32,
    /// Data segments received from the client (first tries + retransmits).
    pub data_segments: u32,
    /// Segments received carrying the Close option.
    pub close_opts: u32,
    /// Terminate commands received from the client.
    pub terminates: u32,
    /// The peer closed its side and exited its run loop.
    pub done: bool,
}

/// A minimal, independent server-side mKCP peer over a loopback UDP socket.
struct FakeKcpPeer {
    sock: UdpSocket,
    /// Client address, adopted from the first datagram.
    client: Option<SocketAddr>,
    /// Conversation id, adopted from the first datagram.
    conv: Option<u16>,
    /// Receive window: `sn → payload` (first copy wins, like the client).
    rcv_window: HashMap<u32, Bytes>,
    /// Next consecutive receive number.
    rcv_next: u32,
    /// Ack numbers not yet flushed to the client.
    pending_acks: Vec<u32>,
    /// The latest (wrap-ahead) data `ts` echoed back in acks.
    last_data_ts: u32,
    /// Echo sequence number (the peer's own Data `sn`).
    snd_next: u32,
    config: PeerConfig,
    /// Datagrams received from the client, post-drop counter.
    received: usize,
    /// Delayed (out-of-order injected) echo datagrams: `(release_tick, bytes)`.
    held: VecDeque<(u32, Vec<u8>)>,
    /// Monotonic loop tick.
    tick: u32,
    /// Monotonic ms clock for the peer's own segment timestamps.
    now: u32,
    /// Terminate replies still to send (2 after the initial one) before the
    /// peer closes its side.
    terminating_sends: u32,
    obs: Arc<Mutex<PeerObs>>,
}

impl FakeKcpPeer {
    /// Bind a loopback socket and return the peer (not yet running).
    async fn bind(config: PeerConfig) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback");
        Self {
            sock,
            client: None,
            conv: None,
            rcv_window: HashMap::new(),
            rcv_next: 0,
            pending_acks: Vec::new(),
            last_data_ts: 0,
            snd_next: 0,
            config,
            received: 0,
            held: VecDeque::new(),
            tick: 0,
            now: 0,
            terminating_sends: 0,
            obs: Arc::new(Mutex::new(PeerObs::default())),
        }
    }

    /// The receive+send loop: tick, release delayed datagrams, serve one
    /// incoming datagram (or time out for a tick), then exit once the close
    /// handshake completes.
    async fn run(mut self) {
        let mut buf = vec![0u8; 4096];
        loop {
            self.tick = self.tick.wrapping_add(1);
            self.now = self.now.wrapping_add(TICK_MS);
            // Release held (out-of-order) echo datagrams whose hold elapsed.
            while let Some((due, datagram)) = self.held.pop_front() {
                if due > self.tick {
                    self.held.push_front((due, datagram));
                    break;
                }
                self.send_bytes(&datagram).await;
            }
            // The close handshake: keep replying Terminate a few ticks,
            // then close our side (Go servers send it repeatedly).
            if self.terminating_sends > 0 {
                self.send_terminate().await;
                self.terminating_sends -= 1;
                if self.terminating_sends == 0 {
                    break;
                }
                continue;
            }
            let recv = timeout(
                Duration::from_millis(u64::from(TICK_MS)),
                self.sock.recv_from(&mut buf),
            )
            .await;
            match recv {
                Ok(Ok((n, src))) => {
                    if let Some(client) = self.client {
                        if src != client {
                            continue;
                        }
                    } else {
                        self.client = Some(src);
                    }
                    let datagram = buf[..n].to_vec();
                    if self.received < self.config.drop_first {
                        self.received += 1;
                        continue;
                    }
                    let idx = self.received;
                    self.received += 1;
                    self.process(&datagram, idx).await;
                }
                Ok(Err(_)) => break, // socket closed underneath us
                Err(_) => {}         // recv timeout — one tick, keep looping
            }
        }
        self.obs.lock().done = true;
    }

    /// Serve one parsed segment: window the data + ack + echo; reply to
    /// pings; start the close handshake on Terminate. `idx` is the index of
    /// this datagram in the client's stream (post-drop), used by the
    /// out-of-order injection to hold the echo of one specific datagram.
    async fn process(&mut self, datagram: &[u8], idx: usize) {
        let Some(seg) = parse_datagram(datagram) else {
            return;
        };
        match seg {
            Segment::Data {
                conv,
                opt,
                ts,
                sn,
                una: _,
                payload,
            } => {
                if self.adopt(conv) != conv {
                    return;
                }
                {
                    let mut obs = self.obs.lock();
                    obs.data_segments += 1;
                    if opt.is_close() {
                        obs.close_opts += 1;
                    }
                }
                // Receive window: keep sns within [rcv_next, rcv_next + RCV_WINDOW).
                if sn.wrapping_sub(self.rcv_next) < RCV_WINDOW
                    && let Entry::Vacant(e) = self.rcv_window.entry(sn)
                {
                    e.insert(payload.clone());
                    self.pending_acks.push(sn);
                    if ts.wrapping_sub(self.last_data_ts) < 0x7FFF_FFFF {
                        self.last_data_ts = ts;
                    }
                }
                // Drain the newly-consecutive window entries and echo each
                // in stream order (the client's original order — the peer's
                // recv window reassembles like a real server's read side).
                while let Some(payload) = self.rcv_window.remove(&self.rcv_next) {
                    self.rcv_next = self.rcv_next.wrapping_add(1);
                    let echo = Segment::Data {
                        conv,
                        opt: SegmentOption::from_u8(0),
                        ts: self.now,
                        sn: self.snd_next,
                        una: self.snd_next, // nothing outstanding in the peer's fiction
                        payload,
                    };
                    self.snd_next = self.snd_next.wrapping_add(1);
                    let mut buf = Vec::with_capacity(1400);
                    encode_segment(&echo, &mut buf);
                    match self.config.delay {
                        Some((d_idx, ticks)) if d_idx == idx => {
                            // Injected out-of-order: this echo reaches the
                            // client after later ones (a real reordered path).
                            self.held.push_back((self.tick + ticks, buf));
                            continue;
                        }
                        _ => {}
                    }
                    self.send_bytes(&buf).await;
                }
                self.flush_acks().await;
            }
            Segment::Ack { conv, .. } => {
                // The peer tracks no outstanding data, so the client's acks
                // carry nothing to apply (the conv is still adopted from the
                // first segment; later mismatches are ignored).
                self.adopt(conv);
            }
            Segment::CmdOnly {
                conv,
                cmd,
                opt,
                snd_nxt: _,
                rcv_nxt: _,
                peer_rto: _,
            } => {
                if self.adopt(conv) != conv {
                    return;
                }
                match cmd {
                    Command::Ping => {
                        self.obs.lock().pings += 1;
                        // Reply with our own CmdOnly ping (wire-correct and
                        // keeps the client's idle timer fresh).
                        let reply = Segment::CmdOnly {
                            conv,
                            cmd: Command::Ping,
                            opt: SegmentOption::from_u8(0),
                            snd_nxt: self.snd_next,
                            rcv_nxt: self.rcv_next,
                            peer_rto: 100,
                        };
                        self.send(&reply).await;
                    }
                    Command::Terminate => {
                        self.obs.lock().terminates += 1;
                        if self.config.ignore_terminate {
                            // Keep serving, never reply: the client's
                            // handshake must advance on its own timers.
                        } else {
                            self.terminating_sends = 2;
                            self.send_terminate().await;
                        }
                    }
                    Command::Ack | Command::Data => {}
                }
                if opt.is_close() {
                    self.obs.lock().close_opts += 1;
                }
            }
        }
    }

    /// Adopt the conversation id from the first segment; later mismatches
    /// are dropped (the peer serves one conversation).
    fn adopt(&mut self, conv: u16) -> u16 {
        self.conv.unwrap_or_else(|| {
            self.conv = Some(conv);
            conv
        })
    }

    /// Flush the pending ack numbers as one Ack segment.
    async fn flush_acks(&mut self) {
        if self.pending_acks.is_empty() {
            return;
        }
        let numbers = std::mem::take(&mut self.pending_acks);
        let ack = Segment::Ack {
            conv: self.conv.unwrap_or(CONV),
            opt: SegmentOption::from_u8(0),
            rcv_wnd: self.rcv_next.wrapping_add(RCV_WINDOW),
            rcv_nxt: self.rcv_next,
            ts: self.last_data_ts,
            numbers,
        };
        self.send(&ack).await;
    }

    async fn send_terminate(&self) {
        let seg = Segment::CmdOnly {
            conv: self.conv.unwrap_or(CONV),
            cmd: Command::Terminate,
            opt: SegmentOption::from_u8(0),
            snd_nxt: self.snd_next,
            rcv_nxt: self.rcv_next,
            peer_rto: 100,
        };
        self.send(&seg).await;
    }

    /// Send one segment to the client. Errors are swallowed (best-effort
    /// peer; the tests' assertions catch any failure).
    async fn send(&self, seg: &Segment) {
        let mut buf = Vec::with_capacity(1400);
        encode_segment(seg, &mut buf);
        self.send_bytes(&buf).await;
    }

    /// Send one already-encoded datagram to the client. Errors are
    /// swallowed (best-effort peer).
    async fn send_bytes(&self, buf: &[u8]) {
        let Some(client) = self.client else {
            return;
        };
        let _ = self.sock.send_to(buf, client).await;
    }
}

/// A real client session wired to the loopback socket: the session's output
/// closure (sync — called from the driver task) pushes datagrams into an
/// unbounded channel drained by a task that `send_to`s them, and a recv
/// task feeds every inbound datagram into [`KcpSession::input`].
pub struct ClientHarness {
    pub session: Arc<KcpSession>,
    _sender: tokio::task::JoinHandle<()>,
    _recv: tokio::task::JoinHandle<()>,
}

impl ClientHarness {
    pub async fn write(&self, buf: &[u8]) -> std::io::Result<()> {
        self.session.write(buf).await
    }

    pub fn close(&self) {
        self.session.close();
    }

    pub fn state(&self) -> State {
        self.session.state()
    }
}

/// Spawn a client session sending to `peer_addr` over a fresh loopback
/// socket (default mtu 1350 / tti 50).
async fn spawn_client(peer_addr: SocketAddr) -> ClientHarness {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback"));
    // The session's output closure is sync (called from the driver task), so
    // datagrams cross an mpsc channel to a task that awaits `send_to`.
    // (`try_send_to` cannot be used here: `try_io` returns WouldBlock until
    // the reactor observes the fresh registration as writable.)
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let session = Arc::new(KcpSession::new(
        CONV,
        KcpSettings::new(1350, 50),
        move |buf: &[u8]| {
            // The channel is unbounded and the sender task drains promptly,
            // so the driver never blocks; a dropped channel would surface as
            // a send error, swallowed like Go's ignored write errors.
            let _ = tx.send(buf.to_vec());
            Ok(())
        },
    ));
    let send_sock = Arc::clone(&sock);
    let sender = tokio::spawn(async move {
        while let Some(buf) = rx.recv().await {
            let _ = send_sock.send_to(&buf, peer_addr).await;
        }
    });
    let recv_sock = Arc::clone(&sock);
    let recv_session = Arc::clone(&session);
    let recv = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, _)) = recv_sock.recv_from(&mut buf).await else {
                break;
            };
            recv_session.input(&buf[..n]);
        }
    });
    ClientHarness {
        session,
        _sender: sender,
        _recv: recv,
    }
}

/// Bind + spawn the peer, then a client pointing at it.
pub async fn spawn_harness(config: PeerConfig) -> (ClientHarness, Arc<Mutex<PeerObs>>) {
    let peer = FakeKcpPeer::bind(config).await;
    let obs = Arc::clone(&peer.obs);
    let peer_addr = peer.sock.local_addr().expect("local addr");
    tokio::spawn(peer.run());
    let client = spawn_client(peer_addr).await;
    (client, obs)
}

/// Read exactly `expected` bytes (or EOF) from the client under `deadline`.
pub async fn read_all(client: &ClientHarness, expected: usize, deadline: Duration) -> Vec<u8> {
    let mut got = Vec::with_capacity(expected);
    let mut chunk = vec![0u8; 8192];
    loop {
        if got.len() >= expected {
            return got;
        }
        let n = timeout(deadline, client.session.read(&mut chunk))
            .await
            .expect("read deadline exceeded")
            .expect("read error");
        if n == 0 {
            return got; // EOF — the caller's equality assert fails
        }
        got.extend_from_slice(&chunk[..n]);
    }
}

/// A non-trivial payload spanning `segments` mss-sized chunks (distinct
/// bytes per chunk, so cross-segment reassembly order is observable).
pub fn payload(segments: usize) -> Vec<u8> {
    let mss = KcpSettings::new(1350, 50).mss; // 1332
    let mut payload = Vec::with_capacity(segments * mss);
    let mut n = 0u32;
    while payload.len() < segments * mss {
        payload.extend_from_slice(&n.to_le_bytes());
        n = n.wrapping_add(1);
    }
    payload.truncate(segments * mss);
    payload
}

#[tokio::test]
async fn hermetic_echo_roundtrip_multisegment() {
    let (client, obs) = spawn_harness(PeerConfig::default()).await;
    // 5328 bytes = 4 mss (1332) segments — crosses the mss boundary, so the
    // client splits the write and the peer echoes 4 Data segments back.
    let payload = payload(4);
    client.write(&payload).await.expect("write");
    let got = read_all(&client, payload.len(), Duration::from_secs(5)).await;
    assert_eq!(got, payload, "echoed payload must match, in order");
    // All 4 segments were received (no spurious retransmission expected on
    // a lossless loopback; >= guards against a pathological driver stall).
    assert!(obs.lock().data_segments >= 4, "peer saw the 4 segments");
}

#[tokio::test]
async fn hermetic_retransmit_under_loss() {
    // Drop the first two client datagrams: segments 0 and 1 are lost, the
    // client's RTO (100ms initial) retransmits them, and the peer's acks +
    // echoes must deliver the full payload with no data loss.
    let (client, obs) = spawn_harness(PeerConfig {
        drop_first: 2,
        ..PeerConfig::default()
    })
    .await;
    let payload = payload(4);
    client.write(&payload).await.expect("write");
    let got = read_all(&client, payload.len(), Duration::from_secs(5)).await;
    assert_eq!(got, payload, "no data loss under injected loss");
    // Segments 2,3 (first try) + 0,1 (retransmit) = 4 deliveries minimum;
    // the full payload could only arrive if the drop was recovered.
    assert!(obs.lock().data_segments >= 4, "retransmissions delivered");
}

#[tokio::test]
async fn hermetic_out_of_order_reassembly() {
    // The peer holds datagram 1 for 4 ticks (~40ms < the client's 100ms
    // RTO): the client receives segments 0 and 2 first, then 1, and must
    // reassemble the stream in order.
    let (client, _obs) = spawn_harness(PeerConfig {
        delay: Some((1, 4)),
        ..PeerConfig::default()
    })
    .await;
    let payload = payload(3);
    client.write(&payload).await.expect("write");
    let got = read_all(&client, payload.len(), Duration::from_secs(5)).await;
    assert_eq!(
        got, payload,
        "out-of-order segments must reassemble in order"
    );
}

#[tokio::test]
async fn hermetic_close_handshake() {
    let (client, obs) = spawn_harness(PeerConfig::default()).await;
    // Leave the send window nonempty at close: the first flush is capped at
    // cwnd = remote_rcv_nxt (32) - first_unacked (0) = 32 segments, so a
    // 34-segment write guarantees a remainder that flushes with the Close
    // option after close() (Go wire order). The peer then sees the
    // Terminate, replies (Go sends it repeatedly), and both sides reach
    // their closed state.
    let payload = vec![0x5Au8; 34 * KcpSettings::new(1350, 50).mss];
    client.write(&payload).await.expect("write");
    client.close();
    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);
    loop {
        let (close_opts, terminates, done, state) = {
            let o = obs.lock();
            (o.close_opts, o.terminates, o.done, client.state())
        };
        if close_opts > 0 && terminates > 0 && done && state == State::Terminated {
            break;
        }
        let _ = tokio::select! {
            () = &mut deadline => panic!(
                "close handshake incomplete: close_opts={close_opts} terminates={terminates} \
                 done={done} state={state:?}"
            ),
            () = tokio::time::sleep(Duration::from_millis(20)) => 1u8,
        };
    }
    assert!(
        obs.lock().close_opts > 0,
        "peer must observe the Close option"
    );
    assert!(obs.lock().terminates > 0, "peer must observe Terminate");
    assert!(obs.lock().done, "peer must close its side");
    assert_eq!(client.state(), State::Terminated);
}

#[tokio::test]
async fn hermetic_ping_cadence() {
    let (client, obs) = spawn_harness(PeerConfig::default()).await;
    // The silence ping fires at 3000ms of no traffic and the driver's ping
    // tick wakes at 5s, so the peer observes a wire-correct CmdOnly Ping
    // within the expected window. The peer's reply keeps the client's idle
    // timer fresh.
    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);
    loop {
        if obs.lock().pings >= 1 {
            break;
        }
        let _ = tokio::select! {
            () = &mut deadline => panic!("no CmdOnly Ping observed within 10s"),
            () = tokio::time::sleep(Duration::from_millis(20)) => 1u8,
        };
    }
    assert_eq!(
        client.state(),
        State::Active,
        "peer pings keep the session alive"
    );
}
