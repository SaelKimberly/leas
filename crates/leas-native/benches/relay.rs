//! Relay benches: the SOCKS5 inbound in front of a Direct outbound — the
//! code in `inbound/mod.rs` (accept → negotiate → route) plus
//! `inbound/outbound.rs::relay` for TCP and `run_udp_relay` for datagrams.
//!
//! Deliberately core-binary free: the client is a hand-written no-auth SOCKS5
//! client (the byte sequences are the ones `inbound/tests.rs` uses), the
//! destination is the in-process sink/source/echo harness, and the router is
//! a rules-free `Engine` with a default route to `direct` (the production
//! shape, `server/mod.rs:104-112`). Every measured nanosecond belongs to this
//! crate — nothing here resolves or spawns an external core, so no row can
//! skip.
#![cfg(feature = "native-e2e")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use leas_native::addr::{Host, TargetAddr};
use leas_native::e2e::harness::{spawn_sink, spawn_source, spawn_udp_echo};
use leas_native::inbound::{Outbound, OutboundKind, Socks5Inbound, Socks5InboundConfig, socks5};
use leas_route::Engine;
use leas_route::ir::{DefaultRoute, ResolveStrategy, RuleSet};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};

/// Datagrams per `socks5-udp/pps` iteration.
const DATAGRAMS: u64 = 1000;
/// Payload bytes per benched datagram.
const UDP_PAYLOAD: usize = 512;
/// Per-datagram reply budget. A lost datagram must not wedge the row, and
/// loopback round trips are microseconds — two seconds only ever fires on a
/// real fault.
const REPLY_WAIT: Duration = Duration::from_secs(2);

fn bench_mb() -> u64 {
    std::env::var("LEAS_BENCH_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(64)
}

/// Bind + serve one SOCKS5 inbound: no auth, no rules, everything routed to
/// the single `direct` outbound. Returns the bound address and the accept
/// loop's handle (abort it when the last row is done).
fn spawn_inbound(rt: &tokio::runtime::Runtime) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let engine = Arc::new(
        Engine::build(RuleSet {
            rules: Vec::new(),
            default: DefaultRoute::Route {
                tag: "direct".to_owned(),
            },
            resolve_strategy: ResolveStrategy::AsIs,
            probes: Vec::new(),
        })
        .expect("bench engine builds"),
    );
    let config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("bench listen addr"),
        engine,
        vec![Outbound {
            tag: "direct".to_owned(),
            kind: OutboundKind::Direct,
        }],
    );
    let inbound = rt
        .block_on(Socks5Inbound::bind(config))
        .expect("bench inbound binds");
    let addr = inbound.local_addr().expect("bench inbound local addr");
    let serve = rt.spawn(async move {
        let _ = inbound.serve().await;
    });
    (addr, serve)
}

/// A no-auth SOCKS5 CONNECT to an IPv4 destination: greeting `05 01 00` →
/// `05 00`, request `05 01 00 01 <ipv4> <port>` → `05 00 …` reply.
async fn socks5_connect(inbound: SocketAddr, target: SocketAddr) -> TcpStream {
    let SocketAddr::V4(target) = target else {
        panic!("bench destinations are IPv4 (the harness binds 127.0.0.1)");
    };
    let mut stream = TcpStream::connect(inbound)
        .await
        .expect("connect to inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut selection = [0u8; 2];
    stream
        .read_exact(&mut selection)
        .await
        .expect("method selection");
    assert_eq!(selection, [0x05, 0x00], "no-auth selected");
    stream
        .write_all(&[0x05, 0x01, 0x00, 0x01])
        .await
        .expect("request head");
    stream
        .write_all(&target.ip().octets())
        .await
        .expect("request dst addr");
    stream
        .write_all(&target.port().to_be_bytes())
        .await
        .expect("request dst port");
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.expect("reply head");
    assert_eq!(head[0], 0x05, "reply version");
    assert_eq!(head[1], 0x00, "CONNECT succeeded");
    assert_eq!(head[3], 0x01, "v4 bind address");
    let mut bnd = [0u8; 4 + 2];
    stream.read_exact(&mut bnd).await.expect("reply bnd addr");
    stream
}

/// Open a no-auth UDP ASSOCIATE. Returns the controlling TCP stream (the
/// association dies with it, RFC 1928 §7 — hold it for the whole row) and
/// the client-facing relay address.
async fn udp_associate(inbound: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut stream = TcpStream::connect(inbound)
        .await
        .expect("connect to inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut selection = [0u8; 2];
    stream
        .read_exact(&mut selection)
        .await
        .expect("method selection");
    assert_eq!(selection, [0x05, 0x00], "no-auth selected");
    // All-zero DST: the server ignores it and binds its own relay socket.
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
    stream.read_exact(&mut bnd).await.expect("reply bnd addr");
    let ip = IpAddr::V4(Ipv4Addr::new(bnd[0], bnd[1], bnd[2], bnd[3]));
    let port = u16::from_be_bytes([bnd[4], bnd[5]]);
    assert_ne!(port, 0, "BND.PORT is the bound relay port");
    (stream, SocketAddr::new(ip, port))
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "the criterion group must stay alive across every row it registers"
)]
fn criterion_benches(c: &mut Criterion) {
    // Multi-thread: the harness targets and the inbound accept loop are
    // `tokio::spawn`ed at setup — a current-thread runtime would never poll
    // them while the bench thread sits in `block_on`.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("bench runtime");
    let n = bench_mb() * 1024 * 1024;
    let payload = vec![0xABu8; 1024 * 1024];
    let chunks = usize::try_from(n).expect("bench bytes fit usize") / payload.len();

    // `spawn_*` call `tokio::spawn` internally: they need an entered runtime
    // context. The guard MUST drop before any `block_on` — `block_on` panics
    // inside an entered context. The spawned tasks keep running on the
    // multi-thread workers afterwards.
    let (sink, source, udp_echo) = {
        let enter = rt.enter();
        let held = (spawn_sink(), spawn_source(), spawn_udp_echo());
        drop(enter);
        held
    };
    let (inbound, serve) = spawn_inbound(&rt);

    let mut group = c.benchmark_group("relay");
    group.throughput(Throughput::Bytes(n));

    // Send: push N client→sink through one CONNECT per row. `write_all`
    // returns on local buffering, so stay in the timed section until the sink
    // has counted N (same goodput gate as `throughput.rs`).
    let mut send_client = rt.block_on(socks5_connect(inbound, sink.addr));
    group.bench_function("socks5-direct/send", |b| {
        b.iter(|| {
            rt.block_on(async {
                let want = sink.received.load(Ordering::SeqCst) + n;
                for _ in 0..chunks {
                    send_client
                        .write_all(&payload)
                        .await
                        .expect("relay send write");
                }
                send_client.flush().await.expect("relay send flush");
                while sink.received.load(Ordering::SeqCst) < want {
                    tokio::task::yield_now().await;
                }
            });
        });
    });
    drop(send_client);

    // Recv: the source streams zeros forever, so one CONNECT serves every
    // iteration — read exactly N per iteration.
    let mut recv_client = rt.block_on(socks5_connect(inbound, source.addr));
    group.bench_function("socks5-direct/recv", |b| {
        let mut buf = vec![0u8; 1024 * 1024];
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..chunks {
                    recv_client
                        .read_exact(&mut buf)
                        .await
                        .expect("relay recv read");
                }
            });
        });
    });
    drop(recv_client);

    // UDP: one association, `DATAGRAMS` round trips per iteration.
    let (control, relay_addr) = rt.block_on(udp_associate(inbound));
    let client_udp = rt
        .block_on(UdpSocket::bind("127.0.0.1:0"))
        .expect("bench client udp socket");
    let target = TargetAddr::new(
        Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        udp_echo.addr.port(),
    );
    let datagram = {
        let mut packet = socks5::new_udp_header(&target);
        packet.extend_from_slice(&[0x5Au8; UDP_PAYLOAD]);
        packet
    };
    let reply_len = datagram.len();
    // Warm-up outside the timed section: the first datagram is what binds the
    // association's upstream socket, and parsing its reply proves the row
    // measures a real round trip through the relay.
    rt.block_on(async {
        client_udp
            .send_to(&datagram, relay_addr)
            .await
            .expect("warm-up datagram");
        let mut buf = vec![0u8; 2048];
        let (len, _) = tokio::time::timeout(REPLY_WAIT, client_udp.recv_from(&mut buf))
            .await
            .expect("warm-up reply timed out")
            .expect("warm-up reply");
        let (frag, replied, echoed) =
            socks5::parse_udp_request(&buf[..len]).expect("reply header parses");
        assert_eq!(frag, 0, "replies are never fragmented");
        assert_eq!(
            replied.port,
            udp_echo.addr.port(),
            "reply header names the echo target"
        );
        assert_eq!(echoed.len(), UDP_PAYLOAD, "payload echoed verbatim");
        assert_eq!(len, reply_len, "reply framing is header + payload");
    });

    group.throughput(Throughput::Elements(DATAGRAMS));
    group.bench_function("socks5-udp/pps", |b| {
        let mut buf = vec![0u8; 2048];
        b.iter(|| {
            let replies = rt.block_on(async {
                let mut replies = 0u64;
                for _ in 0..DATAGRAMS {
                    client_udp
                        .send_to(&datagram, relay_addr)
                        .await
                        .expect("relay udp send");
                    // One datagram in flight at a time: a 1000-datagram burst
                    // overruns the loopback socket buffers and the row would
                    // measure kernel drops instead of the relay.
                    match tokio::time::timeout(REPLY_WAIT, client_udp.recv_from(&mut buf)).await {
                        Ok(Ok((len, _))) => {
                            assert_eq!(len, reply_len, "reply framing is header + payload");
                            replies += 1;
                        }
                        Ok(Err(error)) => panic!("relay udp recv: {error}"),
                        // Lost datagram: never waited on again, counted below.
                        Err(_) => (),
                    }
                }
                replies
            });
            assert!(
                replies * 100 >= DATAGRAMS * 99,
                "relay dropped {} of {DATAGRAMS} datagrams",
                DATAGRAMS - replies
            );
        });
    });

    group.finish();
    // The association outlives its rows only while the controlling stream is
    // open; the accept loop and harness targets die with their handles.
    drop(control);
    serve.abort();
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
