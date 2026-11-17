//! Test-only helpers for the external `leas-oracles` e2e crate
//! (`e2e-support` feature).
//!
//! The carrier-reuse probe drives the **real** `Socks5Inbound` — the user-visible
//! path (SOCKS → router → pool → carrier → core) — with a counting TCP proxy in
//! front of the core, so a multiplexed workload can be asserted to open exactly
//! one carrier handshake (spec 2026-11-17 A10). Nothing in the crate sets this
//! feature.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use leas_proto::proto_spec::endpoint::EndpointEssentials;
use leas_proto::proto_spec::{ProtocolConfig, ProtocolKind};
use leas_route::Engine;
use leas_route::ir::{DefaultRoute, ResolveStrategy, RuleSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::addr::{Host, TargetAddr};
use crate::inbound::outbound::ProxyOutbound;
use crate::mux_pool::MuxPolicy;
use crate::{Outbound, OutboundKind, Socks5Inbound, Socks5InboundConfig};

/// One pooled-reuse probe run.
pub struct PooledSocks {
    /// SOCKS reply code per CONNECT (`0` = success).
    pub codes: Vec<u8>,
    /// Body of each successful HTTP exchange (empty for failed legs).
    pub bodies: Vec<String>,
    /// Carrier handshakes counted in front of the core.
    pub accepted: usize,
}

/// Drive `sessions` SOCKS CONNECTs through a real [`Socks5Inbound`] whose proxy
/// outbound dials the core through a counting TCP proxy.
///
/// The core must be reachable at `server`; the inbound's own server is the
/// counting proxy. A multiplexed row should report **one** accept; a per-leg
/// row reports one per session.
pub async fn probe_pooled_socks(
    protocol: ProtocolConfig,
    kind: ProtocolKind,
    server: EndpointEssentials,
    target: SocketAddr,
    sessions: usize,
    padding: bool,
) -> PooledSocks {
    let ip: IpAddr = server.host.parse().expect("oracle core host is an IP");
    let core = SocketAddr::new(ip, server.port);
    let (proxy_addr, accepted) = spawn_counting_proxy(core).await;

    let proxy_server = EndpointEssentials::new(server.host.clone(), proxy_addr.port());
    let proxy_out = ProxyOutbound {
        protocol,
        kind,
        server: proxy_server,
        resolved_ip: Some(proxy_addr),
    };
    let engine = Arc::new(
        Engine::build(RuleSet {
            rules: Vec::new(),
            default: DefaultRoute::Route {
                tag: "proxy".to_owned(),
            },
            resolve_strategy: ResolveStrategy::AsIs,
            probes: Vec::new(),
        })
        .expect("reuse probe engine"),
    );
    let mut config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("socks addr"),
        engine,
        vec![Outbound {
            tag: "proxy".to_owned(),
            kind: OutboundKind::Proxy(Box::new(proxy_out)),
        }],
    );
    config.udp = false;
    let mut policy = MuxPolicy::production();
    policy.padding = padding;
    config.mux_policy = policy;
    // The helper intentionally ignores the app config: the row's request is
    // what the e2e case carries (`.with_mux(true)`), and production policy
    // covers the default-on rows.
    let inbound = Socks5Inbound::bind(config)
        .await
        .expect("bind reuse inbound");
    let socks = inbound.local_addr().expect("reuse socks addr");
    let task = tokio::spawn(async move {
        let _ = inbound.serve().await;
    });

    let mut codes = Vec::with_capacity(sessions);
    let mut bodies = Vec::with_capacity(sessions);
    for _ in 0..sessions {
        let (reply_code, body) = socks_session(socks, target)
            .await
            .unwrap_or_else(|| (0xFF, String::new()));
        codes.push(reply_code);
        bodies.push(body);
    }
    let accepted = accepted.load(Ordering::Acquire);
    task.abort();
    PooledSocks {
        codes,
        bodies,
        accepted,
    }
}

/// One SOCKS CONNECT + HTTP GET through the relay. `None` for a broken
/// handshake.
async fn socks_session(socks: SocketAddr, target: SocketAddr) -> Option<(u8, String)> {
    let mut stream = tokio::net::TcpStream::connect(socks).await.ok()?;
    stream.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await.ok()?;
    if selection != [0x05, 0x00] {
        return None;
    }
    let mut request = vec![0x05, 0x01, 0x00];
    match target.ip() {
        IpAddr::V4(v4) => {
            request.push(0x01);
            request.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(_) => return None,
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.ok()?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.ok()?;
    let code = reply[1];
    // BND.ADDR/BND.PORT: this inbound reports 0.0.0.0:0 (ATYP 1 + 6 bytes).
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await.ok()?;
    if code != 0 {
        return Some((code, String::new()));
    }
    let body = http_get(&mut stream).await;
    Some((code, body))
}

/// GET `/` and return the body (empty on failure), bounded by 15 s.
async fn http_get<S>(stream: &mut S) -> String
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const STEP: std::time::Duration = std::time::Duration::from_secs(15);
    if tokio::time::timeout(STEP, stream.write_all(REQUEST))
        .await
        .is_err()
    {
        return String::new();
    }
    let mut buf = Vec::new();
    if tokio::time::timeout(STEP, stream.read_to_end(&mut buf))
        .await
        .is_err()
    {
        return String::new();
    }
    let text = String::from_utf8_lossy(&buf);
    text.split_once("\r\n\r\n")
        .map_or_else(String::new, |(_, body)| body.to_owned())
}

/// A transparent TCP forwarder + accept counter (one per carrier handshake).
async fn spawn_counting_proxy(target: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting proxy");
    let addr = listener.local_addr().expect("counting proxy addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                break;
            };
            count.fetch_add(1, Ordering::AcqRel);
            let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });
    (addr, accepted)
}

/// The target as the mux frame expects it (domain or IP, port).
#[must_use]
pub fn target_addr(target: SocketAddr) -> TargetAddr {
    TargetAddr::new(Host::Ip(target.ip()), target.port())
}

/// One pooled-reuse UDP probe run (A12).
pub struct PooledSocksUdp {
    /// Datagrams sent.
    pub sent: usize,
    /// Datagrams whose echo came back intact.
    pub replies: usize,
    /// Carrier handshakes counted in front of the core.
    pub accepted: usize,
}

/// Drive `count` UDP datagrams through a real `Socks5Inbound` UDP ASSOCIATE.
///
/// The proxy leg is pooled (XUDP on mux.cool, a UDP stream on an sbox wire);
/// a multiplexed row must open ONE carrier for all of them.
pub async fn probe_pooled_socks_udp(
    protocol: ProtocolConfig,
    kind: ProtocolKind,
    server: EndpointEssentials,
    target: SocketAddr,
    count: usize,
    padding: bool,
) -> PooledSocksUdp {
    use std::net::Ipv4Addr;
    use tokio::net::{TcpStream, UdpSocket};

    let ip: IpAddr = server.host.parse().expect("oracle core host is an IP");
    let core = SocketAddr::new(ip, server.port);
    let (proxy_addr, accepted) = spawn_counting_proxy(core).await;

    let proxy_server = EndpointEssentials::new(server.host.clone(), proxy_addr.port());
    let proxy_out = ProxyOutbound {
        protocol,
        kind,
        server: proxy_server,
        resolved_ip: Some(proxy_addr),
    };
    let engine = Arc::new(
        Engine::build(RuleSet {
            rules: Vec::new(),
            default: DefaultRoute::Route {
                tag: "proxy".to_owned(),
            },
            resolve_strategy: ResolveStrategy::AsIs,
            probes: Vec::new(),
        })
        .expect("udp reuse engine"),
    );
    let mut config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("socks addr"),
        engine,
        vec![Outbound {
            tag: "proxy".to_owned(),
            kind: OutboundKind::Proxy(Box::new(proxy_out)),
        }],
    );
    config.udp = true;
    let mut policy = MuxPolicy::production();
    policy.padding = padding;
    config.mux_policy = policy;
    let inbound = Socks5Inbound::bind(config)
        .await
        .expect("bind udp reuse inbound");
    let socks = inbound.local_addr().expect("socks addr");
    let task = tokio::spawn(async move {
        let _ = inbound.serve().await;
    });

    let mut sent = 0;
    let mut replies = 0;
    let Ok(mut control) = TcpStream::connect(socks).await else {
        task.abort();
        return PooledSocksUdp {
            sent,
            replies,
            accepted: accepted.load(Ordering::Acquire),
        };
    };
    if control.write_all(&[0x05, 0x01, 0x00]).await.is_ok() {
        let mut selection = [0u8; 2];
        if control.read_exact(&mut selection).await.is_ok()
            && selection == [0x05, 0x00]
            && control
                .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .is_ok()
        {
            let mut reply = [0u8; 4];
            if control.read_exact(&mut reply).await.is_ok() && reply[1] == 0 {
                let mut port = [0u8; 2];
                let ok = match reply[3] {
                    0x01 => {
                        let mut addr = [0u8; 6];
                        control.read_exact(&mut addr).await.is_ok().then(|| {
                            port.copy_from_slice(&addr[4..6]);
                        })
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        if control.read_exact(&mut len).await.is_err() {
                            None
                        } else {
                            let mut addr = vec![0u8; usize::from(len[0]) + 2];
                            control.read_exact(&mut addr).await.ok().map(|_| {
                                port.copy_from_slice(&addr[addr.len() - 2..]);
                            })
                        }
                    }
                    0x04 => {
                        let mut addr = [0u8; 18];
                        control.read_exact(&mut addr).await.is_ok().then(|| {
                            port.copy_from_slice(&addr[16..18]);
                        })
                    }
                    _ => None,
                };
                if ok.is_some() {
                    let relay =
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), u16::from_be_bytes(port));
                    if let Ok(udp) = UdpSocket::bind("127.0.0.1:0").await {
                        for index in 0..count {
                            let payload = format!("udp-{index}");
                            let mut frame = vec![0u8, 0, 0];
                            match target.ip() {
                                IpAddr::V4(v4) => {
                                    frame.push(0x01);
                                    frame.extend_from_slice(&v4.octets());
                                }
                                IpAddr::V6(v6) => {
                                    frame.push(0x04);
                                    frame.extend_from_slice(&v6.octets());
                                }
                            }
                            frame.extend_from_slice(&target.port().to_be_bytes());
                            frame.extend_from_slice(payload.as_bytes());
                            if udp.send_to(&frame, relay).await.is_err() {
                                break;
                            }
                            sent += 1;
                            let mut buffer = [0u8; 2048];
                            let read = tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                udp.recv_from(&mut buffer),
                            )
                            .await;
                            let Ok(Ok((length, _))) = read else {
                                break;
                            };
                            if let Some(echo) = socks5_udp_payload(&buffer[..length])
                                && echo == payload.as_bytes()
                            {
                                replies += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    drop(control);
    let accepted = accepted.load(Ordering::Acquire);
    task.abort();
    PooledSocksUdp {
        sent,
        replies,
        accepted,
    }
}

/// Strip the SOCKS5 UDP header (`RSV,FRAG,ATYP,addr,port`).
fn socks5_udp_payload(packet: &[u8]) -> Option<&[u8]> {
    const PREFIX: usize = 3;
    let atyp = *packet.get(PREFIX)?;
    let mut offset = PREFIX + 1;
    match atyp {
        0x01 => offset += 4,
        0x04 => offset += 16,
        0x03 => {
            let length = usize::from(*packet.get(offset)?);
            offset += 1 + length;
        }
        _ => return None,
    }
    offset += 2;
    packet.get(offset..)
}
