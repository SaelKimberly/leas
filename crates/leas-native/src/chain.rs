//! Client-side chaining: tunnel through several proxies in order.
//!
//! Parity with xray `outbound.proxySettings.socksTag` and sing-box `detour`.
//! `links[0]` is dialed directly and carries `links[1]`'s traffic
//! (links[0].target = links[1].server); the last link reaches `target`.
//!
//! Fold (n=1 is `connect`): for each link, dial (first hop) or reuse the
//! previous tunnel, then run security (TLS/REALITY) OUTERMOST, then the
//! transport upgrade (ws/grpc framing inside the TLS session), then the
//! protocol, threading the resulting stream into the next link as its
//! `base`.

use leas_proto::proto_spec::ProtocolKind;

use crate::addr::TargetAddr;
use crate::context::{LinkContext, NativeConnectParams};
use crate::error::NativeError;
use crate::protocol;
use crate::protocol::PacketTunnel;
use crate::protocol::ss;
use crate::security;
use crate::transport;
use crate::{BoxStream, NativeTunnel};

/// The destination of link `i`: the next link's server, or `target` for the
/// last link. Pure function — unit-tested independently of the fold.
fn next_target(links: &[NativeConnectParams], i: usize, target: &TargetAddr) -> TargetAddr {
    links.get(i + 1).map_or_else(
        || target.clone(),
        |next| TargetAddr::new(next.server.host.as_str(), next.server.port),
    )
}

/// The QUIC-family placement rule, shared by every fold: a QUIC-family
/// protocol (Hysteria2/Hysteria1/TUIC) dials its own connection, replacing
/// dial + security + upgrade (spec §5.2), so it must be the LAST link and
/// cannot ride an existing base tunnel.
fn quic_guard(
    links: &[NativeConnectParams],
    i: usize,
    base: Option<&BoxStream>,
) -> Result<(), NativeError> {
    if i + 1 != links.len() {
        return Err(NativeError::Config(
            "a QUIC-family protocol (Hysteria2/Hysteria1/TUIC) must be the last link".into(),
        ));
    }
    if base.is_some() {
        return Err(NativeError::Config(
            "a QUIC-family protocol cannot reuse a base tunnel (fresh QUIC dial)".into(),
        ));
    }
    Ok(())
}

/// An SS UDP link dials its own UDP socket straight to the server, so it must
/// be the only link: there is no base tunnel for it to ride and no way to
/// carry it through a chain (mirrors [`quic_guard`]).
fn ss_udp_guard(
    links: &[NativeConnectParams],
    i: usize,
    base: Option<&BoxStream>,
) -> Result<(), NativeError> {
    if links.len() != 1 || i + 1 != links.len() || base.is_some() {
        return Err(NativeError::Config(
            "shadowsocks UDP dials its own UDP socket and cannot ride a proxy chain".into(),
        ));
    }
    Ok(())
}

/// One link's stream after the dial: security (TLS/REALITY) OUTERMOST, then
/// the transport upgrade (ws/grpc framing inside the TLS session) — except
/// for self-contained dials (xhttp+h3) where the dial already IS the
/// finished tunnel and the engine TLS/upgrade must be skipped (spec §5.2:
/// the QUIC dial replaces dial + security + upgrade; quinn's rustls is
/// internal).
async fn secured_upgraded(ctx: &LinkContext, dialed: BoxStream) -> Result<BoxStream, NativeError> {
    if transport::is_self_contained(ctx) {
        return Ok(dialed);
    }
    let secured = security::wrap(ctx, dialed).await?;
    transport::upgrade(ctx, secured).await
}

/// Connect through a chain of proxies to the final `target`.
pub async fn connect_chain(
    links: &[NativeConnectParams],
    target: TargetAddr,
) -> Result<NativeTunnel, NativeError> {
    let mut base: Option<BoxStream> = None;
    for (i, link) in links.iter().enumerate() {
        let to = next_target(links, i, &target);
        // Owned clone per hop (not `&link`): `LinkContext` crosses `.await`
        // points and a borrow would lifetime-infect the struct plus every
        // `&ctx` consumer for a per-connection, usually-single-hop clone.
        // Deliberately kept (memory-diet Task 6 ruling).
        let ctx = LinkContext::new(link.clone(), to);
        if protocol::is_quic_link(&ctx) {
            // QUIC-family protocols (Hysteria2/Hysteria1/TUIC) are a
            // divergent dial: `protocol::connect_quic` performs the QUIC dial
            // (replacing dial + security + upgrade — spec §5.2) and the
            // placement rule applies (`quic_guard`).
            quic_guard(links, i, base.as_ref())?;
            base = Some(protocol::connect_quic(&ctx).await?);
            continue;
        }
        let dialed = transport::connect(&ctx, base).await?;
        let upgraded = secured_upgraded(&ctx, dialed).await?;
        base = Some(protocol::connect(&ctx, upgraded).await?);
    }
    base.map(NativeTunnel::from_stream)
        .ok_or_else(|| NativeError::Config("empty chain".into()))
}

/// Connect through a chain of proxies to `target` with a protocol-generic
/// UDP datagram tunnel.
///
/// Identical to [`connect_chain`] except the LAST link runs the UDP
/// protocol phase and the result is the datagram [`PacketTunnel`] instead
/// of a byte tunnel. The carrier is the last link's protocol: VLESS command
/// 0x02 (`[2B len]` framing, packetaddr headers, or mux XUDP), `VMess`
/// command 0x02 AEAD records, trojan command 3 address-prefixed frames, or
/// hysteria2 QUIC DATAGRAM `UDPMessage` frames. Intermediate links tunnel
/// TCP as usual — they carry the UDP tunnel as a byte stream to the next
/// hop; hysteria2 dials its own QUIC connection and is therefore the only
/// link (`quic_guard`). Shadowsocks is the same shape for a different reason:
/// its UDP relay is reached by sending datagrams to the server's own UDP
/// port, so `ss_udp_guard` refuses any chain around it and the carrier binds
/// its socket directly.
pub async fn connect_chain_udp(
    links: &[NativeConnectParams],
    target: TargetAddr,
) -> Result<PacketTunnel, NativeError> {
    let mut base: Option<BoxStream> = None;
    for (i, link) in links.iter().enumerate() {
        let to = next_target(links, i, &target);
        let ctx = LinkContext::new(link.clone(), to);
        if protocol::is_quic_link(&ctx) {
            // QUIC-family protocols are a divergent dial: the hysteria2 UDP
            // path dials a fresh QUIC connection and runs its own datagram
            // relay, under the same placement rule (`quic_guard`).
            quic_guard(links, i, base.as_ref())?;
            return match &ctx.params.protocol {
                leas_proto::proto_spec::ProtocolConfig::Hysteria2(cfg) => {
                    protocol::reject_vless_only_mode(&ctx, ProtocolKind::Hysteria2)?;
                    Ok(PacketTunnel::Hysteria2(
                        crate::protocol::hysteria2::connect_udp(&ctx, cfg).await?,
                    ))
                }
                _ => Err(NativeError::NotImplemented {
                    feature: "udp over a QUIC-family protocol (only hysteria2 implemented)".into(),
                }),
            };
        }
        if protocol::is_udp_dial_link(&ctx) {
            // Shadowsocks UDP: the dial IS a UDP socket to the server — no
            // security, no transport, no base tunnel. A link that dials its
            // own socket cannot ride a chain (mirrors `quic_guard`).
            ss_udp_guard(links, i, base.as_ref())?;
            let leas_proto::proto_spec::ProtocolConfig::Ss(cfg) = &ctx.params.protocol else {
                unreachable!("is_udp_dial_link matches only Ss");
            };
            let method = ss::resolve_method(cfg)?;
            protocol::reject_vless_only_mode(&ctx, method.kind())?;
            return Ok(PacketTunnel::Ss(
                ss::udp::connect_udp(&ctx, method, cfg).await?,
            ));
        }
        let dialed = transport::connect(&ctx, base).await?;
        let upgraded = secured_upgraded(&ctx, dialed).await?;
        if i + 1 == links.len() {
            // The last link speaks the UDP protocol phase: it owns the
            // stream and returns the datagram tunnel.
            return protocol::connect_udp(&ctx, upgraded).await;
        }
        base = Some(protocol::connect(&ctx, upgraded).await?);
    }
    Err(NativeError::Config("empty chain".into()))
}

/// Connect through a chain of proxies to `target` with a VLESS v1.mux.cool
/// multiplexed tunnel (command 0x03).
///
/// Identical to [`connect_chain`] except the LAST link runs the mux
/// protocol phase and the result is a [`protocol::MuxTunnel`] instead of a
/// byte tunnel. Intermediate links tunnel TCP as usual — they carry the mux
/// tunnel as a byte stream to the next hop.
///
/// The tunnel is per family ([`protocol::MuxTunnel`]): VLESS's sessions are
/// already framed by the multiplexer, while a Shadowsocks plugin row's
/// sessions still need their own codec, so the caller opens a session through
/// one method on both.
pub async fn connect_chain_mux(
    links: &[NativeConnectParams],
    target: TargetAddr,
) -> Result<protocol::MuxTunnel, NativeError> {
    let mut base: Option<BoxStream> = None;
    for (i, link) in links.iter().enumerate() {
        let to = next_target(links, i, &target);
        let ctx = LinkContext::new(link.clone(), to);
        if protocol::is_quic_link(&ctx) {
            return Err(NativeError::Config(
                "a QUIC-family protocol (Hysteria2/Hysteria1/TUIC) is not supported by the                  mux tunnel path".into(),
            ));
        }
        let dialed = transport::connect(&ctx, base).await?;
        let upgraded = secured_upgraded(&ctx, dialed).await?;
        if i + 1 == links.len() {
            // The last link speaks the mux protocol phase: it owns the
            // stream and returns the multiplexer.
            return protocol::connect_mux(&ctx, upgraded).await;
        }
        base = Some(protocol::connect(&ctx, upgraded).await?);
    }
    Err(NativeError::Config("empty chain".into()))
}

#[cfg(test)]
mod tests {
    use leas_proto::proto_spec::ProtocolConfig;
    use leas_proto::proto_spec::SecurityConfig;
    use leas_proto::proto_spec::SsConfig;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;

    use super::*;
    use crate::addr::Host;

    fn vless_empty() -> ProtocolConfig {
        serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "tcp" }
        }))
        .expect("vless config parses")
    }

    fn params(host: &str, port: u16) -> NativeConnectParams {
        NativeConnectParams::new(
            vless_empty(),
            EndpointEssentials::new(host, port),
            TargetAddr::new(Host::Domain("ignored".into()), 1),
        )
    }

    #[test]
    fn next_target_uses_next_server() {
        let links = [params("a.example", 10), params("b.example", 20)];
        let final_target = TargetAddr::new(Host::Domain("www.example.com".into()), 443);
        assert_eq!(
            next_target(&links, 0, &final_target),
            TargetAddr::new(Host::Domain("b.example".into()), 20)
        );
        assert_eq!(next_target(&links, 1, &final_target), final_target);
    }

    #[test]
    fn quic_guard_allows_only_a_last_link_without_a_base() {
        // The placement rule both folds share: a fresh QUIC dial cannot be
        // an intermediate hop and cannot ride an existing tunnel.
        let links = [params("a.example", 10), params("b.example", 20)];
        quic_guard(&links, 1, None).expect("last link, no base tunnel");
        assert!(matches!(
            quic_guard(&links, 0, None),
            Err(NativeError::Config(msg)) if msg.contains("must be the last link")
        ));
        let base: BoxStream = Box::new(tokio::io::duplex(1).0);
        assert!(matches!(
            quic_guard(&links, 1, Some(&base)),
            Err(NativeError::Config(msg)) if msg.contains("cannot reuse a base tunnel")
        ));
    }

    /// A single-link SS row pointed at a local port (the server double in the
    /// carrier tests); the link target is a placeholder that the chain target
    /// deliberately overrides.
    fn ss_params(method: &str, password: &str, port: u16) -> NativeConnectParams {
        NativeConnectParams::new(
            ProtocolConfig::Ss(SsConfig {
                method: method.into(),
                password: password.into(),
                security: SecurityConfig::default(),
                remarks: None,
                plugin: None,
            }),
            EndpointEssentials::new("127.0.0.1", port),
            TargetAddr::new(Host::Domain("ignored".into()), 1),
        )
    }

    /// An SS UDP link dials its own socket, like a QUIC-family link: it must
    /// be the only link and there is no base tunnel to hand it.
    #[test]
    fn ss_udp_guard_allows_only_the_single_link() {
        let links = [
            ss_params("aes-128-gcm", "pw", 8388),
            params("b.example", 20),
        ];
        ss_udp_guard(&links[..1], 0, None).expect("the only link");
        assert!(matches!(
            ss_udp_guard(&links, 0, None),
            Err(NativeError::Config(msg)) if msg.contains("cannot ride a proxy chain")
        ));
        let base: BoxStream = Box::new(tokio::io::duplex(1).0);
        assert!(matches!(
            ss_udp_guard(&links[..1], 0, Some(&base)),
            Err(NativeError::Config(_))
        ));
    }

    /// The SS UDP arm reaches the carrier with no TLS or transport in
    /// between: the tunnel really owns a socket pointing at the server's
    /// port, and a datagram sent through it lands there. The payload's
    /// `ATYP|addr|port` is the 7-byte IPv4 form of the chain TARGET, not the
    /// link's placeholder domain — the wire pins which one the carrier uses.
    #[tokio::test]
    async fn ss_udp_link_dials_the_carrier_directly() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let links = [ss_params("aes-128-gcm", "hunter2", port)];
        let target = TargetAddr::new(Host::Ip(std::net::IpAddr::from([1, 2, 3, 4])), 53);
        let mut tunnel = connect_chain_udp(&links, target).await.unwrap();
        assert!(matches!(&tunnel, PacketTunnel::Ss(_)));

        tunnel.send(None, b"x").await.unwrap();
        let mut buf = [0u8; 256];
        let (read, _from) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.recv_from(&mut buf),
        )
        .await
        .expect("the datagram reaches the server")
        .unwrap();
        // aes-128-gcm: [salt 16][seal(ATYP|addr|port ‖ payload) 7+1+16].
        assert_eq!(read, 16 + 7 + 1 + 16);
    }

    #[test]
    fn empty_chain_errors() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let res = rt.block_on(connect_chain(
            &[],
            TargetAddr::new(Host::Domain("x".into()), 1),
        ));
        assert!(matches!(res, Err(NativeError::Config(_))));
    }
}
