//! VLESS — the reference protocol for the native core.

use tokio::io::AsyncWriteExt;

use leas_proto::proto_spec::{VlessConfig, parse_mlkem_encryption};

use crate::BoxStream;
use crate::addr::{Host, TargetAddr};
use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};
use crate::protocol::vless::stream::VlessClientStream;
use crate::protocol::vless::vision::{
    FLOW_XTLS_RPRX_VISION, FLOW_XTLS_RPRX_VISION_UDP443, VisionStream,
};

pub mod encryption;
pub mod header;
pub mod packet;
pub(crate) mod packetaddr;
pub mod stream;
pub(crate) mod udp;
pub(crate) mod vision;

// The mux codec moved to `crate::transport::mux` (spec §7): the
// v1.mux.cool frame format plus a session multiplexer, with no VLESS
// specifics — the SS plugin arm shares it verbatim.
pub use crate::transport::mux::{MuxClient, MuxTarget, SessionStream, UdpSession};
pub use packet::{PacketConn, PacketMode, PacketReader, PacketWriter, SplitHalves};

/// Connect through a VLESS outbound over an already-secured stream.
///
/// Writes the request header and returns a tunnel that strips the response
/// header on its first read (see `stream.rs` for the eager-vs-lazy header
/// semantics of xray-core vs sing-box).
///
/// `flow == "xtls-rprx-vision"` / `"xtls-rprx-vision-udp443"` takes the
/// vision path: the header carries the protobuf flow addon (spec §4.1,
/// the udp443 variant truncated to `xtls-rprx-vision` on the wire — spec
/// §4.3), the camouflage frame is emitted right after it (spec §4.6 step
/// 3, deviation 1), and the padded codec wraps the stream (spec §5.4).
/// Any other non-empty flow stays the `NotImplemented` guard.
pub async fn connect(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &VlessConfig,
) -> Result<BoxStream, NativeError> {
    // `mlkem768x25519plus` account encryption wraps the whole session (xray
    // outbound.go): the PQ handshake runs on the secured stream first, then
    // the request header goes through it sealed.
    if let Some(enc) = cfg.encryption.as_deref().filter(|e| !e.is_empty()) {
        return connect_encrypted(ctx, stream, cfg, enc).await;
    }
    let uuid = header::uuid_bytes(&cfg.uuid)?;
    match cfg.flow.as_deref() {
        None | Some("") => connect_plain(ctx, stream, uuid).await,
        Some(FLOW_XTLS_RPRX_VISION | FLOW_XTLS_RPRX_VISION_UDP443) => {
            connect_vision(ctx, stream, uuid, cfg.flow.as_deref()).await
        }
        Some(other) => Err(NativeError::NotImplemented {
            feature: format!("vless flow {other}"),
        }),
    }
}

/// The `mlkem768x25519plus` connect path (spec §4.3, §5.3): PQ handshake,
/// then the plain request header through the encrypted tunnel, then the
/// response-peeled tunnel. Flow addons cannot combine with it (xray treats
/// the encryption as the account's whole identity layer).
async fn connect_encrypted(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &VlessConfig,
    enc: &str,
) -> Result<BoxStream, NativeError> {
    let invalid = |what: String| NativeError::Config(format!("vless mlkem encryption: {what}"));
    let parsed = parse_mlkem_encryption(enc)
        .map_err(|e| invalid(e.to_string()))?
        .ok_or_else(|| invalid(format!("unsupported encryption value {enc}")))?;
    if cfg.flow.as_deref().is_some_and(|f| !f.is_empty()) {
        return Err(invalid(
            "flow cannot be combined with mlkem encryption".into(),
        ));
    }
    let uuid = header::uuid_bytes(&cfg.uuid)?;
    let ecfg = encryption::EncryptionConfig::try_from_parsed(&parsed)?;
    let mut conn = encryption::handshake(stream, &ecfg).await?;
    let request = header::encode_request(&uuid, &ctx.target, header::CMD_TCP, None)?;
    let timeout = timeouts::PROTOCOL;
    tokio::time::timeout(timeout, conn.write_all(&request))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "vless mlkem request write",
            limit: timeout,
        })??;
    Ok(Box::new(VlessClientStream::with_ack_slot(
        Box::new(conn),
        ctx.ack.clone(),
    )))
}

/// Plain VLESS connect: request header without addons, then the tunnel.
async fn connect_plain(
    ctx: &LinkContext,
    stream: BoxStream,
    uuid: [u8; 16],
) -> Result<BoxStream, NativeError> {
    let request = header::encode_request(&uuid, &ctx.target, header::CMD_TCP, None)?;
    let timeout = timeouts::PROTOCOL;
    let mut stream = stream;
    tokio::time::timeout(timeout, stream.write_all(&request))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "vless request write",
            limit: timeout,
        })??;

    Ok(Box::new(VlessClientStream::with_ack_slot(
        stream,
        ctx.ack.clone(),
    )))
}

/// Vision (`xtls-rprx-vision` / `xtls-rprx-vision-udp443`) connect path
/// (spec §5.4).
///
/// Guarded preconditions, checked before any protocol-phase I/O (the
/// header write):
/// - outer security is TLS or REALITY (the engine is TLS 1.3-only, so the
///   `ctx.is_tls()` check is the whole story) — mirroring xray's rejection;
/// - the transport is raw TCP — vision requires the socket for the Direct
///   handoff (spec §5.1; ws/grpc/xhttp framing is incompatible);
/// - the command is TCP. The UDP path is separate ([`connect_udp`]); the
///   udp443 variant takes this same path for TCP — the `-udp443` suffix
///   only lifts the UDP rejection via the mux rewrite (spec §4.3).
async fn connect_vision(
    ctx: &LinkContext,
    stream: BoxStream,
    uuid: [u8; 16],
    flow: Option<&str>,
) -> Result<BoxStream, NativeError> {
    if !ctx.is_tls() {
        return Err(NativeError::Config(
            "XTLS only supports TLS and REALITY directly for now".into(),
        ));
    }
    if ctx.transport_type() != Some("tcp") {
        return Err(NativeError::Config(
            "XTLS only supports the TCP transport for now".into(),
        ));
    }

    // Step 2: request header with the flow addon (addon_len = 18; the
    // udp443 variant's addon is truncated to `xtls-rprx-vision` — spec
    // §4.3).
    let request = header::encode_request(
        &uuid,
        &ctx.target,
        header::CMD_TCP,
        header::encode_addons(flow).as_deref(),
    )?;
    let timeout = timeouts::PROTOCOL;
    let mut stream = stream;
    tokio::time::timeout(timeout, stream.write_all(&request))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "vless request write",
            limit: timeout,
        })??;

    // Step 3: the camouflage frame — one empty long-padding Continue frame
    // carrying the UUID, right after the header (xray delays it 500 ms via
    // a timer; we emit it immediately — same wire bytes, spec §9 deviation
    // 1). The camouflage consumes the writer's UUID, so the codec's own
    // frames never carry one.
    let camo = VisionStream::<BoxStream>::camouflage_frame(&uuid);
    tokio::time::timeout(timeout, stream.write_all(&camo))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "vless vision camouflage write",
            limit: timeout,
        })??;

    // Wrap the secured stream in the padded codec, with the response-header
    // peel INSIDE it — Go's exact composition (outbound.go getResponse
    // peels the header from the raw conn BEFORE wrapping the VisionReader).
    // The server's `[0,0]` response header — whether its own outer-TLS
    // record or coalesced with the first padded frame (xray's inbound
    // buffers it via EncodeResponseHeader + SetFlushNext and flushes both
    // together) — is consumed by the peel, so the codec's UUID gate never
    // sees it and the multiplexer/payload never sees it either.
    let peeled: BoxStream = Box::new(VlessClientStream::with_ack_slot(stream, ctx.ack.clone()));
    let vision = VisionStream::new(peeled, uuid);
    Ok(Box::new(vision))
}

/// UDP/flow guard: the vision flows cannot carry UDP over the RAW
/// `command=0x02` tunnel — xray rewrites UDP to the XUDP mux path under
/// vision (spec §2), so the raw path rejects here; the mux path
/// (`params.mux`, or the udp443 flow which forces it) is allowed (XUDP,
/// spec §4.3, §5.3).
fn check_udp_allowed(
    flow: Option<&str>,
    udp: Option<PacketMode>,
    mux: bool,
) -> Result<(), NativeError> {
    let vision_flow =
        flow == Some(FLOW_XTLS_RPRX_VISION) || flow == Some(FLOW_XTLS_RPRX_VISION_UDP443);
    if udp.is_some() && !mux && vision_flow {
        return Err(NativeError::NotImplemented {
            feature:
                "VLESS vision does not support UDP over the raw path (XUDP requires the mux tunnel)"
                    .into(),
        });
    }
    Ok(())
}

/// A fresh random 8-byte `GlobalID` per tunnel (spec §4.2, deviation 1):
/// xray derives it per source via blake3; the server requires only
/// non-empty, so a CSPRNG draw is functionally equivalent for a
/// single-user client (ring is already a dep — the xhttp `x_padding`
/// pattern).
fn random_global_id() -> [u8; 8] {
    let mut gid = [0u8; 8];
    crate::rand::fill_nonsecret(&mut gid);
    gid
}

/// UDP connect (protocol phase, parallel to [`connect_plain`]).
///
/// The chain runs dial → security → transport exactly as for TCP. Two
/// tunnels:
/// - RAW (`params.mux = false`, and not the udp443 flow): writes the
///   request header with `command = 0x02` and the UDP destination
///   (port-first, spec §4.1), then wraps the tunnel in the packet-framed
///   [`PacketConn`] for the configured mode, carrying that header
///   destination along — in `Raw` mode a send naming a different
///   destination is refused ([`PacketConn::send`]).
/// - XUDP (`params.mux`, or the udp443 flow which forces it): runs the
///   mux tunnel (`connect_mux`), opens one UDP session with a fresh
///   random `GlobalID`, and wraps it in the `XUdp` [`PacketConn`].
///
/// The vision+UDP guard ([`check_udp_allowed`]) runs before any
/// protocol-phase I/O (the header write).
pub async fn connect_udp(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &VlessConfig,
) -> Result<PacketConn<BoxStream>, NativeError> {
    let uuid = header::uuid_bytes(&cfg.uuid)?;
    // The udp443 flow rewrites UDP to the mux tunnel regardless of
    // `params.mux` — xray's `allowUDP443` skips the vision UDP rejection
    // and the mux rewrite applies to all UDP under vision (spec §4.3).
    let mux = ctx.params.mux || cfg.flow.as_deref() == Some(FLOW_XTLS_RPRX_VISION_UDP443);
    check_udp_allowed(cfg.flow.as_deref(), ctx.params.udp, mux)?;
    let mode = ctx.params.udp.ok_or_else(|| {
        NativeError::Config("vless udp connect requires params.udp (None = TCP path)".into())
    })?;
    if mux {
        // XUDP (spec §5.3): the mux tunnel (vision composition for the
        // vision flows — addon + camouflage, peel inside), one UDP session
        // with a fresh random GlobalID, wrapped in the XUdp PacketConn. No
        // 2-byte framing — the mux frames carry the length and the
        // per-packet destination (spec §4.1, §5.2).
        let mux_client = connect_mux(ctx, stream, cfg).await?;
        let session = mux_client.open_udp_session(random_global_id())?;
        return Ok(PacketConn::xudp(session));
    }
    match cfg.flow.as_deref() {
        None | Some("") => connect_udp_plain(ctx, stream, uuid, mode).await,
        Some(other) => Err(NativeError::NotImplemented {
            feature: format!("vless flow {other}"),
        }),
    }
}

/// Plain UDP connect: request header without addons (`cmd = CMD_UDP`), then
/// the packet-framed tunnel over the same header destination.
async fn connect_udp_plain(
    ctx: &LinkContext,
    stream: BoxStream,
    uuid: [u8; 16],
    mode: PacketMode,
) -> Result<PacketConn<BoxStream>, NativeError> {
    let header_dest = udp_header_target(ctx, mode)?;
    let request = header::encode_request(&uuid, &header_dest, header::CMD_UDP, None)?;
    let timeout = timeouts::PROTOCOL;
    let mut stream = stream;
    tokio::time::timeout(timeout, stream.write_all(&request))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "vless udp request write",
            limit: timeout,
        })??;

    Ok(PacketConn::new(stream, mode, &header_dest))
}

/// The header destination for the UDP command.
///
/// Raw mode: the UDP target itself (port-first). `PacketAddr` mode: the magic
/// fqdn with port 0 — the header carries no real destination, the
/// per-packet magic-address headers do (spec §4.3; sing-vmess
/// `DialEarlyPacketConn(conn, Socksaddr{Fqdn: magic})`). Domain targets are
/// rejected in packetaddr mode (spec §4.3, sing's `ErrFqdnUnsupported`).
fn udp_header_target(ctx: &LinkContext, mode: PacketMode) -> Result<TargetAddr, NativeError> {
    match mode {
        PacketMode::Raw => Ok(ctx.target.clone()),
        PacketMode::PacketAddr => {
            if matches!(ctx.target.host, Host::Domain(_)) {
                return Err(NativeError::Config(
                    "packetaddr: domain destination is not supported".into(),
                ));
            }
            Ok(TargetAddr::new(
                Host::Domain(packetaddr::MAGIC.to_string()),
                0,
            ))
        }
        // XUdp never builds a raw header destination: the mux command
        // carries none (connect_mux's mux_header_target) — the UDP header
        // path is the non-mux one only.
        PacketMode::XUdp => Err(NativeError::Config(
            "vless xudp has no header destination (the mux command carries none)".into(),
        )),
    }
}

/// Mux connect (protocol phase, parallel to [`connect_udp`]).
///
/// The chain runs dial → security → transport exactly as for TCP; this
/// writes the request header with `command = 0x03` and the fixed
/// `v1.mux.cool` destination (spec §4.1), then wraps the tunnel in the
/// [`MuxClient`] multiplexer. The wire carries NO destination bytes for
/// the mux command (xray's `EncodeRequestHeader` skips the address; the
/// server derives the magic fqdn from the command byte) — the target
/// built by [`mux_header_target`] is the semantic destination, not
/// encoded bytes. Sessions are TCP streams
/// ([`MuxClient::open_session`]) or XUDP datagrams
/// ([`MuxClient::open_udp_session`] — the UDP path [`connect_udp`] takes
/// when mux is enabled). The udp443 flow takes the vision composition
/// here (addon truncated to `xtls-rprx-vision` — spec §4.3).
pub async fn connect_mux(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &VlessConfig,
) -> Result<MuxClient<BoxStream>, NativeError> {
    // The mux tunnel only carries XUDP datagrams (or TCP sessions) — the
    // Raw/PacketAddr packet modes belong to the command=0x02 path
    // (connect_udp's mux branch never reads the mode value, but a caller
    // reaching connect_mux directly with a misconfigured params.udp would
    // silently lose it). Reject upfront.
    if let Some(mode) = ctx.params.udp
        && mode != PacketMode::XUdp
    {
        return Err(NativeError::Config(format!(
            "vless mux: params.udp {mode:?} is not XUdp — the mux tunnel only carries XUDP datagrams (Raw/PacketAddr belong to the command=0x02 path)"
        )));
    }
    let uuid = header::uuid_bytes(&cfg.uuid)?;
    match cfg.flow.as_deref() {
        None | Some("") => connect_mux_plain(ctx, stream, uuid).await,
        Some(FLOW_XTLS_RPRX_VISION | FLOW_XTLS_RPRX_VISION_UDP443) => {
            connect_mux_vision(ctx, stream, uuid, cfg.flow.as_deref()).await
        }
        Some(other) => Err(NativeError::NotImplemented {
            feature: format!("vless flow {other}"),
        }),
    }
}

/// Plain mux connect: request header without addons (`cmd = CMD_MUX`),
/// then the multiplexer over the peeled tunnel.
async fn connect_mux_plain(
    ctx: &LinkContext,
    stream: BoxStream,
    uuid: [u8; 16],
) -> Result<MuxClient<BoxStream>, NativeError> {
    let request = header::encode_request(&uuid, &mux_header_target(), header::CMD_MUX, None)?;
    let timeout = timeouts::PROTOCOL;
    let mut stream = stream;
    tokio::time::timeout(timeout, stream.write_all(&request))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "vless mux request write",
            limit: timeout,
        })??;

    // The mux frame stream rides the peeled tunnel: the server's `[0,0]`
    // response header is consumed on the first read, then frames flow.
    let peeled: BoxStream = Box::new(VlessClientStream::with_ack_slot(stream, ctx.ack.clone()));
    Ok(MuxClient::new(peeled))
}

/// Vision (`xtls-rprx-vision` / `xtls-rprx-vision-udp443`) mux connect
/// (spec §5.3): `cmd = CMD_MUX` with the flow addon, the camouflage
/// frame, then the vision-padded multiplexer.
///
/// Guarded preconditions mirror [`connect_vision`], checked before any
/// protocol-phase I/O:
/// - outer security is TLS or REALITY (`ctx.is_tls()`) — mirroring xray's
///   rejection of bare vision;
/// - the transport is raw TCP — vision requires the socket for the Direct
///   handoff (spec §5.1; ws/grpc/xhttp framing is incompatible).
///
/// Unlike the TCP command path there is no command guard: xray servers
/// accept vision+mux (`inbound.go` splices `RequestCommandMux` under flow
/// XRV with `CanSpliceCopy = 3`). The udp443 variant is the XUDP carrier
/// under vision — the addon truncates to `xtls-rprx-vision` (spec §4.3).
async fn connect_mux_vision(
    ctx: &LinkContext,
    stream: BoxStream,
    uuid: [u8; 16],
    flow: Option<&str>,
) -> Result<MuxClient<BoxStream>, NativeError> {
    if !ctx.is_tls() {
        return Err(NativeError::Config(
            "XTLS only supports TLS and REALITY directly for now".into(),
        ));
    }
    if ctx.transport_type() != Some("tcp") {
        return Err(NativeError::Config(
            "XTLS only supports the TCP transport for now".into(),
        ));
    }

    // Step 2: request header with the flow addon (addon_len = 18; the
    // udp443 variant's addon is truncated to `xtls-rprx-vision` — spec
    // §4.3).
    let request = header::encode_request(
        &uuid,
        &mux_header_target(),
        header::CMD_MUX,
        header::encode_addons(flow).as_deref(),
    )?;
    let timeout = timeouts::PROTOCOL;
    let mut stream = stream;
    tokio::time::timeout(timeout, stream.write_all(&request))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "vless mux request write",
            limit: timeout,
        })??;

    // Step 3: the camouflage frame — one empty long-padding Continue frame
    // carrying the UUID, right after the header (same wire bytes as the
    // TCP vision path, spec §4.6 step 3 deviation 1).
    let camo = VisionStream::<BoxStream>::camouflage_frame(&uuid);
    tokio::time::timeout(timeout, stream.write_all(&camo))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "vless mux vision camouflage write",
            limit: timeout,
        })??;

    // The response-header peel, THEN the vision codec, then the
    // multiplexer — Go's client peels the header from the raw conn before
    // wrapping the VisionReader (outbound.go getResponse), so neither the
    // VisionReader nor the mux dispatcher ever sees the `[0,0]` (the same
    // composition as the TCP vision path `connect_vision`).
    let peeled: BoxStream = Box::new(VlessClientStream::with_ack_slot(stream, ctx.ack.clone()));
    let vision = VisionStream::new(peeled, uuid);
    Ok(MuxClient::new(Box::new(vision)))
}

/// The header destination for the mux command: the fixed `v1.mux.cool`
/// fqdn and port (spec §4.1 — xray `common/mux/client.go`
/// `muxCoolAddress` / `muxCoolPort`). Passed to
/// [`header::encode_request`] as the mux command's target; the `CMD_MUX`
/// arm does not encode it on the wire.
fn mux_header_target() -> TargetAddr {
    TargetAddr::new(
        Host::Domain(crate::transport::mux::MUX_DEST.to_string()),
        crate::transport::mux::MUX_PORT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Host, TargetAddr};
    use crate::context::NativeConnectParams;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use rstest::rstest;

    fn vless(flow: Option<&str>, transport: &str, security: bool) -> VlessConfig {
        let mut obj = serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": transport },
        });
        if let Some(f) = flow {
            obj["flow"] = serde_json::json!(f);
        }
        if security {
            obj["security"] = serde_json::json!({ "type": "tls", "sni": "example.com" });
        }
        serde_json::from_value(obj).expect("vless config parses")
    }

    fn ctx_for(cfg: &VlessConfig) -> LinkContext {
        let params = NativeConnectParams::new(
            leas_proto::proto_spec::ProtocolConfig::Vless(cfg.clone()),
            EndpointEssentials::new("127.0.0.1", 443),
            TargetAddr::new(Host::Domain("example.com".into()), 80),
        );
        LinkContext::new(
            params,
            TargetAddr::new(Host::Domain("example.com".into()), 80),
        )
    }

    /// A client stream plus its live peer half (the header write must have
    /// somewhere to go; the guard-error tests fail before any write).
    fn stream_pair() -> (BoxStream, tokio::io::DuplexStream) {
        let (client, peer) = tokio::io::duplex(1024);
        (Box::new(client), peer)
    }

    /// The flow gates reject the invalid configs, identically for both entry
    /// points (`connect` / `connect_mux`): vision needs an outer TLS/REALITY
    /// layer and a TCP transport, and any other flow stays `NotImplemented`.
    #[rstest]
    #[case::vision_requires_tls(
        false,
        vless(Some("xtls-rprx-vision"), "tcp", false),
        false,
        "TLS and REALITY"
    )]
    #[case::vision_rejects_non_tcp(
        false,
        vless(Some("xtls-rprx-vision"), "ws", true),
        false,
        "TCP transport"
    )]
    #[case::unknown_flow(
        false,
        vless(Some("xtls-rprx-splice"), "tcp", true),
        true,
        "xtls-rprx-splice"
    )]
    #[case::mux_vision_requires_tls(
        true,
        vless(Some("xtls-rprx-vision"), "tcp", false),
        false,
        "TLS and REALITY"
    )]
    #[case::mux_vision_rejects_non_tcp(
        true,
        vless(Some("xtls-rprx-vision"), "ws", true),
        false,
        "TCP transport"
    )]
    #[case::mux_unknown_flow(
        true,
        vless(Some("xtls-rprx-splice"), "tcp", true),
        true,
        "xtls-rprx-splice"
    )]
    fn flow_gates_reject_invalid_configs(
        #[case] mux: bool,
        #[case] cfg: VlessConfig,
        #[case] not_implemented: bool,
        #[case] expected: &str,
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (stream, _peer) = stream_pair();
            let result = if mux {
                connect_mux(&ctx_for(&cfg), stream, &cfg).await.map(|_| ())
            } else {
                connect(&ctx_for(&cfg), stream, &cfg).await.map(|_| ())
            };
            let err = result.expect_err("the flow gate must reject the config");
            if not_implemented {
                assert!(matches!(
                    &err,
                    NativeError::NotImplemented { feature } if feature.contains(expected)
                ));
            } else {
                assert!(matches!(&err, NativeError::Config(msg) if msg.contains(expected)));
            }
        });
    }

    #[tokio::test]
    async fn empty_and_missing_flow_take_plain_path() {
        // No TLS: the plain path writes the header and returns a tunnel —
        // the peer half stays alive so the header write lands. Vision would
        // reject this config; plain must not.
        for flow in [None, Some("")] {
            let cfg = vless(flow, "tcp", false);
            let (stream, _peer) = stream_pair();
            let result = connect(&ctx_for(&cfg), stream, &cfg).await;
            assert!(result.is_ok(), "flow {flow:?} must take the plain path");
        }
    }

    /// A `LinkContext` with the UDP mode set, otherwise like [`ctx_for`].
    fn udp_ctx_for(cfg: &VlessConfig, mode: PacketMode) -> LinkContext {
        let mut ctx = ctx_for(cfg);
        ctx.params.udp = Some(mode);
        ctx
    }

    #[tokio::test]
    async fn vision_udp_raw_still_rejected() {
        // Vision + UDP on the RAW path is still rejected in BOTH packet
        // modes, before any I/O — SP1's guard, exercised through the real
        // connect_udp entry (XUDP requires the mux tunnel; spec §5.3).
        for mode in [PacketMode::Raw, PacketMode::PacketAddr] {
            let cfg = vless(Some("xtls-rprx-vision"), "tcp", true);
            let (stream, _peer) = stream_pair();
            let err = connect_udp(&udp_ctx_for(&cfg, mode), stream, &cfg)
                .await
                .err()
                .expect("vision + UDP must fail");
            assert!(
                matches!(&err, NativeError::NotImplemented { feature } if feature.contains("XUDP")),
                "mode {mode:?}: {err}"
            );
        }
    }

    #[test]
    fn check_udp_allowed_guard_matrix() {
        // The guard rejects ONLY the vision flows + UDP on the RAW path
        // (XUDP requires the mux tunnel); every other combination passes —
        // plain flows, unknown flows, vision over the mux path, vision on
        // the TCP path.
        for flow in [
            Some(FLOW_XTLS_RPRX_VISION),
            Some(FLOW_XTLS_RPRX_VISION_UDP443),
        ] {
            for mode in [Some(PacketMode::Raw), Some(PacketMode::PacketAddr)] {
                let err = check_udp_allowed(flow, mode, false).unwrap_err();
                assert!(
                    matches!(&err, NativeError::NotImplemented { feature } if feature.contains("XUDP")),
                    "{flow:?} mode {mode:?}: {err}"
                );
            }
        }
        // The mux path lifts the rejection (XUDP) for both vision flows.
        assert!(
            check_udp_allowed(Some(FLOW_XTLS_RPRX_VISION), Some(PacketMode::Raw), true).is_ok()
        );
        assert!(
            check_udp_allowed(
                Some(FLOW_XTLS_RPRX_VISION_UDP443),
                Some(PacketMode::PacketAddr),
                true
            )
            .is_ok()
        );
        assert!(check_udp_allowed(None, Some(PacketMode::Raw), false).is_ok());
        assert!(check_udp_allowed(Some(""), Some(PacketMode::PacketAddr), false).is_ok());
        assert!(check_udp_allowed(Some("xtls-rprx-splice"), Some(PacketMode::Raw), false).is_ok());
        assert!(check_udp_allowed(Some(FLOW_XTLS_RPRX_VISION), None, false).is_ok());
        assert!(check_udp_allowed(None, None, true).is_ok());
    }

    #[tokio::test]
    async fn udp_connect_requires_udp_mode() {
        // connect_udp with params.udp = None is a config error (None = the
        // TCP path), never a silent default.
        let cfg = vless(None, "tcp", false);
        let (stream, _peer) = stream_pair();
        let err = connect_udp(&ctx_for(&cfg), stream, &cfg)
            .await
            .err()
            .expect("udp: None must fail");
        assert!(matches!(&err, NativeError::Config(msg) if msg.contains("params.udp")));
    }

    #[tokio::test]
    async fn udp_connect_writes_cmd_udp_header() {
        // Raw mode: version, uuid, addon_len 0, cmd 0x02, then the
        // port-first UDP dest — identical to TCP except the command byte
        // (spec §4.1). The returned PacketConn is live over the tunnel.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let cfg = vless(None, "tcp", false);
        let mut ctx = ctx_for(&cfg);
        ctx.target = TargetAddr::new(Host::new("1.2.3.4"), 8080);
        ctx.params.udp = Some(PacketMode::Raw);
        let (stream, mut peer) = stream_pair();
        let mut conn = connect_udp(&ctx, stream, &cfg)
            .await
            .expect("raw udp connect");

        let mut expected = vec![0x00];
        expected.extend_from_slice(&header::uuid_bytes(&cfg.uuid).unwrap());
        expected.push(0x00); // addon_len 0
        expected.push(0x02); // cmd UDP
        expected.extend_from_slice(&[0x1f, 0x90, 0x01, 1, 2, 3, 4]); // port-first dest
        let mut got = [0u8; 26];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, &expected[..]);

        // One datagram roundtrip through the tunnel.
        conn.send(None, b"ping").await.unwrap();
        let mut frame = [0u8; 6];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, &[0x00, 0x04, b'p', b'i', b'n', b'g']);
        peer.write_all(&[0x00, 0x00]).await.unwrap(); // response header
        peer.write_all(&[0x00, 0x02, b'o', b'k']).await.unwrap();
        let (dest, payload) = conn.recv().await.unwrap().unwrap();
        assert_eq!(dest, None);
        assert_eq!(&payload[..], b"ok");
    }

    #[tokio::test]
    async fn udp_packetaddr_header_is_magic_fqdn() {
        // PacketAddr mode: the header destination is the magic fqdn with
        // port 0 — the UDP target stays out of the header; per-packet
        // destinations carry it (spec §4.3).
        use tokio::io::AsyncReadExt;

        let cfg = vless(None, "tcp", false);
        let mut ctx = ctx_for(&cfg);
        ctx.target = TargetAddr::new(Host::new("1.2.3.4"), 8080);
        ctx.params.udp = Some(PacketMode::PacketAddr);
        let (stream, mut peer) = stream_pair();
        let mut conn = connect_udp(&ctx, stream, &cfg)
            .await
            .expect("packetaddr udp connect");

        let mut expected = vec![0x00];
        expected.extend_from_slice(&header::uuid_bytes(&cfg.uuid).unwrap());
        expected.push(0x00); // addon_len 0
        expected.push(0x02); // cmd UDP
        expected.extend_from_slice(&[0x00, 0x00]); // port 0
        expected.push(0x02); // domain atyp
        expected.push(u8::try_from(packetaddr::MAGIC.len()).expect("magic fqdn fits one byte"));
        expected.extend_from_slice(packetaddr::MAGIC.as_bytes());
        let mut got = [0u8; 1 + 16 + 1 + 1 + 2 + 1 + 1 + 25];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, &expected[..]);

        // The packetaddr tunnel is live: a per-packet destination travels
        // with the datagram (spec §4.3).
        let dest = "1.2.3.4:8080".parse().unwrap();
        conn.send(Some(dest), b"p").await.unwrap();
        let mut frame = vec![0u8; 2 + packetaddr::encode_dest(dest).len() + 1];
        peer.read_exact(&mut frame).await.unwrap();
        let mut want = packetaddr::encode_dest(dest);
        want.push(b'p');
        // Frame length = 1 (atyp) + 4 (addr) + 2 (port) + 1 (payload) = 8 —
        // no magic prefix in the frame (sing serializer; Task 5 report).
        let mut expected_frame = vec![0x00, 0x08];
        expected_frame.extend_from_slice(&want);
        assert_eq!(&frame, &expected_frame[..]);
    }

    #[tokio::test]
    async fn udp_packetaddr_rejects_domain_target() {
        // packetaddr fqdn targets are unsupported (spec §4.3): a domain UDP
        // target errors before any header write (sing's ErrFqdnUnsupported).
        let cfg = vless(None, "tcp", false);
        let (stream, _peer) = stream_pair();
        let err = connect_udp(&udp_ctx_for(&cfg, PacketMode::PacketAddr), stream, &cfg)
            .await
            .err()
            .expect("packetaddr + domain target must fail");
        assert!(matches!(&err, NativeError::Config(msg) if msg.contains("packetaddr")));
    }

    #[tokio::test]
    async fn vision_udp443_mux_not_rejected() {
        // flow=udp443 + UDP + mux path → Ok: the udp443 flow rewrites UDP
        // to the mux tunnel (XUDP) — the vision UDP rejection is lifted
        // for the mux path even WITHOUT an explicit params.mux (spec
        // §4.3, xray's `allowUDP443` + the UDP→mux rewrite).
        use tokio::io::AsyncReadExt;

        let cfg = vless(Some("xtls-rprx-vision-udp443"), "tcp", true);
        // XUdp is the mux tunnel's packet mode (connect_mux rejects
        // Raw/PacketAddr there).
        let ctx = udp_ctx_for(&cfg, PacketMode::XUdp);
        let (stream, mut peer) = tokio::io::duplex(4096);
        let stream: BoxStream = Box::new(stream);
        let conn = connect_udp(&ctx, stream, &cfg)
            .await
            .expect("udp443 + UDP must take the XUDP mux path");

        // The wire proves the rewrite: header with the TRUNCATED addon
        // (addon_len 18, `xtls-rprx-vision` bytes) and cmd 0x03 MUX — not
        // cmd 0x02 UDP.
        let uuid = header::uuid_bytes(&cfg.uuid).unwrap();
        let addons = header::encode_addons(Some(FLOW_XTLS_RPRX_VISION_UDP443)).unwrap();
        let mut expected = vec![0x00];
        expected.extend_from_slice(&uuid);
        expected.push(18); // addon_len
        expected.extend_from_slice(&addons);
        expected.push(header::CMD_MUX);
        let mut got = vec![0u8; 1 + 16 + 1 + 18 + 1];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, &expected[..]);

        // The vision camouflage frame follows (the vision mux composition,
        // spec §5.3).
        let mut head = [0u8; 21];
        peer.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..16], &uuid);
        assert_eq!(head[16], vision::CMD_CONTINUE);
        assert_eq!(&head[17..19], &[0x00, 0x00]); // clen 0 (empty content)
        let plen = usize::from(u16::from_be_bytes([head[19], head[20]]));
        let mut pad = vec![0u8; plen];
        peer.read_exact(&mut pad).await.unwrap();

        drop(conn);
    }

    #[tokio::test]
    async fn udp443_flow_tcp_connects_like_vision() {
        // The udp443 flow on the TCP command takes the vision path — the
        // addon is truncated to `xtls-rprx-vision` (spec §4.3); only the
        // UDP rejection differs (and only via the mux rewrite).
        let cfg = vless(Some("xtls-rprx-vision-udp443"), "tcp", true);
        let (stream, _peer) = tokio::io::duplex(4096);
        let stream: BoxStream = Box::new(stream);
        let result = connect(&ctx_for(&cfg), stream, &cfg).await;
        assert!(result.is_ok(), "udp443 + TCP must take the vision path");
    }

    #[tokio::test]
    async fn mux_plain_writes_cmd_mux_header() {
        // Header: version, uuid, addon_len 0, cmd 0x03 — and NOTHING after
        // (the mux command carries no destination bytes; the wire ends at
        // the command byte). The returned MuxClient is live over the
        // tunnel: an eager New frame + a Keep data roundtrip.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let cfg = vless(None, "tcp", false);
        let (stream, mut peer) = stream_pair();
        let client = connect_mux(&ctx_for(&cfg), stream, &cfg)
            .await
            .expect("plain mux connect");

        let mut expected = vec![0x00];
        expected.extend_from_slice(&header::uuid_bytes(&cfg.uuid).unwrap());
        expected.push(0x00); // addon_len 0
        expected.push(0x03); // cmd MUX
        let mut got = [0u8; 19];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, &expected[..]);

        // Server response header, then a session open through the mux.
        peer.write_all(&[0x00, 0x00]).await.unwrap();
        let mut session = client
            .open_session(MuxTarget::TcpDomain("example.com".into(), 80))
            .await
            .expect("open session");

        // The eager New frame arrives at the server (spec §8 deviation 1).
        let frame = crate::transport::mux::read_frame(&mut peer)
            .await
            .unwrap()
            .expect("eager new frame");
        assert_eq!(frame.session_id, 1);
        assert_eq!(frame.status, crate::transport::mux::STATUS_NEW);
        assert_eq!(
            frame.target,
            Some(MuxTarget::TcpDomain("example.com".into(), 80))
        );

        // App data roundtrips as a Keep frame with the payload.
        session.write_all(b"ping").await.unwrap();
        let frame = crate::transport::mux::read_frame(&mut peer)
            .await
            .unwrap()
            .expect("keep frame");
        assert_eq!(frame.session_id, 1);
        assert_eq!(frame.status, crate::transport::mux::STATUS_KEEP);
        assert_eq!(frame.payload.as_ref(), b"ping");

        // The server's Keep reply reaches the session stream.
        crate::transport::mux::write_frame(
            &mut peer,
            &crate::transport::mux::Frame {
                session_id: 1,
                status: crate::transport::mux::STATUS_KEEP,
                option: crate::transport::mux::OPT_DATA,
                target: None,
                global_id: None,
                payload: bytes::Bytes::from_static(b"ok"),
            },
        )
        .await
        .unwrap();
        let mut buf = [0u8; 2];
        session.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");
    }

    #[tokio::test]
    async fn mux_rejects_non_xudp_udp_mode() {
        // The mux tunnel only carries XUDP datagrams — a params.udp of
        // Raw/PacketAddr (a command=0x02 mode) is a misconfiguration,
        // rejected before any protocol I/O (connect_udp's mux branch never
        // reads the mode value, so reaching connect_mux with one would
        // otherwise silently lose it).
        for mode in [PacketMode::Raw, PacketMode::PacketAddr] {
            let cfg = vless(None, "tcp", false);
            let (stream, _peer) = stream_pair();
            let err = connect_mux(&udp_ctx_for(&cfg, mode), stream, &cfg)
                .await
                .err()
                .expect("non-XUdp udp mode on the mux tunnel must fail");
            assert!(matches!(&err, NativeError::Config(msg) if msg.contains("not XUdp")));
        }
        // XUdp (and None — the TCP-session mux rows) stay accepted.
        let cfg = vless(None, "tcp", false);
        let (stream, _peer) = stream_pair();
        connect_mux(&udp_ctx_for(&cfg, PacketMode::XUdp), stream, &cfg)
            .await
            .expect("xudp mode is the mux tunnel's udp mode");
    }

    #[tokio::test]
    async fn mux_vision_writes_addon_and_camouflage() {
        // Vision mux header: the flow addon (addon_len 18) + cmd 0x03, then
        // the camouflage frame ([uuid][CMD_CONTINUE][clen=0][long plen][zeros])
        // right after — the vision wire precedes the mux frames (spec §5.3).
        use tokio::io::AsyncReadExt;

        let cfg = vless(Some("xtls-rprx-vision"), "tcp", true);
        // The camouflage frame (up to ~1.4 KiB) is written before the test
        // starts reading, so the duplex buffer must hold header + frame.
        let (stream, mut peer) = tokio::io::duplex(4096);
        let stream: BoxStream = Box::new(stream);
        let client = connect_mux(&ctx_for(&cfg), stream, &cfg)
            .await
            .expect("vision mux connect");
        let uuid = header::uuid_bytes(&cfg.uuid).unwrap();
        let addons = header::encode_addons(Some(FLOW_XTLS_RPRX_VISION)).unwrap();

        let mut expected = vec![0x00];
        expected.extend_from_slice(&uuid);
        expected.push(18); // addon_len
        expected.extend_from_slice(&addons);
        expected.push(0x03); // cmd MUX
        let mut got = vec![0u8; 1 + 16 + 1 + 18 + 1];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, &expected[..]);

        let mut head = [0u8; 21];
        peer.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..16], &uuid);
        assert_eq!(head[16], vision::CMD_CONTINUE);
        assert_eq!(&head[17..19], &[0x00, 0x00]); // clen 0 (empty content)
        let plen = usize::from(u16::from_be_bytes([head[19], head[20]]));
        // Long padding for empty content: 900 + rand(0..500).
        assert!((900..=1399).contains(&plen), "plen {plen}");
        let mut pad = vec![0u8; plen];
        peer.read_exact(&mut pad).await.unwrap();
        assert!(pad.iter().all(|&b| b == 0));

        drop(client);
    }
}
