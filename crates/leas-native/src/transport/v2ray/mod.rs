//! SIP003 plugin framing: the `transport/v2ray` layer (spec §5 items 1–2).
//!
//! A plugin row's wire is `TCP → [TLS] → plugin framing → [mux] → SS codec`, and
//! the obfs modes here are **stream transformers**, not transports: they rewrite
//! the first bytes and then pass everything through. The v2ray-plugin modes
//! (websocket) arrive in `ws.rs`. `mode=quic` would replace the dial entirely,
//! so it has NO arm in this layer — and none is promised: it is refused at
//! `capability` before any dial, because its client wire could not be pinned
//! from evidence. `protocol::connect_quic` is NOT the plugin's arm (it covers
//! Hysteria2/1/TUIC). See the T22 evidence note in
//! `docs/aegis/plans/2026-09-30-ss-plugin.md` before adding one.
//!
//! This layer is **framing only**: it never applies TLS and never produces the
//! mux multiplexer (`transport::upgrade` returns a `BoxStream`, and a
//! multiplexer is not a byte stream). TLS is the chain's security phase —
//! outermost, matching both references (v2ray-core's websocket dialer wraps the
//! raw dialer in `securityEngine.Client` and upgrades over that; sing-box wraps
//! the dialer with `tls.NewDialer` and then upgrades).
//!
//! References: `thirdparty/sing-box/transport/simple-obfs/{http,tls}.go` (the
//! exact bytes), `thirdparty/sing-box/transport/sip003/` (the option
//! vocabulary), `common/mux/server.go` (why mux is the plugin's business).

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::NativeError;

pub mod http_obfs;
pub mod tls_obfs;
pub mod ws;

/// Apply the plugin framing for a row's resolved mode, over an established
/// (and, for a TLS-bearing mode, already-secure) stream.
///
/// The obfs modes and `mode=websocket` are all *framing over a stream*, so they
/// live here. `mode=quic` does not: it would replace `dial` + framing + TLS with
/// one QUIC session, so there is no stream for this layer to frame.
///
/// **There is deliberately no quic arm here, and none is promised.** The wire
/// could not be pinned from evidence — the reference server is v2ray-plugin
/// v1.3.2 embedding `V2Ray 4.38.3`, whose source is not in-tree, and three
/// mutually incompatible QUIC wires are — so `mode=quic` is REFUSED at
/// `capability::QUIC_WIRE_UNPINNED` before any dial, and this catch-all is
/// unreachable for it. `protocol::connect_quic` covers Hysteria2/1/TUIC only and
/// is NOT the plugin's arm; do not read this note as an invitation to add one
/// without first closing that evidence gap (the plan's T22 note).
pub async fn upgrade(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let spec = ctx.plugin_spec().ok_or_else(|| {
        NativeError::Config("v2ray plugin framing requested for a row with no plugin".into())
    })?;
    match spec.resolved_mode() {
        leas_proto::proto_spec::PluginMode::Http => Ok(http_obfs::wrap_for(ctx, stream, spec)),
        leas_proto::proto_spec::PluginMode::Tls => Ok(tls_obfs::wrap_for(ctx, stream, spec)),
        leas_proto::proto_spec::PluginMode::Websocket => ws::wrap_for(ctx, stream, spec).await,
        other => Err(NativeError::Config(format!(
            "shadowsocks plugin mode `{}` is not framed by the transport",
            other.as_str()
        ))),
    }
}

/// The `Host` header value an obfs mode sends: the plugin's host, with the
/// `:port` suffix the row states (omitted when 80).
///
/// `simple-obfs`'s `NewHTTPObfs(conn, host, port)` is the shape being mirrored
/// (`transport/simple-obfs/http.go:90-95`), and the synthetic TLS hello puts the
/// same name in its `server_name` extension (`tls.go:178-183`) — the port
/// reaches the header only, never the dial.
pub(crate) fn obfs_host_header(host: Option<&str>, port: Option<u16>, fallback: &str) -> String {
    let host = host.unwrap_or(fallback);
    match port {
        Some(port) if port != 80 => format!("{host}:{port}"),
        _ => host.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::obfs_host_header;

    /// The port reaches the `Host` header only when it is not 80 — the
    /// reference's `NewHTTPObfs(conn, host, port)` split
    /// (`transport/simple-obfs/http.go:90-95`).
    #[test]
    fn the_obfs_host_header_elides_port_80_only() {
        assert_eq!(
            obfs_host_header(Some("cdn.example"), None, "srv"),
            "cdn.example"
        );
        assert_eq!(
            obfs_host_header(Some("cdn.example"), Some(80), "srv"),
            "cdn.example"
        );
        assert_eq!(
            obfs_host_header(Some("cdn.example"), Some(16569), "srv"),
            "cdn.example:16569"
        );
        // An obfs row that states no host uses the server's.
        assert_eq!(
            obfs_host_header(None, None, "server.example"),
            "server.example"
        );
        assert_eq!(
            obfs_host_header(None, Some(8080), "server.example"),
            "server.example:8080"
        );
    }
}
