//! `mode=websocket` framing: a WebSocket upgrade whose parameters come from the
//! plugin spec rather than a `TransportConfig`.
//!
//! The reference is `thirdparty/sing-box/transport/v2raywebsocket/client.go:36-74` (and
//! v2ray-core's `transport/internet/websocket/dialer.go`, the same exchange):
//!
//! * the path is normalized to a leading `/` — the same normalization the ws
//!   path canonicalization already pins;
//! * the `Host` header is the plugin's `host` option, **not** the endpoint: it
//!   is the CDN fronting the v2ray-plugin server, and for `wss` it is the
//!   name the certificate is issued for, which is also why it is the SNI (§5.1);
//! * `User-Agent` defaults to `Go-http-client/1.1`;
//! * **early data is off.** The plugin path constructs `Headers` + `Path` only
//!   (`sip003/v2ray.go:71-76`), so `max_early_data` is never populated and no
//!   `ed` value is carried in `Sec-WebSocket-Protocol`. Our own ws transport
//!   supports early data, so this must be off *by construction* here: the
//!   request is built field by field rather than through
//!   [`crate::transport::ws::ws_request`], which would otherwise have nothing to
//!   turn on but also nothing to turn off.
//!
//! The exchange itself is shared: [`crate::transport::ws::upgrade_with`] performs the
//! handshake, the 101 requirement and the binary-message wrapping, so a plugin row
//! and a `TransportConfig` row are provably the same wire.

use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{CONNECTION, HOST, UPGRADE, USER_AGENT};
use tokio_tungstenite::tungstenite::http::{HeaderValue, Request};

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::NativeError;
use crate::transport::ws as ws_transport;

/// The `User-Agent` the reference sends when the row states none
/// (`v2raywebsocket/client.go:63-65`).
const DEFAULT_USER_AGENT: &str = "Go-http-client/1.1";

/// The upgrade request for a plugin row, built from the spec. Pure and
/// unit-testable, like [`crate::transport::ws::ws_request`] for the other path.
pub fn plugin_ws_request(
    spec: &leas_proto::proto_spec::PluginSpec,
    endpoint_host: &str,
) -> Result<Request<()>, NativeError> {
    let path = normalize_path(spec.path.as_deref().unwrap_or("/"));
    let host = spec.host.as_deref().unwrap_or(endpoint_host);
    // A relative request target is not a valid HTTP request line, and the
    // plugin path is a path — never a full URL (the reference builds
    // `ws://<host><path>` before handing it to the ws dialer, which the
    // `into_client_request` conversion below reproduces).
    let mut req = format!("ws://{host}{path}")
        .into_client_request()
        .map_err(|e| NativeError::Config(format!("v2ray-plugin ws request: {e}")))?;
    req.headers_mut().insert(
        HOST,
        HeaderValue::from_str(host)
            .map_err(|e| NativeError::Config(format!("v2ray-plugin ws host: {e}")))?,
    );
    req.headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    req.headers_mut()
        .insert(UPGRADE, HeaderValue::from_static("websocket"));
    req.headers_mut()
        .insert(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
    Ok(req)
}

/// Apply the plugin's WebSocket upgrade over an established (and, for a TLS row,
/// already-secure) stream.
pub(crate) async fn wrap_for(
    ctx: &LinkContext,
    stream: BoxStream,
    spec: &leas_proto::proto_spec::PluginSpec,
) -> Result<BoxStream, NativeError> {
    let req = plugin_ws_request(spec, ctx.params.server.host.as_str())?;
    let ws = ws_transport::upgrade_with(req, stream, "v2ray-plugin ws upgrade").await?;
    Ok(Box::new(ws_transport::WsStream::new(ws)))
}

/// A leading `/`, and nothing else: the plugin path is a URL path.
fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

#[cfg(test)]
mod tests {
    use leas_proto::proto_spec::{PluginMode, PluginSpec};

    use super::*;

    fn spec(opts: &str) -> PluginSpec {
        PluginSpec::from_parts(Some("v2ray-plugin"), opts)
    }

    /// The plugin path is a URL path; a relative one gains the leading slash.
    #[test]
    fn the_path_always_carries_a_leading_slash() {
        assert_eq!(normalize_path("/kpnzyxsj"), "/kpnzyxsj");
        assert_eq!(normalize_path("kpnzyxsj"), "/kpnzyxsj");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(
            normalize_path("/a?b=c"),
            "/a?b=c",
            "a query survives verbatim"
        );
    }

    /// The request line and headers are the plugin's, not the endpoint's:
    /// `Host` from the `host` option, the reference's `User-Agent`, the upgrade
    /// pair, and **no** `Sec-WebSocket-Protocol` (early data is never on for a
    /// plugin row).
    #[test]
    fn the_request_carries_the_plugin_headers_and_no_early_data() {
        let req = plugin_ws_request(&spec("host=cdn.example;path=/kpnzyxsj"), "server.example")
            .expect("request");
        assert_eq!(req.uri().path(), "/kpnzyxsj");
        assert_eq!(req.headers().get(HOST).expect("host"), "cdn.example");
        assert_eq!(
            req.headers().get(USER_AGENT).expect("ua"),
            DEFAULT_USER_AGENT
        );
        assert_eq!(
            req.headers().get(CONNECTION).expect("connection"),
            "Upgrade"
        );
        assert_eq!(req.headers().get(UPGRADE).expect("upgrade"), "websocket");
        assert!(
            req.headers().get("sec-websocket-protocol").is_none(),
            "a plugin row never sends early data"
        );
    }

    /// A row with no `host` falls back to the endpoint, and a relative path is
    /// normalized — the two cases the corpus exercises.
    #[test]
    fn the_defaults_match_the_reference() {
        let req = plugin_ws_request(&spec(""), "server.example").expect("request");
        assert_eq!(req.uri().path(), "/", "the reference default path is /");
        assert_eq!(req.headers().get(HOST).expect("host"), "server.example");
        let relative =
            plugin_ws_request(&spec("path=kpnzyxsj"), "server.example").expect("request");
        assert_eq!(relative.uri().path(), "/kpnzyxsj");
    }

    /// The mode is the one this module frames: a row the transport must not
    /// send down the ws path.
    #[test]
    fn the_ws_arm_owns_only_the_websocket_mode() {
        assert_eq!(spec("mode=websocket").mode, PluginMode::Websocket);
        assert_eq!(spec("").mode, PluginMode::Websocket, "the default mode");
        assert_eq!(
            spec("mode=quic").mode,
            PluginMode::Quic,
            "a quic row is STORED as quic (and refused at capability, not here) \
             — this layer never frames it"
        );
    }
}
