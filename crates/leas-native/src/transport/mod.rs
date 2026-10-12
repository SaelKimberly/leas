//! Transport phase: get a byte stream to the proxy server (or reuse an
//! existing tunnel for the later hops of a chain).
//!
//! `connect` dials the server (`base: None`) or reuses an existing tunnel
//! (`base: Some`). `upgrade` runs the transport framing (ws/grpc/httpupgrade)
//! over an ALREADY-established stream — the engine TLS/REALITY session (Xray
//! composition order: dial → security → transport upgrade → protocol; TLS is
//! OUTERMOST, transport framing runs inside it).

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::NativeError;

pub mod grpc;
pub mod http;
pub mod httpupgrade;
pub mod kcp;
pub mod mux;
pub mod quic;
pub mod tcp;
pub mod v2ray;
pub mod v2rayhttp;
pub mod ws;
pub mod xhttp;

/// Run the transport step: dial the server (`base: None`) or reuse the
/// previous tunnel (`base: Some`); `kcp` does a fresh UDP dial.
pub async fn connect(ctx: &LinkContext, base: Option<BoxStream>) -> Result<BoxStream, NativeError> {
    match ctx.transport_type() {
        // xhttp + a single `h3` ALPN → HTTP/3 over QUIC: a different dial
        // (UDP + quinn) that replaces the dial + security + upgrade chain
        // (spec §4.1/§5.2). It is a fresh QUIC dial — it never reuses a
        // base tunnel (xhttp+h3 as a later chain hop is a Config error).
        Some("xhttp") if is_self_contained(ctx) => {
            if base.is_some() {
                return Err(NativeError::Config(
                    "xhttp over HTTP/3 cannot reuse a base tunnel: the QUIC dial is a fresh connection".into(),
                ));
            }
            xhttp::connect_quic(ctx).await
        }
        None | Some("tcp" | "ws" | "grpc" | "httpupgrade" | "xhttp" | "http") => {
            tcp::connect(ctx, base).await
        }
        Some("kcp" | "mkcp") => kcp::connect(ctx, base).await,
        Some(t) => Err(NativeError::NotImplemented {
            feature: format!("transport {t}"),
        }),
    }
}

/// True when the transport's [`connect`] already produced the finished
/// tunnel: xhttp + a single `h3` ALPN (the QUIC dial replaces dial +
/// security + upgrade — spec §5.2). The chain then skips the security and
/// upgrade phases and runs the protocol phase directly on the dialed
/// stream.
#[must_use]
pub(crate) fn is_self_contained(ctx: &LinkContext) -> bool {
    ctx.transport_type() == Some("xhttp") && xhttp::http_version(ctx.security()) == "3"
}

/// Run the transport-upgrade step over an established (secured) stream.
///
/// TCP/kcp = passthrough (mKCP is a dial, never framed);
/// ws/grpc/httpupgrade/xhttp/v2rayhttp = framing handshake;
/// a SIP003 plugin row = that plugin's framing.
///
/// The plugin arm is dispatched FIRST, on `LinkContext::plugin_spec()`, because an
/// `SsConfig` carries no transport field at all (`context::transport_type()` is
/// `None` for it) — there is no `TransportConfig` arm that could select it. The
/// arm is framing only: TLS is the security phase above, and the mux
/// multiplexer is the protocol phase's return type (§5.2).
pub async fn upgrade(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    if ctx.plugin_spec().is_some() {
        return v2ray::upgrade(ctx, stream).await;
    }
    match ctx.transport_type() {
        Some("ws") => ws::connect(ctx, stream).await,
        Some("grpc") => grpc::connect(ctx, stream).await,
        Some("httpupgrade") => httpupgrade::connect(ctx, stream).await,
        Some("xhttp") => xhttp::connect(ctx, stream).await,
        Some("http") => v2rayhttp::connect(ctx, stream).await,
        None | Some("tcp" | "kcp" | "mkcp") => Ok(stream),
        Some(t) => Err(NativeError::NotImplemented {
            feature: format!("transport {t}"),
        }),
    }
}
