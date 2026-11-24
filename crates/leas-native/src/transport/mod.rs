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
pub mod sbox;
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

/// A configured `Host`/authority, or the fallback when it is absent **or
/// empty**.
///
/// The share-link grammars keep `?host=` as `Some("")`; the references treat
/// that as "not set" (fall back to the server/endpoint name), so building a
/// request from the raw option would produce `ws:///path` or an empty
/// authority.
pub(crate) fn host_or<'a>(host: Option<&'a str>, fallback: &'a str) -> &'a str {
    host.filter(|h| !h.is_empty()).unwrap_or(fallback)
}

/// Percent-encode a configured URI path/query into an ASCII request target.
///
/// `http::Uri` rejects a space (and other non-URI ASCII) in the path, while a
/// non-ASCII path is accepted and then sent as raw UTF-8 — and a `#` is parsed
/// as a fragment and silently truncates the request target. Go's
/// `url.EscapedPath` has none of those behaviours: everything outside the
/// RFC 3986 path/query set is `%XX`, and an existing valid `%HH` is kept.
///
/// Borrowed when the input is already a valid target, so the common ASCII
/// path allocates nothing.
pub(crate) fn request_target(path: &str) -> std::borrow::Cow<'_, str> {
    use std::fmt::Write as _;

    let bytes = path.as_bytes();
    if bytes
        .iter()
        .enumerate()
        .all(|(i, &b)| target_byte_ok(bytes, i, b))
    {
        return std::borrow::Cow::Borrowed(path);
    }
    let mut out = String::with_capacity(path.len() + 8);
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && pct_escape(bytes, i) {
            out.push_str(&path[i..i + 3]);
            i += 3;
            continue;
        }
        if target_byte_ok(bytes, i, b) {
            out.push(char::from(b));
        } else {
            write!(out, "%{b:02X}").expect("write! to String cannot fail");
        }
        i += 1;
    }
    std::borrow::Cow::Owned(out)
}

/// RFC 3986 path/query bytes Go's `url.EscapedPath` leaves alone, plus the
/// brackets modern browsers also leave alone. `%` is handled separately so a
/// valid escape is preserved and an invalid one is encoded as `%25`.
fn target_byte_ok(bytes: &[u8], i: usize, b: u8) -> bool {
    if b.is_ascii_alphanumeric() {
        return true;
    }
    if matches!(
        b,
        b'-' | b'.'
            | b'_'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b'/'
            | b':'
            | b';'
            | b'='
            | b'?'
            | b'@'
            | b'['
            | b']'
    ) {
        return true;
    }
    b == b'%' && pct_escape(bytes, i)
}

fn pct_escape(bytes: &[u8], i: usize) -> bool {
    matches!(bytes.get(i + 1), Some(b) if b.is_ascii_hexdigit())
        && matches!(bytes.get(i + 2), Some(b) if b.is_ascii_hexdigit())
}

#[cfg(test)]
mod request_target_tests {
    use super::request_target;
    use std::borrow::Cow;

    #[test]
    fn ascii_path_borrows() {
        assert!(matches!(
            request_target("/ws?ed=2048&x=1"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn space_and_unicode_are_escaped() {
        assert_eq!(request_target("/a b/ü"), "/a%20b/%C3%BC");
        assert_eq!(
            request_target("/?ed=Telegram🇨🇳+@WangCai2"),
            "/?ed=Telegram%F0%9F%87%A8%F0%9F%87%B3+@WangCai2"
        );
    }

    #[test]
    fn fragment_is_escaped_not_truncated() {
        assert_eq!(request_target("/x#f/more"), "/x%23f/more");
    }

    #[test]
    fn valid_pct_is_preserved_and_invalid_is_escaped() {
        assert_eq!(request_target("/%2Fok"), "/%2Fok");
        assert_eq!(request_target("/%zz"), "/%25zz");
    }

    #[test]
    fn every_target_parses_as_a_request_target() {
        for raw in [
            "/a b/ü",
            "/?ed=Telegram🇨🇳+@WangCai2",
            "/x#f/more",
            "/%zz",
            "/[]{}|\\^`\"<>",
        ] {
            let out = request_target(raw);
            assert!(
                http::uri::PathAndQuery::try_from(out.as_ref()).is_ok(),
                "{raw:?} -> {out:?}"
            );
        }
    }
}
