//! `HTTPUpgrade` transport ("fake WebSocket"): an HTTP/1.1 `101` upgrade that
//! becomes a raw duplex byte stream.
//!
//! The client sends `GET` with `Connection: Upgrade` + `Upgrade: websocket`;
//! ALPN is forced to `http/1.1` (xray-core forces it; sing-box sets it when
//! `NextProtos` is empty).
//!
//! Wire reference: `thirdparty/Xray-core/transport/internet/httpupgrade/dialer.go`,
//! `thirdparty/sing-box/transport/v2rayhttpupgrade/client.go`.

use http::StatusCode;
use http::header::{CONNECTION, HOST, UPGRADE};
use hyper_util::rt::TokioIo;

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};
use crate::transport::http::{ReqBody, h1_client};

/// Normalize a transport path to start with `/`.
fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Run the `HTTPUpgrade` handshake over the established (secured) stream.
pub async fn connect(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let cfg = ctx
        .transport_httpupgrade()
        .ok_or_else(|| NativeError::Config("httpupgrade transport config missing".into()))?;
    let host = cfg
        .host
        .as_deref()
        .map_or_else(|| ctx.params.server.host.clone(), str::to_string);
    let path = cfg
        .path
        .as_deref()
        .map_or_else(|| "/".to_string(), normalize_path);

    let mut sender = h1_client(stream).await?;

    let mut builder = http::Request::builder()
        .method("GET")
        .uri(&path)
        .header(HOST, &host)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket");
    if let Some(headers) = &cfg.headers {
        for (k, v) in headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
    }
    let req = builder
        .body(ReqBody::Empty)
        .map_err(|e| NativeError::Config(format!("httpupgrade request build: {e}")))?;

    let limit = timeouts::TRANSPORT;
    let resp = tokio::time::timeout(limit, sender.send_request(req))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "httpupgrade request",
            limit,
        })?
        .map_err(|e| NativeError::Transport(format!("httpupgrade request: {e}")))?;

    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(NativeError::TransportRejected {
            detail: format!("httpupgrade: expected 101, got {}", resp.status()),
            status: resp.status().as_u16(),
        });
    }
    // sing-box contract: both echo headers required, case-insensitive.
    let h = resp.headers();
    let upgrade_ok = h
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let connection_ok = h
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("upgrade"));
    if !upgrade_ok || !connection_ok {
        return Err(NativeError::Transport(
            "httpupgrade: bad upgrade response headers".into(),
        ));
    }

    let upgraded = tokio::time::timeout(limit, hyper::upgrade::on(resp))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "httpupgrade upgrade",
            limit,
        })?
        .map_err(|e| NativeError::Transport(format!("httpupgrade upgrade: {e}")))?;
    // hyper's `Upgraded` implements hyper's rt traits only; TokioIo bridges
    // them back to tokio AsyncRead/AsyncWrite (the same adapter `h1_client`
    // uses to hand the stream to hyper).
    Ok(Box::new(TokioIo::new(upgraded)))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use leas_proto::proto_spec::ProtocolConfig;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::addr::{Host, TargetAddr};
    use crate::context::{LinkContext, NativeConnectParams};
    use crate::error::NativeError;
    use crate::transport::httpupgrade::connect;

    fn vless_httpupgrade() -> ProtocolConfig {
        // The proto's `TransportConfig` serde tag is snake_case (`http_upgrade`);
        // `transport_type()` reports the wire name `httpupgrade`.
        serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "http_upgrade", "path": "/hu", "host": "example.com" }
        }))
        .expect("config parses")
    }

    fn ctx_at(addr: SocketAddr) -> LinkContext {
        LinkContext::new(
            NativeConnectParams::new(
                vless_httpupgrade(),
                EndpointEssentials::new(addr.ip().to_string(), addr.port()),
                TargetAddr::new(Host::Domain("dest.test".into()), 80),
            ),
            TargetAddr::new(Host::Domain("dest.test".into()), 80),
        )
    }

    /// Raw TCP server: read the request head, assert the upgrade headers,
    /// reply 101, then echo bytes (the vless protocol bytes ping-pong).
    #[tokio::test]
    async fn upgrade_then_echo() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                sock.read_exact(&mut buf).await.unwrap();
                head.push(buf[0]);
            }
            let head = String::from_utf8(head).unwrap();
            assert!(head.starts_with("GET /hu HTTP/1.1"), "{head}");
            assert!(head.to_lowercase().contains("connection: upgrade"));
            assert!(head.to_lowercase().contains("upgrade: websocket"));
            assert!(head.contains("host: example.com"), "{head}");
            sock.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n").await.unwrap();
            let mut echo = [0u8; 5];
            sock.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"hello");
            sock.write_all(b"world").await.unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ctx = ctx_at(addr);
        let mut t = connect(&ctx, Box::new(stream)).await.unwrap();
        t.write_all(b"hello").await.unwrap();
        let mut out = [0u8; 5];
        t.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"world");
        server.await.unwrap();
    }

    /// A non-101 response must surface as a Transport error, not hang.
    #[tokio::test]
    async fn non_101_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                sock.read_exact(&mut buf).await.unwrap();
                head.push(buf[0]);
            }
            sock.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ctx = ctx_at(addr);
        // `BoxStream` is not `Debug`, so `unwrap_err` cannot name the error
        // type; bind the error with `let-else` instead.
        let Err(err) = connect(&ctx, Box::new(stream)).await else {
            panic!("expected a transport error, got a connection");
        };
        assert!(
            matches!(err, NativeError::TransportRejected { status: 400, .. }),
            "the peer's status is the typed evidence: {err}"
        );
    }
}
