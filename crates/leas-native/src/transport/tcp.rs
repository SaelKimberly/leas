use crate::BoxStream;
use crate::error::{NativeError, timeouts};
/// Dial the server's TCP socket directly (`base` is None) or pass through an
/// existing tunnel (`base` is Some — a TCP "transport" over a tunnel is raw
/// bytes, so this is the identity function).
pub async fn connect(
    ctx: &crate::context::LinkContext,
    base: Option<BoxStream>,
) -> Result<BoxStream, NativeError> {
    if let Some(stream) = base {
        Ok(stream)
    } else {
        let socket = ctx.server_socket().await?;
        // Options are applied to the UNCONNECTED socket: `TCP_MAXSEG` changes
        // the MSS announced in the SYN only when it is set before connection
        // establishment, and the whole point is that the server never sends a
        // segment larger than the path can carry. Applying it after connect
        // would cap only our own segments — cost without benefit.
        let sock = if socket.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        }
        .map_err(|e| NativeError::Dial(format!("{socket}: {e}")))?;
        // The one socket option every dial has always set, now through the
        // `sockopt` seam so a future config surface has a single owner.
        let opts = crate::sockopt::SockOpts {
            nodelay: Some(true),
            tcp_maxseg: Some(crate::path_mss::current()),
            tcp_quickack: Some(true),
            ..crate::sockopt::SockOpts::default()
        };
        opts.apply_to_stream(&sock);
        let timeout = timeouts::TRANSPORT;
        let stream = tokio::time::timeout(timeout, sock.connect(socket))
            .await
            .map_err(|_| NativeError::Timeout {
                step: "tcp dial",
                limit: timeout,
            })?
            .map_err(|e| NativeError::Dial(format!("{socket}: {e}")))?;
        Ok(Box::new(stream))
    }
}
#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use leas_proto::proto_spec::ProtocolConfig;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::addr::{Host, TargetAddr};
    use crate::context::{LinkContext, NativeConnectParams};
    use crate::transport::tcp::connect;

    fn vless_empty() -> ProtocolConfig {
        serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "tcp" }
        }))
        .expect("vless config parses")
    }

    fn params_at(addr: SocketAddr) -> NativeConnectParams {
        NativeConnectParams::new(
            vless_empty(),
            EndpointEssentials::new(addr.ip().to_string(), addr.port()),
            TargetAddr::new(Host::Domain("example.com".into()), 80),
        )
    }

    #[tokio::test]
    async fn dial_connects_to_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            buf
        });
        let ctx = LinkContext::new(
            params_at(addr),
            TargetAddr::new(Host::Domain("example.com".into()), 80),
        );
        let mut stream = connect(&ctx, None).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let echoed = server.await.unwrap();
        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn base_stream_passes_through() {
        let (a, mut b) = tokio::io::duplex(64);
        let ctx = LinkContext::new(
            params_at(SocketAddr::from(([127, 0, 0, 1], 1))),
            TargetAddr::new(Host::Domain("example.com".into()), 80),
        );
        let mut out = connect(&ctx, Some(Box::new(a))).await.unwrap();
        out.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 1];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"x");
    }
}
