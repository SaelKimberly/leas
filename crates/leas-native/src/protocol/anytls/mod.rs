//! `AnyTLS` client: a TLS session that multiplexes per-destination streams.
//!
//! Reference implementations: `thirdparty/anytls-go` (the protocol's own
//! reference client) and `thirdparty/mihomo/transport/anytls`; the wire is
//! specified in `thirdparty/anytls-go/docs/protocol.md`.
//!
//! Two entry shapes:
//!
//! - [`connect`] — one stream on a fresh session over the caller's stream. Used
//!   for a chained hop (an upstream tunnel carries it) and for UDP.
//! - [`connect_pooled`] — the first chain link: reuses one of the link's idle
//!   sessions (the protocol mandates reuse) or dials a new one.
//!
//! The session/stream machinery lives in [`session`], the pool in [`client`],
//! the datagram carrier in [`udp`].

pub(crate) mod client;
mod frame;
mod padding;
mod session;
pub mod udp;

use std::sync::Arc;

use leas_proto::proto_spec::AnyTlsConfig;

use crate::BoxStream;
use crate::addr::{Host, TargetAddr};
use crate::context::LinkContext;
use crate::error::NativeError;
use crate::protocol::anytls::padding::PaddingScheme;
use crate::protocol::anytls::session::{AnyTlsStream, Padding, Session};
use crate::protocol::anytls::udp::{UOT_DESTINATION, UdpConn};

pub(crate) use client::connect_pooled;

/// Open one TCP stream to `ctx.target` on a fresh session over `stream`.
pub async fn connect(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &AnyTlsConfig,
) -> Result<BoxStream, NativeError> {
    let session = start(ctx, stream, cfg).await?;
    open(session, &ctx.target).await
}

/// Open the uot v2 datagram tunnel to `ctx.target` on a fresh session over
/// `stream`.
pub async fn connect_udp(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &AnyTlsConfig,
) -> Result<UdpConn, NativeError> {
    let session = start(ctx, stream, cfg).await?;
    // The uot service is reached by opening a stream to its magic FQDN; the
    // uot request on that stream carries the real destination.
    let service = TargetAddr::new(Host::Domain(UOT_DESTINATION.to_string()), 0);
    let inner = session.open_stream(&service).await?;
    let session_stream: BoxStream = Box::new(SessionStream {
        stream: inner,
        session,
    });
    let conn = UdpConn::new(session_stream, &ctx.target).await?;
    Ok(conn)
}

/// Create the session (its padding state is per session here — a pooled link
/// shares one, see [`client`]).
async fn start(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &AnyTlsConfig,
) -> Result<Arc<Session>, NativeError> {
    let password = cfg
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| NativeError::Config("anytls: missing password".into()))?;
    let padding: Arc<Padding> = Arc::new(std::sync::RwLock::new(Arc::new(
        PaddingScheme::default_scheme().clone(),
    )));
    let session = Session::start(stream, password, padding, ctx.ack.clone(), 0).await?;
    Ok(Arc::new(session))
}

/// Open a stream and hand back a stream that owns its session.
async fn open(session: Arc<Session>, target: &TargetAddr) -> Result<BoxStream, NativeError> {
    let stream = session.open_stream(target).await?;
    Ok(Box::new(SessionStream { stream, session }))
}

/// A stream plus the session carrying it: dropping the stream ends the
/// session, and the session lives exactly as long as the stream needs it.
struct SessionStream {
    stream: AnyTlsStream,
    /// Held, never read: its `Drop` shuts the session's tasks down.
    #[allow(dead_code)]
    session: Arc<Session>,
}

impl tokio::io::AsyncRead for SessionStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for SessionStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use sha2::{Digest as _, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::frame::{
        self, CMD_PSH, CMD_SERVER_SETTINGS, CMD_SYN, CMD_WASTE, HEADER_LEN, Header,
    };
    use super::*;
    use crate::addr::Host;
    use crate::context::NativeConnectParams;

    fn anytls_cfg() -> AnyTlsConfig {
        AnyTlsConfig {
            password: Some("secret".into()),
            security: leas_proto::proto_spec::SecurityConfig::default(),
            remarks: None,
        }
    }

    fn context(target: TargetAddr) -> LinkContext {
        let params = NativeConnectParams::new(
            leas_proto::proto_spec::ProtocolConfig::AnyTls(anytls_cfg()),
            EndpointEssentials::new("127.0.0.1", 8443),
            target,
        );
        LinkContext::with_auth_ack(
            params,
            TargetAddr::new(Host::Ip("127.0.0.1".parse().unwrap()), 80),
        )
    }

    /// Read one frame, skipping `cmdWaste` padding frames.
    async fn read_frame<S: tokio::io::AsyncRead + Unpin>(
        stream: &mut S,
    ) -> std::io::Result<Header> {
        loop {
            let mut raw = [0u8; HEADER_LEN];
            stream.read_exact(&mut raw).await?;
            let header = Header::parse(raw);
            let mut data = vec![0u8; usize::from(header.len)];
            stream.read_exact(&mut data).await?;
            if header.command == CMD_WASTE {
                continue;
            }
            return Ok(header);
        }
    }

    async fn read_payload<S: tokio::io::AsyncRead + Unpin>(
        stream: &mut S,
    ) -> std::io::Result<(Header, Vec<u8>)> {
        loop {
            let mut raw = [0u8; HEADER_LEN];
            stream.read_exact(&mut raw).await?;
            let header = Header::parse(raw);
            let mut data = vec![0u8; usize::from(header.len)];
            stream.read_exact(&mut data).await?;
            if header.command == CMD_WASTE {
                continue;
            }
            return Ok((header, data));
        }
    }

    /// A hand-written `AnyTLS` server: auth, settings, SYN+target, one echo.
    async fn fake_server(mut stream: tokio::io::DuplexStream) -> Vec<u8> {
        // auth: 32-byte hash + u16 padding0 length + zeros.
        let mut auth = [0u8; 34];
        stream.read_exact(&mut auth).await.expect("auth header");
        assert_eq!(
            &auth[..32],
            Sha256::digest(b"secret").as_slice(),
            "wrong password hash"
        );
        let padding0 = usize::from(u16::from_be_bytes([auth[32], auth[33]]));
        assert_eq!(padding0, 30, "default scheme's padding0");
        let mut zeros = vec![0u8; padding0];
        stream.read_exact(&mut zeros).await.expect("padding0");
        assert!(zeros.iter().all(|&b| b == 0));

        let (settings, body) = read_payload(&mut stream).await.expect("settings");
        assert_eq!(settings.command, frame::CMD_SETTINGS);
        let body = String::from_utf8(body).expect("settings utf8");
        assert!(body.contains("v=2"), "{body}");
        assert!(body.contains("client=leas/"), "{body}");
        assert!(
            body.contains("padding-md5=75cff2ad89aadf5e257059ee571ebe11"),
            "{body}"
        );
        // v2 server: report settings back.
        let mut reply = frame::frame(CMD_SERVER_SETTINGS, 0, b"v=2");
        stream.write_all(&reply).await.expect("server settings");

        let syn = read_frame(&mut stream).await.expect("syn");
        assert_eq!(syn.command, CMD_SYN);
        assert_eq!(syn.len, 0);
        let (psh, addr) = read_payload(&mut stream).await.expect("target");
        assert_eq!(psh.command, CMD_PSH);
        assert_eq!(psh.stream_id, syn.stream_id);
        // SOCKS5 ATYP 1 + 127.0.0.1 + port 80.
        assert_eq!(addr, vec![0x01, 127, 0, 0, 1, 0, 80]);

        let (data, payload) = read_payload(&mut stream).await.expect("payload");
        assert_eq!(data.command, CMD_PSH);
        assert_eq!(payload, b"hello");
        reply = frame::frame(CMD_PSH, data.stream_id, b"hello back");
        stream.write_all(&reply).await.expect("echo");
        payload
    }

    #[tokio::test]
    async fn handshake_opens_a_stream_and_relays_bytes() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(fake_server(server));
        let ctx = context(TargetAddr::new(Host::Ip("127.0.0.1".parse().unwrap()), 80));
        let cfg = anytls_cfg();
        let mut tunnel = connect(&ctx, Box::new(client), &cfg)
            .await
            .expect("connect");
        tunnel.write_all(b"hello").await.expect("write");
        tunnel.flush().await.expect("flush");
        let mut echo = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut echo))
            .await
            .expect("read timeout")
            .expect("read");
        assert_eq!(&echo, b"hello back");
        assert_eq!(server.await.expect("server task"), b"hello");
    }

    #[tokio::test]
    async fn a_missing_password_is_a_config_error() {
        let (client, _server) = tokio::io::duplex(1024);
        let cfg = AnyTlsConfig {
            password: None,
            security: leas_proto::proto_spec::SecurityConfig::default(),
            remarks: None,
        };
        let ctx = context(TargetAddr::new(Host::Ip("127.0.0.1".parse().unwrap()), 80));
        let Err(error) = connect(&ctx, Box::new(client), &cfg).await else {
            panic!("a missing password must be refused before the session starts");
        };
        assert!(matches!(error, NativeError::Config(_)), "{error:?}");
    }
}
