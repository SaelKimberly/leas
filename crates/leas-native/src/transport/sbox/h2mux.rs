//! `h2mux`: one HTTP/2 connection, one `CONNECT` stream per session
//! (`h2mux.go` / `client_conn.go` at the pinned reference).
//!
//! The carrier already carries the sbox handshake (request + optional
//! padding); this layer speaks HTTP/2 over it. Each session opens a `CONNECT
//! https://localhost` stream, sends the stream request (`flags + addr`), and
//! peels the stream response (`status[+message]`) on the first read.
//!
//! Reference: `thirdparty/sing-mux@caf09fe` `h2mux.go`, `client_conn.go`,
//! `protocol.go`. The error-message length is a compaction/uvarint prefix
//! (`SagerNet/sing@v0.9.5` `common/varbin/slices.go`: `ReadSlice` =
//! `ReadUvarint` + that many elements), not a fixed-width length.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::protocol::{StreamRequest, StreamResponse};
use crate::BoxStream;
use crate::addr::TargetAddr;
use crate::error::{NativeError, timeouts};

/// The largest h2 DATA frame this client queues per write (matches the gRPC
/// transport's chunk).
const WRITE_CHUNK: usize = 16 * 1024;

/// A live h2mux carrier.
pub struct H2Mux {
    send: h2::client::SendRequest<Bytes>,
}

impl H2Mux {
    /// Run the HTTP/2 handshake over `carrier` and drive the connection in the
    /// background for the carrier's lifetime.
    ///
    /// # Errors
    ///
    /// The h2 handshake failure or its timeout.
    pub async fn connect(carrier: BoxStream) -> Result<Self, NativeError> {
        let handshake = tokio::time::timeout(timeouts::TRANSPORT, h2::client::handshake(carrier))
            .await
            .map_err(|_| NativeError::Timeout {
                step: "sbox h2mux handshake",
                limit: timeouts::TRANSPORT,
            })?;
        let (send, connection) =
            handshake.map_err(|e| NativeError::Transport(format!("sbox h2mux: {e}")))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { send })
    }

    /// Open one session to `target`.
    ///
    /// # Errors
    ///
    /// A broken sender (dead carrier) or a malformed request URI.
    pub fn open(&self, target: &TargetAddr) -> Result<BoxStream, NativeError> {
        self.open_with(target, false)
    }

    /// Open one session, optionally a UDP association (`flags = UDP`).
    ///
    /// # Errors
    ///
    /// A broken sender (dead carrier) or a malformed request URI.
    pub fn open_with(&self, target: &TargetAddr, udp: bool) -> Result<BoxStream, NativeError> {
        // CONNECT is authority-only (RFC 7540 §8.3): a `:scheme`/`:path` pair
        // makes strict servers reject the stream. `Uri` with an authority and
        // no path/scheme produces exactly that pseudo-header set.
        let authority = http::uri::Authority::from_static("localhost");
        let uri = http::Uri::builder()
            .authority(authority.clone())
            .build()
            .map_err(|e| NativeError::Transport(format!("sbox h2mux uri: {e}")))?;
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(uri)
            .header(http::header::HOST, authority.as_str())
            .body(())
            .map_err(|e| NativeError::Transport(format!("sbox h2mux request: {e}")))?;
        let (response, send) = self
            .send
            .clone()
            .send_request(request, false)
            .map_err(|e| NativeError::Transport(format!("sbox h2mux open: {e}")))?;
        let mut prefix = Vec::with_capacity(8);
        StreamRequest {
            udp,
            packet_addr: false,
            target: target.clone(),
        }
        .encode(&mut prefix)
        .map_err(|e| NativeError::Config(format!("sbox stream request: {e}")))?;
        Ok(Box::new(H2Stream {
            send,
            response: Some(response),
            recv: None,
            prefix: Some(prefix),
            pending: Vec::new(),
            pending_take: 0,
            peel: BytesMut::new(),
            peeled: false,
        }))
    }
}

/// One h2mux session.
struct H2Stream {
    send: SendStream<Bytes>,
    /// Resolves to the `RecvStream` once the server answers 200.
    response: Option<h2::client::ResponseFuture>,
    recv: Option<RecvStream>,
    /// The stream request, prepended to the first payload write.
    prefix: Option<Vec<u8>>,
    /// A coalesced first frame (request + payload) waiting for h2 capacity.
    pending: Vec<u8>,
    /// Caller bytes inside `pending`, reported once the frame is sent.
    pending_take: usize,
    /// Bytes received from the body before the stream response was fully
    /// peeled.
    peel: BytesMut,
    peeled: bool,
}

impl H2Stream {
    /// Peel the stream response from the body; EOF before a full response is
    /// a protocol error.
    fn poll_peel(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(response) = self.response.as_mut() {
                match Pin::new(response).poll(cx) {
                    Poll::Ready(Ok(response)) => {
                        if response.status() != http::StatusCode::OK {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "sbox h2mux stream rejected: {}",
                                response.status()
                            ))));
                        }
                        self.recv = Some(response.into_body());
                        self.response = None;
                    }
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err(io::Error::other(error)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            if let Some((response, used)) = StreamResponse::decode(&self.peel) {
                self.peel.advance(used);
                self.peeled = true;
                return match response {
                    StreamResponse::Ok => Poll::Ready(Ok(())),
                    StreamResponse::Error(message) => Poll::Ready(Err(io::Error::other(message))),
                };
            }
            let Some(recv) = self.recv.as_mut() else {
                return Poll::Ready(Err(io::Error::other("sbox h2mux: no stream")));
            };
            match Pin::new(&mut *recv).poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    self.peel.extend_from_slice(&chunk);
                    let _ = recv.flow_control().release_capacity(len);
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "sbox h2mux: body ended before the stream response",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Send the coalesced first frame, looping until h2 grants its full capacity.
fn flush_first_frame(stream: &mut H2Stream, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
    loop {
        let len = stream.pending.len();
        stream.send.reserve_capacity(len);
        match Pin::new(&mut stream.send).poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) if capacity >= len => {
                let frame = std::mem::take(&mut stream.pending);
                if let Err(error) = stream.send.send_data(Bytes::from(frame), false) {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                let accepted = stream.pending_take;
                stream.pending_take = 0;
                return Poll::Ready(Ok(accepted));
            }
            Poll::Ready(Some(Ok(_))) => {}
            Poll::Ready(Some(Err(error))) => {
                return Poll::Ready(Err(io::Error::other(error)));
            }
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sbox h2mux send stream closed",
                )));
            }
            Poll::Pending => return Poll::Pending,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.peeled {
            match this.poll_peel(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if !this.peel.is_empty() {
            let take = this.peel.len().min(buf.remaining());
            buf.put_slice(&this.peel[..take]);
            this.peel.advance(take);
            return Poll::Ready(Ok(()));
        }
        let recv = this
            .recv
            .as_mut()
            .expect("recv present after the response peel");
        match Pin::new(&mut *recv).poll_data(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let len = chunk.len();
                let take = len.min(buf.remaining());
                buf.put_slice(&chunk[..take]);
                if take < len {
                    this.peel.extend_from_slice(&chunk[take..]);
                }
                let _ = recv.flow_control().release_capacity(len);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Faithful to the reference: the stream request and the first payload
        // leave in ONE DATA frame, coalesced before capacity is reserved.
        if !self.pending.is_empty() {
            return flush_first_frame(&mut self, cx);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(mut frame) = self.prefix.take() {
            let take = buf.len().min(WRITE_CHUNK);
            frame.extend_from_slice(&buf[..take]);
            self.pending = frame;
            self.pending_take = take;
            return flush_first_frame(&mut self, cx);
        }
        let requested = buf.len().min(WRITE_CHUNK);
        self.send.reserve_capacity(requested);
        let capacity = match Pin::new(&mut self.send).poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => capacity,
            Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io::Error::other(error))),
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sbox h2mux send stream closed",
                )));
            }
            Poll::Pending => return Poll::Pending,
        };
        let take = requested.min(capacity);
        if take == 0 {
            return Poll::Pending;
        }
        if let Err(error) = self
            .send
            .send_data(Bytes::copy_from_slice(&buf[..take]), false)
        {
            return Poll::Ready(Err(io::Error::other(error)));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.send.send_data(Bytes::new(), true) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(io::Error::other(error))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;
    use crate::addr::Host;

    fn target() -> TargetAddr {
        TargetAddr::new(Host::Domain("example.com".to_owned()), 443)
    }

    /// Send one DATA frame from the server side (h2 requires a capacity
    /// reservation first).
    async fn send_frame(send: &mut h2::SendStream<Bytes>, bytes: Bytes, end: bool) {
        if !bytes.is_empty() {
            send.reserve_capacity(bytes.len());
            std::future::poll_fn(|cx| match Pin::new(&mut *send).poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) if capacity >= bytes.len() => Poll::Ready(()),
                Poll::Ready(Some(Ok(capacity))) => {
                    panic!("server capacity {capacity} < {} bytes", bytes.len())
                }
                Poll::Ready(Some(Err(error))) => panic!("server capacity: {error}"),
                Poll::Ready(None) => panic!("server send stream closed"),
                Poll::Pending => Poll::Pending,
            })
            .await;
        }
        send.send_data(bytes, end).expect("server data");
    }

    /// One stream's handler: read the stream request, echo every payload
    /// chunk, end the body when the client half-closes.
    async fn handle(
        request: http::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        error: Option<&'static str>,
    ) {
        assert_eq!(request.method(), http::Method::CONNECT);
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .expect("response");
        let mut send = respond.send_response(response, false).expect("200");
        let mut body = request.into_body();
        let mut first = true;
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("body chunk");
            let mut out = Vec::new();
            let payload = if first {
                first = false;
                let (stream_request, used) = StreamRequest::decode(&chunk).expect("stream request");
                assert_eq!(stream_request.target, target());
                if let Some(message) = error {
                    out.extend_from_slice(&StreamResponse::Error(message.to_owned()).encode());
                } else {
                    out.push(super::super::protocol::STATUS_SUCCESS);
                }
                &chunk[used..]
            } else {
                &chunk[..]
            };
            out.extend_from_slice(payload);
            send_frame(&mut send, Bytes::from(out), false).await;
        }
        send_frame(&mut send, Bytes::new(), true).await;
    }

    /// A minimal h2mux server: pump the connection (which is what delivers
    /// stream frames) and hand each accepted stream to [`handle`].
    async fn serve(io: DuplexStream, error: Option<&'static str>) {
        let mut conn = h2::server::handshake(io).await.expect("h2 server");
        while let Some(accepted) = conn.accept().await {
            let (request, respond) = accepted.expect("one request");
            tokio::spawn(handle(request, respond, error));
        }
    }

    #[tokio::test]
    async fn connect_open_and_round_trip_one_stream() {
        let (client, server) = duplex(1 << 20);
        let server = tokio::spawn(serve(server, None));
        let mux = H2Mux::connect(Box::new(client) as crate::BoxStream)
            .await
            .expect("connect");
        let mut stream = mux.open(&target()).expect("open");
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.write_all(b"hello"),
        )
        .await
        .expect("write timeout")
        .expect("write");
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.shutdown())
            .await
            .expect("shutdown timeout")
            .expect("half-close");
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut got),
        )
        .await
        .expect("read timeout")
        .expect("read");
        assert_eq!(got, b"hello");
        server.abort();
    }

    #[tokio::test]
    async fn error_stream_response_surfaces_on_first_read() {
        let (client, server) = duplex(1 << 20);
        let server = tokio::spawn(serve(server, Some("no!")));
        let mux = H2Mux::connect(Box::new(client) as crate::BoxStream)
            .await
            .expect("connect");
        let mut stream = mux.open(&target()).expect("open");
        // The server may end the stream on the request frame; the payload
        // write racing that end is not what this test asserts.
        let _ = stream.write_all(b"x").await;
        let mut got = Vec::new();
        let error = stream.read_to_end(&mut got).await.expect_err("error");
        assert!(error.to_string().contains("no!"), "{error}");
        server.abort();
    }
}
