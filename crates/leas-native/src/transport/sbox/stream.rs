//! The per-stream request/response wrapper for sbox sessions that speak a raw
//! byte stream (`smux`, `yamux`).
//!
//! `h2mux` carries the same framing inside its own stream adapter; those two
//! protocols need it here: the stream request (`flags + addr`) is prepended to
//! the first payload write, and the stream response (`status[+message]`) is
//! peeled from the first read.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::protocol::StreamResponse;

/// Wraps a session stream: response peel on the read side.
///
/// The write side is composed by the caller with
/// [`crate::protocol::first_flight::HeaderFirst`], which prepends the stream
/// request to the first payload write.
pub struct ResponsePeel<S> {
    inner: S,
    peel: BytesMut,
    peeled: bool,
}

impl<S> ResponsePeel<S> {
    /// Wrap `inner`.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            peel: BytesMut::new(),
            peeled: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ResponsePeel<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.peeled {
            loop {
                if let Some((response, used)) = StreamResponse::decode(&this.peel) {
                    this.peel.advance(used);
                    this.peeled = true;
                    match response {
                        StreamResponse::Ok => break,
                        StreamResponse::Error(message) => {
                            return Poll::Ready(Err(io::Error::other(message)));
                        }
                    }
                }
                let mut scratch = [0u8; 512];
                let mut rb = ReadBuf::new(&mut scratch);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let filled = rb.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "sbox stream ended before its response",
                            )));
                        }
                        this.peel.extend_from_slice(rb.filled());
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        if !this.peel.is_empty() {
            let take = this.peel.len().min(buf.remaining());
            buf.put_slice(&this.peel[..take]);
            this.peel.advance(take);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ResponsePeel<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn peels_the_response_then_passes_data_through() {
        let (client, mut peer) = duplex(1024);
        let mut stream = ResponsePeel::new(client);
        let mut frame = StreamResponse::Error("denied".to_owned()).encode();
        frame.extend_from_slice(b"tail");
        peer.write_all(&frame).await.expect("write");
        let mut got = Vec::new();
        let error = stream.read_to_end(&mut got).await.expect_err("error");
        assert!(error.to_string().contains("denied"), "{error}");
    }

    #[tokio::test]
    async fn ok_response_leaves_the_payload() {
        let (client, mut peer) = duplex(1024);
        let mut stream = ResponsePeel::new(client);
        let mut frame = vec![super::super::protocol::STATUS_SUCCESS];
        frame.extend_from_slice(b"payload");
        peer.write_all(&frame).await.expect("write");
        let mut got = [0u8; 7];
        stream.read_exact(&mut got).await.expect("read");
        assert_eq!(&got, b"payload");
    }
}
