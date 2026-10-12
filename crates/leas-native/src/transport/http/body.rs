//! Body adapters for the hyper HTTP layer.
//!
//! `ReqBody` is the request-body union (empty / fixed chunk / live channel
//! pipe); hyper drives framing: `Full` sets Content-Length, `Channel`
//! streams (chunked on h1, DATA frames on h2). `IncomingReader` turns a
//! hyper response body into our `AsyncRead` stream.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame};

/// Request body for a hyper client connection.
#[derive(Default)]
pub enum ReqBody {
    #[default]
    Empty,
    Full(Bytes),
    Channel(http_body_util::Channel<Bytes>),
}

impl ReqBody {
    /// A live pipe body: push app bytes via the returned sender. Used for the
    /// xhttp stream-up POST and the v2rayhttp PUT (upload side).
    #[must_use]
    pub fn channel() -> (http_body_util::channel::Sender<Bytes>, Self) {
        let (tx, body) = http_body_util::Channel::new(1);
        (tx, Self::Channel(body))
    }
}

impl http_body::Body for ReqBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Empty => Poll::Ready(None),
            Self::Full(b) => {
                if b.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Frame::data(std::mem::take(b)))))
                }
            }
            Self::Channel(c) => Pin::new(c).poll_frame(cx),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Empty => http_body::SizeHint::with_exact(0),
            Self::Full(b) => http_body::SizeHint::with_exact(b.len() as u64),
            Self::Channel(_) => http_body::SizeHint::default(),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Full(b) => b.is_empty(),
            Self::Channel(_) => false,
        }
    }
}

/// `AsyncRead` adapter over a hyper response body (`Incoming`). hyper handles
/// chunked / Content-Length / EOF framing; this yields DATA-frame bytes.
pub struct IncomingReader {
    body: hyper::body::Incoming,
    /// Bytes left over from a DATA frame that did not fit the caller's
    /// `ReadBuf` on the previous poll — served first on the next read.
    pending: Option<Bytes>,
}

impl IncomingReader {
    #[must_use]
    pub const fn new(body: hyper::body::Incoming) -> Self {
        Self {
            body,
            pending: None,
        }
    }
}

impl tokio::io::AsyncRead for IncomingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            // Serve bytes left over from a previous frame that didn't fit the
            // caller's buffer before polling the body again. Never drops
            // DATA (AsyncRead contract: bytes are only lost at EOF).
            if let Some(data) = self.pending.take() {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.pending = Some(data.slice(n..));
                }
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        // An empty DATA frame carries no bytes; treat it as a
                        // no-op, not EOF (an empty read signals end-of-stream
                        // to AsyncRead callers).
                        if data.is_empty() {
                            continue;
                        }
                        let n = data.len().min(buf.remaining());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            self.pending = Some(data.slice(n..));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    // non-data frame (trailers) — skip and continue.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body::Body;

    #[test]
    fn empty_is_end_stream() {
        let body = ReqBody::Empty;
        assert!(body.is_end_stream());
        let size = body.size_hint();
        assert_eq!(size.exact(), Some(0));
    }

    #[test]
    fn full_yields_one_frame_then_eof() {
        let mut body = ReqBody::Full(Bytes::from_static(b"abc"));
        let size = body.size_hint();
        assert_eq!(size.exact(), Some(3));
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let poll = Pin::new(&mut body).poll_frame(&mut cx);
        let Poll::Ready(Some(Ok(frame))) = poll else {
            panic!("expected a frame")
        };
        assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"abc"));
        let poll = Pin::new(&mut body).poll_frame(&mut cx);
        assert!(matches!(poll, Poll::Ready(None)));
    }

    #[test]
    fn channel_send_receives_data() {
        let (mut tx, mut body) = ReqBody::channel();
        tx.try_send(Frame::data(Bytes::from_static(b"xy"))).unwrap();
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let poll = Pin::new(&mut body).poll_frame(&mut cx);
        let Poll::Ready(Some(Ok(frame))) = poll else {
            panic!("expected frame")
        };
        assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"xy"));
        // Dropping `tx` closes the pipe: the body then reads EOF.
        drop(tx);
        let poll = Pin::new(&mut body).poll_frame(&mut cx);
        assert!(matches!(poll, Poll::Ready(None)));
    }
}
