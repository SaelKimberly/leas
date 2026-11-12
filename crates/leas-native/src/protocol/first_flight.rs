//! Sends a protocol's request header in the same write as the first payload.
//!
//! VLESS and Trojan open a proxied stream with a short request header (who is
//! asking, where to). Written on its own it becomes a tiny TLS record and, with
//! `TCP_NODELAY`, a tiny packet of a recognisable size at the very start of
//! every connection, followed by a second packet carrying what the application
//! wanted to say. [`HeaderFirst`] holds the header back until the application
//! writes, then hands both to the carrier as one write: one record, one packet,
//! one less thing to recognise.
//!
//! The rules it keeps:
//!
//! * the header is always the first bytes on the carrier, exactly once, and
//!   nothing the caller wrote is reordered or lost;
//! * bytes accepted from a caller are ours, so a partially flushed header never
//!   makes `poll_write` report less than it took;
//! * the protocol handshake no longer blocks on a write, so the per-write
//!   timeout that used to guard it is gone — the relay's idle bound is the
//!   outer one.
//!
//! The surprise: some protocols let the *server* speak first (SSH, SMTP), so
//! the application may never write until it has read. A header that waited
//! forever would deadlock those. So a **read flushes the header before it
//! hands up read data**: the server-first case costs one write, not a timer,
//! and the carrier never carries read data ahead of the request header.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The most caller bytes copied in beside the header. A larger first write
/// leaves the remainder to the caller, which writes it straight through next.
const FIRST_PAYLOAD_MAX: usize = 16 * 1024;

/// A stream whose first write carries `header` in front of the caller's bytes.
pub struct HeaderFirst<S> {
    inner: S,
    /// The header, followed by whatever the first write added.
    pending: Vec<u8>,
    /// How much of `pending` the carrier has taken.
    pos: usize,
    /// True once a first payload was accepted.
    released: bool,
}

impl<S> HeaderFirst<S> {
    /// Wrap `inner`, holding `header` back until the first write or the timer.
    pub const fn new(inner: S, header: Vec<u8>) -> Self {
        Self {
            inner,
            pending: header,
            pos: 0,
            released: false,
        }
    }

    /// The wrapped carrier.
    ///
    /// The vision codec peels the concrete stream behind the boxed seam (its
    /// `Direct` hand-off downcasts to the engine `TlsStream`). This wrapper sits
    /// between the response peel and that stream, so the peel has to be able to
    /// look through it — a downcast miss is a loud failure, not a silent
    /// corruption.
    pub const fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// The wrapped carrier by shared reference (the e2e oracle walks down to
    /// the engine `TlsStream` through this wrapper).
    #[cfg(feature = "e2e-support")]
    #[doc(hidden)]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// The wrapped carrier, for tests that assert on what reached it.
    #[cfg(test)]
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Push as much of `pending` into the carrier as it takes.
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while self.pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the carrier accepted zero bytes of the request header",
                    )));
                }
                Poll::Ready(Ok(n)) => self.pos += n,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        // The header is on the carrier; the buffer is small and stays allocated
        // so a retry cannot make this path allocate.
        self.pending.clear();
        self.pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HeaderFirst<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.released {
            // The application reads before it writes (a server-first protocol
            // such as SSH or SMTP): the header goes out on its own now, ahead
            // of any read data, which is what happened on every connection
            // before this wrapper existed.
            this.released = true;
        }
        if !this.pending.is_empty() {
            // The header must lead: do not hand up read data before it is on
            // the carrier. A pending carrier registers its waker here.
            ready!(this.flush_pending(cx))?;
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HeaderFirst<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.released {
            let take = buf.len().min(FIRST_PAYLOAD_MAX);
            this.pending.extend_from_slice(&buf[..take]);
            this.released = true;
            // Flush what the carrier takes now. The accepted bytes are already
            // ours, so a `Pending` here must not shrink the reported count.
            match this.flush_pending(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) | Poll::Pending => {}
            }
            return Poll::Ready(Ok(take));
        }
        ready!(this.flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        ready!(this.flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.released && !this.pending.is_empty() {
            // A tunnel closed without ever writing still owes its header.
            this.released = true;
        }
        ready!(this.flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// A carrier that records every write call, so "one write" is observable
    /// rather than inferred from how a buffer happened to be split.
    #[derive(Default)]
    struct Recording {
        writes: Vec<Vec<u8>>,
        /// At most this many bytes accepted per call; 0 means "all".
        max_chunk: usize,
        /// Return `Pending` once (waking immediately) before accepting bytes,
        /// which is the branch that must not shrink the reported count.
        block_once: bool,
    }

    impl AsyncWrite for Recording {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.block_once {
                self.block_once = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = if self.max_chunk == 0 {
                buf.len()
            } else {
                buf.len().min(self.max_chunk)
            };
            if n == 0 && !buf.is_empty() {
                return Poll::Ready(Err(io::ErrorKind::WouldBlock.into()));
            }
            self.writes.push(buf[..n].to_vec());
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for Recording {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    const HEADER: &[u8] = b"request-header";
    const PAYLOAD: &[u8] = b"GET / HTTP/1.0\r\n\r\n";

    fn flattened(writes: &[Vec<u8>]) -> Vec<u8> {
        writes.concat()
    }

    #[tokio::test]
    async fn header_and_first_payload_leave_in_one_write() {
        let carrier = Recording::default();
        let mut stream = HeaderFirst::new(carrier, HEADER.to_vec());
        stream.write_all(PAYLOAD).await.unwrap();
        let carrier = stream.into_inner();
        assert_eq!(carrier.writes.len(), 1, "expected a single carrier write");
        let mut expected = HEADER.to_vec();
        expected.extend_from_slice(PAYLOAD);
        assert_eq!(flattened(&carrier.writes), expected);
    }

    #[tokio::test]
    async fn the_header_is_written_exactly_once() {
        let carrier = Recording::default();
        let mut stream = HeaderFirst::new(carrier, HEADER.to_vec());
        stream.write_all(PAYLOAD).await.unwrap();
        stream.write_all(b"second").await.unwrap();
        let carrier = stream.into_inner();
        let mut expected = HEADER.to_vec();
        expected.extend_from_slice(PAYLOAD);
        expected.extend_from_slice(b"second");
        assert_eq!(flattened(&carrier.writes), expected);
        assert_eq!(
            flattened(&carrier.writes)
                .windows(HEADER.len())
                .filter(|w| *w == HEADER)
                .count(),
            1,
            "the header must not be repeated"
        );
    }

    /// A carrier that takes small bites must not lose or reorder a byte, and
    /// every accepted caller byte must be reported as written.
    #[tokio::test]
    async fn a_partial_carrier_still_delivers_header_then_payload() {
        let carrier = Recording {
            max_chunk: 7,
            ..Recording::default()
        };
        let mut stream = HeaderFirst::new(carrier, HEADER.to_vec());
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        let carrier = stream.into_inner();
        let mut expected = HEADER.to_vec();
        expected.extend_from_slice(PAYLOAD);
        assert_eq!(flattened(&carrier.writes), expected);
    }

    /// Server-first protocol: the application reads and never writes. The
    /// read flushes the header ahead of any read data, so the server sees the
    /// request even though the client never wrote.
    #[tokio::test]
    async fn a_read_flushes_the_header_before_read_data() {
        let (client, mut server) = tokio::io::duplex(256);
        let mut stream = HeaderFirst::new(client, HEADER.to_vec());
        server.write_all(b"greeting").await.unwrap();
        let mut buf = [0u8; 8];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"greeting");
        let mut got = vec![0u8; HEADER.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, HEADER, "the read must have flushed the header");
    }

    /// A carrier that takes the first write as pending must not shrink the
    /// count `poll_write` reports: the caller's bytes are already ours.
    #[tokio::test]
    async fn a_pending_carrier_does_not_shrink_the_reported_count() {
        let carrier = Recording {
            block_once: true,
            ..Recording::default()
        };
        let mut stream = HeaderFirst::new(carrier, HEADER.to_vec());
        assert_eq!(
            stream.write(PAYLOAD).await.unwrap(),
            PAYLOAD.len(),
            "buffered caller bytes are ours, not the carrier's"
        );
        stream.flush().await.unwrap();
        let carrier = stream.into_inner();
        let mut expected = HEADER.to_vec();
        expected.extend_from_slice(PAYLOAD);
        assert_eq!(flattened(&carrier.writes), expected);
    }

    /// Closing without a write still sends the header, so a failed or
    /// abandoned connect is not silently headerless.
    #[tokio::test]
    async fn shutdown_without_a_write_sends_the_header() {
        let (client, mut server) = tokio::io::duplex(256);
        let mut stream = HeaderFirst::new(client, HEADER.to_vec());
        stream.shutdown().await.unwrap();
        let mut got = vec![0u8; HEADER.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, HEADER);
    }
}
