//! TUIC CONNECT: one bidirectional QUIC stream with the request header
//! withheld until the first payload, plus transparent 0-RTT retry.
//!
//! Only the first write can be early data. If the server rejects 0-RTT, that
//! write is replayed on a fresh stream on the same connection; later writes
//! wait for the handshake phase, so no second early-data write exists.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

use leas_proto::proto_spec::TuicConfig;

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};

use super::quic::{self, ConnectionGuard, Phase, PhaseSlot};
use super::wire::{self, Address, CONNECT_HEADER_MAX};

enum State {
    /// No byte has been sent yet; the header is still pending.
    Idle,
    /// The first frame (header + first payload) is being written.
    First {
        offset: usize,
        caller_len: usize,
    },
    /// The first frame is done and the stream is usable.
    Ready,
    /// A replacement stream is being opened after 0-RTT rejection.
    RetryOpen {
        rx: oneshot::Receiver<Result<(SendStream, RecvStream), String>>,
    },
    /// The replacement stream exists and the first frame is being replayed.
    RetryWrite {
        offset: usize,
    },
    Failed,
}

pub struct TuicConnect {
    conn: Connection,
    _guard: ConnectionGuard,
    phase: Arc<PhaseSlot>,
    header: [u8; CONNECT_HEADER_MAX],
    header_len: usize,
    send: SendStream,
    recv: RecvStream,
    /// Header + first payload, retained only until the phase resolves. On
    /// acceptance it is dropped; on rejection it is replayed.
    pending_frame: Option<Vec<u8>>,
    /// The rejection retry is one-shot: the phase stays `Rejected` after it,
    /// so every later poll must use the current stream, not open another.
    retried: bool,
    state: State,
}

impl TuicConnect {
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the stack header is moved once into the stream that owns it"
    )]
    const fn new(
        conn: Connection,
        guard: ConnectionGuard,
        phase: Arc<PhaseSlot>,
        header: [u8; CONNECT_HEADER_MAX],
        header_len: usize,
        send: SendStream,
        recv: RecvStream,
    ) -> Self {
        Self {
            conn,
            _guard: guard,
            phase,
            header,
            header_len,
            send,
            recv,
            pending_frame: None,
            retried: false,
            state: State::Idle,
        }
    }

    fn frame(&self, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(self.header_len + payload.len());
        frame.extend_from_slice(&self.header[..self.header_len]);
        frame.extend_from_slice(payload);
        frame
    }

    fn io_error(&self, context: &str) -> io::Error {
        let detail = self.phase.error().unwrap_or_else(|| context.into());
        io::Error::other(format!("tuic {context}: {detail}"))
    }

    /// Write as much of `frame` as the send stream accepts. Returns `true`
    /// when the whole frame is queued.
    fn poll_frame(
        send: &mut SendStream,
        frame: &[u8],
        offset: &mut usize,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        while *offset < frame.len() {
            match tokio::io::AsyncWrite::poll_write(Pin::new(&mut *send), cx, &frame[*offset..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tuic CONNECT stream refused bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => *offset += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(true))
    }

    /// Send the header alone (server-first read, or shutdown without a write).
    fn poll_ensure_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Idle => {
                self.pending_frame = Some(self.frame(&[]));
                self.state = State::First {
                    offset: 0,
                    caller_len: 0,
                };
            }
            State::First { .. } => {}
            State::Ready | State::RetryOpen { .. } | State::RetryWrite { .. } => {
                return Poll::Ready(Ok(()));
            }
            State::Failed => return Poll::Ready(Err(self.io_error("stream failed"))),
        }
        self.poll_first(cx)
    }

    fn poll_first(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let State::First { offset, .. } = &mut self.state else {
            return if matches!(self.state, State::Ready) {
                Poll::Ready(Ok(()))
            } else {
                self.state = State::Failed;
                Poll::Ready(Err(io::Error::other(
                    "tuic first-frame state is inconsistent",
                )))
            };
        };
        let Some(frame) = self.pending_frame.as_deref() else {
            self.state = State::Failed;
            return Poll::Ready(Err(io::Error::other("tuic missing first frame")));
        };
        match Self::poll_frame(&mut self.send, frame, offset, cx) {
            Poll::Ready(Ok(true)) => {
                self.state = State::Ready;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(false)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => {
                self.state = State::Failed;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// The first write: header + payload in one frame.
    fn poll_first_write(&mut self, buf: &[u8], cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.state, State::Idle) {
            self.pending_frame = Some(self.frame(buf));
            self.state = State::First {
                offset: 0,
                caller_len: buf.len(),
            };
        }
        self.poll_first(cx)
    }

    fn phase(&mut self, cx: &Context<'_>) -> Poll<Phase> {
        match self.phase.poll(cx) {
            Poll::Ready(Phase::Accepted) => {
                if matches!(self.state, State::Ready) {
                    self.pending_frame = None;
                }
                Poll::Ready(Phase::Accepted)
            }
            other => other,
        }
    }

    fn start_retry(&mut self) {
        self.retried = true;
        if self.pending_frame.is_none() {
            self.pending_frame = Some(self.frame(&[]));
        }
        let conn = self.conn.clone();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = tx.send(
                conn.open_bi()
                    .await
                    .map_err(|error| format!("tuic retry stream: {error}")),
            );
        });
        self.state = State::RetryOpen { rx };
    }

    fn poll_retry(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.state {
                State::RetryOpen { rx } => match Pin::new(rx).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(Ok((send, recv)))) => {
                        self.send = send;
                        self.recv = recv;
                        self.state = State::RetryWrite { offset: 0 };
                    }
                    Poll::Ready(Ok(Err(detail))) => {
                        self.state = State::Failed;
                        return Poll::Ready(Err(io::Error::other(detail)));
                    }
                    Poll::Ready(Err(_)) => {
                        self.state = State::Failed;
                        return Poll::Ready(Err(io::Error::other("tuic retry task disappeared")));
                    }
                },
                State::RetryWrite { offset } => {
                    let Some(frame) = self.pending_frame.as_deref() else {
                        self.state = State::Failed;
                        return Poll::Ready(Err(io::Error::other("tuic missing retry frame")));
                    };
                    match Self::poll_frame(&mut self.send, frame, offset, cx) {
                        Poll::Ready(Ok(true)) => {
                            self.pending_frame = None;
                            self.state = State::Ready;
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Ok(false)) => {}
                        Poll::Ready(Err(error)) => {
                            self.state = State::Failed;
                            return Poll::Ready(Err(error));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                State::Ready => return Poll::Ready(Ok(())),
                _ => {
                    self.state = State::Failed;
                    return Poll::Ready(Err(io::Error::other("tuic retry state is inconsistent")));
                }
            }
        }
    }

    /// Drive any pending frame and, when the phase says so, the retry.
    fn poll_ready_stream(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_ensure_header(cx))?;
        match ready!(self.phase(cx)) {
            Phase::Rejected if !self.retried => {
                self.start_retry();
                self.poll_retry(cx)
            }
            Phase::Rejected => match self.state {
                State::RetryOpen { .. } | State::RetryWrite { .. } => self.poll_retry(cx),
                _ => Poll::Ready(Ok(())),
            },
            Phase::Accepted => Poll::Ready(Ok(())),
            Phase::Failed => Poll::Ready(Err(self.io_error("handshake failed"))),
            Phase::Pending => Poll::Pending,
        }
    }

    fn poll_direct_write(&mut self, buf: &[u8], cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
}

impl AsyncWrite for TuicConnect {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.state {
            State::Idle => {
                match self.phase.poll(cx) {
                    Poll::Ready(Phase::Failed) => {
                        return Poll::Ready(Err(self.io_error("handshake failed")));
                    }
                    Poll::Ready(Phase::Rejected) => {
                        self.pending_frame = Some(self.frame(buf));
                        self.start_retry();
                        return Poll::Ready(ready!(self.poll_retry(cx)).map(|()| buf.len()));
                    }
                    _ => {}
                }
                ready!(self.poll_first_write(buf, cx))?;
                Poll::Ready(Ok(buf.len()))
            }
            State::First { .. } => {
                let State::First { caller_len, .. } = self.state else {
                    unreachable!("matched State::First");
                };
                let len = caller_len;
                ready!(self.poll_first(cx))?;
                Poll::Ready(Ok(len))
            }
            State::Ready => match ready!(self.phase(cx)) {
                Phase::Failed => Poll::Ready(Err(self.io_error("handshake failed"))),
                Phase::Pending => Poll::Pending,
                Phase::Accepted => self.poll_direct_write(buf, cx),
                Phase::Rejected if self.retried => self.poll_direct_write(buf, cx),
                Phase::Rejected => {
                    self.start_retry();
                    ready!(self.poll_retry(cx))?;
                    self.poll_direct_write(buf, cx)
                }
            },
            State::RetryOpen { .. } | State::RetryWrite { .. } => {
                ready!(self.poll_retry(cx))?;
                self.poll_direct_write(buf, cx)
            }
            State::Failed => Poll::Ready(Err(self.io_error("stream failed"))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::First { .. } => ready!(self.poll_first(cx))?,
            State::RetryOpen { .. } | State::RetryWrite { .. } => {
                ready!(self.poll_retry(cx))?;
            }
            State::Idle | State::Ready | State::Failed => {}
        }
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_ready_stream(cx))?;
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

impl AsyncRead for TuicConnect {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_ready_stream(cx))?;
        tokio::io::AsyncRead::poll_read(Pin::new(&mut self.recv), cx, out)
    }
}

/// Dial and return the CONNECT tunnel. The request header is withheld until
/// the first payload (or the first read), so one stream write carries both.
pub async fn connect(ctx: &LinkContext, cfg: &TuicConfig) -> Result<BoxStream, NativeError> {
    let dialed = quic::dial(ctx, cfg, true).await?;
    let address = Address::of_host(&ctx.target.host)
        .map_err(|e| NativeError::Config(format!("tuic destination: {e}")))?;
    let mut header = [0u8; CONNECT_HEADER_MAX];
    let header_len = wire::connect_header(address, ctx.target.port, &mut header)
        .map_err(|e| NativeError::Config(format!("tuic CONNECT header: {e}")))?;
    let (send, recv) = tokio::time::timeout(timeouts::DIAL, dialed.conn.open_bi())
        .await
        .map_err(|_| NativeError::Timeout {
            step: "tuic connect stream",
            limit: timeouts::DIAL,
        })?
        .map_err(|e| NativeError::Dial(format!("tuic connect stream: {e}")))?;
    Ok(Box::new(TuicConnect::new(
        dialed.conn,
        dialed.guard,
        dialed.phase,
        header,
        header_len,
        send,
        recv,
    )))
}
