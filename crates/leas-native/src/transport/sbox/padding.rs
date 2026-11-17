//! The sing-box mux padding connection (`padding.go` at the pinned reference).
//!
//! Only the first [`FIRST_PADDINGS`] frames are padded; afterwards the
//! connection is a pass-through. A padded frame is
//! `[2B data_len BE][2B pad_len BE][data][pad]`, written as ONE write. The
//! reader must parse the same header, hand the data up, then skip the pad.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::protocol::PAD_MAX;

/// The reference's `kFirstPaddings`: frames after this many are unpadded.
pub const FIRST_PADDINGS: u8 = 16;

/// A connection that pads its first [`FIRST_PADDINGS`] writes and strips the
/// padding from the peer's first [`FIRST_PADDINGS`] frames.
///
/// Applied OUTSIDE the request preamble wrapper (`HeaderFirst` in our tree):
/// the preamble is prepended to the first padded frame, exactly like the
/// reference's `protocolConn` under its `paddingConn`.
pub struct PaddingConn<S> {
    inner: S,
    written_frames: u8,
    pending: Vec<u8>,
    pending_pos: usize,
    /// Caller bytes accepted into `pending`, reported once the frame is out.
    pending_data: usize,
    read_frames: u8,
    read_data: usize,
    read_padding: usize,
    header: [u8; 4],
    header_fill: usize,
    scratch: [u8; 512],
}

impl<S> PaddingConn<S> {
    /// Wrap `inner`.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            written_frames: 0,
            pending: Vec::with_capacity(4 + 65535 + PAD_MAX),
            pending_pos: 0,
            pending_data: 0,
            read_frames: 0,
            read_data: 0,
            read_padding: 0,
            header: [0u8; 4],
            header_fill: 0,
            scratch: [0u8; 512],
        }
    }
}

impl<S: AsyncWrite + Unpin> PaddingConn<S> {
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            let written =
                Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]);
            match written {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => self.pending_pos += n,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PaddingConn<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        loop {
            if this.pending_pos < this.pending.len() {
                match this.flush_pending(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if this.pending_data > 0 {
                let accepted = this.pending_data;
                this.pending_data = 0;
                this.pending.clear();
                this.pending_pos = 0;
                return Poll::Ready(Ok(accepted));
            }
            if this.written_frames >= FIRST_PADDINGS || buf.is_empty() {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            let chunk = buf.len().min(u16::MAX as usize);
            let pad_len = super::protocol::pad_len();
            this.pending.clear();
            this.pending
                .extend_from_slice(&u16::try_from(chunk).expect("chunk ≤ 65535").to_be_bytes());
            this.pending
                .extend_from_slice(&u16::try_from(pad_len).expect("pad < 768").to_be_bytes());
            this.pending.extend_from_slice(&buf[..chunk]);
            let start = this.pending.len();
            this.pending.resize(start + pad_len, 0);
            crate::rand::fill_nonsecret(&mut this.pending[start..]);
            this.pending_pos = 0;
            this.pending_data = chunk;
            this.written_frames += 1;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PaddingConn<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_data > 0 {
                let want = buf.remaining().min(this.read_data);
                let mut scratch = ReadBuf::new(&mut this.scratch[..want]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut scratch) {
                    Poll::Ready(Ok(())) => {
                        let filled = scratch.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        buf.put_slice(scratch.filled());
                        this.read_data -= filled;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if this.read_padding > 0 {
                let want = this.scratch.len().min(this.read_padding);
                let mut scratch = ReadBuf::new(&mut this.scratch[..want]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut scratch) {
                    Poll::Ready(Ok(())) => {
                        let filled = scratch.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        this.read_padding -= filled;
                        continue;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if this.read_frames >= FIRST_PADDINGS {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            while this.header_fill < 4 {
                let mut scratch = ReadBuf::new(&mut this.header[this.header_fill..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut scratch) {
                    Poll::Ready(Ok(())) => {
                        let filled = scratch.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        this.header_fill += filled;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            this.read_data = usize::from(u16::from_be_bytes([this.header[0], this.header[1]]));
            this.read_padding = usize::from(u16::from_be_bytes([this.header[2], this.header[3]]));
            this.header_fill = 0;
            this.read_frames += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::transport::sbox::protocol::{PAD_MAX, PAD_MIN};

    #[tokio::test]
    async fn first_writes_are_framed_and_later_writes_pass_through() {
        let (client, mut peer) = duplex(1 << 20);
        let mut conn = PaddingConn::new(client);

        conn.write_all(b"abc").await.expect("padded write");
        let mut header = [0u8; 4];
        peer.read_exact(&mut header).await.expect("frame header");
        assert_eq!(u16::from_be_bytes([header[0], header[1]]), 3);
        let pad_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        assert!((PAD_MIN..PAD_MAX).contains(&pad_len));
        let mut data = [0u8; 3];
        peer.read_exact(&mut data).await.expect("frame data");
        assert_eq!(&data, b"abc");
        let mut pad = vec![0u8; pad_len];
        peer.read_exact(&mut pad).await.expect("frame padding");

        // 16 frames total; the 17th is a raw write.
        for _ in 0..15 {
            conn.write_all(b"x").await.expect("padded write");
            peer.read_exact(&mut header).await.expect("header");
            let pad_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let mut sink = vec![0u8; 1 + pad_len];
            peer.read_exact(&mut sink).await.expect("frame body");
        }
        conn.write_all(b"raw").await.expect("passthrough write");
        let mut raw = [0u8; 3];
        peer.read_exact(&mut raw).await.expect("raw bytes");
        assert_eq!(&raw, b"raw");
    }

    #[tokio::test]
    async fn reads_strip_padding_and_then_pass_through() {
        let (client, mut peer) = duplex(1 << 20);
        let mut conn = PaddingConn::new(client);

        for byte in 0u8..16 {
            let mut frame = Vec::new();
            frame.extend_from_slice(&1u16.to_be_bytes());
            frame.extend_from_slice(&2u16.to_be_bytes());
            frame.push(byte);
            frame.extend_from_slice(&[0xAA, 0xBB]);
            peer.write_all(&frame).await.expect("padded frame");
        }
        let mut got = [0u8; 16];
        conn.read_exact(&mut got).await.expect("16 data bytes");
        assert_eq!(got, std::array::from_fn(|i| u8::try_from(i).expect("i")));

        peer.write_all(b"plain").await.expect("raw bytes");
        let mut raw = [0u8; 5];
        conn.read_exact(&mut raw).await.expect("raw read");
        assert_eq!(&raw, b"plain");
    }
}
