//! Client-side VLESS tunnel stream: peels the response header.
//!
//! The VLESS response header (`version(1B) | addon_len(1B) | addons`) may be
//! sent EAGERLY (xray-core writes it right after parsing the request) or
//! LAZILY (sing-box writes it only before the first application-data write;
//! see sing-vmess `vless/service.go` `serverConn.responseWritten`). A client
//! that blocks reading the header before sending payload deadlocks against
//! sing-box — xray's own outbound copies the request payload FIRST and only
//! then decodes the response header (`Xray-core/proxy/vless/outbound/
//! outbound.go` `getResponse`). We mirror that: the header is peeled on the
//! first read, whatever its arrival order.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::BoxStream;
use crate::protocol::vless::header;

/// Response-header peel state machine (private to [`Peel`]).
#[derive(Clone, Copy)]
enum PeelState {
    Head,
    Addons { total: usize, filled: usize },
    Done,
}

/// What the peel saw of the server's ack (spec D3).
///
/// The peel is where the ack is observable: a vless server's `[0,0]` response
/// header IS the acceptance, and its absence is the rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum PeelAck {
    /// The header was not read yet — the ack is possible but unobserved.
    #[default]
    Pending,
    /// The header arrived: the server accepted this config.
    Accepted,
    /// The header was NOT a vless header: a non-vless endpoint answered, so
    /// the ack is not applicable to this row.
    NotApplicable,
    /// The header was truncated (EOF before it completed): POSITIVE rejection
    /// evidence — the server closed instead of accepting.
    Rejected,
}

/// The VLESS response-header peel: `version(1B) | addon_len(1B) | addons`,
/// consumed once from the tunnel before the first payload byte.
///
/// Extracted from [`VlessClientStream`] so the UDP `PacketConn` (Task 2)
/// reuses the exact same logic. State persists in the struct, so the peel
/// is resumable across Pending polls and dropped futures — a partial poll
/// never re-consumes the version byte.
pub(crate) struct Peel {
    /// Whether the response-header version byte has been read.
    ver_read: bool,
    /// Staging for the addons bytes (discarded after the peel).
    addons: [u8; 255],
    addons_total: usize,
    state: PeelState,
    /// A non-vless first byte (REALITY transparent-proxy fallback) handed
    /// back to the reader as payload via [`Peel::take_passthrough`].
    passthrough: Option<u8>,
    /// The shared slot the ack is reported into — owned so the peel can
    /// report AT READ TIME (the ack is observed lazily, on the tunnel's first
    /// read, which happens during the probe's target-TLS handshake, long
    /// after the protocol phase returned).
    ack_slot: crate::protocol::AuthAckSlot,
    /// What the peel saw of the server's ack (spec D3).
    ack: PeelAck,
}

impl Peel {
    #[must_use]
    pub(crate) const fn new(ack_slot: crate::protocol::AuthAckSlot) -> Self {
        Self {
            ver_read: false,
            addons: [0; 255],
            addons_total: 0,
            state: PeelState::Head,
            passthrough: None,
            ack_slot,
            ack: PeelAck::Pending,
        }
    }

    /// True once the response header (or the non-vless passthrough byte)
    /// has been consumed; the stream is then plain payload.
    #[must_use]
    pub(crate) const fn is_peeled(&self) -> bool {
        matches!(self.state, PeelState::Done)
    }

    /// Returns the non-vless first byte, if the peel stashed one (REALITY
    /// transparent-proxy fallback: the first byte is payload, not a vless
    /// response header).
    #[must_use]
    pub(crate) const fn take_passthrough(&mut self) -> Option<u8> {
        self.passthrough.take()
    }

    /// Reads the VLESS response header (`version|addons_len|addons`) once.
    ///
    /// Reuses the exact `VlessClientStream` logic: eager/lazy-server-safe,
    /// fragmented-header-safe, non-vless passthrough (stashed via
    /// [`Peel::take_passthrough`]), EOF-before-header is `UnexpectedEof`.
    pub(crate) async fn ensure_peeled<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> io::Result<()> {
        loop {
            match self.state {
                PeelState::Done => return Ok(()),
                PeelState::Head => {
                    // The response header is `version(1) | addon_len(1) |
                    // addons`. A vless server always sends version 0x00; a
                    // NON-vless endpoint (REALITY transparent-proxy
                    // fallback — the client's TLS session terminates at the
                    // dest, not at a vless server) sends no header at all,
                    // so the first byte is plain payload. The version byte
                    // is read first (persisted in `ver_read` so a Pending
                    // addon-length poll does not re-consume it).
                    if !self.ver_read {
                        let mut tmp = [0u8; 1];
                        let got = r.read(&mut tmp).await?;
                        if got == 0 {
                            // The server closed instead of accepting: the
                            // header was truncated. POSITIVE rejection
                            // evidence (spec D3) — not an unobserved ack.
                            self.ack = PeelAck::Rejected;
                            self.ack_slot.set(crate::protocol::AuthAck::Failed);
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "vless response header truncated (EOF)",
                            ));
                        }
                        self.ver_read = true;
                        if tmp[0] != header::VERSION {
                            // No vless response header: hand the byte back
                            // as payload. The peer is not a vless server, so
                            // the ack does not apply to this row (the
                            // REALITY transparent-proxy fallback).
                            self.state = PeelState::Done;
                            self.ack = PeelAck::NotApplicable;
                            self.ack_slot.set(crate::protocol::AuthAck::NotApplicable);
                            self.passthrough = Some(tmp[0]);
                            return Ok(());
                        }
                    }
                    // Version matches: read the addon length.
                    let mut tmp = [0u8; 1];
                    let got = r.read(&mut tmp).await?;
                    if got == 0 {
                        // The header was truncated after its version byte:
                        // the same positive rejection evidence.
                        self.ack = PeelAck::Rejected;
                        self.ack_slot.set(crate::protocol::AuthAck::Failed);
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vless response header truncated (EOF)",
                        ));
                    }
                    self.addons_total = usize::from(tmp[0]);
                    self.state = if self.addons_total > 0 {
                        PeelState::Addons {
                            total: self.addons_total,
                            filled: 0,
                        }
                    } else {
                        // A zero-length addon section: the header is complete,
                        // so the server accepted this config.
                        self.ack = PeelAck::Accepted;
                        self.ack_slot.set(crate::protocol::AuthAck::Ok);
                        PeelState::Done
                    };
                }
                PeelState::Addons { total, filled } => {
                    // Bound the staging read to the addons remainder — a
                    // fixed-size buffer would swallow payload bytes.
                    let need = total - filled;
                    let mut tmp = [0u8; 255];
                    let got = r.read(&mut tmp[..need]).await?;
                    if got == 0 {
                        // The addons were truncated: the header never
                        // completed, so the server did not accept.
                        self.ack = PeelAck::Rejected;
                        self.ack_slot.set(crate::protocol::AuthAck::Failed);
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vless response addons truncated (EOF)",
                        ));
                    }
                    self.addons[filled..filled + got].copy_from_slice(&tmp[..got]);
                    let filled = filled + got;
                    self.state = if filled == total {
                        // The header completed: the server ACCEPTED this
                        // config (the header IS the acceptance).
                        self.ack = PeelAck::Accepted;
                        self.ack_slot.set(crate::protocol::AuthAck::Ok);
                        PeelState::Done
                    } else {
                        PeelState::Addons { total, filled }
                    };
                }
            }
        }
    }
}

/// Tunnel stream over the secured connection; strips the VLESS response
/// header once, then transparently streams the body.
pub struct VlessClientStream {
    inner: BoxStream,
    peel: Peel,
}

impl VlessClientStream {
    #[must_use]
    pub fn new(inner: BoxStream) -> Self {
        Self::with_ack_slot(inner, crate::protocol::AuthAckSlot::default())
    }

    /// A tunnel whose peel reports its ack into `ack_slot` (spec D3).
    #[must_use]
    pub fn with_ack_slot(inner: BoxStream, ack_slot: crate::protocol::AuthAckSlot) -> Self {
        Self {
            inner,
            peel: Peel::new(ack_slot),
        }
    }

    /// The wrapped stream — the vision Direct-splice seam recovers the
    /// engine `TlsStream` through the peel wrapper (see `vision.rs`
    /// `tls_stream_mut`).
    pub(crate) fn inner_mut(&mut self) -> &mut BoxStream {
        &mut self.inner
    }

    /// The wrapped stream, shared (the e2e PQ assertion recovers the
    /// engine `TlsStream` through the peel wrapper).
    #[cfg_attr(not(feature = "native-e2e"), allow(dead_code))] // e2e PQ assertion only
    pub(crate) fn inner(&self) -> &BoxStream {
        &self.inner
    }
}

impl AsyncRead for VlessClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let this = self.as_mut().get_mut();
            // A NON-vless endpoint's first byte was stashed by the peel:
            // return it as payload before streaming the tunnel.
            if let Some(b) = this.peel.take_passthrough() {
                buf.put_slice(&[b]);
                return Poll::Ready(Ok(()));
            }
            if this.peel.is_peeled() {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let fut = std::pin::pin!(this.peel.ensure_peeled(&mut this.inner));
            ready!(fut.poll(cx))?;
        }
    }
}

impl AsyncWrite for VlessClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Pair: `write` half receives what the SERVER writes; `read` half is
    /// what the client tunnel reads from.
    fn pair() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(256);
        // a -> client side (tunnel reads a); b -> server side (server writes b)
        (a, b)
    }

    async fn read_n(mut stream: VlessClientStream, n: usize) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut out = vec![0u8; n];
        stream.read_exact(&mut out).await.unwrap();
        out
    }

    /// The peel reports the ack into the slot it was built with (spec D3):
    /// a server's `[0,0]` header IS the acceptance, so the slot reads `Ok`
    /// after the header is peeled — and `Failed` when the server closes
    /// instead (the positive-rejection case), never `Unknown` for either.
    #[tokio::test]
    async fn the_peel_reports_the_ack_into_its_slot() {
        // ── the accepted case ──
        let (client, mut server) = pair();
        let slot = crate::protocol::AuthAckSlot::new(crate::protocol::AuthAck::Unknown);
        let stream = VlessClientStream::with_ack_slot(Box::new(client), slot.clone());
        server.write_all(&[0x00, 0x00]).await.unwrap();
        server.write_all(b"payload").await.unwrap();
        assert_eq!(read_n(stream, 7).await, b"payload");
        assert_eq!(
            slot.get(),
            crate::protocol::AuthAck::Ok,
            "the server's response header IS the acceptance"
        );

        // ── the rejected case: the server closes before the header ──
        let (client, server) = pair();
        let slot = crate::protocol::AuthAckSlot::new(crate::protocol::AuthAck::Unknown);
        let mut stream = VlessClientStream::with_ack_slot(Box::new(client), slot.clone());
        drop(server);
        let mut buf = [0u8; 4];
        assert!(
            tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                .await
                .is_err(),
            "a truncated header is an error"
        );
        assert_eq!(
            slot.get(),
            crate::protocol::AuthAck::Failed,
            "an EOF during the peel is POSITIVE rejection evidence, never Unknown"
        );

        // ── the not-applicable case: a non-vless first byte ──
        let (client, mut server) = pair();
        let slot = crate::protocol::AuthAckSlot::new(crate::protocol::AuthAck::Unknown);
        let stream = VlessClientStream::with_ack_slot(Box::new(client), slot.clone());
        // A first byte that is not the vless version: a transparent proxy.
        server.write_all(b"HTTP/1.1 200 OK").await.unwrap();
        let _ = read_n(stream, 1).await;
        assert_eq!(
            slot.get(),
            crate::protocol::AuthAck::NotApplicable,
            "a non-vless peer means the ack does not apply"
        );
    }

    #[tokio::test]
    async fn peels_header_sent_alone_then_payload() {
        let (client, mut server) = pair();
        let stream = VlessClientStream::new(Box::new(client));
        server.write_all(&[0x00, 0x00]).await.unwrap();
        server.write_all(b"hello native core").await.unwrap();
        assert_eq!(&read_n(stream, 5).await, b"hello");
    }

    #[tokio::test]
    async fn peels_fragmented_header_across_writes() {
        // The 2-byte response header arrives byte-by-byte: the first header
        // byte lands alone, the second is bundled with the first payload byte
        // (e.g. two TCP segments). A peel state that reads without bounding
        // to the header remainder swallows that payload byte or mis-parses
        // the header — this used to corrupt the stream.
        let (client, server) = pair();
        let stream = VlessClientStream::new(Box::new(client));
        let writer = tokio::spawn(async move {
            let mut server = server;
            server.write_all(&[0x00]).await.unwrap();
            tokio::task::yield_now().await;
            server.write_all(&[0x00, b'h']).await.unwrap();
            tokio::task::yield_now().await;
            server.write_all(b"ello native core").await.unwrap();
        });
        assert_eq!(&read_n(stream, 5).await, b"hello");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn peels_header_and_payload_in_one_write() {
        let (client, mut server) = pair();
        let stream = VlessClientStream::new(Box::new(client));
        server.write_all(&[0x00, 0x00, b'h', b'i']).await.unwrap();
        assert_eq!(&read_n(stream, 2).await, b"hi");
    }

    #[tokio::test]
    async fn skips_addons() {
        let (client, mut server) = pair();
        let stream = VlessClientStream::new(Box::new(client));
        server
            .write_all(&[0x00, 0x02, 0xaa, 0xbb, b'd', b'a', b't', b'a'])
            .await
            .unwrap();
        assert_eq!(&read_n(stream, 4).await, b"data");
    }

    #[tokio::test]
    async fn passes_through_non_vless_response() {
        // A REALITY transparent-proxy fallback terminates the client's TLS
        // session at a non-vless endpoint: the first byte is payload, not a
        // vless response header, and must pass through untouched.
        use tokio::io::AsyncReadExt;
        let (client, mut server) = pair();
        let mut stream = VlessClientStream::new(Box::new(client));
        let expected = b"HTTP/1.1 200 OK\r\nhello";
        server.write_all(expected).await.unwrap();
        let mut out = vec![0u8; expected.len()];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, expected);
    }

    #[tokio::test]
    async fn eof_before_header_is_error() {
        use tokio::io::AsyncReadExt;
        let (client, server) = pair();
        let mut stream = VlessClientStream::new(Box::new(client));
        drop(server);
        let mut out = [0u8; 4];
        assert!(stream.read(&mut out).await.is_err());
    }
}
