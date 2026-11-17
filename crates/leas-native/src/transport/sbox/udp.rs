//! Datagram framing over an sbox UDP stream.
//!
//! The stream request carries `flags = UDP` and the association's destination;
//! every datagram is `[2B BE length][payload]` in both directions. The stream
//! has no per-packet address, so a send naming a different destination than
//! the association's is refused rather than silently mis-routed.

use std::io;
use std::net::SocketAddr;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::BoxStream;

/// One sbox UDP association.
pub struct SboxUdpTunnel {
    stream: BoxStream,
    /// The association's destination, when the caller could resolve it. A
    /// datagram naming another destination is refused.
    session: Option<SocketAddr>,
}

impl SboxUdpTunnel {
    /// Wrap the UDP stream (`udp` flag already in its request).
    #[must_use]
    pub fn new(stream: BoxStream, session: Option<SocketAddr>) -> Self {
        Self { stream, session }
    }

    /// Send one datagram.
    ///
    /// # Errors
    ///
    /// A destination other than the association's, a payload over 65 535
    /// bytes, or a write failure.
    pub async fn send(&mut self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        if let (Some(session), Some(dest)) = (self.session, dest)
            && session != dest
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sbox udp: the association carries one destination; a different one cannot be framed",
            ));
        }
        let len = u16::try_from(payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "sbox udp: datagram exceeds 65535 bytes",
            )
        })?;
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame).await
    }

    /// Receive one datagram; `Ok(None)` on a clean end-of-stream.
    ///
    /// # Errors
    ///
    /// A read failure or a truncated frame.
    pub async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Bytes)>> {
        let mut len = [0u8; 2];
        match self.stream.read_exact(&mut len).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        let len = usize::from(u16::from_be_bytes(len));
        if len == 0 {
            // An empty datagram is legal and is delivered as such (the
            // reference's `Read` returns it; the split reader agrees).
            return Ok(Some((None, Bytes::new())));
        }
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).await?;
        Ok(Some((None, Bytes::from(payload))))
    }

    /// Split into a reader and a writer for concurrent relay halves.
    #[must_use]
    pub fn split(self) -> (SboxUdpReader, SboxUdpWriter) {
        let (r, w) = tokio::io::split(self.stream);
        (
            SboxUdpReader { stream: r },
            SboxUdpWriter {
                stream: w,
                session: self.session,
            },
        )
    }
}

/// The read half of a split sbox UDP association.
pub struct SboxUdpReader {
    stream: ReadHalf<BoxStream>,
}

impl SboxUdpReader {
    /// Receive one datagram; `Ok(None)` on a clean end-of-stream.
    pub(crate) async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Bytes)>> {
        let mut len = [0u8; 2];
        match self.stream.read_exact(&mut len).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        let len = usize::from(u16::from_be_bytes(len));
        if len == 0 {
            return Ok(Some((None, Bytes::new())));
        }
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).await?;
        Ok(Some((None, Bytes::from(payload))))
    }
}

/// The write half of a split sbox UDP association.
pub struct SboxUdpWriter {
    stream: WriteHalf<BoxStream>,
    session: Option<SocketAddr>,
}

impl SboxUdpWriter {
    /// Send one datagram (same destination rule as the unsplit tunnel).
    pub(crate) async fn send(
        &mut self,
        dest: Option<SocketAddr>,
        payload: &[u8],
    ) -> io::Result<()> {
        if let (Some(session), Some(dest)) = (self.session, dest)
            && session != dest
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sbox udp: the association carries one destination; a different one cannot be framed",
            ));
        }
        let len = u16::try_from(payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "sbox udp: datagram exceeds 65535 bytes",
            )
        })?;
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame).await
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn frames_datagrams_both_ways_and_refuses_a_foreign_destination() {
        let (client, mut peer) = duplex(1024);
        let session: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut tunnel = SboxUdpTunnel::new(Box::new(client), Some(session));
        tunnel.send(Some(session), b"query").await.expect("send");
        let mut wire = [0u8; 7];
        peer.read_exact(&mut wire).await.expect("wire");
        assert_eq!(&wire[..2], [0, 5], "BE16 length");
        assert_eq!(&wire[2..], b"query");

        let mut reply = vec![0u8, 5];
        reply.extend_from_slice(b"reply");
        peer.write_all(&reply).await.expect("reply");
        let (_, payload) = tunnel.recv().await.expect("recv").expect("one");
        assert_eq!(&payload[..], b"reply");

        let foreign: SocketAddr = "127.0.0.1:54".parse().expect("addr");
        assert!(
            tunnel.send(Some(foreign), b"x").await.is_err(),
            "the association carries one destination"
        );
    }

    #[tokio::test]
    async fn split_halves_relay_independently() {
        let (client, mut peer) = duplex(1024);
        let tunnel = SboxUdpTunnel::new(Box::new(client), None);
        let (mut reader, mut writer) = tunnel.split();
        writer.send(None, b"out").await.expect("send");
        let mut frame = [0u8; 5];
        peer.read_exact(&mut frame).await.expect("wire");
        peer.write_all(&[0, 2, b'o', b'k']).await.expect("reply");
        let (_, payload) = reader.recv().await.expect("recv").expect("one");
        assert_eq!(&payload[..], b"ok");
    }
}
