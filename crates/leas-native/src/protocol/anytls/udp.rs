//! `AnyTLS` UDP carrier: sing-box's udp-over-tcp (uot) v2.
//!
//! The protocol relays UDP by opening a stream to the magic FQDN
//! `sp.v2.udp-over-tcp.arpa` and then speaking uot over that stream
//! (`thirdparty/sing-box/protocol/anytls/outbound.go`, `sing/common/uot`):
//!
//! ```text
//! request:  isConnect:u8 | address | port BE2
//! datagram: address | port BE2 | length:u16 BE | payload
//! ```
//!
//! uot's address family bytes differ from SOCKS5 (and from the `AnyTLS` stream
//! target): `0x00` IPv4, `0x01` IPv6, `0x02` FQDN (length-prefixed). We use
//! `isConnect = 0`, so every datagram carries its own destination — the
//! per-packet semantics a SOCKS UDP association needs.

use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::BoxStream;
use crate::addr::{Host, TargetAddr};

const UOT_IPV4: u8 = 0x00;
const UOT_IPV6: u8 = 0x01;
const UOT_FQDN: u8 = 0x02;

/// The stream destination that selects sing-box's uot service.
pub const UOT_DESTINATION: &str = "sp.v2.udp-over-tcp.arpa";

/// One uot v2 datagram tunnel over an `AnyTLS` stream.
pub struct UdpConn {
    inner: BoxStream,
    /// The request destination; `None`-destination sends fall back to it.
    session: TargetAddr,
}

impl UdpConn {
    /// Write the uot request and return the tunnel.
    pub async fn new(mut inner: BoxStream, session: &TargetAddr) -> io::Result<Self> {
        let request = encode_request(session)?;
        inner.write_all(&request).await?;
        inner.flush().await?;
        Ok(Self {
            inner,
            session: session.clone(),
        })
    }

    /// Send one datagram.
    pub async fn send(&mut self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        let mut out = Vec::with_capacity(1 + 16 + 2 + 2 + 2 + payload.len());
        match dest {
            Some(dest) => push_socket_addr(&mut out, dest),
            None => push_target(&mut out, &self.session)?,
        }
        let len = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "uot datagram too large"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        self.inner.write_all(&out).await
    }

    /// Receive one datagram; `Ok(None)` on a clean EOF at a frame boundary.
    pub async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Vec<u8>)>> {
        read_datagram(&mut self.inner).await
    }

    /// Split into a reader and writer half.
    pub fn split(self) -> io::Result<(UdpReader, UdpWriter)> {
        let Self { inner, session } = self;
        let (rx, tx) = tokio::io::split(inner);
        Ok((UdpReader { inner: rx }, UdpWriter { inner: tx, session }))
    }
}

/// The read half of a split [`UdpConn`].
pub struct UdpReader {
    inner: tokio::io::ReadHalf<BoxStream>,
}

impl UdpReader {
    pub async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Vec<u8>)>> {
        read_datagram(&mut self.inner).await
    }
}

/// The write half of a split [`UdpConn`].
pub struct UdpWriter {
    inner: tokio::io::WriteHalf<BoxStream>,
    session: TargetAddr,
}

impl UdpWriter {
    pub async fn send(&mut self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        let mut out = Vec::with_capacity(1 + 16 + 2 + 2 + 2 + payload.len());
        match dest {
            Some(dest) => push_socket_addr(&mut out, dest),
            None => push_target(&mut out, &self.session)?,
        }
        let len = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "uot datagram too large"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        self.inner.write_all(&out).await
    }
}

/// Parse one `address | port | length | payload` datagram.
async fn read_datagram<R: AsyncRead + Unpin>(
    inner: &mut R,
) -> io::Result<Option<(Option<SocketAddr>, Vec<u8>)>> {
    let mut family = [0u8; 1];
    match inner.read_exact(&mut family).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let addr = match family[0] {
        UOT_IPV4 => {
            let mut octets = [0u8; 4];
            inner.read_exact(&mut octets).await?;
            Some(IpAddr::from(octets))
        }
        UOT_IPV6 => {
            let mut octets = [0u8; 16];
            inner.read_exact(&mut octets).await?;
            Some(IpAddr::from(octets))
        }
        UOT_FQDN => {
            let mut len = [0u8; 1];
            inner.read_exact(&mut len).await?;
            // A domain reply has no `SocketAddr` form; the inbound resolves it
            // from the session destination instead (the trojan carrier's rule).
            let mut name = vec![0u8; usize::from(len[0])];
            inner.read_exact(&mut name).await?;
            None
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("uot: unknown address family {other:#x}"),
            ));
        }
    };
    let mut port = [0u8; 2];
    inner.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    let mut len = [0u8; 2];
    inner.read_exact(&mut len).await?;
    let mut payload = vec![0u8; usize::from(u16::from_be_bytes(len))];
    inner.read_exact(&mut payload).await?;
    Ok(Some((addr.map(|ip| SocketAddr::new(ip, port)), payload)))
}

/// `isConnect = 0` + the request destination.
///
/// The REQUEST destination uses sing's default SOCKS5 serializer
/// (`M.SocksaddrSerializer`: ATYP `1`/`4`/`3` + port), while per-datagram
/// addresses use uot's own family set (`0x00`/`0x01`/`0x02`) — mixing the two
/// makes the server fail to parse the request and close the stream.
fn encode_request(session: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut out = vec![0];
    let addr = crate::addr::encode_addr_port_last(session)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    out.extend_from_slice(&addr);
    Ok(out)
}

fn push_target(out: &mut Vec<u8>, target: &TargetAddr) -> io::Result<()> {
    match &target.host {
        Host::Ip(ip) => push_ip(out, *ip),
        Host::Domain(domain) => {
            let len = u8::try_from(domain.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "uot: domain exceeds 255 bytes")
            })?;
            out.push(UOT_FQDN);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

fn push_socket_addr(out: &mut Vec<u8>, dest: SocketAddr) {
    push_ip(out, dest.ip());
    out.extend_from_slice(&dest.port().to_be_bytes());
}

fn push_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            out.push(UOT_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(UOT_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_uses_socks5_atyp_not_the_uot_family_set() {
        // The request destination is read with sing's default serializer:
        // ATYP 1/4/3, not uot's 0x00/0x01/0x02 (which frame the datagrams).
        let target = TargetAddr::new(Host::Ip("1.2.3.4".parse().expect("ip")), 53);
        assert_eq!(
            encode_request(&target).expect("encodes"),
            vec![0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35]
        );
        let v6 = TargetAddr::new(Host::Ip("::1".parse().expect("ip")), 443);
        let encoded = encode_request(&v6).expect("encodes");
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x04);
        assert_eq!(&encoded[18..], &[0x01, 0xBB]);
        let domain = TargetAddr::new(Host::Domain("example.test".into()), 80);
        let encoded = encode_request(&domain).expect("encodes");
        assert_eq!(&encoded[..3], &[0x00, 0x03, 12]);
        assert_eq!(&encoded[15..], &[0x00, 0x50]);
    }

    #[tokio::test]
    async fn datagrams_roundtrip_through_the_split_halves() {
        // The peer side speaks the same framing by hand: read the request,
        // then echo one datagram with the same destination.
        let (client, mut peer) = tokio::io::duplex(4096);
        let session = TargetAddr::new(Host::Ip("127.0.0.1".parse().expect("ip")), 9);
        let conn = UdpConn::new(Box::new(client), &session)
            .await
            .expect("request writes");
        let (mut reader, mut writer) = conn.split().expect("splits");

        let request = {
            let mut buf = vec![0u8; 1 + 1 + 4 + 2];
            peer.read_exact(&mut buf).await.expect("request");
            buf
        };
        assert_eq!(request, vec![0x00, 0x01, 127, 0, 0, 1, 0, 9]);

        let dest: SocketAddr = "8.8.8.8:53".parse().expect("addr");
        writer.send(Some(dest), b"ping").await.expect("send");
        let mut echoed = vec![0u8; 7 + 2 + 4];
        peer.read_exact(&mut echoed).await.expect("datagram");
        // Echo it back verbatim.
        peer.write_all(&echoed).await.expect("echo");
        let (got_dest, payload) = reader.recv().await.expect("recv").expect("one datagram");
        assert_eq!(got_dest, Some(dest));
        assert_eq!(payload, b"ping");
    }

    #[tokio::test]
    async fn recv_reports_a_clean_eof() {
        let (client, peer) = tokio::io::duplex(64);
        let session = TargetAddr::new(Host::Ip("127.0.0.1".parse().expect("ip")), 9);
        let conn = UdpConn::new(Box::new(client), &session)
            .await
            .expect("request writes");
        drop(peer);
        let mut conn = conn;
        assert!(conn.recv().await.expect("eof").is_none());
    }
}
