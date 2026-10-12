//! VLESS UDP packet framing codec (spec §4.2).
//!
//! After the request header the tunnel stream carries length-prefixed
//! packets in both directions: `[2 bytes big-endian length][payload]`.
//! The framing mirrors xray's `LengthPacketReader`/`LengthPacketWriter`
//! semantics: empty (len 0) frames are skipped, a clean EOF at a frame
//! boundary is `Ok(None)`, and a truncated frame (partial length or short
//! payload) is an `UnexpectedEof` error (spec §5.1/§6).

use std::future::poll_fn;
use std::io;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::Poll;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// Resumable `[2B BE len][payload]` frame-read state.
///
/// The framing progress — the partially filled length prefix and the
/// partially filled payload — lives HERE instead of in a future's locals,
/// so a read future dropped mid-frame (a cancelled `select!` branch, a
/// timeout) loses nothing: the next call resumes the same frame at the
/// exact byte it stopped on. `tokio`'s `read` is itself cancel-safe (a
/// cancelled read consumed nothing), so a `FrameReader` outliving the
/// future makes datagram reads cancel-safe end to end — the property the
/// split [`super::packet::PacketReader`] rests on.
pub struct FrameReader {
    /// The 2-byte big-endian length prefix, filled across reads.
    len: [u8; 2],
    /// Length-prefix bytes already read; 2 once the length is complete.
    len_filled: usize,
    /// The current frame's payload staging: a per-connection `BytesMut`
    /// scratch buffer, `resize`d (never a fresh `vec!`) to the length prefix
    /// once that is known. Empty between frames.
    payload: BytesMut,
    /// Payload bytes already read.
    payload_filled: usize,
}

impl FrameReader {
    #[must_use]
    pub fn new() -> Self {
        Self {
            len: [0; 2],
            len_filled: 0,
            payload: BytesMut::new(),
            payload_filled: 0,
        }
    }

    /// Reads one `[2B BE len][payload]` frame, resuming the frame a
    /// previous (dropped) call left half-read.
    ///
    /// Returns `Ok(None)` on a clean EOF at a frame boundary (zero bytes
    /// read for the length). Empty frames (len 0) are skipped. A truncated
    /// frame — a partial length byte or a short payload at EOF — is
    /// `UnexpectedEof`.
    pub async fn read_frame<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> io::Result<Option<Bytes>> {
        loop {
            // Read the length byte-by-byte so a clean EOF (0 bytes) is
            // distinguishable from a truncated length (1 byte then EOF).
            while self.len_filled < self.len.len() {
                match r.read(&mut self.len[self.len_filled..]).await {
                    Ok(0) if self.len_filled == 0 => return Ok(None),
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vless udp frame truncated (partial length)",
                        ));
                    }
                    Ok(n) => self.len_filled += n,
                    Err(e) => return Err(e),
                }
            }
            let n = usize::from(u16::from_be_bytes(self.len));
            if n == 0 {
                self.len_filled = 0;
                continue; // skip empty frames
            }
            // Reuse the scratch across frames: grow once, never a fresh
            // `vec!` per datagram. `resize` keeps the existing allocation.
            if self.payload.len() != n {
                self.payload.resize(n, 0);
            }
            while self.payload_filled < n {
                let got = r.read(&mut self.payload[self.payload_filled..]).await?;
                if got == 0 {
                    // Byte-identical to the `read_exact` this loop replaced
                    // (kind AND text): a short payload at EOF is a
                    // truncated frame, not a clean close.
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "early eof"));
                }
                self.payload_filled += got;
            }
            self.len_filled = 0;
            self.payload_filled = 0;
            return Ok(Some(self.payload.split_to(n).freeze()));
        }
    }
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads one `[2B BE len][payload]` frame in one shot.
///
/// The FAKE-PEER side of the tests: a server double reads a whole frame off
/// a duplex and is never cancelled, so it needs no framing state. The
/// client reads through [`FrameReader`] instead — this one-shot form is NOT
/// cancel-safe (a dropped future loses the bytes it consumed).
///
/// Returns `Ok(None)` on a clean EOF at a frame boundary (zero bytes read
/// for the length). Empty frames (len 0) are skipped. A truncated frame —
/// a partial length byte or a short payload at EOF — is `UnexpectedEof`.
#[cfg(test)]
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Bytes>> {
    FrameReader::new().read_frame(r).await
}

pub async fn write_packet<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    let n = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "vless udp datagram exceeds the 2-byte frame length (65535)",
        )
    })?;
    // No frame `Vec`: the stack length prefix and the payload go out as one
    // vectored write.
    let prefix = n.to_be_bytes();
    write_all_vectored(w, &[&prefix, payload]).await
}

/// Write all of `bufs` out as vectored writes — no combined frame `Vec`.
/// Shared by [`write_packet`] (prefix + payload) and the packetaddr sender
/// (prefix + address header + payload).
pub async fn write_all_vectored<W: AsyncWrite + Unpin>(
    w: &mut W,
    bufs: &[&[u8]],
) -> io::Result<()> {
    let mut offs = [0usize; 4];
    debug_assert!(bufs.len() <= offs.len(), "vectored write takes <= 4 parts");
    let total: usize = bufs.iter().map(|b| b.len()).sum();
    let mut done = 0usize;
    poll_fn(|cx| {
        let slices = [
            IoSlice::new(&bufs[0][offs[0].min(bufs[0].len())..]),
            IoSlice::new(bufs.get(1).map_or(&[][..], |b| &b[offs[1].min(b.len())..])),
            IoSlice::new(bufs.get(2).map_or(&[][..], |b| &b[offs[2].min(b.len())..])),
            IoSlice::new(bufs.get(3).map_or(&[][..], |b| &b[offs[3].min(b.len())..])),
        ];
        let n = match Pin::new(&mut *w).poll_write_vectored(cx, &slices[..bufs.len()]) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        if n == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "vless udp frame write returned 0",
            )));
        }
        let mut left = n;
        for (i, b) in bufs.iter().enumerate() {
            let rem = b.len() - offs[i].min(b.len());
            let take = left.min(rem);
            offs[i] += take;
            left -= take;
        }
        done += n;
        if done >= total {
            Poll::Ready(Ok(()))
        } else {
            // Partial vectored write: re-poll for the remainder.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use leas_proto::proto_spec::{ProtocolConfig, VlessConfig};

    use super::*;
    use crate::addr::{ADDR_TYPE_DOMAIN, ADDR_TYPE_IPV4, Host, TargetAddr};
    use crate::context::{LinkContext, NativeConnectParams};
    use crate::protocol::vless::{PacketMode, connect_udp, header, packetaddr};
    use crate::security;
    use crate::security::fingerprint;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_packet(&mut a, b"hello").await.unwrap();
        drop(a);
        assert_eq!(
            read_packet(&mut b).await.unwrap().unwrap(),
            Bytes::from_static(b"hello")
        );
    }

    #[tokio::test]
    async fn exact_wire_bytes() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_packet(&mut a, b"hi").await.unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(raw, [0x00, 0x02, b'h', b'i']);
    }

    #[tokio::test]
    async fn oversized_datagram_is_invalid_input() {
        // A payload that cannot fit the 2-byte length is a client error,
        // never a panic (spec §6) — even though `PacketConn::send` rejects
        // it first, the primitive must not crash. Nothing is written on
        // the error path.
        let (mut a, mut b) = tokio::io::duplex(1024);
        let big = vec![0xAB; 65_536];
        let err = write_packet(&mut a, &big).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(raw.len(), 0);
    }

    #[tokio::test]
    async fn split_frame_reads() {
        // One frame split across two writes: the length + first payload
        // byte, then the remainder; read_packet must reassemble across
        // partial reads.
        let (mut a, mut b) = tokio::io::duplex(4);
        a.write_all(&[0x00, 0x04, 0xAA]).await.unwrap();
        let reader = tokio::spawn(async move { read_packet(&mut b).await.unwrap().unwrap() });
        tokio::task::yield_now().await;
        a.write_all(&[0xBB, 0xCC, 0xDD]).await.unwrap();
        drop(a);
        assert_eq!(
            reader.await.unwrap(),
            Bytes::from_static(&[0xAA, 0xBB, 0xCC, 0xDD])
        );
    }

    #[tokio::test]
    async fn eof_at_boundary_is_none() {
        // Peer closes cleanly (no partial frame): clean end of the tunnel.
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(read_packet(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn empty_frame_skipped() {
        // A len=0 frame is skipped; the next frame's payload is returned.
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0x00, 0x00, 0x00, 0x02, b'h', b'i'])
            .await
            .unwrap();
        drop(a);
        assert_eq!(
            read_packet(&mut b).await.unwrap().unwrap(),
            Bytes::from_static(b"hi")
        );
    }

    #[tokio::test]
    async fn truncated_frame_is_error() {
        // Full length but a short payload at EOF: truncated frame.
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0x00, 0x05, b'a']).await.unwrap();
        drop(a);
        let err = read_packet(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn partial_length_then_eof_is_error() {
        // One length byte then EOF is a truncated frame, not a clean close
        // (spec §6): only a boundary-aligned EOF yields Ok(None).
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0x00]).await.unwrap();
        drop(a);
        let err = read_packet(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    // ---- Hermetic: fake UDP server over a real outer TLS session ----
    //
    // The raw-TCP fake server pattern from the vision-plan hermetic tests
    // (fake server = the rustls server double + raw socket): one
    // `TcpListener`, the outer TLS handshake as a rustls `ServerConnection`,
    // then the VLESS UDP wire spoken exactly — read + assert the request
    // header (cmd 0x02, port-first dest), send the `[0,0]` response header,
    // exchange `[2B len][payload]` frames both directions. The CLIENT drives
    // the real path: `security::wrap` (engine TLS 1.3) +
    // `protocol::vless::connect_udp` + `PacketConn::send`/`recv`. This is
    // the frame-level gate (brief steps 1-5) before the real-core e2e rows.

    /// A VLESS config for the UDP path: no flow, plain TLS to the fake
    /// server. The UDP mode (`Raw` / `PacketAddr`) lives in the context, not
    /// the config (the proto has no `packet_encoding` field yet).
    fn vless_udp_config() -> VlessConfig {
        let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00010203-0405-0607-0809-0a0b0c0d0e0f",
            "transport": { "type": "tcp" },
            "security": { "type": "tls", "sni": "localhost" }
        }))
        .expect("vless udp config parses");
        match protocol {
            ProtocolConfig::Vless(cfg) => cfg,
            _ => panic!("expected a vless config"),
        }
    }

    /// rcgen CA + server cert/key PEM + CA DER (the security-phase fixture).
    fn rcgen_ca_and_server(sni: &str) -> (String, String, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let mut ca_params = CertificateParams::new(vec![sni.to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_params =
            CertificateParams::new(vec![sni.to_string(), "127.0.0.1".to_string()]).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::new(ca_params, &ca_key);
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        (
            server_cert.pem(),
            server_key.serialize_pem(),
            ca_cert.der().to_vec(),
        )
    }

    fn server_config(cert_pem: &str, key_pem: &str) -> rustls::ServerConfig {
        use rustls::pki_types::pem::PemObject;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .map(|c| c.expect("cert pem parses"))
                .collect();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .expect("key pem parses");
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config builds")
    }

    /// Read exactly `out.len()` decrypted bytes, pulling new outer-TLS
    /// records from the socket whenever the rustls plaintext buffer is
    /// empty (rustls 0.23 `Reader::read` signals that with `WouldBlock`).
    fn read_exact_decrypted(
        conn: &mut rustls::ServerConnection,
        sock: &mut std::net::TcpStream,
        out: &mut [u8],
    ) -> std::io::Result<()> {
        let mut filled = 0;
        while filled < out.len() {
            match conn.reader().read(&mut out[filled..]) {
                Ok(n) if n > 0 => {
                    filled += n;
                    continue;
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            // No plaintext buffered. `complete_io` may have pulled the
            // peer's first application-data records into rustls's read
            // buffer together with the final handshake flight — process
            // whatever is buffered before blocking on the socket.
            let state = conn
                .process_new_packets()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            if state.plaintext_bytes_to_read() > 0 {
                continue;
            }
            if conn.read_tls(sock)? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "fake udp server: outer TLS peer closed",
                ));
            }
            conn.process_new_packets()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
        Ok(())
    }

    /// Write `data` as decrypted bytes (buffered into the record layer,
    /// then flushed until nothing is left to send).
    fn write_all_encrypted(
        conn: &mut rustls::ServerConnection,
        sock: &mut std::net::TcpStream,
        data: &[u8],
    ) -> std::io::Result<()> {
        conn.writer().write_all(data)?;
        loop {
            if conn.write_tls(sock)? == 0 {
                return Ok(());
            }
        }
    }

    /// Read the VLESS request header prefix: version, uuid, `addons_len` (0 —
    /// the UDP path carries no flow), and the command byte. The destination
    /// is left to the caller (raw: the UDP target; packetaddr: the magic
    /// fqdn, spec §4.1/§4.3).
    fn read_header_prefix(
        conn: &mut rustls::ServerConnection,
        sock: &mut std::net::TcpStream,
        uuid: &[u8; 16],
    ) -> std::io::Result<()> {
        let mut head = [0u8; 19];
        read_exact_decrypted(conn, sock, &mut head)?;
        assert_eq!(head[0], header::VERSION, "vless version byte");
        assert_eq!(&head[1..17], uuid, "vless user uuid");
        assert_eq!(head[17], 0, "addons_len (no flow on the UDP path)");
        assert_eq!(head[18], header::CMD_UDP, "vless command must be UDP 0x02");
        Ok(())
    }

    /// Read one `[2B BE len][payload]` frame raw from the decrypted stream
    /// — the server speaks the wire directly, independently of the codec
    /// under test.
    fn read_raw_frame(
        conn: &mut rustls::ServerConnection,
        sock: &mut std::net::TcpStream,
    ) -> std::io::Result<Vec<u8>> {
        let mut len = [0u8; 2];
        read_exact_decrypted(conn, sock, &mut len)?;
        let n = usize::from(u16::from_be_bytes(len));
        let mut payload = vec![0u8; n];
        read_exact_decrypted(conn, sock, &mut payload)?;
        Ok(payload)
    }

    /// Write one `[2B BE len][payload]` frame to the decrypted stream.
    fn write_raw_frame(
        conn: &mut rustls::ServerConnection,
        sock: &mut std::net::TcpStream,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let n = u16::try_from(payload.len()).expect("frame payload fits u16");
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&n.to_be_bytes());
        frame.extend_from_slice(payload);
        write_all_encrypted(conn, sock, &frame)
    }

    /// Spawn the fake UDP server: accept one connection, complete the outer
    /// TLS handshake as the rustls server double, run the wire `script`.
    /// Returns the listener address + the join handle (server-side
    /// assertion failures surface as panics through it).
    fn spawn_udp_server(
        cert_pem: &str,
        key_pem: &str,
        script: impl FnOnce(
            &mut rustls::ServerConnection,
            &mut std::net::TcpStream,
        ) -> std::io::Result<()>
        + Send
        + 'static,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let cfg = server_config(cert_pem, key_pem);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let timeout = Duration::from_secs(15);
            sock.set_read_timeout(Some(timeout)).expect("read timeout");
            sock.set_write_timeout(Some(timeout))
                .expect("write timeout");
            let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).expect("server conn");
            while conn.is_handshaking() {
                conn.complete_io(&mut sock).expect("outer TLS handshake");
            }
            script(&mut conn, &mut sock).expect("fake udp server wire script");
        });
        (addr, handle)
    }

    /// A `LinkContext` pointing the client at the fake server, with the UDP
    /// packet mode set and a known target (asserted on the server side).
    fn udp_ctx(
        addr: SocketAddr,
        cfg: VlessConfig,
        mode: PacketMode,
        target: TargetAddr,
    ) -> LinkContext {
        let mut params = NativeConnectParams::new(
            ProtocolConfig::Vless(cfg),
            EndpointEssentials::new("127.0.0.1", 1),
            target.clone(),
        );
        params.server = EndpointEssentials::new(addr.ip().to_string(), addr.port());
        params.udp = Some(mode);
        LinkContext::new(params, target)
    }

    /// The hermetic frame-level gate (brief steps 1-5), raw mode: the real
    /// client path — engine TLS wrap + vless `connect_udp` + `PacketConn` —
    /// against the fake server. Asserts the header's cmd 0x02 + port-first
    /// dest, the `[0,0]` response, and the `[2B len][payload]` frames in
    /// both directions.
    #[tokio::test]
    async fn hermetic_fake_udp_server_frames() {
        // Feature unification enables both rustls backends; the app installs
        // the ring provider at startup (workspace convention), tests do it
        // here (idempotent).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem, ca_der) = rcgen_ca_and_server("localhost");
        // The engine verifies through its thread-local harness CA.
        fingerprint::set_test_ca(&ca_der);
        let uuid = header::uuid_bytes("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap();
        let target = TargetAddr::new(Host::new("1.2.3.4"), 8080);
        let (addr, server) = spawn_udp_server(&cert_pem, &key_pem, move |conn, sock| {
            // Step 1: the request header — cmd 0x02, port-first dest.
            read_header_prefix(conn, sock, &uuid)?;
            let mut port = [0u8; 2];
            read_exact_decrypted(conn, sock, &mut port)?;
            assert_eq!(u16::from_be_bytes(port), 8080, "target port first");
            let mut atyp = [0u8; 1];
            read_exact_decrypted(conn, sock, &mut atyp)?;
            assert_eq!(atyp[0], ADDR_TYPE_IPV4, "target address type");
            let mut got_addr = [0u8; 4];
            read_exact_decrypted(conn, sock, &mut got_addr)?;
            assert_eq!(&got_addr, &[1, 2, 3, 4], "target address");

            // Step 2: the `[0,0]` response header.
            write_all_encrypted(conn, sock, &[header::VERSION, 0x00])?;

            // Step 3: one client frame `[2B len][payload]`.
            let frame = read_raw_frame(conn, sock)?;
            assert_eq!(frame, b"hello", "client datagram payload");

            // Step 4: one frame back; the client's recv must deliver it.
            write_raw_frame(conn, sock, b"world")?;
            Ok(())
        });
        let cfg = vless_udp_config();
        let ctx = udp_ctx(addr, cfg.clone(), PacketMode::Raw, target);

        let (dest, payload) = tokio::time::timeout(Duration::from_secs(30), async {
            let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
            let wrapped = security::wrap(&ctx, Box::new(sock)).await.unwrap();
            let mut conn = connect_udp(&ctx, wrapped, &cfg).await.unwrap();
            conn.send(None, b"hello").await.unwrap();
            conn.recv().await.unwrap().unwrap()
        })
        .await
        .expect("hermetic udp flow timed out");
        assert_eq!(dest, None, "raw mode: no per-packet destination");
        assert_eq!(&payload[..], b"world", "client delivers the server frame");
        server.await.expect("fake udp server task failed");
    }

    /// The packetaddr-mode variant (brief step 5, spec §4.3): the header
    /// destination is the magic fqdn with port 0, and each datagram frame
    /// carries the per-packet address header (`atyp | addr | port`, NO
    /// magic prefix — sing-vmess serializer semantics, corrected in the
    /// Task 5 report) — asserted in the client's frame on the server side;
    /// the server's reply frame decodes back to a per-packet destination on
    /// the client side.
    #[tokio::test]
    async fn hermetic_fake_udp_server_packetaddr_frames() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem, ca_der) = rcgen_ca_and_server("localhost");
        fingerprint::set_test_ca(&ca_der);
        let uuid = header::uuid_bytes("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap();
        let target = TargetAddr::new(Host::new("1.2.3.4"), 8080);
        let (addr, server) = spawn_udp_server(&cert_pem, &key_pem, move |conn, sock| {
            // The header dest is the magic fqdn with port 0 — the UDP target
            // stays out of the header (spec §4.3).
            read_header_prefix(conn, sock, &uuid)?;
            let mut port = [0u8; 2];
            read_exact_decrypted(conn, sock, &mut port)?;
            assert_eq!(u16::from_be_bytes(port), 0, "packetaddr header port 0");
            let mut atyp = [0u8; 1];
            read_exact_decrypted(conn, sock, &mut atyp)?;
            assert_eq!(atyp[0], ADDR_TYPE_DOMAIN, "magic fqdn address type");
            let mut alen = [0u8; 1];
            read_exact_decrypted(conn, sock, &mut alen)?;
            assert_eq!(
                usize::from(alen[0]),
                packetaddr::MAGIC.len(),
                "magic fqdn length"
            );
            let mut magic = vec![0u8; packetaddr::MAGIC.len()];
            read_exact_decrypted(conn, sock, &mut magic)?;
            assert_eq!(&magic, packetaddr::MAGIC.as_bytes(), "magic fqdn bytes");

            // The `[0,0]` response header.
            write_all_encrypted(conn, sock, &[header::VERSION, 0x00])?;

            // The client's datagram frame carries the per-packet address
            // header: `atyp 0x01 | 1.2.3.4 | port 8080 | 'p'` (the magic
            // fqdn is the header destination only — sing serializer).
            let frame = read_raw_frame(conn, sock)?;
            let mut expected = packetaddr::encode_dest("1.2.3.4:8080".parse().unwrap());
            expected.push(b'p');
            assert_eq!(frame, expected, "packetaddr per-packet address frame");

            // One frame back with its own per-packet destination; the
            // client's recv must decode it.
            let reply_dest = "[::1]:53".parse().unwrap();
            let mut reply = packetaddr::encode_dest(reply_dest);
            reply.extend_from_slice(b"ok");
            write_raw_frame(conn, sock, &reply)?;
            Ok(())
        });
        let cfg = vless_udp_config();
        let ctx = udp_ctx(addr, cfg.clone(), PacketMode::PacketAddr, target);

        let (dest, payload) = tokio::time::timeout(Duration::from_secs(30), async {
            let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
            let wrapped = security::wrap(&ctx, Box::new(sock)).await.unwrap();
            let mut conn = connect_udp(&ctx, wrapped, &cfg).await.unwrap();
            conn.send(Some("1.2.3.4:8080".parse().unwrap()), b"p")
                .await
                .unwrap();
            conn.recv().await.unwrap().unwrap()
        })
        .await
        .expect("hermetic packetaddr flow timed out");
        assert_eq!(
            dest,
            Some("[::1]:53".parse().unwrap()),
            "per-packet dest decoded"
        );
        assert_eq!(&payload[..], b"ok", "client delivers the packetaddr frame");
        server.await.expect("fake udp server task failed");
    }
}
