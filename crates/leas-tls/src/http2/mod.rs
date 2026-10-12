//! Minimal HTTP/2 implementation for the tls.peet.ws grader.
//!
//! Port of `thirdparty/tls-fingerprint/src/http2.rs`, adapted from the
//! reference's `TlsConnection` (TcpStream-bound, custom read helpers) to
//! this crate's [`TlsStream`] (a generic `AsyncRead + AsyncWrite` record
//! stream): `read_exact`/`write_all` come from the tokio IO traits instead
//! of hand-rolled buffer helpers.
//!
//! Scope: several GET requests on one connection (stream ids 1, 3, 5, …),
//! h2 ALPN negotiated.
//! Implements: client preface, SETTINGS exchange, HPACK-encoded HEADERS,
//! DATA frame accumulation, PING/GOAWAY handling.
//! Deliberately excludes: dynamic HPACK table, `PUSH_PROMISE`, flow-control
//! `WINDOW_UPDATE` (default 64 KiB window is enough for the JSON response).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Result, TlsError};
use crate::record::stream::TlsStream;

// ── Frame type constants ────────────────────────────────────────────────────
pub const FRAME_DATA: u8 = 0x00;
pub const FRAME_HEADERS: u8 = 0x01;
pub const FRAME_PRIORITY: u8 = 0x02;
pub const FRAME_RST_STREAM: u8 = 0x03;
pub const FRAME_SETTINGS: u8 = 0x04;
pub const FRAME_PUSH_PROMISE: u8 = 0x05;
pub const FRAME_PING: u8 = 0x06;
pub const FRAME_GOAWAY: u8 = 0x07;
pub const FRAME_WINDOW_UPDATE: u8 = 0x08;
pub const FRAME_CONTINUATION: u8 = 0x09;

// ── Flag constants ──────────────────────────────────────────────────────────
pub const FLAG_END_STREAM: u8 = 0x01;
pub const FLAG_END_HEADERS: u8 = 0x04;
pub const FLAG_ACK: u8 = 0x01;

// ── HTTP/2 client connection preface (RFC 7540 §3.5) ───────────────────────
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Default maximum frame payload size (RFC 7540 §6.5.2). Frames larger than
/// this must be rejected with a `FRAME_SIZE_ERROR`; we treat them as a
/// protocol error (also bounds the per-frame allocation).
const MAX_FRAME_SIZE: usize = 16_384;

/// Cap on waiting for the response frames, so a stalling server fails the
/// tier-2 gate instead of hanging forever.
const RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

// ── Frame builder ───────────────────────────────────────────────────────────

/// Serialize an HTTP/2 frame (9-byte header + payload, RFC 7540 §4.1).
#[must_use]
pub fn make_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut f = Vec::with_capacity(9 + len);
    // 24-bit payload length; our frames are small, so a panic here is a
    // programming error, not a runtime condition.
    let len32 = u32::try_from(len).expect("HTTP/2 frame length fits u32");
    let [_, b0, b1, b2] = len32.to_be_bytes();
    f.push(b0);
    f.push(b1);
    f.push(b2);
    f.push(frame_type);
    f.push(flags);
    f.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

// ── Minimal HPACK encoder ───────────────────────────────────────────────────
//
// Uses only:
//   - Indexed header field representation  (RFC 7541 §6.1) for static table entries
//   - Literal without indexing + indexed name (RFC 7541 §6.2.2) for custom values
//   - Literal without indexing + new name   (RFC 7541 §6.2.2) for custom name+value
//
// HPACK static table (subset we use):
//   1 = :authority
//   2 = :method  GET
//   4 = :path    /
//   7 = :scheme  https

/// Appends a raw (non-Huffman) HPACK string. The length uses the RFC 7541
/// §5.2 variable-length integer (7-bit prefix): values < 127 fit the prefix
/// byte (H=0); longer values escape with `0x7F` followed by base-128
/// continuation octets (0x80 continuation bit set on every octet but the
/// last). The spider's padding cookie (`padding=0…0`, up to 520 bytes)
/// requires the long form — a single-byte prefix would panic on any value
/// >= 127.
fn hpack_string(buf: &mut Vec<u8>, s: &[u8]) {
    let len = s.len();
    if len < 127 {
        buf.push(u8::try_from(len).expect("len < 127 per the check above"));
    } else {
        buf.push(0x7F); // 2^7 - 1 escape: the length continues in the payload
        let mut rest = len - 127;
        while rest >= 128 {
            buf.push(u8::try_from((rest % 128) + 128).expect("continuation octet < 256"));
            rest /= 128;
        }
        buf.push(u8::try_from(rest).expect("final octet < 128"));
    }
    buf.extend_from_slice(s);
}

/// Encode the request headers for a plain `GET <path>` on `host`.
#[must_use]
pub fn encode_get_headers(path: &str, host: &str) -> Vec<u8> {
    let mut h = Vec::new();

    // :method: GET  →  indexed, static[2]  →  0x82
    h.push(0x82);

    // :scheme: https  →  indexed, static[7]  →  0x87
    h.push(0x87);

    // :path: <path>  →  literal without indexing, name = static[4] (:path)
    //   prefix byte: 0000_nnnn  where nnnn=4
    h.push(0x04);
    hpack_string(&mut h, path.as_bytes());

    // :authority: <host>  →  literal without indexing, name = static[1] (:authority)
    h.push(0x01);
    hpack_string(&mut h, host.as_bytes());

    // accept: application/json  →  literal without indexing, new name
    h.push(0x00);
    hpack_string(&mut h, b"accept");
    hpack_string(&mut h, b"application/json");

    h
}

/// Read one complete HTTP/2 frame.
/// Returns `(frame_type, flags, stream_id, payload)`.
///
/// Uses `read_exact` on the decrypted stream; a clean EOF (or truncated
/// frame) surfaces as an `UnexpectedEof` `io::Error` and propagates as
/// [`TlsError::Io`].
pub async fn read_frame<S>(conn: &mut TlsStream<S>) -> Result<(u8, u8, u32, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut hdr = [0u8; 9];
    conn.read_exact(&mut hdr).await?;
    let len = (usize::from(hdr[0]) << 16) | (usize::from(hdr[1]) << 8) | usize::from(hdr[2]);
    if len > MAX_FRAME_SIZE {
        return Err(TlsError::Protocol(format!(
            "HTTP/2 frame length {len} exceeds default max frame size {MAX_FRAME_SIZE}"
        )));
    }
    let frame_type = hdr[3];
    let flags = hdr[4];
    let stream_id = u32::from_be_bytes([hdr[5] & 0x7F, hdr[6], hdr[7], hdr[8]]);
    let mut payload = vec![0u8; len];
    conn.read_exact(&mut payload).await?;
    Ok((frame_type, flags, stream_id, payload))
}

// ── High-level GET ──────────────────────────────────────────────────────────

/// A minimal HTTP/2 client capable of several GETs on one connection.
///
/// The connection preface + SETTINGS exchange run once (first `get`);
/// subsequent GETs reuse the connection on stream ids 1, 3, 5, … (RFC 7540
/// §5.1.1 — client-initiated streams are odd and monotonically increasing).
pub struct Client {
    next_stream: u32,
}

impl Client {
    #[must_use]
    pub const fn new() -> Self {
        Self { next_stream: 1 }
    }

    /// Send a GET request and return the response body as a String.
    ///
    /// Flow (RFC 7540):
    ///   1. First request only: client preface + empty SETTINGS; later
    ///      GETs reuse the connection.
    ///   2. HEADERS frame on the next odd stream id (`END_STREAM` |
    ///      `END_HEADERS`); extra headers append after the static-table
    ///      pseudo-headers.
    ///   3. Process incoming frames:
    ///      - SETTINGS (not ACK) → send SETTINGS ACK
    ///      - PING (not ACK)     → send PING ACK
    ///      - DATA on the stream → accumulate body; stop on `END_STREAM`
    ///      - HEADERS on the stream → check `END_STREAM` (no body)
    ///      - GOAWAY             → error
    ///      - everything else    → ignore
    pub async fn get<S: AsyncRead + AsyncWrite + Unpin + Send>(
        &mut self,
        conn: &mut TlsStream<S>,
        path: &str,
        host: &str,
        extra_headers: &[(&str, &str)],
    ) -> Result<String> {
        if self.next_stream == 1 {
            // First request: client preface + empty SETTINGS (RFC 7540 §3.5).
            conn.write_all(PREFACE).await?;
            conn.write_all(&make_frame(FRAME_SETTINGS, 0, 0, &[]))
                .await?;
        }
        let mut hpack = encode_get_headers(path, host);
        for (name, value) in extra_headers {
            encode_literal_header(&mut hpack, name, value.as_bytes());
        }
        let stream_id = self.next_stream;
        self.next_stream += 2;
        conn.write_all(&make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            stream_id,
            &hpack,
        ))
        .await?;

        // Receive frames until END_STREAM on this stream, bounded so a
        // stalling server fails the gate instead of hanging forever.
        let body = tokio::time::timeout(RESPONSE_TIMEOUT, receive_response(conn, stream_id))
            .await
            .map_err(|_| TlsError::Protocol("HTTP/2 response timed out".to_string()))??;

        String::from_utf8(body)
            .map_err(|e| TlsError::Protocol(format!("HTTP/2 response body not UTF-8: {e}")))
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes a literal header field *without indexing, new name* (RFC 7541
/// §6.2.2): `0x00` prefix, then name and value as raw length-prefixed
/// strings. Used for `cookie` and `referer` in the spider's extra headers.
fn encode_literal_header(buf: &mut Vec<u8>, name: &str, value: &[u8]) {
    buf.push(0x00);
    hpack_string(buf, name.as_bytes());
    hpack_string(buf, value);
}

/// Perform an HTTP/2 GET request on a fresh connection and return the
/// response body as a String.
///
/// Convenience wrapper around [`Client::get`] with no extra headers, kept
/// for the tls.peet.ws grader (preface + stream 1 per call).
pub async fn get<S>(conn: &mut TlsStream<S>, path: &str, host: &str) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    Client::new().get(conn, path, host, &[]).await
}

/// Reads frames until `END_STREAM` on `stream_id`, acknowledging the
/// server's `SETTINGS` and PINGs, and returns the accumulated response body.
async fn receive_response<S>(conn: &mut TlsStream<S>, stream_id: u32) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut body: Vec<u8> = Vec::new();
    loop {
        let (ftype, flags, frame_stream, payload) = read_frame(conn).await?;

        match ftype {
            FRAME_SETTINGS => {
                // The server's SETTINGS must be ACKed (RFC 7540 §6.5.3);
                // an ACK of our own SETTINGS needs no reply.
                if flags & FLAG_ACK == 0 {
                    conn.write_all(&make_frame(FRAME_SETTINGS, FLAG_ACK, 0, &[]))
                        .await?;
                }
            }
            FRAME_PING if flags & FLAG_ACK == 0 => {
                // Ping must be ACKed with identical payload (RFC 7540 §6.7)
                conn.write_all(&make_frame(FRAME_PING, FLAG_ACK, 0, &payload))
                    .await?;
            }
            FRAME_DATA if frame_stream == stream_id => {
                // Handle optional PADDED flag (RFC 7540 §6.1): the pad
                // length byte must not exceed the payload.
                let data = if flags & 0x08 != 0 {
                    let Some((&pad_len, rest)) = payload.split_first() else {
                        return Err(TlsError::Protocol(
                            "HTTP/2 PADDED DATA frame missing pad length".into(),
                        ));
                    };
                    let pad_len = usize::from(pad_len);
                    let Some(end) = rest.len().checked_sub(pad_len) else {
                        return Err(TlsError::Protocol(format!(
                            "HTTP/2 PADDED DATA pad length {pad_len} exceeds payload length {}",
                            rest.len()
                        )));
                    };
                    &rest[..end]
                } else {
                    &payload[..]
                };
                body.extend_from_slice(data);
                if flags & FLAG_END_STREAM != 0 {
                    break;
                }
            }
            FRAME_HEADERS if frame_stream == stream_id => {
                // Response headers (we don't need to parse them)
                if flags & FLAG_END_STREAM != 0 {
                    break; // response has no body (e.g. 204 No Content)
                }
            }
            FRAME_RST_STREAM if frame_stream == stream_id => {
                let code = u32::from_be_bytes(payload.try_into().unwrap_or([0; 4]));
                return Err(TlsError::Protocol(format!(
                    "HTTP/2 RST_STREAM error_code={code}"
                )));
            }
            FRAME_GOAWAY => {
                let code = if payload.len() >= 8 {
                    u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]])
                } else {
                    0
                };
                return Err(TlsError::Protocol(format!(
                    "HTTP/2 GOAWAY error_code={code}"
                )));
            }
            _ => {
                // WINDOW_UPDATE, PRIORITY, CONTINUATION, unknown — ignore
            }
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{
        Client, FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM, FRAME_HEADERS, FRAME_SETTINGS,
        PREFACE, hpack_string, make_frame,
    };
    use crate::handshake::{AcceptAll, HandshakeParams, connect};
    use crate::spec::{ClientHelloSpec, ExtensionSpec, KeyShareGroup, SessionIdSpec};
    use parking_lot::Mutex;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    /// A Chrome-flavoured spec with only TLS 1.3 suites/groups/versions,
    /// the minimal surface a rustls server needs to complete a 1-RTT
    /// handshake (identical to the handshake interop test's helper).
    fn test_spec() -> ClientHelloSpec {
        ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302, 0x1303],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![
                ExtensionSpec::ServerName,
                ExtensionSpec::SupportedGroups(vec![0x001D]),
                ExtensionSpec::KeyShare(vec![KeyShareGroup::X25519]),
                ExtensionSpec::SupportedVersions(vec![0x0304, 0x0303]),
                ExtensionSpec::SignatureAlgorithms(vec![
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                ]),
                ExtensionSpec::Alpn(vec!["h2".into(), "http/1.1".into()]),
                ExtensionSpec::EcPointFormats,
                ExtensionSpec::SessionTicket,
                ExtensionSpec::PskKeyExchangeModes,
            ],
        }
    }

    fn server_config(cert: &rcgen::Certificate, key: &rcgen::KeyPair) -> rustls::ServerConfig {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        // Workspace feature unification compiles rustls with BOTH backends
        // (ring via our crates, aws-lc-rs via other workspace members), so
        // rustls cannot auto-select a provider here — install ring
        // explicitly. Idempotent: a concurrent/earlier install returns
        // `Err`, ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap()
    }

    /// Spawns a recording rustls TLS server on a blocking thread.
    ///
    /// After the handshake it sends its own empty SETTINGS, then loops
    /// reading TLS records and appends the decrypted HTTP/2 plaintext
    /// (preface + frames) to `recorded` — bounded to the first 512 bytes,
    /// then keeps draining reads so the client's writes never wedge on TCP
    /// backpressure. Every `END_STREAM` HEADERS is answered with an empty
    /// HEADERS + `END_STREAM` on the same stream (a 204-style reply) so
    /// the client's GETs complete promptly.
    fn spawn_recording_tls_server(recorded: Arc<Mutex<Vec<u8>>>) -> std::net::SocketAddr {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = server_config(&certified.cert, &certified.signing_key);

        tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let timeout = std::time::Duration::from_secs(15);
            sock.set_read_timeout(Some(timeout)).unwrap();
            sock.set_write_timeout(Some(timeout)).unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut sock).unwrap();
            }
            // Server connection preface: our own empty SETTINGS (RFC 7540 §3.5).
            conn.writer()
                .write_all(&make_frame(FRAME_SETTINGS, 0, 0, &[]))
                .unwrap();
            conn.write_tls(&mut sock).unwrap();

            // Decrypted HTTP/2 plaintext: 24-byte preface, then 9-byte
            // frame header + payload; `off` is the parse cursor.
            let mut plain = Vec::new();
            let mut off = 0usize;
            loop {
                if conn.read_tls(&mut sock).unwrap() == 0 {
                    break; // client closed the connection
                }
                let state = conn.process_new_packets().unwrap();
                if state.plaintext_bytes_to_read() > 0 {
                    let mut buf = vec![0u8; state.plaintext_bytes_to_read()];
                    // The buffer is exactly the available plaintext, so a
                    // blocking read_exact cannot stall.
                    conn.reader().read_exact(&mut buf).unwrap();
                    plain.extend_from_slice(&buf);
                }

                // Record everything new since the last parse pass, bounded.
                {
                    let mut rec = recorded.lock();
                    let take = (plain.len() - off).min(512usize.saturating_sub(rec.len()));
                    rec.extend_from_slice(&plain[off..off + take]);
                }

                // Skip the client preface (may span several reads).
                if off < PREFACE.len() {
                    if plain.len() < PREFACE.len() {
                        continue;
                    }
                    off = PREFACE.len();
                }

                // Parse complete frames and reply per RFC 7540.
                loop {
                    if plain.len() - off < 9 {
                        break; // incomplete frame header
                    }
                    let len = (usize::from(plain[off]) << 16)
                        | (usize::from(plain[off + 1]) << 8)
                        | usize::from(plain[off + 2]);
                    let frame_len = 9usize + len;
                    if plain.len() - off < frame_len {
                        break; // incomplete frame payload
                    }
                    let ftype = plain[off + 3];
                    let flags = plain[off + 4];
                    let stream_id = u32::from_be_bytes([
                        plain[off + 5] & 0x7F,
                        plain[off + 6],
                        plain[off + 7],
                        plain[off + 8],
                    ]);
                    off += frame_len;
                    match ftype {
                        FRAME_SETTINGS if flags & FLAG_ACK == 0 => {
                            conn.writer()
                                .write_all(&make_frame(FRAME_SETTINGS, FLAG_ACK, 0, &[]))
                                .unwrap();
                            conn.write_tls(&mut sock).unwrap();
                        }
                        FRAME_HEADERS if flags & FLAG_END_STREAM != 0 => {
                            conn.writer()
                                .write_all(&make_frame(
                                    FRAME_HEADERS,
                                    FLAG_END_STREAM | FLAG_END_HEADERS,
                                    stream_id,
                                    &[],
                                ))
                                .unwrap();
                            conn.write_tls(&mut sock).unwrap();
                        }
                        _ => {}
                    }
                }
            }
        });

        addr
    }

    #[test]
    fn hpack_string_long_values_use_rfc7541_variable_length_integer() {
        // Short values keep the single-prefix-byte form (H=0, len < 127).
        let mut buf = Vec::new();
        hpack_string(&mut buf, b"GET");
        assert_eq!(buf, b"\x03GET");

        // Boundary: 126 fits the 7-bit prefix; 127 must escape (0x7F 0x00).
        let mut buf = Vec::new();
        hpack_string(&mut buf, &[b'a'; 126]);
        assert_eq!(buf[0], 126);
        assert_eq!(&buf[1..], &[b'a'; 126]);

        let mut buf = Vec::new();
        hpack_string(&mut buf, &[b'b'; 127]);
        assert_eq!(&buf[..2], &[0x7F, 0x00]);
        assert_eq!(&buf[2..], &[b'b'; 127]);

        // The spider's padding cookie: `padding=` + 512 zeros = 520 bytes →
        // 0x7F escape, then 393 as base-128 continuation octets 0x89 0x03
        // (RFC 7541 §5.2: 127 + 9 + 3·128 = 520).
        let mut buf = Vec::new();
        hpack_string(&mut buf, &[b'0'; 520]);
        assert_eq!(&buf[..3], &[0x7F, 0x89, 0x03]);
        assert_eq!(&buf[3..], &[b'0'; 520]);
    }

    #[tokio::test]
    async fn client_reuses_connection_across_gets() {
        let recorded: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let addr = spawn_recording_tls_server(recorded.clone());

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let rng = ring::rand::SystemRandom::new();
        let mut conn = connect(
            stream,
            HandshakeParams {
                spec: &test_spec(),
                server_name: "localhost",
                alpn: None, // the spec already offers h2/http/1.1
                verifier: &AcceptAll,
                rng: &rng,
            },
        )
        .await
        .unwrap();

        let mut client = Client::new();
        client
            .get(&mut conn, "/a", "localhost", &[("cookie", "padding=0")])
            .await
            .expect("first GET must complete");
        client
            .get(&mut conn, "/b", "localhost", &[])
            .await
            .expect("second GET must complete");

        let bytes = recorded.lock().clone();
        let preface_count = bytes
            .windows(PREFACE.len())
            .filter(|w| *w == PREFACE)
            .count();
        assert_eq!(preface_count, 1, "preface must be sent exactly once");
        // Frame header layout (RFC 7540 §4.1): length(3), type(1) at
        // offset 3, flags(1), stream id(4) at offsets 5..9.
        let headers_on = |stream: u32| {
            bytes.windows(9).any(|w| {
                w[3] == FRAME_HEADERS && u32::from_be_bytes(w[5..9].try_into().unwrap()) == stream
            })
        };
        assert!(headers_on(1), "HEADERS frame on stream 1 expected");
        assert!(headers_on(3), "HEADERS frame on stream 3 expected");
    }
}
