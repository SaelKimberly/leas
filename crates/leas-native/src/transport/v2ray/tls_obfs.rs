//! `obfs=tls` framing: a **synthetic** TLS record stream.
//!
//! This is not a TLS session and must never become one: the server side is
//! `simple-obfs`, which parses these bytes and pipes the payload onward without
//! any handshake. The reference is
//! `thirdparty/sing-box/transport/simple-obfs/tls.go`:
//!
//! * **first write** — a TLS-1.0-framed record (`22 03 01 <len>`) whose body is
//!   a TLS-1.2-shaped `ClientHello` in which the **first extension is
//!   `session_ticket` carrying the payload** and `server_name` carries the obfs
//!   host (`tls.go:130-204`).
//! * **later writes** — `17 03 03 <len>` application-data records, chunked at
//!   16 KiB (`tls.go:19-21, 99-114`).
//! * **reads** — discard the first 105 bytes of the server's flight, then one
//!   record header per record (`tls.go:59-81`).
//!
//! Three things that are easy to get wrong, each pinned by a test below:
//! the length fields are **2 bytes**, so one record carries at most 65535 bytes;
//! the record type bytes are `0x16`/`0x17`, not the decimals 22/17 one might
//! type; and a read is bounded to its record (the reference discards a fixed 3
//! bytes per read, which silently eats payload when a read crosses a boundary —
//! here the remainder is buffered instead).

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxStream;
use crate::context::LinkContext;
use crate::rand::fill_nonsecret;

use super::obfs_host_header;

/// The reference's write chunk: `chunkSize = 1 << 14` (`tls.go:19-21`).
const CHUNK: usize = 1 << 14;

/// Record type bytes, in HEX: `22` decimal is `0x16` and `23` decimal is
/// `0x17` — a decimal `17` here would emit `0x11`, which no TLS parser accepts.
const REC_HANDSHAKE: u8 = 0x16;
const REC_APPLICATION: u8 = 0x17;

/// Bytes of the peer's first flight to discard before its length field.
///
/// NOT a "flight size" — it is the **offset of the encrypted-handshake length field** in the
/// C server's first buffer (`simple-obfs/src/obfs_tls.c:364-368`): the buffer is
/// `[server_hello 96][change_cipher_spec 6][encrypted_handshake header 5][payload]`, so the
/// payload starts at 107 and its length is the EH header's last two bytes, at 105.
///
/// **Those three sizes are exact because every one of these structs is declared
/// `__attribute__((packed, aligned(1)))`** (`obfs_tls.h:47,56,62,85,116,123,130`): the
/// `short`/`int` members sit on odd offsets with no padding inserted, so the field sums and
/// the compiler's `sizeof` agree (a probe over that header prints 96 / 6 / 5 with
/// `offsetof(len) = 3`). Assuming ordinary alignment rules instead yields a 100/8/6 triple
/// and a payload at 114 — do not "correct" this constant on that basis. The Go
/// port instead discards 105 and then a 3-byte record header per read
/// (`transport/simple-obfs/tls.go:71-81`); the C `obfs-server` — the oracle and the deployed
/// server side — appends the first payload **raw inside the first record**, with no
/// `17 03 03` header at all (`obfs_tls.c:165, 337-368`); only later writes get one.
const FIRST_FLIGHT_SKIP: usize = 105;

/// Per record: the 3-byte type+version header, then a 2-byte length.
const RECORD_HEADER: usize = 3;
const RECORD_LENGTH: usize = 2;

/// The 2-byte length field, or an error when the value cannot fit.
///
/// A record length IS two bytes, so an oversized value is a framing failure and
/// must not be truncated into a record the peer mis-parses. Every length the
/// framing writes goes through here, which is also what keeps clippy's
/// truncation lint honest about the 16 KiB chunk cap.
fn len16(len: usize) -> std::io::Result<u16> {
    u16::try_from(len).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "obfs tls record length does not fit the 2-byte field",
        )
    })
}

/// The 3-byte handshake length field.
fn len24(len: usize) -> std::io::Result<[u8; 3]> {
    let len = u32::try_from(len).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "obfs tls hello is too long",
        )
    })?;
    Ok(len.to_be_bytes()[1..].try_into().expect("three bytes"))
}

/// Wrap `inner` so writes become synthetic TLS records.
pub(crate) fn wrap(inner: BoxStream, host: String) -> BoxStream {
    Box::new(TlsObfs {
        inner,
        host,
        pending: Vec::new(),
        hello_written: false,
        state: ReadState::Flight,
        flight_left: FIRST_FLIGHT_SKIP,
        buffer: Vec::new(),
    })
}

/// The `LinkContext`-driven entry the transport arm calls: resolve the host the
/// synthetic hello's `server_name` carries, then wrap.
pub(crate) fn wrap_for(
    ctx: &LinkContext,
    inner: BoxStream,
    spec: &leas_proto::proto_spec::PluginSpec,
) -> BoxStream {
    let host = obfs_host_header(
        spec.host.as_deref(),
        spec.port,
        ctx.params.server.host.as_str(),
    );
    wrap(inner, host)
}

/// Where the read side is. Records are bounded, so a read never crosses into
/// the next one: the excess is buffered rather than dropped or mistaken for a
/// header on the next call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    /// Discarding the peer's first flight up to the payload-length field (105).
    Flight,
    /// Reading the first buffer's 2-byte length — the encrypted-handshake header's own
    /// length, which is where the raw payload's size lives.
    FirstLength,
    /// Delivering the first buffer's payload, **raw**: it was appended inside the first
    /// record with no `17 03 03` header (`obfs_tls.c:364-368`).
    FirstBody { remaining: usize },
    /// Discarding one later record's 3-byte type+version header (`0x17 0x03 0x03`).
    Header,
    /// Reading a later record's 2-byte length.
    Length,
    /// Delivering a later record's payload.
    Body { remaining: usize },
}

struct TlsObfs {
    inner: BoxStream,
    host: String,
    /// Bytes not yet handed to the socket.
    pending: Vec<u8>,
    hello_written: bool,
    state: ReadState,
    flight_left: usize,
    /// Payload read past a record boundary, held for the next call.
    buffer: Vec<u8>,
}

/// The outcome of one bounded read from the inner stream.
enum Fill {
    Got(usize),
    Eof,
}

impl TlsObfs {
    /// Read exactly 2 length bytes, or `None` on a clean EOF mid-length.
    fn read_length(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Option<[u8; 2]>>> {
        let mut bytes = [0u8; RECORD_LENGTH];
        let mut at = 0;
        while at < RECORD_LENGTH {
            match self.read_step(cx, &mut bytes[at..]) {
                None => return Poll::Pending,
                Some(Err(e)) => return Poll::Ready(Err(e)),
                Some(Ok(Fill::Eof)) => return Poll::Ready(Ok(None)),
                Some(Ok(Fill::Got(n))) => at += n,
            }
        }
        Poll::Ready(Ok(Some(bytes)))
    }

    /// Deliver up to `remaining` bytes of one record's payload, never crossing the
    /// record boundary: what the caller asked for AND what this record holds.
    ///
    /// Shared by the first buffer's raw payload and by later record bodies, which
    /// differ only in which state they return to.
    fn read_body(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        scratch: &mut [u8],
        remaining: usize,
    ) -> Poll<std::io::Result<()>> {
        let want = remaining.min(buf.remaining()).min(scratch.len());
        match self.read_step(cx, &mut scratch[..want]) {
            None => Poll::Pending,
            Some(Err(e)) => Poll::Ready(Err(e)),
            Some(Ok(Fill::Eof)) => Poll::Ready(Ok(())),
            Some(Ok(Fill::Got(n))) => {
                buf.put_slice(&scratch[..n]);
                let left = remaining - n;
                self.state = match self.state {
                    ReadState::FirstBody { .. } => {
                        if left == 0 {
                            ReadState::Header
                        } else {
                            ReadState::FirstBody { remaining: left }
                        }
                    }
                    _ => {
                        if left == 0 {
                            ReadState::Header
                        } else {
                            ReadState::Body { remaining: left }
                        }
                    }
                };
                Poll::Ready(Ok(()))
            }
        }
    }

    /// One bounded read from the inner stream into `dst`. `None` means "not
    /// ready"; a short read is `Got(n < dst.len())` because a record boundary
    /// or a clean EOF can both land mid-buffer, and treating that as EOF would
    /// truncate the payload.
    fn read_step(&mut self, cx: &mut Context<'_>, dst: &mut [u8]) -> Option<std::io::Result<Fill>> {
        let mut read_buf = ReadBuf::new(dst);
        match Pin::new(&mut *self.inner).poll_read(cx, &mut read_buf) {
            Poll::Pending => None,
            Poll::Ready(Err(e)) => Some(Err(e)),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                Some(Ok(if n == 0 { Fill::Eof } else { Fill::Got(n) }))
            }
        }
    }

    /// The synthetic `ClientHello` record carrying `payload` in its
    /// `session_ticket` extension, with `host` as `server_name`.
    ///
    /// Layout mirrors `makeClientHelloMsg` (`tls.go:130-204`): a TLS-1.0 record
    /// header, a TLS-1.2 `ClientHello` whose `random` is 32 bytes (4 timestamp the
    /// server ignores + 28 random), a 32-byte session id, the reference's cipher
    /// list, then the extensions — `session_ticket` FIRST (it carries the
    /// payload), then `server_name`, `ec_point_formats`, `supported_groups`,
    /// `signature_algorithms`, `encrypt_then_mac` and `extended_master_secret`.
    /// Every length is COMPUTED from what was written; the reference's
    /// `208 + len(data) + len(server)` constant is exactly the kind of number
    /// that drifts the moment a byte moves.
    fn client_hello(&self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut random = [0u8; 28];
        let mut session_id = [0u8; 32];
        fill_nonsecret(&mut random);
        fill_nonsecret(&mut session_id);
        let host = self.host.as_bytes();

        let mut body: Vec<u8> = Vec::with_capacity(256 + payload.len() + host.len());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&random);
        body.push(32);
        body.extend_from_slice(&session_id);
        // Cipher suites: the reference's exact list (`tls.go:159-164`).
        body.extend_from_slice(&0x0038u16.to_be_bytes());
        body.extend_from_slice(&[
            0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b,
            0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27,
            0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33,
            0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
        ]);
        // Compression: null.
        body.extend_from_slice(&[0x01, 0x00]);

        let mut extensions: Vec<u8> = Vec::with_capacity(128 + payload.len() + host.len());
        extensions.extend_from_slice(&0x0023u16.to_be_bytes());
        extensions.extend_from_slice(&len16(payload.len())?.to_be_bytes());
        extensions.extend_from_slice(payload);
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&len16(host.len() + 5)?.to_be_bytes());
        extensions.extend_from_slice(&len16(host.len() + 3)?.to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&len16(host.len())?.to_be_bytes());
        extensions.extend_from_slice(host);
        extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);
        extensions.extend_from_slice(&[
            0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
        ]);
        extensions.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01,
            0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02,
            0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
        ]);
        extensions.extend_from_slice(&[0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00]);
        body.extend_from_slice(&len16(extensions.len())?.to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::with_capacity(6 + body.len());
        // `handshake_type(1) + length(3) + version(2)` — the order the C struct
        // declares (`obfs_tls.h:33-36`) and the order `check_tls_request` checks:
        // it accepts only when `data[9] == 0x03 && data[10] == 0x03`
        // (`obfs_tls.c:514-520`), i.e. the version sits at 9..11. Emitting the
        // version BEFORE the length fails that check, and the plugin then
        // `disable`s itself and passes every byte through raw
        // (`obfs_tls.c:525-530`) — a silent failure that reaches the SS server as
        // our TLS record. The reference's own bytes agree: the built `obfs-local`
        // emits `16 03 01 00 ec | 01 | 00 00 e8 | 03 03 …`.
        handshake.push(1);
        handshake.extend_from_slice(&len24(body.len())?);
        handshake.extend_from_slice(&[0x03, 0x03]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::with_capacity(5 + handshake.len());
        record.push(REC_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&len16(handshake.len())?.to_be_bytes());
        record.extend_from_slice(&handshake);
        Ok(record)
    }

    /// An application-data record carrying `payload`.
    fn data_record(payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut record = Vec::with_capacity(5 + payload.len());
        record.push(REC_APPLICATION);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&len16(payload.len())?.to_be_bytes());
        record.extend_from_slice(payload);
        Ok(record)
    }
}

impl AsyncRead for TlsObfs {
    /// The C server's first buffer is `[server_hello 96][CCS 6][EH header 5][payload]`
    /// with the payload **raw** — no `17 03 03` header (`obfs_tls.c:337-368`); the EH
    /// header's last two bytes are the payload length, at offset 105. Only later
    /// writes are wrapped records (`obfs_tls.c:165, 372-375`). The sizes are the
    /// compiler's, from a probe over the real header: `sizeof` 96 / 6 / 5,
    /// `offsetof(len) = 3`.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut scratch = [0u8; 1024];
        loop {
            // Buffered payload from a previous read comes first, whatever the state.
            if !this.buffer.is_empty() {
                let take = this.buffer.len().min(buf.remaining());
                if take > 0 {
                    buf.put_slice(&this.buffer[..take]);
                }
                this.buffer.drain(..take);
                return Poll::Ready(Ok(()));
            }
            match this.state {
                ReadState::Flight => {
                    let want = this.flight_left.min(scratch.len());
                    match this.read_step(cx, &mut scratch[..want]) {
                        None => return Poll::Pending,
                        Some(Err(e)) => return Poll::Ready(Err(e)),
                        Some(Ok(Fill::Eof)) => return Poll::Ready(Ok(())),
                        Some(Ok(Fill::Got(n))) => {
                            this.flight_left -= n;
                            if this.flight_left == 0 {
                                this.state = ReadState::FirstLength;
                            }
                        }
                    }
                }
                // Both lengths are 2 bytes; they differ only in what follows.
                ReadState::FirstLength | ReadState::Length => {
                    let len_bytes = match this.read_length(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(Some(bytes))) => bytes,
                        // A clean EOF inside the length: nothing is left.
                        Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                    };
                    let remaining = u16::from_be_bytes(len_bytes) as usize;
                    this.state = if matches!(this.state, ReadState::FirstLength) {
                        ReadState::FirstBody { remaining }
                    } else {
                        ReadState::Body { remaining }
                    };
                }
                ReadState::FirstBody { remaining } | ReadState::Body { remaining } => {
                    if remaining == 0 {
                        this.state = ReadState::Header;
                        continue;
                    }
                    return this.read_body(cx, buf, &mut scratch, remaining);
                }
                ReadState::Header => match this.read_step(cx, &mut scratch[..RECORD_HEADER]) {
                    None => return Poll::Pending,
                    Some(Err(e)) => return Poll::Ready(Err(e)),
                    Some(Ok(Fill::Eof)) => return Poll::Ready(Ok(())),
                    Some(Ok(Fill::Got(_))) => this.state = ReadState::Length,
                },
            }
        }
    }
}

impl AsyncWrite for TlsObfs {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        // A length that cannot be framed is an I/O error, never a truncated
        // record: the peer would mis-parse it rather than fail cleanly.
        let framed = if this.hello_written {
            // One record per chunk, capped at 16 KiB so a 2-byte length always
            // has room.
            match buf
                .chunks(CHUNK)
                .map(Self::data_record)
                .collect::<std::io::Result<Vec<_>>>()
            {
                Ok(records) => records,
                Err(e) => return Poll::Ready(Err(e)),
            }
        } else {
            this.hello_written = true;
            match this.client_hello(buf) {
                Ok(record) => vec![record],
                Err(e) => return Poll::Ready(Err(e)),
            }
        };
        for record in framed {
            this.pending.extend_from_slice(&record);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            return Pin::new(&mut *this.inner).poll_flush(cx);
        }
        let chunk = std::mem::take(&mut this.pending);
        match Pin::new(&mut *this.inner).poll_write(cx, &chunk) {
            Poll::Pending => {
                this.pending = chunk;
                Poll::Pending
            }
            Poll::Ready(Err(e)) => {
                this.pending = chunk;
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(n)) => {
                if n < chunk.len() {
                    this.pending = chunk[n..].to_vec();
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self;
        if !this.pending.is_empty() {
            let _ = Pin::new(&mut *this).poll_flush(cx)?;
        }
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    fn wrap_pair(host: &str) -> (TlsObfs, tokio::io::DuplexStream) {
        let (client, server) = duplex(256 * 1024);
        let obfs = TlsObfs {
            inner: Box::new(client),
            host: host.to_string(),
            pending: Vec::new(),
            hello_written: false,
            state: ReadState::Flight,
            flight_left: FIRST_FLIGHT_SKIP,
            buffer: Vec::new(),
        };
        (obfs, server)
    }

    /// The read side follows the **C server's** first-buffer layout. The sizes are
    /// the compiler's, printed by a probe over `obfs_tls.h`:
    /// `sizeof(tls_server_hello) = 96`, `sizeof(tls_change_cipher_spec) = 6`,
    /// `sizeof(tls_encrypted_handshake) = 5` with `offsetof(len) = 3` — so the
    /// payload length sits at 96 + 6 + 3 = **105** and the payload starts at **107**,
    /// appended **raw**, with no `17 03 03` header (`obfs_tls.c:337-368`). Only later
    /// writes are wrapped records (`obfs_tls.c:165, 372-375`).
    #[tokio::test]
    async fn the_first_buffer_payload_is_raw_after_a_105_byte_flight() {
        const PAYLOAD: &[u8] = b"REAL-PAYLOAD";
        let (mut obfs, mut peer) = wrap_pair("h");

        let mut server = vec![0xAA; FIRST_FLIGHT_SKIP];
        server.extend_from_slice(
            &u16::try_from(PAYLOAD.len())
                .expect("a test payload fits")
                .to_be_bytes(),
        );
        server.extend_from_slice(PAYLOAD);
        // A later write IS a wrapped record: 0x17 0x03 0x03 + 2-byte length.
        server.extend_from_slice(&[REC_APPLICATION, 0x03, 0x03]);
        server.extend_from_slice(&6u16.to_be_bytes());
        server.extend_from_slice(b"SECOND");
        peer.write_all(&server).await.expect("server writes");

        // Small reads, so they straddle the boundary between the raw first payload
        // and the next record — the case the old "discard 3 bytes per read" rule
        // got wrong by eating payload.
        let mut got = Vec::new();
        let mut chunk = [0u8; 5];
        while got.len() < PAYLOAD.len() + 6 {
            let n = obfs.read(&mut chunk).await.expect("read");
            assert!(n > 0, "no progress at {} bytes", got.len());
            got.extend_from_slice(&chunk[..n]);
        }
        let mut want = PAYLOAD.to_vec();
        want.extend_from_slice(b"SECOND");
        assert_eq!(
            got, want,
            "the flight, the raw first payload and one record header go"
        );
    }

    /// The first write is a TLS-1.0-framed record whose `ClientHello` carries the
    /// payload inside `session_ticket` — the disguise's whole trick
    /// (`tls.go:130-204`).
    #[tokio::test]
    async fn the_first_write_is_a_synthetic_hello_carrying_the_payload() {
        let (mut obfs, mut peer) = wrap_pair("IsiBugSendiri");
        obfs.write_all(b"PAYLOAD").await.expect("write");
        obfs.flush().await.expect("flush");

        let mut wire = vec![0u8; 4096];
        let n = peer.read(&mut wire).await.expect("read");
        let wire = &wire[..n];

        assert_eq!(wire[0], REC_HANDSHAKE, "handshake record");
        assert_eq!(&wire[1..3], &[0x03, 0x01], "TLS 1.0 record version");
        let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        assert_eq!(len, wire.len() - 5, "the record length covers the body");
        assert_eq!(wire[5], 0x01, "client_hello");
        // `handshake_type(1) + length(3) + version(2)`: the version is at 9..11,
        // which is where `check_tls_request` reads it (`obfs_tls.c:514-520`), and
        // the reference's own bytes agree (`16 03 01 00 ec | 01 | 00 00 e8 | 03 03`).
        let hello_len = u32::from_be_bytes([0, wire[6], wire[7], wire[8]]) as usize;
        assert_eq!(
            hello_len,
            wire.len() - 11,
            "the hello length covers its body"
        );
        assert_eq!(&wire[9..11], &[0x03, 0x03], "TLS 1.2 in the hello");
        assert_eq!(wire[43], 32, "session id length");
        let text = String::from_utf8_lossy(wire);
        let ticket_at = text
            .find("PAYLOAD")
            .expect("the payload rides in session_ticket");
        let host_at = text
            .find("IsiBugSendiri")
            .expect("the host rides in server_name");
        assert!(ticket_at < host_at, "session_ticket comes first");
    }

    /// Later writes are `0x17` application records, one per 16 KiB chunk
    /// (`tls.go:99-114`).
    #[tokio::test]
    async fn later_writes_are_application_records() {
        let (mut obfs, mut peer) = wrap_pair("h");
        obfs.write_all(b"first").await.expect("write");
        obfs.flush().await.expect("flush");
        let mut head = vec![0u8; 4096];
        let _ = peer.read(&mut head).await.expect("read the hello");

        obfs.write_all(b"second").await.expect("write");
        obfs.flush().await.expect("flush");
        let mut rec = vec![0u8; 64];
        let m = peer.read(&mut rec).await.expect("read");
        assert_eq!(rec[0], REC_APPLICATION, "application data, 0x17 — not 0x11");
        assert_eq!(&rec[1..3], &[0x03, 0x03], "TLS 1.2 in the record");
        assert_eq!(u16::from_be_bytes([rec[3], rec[4]]) as usize, m - 5);
        assert_eq!(&rec[5..m], b"second");
    }

    /// A write larger than 16 KiB is split, because the length field is 2 bytes
    /// and the reference caps a record at 1 << 14.
    #[tokio::test]
    async fn a_large_write_is_chunked_at_16_kib() {
        let (mut obfs, mut peer) = wrap_pair("h");
        obfs.write_all(b"x").await.expect("prime the hello");
        obfs.flush().await.expect("flush");
        let mut head = vec![0u8; 8192];
        let _ = peer.read(&mut head).await.expect("read the hello");

        obfs.write_all(&vec![b'y'; CHUNK * 2 + 7])
            .await
            .expect("write");
        obfs.flush().await.expect("flush");
        let mut got = vec![0u8; 128 * 1024];
        let n = peer.read(&mut got).await.expect("read");
        let mut at = 0;
        let mut records = 0;
        while at < n {
            let len = u16::from_be_bytes([got[at + 3], got[at + 4]]) as usize;
            at += 5 + len;
            records += 1;
            if at >= n {
                break;
            }
        }
        assert_eq!(records, 3, "16384 + 16384 + 7 in three records");
        assert_eq!(n, 3 * 5 + CHUNK * 2 + 7, "no padding, no truncation");
    }
}
