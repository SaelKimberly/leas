//! Legacy (pre-AEAD) Shadowsocks TCP codec — client side.
//!
//! Wire (the classic Shadowsocks protocol; the same shape shadowsocks-rust's
//! `relay/tcprelay/stream.rs` and mihomo's stream outbound speak):
//!
//! ```text
//! client → server : [IV] cipher(addr ‖ payload…)      one continuous keystream
//! server → client : [IV] cipher(payload…)             one continuous keystream
//! ```
//!
//! Differences from [`super::stream`] (the 2017 AEAD set), which this module
//! must not be confused with: there is **no** chunk framing, **no** per-chunk
//! length or tag, **no** subkey derivation (the IV is the cipher's nonce, not a
//! salt), and the keystream runs continuously across writes for the life of the
//! connection. `none` sends no IV at all — `v2ray-core-v4.38.3`'s `NoneCipher`
//! reports `KeySize() == IVSize() == 0` and returns the reader/writer unchanged
//! (`proxy/shadowsocks/config.go:185-207`).
//!
//! `rc4-md5` does not key RC4 with the master key: its session key is
//! `MD5(master_key ‖ IV)` (shadowsocks-rust `crypto/stream/rc4_md5.rs`), which
//! is why it needs its own constructor arm here.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use aes::{Aes128, Aes192, Aes256};
use chacha20::cipher::KeyIvInit;
use chacha20::{ChaCha20, XChaCha20};
use ctr::Ctr128BE;
use md5::Md5;
use md5::digest::Digest as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::BoxStream;
use crate::addr::TargetAddr;
use crate::addr::encode_addr_port_last;
use crate::context::LinkContext;
use crate::crypto::legacy_stream::{Aes128Cfb, Aes192Cfb, Aes256Cfb, Rc4};
use crate::error::{NativeError, timeouts};
use crate::protocol::ss::method::{SsFamily, SsMethod, StreamCipher, password_key};

/// The widest IV any legacy cipher uses (`xchacha20`, 24 bytes).
const MAX_IV: usize = 24;

/// The most plaintext one `poll_write` accepts: the write buffer is drained
/// first, so at most this much ciphertext is ever queued.
const MAX_WRITE_CHUNK: usize = 64 * 1024;

/// One direction's keystream. CFB and the XOR keystreams need different calls
/// because CFB's feedback register follows the ciphertext on decrypt.
pub(crate) trait Keystream: Send {
    fn encrypt(&mut self, data: &mut [u8]);
    fn decrypt(&mut self, data: &mut [u8]);
}

impl Keystream for Aes128Cfb {
    fn encrypt(&mut self, data: &mut [u8]) {
        self.encrypt(data);
    }
    fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt(data);
    }
}

impl Keystream for Aes192Cfb {
    fn encrypt(&mut self, data: &mut [u8]) {
        self.encrypt(data);
    }
    fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt(data);
    }
}

impl Keystream for Aes256Cfb {
    fn encrypt(&mut self, data: &mut [u8]) {
        self.encrypt(data);
    }
    fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt(data);
    }
}

/// `CTR` and `ChaCha20` are pure XOR keystreams: the same call in both directions.
macro_rules! xor_keystream {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Keystream for $ty {
                fn encrypt(&mut self, data: &mut [u8]) {
                    <Self as chacha20::cipher::StreamCipher>::apply_keystream(self, data);
                }
                fn decrypt(&mut self, data: &mut [u8]) {
                    <Self as chacha20::cipher::StreamCipher>::apply_keystream(self, data);
                }
            }
        )*
    };
}

xor_keystream!(
    Ctr128BE<Aes128>,
    Ctr128BE<Aes192>,
    Ctr128BE<Aes256>,
    ChaCha20,
    XChaCha20,
);

impl Keystream for Rc4 {
    fn encrypt(&mut self, data: &mut [u8]) {
        self.apply(data);
    }
    fn decrypt(&mut self, data: &mut [u8]) {
        self.apply(data);
    }
}

/// Config error for a shape the cipher table says cannot happen.
fn config_error(detail: &str) -> NativeError {
    NativeError::Config(detail.to_owned())
}

fn wire_error(error: NativeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn unexpected_eof() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        wire_error(config_error("response stream ended before its IV")),
    )
}

/// Build one direction's keystream. `None` for the `none` cipher (passthrough).
pub(crate) fn keystream(
    cipher: StreamCipher,
    key: &[u8],
    iv: &[u8],
) -> Result<Option<Box<dyn Keystream>>, io::Error> {
    use StreamCipher::{
        Aes128Cfb as Cfb128, Aes128Ctr, Aes192Cfb as Cfb192, Aes192Ctr, Aes256Cfb as Cfb256,
        Aes256Ctr, Chacha20Ietf, None as NoneCipher, Rc4Md5, XChacha20 as XChaCha,
    };
    let bad = |what: &str| {
        wire_error(config_error(&format!(
            "shadowsocks legacy cipher `{cipher:?}`: {what}"
        )))
    };
    let iv16 = |iv: &[u8]| -> Result<[u8; 16], io::Error> {
        iv.try_into().map_err(|_| bad("IV is not 16 bytes"))
    };
    let key16 = |key: &[u8]| -> Result<[u8; 16], io::Error> {
        key.try_into().map_err(|_| bad("key is not 16 bytes"))
    };
    let key24 = |key: &[u8]| -> Result<[u8; 24], io::Error> {
        key.try_into().map_err(|_| bad("key is not 24 bytes"))
    };
    let key32 = |key: &[u8]| -> Result<[u8; 32], io::Error> {
        key.try_into().map_err(|_| bad("key is not 32 bytes"))
    };
    let out: Box<dyn Keystream> = match cipher {
        NoneCipher => return Ok(None),
        Cfb128 => Box::new(Aes128Cfb::new(&key16(key)?, &iv16(iv)?)),
        Cfb192 => Box::new(Aes192Cfb::new(&key24(key)?, &iv16(iv)?)),
        Cfb256 => Box::new(Aes256Cfb::new(&key32(key)?, &iv16(iv)?)),
        Aes128Ctr => {
            let (k, n) = (key16(key)?, iv16(iv)?);
            Box::new(Ctr128BE::<Aes128>::new(&k.into(), &n.into()))
        }
        Aes192Ctr => {
            let (k, n) = (key24(key)?, iv16(iv)?);
            Box::new(Ctr128BE::<Aes192>::new(&k.into(), &n.into()))
        }
        Aes256Ctr => {
            let (k, n) = (key32(key)?, iv16(iv)?);
            Box::new(Ctr128BE::<Aes256>::new(&k.into(), &n.into()))
        }
        Chacha20Ietf => {
            let (k, n) = (key32(key)?, iv12(iv)?);
            Box::new(ChaCha20::new(&k.into(), &n.into()))
        }
        XChaCha => {
            let (k, n) = (key32(key)?, iv24(iv)?);
            Box::new(XChaCha20::new(&k.into(), &n.into()))
        }
        Rc4Md5 => {
            // The RC4 key is a SESSION key: MD5(master_key ‖ IV).
            let mut hash = Md5::new();
            hash.update(key);
            hash.update(iv);
            let session = Zeroizing::new(hash.finalize());
            Box::new(Rc4::new(&session))
        }
    };
    Ok(Some(out))
}

fn iv12(iv: &[u8]) -> Result<[u8; 12], io::Error> {
    iv.try_into().map_err(|_| {
        wire_error(config_error(
            "shadowsocks legacy cipher: IV is not 12 bytes",
        ))
    })
}

fn iv24(iv: &[u8]) -> Result<[u8; 24], io::Error> {
    iv.try_into().map_err(|_| {
        wire_error(config_error(
            "shadowsocks legacy cipher: IV is not 24 bytes",
        ))
    })
}

/// A legacy Shadowsocks stream: one continuous keystream per direction behind
/// an IV that leads each direction.
///
/// The write direction buffers ciphertext until the transport accepts it (a
/// single caller write can exceed what the socket takes); the read direction
/// consumes the server's IV before decrypting anything.
pub struct SsLegacyStream<S> {
    inner: S,
    cipher: StreamCipher,
    /// Master key, needed until the server IV derives the reader state.
    key: Zeroizing<Vec<u8>>,
    write: Option<Box<dyn Keystream>>,
    read: Option<Box<dyn Keystream>>,
    /// The request IV has been generated and its keystream built.
    write_started: bool,
    /// Bytes of the server IV received so far.
    read_iv: Vec<u8>,
    /// The reader keystream is built (`true` immediately for the `none` cipher).
    read_ready: bool,
    /// Ciphertext waiting for the transport.
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> SsLegacyStream<S> {
    fn new(inner: S, cipher: StreamCipher, key: Zeroizing<Vec<u8>>) -> Self {
        Self {
            inner,
            cipher,
            key,
            write: None,
            read: None,
            write_started: false,
            read_iv: Vec::new(),
            read_ready: cipher.iv_len() == 0,
            out: Vec::new(),
            out_pos: 0,
        }
    }

    /// Start the request direction: generate (or take) the IV, build the
    /// keystream, and queue `first` (the encoded target address) after it.
    ///
    /// `iv` is `Some` only in tests, which pin the request bytes.
    fn start_write(&mut self, iv: Option<&[u8]>, first: &[u8]) -> io::Result<()> {
        let iv = if let Some(iv) = iv {
            iv.to_vec()
        } else {
            let mut iv = vec![0u8; self.cipher.iv_len()];
            crate::rand::fill_nonsecret(&mut iv);
            iv
        };
        if iv.len() != self.cipher.iv_len() {
            return Err(wire_error(config_error(
                "shadowsocks legacy request IV has the wrong length",
            )));
        }
        self.out.extend_from_slice(&iv);
        self.write = keystream(self.cipher, &self.key, &iv)?;
        self.write_started = true;
        if !first.is_empty() {
            self.queue(first);
        }
        Ok(())
    }

    /// Encrypt `data` with the write keystream and append it to the buffer.
    fn queue(&mut self, data: &[u8]) {
        let start = self.out.len();
        self.out.extend_from_slice(data);
        if let Some(state) = &mut self.write {
            state.encrypt(&mut self.out[start..]);
        }
    }

    /// Drain the buffered ciphertext into the transport.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while self.out_pos < self.out.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SsLegacyStream<S> {
    /// Read the server's IV (if any) and build the reader keystream.
    fn poll_read_iv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let want = self.cipher.iv_len();
        while self.read_iv.len() < want {
            let mut chunk = [0u8; MAX_IV];
            let mut buf = ReadBuf::new(&mut chunk[..want - self.read_iv.len()]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
            let filled = buf.filled();
            if filled.is_empty() {
                return Poll::Ready(Err(unexpected_eof()));
            }
            self.read_iv.extend_from_slice(filled);
        }
        self.read = keystream(self.cipher, &self.key, &self.read_iv)?;
        self.read_ready = true;
        self.key = Zeroizing::new(Vec::new());
        Poll::Ready(Ok(()))
    }

    /// Flush every queued byte, used by the connect handshake.
    async fn flush_out(&mut self) -> io::Result<()>
    where
        S: Unpin,
    {
        std::future::poll_fn(|cx| self.poll_drain(cx)).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for SsLegacyStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.read_ready {
            ready!(self.poll_read_iv(cx))?;
        }
        let filled_before = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        let filled = buf.filled().len();
        if filled > filled_before {
            let this = &mut *self;
            if let Some(state) = &mut this.read {
                state.decrypt(&mut buf.filled_mut()[filled_before..]);
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for SsLegacyStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        {
            let this = &mut *self;
            if !this.write_started {
                this.start_write(None, &[])?;
            }
            // Accept at most one buffer-sized slice per call: `poll_drain`
            // emptied `out` above, so the queued ciphertext is bounded by this
            // constant regardless of how large a single `write_all`/`copy`
            // buffer is.
            let take = data.len().min(MAX_WRITE_CHUNK);
            this.queue(&data[..take]);
        }
        // Push what was just queued: a caller that writes once and then reads
        // (one HTTP request, no `flush`) must not leave the ciphertext parked
        // in `out`. A transport that is not ready keeps the bytes queued —
        // they are still counted as accepted, and the next write/flush drains
        // them in order.
        let _ = self.poll_drain(cx);
        Poll::Ready(Ok(data.len().min(MAX_WRITE_CHUNK)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// TCP protocol phase for a legacy (stream-cipher) row.
pub async fn connect(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &leas_proto::proto_spec::SsConfig,
    method: SsMethod,
) -> Result<BoxStream, NativeError> {
    connect_to(&ctx.target, stream, cfg, method).await
}

/// The same handshake against an explicit target (the mux path's entry).
pub async fn connect_to(
    target: &TargetAddr,
    stream: BoxStream,
    cfg: &leas_proto::proto_spec::SsConfig,
    method: SsMethod,
) -> Result<BoxStream, NativeError> {
    if method.family() != SsFamily::Stream {
        return Err(NativeError::Config(format!(
            "shadowsocks legacy codec requires a legacy method, got {:?}",
            cfg.method
        )));
    }
    let cipher = method
        .stream()
        .ok_or_else(|| config_error("shadowsocks legacy method has no cipher"))?;
    let key = password_key(method, &cfg.password)?;
    let first = encode_addr_port_last(target)?;
    let mut stream = SsLegacyStream::new(stream, cipher, key);
    stream
        .start_write(None, &first)
        .map_err(|e| NativeError::Config(format!("shadowsocks legacy request: {e}")))?;
    let timeout = timeouts::PROTOCOL;
    tokio::time::timeout(timeout, stream.flush_out())
        .await
        .map_err(|_| NativeError::Timeout {
            step: "shadowsocks request write",
            limit: timeout,
        })??;
    Ok(Box::new(stream))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use chacha20::cipher::StreamCipher as _;

    use super::*;
    use crate::addr::Host;

    fn target() -> TargetAddr {
        TargetAddr {
            host: Host::Domain("example.com".into()),
            port: 443,
        }
    }

    /// One `write_all` with **no** `flush` must put its bytes on the wire.
    ///
    /// The write half queues into a buffer and drains it inside
    /// `poll_write`; before that drain existed, a caller that wrote a request
    /// and then read (one HTTP exchange, no explicit flush — the harness probe)
    /// left the ciphertext parked, so a real server saw the address header and
    /// nothing else. A legacy server cannot answer a request it never got, and
    /// the symptom is a silent stall, not an error.
    #[tokio::test]
    async fn a_write_reaches_the_transport_without_an_explicit_flush() {
        let method = SsMethod::from_method("aes-256-cfb").unwrap();
        let key = password_key(method, "password").unwrap();
        let cipher = method.stream().unwrap();
        let (client, mut server) = duplex(4096);
        let mut stream = SsLegacyStream::new(client, cipher, key);
        let iv = [0x22u8; 16];
        stream
            .start_write(Some(&iv), &[0x01, 1, 2, 3, 4, 0, 80])
            .unwrap();
        stream.flush_out().await.unwrap();
        // The handshake bytes are out; drain them so the next read is the
        // payload alone.
        let mut first = [0u8; 64];
        let n = server.read(&mut first).await.unwrap();
        assert_eq!(n, 16 + 7);

        stream.write_all(b"payload").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), server.read(&mut buf))
            .await
            .expect("the write must reach the transport without an explicit flush")
            .unwrap();
        assert_eq!(n, 7, "the queued ciphertext must be drained on write");
    }

    /// The request direction is `[IV] cipher(addr ‖ payload)` — a golden
    /// ciphertext for a pinned IV, and the keystream crosses the addr/payload
    /// boundary (one continuous stream, no per-record framing).
    #[tokio::test]
    async fn request_is_iv_then_cipher_of_addr_and_payload() {
        let method = SsMethod::from_method("aes-256-ctr").unwrap();
        let key = password_key(method, "password").unwrap();
        let cipher = method.stream().unwrap();
        let iv = [0x11u8; 16];
        let (client, mut server) = duplex(4096);

        let mut stream = SsLegacyStream::new(client, cipher, key.clone());
        let first = encode_addr_port_last(&target()).unwrap();
        stream.start_write(Some(&iv), &first).unwrap();
        stream.flush_out().await.unwrap();
        stream.write_all(b"payload").await.unwrap();
        stream.flush().await.unwrap();

        let mut wire = vec![0u8; iv.len() + first.len() + 7];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire[..16], &iv, "IV leads the request");

        // Independent decode: a fresh CTR keystream over the same key/IV.
        let mut expected = first.clone();
        expected.extend_from_slice(b"payload");
        let mut decoded = wire[16..].to_vec();
        Ctr128BE::<Aes256>::new(&key.as_slice().try_into().unwrap(), &iv.into())
            .apply_keystream(&mut decoded);
        assert_eq!(decoded, expected, "addr ‖ payload under one keystream");
    }

    /// The response direction consumes the server's IV before decrypting.
    #[tokio::test]
    async fn response_consumes_iv_then_decrypts() {
        let method = SsMethod::from_method("aes-128-ctr").unwrap();
        let key = password_key(method, "password").unwrap();
        let cipher = method.stream().unwrap();
        let iv = [0x22u8; 16];
        let (client, mut server) = duplex(4096);
        let mut stream = SsLegacyStream::new(client, cipher, key.clone());
        stream.start_write(Some(&iv), b"").unwrap();
        stream.flush_out().await.unwrap();

        let mut body = b"hello".to_vec();
        Ctr128BE::<Aes128>::new(&key.as_slice().try_into().unwrap(), &iv.into())
            .apply_keystream(&mut body);
        let mut wire = iv.to_vec();
        wire.extend_from_slice(&body);
        server.write_all(&wire).await.unwrap();

        let mut got = vec![0u8; 5];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
    }

    /// `none` is a passthrough with NO IV, on both directions.
    #[tokio::test]
    async fn none_sends_and_expects_no_iv() {
        let method = SsMethod::from_method("none").unwrap();
        let key = password_key(method, "password").unwrap();
        assert!(key.is_empty());
        let (client, mut server) = duplex(4096);
        let mut stream = SsLegacyStream::new(client, StreamCipher::None, key);
        let first = encode_addr_port_last(&target()).unwrap();
        stream.start_write(None, &first).unwrap();
        stream.flush_out().await.unwrap();
        stream.write_all(b"payload").await.unwrap();
        stream.flush().await.unwrap();

        let mut wire = vec![0u8; first.len() + 7];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire[..first.len()], first.as_slice());
        assert_eq!(&wire[first.len()..], b"payload");

        server.write_all(b"reply").await.unwrap();
        let mut got = vec![0u8; 5];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"reply");
    }

    /// `rc4-md5` keys RC4 with `MD5(key ‖ IV)`, not with the master key.
    #[test]
    fn rc4md5_session_key_is_md5_of_key_and_iv() {
        let key = [0x33u8; 16];
        let iv = [0x44u8; 16];
        let mut hash = md5::Md5::new();
        hash.update(key);
        hash.update(iv);
        let session = hash.finalize();

        let mut direct = Rc4::new(&session);
        let mut via_arm = keystream(StreamCipher::Rc4Md5, &key, &iv).unwrap().unwrap();
        let mut a = b"same plaintext".to_vec();
        let mut b = b"same plaintext".to_vec();
        direct.apply(&mut a);
        via_arm.encrypt(&mut b);
        assert_eq!(a, b);
    }
}
