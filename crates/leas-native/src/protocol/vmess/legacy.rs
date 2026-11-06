//! Legacy (pre-AEAD) `VMess`: the `alterId > 0` wire that Xray-core dropped
//! but v2ray-core 4.x and sing-box still speak.
//!
//! Authority: `thirdparty/v2ray-core-legacy/proxy/vmess/encoding/client.go`
//! (`EncodeRequestHeader` / `DecodeResponseHeader`), `common/protocol/id.go`.
//!
//! The delta against the AEAD wire is small and entirely in the two headers:
//!
//! * the request header is `idHash` (16 bytes, PLAINTEXT) followed by the same
//!   49+-byte body, encrypted with **AES-128-CFB** under `cmdKey` with the IV
//!   `md5(timestamp_be8 × 4)`;
//! * the response header is **4 plaintext bytes** read from the same CFB
//!   stream the response body uses (`responseBodyKey`/`responseBodyIV`):
//!   `[echo][option][0][0]`.
//!
//! Body records are unchanged AEAD chunks. The option byte carries
//! `RequestOptionChunkStream` (`0x01`) — the legacy framing bit that the AEAD
//! era deprecated — so the chunk layer is the plain 2-byte size + AEAD body
//! the modern path already implements.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use md5::Md5;
use md5::digest::Digest as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) use crate::crypto::legacy_stream::Aes128Cfb as Cfb;

/// `RequestOptionChunkStream` — `[DEPRECATED 2023-06]` on the AEAD wire, but
/// the *only* framing bit the legacy wire understands.
pub const OPTION_CHUNK_STREAM: u8 = 0x01;

/// Go `hashTimestamp(h, t)`: the timestamp is written into the hash FOUR
/// times, then the digest is taken (`encoding/client.go:29-35`). This is the
/// CFB IV, not a MAC.
#[must_use]
pub fn hash_timestamp(ts: i64) -> [u8; 16] {
    let mut h = Md5::new();
    for _ in 0..4 {
        h.update(ts.to_be_bytes());
    }
    h.finalize().into()
}

/// The 16-byte plaintext prefix that precedes the CFB-encrypted header:
/// `md5(uuid ‖ timestamp_be8)` (Go `idHash.Sum(nil)` after
/// `serial.WriteUint64(idHash, ts)`).
#[must_use]
pub fn id_hash(uuid: &[u8; 16], ts: i64) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid);
    h.update(ts.to_be_bytes());
    h.finalize().into()
}

/// Read wrapper: decrypts every byte the peer sends after the CFB prefix.
///
/// The write half is untouched — the request body is NOT CFB-framed, only the
/// request header was, and it is written before this wrapper exists.
pub struct CfbReader<S> {
    inner: S,
    cfb: Cfb,
}

impl<S> CfbReader<S> {
    #[must_use]
    pub fn new(inner: S, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            inner,
            cfb: Cfb::new(key, iv),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CfbReader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        let filled = buf.filled().len();
        if filled > filled_before {
            let this = &mut *self;
            this.cfb
                .decrypt(&mut buf.filled_mut()[filled_before..filled]);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CfbReader<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
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

    /// Independent oracle: `python3 -c "hashlib.md5(...)"`. The prefix is
    /// `md5(uuid ‖ ts_be8)`; the CFB IV is `md5(ts_be8 × 4)`.
    #[test]
    fn id_hash_and_iv_match_go_helpers() {
        assert_eq!(
            hex(&id_hash(&[0u8; 16], 0x6000_0000_0000_0000)),
            "8624959d45c80fecd9bef2113b47e849"
        );
        assert_eq!(
            hex(&hash_timestamp(0x6000_0000_0000_0000)),
            "9ae35f9fa5bca3fa101e510a5d4402e9"
        );
    }

    fn hex(b: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(b.len() * 2);
        for x in b {
            let _ = write!(out, "{x:02x}");
        }
        out
    }
}
