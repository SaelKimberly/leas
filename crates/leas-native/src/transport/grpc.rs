//! gRPC transport: HTTP/2 framing (h2 crate) over the engine stream.
//! Single bidirectional stream (gun mode); 5-byte gRPC prefix framing per
//! the xray-core/sing-box wire format.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskCx, Poll};

use bytes::{Buf, Bytes, BytesMut};
use h2::RecvStream;
use h2::SendStream;
use leas_proto::proto_spec::common::GrpcConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};

/// gRPC service name: config value verbatim (no default). Stream path is
/// `/{service}/Tun`; empty service yields `//Tun` (xray `getServiceName`,
/// sing-box `TunCustomName`).
#[must_use]
pub fn grpc_service_name(cfg: &GrpcConfig) -> String {
    cfg.service_name.as_deref().unwrap_or("").to_string()
}

/// Request path: explicit config path, else `/{service}/Tun` (empty service
/// → `//Tun`, matching both cores).
fn grpc_path(cfg: &GrpcConfig, service: &str) -> String {
    cfg.path
        .as_deref()
        .filter(|p| !p.is_empty())
        .map_or_else(|| format!("/{service}/Tun"), ToString::to_string)
}

/// The xray/sing-box grpc transport carries VLESS bytes inside a protobuf
/// `Hunk` message (`message Hunk { bytes data = 1; }`), which rides inside
/// the standard gRPC 5-byte framing. Wire layout per message:
/// `0x00 | BE32(hunk_len) | 0x0A | varint(data_len) | data`.
/// (Verified: xray-core's `HunkConn.Recv` unmarshals the payload as Hunk —
/// raw bytes fail with "cannot parse invalid wire-format data".
/// Encode `n` as a base-128 varint into a stack buffer. Returns the bytes
/// and their length — no heap allocation on the encode path.
fn encode_varint_stack(mut n: usize) -> ([u8; 8], usize) {
    let mut out = [0u8; 8];
    let mut len = 0;
    loop {
        let mut b = u8::try_from(n & 0x7f).unwrap_or(0x7f);
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out[len] = b;
        len += 1;
        if n == 0 {
            return (out, len);
        }
    }
}

/// Encode one VLESS byte chunk as a gRPC Hunk message. Pure, unit-tested.
#[must_use]
pub fn encode_frame(payload: &[u8]) -> Bytes {
    let (varint, varint_len) = encode_varint_stack(payload.len());
    let hunk_len = 1 + varint_len + payload.len();
    let mut hunk_header_stack = [0u8; 9];
    hunk_header_stack[0] = 0x0A; // field 1, wire type 2 (length-delimited)
    hunk_header_stack[1..=varint_len].copy_from_slice(&varint[..varint_len]);
    let mut out = bytes::BytesMut::with_capacity(5 + hunk_len);
    out.extend_from_slice(&[0u8]);
    out.extend_from_slice(&u32::try_from(hunk_len).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&hunk_header_stack[..=varint_len]);
    out.extend_from_slice(payload);
    out.freeze()
}

/// Upper bound on a peer-declared gRPC frame (Hunk) length. A legitimate Hunk
/// carries one VLESS byte chunk; a multi-megabyte declaration is a protocol
/// violation. Without this bound a peer declaring `0xFFFFFFFF` makes the
/// client buffer every byte it sends, unbounded (found `f13`).
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// A framing violation the peer caused. Unlike `Ok(None)` ("need more
/// bytes"), this is terminal: the caller must fail the stream rather than
/// buffer forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GrpcFrameError {
    #[error("gRPC frame declares {0} bytes, over the {1}-byte cap")]
    FrameTooLarge(usize, usize),
    #[error("gRPC Hunk declares an out-of-range payload length")]
    LengthOverflow,
}

/// Decode ONE gRPC Hunk message from the front of `buf`.
///
/// Consumes only complete messages: returns `Ok(None)` when fewer than a full
/// message is available (partial prefix/payload stays in `buf`), and `Err` when
/// the peer declares a frame the client refuses to buffer.
///
/// # Errors
///
/// [`GrpcFrameError::FrameTooLarge`] when the peer's declared frame length
/// exceeds [`MAX_FRAME_LEN`], and [`GrpcFrameError::LengthOverflow`] when the
/// peer's inner varint length does not fit the address space (the old
/// `1 + dstart + dlen` panicked in debug and sliced `16..15` in release).
pub fn decode_frame(buf: &mut BytesMut) -> Result<Option<Bytes>, GrpcFrameError> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > MAX_FRAME_LEN {
        return Err(GrpcFrameError::FrameTooLarge(len, MAX_FRAME_LEN));
    }
    if buf.len() < 5 + len {
        return Ok(None);
    }
    let msg = buf.split_to(5 + len).freeze();
    let hunk = &msg[5..];
    // Hunk: 0x0A tag, then varint data length, then data.
    let Some(&tag) = hunk.first() else {
        return Ok(None);
    };
    if tag != 0x0A {
        return Ok(None);
    }
    let Some((dlen, dstart)) = varint_decode(hunk, 1) else {
        return Ok(None);
    };
    // `dlen` is a peer-supplied varint value (up to usize::MAX): keep every
    // bound check in checked arithmetic and slice in message coordinates.
    let start = 1usize
        .checked_add(dstart)
        .ok_or(GrpcFrameError::LengthOverflow)?;
    let end = start
        .checked_add(dlen)
        .ok_or(GrpcFrameError::LengthOverflow)?;
    if end > hunk.len() {
        return Ok(None);
    }
    Ok(Some(msg.slice(5 + start..5 + end)))
}

/// Decode a base-128 varint starting at `start`; returns (value, bytes).
fn varint_decode(buf: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut val = 0usize;
    let mut shift = 0;
    for (i, &b) in buf.iter().enumerate().skip(start) {
        val |= usize::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((val, i + 1 - start));
        }
        shift += 7;
        if shift >= usize::BITS {
            return None;
        }
    }
    None
}

/// Run the gRPC transport: h2 handshake over the (secured) stream, open the
/// single `/{service}/Tun` stream, return the bidirectional byte stream.
pub async fn connect(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let cfg = ctx.transport_grpc().ok_or_else(|| {
        NativeError::Config("grpc transport requested but config has no grpc settings".into())
    })?;
    let service = grpc_service_name(cfg);
    let path = grpc_path(cfg, &service);
    let authority = cfg
        .authority
        .as_deref()
        .filter(|a| !a.is_empty())
        .map_or_else(|| ctx.params.server.host.clone(), ToString::to_string);

    let handshake = h2::client::handshake(stream);
    let (mut send_req, conn) = tokio::time::timeout(timeouts::TRANSPORT, handshake)
        .await
        .map_err(|_| NativeError::Timeout {
            step: "grpc h2 handshake",
            limit: timeouts::TRANSPORT,
        })?
        .map_err(|e| NativeError::Transport(format!("grpc h2 handshake: {e}")))?;
    // Drive the h2 connection in the background for the stream's lifetime.
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = http::Request::builder()
        .method("POST")
        .uri(format!("https://{authority}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-accept-encoding", "identity")
        .header(
            "user-agent",
            cfg.user_agent
                .as_deref()
                .filter(|ua| !ua.is_empty())
                .unwrap_or("grpc-go/1.64.0"),
        )
        .body(())
        .map_err(|e| NativeError::Transport(format!("grpc request: {e}")))?;
    let (resp, send_stream) = send_req
        .send_request(req, false)
        .map_err(|e| NativeError::Transport(format!("grpc stream open: {e}")))?;
    // Do NOT block on the response headers here: xray's grpc `Tun` handler
    // defers its 200 until the first client DATA message (verified with
    // curl — no body hangs, body → 200). The protocol writes the VLESS
    // request as the first message; a background task hands the `RecvStream`
    // over once the server responds.
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let out = match tokio::time::timeout(timeouts::TRANSPORT, resp).await {
            Ok(Ok(r)) if r.status() == http::StatusCode::OK => Ok(r.into_body()),
            Ok(Ok(r)) => Err(NativeError::Transport(format!(
                "grpc stream rejected: {}",
                r.status()
            ))),
            Ok(Err(e)) => Err(NativeError::Transport(format!("grpc response: {e}"))),
            Err(_) => Err(NativeError::Timeout {
                step: "grpc response headers",
                limit: timeouts::TRANSPORT,
            }),
        };
        let _ = tx.send(out);
    });
    Ok(Box::new(GrpcStream::new(send_stream, rx)))
}

/// Single bidirectional gRPC stream: `AsyncWrite` prefixes + sends DATA
/// frames; `AsyncRead` parses the 5-byte prefix and yields payloads.
pub struct GrpcStream {
    send: SendStream<Bytes>,
    recv: Option<RecvStream>,
    response: Option<tokio::sync::oneshot::Receiver<Result<RecvStream, NativeError>>>,
    read_buf: BytesMut,
    /// Decoded Hunk payloads awaiting the app: `decode_frame` slices the
    /// frozen staging buffer, so queueing moves `Bytes` — no `to_vec`.
    queued: VecDeque<Bytes>,
}

impl GrpcStream {
    /// `response` resolves once the server replies to the first message;
    /// the read side starts pulling from it (the write side works at once).
    #[must_use]
    pub fn new(
        send: SendStream<Bytes>,
        response: tokio::sync::oneshot::Receiver<Result<RecvStream, NativeError>>,
    ) -> Self {
        Self {
            send,
            recv: None,
            response: Some(response),
            read_buf: BytesMut::new(),
            queued: VecDeque::new(),
        }
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(front) = self.queued.front_mut() {
                let n = std::cmp::min(front.len(), buf.remaining());
                buf.put_slice(&front[..n]);
                front.advance(n);
                if front.is_empty() {
                    self.queued.pop_front();
                }
                return Poll::Ready(Ok(()));
            }
            match decode_frame(&mut self.read_buf) {
                Ok(Some(msg)) => {
                    self.queued.push_back(msg);
                    continue;
                }
                // Partial frame: fall through and pull more bytes.
                Ok(None) => {}
                // Protocol violation (over-cap or overflow): fail the stream
                // instead of buffering the peer's bytes without bound.
                Err(e) => return Poll::Ready(Err(io::Error::other(e))),
            }
            if self.recv.is_none() {
                let rx = self
                    .response
                    .as_mut()
                    .expect("response channel present while recv unset");
                match Pin::new(rx).poll(cx) {
                    Poll::Ready(Ok(Ok(recv))) => {
                        self.recv = Some(recv);
                        self.response = None;
                        continue;
                    }
                    Poll::Ready(Ok(Err(e))) => {
                        return Poll::Ready(Err(io::Error::other(e)));
                    }
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "grpc response task dropped",
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            let recv = self.recv.as_mut().expect("recv set above");
            match Pin::new(recv).poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    // h2 flow control: the receive window does NOT
                    // auto-replenish — without release the server stops
                    // after one window (64 KiB default) and bulk recv
                    // stalls forever. We own these bytes now (buffered
                    // in `read_buf`), so release the full chunk.
                    let n = chunk.len();
                    self.read_buf.extend_from_slice(&chunk);
                    let _ = self
                        .recv
                        .as_mut()
                        .expect("recv set above")
                        .flow_control()
                        .release_capacity(n);
                }
                Poll::Ready(Some(Err(e))) => {
                    // A reset with NO_ERROR (grpc-go closes streams that
                    // way) is a clean end: report EOF so `read_to_end`
                    // completes. Any other reset is a real error.
                    if e.reason() == Some(h2::Reason::NO_ERROR) {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Ready(None) => {
                    // Clean end-of-stream (trailers): report EOF so
                    // `read_to_end` completes instead of erroring.
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Write-through: one gRPC message per write, chunked at 16 KiB so a
        // single message never exceeds the h2 flow window. `reserve` +
        // `poll_capacity` before consuming keeps the AsyncWrite contract
        // (Pending = nothing consumed).
        let take = buf.len().min(16384);
        let framed = encode_frame(&buf[..take]);
        self.send.reserve_capacity(framed.len());
        match Pin::new(&mut self.send).poll_capacity(cx) {
            Poll::Ready(Some(Ok(_))) => {}
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "grpc send stream closed",
                )));
            }
            Poll::Pending => return Poll::Pending,
        }
        if let Err(e) = self.send.send_data(framed, false) {
            return Poll::Ready(Err(io::Error::other(e)));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        // `poll_write` hands every message to h2's connection buffer via
        // `send_data` — there is no user-space buffer left to drain, so
        // flush is immediately ready (like a TCP write: delivery to the
        // transport, not to the peer; arrival pacing is the caller's job).
        // Waiting for window capacity here would hang: once everything
        // queued is transmitted, the windows sit empty with no new
        // WINDOW_UPDATEs coming, and `poll_capacity` pends forever (bulk
        // send over xray stalls at the first flush).
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        // End-of-stream: empty DATA frame with END_STREAM (SendStream has no
        // poll_close; send_data with eos=true is the shutdown signal).
        match self.send.send_data(Bytes::new(), true) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::other(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_proto::proto_spec::common::GrpcConfig;
    use rstest::rstest;

    #[rstest]
    #[case::short(b"hello vless".to_vec())]
    #[case::varint_two_byte(vec![0x42; 200])]
    #[case::empty(Vec::new())]
    fn frame_roundtrip(#[case] payload: Vec<u8>) {
        let framed = encode_frame(&payload);
        // gRPC prefix (flag 0 + BE hunk byte-len) + Hunk protobuf:
        // tag 0x0A + varint(data_len) + data.
        // `encode_varint_stack(n)` returns the varint BYTES, so the second
        // tuple element is the encoded width.
        let hunk_len = 1 + encode_varint_stack(payload.len()).1 + payload.len();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "gRPC frame-prefix bytes are u8 by wire spec; rstest clears fn-level attrs from the retained source fn, so the allow must be statement-level"
        )]
        let prefix = [0, 0, 0, (hunk_len >> 8) as u8, hunk_len as u8];
        assert_eq!(&framed[..5], &prefix);
        assert_eq!(framed[5], 0x0A);
        let mut buf = BytesMut::from(&framed[..]);
        assert_eq!(decode_frame(&mut buf), Ok(Some(Bytes::from(payload))));
        assert!(buf.is_empty());
    }

    #[rstest]
    #[case::short(b"abcdef".to_vec())]
    #[case::varint_two_byte(vec![0x42; 200])]
    #[case::empty(Vec::new())]
    fn frame_parse_splits_across_chunks(
        #[case] payload: Vec<u8>,
        #[values(0, 2, 5, 6)] split: usize,
    ) {
        let framed = encode_frame(&payload);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&framed[..split]);
        assert_eq!(decode_frame(&mut buf), Ok(None)); // partial frame
        buf.extend_from_slice(&framed[split..]);
        assert_eq!(decode_frame(&mut buf), Ok(Some(Bytes::from(payload))));
    }

    #[test]
    fn frame_parse_handles_multiple_messages() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_frame(b"one"));
        buf.extend_from_slice(&encode_frame(b"two"));
        assert_eq!(decode_frame(&mut buf), Ok(Some(Bytes::from_static(b"one"))));
        assert_eq!(decode_frame(&mut buf), Ok(Some(Bytes::from_static(b"two"))));
        assert!(buf.is_empty());
    }

    /// A peer-declared varint of `usize::MAX` must be rejected with checked
    /// arithmetic — the old `1 + dstart + dlen` panicked in debug and sliced
    /// `16..15` in release (finding f6).
    #[test]
    fn hostile_varint_length_is_rejected_not_panicking() {
        // gRPC prefix: flag 0, BE hunk len = 11 (tag + 10-byte varint).
        // Hunk: tag 0x0A + 10-byte protobuf varint = usize::MAX.
        let mut buf = BytesMut::from(
            &[
                0x00, 0x00, 0x00, 0x00, 0x0b, 0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0x01,
            ][..],
        );
        assert_eq!(decode_frame(&mut buf), Err(GrpcFrameError::LengthOverflow));
    }

    /// A peer-declared frame larger than `MAX_FRAME_LEN` must be refused
    /// before any buffering (finding f13).
    #[test]
    fn oversized_declared_frame_is_rejected() {
        let mut buf = BytesMut::from(&[0x00, 0xff, 0xff, 0xff, 0xff][..]);
        assert_eq!(
            decode_frame(&mut buf),
            Err(GrpcFrameError::FrameTooLarge(
                u32::MAX as usize,
                MAX_FRAME_LEN
            ))
        );
    }

    #[test]
    fn service_name_is_verbatim_no_default() {
        assert_eq!(grpc_service_name(&GrpcConfig::default()), "");
        let cfg = GrpcConfig {
            service_name: Some("gun".into()),
            ..Default::default()
        };
        assert_eq!(grpc_service_name(&cfg), "gun");
    }

    #[test]
    fn path_builds_slash_service_tun() {
        // Empty service → "//Tun", matching xray + sing-box path derivation.
        assert_eq!(grpc_path(&GrpcConfig::default(), ""), "//Tun");
        assert_eq!(grpc_path(&GrpcConfig::default(), "gun"), "/gun/Tun");
        let cfg = GrpcConfig {
            path: Some("/custom/path".into()),
            ..Default::default()
        };
        assert_eq!(grpc_path(&cfg, "gun"), "/custom/path");
    }
}
