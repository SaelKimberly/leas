//! Hysteria2 Gecko packet shaping (sans I/O).
//!
//! Gecko wraps Salamander: each QUIC **long-header** datagram (first byte bit
//! 7 set in the plaintext) is split into `2..=8` chunks, each emitted as
//! `[0x80][msgID][chunkIdx<<4 | totalChunks][padLen BE16][padding][chunk]`,
//! padded so the final Salamander datagram lands in `[min, max]`. QUIC short
//! header datagrams pass through untouched.
//!
//! Decryption is the caller's job (Salamander sits between this layer and the
//! socket), so every function here sees plaintext. The frame codec and the
//! reassembler hold no sockets, no clock and no wakers: the adapter in
//! `protocol/hysteria2/quic.rs` supplies `now`, the random draws and the
//! destination buffer.
//!
//! Reference: `thirdparty/hysteria/extras/obfs/{gecko.go,gecko_frame.go}`
//! (MIT) and the byte-identical
//! `thirdparty/Xray-core/transport/internet/finalmask/salamander/gecko.go`.

use std::net::SocketAddr;
use std::ops::Range;
use std::time::{Duration, Instant};

/// The 5-byte frame header (`geckoHeaderSize`).
pub const FRAME_HEADER_LEN: usize = 5;
/// Long-header fragment marker (`geckoFlagFragment`).
pub const FLAG_FRAGMENT: u8 = 0x80;
/// Fewest chunks one long header is split into (`geckoMinFragmentChunks`).
pub const MIN_CHUNKS: u8 = 2;
/// Most chunks one long header is split into (`geckoMaxFragmentChunks`).
pub const MAX_CHUNKS: u8 = 8;
/// Largest chunk a receiver buffers (`geckoBufferSize`).
pub const MAX_PACKET: usize = 2048;
/// Incomplete-message lifetime (`geckoReassemblyTTL`).
pub const REASSEMBLY_TTL: Duration = Duration::from_secs(8);
/// In-flight messages per socket (upstream's per-source cap).
pub const MAX_IN_FLIGHT: usize = 8;

/// One Gecko fragment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Random padding before the chunk.
    pub pad_len: u16,
    /// Message id; fresh per transmit attempt, wraps at 256.
    pub msg_id: u8,
    /// Zero-based chunk index; `< total_chunks`.
    pub chunk_idx: u8,
    /// Number of chunks in the message, `2..=8`.
    pub total_chunks: u8,
}

/// Why a frame could not be encoded or decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The output buffer is too small, or the input is shorter than the
    /// header plus its declared padding.
    Truncated,
    /// Not a fragment, or the chunk counters are out of range.
    Invalid,
}

/// Encode one frame: header, `fill_pad`-provided padding, then `payload`.
///
/// `fill_pad` receives the padding slice (its length is `h.pad_len`); the
/// adapter passes the shared non-secret RNG, tests pass a constant filler.
///
/// # Errors
///
/// [`FrameError::Invalid`] when `total_chunks`/`chunk_idx` are out of range;
/// [`FrameError::Truncated`] when `out` cannot hold the frame.
pub fn encode_frame_into(
    h: FrameHeader,
    payload: &[u8],
    out: &mut [u8],
    fill_pad: impl FnOnce(&mut [u8]),
) -> Result<usize, FrameError> {
    if h.total_chunks < MIN_CHUNKS || h.total_chunks > MAX_CHUNKS || h.chunk_idx >= h.total_chunks {
        return Err(FrameError::Invalid);
    }
    let needed = FRAME_HEADER_LEN + usize::from(h.pad_len) + payload.len();
    let Some(frame) = out.get_mut(..needed) else {
        return Err(FrameError::Truncated);
    };
    frame[0] = FLAG_FRAGMENT;
    frame[1] = h.msg_id;
    frame[2] = (h.chunk_idx << 4) | (h.total_chunks & 0x0f);
    frame[3..5].copy_from_slice(&h.pad_len.to_be_bytes());
    fill_pad(&mut frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + usize::from(h.pad_len)]);
    frame[FRAME_HEADER_LEN + usize::from(h.pad_len)..].copy_from_slice(payload);
    Ok(needed)
}

/// Decode one frame, returning its header and a zero-copy payload slice.
///
/// # Errors
///
/// [`FrameError::Truncated`] for a short header or a padding overrun;
/// [`FrameError::Invalid`] when the fragment marker is clear or the chunk
/// counters are out of range.
pub fn decode_frame(input: &[u8]) -> Result<(FrameHeader, &[u8]), FrameError> {
    let Some(head) = input.get(..FRAME_HEADER_LEN) else {
        return Err(FrameError::Truncated);
    };
    if head[0] & FLAG_FRAGMENT == 0 {
        return Err(FrameError::Invalid);
    }
    let h = FrameHeader {
        pad_len: u16::from_be_bytes([head[3], head[4]]),
        msg_id: head[1],
        chunk_idx: head[2] >> 4,
        total_chunks: head[2] & 0x0f,
    };
    if h.total_chunks < MIN_CHUNKS || h.total_chunks > MAX_CHUNKS || h.chunk_idx >= h.total_chunks {
        return Err(FrameError::Invalid);
    }
    let start = FRAME_HEADER_LEN + usize::from(h.pad_len);
    let Some(payload) = input.get(start..) else {
        return Err(FrameError::Truncated);
    };
    Ok((h, payload))
}

/// A `0..total` chunk split of a `len`-byte datagram: equal chunks with the
/// remainder in the last one (upstream `writeFragmented`).
#[must_use]
pub fn chunk_range(len: usize, total: u8, idx: u8) -> Range<usize> {
    debug_assert!(total >= MIN_CHUNKS && idx < total);
    let size = len / usize::from(total);
    if idx + 1 == total {
        idx as usize * size..len
    } else {
        idx as usize * size..(idx as usize + 1) * size
    }
}

/// Frames one long header uses: uniform in `2..=8` from a caller-supplied draw
/// (`randomFragmentChunks`).
#[must_use]
pub fn fragment_count(draw: u32) -> u8 {
    let span = u32::from(MAX_CHUNKS - MIN_CHUNKS + 1);
    MIN_CHUNKS + u8::try_from(draw % span).expect("draw % 7 fits u8")
}

/// Padding length that brings the salted frame to `[min, max]`
/// (`randomPadLen`), or `0` when the chunk alone already exceeds `max`.
///
/// `base` counts the 8-byte Salamander salt plus the 5-byte header, exactly
/// like upstream, because the padding is chosen for the on-wire datagram.
#[must_use]
pub fn pad_len(chunk_len: usize, min: u16, max: u16, draw: u32) -> u16 {
    let base = 8 + FRAME_HEADER_LEN + chunk_len;
    let lo = usize::from(min).max(base);
    let hi = usize::from(max);
    if lo > hi {
        return 0;
    }
    let span = hi - lo + 1;
    let draw = usize::try_from(draw).expect("u32 fits usize");
    u16::try_from(lo - base + draw % span).expect("pad within the window")
}

/// Outcome of [`GeckoReassembler::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// The message completed; the assembled datagram is `len` bytes in the
    /// caller's buffer.
    Complete(usize),
    /// The chunk was buffered; more are needed.
    Buffered,
    /// The datagram was dropped (duplicate, inconsistent, oversized, or the
    /// destination buffer was too small).
    Dropped,
}

/// One in-flight message slot.
#[derive(Debug)]
struct Entry {
    in_use: bool,
    peer: SocketAddr,
    msg_id: u8,
    deadline: Option<Instant>,
    total: u8,
    filled: u8,
    received: u8,
    chunks: [Vec<u8>; MAX_CHUNKS as usize],
}

impl Entry {
    fn empty() -> Self {
        Self {
            in_use: false,
            peer: SocketAddr::from(([0, 0, 0, 0], 0)),
            msg_id: 0,
            deadline: None,
            total: 0,
            filled: 0,
            received: 0,
            chunks: std::array::from_fn(|_| Vec::new()),
        }
    }

    fn reset(&mut self) {
        for chunk in &mut self.chunks {
            chunk.clear();
        }
        self.filled = 0;
        self.received = 0;
    }
}

/// Bounded, clock-injected reassembly of Gecko fragments.
///
/// At most [`MAX_IN_FLIGHT`] messages exist; each holds up to [`MAX_CHUNKS`]
/// chunk buffers that are cleared and reused, so steady-state pushes do not
/// allocate once a handshake has warmed the slots. Expired entries are swept
/// lazily on every push and the oldest is evicted when a new message needs a
/// free slot.
#[derive(Debug)]
pub struct GeckoReassembler {
    entries: [Entry; MAX_IN_FLIGHT],
}

impl Default for GeckoReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl GeckoReassembler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| Entry::empty()),
        }
    }

    /// Feed one decoded fragment. `now` comes from the adapter (this type
    /// never reads the clock); `out` receives the completed datagram.
    pub fn push(
        &mut self,
        peer: SocketAddr,
        h: FrameHeader,
        payload: &[u8],
        now: Instant,
        out: &mut [u8],
    ) -> Push {
        self.sweep(now);
        if h.total_chunks < MIN_CHUNKS
            || h.total_chunks > MAX_CHUNKS
            || h.chunk_idx >= h.total_chunks
            || payload.len() > MAX_PACKET
        {
            return Push::Dropped;
        }
        let slot = self
            .find(peer, h.msg_id)
            .unwrap_or_else(|| self.claim(peer, h.msg_id, h.total_chunks, now));
        let entry = &mut self.entries[slot];
        if entry.total != h.total_chunks {
            return Push::Dropped;
        }
        let bit = 1_u8 << h.chunk_idx;
        if entry.filled & bit != 0 {
            return Push::Dropped;
        }
        // Reuse the chunk buffer: `clear` keeps its capacity.
        let chunk = &mut entry.chunks[usize::from(h.chunk_idx)];
        chunk.clear();
        chunk.extend_from_slice(payload);
        entry.filled |= bit;
        entry.received += 1;
        if entry.received < entry.total {
            return Push::Buffered;
        }

        let total = usize::from(entry.total);
        let total_len: usize = entry.chunks[..total].iter().map(Vec::len).sum();
        if total_len > out.len() {
            self.release(slot);
            return Push::Dropped;
        }
        let mut off = 0;
        for chunk in &entry.chunks[..total] {
            out[off..off + chunk.len()].copy_from_slice(chunk);
            off += chunk.len();
        }
        self.release(slot);
        Push::Complete(total_len)
    }

    /// Number of in-flight messages (tests and diagnostics).
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.entries.iter().filter(|e| e.in_use).count()
    }

    fn sweep(&mut self, now: Instant) {
        for i in 0..self.entries.len() {
            if self.entries[i]
                .deadline
                .is_some_and(|deadline| now >= deadline)
            {
                self.release(i);
            }
        }
    }

    fn find(&self, peer: SocketAddr, msg_id: u8) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.in_use && e.peer == peer && e.msg_id == msg_id)
    }

    fn claim(&mut self, peer: SocketAddr, msg_id: u8, total: u8, now: Instant) -> usize {
        let slot = self
            .entries
            .iter()
            .position(|e| !e.in_use)
            .unwrap_or_else(|| {
                // Capacity eviction: the entry with the earliest deadline.
                let mut oldest = 0;
                for (i, e) in self.entries.iter().enumerate() {
                    if e.deadline < self.entries[oldest].deadline {
                        oldest = i;
                    }
                }
                oldest
            });
        let entry = &mut self.entries[slot];
        entry.reset();
        entry.in_use = true;
        entry.peer = peer;
        entry.msg_id = msg_id;
        entry.total = total;
        entry.deadline = Some(now + REASSEMBLY_TTL);
        slot
    }

    fn release(&mut self, slot: usize) {
        self.entries[slot].reset();
        self.entries[slot].in_use = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];

    fn no_pad(bytes: &mut [u8]) {
        bytes.fill(0x5a);
    }

    /// Upstream `TestEncodeDecodeFrame`: every total/index/padding combination
    /// round-trips with the header intact and the payload untouched.
    #[test]
    fn encode_decode_table() {
        for total in MIN_CHUNKS..=MAX_CHUNKS {
            for idx in 0..total {
                for pad in [0_u16, 1, 64, 127, 512, 1100] {
                    let h = FrameHeader {
                        pad_len: pad,
                        msg_id: 0xa5,
                        chunk_idx: idx,
                        total_chunks: total,
                    };
                    let mut out = vec![0_u8; FRAME_HEADER_LEN + usize::from(pad) + PAYLOAD.len()];
                    let n = encode_frame_into(h, &PAYLOAD, &mut out, no_pad).expect("encode");
                    assert_eq!(n, out.len());
                    let (got, body) = decode_frame(&out).expect("decode");
                    assert_eq!(got, h);
                    assert_eq!(body, PAYLOAD);
                    assert!(
                        out[FRAME_HEADER_LEN..FRAME_HEADER_LEN + usize::from(pad)]
                            .iter()
                            .all(|b| *b == 0x5a)
                    );
                }
            }
        }
    }

    /// Upstream `TestEncodeFrameRejectsInvalid` + short buffer.
    #[test]
    fn encode_rejects_invalid() {
        let mut out = [0_u8; 1024];
        for h in [
            FrameHeader {
                pad_len: 0,
                msg_id: 1,
                chunk_idx: 0,
                total_chunks: 0,
            },
            FrameHeader {
                pad_len: 0,
                msg_id: 1,
                chunk_idx: 0,
                total_chunks: 1,
            },
            FrameHeader {
                pad_len: 0,
                msg_id: 1,
                chunk_idx: 0,
                total_chunks: 9,
            },
            FrameHeader {
                pad_len: 0,
                msg_id: 1,
                chunk_idx: 4,
                total_chunks: 4,
            },
        ] {
            assert_eq!(
                encode_frame_into(h, &[0xff], &mut out, no_pad),
                Err(FrameError::Invalid),
                "{h:?}"
            );
        }
        let h = FrameHeader {
            pad_len: 8,
            msg_id: 1,
            chunk_idx: 0,
            total_chunks: 2,
        };
        let mut short = [0_u8; 5];
        assert_eq!(
            encode_frame_into(h, &[1, 2, 3], &mut short, no_pad),
            Err(FrameError::Truncated)
        );
    }

    /// Upstream `TestDecodeFrameRejectsInvalid`.
    #[test]
    fn decode_rejects_invalid() {
        let cases: [(&[u8], FrameError); 8] = [
            (&[], FrameError::Truncated),
            (&[0x80, 0x55, 0x22, 0x00], FrameError::Truncated),
            (&[0x00, 0x00, 0x22, 0x00, 0x00], FrameError::Invalid),
            (&[0x80, 0x00, 0x00, 0x00, 0x00], FrameError::Invalid),
            (&[0x80, 0x00, 0x01, 0x00, 0x00], FrameError::Invalid),
            (&[0x80, 0x00, 0x09, 0x00, 0x00], FrameError::Invalid),
            (&[0x80, 0x00, 0x44, 0x00, 0x00], FrameError::Invalid),
            (
                &[0x80, 0x00, 0x02, 0x00, 0x12, 0x01, 0x02],
                FrameError::Truncated,
            ),
        ];
        for (input, want) in cases {
            assert_eq!(decode_frame(input), Err(want), "{input:?}");
        }
    }

    #[test]
    fn fragment_ranges_cover_the_payload_exactly() {
        for len in [1_usize, 8, 1200, 1500, 2048] {
            for total in MIN_CHUNKS..=MAX_CHUNKS {
                let covered: usize = (0..total).map(|i| chunk_range(len, total, i).len()).sum();
                assert_eq!(covered, len, "len={len} total={total}");
                assert_eq!(chunk_range(len, total, 0).start, 0);
                assert_eq!(chunk_range(len, total, total - 1).end, len);
            }
        }
    }

    #[test]
    fn fragment_count_and_pad_stay_in_bounds() {
        for draw in [0_u32, 1, 6, 7, 8, 99, u32::MAX] {
            let n = fragment_count(draw);
            assert!((MIN_CHUNKS..=MAX_CHUNKS).contains(&n));
        }
        for chunk_len in [0_usize, 1, 500, 1200, 2048] {
            for draw in [0_u32, 1, 400, u32::MAX] {
                let pad = pad_len(chunk_len, 512, 1200, draw);
                let wire = 8 + FRAME_HEADER_LEN + chunk_len + usize::from(pad);
                if 8 + FRAME_HEADER_LEN + chunk_len > 1200 {
                    assert_eq!(pad, 0, "chunk_len={chunk_len}");
                } else {
                    assert!((512..=1200).contains(&wire), "wire={wire}");
                }
            }
        }
        // min is raised to the base when the chunk is already larger.
        for draw in [0_u32, 1, 187, u32::MAX] {
            let pad = usize::from(pad_len(1000, 512, 1200, draw));
            let wire = 8 + FRAME_HEADER_LEN + 1000 + pad;
            assert!((1013..=1200).contains(&wire), "wire={wire} draw={draw}");
        }
    }

    fn push_bytes(
        r: &mut GeckoReassembler,
        peer: SocketAddr,
        msg_id: u8,
        idx: u8,
        total: u8,
        payload: &[u8],
        now: Instant,
    ) -> Push {
        let mut out = [0_u8; MAX_PACKET];
        r.push(
            peer,
            FrameHeader {
                pad_len: 0,
                msg_id,
                chunk_idx: idx,
                total_chunks: total,
            },
            payload,
            now,
            &mut out,
        )
    }

    #[test]
    fn reassembles_out_of_order_and_interleaved() {
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut r = GeckoReassembler::new();
        let mut out = [0_u8; MAX_PACKET];

        // Another message interleaves with the first.
        assert_eq!(
            push_bytes(&mut r, peer, 1, 0, 3, b"aa", now),
            Push::Buffered
        );
        assert_eq!(
            push_bytes(&mut r, peer, 2, 0, 2, b"zz", now),
            Push::Buffered
        );
        assert_eq!(
            push_bytes(&mut r, peer, 1, 2, 3, b"cc", now),
            Push::Buffered
        );

        let p = r.push(
            peer,
            FrameHeader {
                pad_len: 0,
                msg_id: 1,
                chunk_idx: 1,
                total_chunks: 3,
            },
            b"bb",
            now,
            &mut out,
        );
        assert_eq!(p, Push::Complete(6));
        assert_eq!(&out[..6], b"aabbcc");
        assert_eq!(r.in_flight(), 1, "message 2 still incomplete");

        let p = r.push(
            peer,
            FrameHeader {
                pad_len: 0,
                msg_id: 2,
                chunk_idx: 1,
                total_chunks: 2,
            },
            b"yy",
            now,
            &mut out,
        );
        assert_eq!(p, Push::Complete(4));
        assert_eq!(&out[..4], b"zzyy");
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn duplicates_and_inconsistent_frames_drop() {
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut r = GeckoReassembler::new();
        assert_eq!(
            push_bytes(&mut r, peer, 3, 0, 3, b"aa", now),
            Push::Buffered
        );
        assert_eq!(push_bytes(&mut r, peer, 3, 0, 3, b"aa", now), Push::Dropped);
        assert_eq!(push_bytes(&mut r, peer, 3, 1, 4, b"bb", now), Push::Dropped);
        assert_eq!(r.in_flight(), 1);
        // A second peer is a distinct message.
        let other: SocketAddr = "127.0.0.1:444".parse().unwrap();
        assert_eq!(
            push_bytes(&mut r, other, 3, 0, 3, b"xx", now),
            Push::Buffered
        );
    }

    #[test]
    fn missing_chunk_never_completes() {
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut r = GeckoReassembler::new();
        assert_eq!(push_bytes(&mut r, peer, 4, 0, 3, b"a", now), Push::Buffered);
        assert_eq!(push_bytes(&mut r, peer, 4, 2, 3, b"c", now), Push::Buffered);
        assert_eq!(r.in_flight(), 1);
    }

    #[test]
    fn ttl_expiry_frees_the_slot_and_reuses_the_msg_id() {
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut r = GeckoReassembler::new();
        assert_eq!(
            push_bytes(&mut r, peer, 5, 0, 2, b"aa", now),
            Push::Buffered
        );
        assert_eq!(
            push_bytes(&mut r, peer, 5, 1, 2, b"bb", now + REASSEMBLY_TTL),
            Push::Buffered,
            "the expired chunk 0 was swept, so this is a fresh message"
        );
        assert_eq!(
            push_bytes(&mut r, peer, 5, 0, 2, b"aa", now + REASSEMBLY_TTL),
            Push::Complete(4),
            "the reused msgID completes with its own chunks"
        );
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn capacity_evicts_the_oldest_message() {
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut r = GeckoReassembler::new();
        for msg in 0..u8::try_from(MAX_IN_FLIGHT).unwrap() {
            assert_eq!(
                push_bytes(
                    &mut r,
                    peer,
                    msg,
                    0,
                    2,
                    b"x",
                    now + Duration::from_millis(u64::from(msg))
                ),
                Push::Buffered
            );
        }
        assert_eq!(r.in_flight(), MAX_IN_FLIGHT);
        // A ninth message evicts msg 0, the earliest deadline.
        assert_eq!(
            push_bytes(&mut r, peer, 99, 0, 2, b"y", now),
            Push::Buffered
        );
        assert_eq!(r.in_flight(), MAX_IN_FLIGHT);
        // The evicted message's remaining chunk starts a fresh entry.
        assert_eq!(push_bytes(&mut r, peer, 0, 1, 2, b"z", now), Push::Buffered);
    }

    #[test]
    fn destination_too_small_drops_and_releases() {
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut r = GeckoReassembler::new();
        let mut tiny = [0_u8; 4];
        assert_eq!(
            push_bytes(&mut r, peer, 6, 0, 2, b"aaa", now),
            Push::Buffered
        );
        let p = r.push(
            peer,
            FrameHeader {
                pad_len: 0,
                msg_id: 6,
                chunk_idx: 1,
                total_chunks: 2,
            },
            b"bbb",
            now,
            &mut tiny,
        );
        assert_eq!(p, Push::Dropped);
        assert_eq!(r.in_flight(), 0);
    }

    /// Warm loop: after the first handshake-sized burst the slot count stops
    /// growing (the structural proxy for "no steady-state allocation").
    #[test]
    fn warm_loop_reuses_slots() {
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut now = Instant::now();
        let mut r = GeckoReassembler::new();
        let mut out = [0_u8; MAX_PACKET];
        for round in 0..16_u8 {
            now += Duration::from_secs(9);
            for idx in 0..MAX_CHUNKS {
                let p = r.push(
                    peer,
                    FrameHeader {
                        pad_len: 0,
                        msg_id: round,
                        chunk_idx: idx,
                        total_chunks: MAX_CHUNKS,
                    },
                    &[idx; 32],
                    now,
                    &mut out,
                );
                if idx + 1 == MAX_CHUNKS {
                    assert_eq!(p, Push::Complete(32 * usize::from(MAX_CHUNKS)));
                } else {
                    assert_eq!(p, Push::Buffered);
                }
            }
            assert_eq!(r.in_flight(), 0);
        }
    }

    #[test]
    fn oversized_chunk_drops() {
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut r = GeckoReassembler::new();
        assert_eq!(
            push_bytes(&mut r, peer, 8, 0, 2, &[0; MAX_PACKET + 1], now),
            Push::Dropped
        );
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn entry_shape_matches_upstream_frame() {
        // A frame built by hand decodes to the documented byte layout:
        // 0x80 | msgID | idx<<4|total | padLen BE16 | padding | chunk.
        let frame = [0x80, 0x2a, 0x23, 0x00, 0x02, 0xaa, 0xbb, 0xcc];
        let (h, body) = decode_frame(&frame).expect("decode");
        assert_eq!(
            h,
            FrameHeader {
                pad_len: 2,
                msg_id: 0x2a,
                chunk_idx: 2,
                total_chunks: 3
            }
        );
        assert_eq!(body, &[0xcc]);
        // The encoded form is the same header, big-endian padding length.
        let mut out = [0_u8; 8];
        let n = encode_frame_into(h, &[0xcc], &mut out, no_pad).expect("encode");
        assert_eq!(n, 8);
        assert_eq!(&out[..5], &frame[..5]);
        assert_eq!(&out[5..7], &[0x5a, 0x5a], "padding from the filler");
        assert_eq!(out[7], 0xcc);
    }
}
