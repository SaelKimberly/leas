//! mKCP wire codec: byte-exact segment serialization per spec §4.1.
//!
//! Authority: `thirdparty/Xray-core/transport/internet/kcp/segment.go`
//! (xray-core 26.3.27). All integers big-endian; **one segment per UDP
//! datagram** (spec §4).
//!
//! Shape notes (documented decisions):
//! - [`parse_datagram`] returns `Option<Segment>` — a malformed datagram is
//!   dropped with a debug log, never fatal (spec §6), so there is no error
//!   variant worth carrying. `None` = truncated body, unknown command byte,
//!   or declared length exceeding the datagram.
//! - Conv is NOT filtered here: a mismatched conv still yields the segment;
//!   the session drops it (§5.2 Input). This mirrors Go, where the conv is
//!   parsed before any session lookup.
//! - The command byte is a closed enum (0..=3). Go's `ReadSegment` falls
//!   back to `CmdOnlySegment` for unknown cmds; we reject them as malformed
//!   instead — xray never sends other values, so interop is unaffected.
//! - The option byte is opaque, exactly like Go (`SegmentOption(buf[1])`):
//!   any value round-trips and is preserved; only `Close` carries meaning.
//! - Trailing bytes after a complete segment are ignored, mirroring
//!   `KCPPacketReader`'s loop over the `extra` returned by Go's
//!   `ReadSegment` (writers emit exactly one segment per datagram, so the
//!   tail is never a real segment in practice).
//! - One Go quirk is reproduced: `DataSegment.parse` requires ≥ 15 bytes
//!   after the prefix — the 14-byte fixed header *plus* at least one byte —
//!   so a wire Data segment with an empty payload (18 bytes total) is
//!   rejected, exactly as xray rejects it. Encoding such a segment still
//!   works (spec §4.1 layout); the session never sends one (mss payloads).

use bytes::Bytes;

/// Fixed overhead of a Data segment, `mtu - mss` (spec §4.1).
pub const DATA_SEGMENT_OVERHEAD: usize = 18;

/// KCP command byte (segment type), spec §4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// `AckSegment`.
    Ack = 0,
    /// `DataSegment`.
    Data = 1,
    /// `CmdOnlySegment`: peer terminates the connection.
    Terminate = 2,
    /// `CmdOnlySegment`: ping.
    Ping = 3,
}

impl Command {
    /// Parse a command byte; `None` for undefined values (0..=3 defined).
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ack),
            1 => Some(Self::Data),
            2 => Some(Self::Terminate),
            3 => Some(Self::Ping),
            _ => None,
        }
    }

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Segment option byte. Only `Close` (1) is defined; like Go, any byte is
/// accepted on parse and preserved verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentOption(u8);

impl SegmentOption {
    /// Set when the local state is `ReadyToClose` (spec §4.3).
    pub const CLOSE: Self = Self(1);

    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        Self(v)
    }

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn is_close(self) -> bool {
        self.0 == Self::CLOSE.0
    }
}

/// One mKCP wire segment (spec §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// `DataSegment` (cmd=1): `[conv u16][cmd=1 u8][opt u8][ts u32][sn u32]
    /// [una u32][len u16][payload]` — 18-byte header + payload.
    Data {
        conv: u16,
        opt: SegmentOption,
        ts: u32,
        sn: u32,
        una: u32,
        payload: Bytes,
    },
    /// `AckSegment` (cmd=0): `[conv u16][cmd=0 u8][opt u8][rcv_wnd u32]
    /// [rcv_nxt u32][ts u32][count u8][numbers u32*count]`.
    Ack {
        conv: u16,
        opt: SegmentOption,
        rcv_wnd: u32,
        rcv_nxt: u32,
        ts: u32,
        numbers: Vec<u32>,
    },
    /// `CmdOnlySegment` — Ping (cmd=3) and Terminate (cmd=2):
    /// `[conv u16][cmd u8][opt u8][snd_nxt u32][rcv_nxt u32][peer_rto u32]`
    /// — 16 bytes (the spec's "(14B)" label is a typo; Go's `ByteSize()` is
    /// 2+1+1+4+4+4 and its parse rule "needs 12 more" after the 4B prefix
    /// both give 16).
    CmdOnly {
        conv: u16,
        cmd: Command,
        opt: SegmentOption,
        snd_nxt: u32,
        rcv_nxt: u32,
        peer_rto: u32,
    },
}

/// Serialize one segment into `out`, clearing it first. The output is a
/// complete UDP datagram payload (one segment per datagram, spec §4).
///
/// The ack `count` is a single byte and the data `len` is u16, so the caller
/// must keep `numbers.len() <= u8::MAX` (session caps at 128,
/// `ackNumberLimit`) and `payload.len() <= u16::MAX` (session caps at mss).
/// Oversized inputs are clamped, mirroring Go's byte-truncating writes.
pub fn encode_segment(seg: &Segment, out: &mut Vec<u8>) {
    out.clear();
    match seg {
        Segment::Data {
            conv,
            opt,
            ts,
            sn,
            una,
            payload,
        } => {
            out.reserve(DATA_SEGMENT_OVERHEAD + payload.len());
            out.extend_from_slice(&conv.to_be_bytes());
            out.push(Command::Data.to_u8());
            out.push(opt.to_u8());
            out.extend_from_slice(&ts.to_be_bytes());
            out.extend_from_slice(&sn.to_be_bytes());
            out.extend_from_slice(&una.to_be_bytes());
            out.extend_from_slice(
                &u16::try_from(payload.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            out.extend_from_slice(payload);
        }
        Segment::Ack {
            conv,
            opt,
            rcv_wnd,
            rcv_nxt,
            ts,
            numbers,
        } => {
            out.reserve(17 + numbers.len() * 4);
            out.extend_from_slice(&conv.to_be_bytes());
            out.push(Command::Ack.to_u8());
            out.push(opt.to_u8());
            out.extend_from_slice(&rcv_wnd.to_be_bytes());
            out.extend_from_slice(&rcv_nxt.to_be_bytes());
            out.extend_from_slice(&ts.to_be_bytes());
            out.push(u8::try_from(numbers.len()).unwrap_or(u8::MAX));
            for n in numbers {
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
        Segment::CmdOnly {
            conv,
            cmd,
            opt,
            snd_nxt,
            rcv_nxt,
            peer_rto,
        } => {
            out.extend_from_slice(&conv.to_be_bytes());
            out.push(cmd.to_u8());
            out.push(opt.to_u8());
            out.extend_from_slice(&snd_nxt.to_be_bytes());
            out.extend_from_slice(&rcv_nxt.to_be_bytes());
            out.extend_from_slice(&peer_rto.to_be_bytes());
        }
    }
}

/// Parse one UDP datagram into at most one segment (spec §4.1).
///
/// Returns `None` for any malformed input: fewer than 4 prefix bytes, a
/// truncated body for the command, an unknown command byte, or a declared
/// data length exceeding the datagram — the caller drops it with a
/// `tracing::debug!` (spec §6, never fatal). A conv mismatch is NOT a parse
/// error: the segment is returned with its conv, and the session drops it.
/// Trailing bytes after the segment are ignored (see module docs).
#[must_use]
pub fn parse_datagram(buf: &[u8]) -> Option<Segment> {
    if buf.len() < 4 {
        return None;
    }
    let conv = u16::from_be_bytes([buf[0], buf[1]]);
    let opt = SegmentOption::from_u8(buf[3]);
    let body = &buf[4..];
    match Command::from_u8(buf[2]) {
        Some(Command::Data) => parse_data(conv, opt, body),
        Some(Command::Ack) => parse_ack(conv, opt, body),
        Some(cmd) => parse_cmd_only(conv, cmd, opt, body),
        None => None,
    }
}

fn parse_data(conv: u16, opt: SegmentOption, body: &[u8]) -> Option<Segment> {
    // Go's DataSegment.parse requires >= 15 bytes post-prefix: the 14-byte
    // fixed header plus at least one byte (an empty-payload Data segment is
    // rejected on the wire — see module docs).
    if body.len() < 15 {
        return None;
    }
    let ts = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let sn = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let una = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
    let len = usize::from(u16::from_be_bytes([body[12], body[13]]));
    let payload = &body[14..];
    if payload.len() < len {
        return None;
    }
    Some(Segment::Data {
        conv,
        opt,
        ts,
        sn,
        una,
        payload: Bytes::copy_from_slice(&payload[..len]),
    })
}

fn parse_ack(conv: u16, opt: SegmentOption, body: &[u8]) -> Option<Segment> {
    if body.len() < 13 {
        return None;
    }
    let rcv_wnd = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let rcv_nxt = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let ts = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
    let count = usize::from(body[12]);
    let numbers = &body[13..];
    if numbers.len() < count * 4 {
        return None;
    }
    let mut list = Vec::with_capacity(count);
    for chunk in numbers[..count * 4].as_chunks::<4>().0 {
        list.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Some(Segment::Ack {
        conv,
        opt,
        rcv_wnd,
        rcv_nxt,
        ts,
        numbers: list,
    })
}

const fn parse_cmd_only(
    conv: u16,
    cmd: Command,
    opt: SegmentOption,
    body: &[u8],
) -> Option<Segment> {
    if body.len() < 12 {
        return None;
    }
    Some(Segment::CmdOnly {
        conv,
        cmd,
        opt,
        snd_nxt: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
        rcv_nxt: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
        peer_rto: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(seg: &Segment) -> Vec<u8> {
        let mut out = Vec::new();
        encode_segment(seg, &mut out);
        out
    }

    fn data(conv: u16, opt: u8, payload: &[u8]) -> Segment {
        Segment::Data {
            conv,
            opt: SegmentOption::from_u8(opt),
            ts: 0x1122_3344,
            sn: 0x5566_7788,
            una: 0x99AA_BBCC,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    fn ack(conv: u16, opt: u8, numbers: &[u32]) -> Segment {
        Segment::Ack {
            conv,
            opt: SegmentOption::from_u8(opt),
            rcv_wnd: 0x0102_0304,
            rcv_nxt: 0x0506_0708,
            ts: 0x090A_0B0C,
            numbers: numbers.to_vec(),
        }
    }

    fn cmd_only(conv: u16, cmd: Command, opt: u8) -> Segment {
        Segment::CmdOnly {
            conv,
            cmd,
            opt: SegmentOption::from_u8(opt),
            snd_nxt: 0x0102_0304,
            rcv_nxt: 0x0506_0708,
            peer_rto: 0x090A_0B0C,
        }
    }

    #[test]
    fn data_layout() {
        // [conv u16][cmd=1][opt][ts u32][sn u32][una u32][len u16][payload]
        let out = enc(&data(0x1234, 0, &[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(
            out,
            [
                0x12, 0x34, // conv
                0x01, // cmd=Data
                0x00, // opt
                0x11, 0x22, 0x33, 0x44, // ts
                0x55, 0x66, 0x77, 0x88, // sn
                0x99, 0xAA, 0xBB, 0xCC, // una
                0x00, 0x04, // len
                0xDE, 0xAD, 0xBE, 0xEF, // payload
            ]
        );
        assert_eq!(out.len(), DATA_SEGMENT_OVERHEAD + 4);
    }

    #[test]
    fn data_opt_close() {
        // Close option flips only the opt byte (position 3).
        let out = enc(&data(0x1234, 1, &[0x01]));
        assert_eq!(
            out,
            [
                0x12, 0x34, 0x01, 0x01, // conv, cmd, opt=Close
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0x00, 0x01,
                0x01,
            ]
        );
    }

    #[test]
    fn data_empty_payload_encodes() {
        // Empty payload still serializes to the full 18-byte segment.
        let out = enc(&data(0x1234, 0, &[]));
        assert_eq!(
            out,
            [
                0x12, 0x34, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
                0xBB, 0xCC, 0x00, 0x00,
            ]
        );
        // Go's parse requires >= 15 post-prefix bytes, so the 18-byte form
        // (14-byte header, no payload) is rejected on the wire — reproduced.
        assert_eq!(parse_datagram(&out), None);
    }

    #[test]
    fn data_max_len_payload() {
        // len field is u16: 65535-byte payload encodes FFFF and round-trips.
        let payload = vec![0xAB; u16::MAX as usize];
        let out = enc(&data(0x1234, 0, &payload));
        assert_eq!(out.len(), DATA_SEGMENT_OVERHEAD + 65535);
        assert_eq!(&out[16..18], &[0xFF, 0xFF]);
        assert_eq!(out[18], 0xAB);
        assert_eq!(out[18 + 65534], 0xAB);
        let back = parse_datagram(&out).expect("max-len payload parses");
        assert_eq!(back, data(0x1234, 0, &payload));
    }

    #[test]
    fn ack_layout_empty() {
        // [conv u16][cmd=0][opt][rcv_wnd u32][rcv_nxt u32][ts u32][count u8]
        let out = enc(&ack(0x1234, 0, &[]));
        assert_eq!(
            out,
            [
                0x12, 0x34, // conv
                0x00, // cmd=Ack
                0x00, // opt
                0x01, 0x02, 0x03, 0x04, // rcv_wnd
                0x05, 0x06, 0x07, 0x08, // rcv_nxt
                0x09, 0x0A, 0x0B, 0x0C, // ts
                0x00, // count=0
            ]
        );
    }

    #[test]
    fn ack_layout_multi_numbers() {
        // count u8 + numbers u32*count, big-endian.
        let out = enc(&ack(0x1234, 0, &[0x0102_0304, 0x0506_0708, 0x090A_0B0C]));
        assert_eq!(
            out,
            [
                0x12, 0x34, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                0x0B, 0x0C, 0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                0x0C,
            ]
        );
    }

    #[test]
    fn ack_opt_close() {
        let out = enc(&ack(0x1234, 1, &[7]));
        assert_eq!(out[2], 0x00);
        assert_eq!(out[3], 0x01); // opt=Close
    }

    #[test]
    fn cmd_only_layout_ping_and_terminate() {
        // [conv u16][cmd][opt][snd_nxt u32][rcv_nxt u32][peer_rto u32] — 16B.
        let ping = enc(&cmd_only(0x1234, Command::Ping, 0));
        assert_eq!(
            ping,
            [
                0x12, 0x34, // conv
                0x03, // cmd=Ping
                0x00, // opt
                0x01, 0x02, 0x03, 0x04, // snd_nxt
                0x05, 0x06, 0x07, 0x08, // rcv_nxt
                0x09, 0x0A, 0x0B, 0x0C, // peer_rto
            ]
        );
        assert_eq!(ping.len(), 16);

        let term = enc(&cmd_only(0x1234, Command::Terminate, 1));
        assert_eq!(
            term,
            [
                0x12, 0x34, 0x02, 0x01, // conv, cmd=Terminate, opt=Close
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            ]
        );
    }

    #[test]
    fn parse_roundtrip_all_variants() {
        let cases = [
            data(0x1234, 0, b"hello"),
            data(0xABCD, 1, &[0x42]), // opt=Close, 1-byte payload
            data(0x0001, 0, &[0; 1]),
            ack(0x1234, 0, &[]),
            ack(0x1234, 1, &[1, 2, 3]),
            ack(0xFFFF, 0, &[0, 0xFFFF_FFFF, 0x7FFF_FFFF]),
            cmd_only(0x1234, Command::Ping, 0),
            cmd_only(0x1234, Command::Terminate, 1),
            cmd_only(0x5678, Command::Ping, 1),
        ];
        for seg in &cases {
            let back = parse_datagram(&enc(seg)).unwrap_or_else(|| {
                panic!("roundtrip parse failed for {seg:?}");
            });
            assert_eq!(&back, seg, "roundtrip mismatch");
        }
    }

    #[test]
    fn parse_conv_not_filtered() {
        // Conv mismatch is NOT a parse error: the segment keeps its conv and
        // the session drops it (§5.2 Input).
        let seg = data(0x1234, 0, &[1]);
        let back = parse_datagram(&enc(&seg)).expect("parses regardless of conv");
        assert_eq!(back, seg);
        let Segment::Data { conv, .. } = &back else {
            panic!("expected Data");
        };
        assert_eq!(*conv, 0x1234); // conv preserved; the session does the dropping
    }

    #[test]
    fn parse_truncated_rejected() {
        let truncated: Vec<Vec<u8>> = vec![
            vec![],                                    // zero-length datagram
            vec![0x12, 0x34, 0x01],                    // 3B prefix
            vec![0x12, 0x34, 0x00, 0x00],              // 4B prefix, Ack, no body
            vec![0x12, 0x34, 0x01, 0x00],              // 4B prefix, Data, no body
            vec![0x12, 0x34, 0x03, 0x00],              // 4B prefix, Ping, no body
            enc(&data(0x1234, 0, &[])),                // Data, 14B header, empty payload (Go quirk)
            enc(&data(0x1234, 0, &[]))[..17].to_vec(), // Data, 13B body
            enc(&ack(0x1234, 0, &[]))[..16].to_vec(),  // Ack, 12B body (no count byte)
            {
                // Ack count=3 but only 2 numbers present
                let mut v = enc(&ack(0x1234, 0, &[1, 2, 3]));
                v.truncate(4 + 13 + 8);
                v[16] = 3;
                v
            },
            enc(&cmd_only(0x1234, Command::Ping, 0))[..15].to_vec(), // CmdOnly, 11B body
        ];
        for datagram in &truncated {
            assert_eq!(
                parse_datagram(datagram),
                None,
                "expected None for {datagram:02X?}"
            );
        }
    }

    #[test]
    fn parse_declared_len_exceeds_datagram() {
        // len field claims 10 bytes but only 2 follow.
        let mut v = enc(&data(0x1234, 0, &[0xAA, 0xBB]));
        v[16..18].copy_from_slice(&[0x00, 0x0A]);
        assert_eq!(parse_datagram(&v), None);
    }

    #[test]
    fn parse_bad_cmd_rejected() {
        // Unknown command bytes (4 and 0x7F) are malformed — Go's
        // CmdOnly fallback is not reproduced (see module docs).
        let mut ping = enc(&cmd_only(0x1234, Command::Ping, 0));
        for bad in [0x04, 0x7F] {
            ping[2] = bad;
            assert_eq!(
                parse_datagram(&ping),
                None,
                "cmd {bad:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn parse_unknown_opt_preserved() {
        // The option byte is opaque, mirroring Go: any value round-trips.
        let seg = ack(0x1234, 0x40, &[9]);
        let back = parse_datagram(&enc(&seg)).expect("unknown opt parses");
        assert_eq!(back, seg);
        let Segment::Ack { opt, .. } = &back else {
            panic!("expected Ack");
        };
        assert!(!opt.is_close());
    }

    #[test]
    fn parse_ignores_trailing_bytes() {
        // One segment per datagram; a trailing tail is ignored like
        // KCPPacketReader's extra loop (which then finds no 4-byte prefix).
        let mut v = enc(&cmd_only(0x1234, Command::Ping, 0));
        v.extend_from_slice(&[0x99, 0x99]);
        assert_eq!(parse_datagram(&v), Some(cmd_only(0x1234, Command::Ping, 0)));
    }

    #[test]
    fn encode_clears_buffer() {
        // encode_segment always starts from an empty buffer.
        let mut out = enc(&cmd_only(0x1, Command::Ping, 0));
        let first = out.clone();
        encode_segment(&cmd_only(0x2, Command::Terminate, 0), &mut out);
        assert_eq!(out.len(), 16);
        assert_ne!(out, first);
        assert_eq!(out[0..2], [0x00, 0x02]);
    }

    #[test]
    fn command_and_option_roundtrip() {
        assert_eq!(Command::from_u8(0), Some(Command::Ack));
        assert_eq!(Command::from_u8(1), Some(Command::Data));
        assert_eq!(Command::from_u8(2), Some(Command::Terminate));
        assert_eq!(Command::from_u8(3), Some(Command::Ping));
        assert_eq!(Command::from_u8(4), None);
        assert_eq!(Command::from_u8(0xFF), None);
        for c in [
            Command::Ack,
            Command::Data,
            Command::Terminate,
            Command::Ping,
        ] {
            assert_eq!(Command::from_u8(c.to_u8()), Some(c));
        }
        assert!(SegmentOption::CLOSE.is_close());
        assert!(SegmentOption::from_u8(1).is_close());
        assert!(!SegmentOption::from_u8(0).is_close());
        assert!(!SegmentOption::from_u8(0x80).is_close());
        assert_eq!(SegmentOption::from_u8(0x80).to_u8(), 0x80);
    }
}
