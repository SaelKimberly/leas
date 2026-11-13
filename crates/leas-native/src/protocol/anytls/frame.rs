//! `AnyTLS` session frame codec.
//!
//! Wire format (`thirdparty/anytls-go/docs/protocol.md`, "会话"):
//!
//! ```text
//! | command : u8 | stream id : u32 BE | data length : u16 BE | data |
//! ```
//!
//! The header is always 7 bytes; the length field counts the data bytes only.
//! Commands 0–6 exist since protocol v1, 7–10 since v2.

/// The fixed header size every frame starts with.
pub const HEADER_LEN: usize = 7;

/// Maximum payload one frame can carry (`u16` length field).
pub const MAX_PAYLOAD: usize = u16::MAX as usize;

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;

/// A parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub command: u8,
    pub stream_id: u32,
    pub len: u16,
}

impl Header {
    #[must_use]
    pub const fn parse(raw: [u8; HEADER_LEN]) -> Self {
        Self {
            command: raw[0],
            stream_id: u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]),
            len: u16::from_be_bytes([raw[5], raw[6]]),
        }
    }

    #[must_use]
    pub const fn encode(self) -> [u8; HEADER_LEN] {
        let id = self.stream_id.to_be_bytes();
        let len = self.len.to_be_bytes();
        [self.command, id[0], id[1], id[2], id[3], len[0], len[1]]
    }
}

/// Append one complete frame to `out`.
///
/// `data.len()` must fit the `u16` length field; callers chunk payloads
/// (`session::write_data` splits at [`MAX_PAYLOAD`]).
pub fn push_frame(out: &mut Vec<u8>, command: u8, stream_id: u32, data: &[u8]) {
    let len = u16::try_from(data.len()).expect("frame payload exceeds u16");
    out.extend_from_slice(
        &Header {
            command,
            stream_id,
            len,
        }
        .encode(),
    );
    out.extend_from_slice(data);
}

/// Encode one frame into a fresh buffer.
#[must_use]
pub fn frame(command: u8, stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + data.len());
    push_frame(&mut out, command, stream_id, data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_is_big_endian() {
        let raw = [CMD_PSH, 0x01, 0x02, 0x03, 0x04, 0x00, 0x05];
        let h = Header::parse(raw);
        assert_eq!(h.command, CMD_PSH);
        assert_eq!(h.stream_id, 0x0102_0304);
        assert_eq!(h.len, 5);
        assert_eq!(h.encode(), raw);
    }

    #[test]
    fn frame_layout_is_cmd_id_len_data() {
        assert_eq!(
            frame(CMD_SYN, 7, b"ab"),
            vec![CMD_SYN, 0, 0, 0, 7, 0, 2, b'a', b'b']
        );
        // A control frame with no data is header-only.
        assert_eq!(frame(CMD_FIN, 1, &[]), vec![CMD_FIN, 0, 0, 0, 1, 0, 0]);
    }
}
