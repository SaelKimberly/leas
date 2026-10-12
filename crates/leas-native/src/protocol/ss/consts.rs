//! Constants and helpers shared by the two 2022-edition codecs: the TCP
//! stream ([`super::stream2022`]) and the UDP relay ([`super::udp`]).
//!
//! The spec fixes the padding ceiling and the timestamp window once for the
//! edition, so both codecs must agree; a second copy in either module lets one
//! drift silently from the other.

use std::time::{SystemTime, UNIX_EPOCH};

use leas_proto::proto_spec::ProtocolKind;

use crate::error::NativeError;

/// `MaxPaddingLength` (TCP) / `AEAD2022_MAX_PADDING_SIZE` (UDP): the largest
/// padding a 2022 request header or datagram may carry (spec §3.1.3, §3.2.3;
/// shadowsocks-rust `relay/mod.rs`).
pub(crate) const MAX_PADDING: u32 = 900;

/// Timestamp skew tolerated on a peer's timestamp: anything older or newer is
/// a replay (spec §3.2.3; shadowsocks-rust `SERVER_STREAM_TIMESTAMP_MAX_DIFF`
/// / `SERVER_PACKET_TIMESTAMP_MAX_DIFF`, v2ray-core's ±30 s).
pub(crate) const TIMESTAMP_TOLERANCE_SECS: u64 = 30;

/// Seconds since the UNIX epoch — the timestamp both codecs stamp and check.
///
/// A clock before the epoch cannot stamp a header anyone will accept, so the
/// failure is reported rather than panicked (shadowsocks-rust's
/// `get_now_timestamp` takes the panic). It is an I/O-class failure, NOT a
/// config one: `NativeError::Config` now means "this row can never dial as
/// stored", and a broken system clock says nothing about the row.
pub(crate) fn now_unix_secs() -> Result<u64, NativeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .map_err(|e| NativeError::Io(std::io::Error::other(e)))
}

/// A wire failure in the 2022 codec (`NativeError::Protocol` with the 2022
/// [`ProtocolKind`]) — one constructor for both codecs' classification.
pub(crate) fn s2022_error(detail: &str) -> NativeError {
    NativeError::Protocol {
        kind: ProtocolKind::Shadowsocks2022,
        detail: detail.to_owned(),
    }
}
