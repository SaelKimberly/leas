//! Hysteria2 — native client (`ConnectShape::Quic`).
//!
//! Wire contract: the hysteria2 client (`thirdparty/hysteria`, MIT; sing-box
//! uses the same wire via `sing-quic`). The link is a QUIC connection with
//! ALPN `h3`:
//! 1. **Auth** — an HTTP/3 POST `https://hysteria/auth` carrying the
//!    password in the `hysteria-auth` request header (+ the client's max
//!    receive bandwidth in `hysteria-cc-rx`); status 233 = OK. The response
//!    headers announce UDP relay (`Hysteria-UDP`) and the server's bandwidth
//!    policy (`Hysteria-CC-RX`).
//! 2. **TCP tunnel** — open a RAW QUIC bidi stream (not h3-framed), write
//!    the `TCPRequest` frame (`0x401 | addrLen | addr | padLen | padding`),
//!    read the `TCPResponse` (status byte 0 = OK), then relay the bytes.
//! 3. **UDP relay** — QUIC DATAGRAM frames carrying the `UDPMessage`
//!    (`sessionID u32 BE | packetID u16 BE | fragID u8 | fragCount u8 |
//!    addrLen varint | addr | payload`), with fragmentation on
//!    `DatagramTooLarge` and per-session defragmentation
//!    ([`udp::UdpConn`]).
//!
//! Optional Salamander packet obfuscation wraps the UDP datagrams
//! (`crypto/salamander`).

use leas_proto::proto_spec::Hysteria2Config;

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::NativeError;

mod quic;
pub mod udp;

/// The h3 ALPN used for the QUIC handshake (`http3.NextProtoH3`).
const ALPN_H3: &[u8] = b"h3";

/// QUIC frame type for a TCP request (`FrameTypeTCPRequest`).
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
/// Overflow guard (`MaxAddressLength`).
const MAX_ADDRESS_LEN: usize = 2048;

/// TCP response status byte: `0` = OK, anything else = the remote error
/// message follows.
const TCP_RESPONSE_OK: u8 = 0;

/// Parse a Hysteria bandwidth string (`"100 mbps"`, `"512kbps"`, `"1g"`) to
/// bytes per second — the `hysteria-cc-rx` wire value (hysteria
/// `utils.StringToBps`; decimal multipliers, `/8` to bytes). `None` when the
/// string has no digits, carries an unknown unit, or overflows `u64`.
#[must_use]
pub(crate) fn bandwidth_bps(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let value: u64 = digits.parse().ok()?;
    let unit = s[digits.len()..].trim();
    let mult: u64 = match unit {
        "b" | "bps" => 1,
        "k" | "kb" | "kbps" => 1_000,
        "m" | "mb" | "mbps" => 1_000_000,
        "g" | "gb" | "gbps" => 1_000_000_000,
        "t" | "tb" | "tbps" => 1_000_000_000_000,
        _ => return None,
    };
    // `down` comes straight from a share link: refuse an overflowing
    // multiplier instead of wrapping (or panicking in debug).
    value.checked_mul(mult).map(|bps| bps / 8)
}

/// Connect through a Hysteria2 outbound.
///
/// Replaces the dial + security + upgrade chain entirely: a fresh QUIC dial
/// (spec §5.2 — quinn's rustls is internal) with ALPN `h3`, the auth
/// exchange, then one open TCP tunnel to `ctx.target`.
pub async fn connect(ctx: &LinkContext, cfg: &Hysteria2Config) -> Result<BoxStream, NativeError> {
    let (conn, auth) = quic::dial(ctx, cfg).await?;
    let stream = quic::open_tcp_tunnel(&conn, auth.keepalive, &ctx.target).await?;
    Ok(Box::new(stream))
}

/// Connect through a Hysteria2 outbound with a UDP datagram tunnel.
///
/// Runs the same QUIC dial + auth as [`connect`], then — if the server
/// enabled UDP (`Hysteria-UDP` response header) — returns the
/// [`udp::UdpConn`] datagram API over QUIC DATAGRAM frames
/// ([`udp::UdpConn`]: `UDPMessage` framing + fragmentation).
///
/// `ctx.target` becomes the session destination: a
/// [`send`](udp::UdpConn::send) without a per-packet address carries it.
pub async fn connect_udp(
    ctx: &LinkContext,
    cfg: &Hysteria2Config,
) -> Result<udp::UdpConn, NativeError> {
    let (conn, auth) = quic::dial(ctx, cfg).await?;
    if !auth.udp_enabled {
        return Err(NativeError::Protocol {
            kind: leas_proto::proto_spec::ProtocolKind::Hysteria2,
            detail: "server disabled UDP relay (Hysteria-UDP response header absent or false)"
                .into(),
        });
    }
    Ok(udp::UdpConn::new(
        conn,
        auth.keepalive,
        quic::target_string(&ctx.target),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_bps_parses_units() {
        assert_eq!(bandwidth_bps("100 mbps"), Some(100 * 1_000_000 / 8));
        assert_eq!(bandwidth_bps("100mbps"), Some(100 * 1_000_000 / 8));
        assert_eq!(bandwidth_bps("512 kbps"), Some(512 * 1_000 / 8));
        assert_eq!(bandwidth_bps("1g"), Some(1_000_000_000 / 8));
        assert_eq!(bandwidth_bps("10"), None);
        assert_eq!(bandwidth_bps(""), None);
        assert_eq!(bandwidth_bps("fast"), None);
        // A bandwidth that overflows u64 bits/sec is refused, not wrapped.
        assert_eq!(bandwidth_bps("99999999999999999t"), None);
        assert_eq!(bandwidth_bps("18446744073709551615g"), None);
    }
}
