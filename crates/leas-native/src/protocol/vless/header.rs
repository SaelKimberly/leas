//! VLESS wire header codec (client side).
//!
//! Request header (v2ray `proxy/vless/encoding/encoding.go`,
//! `EncodeRequestHeader`): `version(1B, 0) | uuid(16B) | addon_len(1B) |
//! addons | command(1B) | [addr+port]`, with the addr encoded
//! PORT-FIRST (`PortThenAddress`). The `[addr+port]` is present only for
//! commands 0x01 TCP and 0x02 UDP; command 0x03 MUX (and 0x04 Rvs)
//! carries NO destination bytes — `EncodeRequestHeader` skips the address
//! for those commands and the server derives the fixed `v1.mux.cool` fqdn
//! from the command byte alone (`DecodeRequestHeader`). Command: 0x01 TCP,
//! 0x02 UDP, 0x03 MUX, 0x04 Rvs.
//! Response header: `version(1B, echoed 0) | addon_len(1B) | addons`.

use crate::addr::{TargetAddr, encode_addr};
use crate::error::NativeError;
use crate::protocol::vless::vision::{FLOW_XTLS_RPRX_VISION, FLOW_XTLS_RPRX_VISION_UDP443};

pub const VERSION: u8 = 0;
pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;
pub const CMD_MUX: u8 = 3;

/// UUID bytes from a canonical UUID string.
pub fn uuid_bytes(uuid_str: &str) -> Result<[u8; 16], NativeError> {
    uuid::Uuid::parse_str(uuid_str)
        .map(|u| *u.as_bytes())
        .map_err(|e| NativeError::Config(format!("invalid uuid {uuid_str:?}: {e}")))
}

/// Protobuf addons bytes for the flow (spec §4.1): field 1 (string Flow),
/// tag `0x0A`, length `0x10`, 16 bytes `"xtls-rprx-vision"` → 18 bytes
/// total. Returns `None` for empty/unknown flows (`addon_len` stays 0).
/// The client sends no `Seed` (field 2 unset) — `addons.proto` declares
/// `Flow = 1`.
///
/// The udp443 variant is truncated to the first 16 bytes on the wire —
/// xray `outbound.go`: `requestAddons.Flow = requestAddons.Flow[:16]`
/// (spec §4.3) — so both vision flows encode the identical addon.
pub(crate) fn encode_addons(flow: Option<&str>) -> Option<Vec<u8>> {
    flow.and_then(|f| {
        let vision = match f {
            FLOW_XTLS_RPRX_VISION | FLOW_XTLS_RPRX_VISION_UDP443 => FLOW_XTLS_RPRX_VISION,
            _ => return None,
        };
        let mut b = Vec::with_capacity(18);
        b.push(0x0A);
        b.push(16);
        b.extend_from_slice(vision.as_bytes());
        Some(b)
    })
}

/// Encode a VLESS request header (version 0). `addons` are the flow addons
/// from [`encode_addons`] (`None` → `addon_len` 0, the no-flow wire form).
pub fn encode_request(
    uuid: &[u8; 16],
    target: &TargetAddr,
    command: u8,
    addons: Option<&[u8]>,
) -> Result<Vec<u8>, NativeError> {
    let mut out = Vec::with_capacity(32);
    out.push(VERSION);
    out.extend_from_slice(uuid);
    // addon_len is one byte; the only addon source is `encode_addons`
    // (18 bytes), so the conversion cannot fail.
    out.push(addons.map_or(0, |a| {
        u8::try_from(a.len()).expect("vless addons fit in one length byte")
    }));
    if let Some(a) = addons {
        out.extend_from_slice(a);
    }
    out.push(command);
    match command {
        CMD_TCP | CMD_UDP => {
            out.extend_from_slice(&encode_addr(target)?);
        }
        // CMD_MUX (0x03) carries NO destination on the wire: xray's
        // `EncodeRequestHeader` skips the address for the Mux/Rvs commands
        // (`proxy/vless/encoding/encoding.go`) and the server derives the
        // magic `v1.mux.cool` fqdn from the command byte alone
        // (`DecodeRequestHeader`); mihomo's sing-vmess client writes only
        // `CommandMux` too. `target` is the tunnel's semantic destination
        // (`v1.mux.cool:9527`, spec §4.1) and is not encoded.
        _ => {}
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Host;

    const UUID_STR: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";

    fn uuid() -> [u8; 16] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]
    }

    #[test]
    fn tcp_request_header_bytes_exact() {
        let target = TargetAddr::new(Host::new("127.0.0.1"), 8080);
        let got = encode_request(&uuid(), &target, CMD_TCP, None).unwrap();
        // version, uuid, addon_len=0, cmd=1, port 0x1f90, type=1, 127.0.0.1
        let mut expected = vec![0x00];
        expected.extend_from_slice(&uuid());
        expected.push(0x00);
        expected.push(0x01);
        expected.extend_from_slice(&[0x1f, 0x90, 0x01, 127, 0, 0, 1]);
        assert_eq!(got, expected);
    }

    #[test]
    fn mux_request_header_has_no_destination() {
        // Command 0x03 ENDS the header — no address bytes follow: xray's
        // `EncodeRequestHeader` skips the address for Mux/Rvs and the
        // server derives `v1.mux.cool` from the command byte alone, so any
        // trailing bytes would be misparsed as the first mux frame's
        // meta_len. The destination argument is the tunnel's semantic
        // target (`v1.mux.cool:9527`) and is not encoded.
        let mux_target = TargetAddr::new(Host::Domain("v1.mux.cool".into()), 9527);
        let got = encode_request(&uuid(), &mux_target, CMD_MUX, None).unwrap();
        let mut expected = vec![0x00];
        expected.extend_from_slice(&uuid());
        expected.push(0x00); // addon_len 0
        expected.push(0x03); // cmd MUX
        assert_eq!(got, expected);
        assert_eq!(got.len(), 19);
    }

    #[test]
    fn encode_addons_vision_bytes_exact() {
        let got = encode_addons(Some("xtls-rprx-vision")).expect("vision flow encodes");
        // protobuf field 1 (Flow, wire type 2): tag 0x0A, len 0x10, 16 bytes.
        let mut expected = vec![0x0A, 0x10];
        expected.extend_from_slice(b"xtls-rprx-vision");
        assert_eq!(got, expected);
        assert_eq!(got.len(), 18);
    }

    #[test]
    fn flow_udp443_truncated_to_vision() {
        // The udp443 flow is truncated to the first 16 bytes on the wire —
        // xray `requestAddons.Flow[:16]` (spec §4.3) — so the addon is
        // byte-identical to the plain vision addon.
        let got = encode_addons(Some("xtls-rprx-vision-udp443")).expect("udp443 flow encodes");
        let mut expected = vec![0x0A, 0x10];
        expected.extend_from_slice(b"xtls-rprx-vision");
        assert_eq!(got, expected);
        assert_eq!(got.len(), 18);
    }

    #[test]
    fn encode_addons_rejects_other_and_empty_flows() {
        assert_eq!(encode_addons(Some("xtls-rprx-splice")), None);
        assert_eq!(encode_addons(Some("")), None);
        assert_eq!(encode_addons(None), None);
    }

    #[test]
    fn request_header_with_flow_addons_bytes_exact() {
        let target = TargetAddr::new(Host::new("127.0.0.1"), 8080);
        let addons = encode_addons(Some("xtls-rprx-vision")).unwrap();
        let got = encode_request(&uuid(), &target, CMD_TCP, Some(&addons)).unwrap();
        // version, uuid, addon_len=18, addons, cmd=1, port 0x1f90, type=1, 127.0.0.1
        let mut expected = vec![0x00];
        expected.extend_from_slice(&uuid());
        expected.push(18);
        expected.extend_from_slice(&addons);
        expected.push(0x01);
        expected.extend_from_slice(&[0x1f, 0x90, 0x01, 127, 0, 0, 1]);
        assert_eq!(got, expected);
    }

    #[test]
    fn uuid_parse_match_expected_bytes() {
        assert_eq!(uuid_bytes(UUID_STR).unwrap(), uuid());
        assert!(uuid_bytes("not-a-uuid").is_err());
    }
}
