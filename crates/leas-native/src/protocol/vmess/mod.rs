//! `VMess` — native client (modern AEAD, xtls dialect).
//!
//! Wire contract: `thirdparty/Xray-core/proxy/vmess/encoding/{client,encoding,server}.go`
//! and `proxy/vmess/aead/` (MIT). Payload security: AES-128-GCM or
//! chacha20-poly1305; xray-core 26.x refuses `none`/`zero`/`auto` body
//! streams server-side.

use tokio::io::AsyncWriteExt;

use leas_proto::proto_spec::VmessConfig;

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};
use crate::protocol::vmess::header::{
    SECURITY_AES128_GCM, SECURITY_CHACHA20_POLY1305, Session, encode_request,
};
use crate::protocol::vmess::keys::cmd_key;
use crate::protocol::vmess::stream::VmessClientStream;

pub mod header;
pub mod keys;
pub mod stream;
pub mod udp;

/// Validate the `VMess` payload security the config requests.
pub fn check_security(cfg: &VmessConfig) -> Result<(), NativeError> {
    security_byte(cfg).map(|_| ())
}

/// Map the requested `security.enc` to the header security byte.
pub fn security_byte(cfg: &VmessConfig) -> Result<u8, NativeError> {
    match cfg.security.enc.as_deref() {
        None | Some("" | "auto" | "aes-128-gcm") => Ok(SECURITY_AES128_GCM),
        Some("chacha20-poly1305") => Ok(SECURITY_CHACHA20_POLY1305),
        Some(other) => Err(NativeError::Config(format!(
            "vmess payload security {other:?} not supported (native core: aes-128-gcm, chacha20-poly1305)"
        ))),
    }
}

/// Write the AEAD request header for `command` and wrap the stream in the
/// record tunnel — the ONE `VMess` handshake, shared by [`connect`]
/// (command 1) and [`connect_udp`] (command 2). `step` names the write for
/// the timeout error.
async fn handshake(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &VmessConfig,
    command: u8,
    step: &'static str,
) -> Result<VmessClientStream, NativeError> {
    check_security(cfg)?;
    let uuid = crate::protocol::vless::header::uuid_bytes(&cfg.uuid)?;
    let ck = cmd_key(&uuid);
    let mut session = Session::new();
    session.security = security_byte(cfg)?;

    let mut entropy = |out: &mut [u8]| {
        use ring::rand::{SecureRandom, SystemRandom};
        SystemRandom::new().fill(out).expect("rng failure");
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0);
    let request = encode_request(&ck, &session, &ctx.target, command, ts, &mut entropy)?;
    let timeout = timeouts::PROTOCOL;
    let mut stream = stream;
    tokio::time::timeout(timeout, stream.write_all(&request))
        .await
        .map_err(|_| NativeError::Timeout {
            step,
            limit: timeout,
        })??;

    Ok(VmessClientStream::new(stream, session))
}

/// Connect through a `VMess` outbound over an already-secured stream.
pub async fn connect(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &VmessConfig,
) -> Result<BoxStream, NativeError> {
    let tunnel = handshake(ctx, stream, cfg, header::COMMAND_TCP, "vmess request write").await?;
    Ok(Box::new(tunnel))
}

/// Connect through a `VMess` outbound with a UDP datagram tunnel (command
/// 0x02).
///
/// The request header carries command `0x02` and the destination; each
/// datagram is one AEAD record over the tunnel (no per-packet address) —
/// the `udp::PacketConn` view over the [`VmessClientStream`], which keeps
/// the header destination so a `send` naming a different one is refused
/// rather than mis-routed.
pub async fn connect_udp(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &VmessConfig,
) -> Result<udp::PacketConn<BoxStream>, NativeError> {
    let tunnel = handshake(
        ctx,
        stream,
        cfg,
        header::COMMAND_UDP,
        "vmess udp request write",
    )
    .await?;
    Ok(udp::PacketConn::new(tunnel, &ctx.target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn vcfg(enc: &str) -> VmessConfig {
        serde_json::from_value(serde_json::json!({
            "schema": "Vmess",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "security": { "enc": enc },
            "transport": { "type": "tcp" }
        }))
        .expect("vmess config parses")
    }

    #[test]
    fn rejects_none_zero_payload_security() {
        for enc in ["none", "zero"] {
            let cfg = vcfg(enc);
            assert!(
                matches!(check_security(&cfg), Err(NativeError::Config(_))),
                "{enc}"
            );
        }
    }

    /// The security gate accepts the AEAD names plus the `auto`/absent
    /// spellings; chacha20 maps to its wire byte (AES is the default).
    #[rstest]
    #[case::aes128_gcm(Some("aes-128-gcm"), None)]
    #[case::auto(Some("auto"), None)]
    #[case::empty_enc(Some(""), None)]
    #[case::absent_key(None, None)]
    #[case::chacha20(Some("chacha20-poly1305"), Some(SECURITY_CHACHA20_POLY1305))]
    fn security_acceptance(#[case] enc: Option<&str>, #[case] expected_byte: Option<u8>) {
        let mut obj = serde_json::json!({
            "schema": "Vmess",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "tcp" }
        });
        if let Some(enc) = enc {
            obj["security"] = serde_json::json!({ "enc": enc });
        }
        let cfg: VmessConfig = serde_json::from_value(obj).expect("vmess config parses");
        // The absent-key case parses to no `enc` at all, and every case is
        // accepted by the gate.
        if enc.is_none() {
            assert!(cfg.security.enc.is_none());
        }
        assert!(check_security(&cfg).is_ok());
        if let Some(byte) = expected_byte {
            assert_eq!(security_byte(&cfg).unwrap(), byte);
        }
    }

    #[test]
    fn aes128_security_still_default() {
        let cfg = vcfg("aes-128-gcm");
        assert_eq!(security_byte(&cfg).unwrap(), SECURITY_AES128_GCM);
        // absent/auto still map to the AES default
        let auto: VmessConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vmess", "uuid": "00000000-0000-0000-0000-000000000000",
            "security": { "enc": "auto", "type": "tls", "sni": "localhost", "alpn": "http/1.1" },
            "transport": { "type": "tcp" }
        }))
        .unwrap();
        assert_eq!(security_byte(&auto).unwrap(), SECURITY_AES128_GCM);
    }
}
