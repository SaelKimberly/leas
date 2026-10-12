//! Shadowsocks — native client (classic AEAD + 2022-blake3, TCP).
//!
//! Cipher scope is the AEAD set + 2022-blake3 (`method.rs`); legacy stream
//! ciphers route to sing-box via [`crate::capability`]. SIP003 plugins are
//! gated off there too. References: shadowsocks-rust `relay/`, mihomo
//! `transport/shadowsocks/`, and the 2022 edition spec.
//!
//! [`connect`] resolves the row's method and hands the stream to the family
//! codec — [`stream`] for the 2017 AEAD set, [`stream2022`] for 2022-blake3 —
//! which writes the handshake and returns the tunnel.

pub mod consts;
pub mod method;
pub mod mux;
pub mod stream;
pub mod stream2022;
pub mod udp;

use leas_proto::proto_spec::SsConfig;

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::NativeError;
use crate::protocol::ss::method::{SsFamily, SsMethod};

/// Resolve the row's method, refusing anything native does not implement.
///
/// The one config-to-codec gate: legacy stream ciphers and unknown names are
/// [`NativeError::Config`], never a silent fallback to a codec that cannot
/// speak them. `pub(crate)` for the UDP carrier's dispatch.
pub(crate) fn resolve_method(cfg: &SsConfig) -> Result<SsMethod, NativeError> {
    SsMethod::from_method(&cfg.method).ok_or_else(|| {
        NativeError::Config(format!(
            "shadowsocks method {:?} has no native implementation",
            cfg.method
        ))
    })
}

/// TCP protocol phase: the family codec writes the handshake and owns the tunnel.
pub async fn connect(
    ctx: &LinkContext,
    stream: BoxStream,
    cfg: &SsConfig,
) -> Result<BoxStream, NativeError> {
    let method = resolve_method(cfg)?;
    match method.family {
        SsFamily::Classic => stream::connect(ctx, stream, cfg, method).await,
        SsFamily::Blake3_2022 => stream2022::connect(ctx, stream, cfg, method).await,
    }
}

#[cfg(test)]
mod tests {
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use leas_proto::proto_spec::{ProtocolConfig, SecurityConfig};
    use tokio::io::{AsyncReadExt, duplex};

    use super::*;
    use crate::addr::{Host, TargetAddr, encode_addr_port_last};
    use crate::context::NativeConnectParams;

    fn ss_cfg(method: &str, password: &str) -> SsConfig {
        SsConfig {
            method: method.into(),
            password: password.into(),
            security: SecurityConfig::default(),
            remarks: None,
            plugin: None,
        }
    }

    /// The link target is the domain `example.com:80`, so the first chunk's
    /// plaintext address is 15 wire bytes (ATYP + len + domain + port BE2).
    fn link(cfg: &SsConfig) -> (LinkContext, TargetAddr) {
        let target = TargetAddr::new(Host::new("example.com"), 80);
        let params = NativeConnectParams::new(
            ProtocolConfig::Ss(cfg.clone()),
            EndpointEssentials::new("127.0.0.1", 8388),
            target.clone(),
        );
        (LinkContext::new(params, target.clone()), target)
    }

    #[tokio::test]
    async fn dispatch_picks_the_family_codec() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        assert_eq!(method.family, SsFamily::Blake3_2022);
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        assert_eq!(method.family, SsFamily::Classic);
    }

    #[tokio::test]
    async fn unknown_method_is_a_config_error() {
        let cfg = SsConfig {
            method: "aes-256-cfb".into(),
            password: "pw".into(),
            security: SecurityConfig::default(),
            remarks: None,
            plugin: None,
        };
        let err = resolve_method(&cfg).unwrap_err();
        assert!(matches!(err, NativeError::Config(_)));
    }

    /// The classic branch really reaches `stream::connect`: the wire opens
    /// with the 16-byte salt, then the length chunk (`2B` sealed length + its
    /// `16B` tag) and one payload chunk carrying the 15-byte address. A
    /// mis-dispatch to the 2022 codec cannot produce this: the password is not
    /// a base64 PSK, so it fails at key derivation, and 2022's 11-byte fixed
    /// header would not fit the framing either.
    #[tokio::test]
    async fn classic_method_is_written_by_the_classic_codec() {
        let cfg = ss_cfg("aes-128-gcm", "hunter2");
        let (ctx, target) = link(&cfg);
        let (client, mut server) = duplex(1 << 16);
        let tunnel = connect(&ctx, Box::new(client), &cfg).await.unwrap();
        drop(tunnel);

        let addr_len = encode_addr_port_last(&target).unwrap().len();
        let mut wire = [0u8; 256];
        let n = server.read(&mut wire).await.unwrap();
        assert_eq!(
            n,
            16 + 2 + 16 + addr_len + 16,
            "classic framing: [salt 16][len seal 2+16][payload {addr_len}+16]"
        );
    }

    /// A legacy cipher never reaches either codec: the guard refuses it and
    /// the stream is dropped unwritten, so the peer sees a clean EOF instead
    /// of a handshake.
    #[tokio::test]
    async fn legacy_method_is_refused_before_any_codec_writes() {
        let cfg = ss_cfg("aes-256-cfb", "pw");
        let (ctx, _target) = link(&cfg);
        let (client, mut server) = duplex(1 << 16);
        let Err(err) = connect(&ctx, Box::new(client), &cfg).await else {
            panic!("a legacy cipher must be refused");
        };
        assert!(matches!(err, NativeError::Config(_)), "got {err:?}");

        let mut wire = [0u8; 16];
        assert_eq!(
            server.read(&mut wire).await.unwrap(),
            0,
            "the guard fires before any handshake byte"
        );
    }
}
