//! Security phase: wrap the transport stream (TLS, Reality — or identity).
//!
//! MIDDLE layer: transport → SECURITY → protocol. Security dispatches on
//! `SecurityConfig` from the proto payload. Every TLS/REALITY connect runs
//! through the `leas-tls` engine (`leas_tls::client::connect`); the
//! rustls client path and the `TlsProvider` plug are gone.

pub mod fingerprint;
pub mod reality;

use std::sync::Arc;

use leas_proto::proto_spec::TlsConfig;
use leas_proto::proto_spec::ss_plugin::PluginSpec;
use leas_tls::SecureRandom;
use leas_tls::client::{TlsConfig as EngineTlsConfig, TlsMode, connect as client_connect};
use leas_tls::error::TlsError;
use leas_tls::handshake::ServerVerifier;
use leas_tls::reality::{HelloProvisioner, SpecProvisioner, SpiderConfig};

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};
use crate::security::reality::{FixedChrome133, HelloProvisionerChoice};

/// Wrap the transport stream according to the profile's security config.
///
/// Both arms build an engine [`EngineTlsConfig`] from the proto security
/// config and run `leas_tls::client::connect`: plain TLS (fingerprint
/// profile + verifier seam) and REALITY (provisioner + server material).
/// Each handshake is bounded by [`timeouts::SECURITY`].
pub async fn wrap(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    // A plugin row's TLS lives in the plugin's `tls` key, and an
    // `SsConfig::security()` is present but EMPTY for it — so the historical
    // `let Some(sec) = ctx.security()` would return the stream untouched and a
    // `mode=websocket;tls` row would perform a **plaintext** upgrade against a
    // TLS port. `is_tls()` is the single decision surface and already folds
    // the plugin key in (`context.rs`), so it gates both halves.
    if !ctx.is_tls() {
        return Ok(stream);
    }
    let Some(sec) = ctx.security() else {
        return Ok(stream);
    };
    let rng: Arc<dyn SecureRandom> = Arc::new(ring::rand::SystemRandom::new());
    match &sec.tls {
        Some(TlsConfig::Tls(opts)) => {
            let (fp_id, approximated) = fingerprint::resolve_fingerprint(opts.fp.as_deref());
            if approximated {
                tracing::debug!(
                    target: "leas_native::security",
                    fp = opts.fp.as_deref().unwrap_or(""),
                    "probing with the default TLS fingerprint: no roster row for the requested id"
                );
            }
            let fingerprint = fp_id.map(fingerprint::profile_for).transpose()?;
            let verifier: Arc<dyn ServerVerifier> = Arc::new(fingerprint::verifier_for(
                opts.insecure.unwrap_or(false),
                fingerprint::decode_pin_sha256(opts.pin_sha256.as_deref())?,
            ));
            let config = EngineTlsConfig {
                mode: TlsMode::Plain {
                    fingerprint,
                    verifier,
                },
                server_name: ctx.server_name(),
                alpn: (!ctx.alpn_vec().is_empty()).then(|| ctx.alpn_vec()),
                curves: {
                    let ids = ctx.curve_ids();
                    (!ids.is_empty()).then_some(ids)
                },
                rng,
            };
            let tls = tokio::time::timeout(timeouts::SECURITY, client_connect(stream, &config))
                .await
                .map_err(|_| NativeError::Timeout {
                    step: "tls handshake",
                    limit: timeouts::SECURITY,
                })?
                .map_err(map_tls_err)?;
            Ok(Box::new(tls))
        }
        Some(TlsConfig::Reality(opts)) => {
            // A missing `pbk` is a CONFIG defect, not a server verdict: the
            // row cannot dial as written. It was a `Reality` error, which
            // `evidence()` maps to `RealityFallback` — so a broken config was
            // permanently purged as "the server is not REALITY / a possible
            // MITM". `Config` maps to `ConfigDefect` → `config_invalid`.
            let pbk = sec
                .pbk()
                .ok_or_else(|| NativeError::Config("reality config missing pbk".into()))?;
            let provisioner: Arc<dyn HelloProvisioner> = match &ctx.params.reality_provisioner {
                HelloProvisionerChoice::Custom(p) => p.clone(),
                HelloProvisionerChoice::FixedChrome133 => {
                    match fingerprint::resolve_fingerprint(opts.fp.as_deref()).0 {
                        Some(id) => Arc::new(SpecProvisioner::from(&fingerprint::profile_for(id)?)),
                        // No fingerprint requested (absent, `""` or `unsafe`), or
                        // an id with no roster row: the fixed provisioner shapes
                        // the surviving wire-exact chrome_130 spec (the
                        // Chrome-133 hand profile was dropped in the roster
                        // reduction). Byte-equivalent to the previous
                        // chrome_133-fingerprint default modulo the dropped
                        // profile's keyshare shape — see `fixed_chrome_spec`.
                        None => Arc::new(FixedChrome133),
                    }
                }
            };
            let spider = SpiderConfig {
                paths: opts
                    .spx
                    .as_ref()
                    .map_or_else(|| vec!["/".to_string()], |s| vec![s.to_string()]),
                ..SpiderConfig::default()
            };
            let config = EngineTlsConfig {
                mode: TlsMode::Reality {
                    provisioner,
                    public_key: reality::decode_pbk(pbk)?,
                    short_id: reality::decode_sid(sec.sid().unwrap_or_default())?,
                    spider,
                },
                // The REALITY steal target: `ctx.server_name()` walks
                // `SecurityConfig::sni()` (which reads `RealityOpts.sni`),
                // so the (often IP-literal) server host never leaks through.
                server_name: ctx.server_name(),
                alpn: None,
                curves: None,
                rng,
            };
            let tls = tokio::time::timeout(timeouts::SECURITY, client_connect(stream, &config))
                .await
                .map_err(|_| NativeError::Timeout {
                    step: "reality handshake",
                    limit: timeouts::SECURITY,
                })?
                .map_err(map_tls_err)?;
            Ok(Box::new(tls))
        }
        // A plugin row states its TLS in the plugin spec, not in `security` —
        // so without an arm here the stream would be left in the clear, which is
        // the silent dial this whole change exists to remove. The SNI comes from
        // the one resolver (`server_name`) and ALPN from `alpn_vec` (which folds
        // the plugin's `http/1.1` in).
        //
        // This arm is reachable ONLY when `security` states nothing at all, so
        // there is no `insecure`/pin/fingerprint to honour: a plugin row that
        // carries them is handled by the `Some(Tls)` arm above, which has always
        // read them. Verification is therefore unconditional here, which is the
        // correct default — a plugin server with a self-signed chain needs the
        // row to say `insecure`, and an earlier version of this comment claimed
        // otherwise.
        None if ctx.plugin_spec().is_some_and(PluginSpec::needs_tls) => {
            let verifier: Arc<dyn ServerVerifier> =
                Arc::new(fingerprint::verifier_for(false, None));
            let config = EngineTlsConfig {
                mode: TlsMode::Plain {
                    fingerprint: None,
                    verifier,
                },
                server_name: ctx.server_name(),
                alpn: (!ctx.alpn_vec().is_empty()).then(|| ctx.alpn_vec()),
                curves: {
                    let ids = ctx.curve_ids();
                    (!ids.is_empty()).then_some(ids)
                },
                rng,
            };
            let tls = tokio::time::timeout(timeouts::SECURITY, client_connect(stream, &config))
                .await
                .map_err(|_| NativeError::Timeout {
                    step: "plugin tls handshake",
                    limit: timeouts::SECURITY,
                })?
                .map_err(map_tls_err)?;
            Ok(Box::new(tls))
        }
        None => Ok(stream),
    }
}

/// Map an engine handshake error onto the native error surface: a REALITY
/// fallback (the server flight was not REALITY-authenticated — a real
/// certificate, e.g. a transparent proxy) is a `Reality` error, and the three
/// causes that identify the endpoint itself keep their own variant so the purge
/// policy can read them typed. Everything else is a plain `Tls` error.
fn map_tls_err(e: TlsError) -> NativeError {
    match e {
        TlsError::RealityFallback => NativeError::Reality(
            "REALITY: received real certificate (potential MITM or redirection)".into(),
        ),
        TlsError::CertNotValidForName(detail) => NativeError::CertNotValidForName(detail),
        TlsError::CertExpired(detail) => NativeError::CertExpired(detail),
        TlsError::CleartextPeer(detail) => NativeError::CleartextPeer(detail),
        // The variant's own Display already carries the `TLS error: ` prefix.
        other => NativeError::Tls(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;

    use leas_proto::proto_spec::ProtocolConfig;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use rustls;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::addr::{Host, TargetAddr};
    use crate::context::NativeConnectParams;

    fn vless_with_security(security: Option<&serde_json::Value>) -> ProtocolConfig {
        let mut obj = serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "tcp" }
        });
        if let Some(sec) = security {
            obj["security"] = sec.clone();
        }
        serde_json::from_value(obj).expect("vless config parses")
    }

    fn vless_with_tls(sni: &str) -> ProtocolConfig {
        vless_with_security(Some(&serde_json::json!({
            "type": "tls", "sni": sni, "alpn": "http/1.1"
        })))
    }

    fn vless_with_tls_fp(sni: &str, fp: &str) -> ProtocolConfig {
        vless_with_security(Some(&serde_json::json!({
            "type": "tls", "sni": sni, "alpn": "http/1.1", "fp": fp
        })))
    }

    /// A 32-byte static public key (0xAA×32) so configs reach the handshake.
    const VALID_PBK: &str = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo";

    fn vless_with_reality() -> ProtocolConfig {
        vless_with_security(Some(&serde_json::json!({
            "type": "reality", "sni": "example.com", "pbk": VALID_PBK, "sid": "0011223344556677"
        })))
    }

    fn vless_with_reality_short_pbk() -> ProtocolConfig {
        vless_with_security(Some(&serde_json::json!({
            "type": "reality", "sni": "example.com", "pbk": "Zm9vYmFy"
        })))
    }

    fn ctx_for(protocol: ProtocolConfig) -> LinkContext {
        LinkContext::new(
            NativeConnectParams::new(
                protocol,
                EndpointEssentials::new("127.0.0.1", 4430),
                TargetAddr::new(Host::Domain("example.com".into()), 80),
            ),
            TargetAddr::new(Host::Domain("example.com".into()), 80),
        )
    }

    /// rcgen CA + server cert/key PEM + CA DER.
    fn rcgen_ca_and_server(sni: &str) -> (String, String, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let mut ca_params = CertificateParams::new(vec![sni.to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_params =
            CertificateParams::new(vec![sni.to_string(), "127.0.0.1".to_string()]).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::new(ca_params, &ca_key);
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        (
            server_cert.pem(),
            server_key.serialize_pem(),
            ca_cert.der().to_vec(),
        )
    }

    fn server_config(cert_pem: &str, key_pem: &str) -> rustls::ServerConfig {
        use rustls::pki_types::pem::PemObject;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .map(|c| c.expect("cert pem parses"))
                .collect();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .expect("key pem parses");
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config builds")
    }

    /// Spawns a blocking-thread rustls server that completes the handshake
    /// and echoes back the first application-data bytes it reads (the client
    /// sends 4, reads 4 back, then drops the stream).
    fn spawn_echo_tls_server(cert_pem: &str, key_pem: &str) -> std::net::SocketAddr {
        let cfg = server_config(cert_pem, key_pem);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let timeout = std::time::Duration::from_secs(15);
            sock.set_read_timeout(Some(timeout)).expect("read timeout");
            sock.set_write_timeout(Some(timeout))
                .expect("write timeout");
            let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).expect("server conn");
            while conn.is_handshaking() {
                conn.complete_io(&mut sock).expect("handshake");
            }
            // Drain decrypted application data; echo the first chunk.
            while let Ok(read) = conn.read_tls(&mut sock) {
                if read == 0 {
                    break;
                }
                let state = conn.process_new_packets().expect("process packets");
                if state.plaintext_bytes_to_read() > 0 {
                    let mut buf = vec![0u8; state.plaintext_bytes_to_read()];
                    // The buffer is exactly the available plaintext, so a
                    // blocking read_exact cannot stall.
                    conn.reader().read_exact(&mut buf).expect("read plaintext");
                    conn.writer().write_all(&buf).expect("write plaintext");
                    conn.write_tls(&mut sock).expect("flush");
                    break;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn none_security_is_identity() {
        // No `security` key at all: `SecurityConfig` has no null representation.
        let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "tcp" }
        }))
        .expect("vless config parses");
        let ctx = ctx_for(protocol);
        let (a, mut b) = tokio::io::duplex(64);
        let mut out = wrap(&ctx, Box::new(a)).await.unwrap();
        out.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
    }

    #[tokio::test]
    async fn tls_wraps_and_passes_bytes() {
        // Feature unification enables both rustls backends; the app installs
        // the ring provider at startup (workspace convention), tests do it
        // here (idempotent).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem, ca_der) = rcgen_ca_and_server("localhost");
        // The engine verifies through its own thread-local test CA (the
        // harness CA), replacing the deleted rustls `set_test_config` path.
        fingerprint::set_test_ca(&ca_der);
        let addr = spawn_echo_tls_server(&cert_pem, &key_pem);

        let ctx = ctx_for(vless_with_tls("localhost"));
        // Point the context at the test listener (server host is 127.0.0.1:addr).
        let mut params = ctx.params.clone();
        params.server = EndpointEssentials::new(addr.ip().to_string(), addr.port());
        let ctx = LinkContext::new(params, ctx.target.clone());

        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut out = wrap(&ctx, Box::new(sock)).await.unwrap();
        out.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        out.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn fingerprint_tls_wraps_and_passes_bytes() {
        // Feature unification enables both rustls backends; the app installs
        // the ring provider at startup (workspace convention), tests do it
        // here (idempotent).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem, ca_der) = rcgen_ca_and_server("localhost");
        fingerprint::set_test_ca(&ca_der);
        let addr = spawn_echo_tls_server(&cert_pem, &key_pem);

        // Engine Plain arm with a fingerprint profile: `fp` id in the config.
        let ctx = ctx_for(vless_with_tls_fp("localhost", "chrome"));
        let mut params = ctx.params.clone();
        params.server = EndpointEssentials::new(addr.ip().to_string(), addr.port());
        let ctx = LinkContext::new(params, ctx.target.clone());

        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut out = wrap(&ctx, Box::new(sock)).await.unwrap();
        out.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        out.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn reality_connect_rejects_short_pbk() {
        // A `pbk` that decodes to ≠32 bytes is a config error, not a hang.
        // Asserted on what the failure PROVES, not on its variant: the point of
        // the mapping is that a broken config must not be purged as a verdict
        // about the peer (it was `NativeError::Reality`, i.e. `RealityFallback`).
        let ctx = ctx_for(vless_with_reality_short_pbk());
        let (a, _) = tokio::io::duplex(64);
        let out = wrap(&ctx, Box::new(a)).await;
        let Err(err) = out else {
            panic!("a short pbk must not dial");
        };
        assert_eq!(
            err.evidence(),
            Some(crate::error::FailureEvidence::ConfigDefect),
            "{err:?} must be a config defect, not a peer verdict"
        );
    }

    #[tokio::test]
    async fn reality_handshake_errors_are_reality_errors_not_not_implemented() {
        // The arm is real: a valid config over a stream that yields EOF
        // surfaces a handshake error — the `NotImplemented` stub is gone.
        let ctx = ctx_for(vless_with_reality());
        let (a, _) = tokio::io::duplex(64);
        let out = wrap(&ctx, Box::new(a)).await;
        assert!(out.is_err(), "duplex EOF must fail the handshake");
        assert!(
            !matches!(out, Err(NativeError::NotImplemented { .. })),
            "reality must not be NotImplemented"
        );
    }

    #[tokio::test]
    async fn reality_against_plain_server_maps_to_reality_error() {
        // A REALITY connect against a server presenting a real certificate
        // (no REALITY auth) must surface the engine's `RealityFallback` as
        // `NativeError::Reality` — the MITM/redirection signal — proving the
        // `map_tls_err` mapping the brief requires.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem, _ca_der) = rcgen_ca_and_server("localhost");
        let addr = spawn_echo_tls_server(&cert_pem, &key_pem);

        let ctx = ctx_for(vless_with_reality());
        let mut params = ctx.params.clone();
        params.server = EndpointEssentials::new(addr.ip().to_string(), addr.port());
        let ctx = LinkContext::new(params, ctx.target.clone());

        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        match wrap(&ctx, Box::new(sock)).await {
            Err(NativeError::Reality(_)) => {}
            Err(other) => {
                panic!("expected NativeError::Reality (engine RealityFallback), got {other:?}");
            }
            Ok(_) => panic!("REALITY against a plain server must fail"),
        }
    }
}
