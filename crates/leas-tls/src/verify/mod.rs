//! Certificate verification: `WebPKI` chain + SAN + `CertificateVerify` signature.
//!
//! [`WebPkiVerifier`] implements the [`ServerVerifier`] seam: the Task-8
//! handshake hands it the raw certificate chain, the offered SNI, the
//! `CertificateVerify` signature scheme and body, and the transcript up to
//! (excluding) `CertificateVerify`. Chain + SAN are delegated to
//! `rustls-webpki` (ring provider), and the `CertificateVerify` signature is
//! verified with the leaf's public key via
//! `webpki::EndEntityCert::verify_signature`.
//!
//! Trust modes, in priority order (`insecure` wins when both it and a pin
//! are set):
//! 1. `insecure` — every server is accepted, with no verification at all.
//! 2. A configured `pin_sha256` — the chain walk (and SAN) are skipped
//!    (v2rayN pin semantics); the leaf SPKI must hash to the pin and the
//!    `CertificateVerify` signature must still verify against the leaf's
//!    public key.
//! 3. Full `WebPKI` — the chain must build to a configured root, the leaf must
//!    be valid for the offered SNI, and the `CertificateVerify` signature
//!    must verify against the leaf's public key.
//!
//! The `CertificateVerify` signature is verified over
//! `Hash(ClientHello .. Certificate)` per RFC 8446 §4.4.3 (the
//! `CertificateVerify` message itself is excluded from the transcript hash).

use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage};

use crate::error::{Result, TlsError};
use crate::handshake::{ServerVerifier, TlsVersion, VerifyContext};

/// RFC 8446 §4.4.3 server context label, NUL-terminated. The signed message
/// is `64*0x20 || SERVER_CV_CONTEXT || transcript_hash` — the literal 64
/// space bytes are the leading padding, not part of this constant.
const SERVER_CV_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\x00";

// ── Verifier ───────────────────────────────────────────────────────────────

/// Real certificate verification via `rustls-webpki` + `ring`.
#[derive(Clone)]
pub struct WebPkiVerifier {
    /// Trust anchors the chain is built against (full-verification mode).
    roots: Vec<TrustAnchor<'static>>,
    /// `true` accepts any server without any verification.
    insecure: bool,
    /// When set, only the leaf SPKI SHA-256 is compared (chain skipped).
    pin_sha256: Option<[u8; 32]>,
}

impl WebPkiVerifier {
    /// Creates a verifier that trusts exactly `roots`.
    #[must_use]
    pub const fn from_roots(roots: Vec<TrustAnchor<'static>>) -> Self {
        Self {
            roots,
            insecure: false,
            pin_sha256: None,
        }
    }

    /// Trusts the Mozilla root program (`webpki-roots`).
    #[must_use]
    pub fn webpki_roots() -> Self {
        Self::from_roots(webpki_roots::TLS_SERVER_ROOTS.to_vec())
    }

    /// Trusts a single CA given as a DER-encoded X.509 certificate.
    ///
    /// Convenience for tests: builds the [`TrustAnchor`] from a trusted CA
    /// certificate (`anchor_from_trusted_cert` performs no validation of the
    /// input — only feed it certificates from a trusted source).
    pub fn from_ca_der(ca_der: &[u8]) -> Result<Self> {
        let cert_der = CertificateDer::from(ca_der.to_vec());
        let anchor = webpki::anchor_from_trusted_cert(&cert_der)
            .map_err(|e| TlsError::Verify(format!("invalid CA certificate DER: {e}")))?
            .to_owned();
        Ok(Self::from_roots(vec![anchor]))
    }

    /// When `insecure` is `true`, accepts any server without verification.
    #[must_use]
    pub const fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Pins the expected SHA-256 of the leaf's `SubjectPublicKeyInfo` (DER).
    ///
    /// When set, the trust-chain walk is replaced by the SPKI hash comparison
    /// (v2rayN semantics); SAN is also skipped. The `CertificateVerify`
    /// signature check is *not* skipped: it proves the server holds the
    /// private key of the presented leaf.
    #[must_use]
    pub const fn with_pin(mut self, pin: [u8; 32]) -> Self {
        self.pin_sha256 = Some(pin);
        self
    }
}

impl ServerVerifier for WebPkiVerifier {
    fn verify(&self, ctx: &VerifyContext<'_>) -> Result<()> {
        // `insecure` takes precedence over everything, including the pin:
        // no verification at all, not even a leaf-certificate parse.
        if self.insecure {
            return Ok(());
        }

        let leaf = ctx
            .chain
            .first()
            .ok_or_else(|| TlsError::Verify("server presented no certificate".to_string()))?;
        let leaf_der = CertificateDer::from(leaf.as_slice());
        let end_entity = EndEntityCert::try_from(&leaf_der)
            .map_err(|e| TlsError::Verify(format!("invalid leaf certificate DER: {e}")))?;

        // Pin mode: the pin replaces the chain walk (which CA signed the
        // cert) but NOT the CertificateVerify signature verification, which
        // authenticates the handshake by proving the server holds the leaf's
        // private key.
        if let Some(pin) = self.pin_sha256 {
            let digest = ring::digest::digest(
                &ring::digest::SHA256,
                end_entity.subject_public_key_info().as_ref(),
            );
            if digest.as_ref() != pin {
                return Err(TlsError::Verify(
                    "server certificate SPKI does not match the configured pin".to_string(),
                ));
            }
            return verify_certificate_verify(&end_entity, ctx);
        }

        // Full WebPKI: chain + SAN + CertificateVerify signature.
        let intermediates: Vec<CertificateDer<'_>> = ctx.chain[1..]
            .iter()
            .map(|c| CertificateDer::from(c.as_slice()))
            .collect();
        end_entity
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &self.roots,
                &intermediates,
                UnixTime::now(),
                KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(|e| match e {
                // Expiry (and "not yet valid") is the one chain failure that is
                // a statement about the certificate rather than a trust gap.
                webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. } => {
                    TlsError::CertExpired(e.to_string())
                }
                webpki::Error::CertNotValidForName(_) => {
                    TlsError::CertNotValidForName(e.to_string())
                }
                other => TlsError::Verify(format!("chain verification failed: {other}")),
            })?;

        let server_name = ServerName::try_from(ctx.sni)
            .map_err(|_| TlsError::Verify(format!("invalid server name {:?}", ctx.sni)))?;
        end_entity
            .verify_is_valid_for_subject_name(&server_name)
            .map_err(|e| TlsError::CertNotValidForName(e.to_string()))?;

        verify_certificate_verify(&end_entity, ctx)
    }
}

// ── CertificateVerify signature ────────────────────────────────────────────

/// Verifies the server's handshake signature (TLS 1.3 `CertificateVerify`
/// or TLS 1.2 `ServerKeyExchange` signature) over the signed data provided
/// by the context.
///
/// TLS 1.3 (RFC 8446 §4.4.3): the signed message is
/// `64*0x20 || "TLS 1.3, server CertificateVerify\x00" || Transcript-Hash(transcript)`
/// where `transcript` = `ClientHello .. Certificate` (the `CertificateVerify`
/// message itself is excluded). The context's `signed_data` carries this
/// transcript prefix.
///
/// TLS 1.2 (RFC 5246 §7.4.3, RFC 4492 §5.4): the signed message is the raw
/// `client_random || server_random || ServerECDHParams` — no hash prefix,
/// no context string. The context's `signed_data` carries these bytes.
fn verify_certificate_verify(
    end_entity: &EndEntityCert<'_>,
    ctx: &VerifyContext<'_>,
) -> Result<()> {
    let signature = ctx.signature;
    if signature.is_empty() {
        return Err(TlsError::Verify(
            "server handshake signature is empty".to_string(),
        ));
    }
    match ctx.version {
        TlsVersion::Tls13 => {
            let algorithm = tls13_algorithm(ctx.signature_scheme)?;
            let transcript_hash = ring::digest::digest(ctx.suite.digest(), ctx.signed_data);
            // Stack-signed content: `64 spaces || SERVER_CV_CONTEXT ||
            // transcript_hash`, sized to the SHA-384 max.
            let mut signed = [0u8; 64 + 34 + 48];
            signed[..64].fill(0x20);
            signed[64..64 + SERVER_CV_CONTEXT.len()].copy_from_slice(SERVER_CV_CONTEXT);
            let th = transcript_hash.as_ref();
            if th.len() > 48 {
                return Err(TlsError::Verify(
                    "transcript hash exceeds SHA-384 length".to_string(),
                ));
            }
            let content_len = 64 + SERVER_CV_CONTEXT.len() + th.len();
            signed[64 + SERVER_CV_CONTEXT.len()..content_len].copy_from_slice(th);
            end_entity
                .verify_signature(algorithm, &signed[..content_len], signature)
                .map_err(|e| {
                    TlsError::Verify(format!(
                        "CertificateVerify signature verification failed: {e}"
                    ))
                })
        }
        TlsVersion::Tls12 => {
            // Any of the scheme's candidate algorithms may match: see
            // `tls12_algorithms`.
            let mut last = None;
            for algorithm in tls12_algorithms(ctx.signature_scheme)? {
                match end_entity.verify_signature(*algorithm, ctx.signed_data, signature) {
                    Ok(()) => return Ok(()),
                    Err(e) => last = Some(e),
                }
            }
            Err(TlsError::Verify(format!(
                "ServerKeyExchange signature verification failed: {}",
                last.map_or_else(|| "no candidate algorithm".to_string(), |e| e.to_string())
            )))
        }
    }
}

/// TLS 1.3 `CertificateVerify` signature scheme → webpki algorithm.
///
/// TLS 1.3 code points name the curve (RFC 8446 §4.2.3), so each maps to
/// exactly one algorithm. SHA-1, MD5, RSA-PKCS1 and anonymous schemes are
/// absent by design — TLS 1.3 forbids them for `CertificateVerify`.
fn tls13_algorithm(
    scheme: u16,
) -> Result<&'static dyn rustls_pki_types::SignatureVerificationAlgorithm> {
    match scheme {
        0x0403 => Ok(webpki::ring::ECDSA_P256_SHA256),
        0x0503 => Ok(webpki::ring::ECDSA_P384_SHA384),
        0x0804 => Ok(webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
        0x0805 => Ok(webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
        0x0806 => Ok(webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),
        0x0807 => Ok(webpki::ring::ED25519),
        other => Err(TlsError::Verify(format!(
            "unsupported TLS 1.3 CertificateVerify signature scheme 0x{other:04X}"
        ))),
    }
}

/// TLS 1.2 `ServerKeyExchange` signature scheme → candidate webpki
/// algorithms.
///
/// A TLS 1.2 `SignatureAndHashAlgorithm` is `(hash, signature_type)` and
/// does NOT name a curve (RFC 5246 §7.4.1.4.1, RFC 8422 §5.1.3), even though
/// the wire values coincide with TLS 1.3's curve-bound code points. Binding
/// 0x0403 to P-256 would reject a legal P-384 leaf that signs with SHA-256,
/// so each ECDSA scheme yields one candidate per curve and the caller tries
/// them in turn (webpki matches the certificate's public-key algorithm, so
/// at most one can succeed — this is not a downgrade of the hash).
///
/// Weak schemes stay unreachable: MD5 (0x01xx), SHA-1 (0x02xx), SHA-224
/// (0x03xx), DSA and anonymous code points all fall through to the error.
fn tls12_algorithms(
    scheme: u16,
) -> Result<&'static [&'static dyn rustls_pki_types::SignatureVerificationAlgorithm]> {
    const ECDSA_SHA256: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
        webpki::ring::ECDSA_P256_SHA256,
        webpki::ring::ECDSA_P384_SHA256,
    ];
    const ECDSA_SHA384: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
        webpki::ring::ECDSA_P384_SHA384,
        webpki::ring::ECDSA_P256_SHA384,
    ];
    const RSA_PKCS1_SHA256: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] =
        &[webpki::ring::RSA_PKCS1_2048_8192_SHA256];
    const RSA_PKCS1_SHA384: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] =
        &[webpki::ring::RSA_PKCS1_2048_8192_SHA384];
    const RSA_PKCS1_SHA512: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] =
        &[webpki::ring::RSA_PKCS1_2048_8192_SHA512];
    const RSA_PSS_SHA256: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] =
        &[webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY];
    const RSA_PSS_SHA384: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] =
        &[webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY];
    const RSA_PSS_SHA512: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] =
        &[webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY];
    const ED25519: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] =
        &[webpki::ring::ED25519];
    match scheme {
        0x0401 => Ok(RSA_PKCS1_SHA256),
        0x0501 => Ok(RSA_PKCS1_SHA384),
        0x0601 => Ok(RSA_PKCS1_SHA512),
        0x0403 => Ok(ECDSA_SHA256),
        0x0503 => Ok(ECDSA_SHA384),
        0x0804 => Ok(RSA_PSS_SHA256),
        0x0805 => Ok(RSA_PSS_SHA384),
        0x0806 => Ok(RSA_PSS_SHA512),
        0x0807 => Ok(ED25519),
        other => Err(TlsError::Verify(format!(
            "unsupported TLS 1.2 ServerKeyExchange signature scheme 0x{other:04X}"
        ))),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{WebPkiVerifier, verify_certificate_verify};
    use crate::crypto::CipherSuiteId;
    use crate::error::{Result, TlsError};
    use crate::handshake::{HandshakeParams, ServerVerifier, TlsVersion, VerifyContext, connect};
    use crate::spec::{ClientHelloSpec, ExtensionSpec, KeyShareGroup, SessionIdSpec};
    use rcgen::PublicKeyData;

    // ── helpers ────────────────────────────────────────────────────────────

    /// A Chrome-flavoured spec with only TLS 1.3 suites/groups/versions, the
    /// minimal surface a rustls server needs to complete a 1-RTT handshake.
    /// Mirrors the handshake tests.
    fn test_spec() -> ClientHelloSpec {
        ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302, 0x1303],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![
                ExtensionSpec::ServerName,
                ExtensionSpec::SupportedGroups(vec![0x001D]),
                ExtensionSpec::KeyShare(vec![KeyShareGroup::X25519]),
                ExtensionSpec::SupportedVersions(vec![0x0304, 0x0303]),
                ExtensionSpec::SignatureAlgorithms(vec![
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                ]),
                ExtensionSpec::Alpn(vec!["h2".into(), "http/1.1".into()]),
                ExtensionSpec::EcPointFormats,
                ExtensionSpec::SessionTicket,
                ExtensionSpec::PskKeyExchangeModes,
            ],
        }
    }

    fn server_config(cert: &rcgen::Certificate, key: &rcgen::KeyPair) -> rustls::ServerConfig {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        // Workspace feature unification compiles rustls with BOTH backends
        // (ring via our crates, aws-lc-rs via reqwest/hickory/quinn), so
        // rustls cannot auto-select a provider here — install ring
        // explicitly, matching `install_tls_provider()` in the binary.
        // Idempotent: a concurrent/earlier install returns `Err`, ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap()
    }

    /// An rcgen test CA and a leaf (SANs `localhost`/`127.0.0.1`) signed by
    /// it, plus their key pairs.
    fn ca_and_leaf() -> (
        rcgen::Certificate,
        rcgen::KeyPair,
        rcgen::Certificate,
        rcgen::KeyPair,
    ) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "leas test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params =
            rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, &ca_key);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        (ca_cert, ca_key, leaf_cert, leaf_key)
    }

    /// SHA-256 of a key's SPKI DER (the pin format), computed from the key
    /// itself — independent of [`leaf_spki`].
    fn spki_pin(key: &rcgen::KeyPair) -> [u8; 32] {
        ring::digest::digest(&ring::digest::SHA256, &key.subject_public_key_info())
            .as_ref()
            .try_into()
            .unwrap()
    }

    /// Spawns a rustls server presenting `cert`/`key` and connects our TLS
    /// client to it with `verifier` and `server_name`. On success the
    /// client echoes 4 bytes of application data; on failure (verification
    /// error) the server observes the client abort and exits quietly.
    async fn connect_server(
        verifier: &dyn crate::handshake::ServerVerifier,
        server_name: &str,
        cert: &rcgen::Certificate,
        key: &rcgen::KeyPair,
    ) -> Result<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = server_config(cert, key);

        let server = tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let timeout = std::time::Duration::from_secs(15);
            sock.set_read_timeout(Some(timeout)).unwrap();
            sock.set_write_timeout(Some(timeout)).unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut sock).is_err() {
                    return; // client aborted (expected on verification failure)
                }
            }
            // Echo 4 bytes of application data, then stop.
            let mut echo = [0u8; 4];
            let mut got = 0;
            while got < echo.len() {
                if conn.read_tls(&mut sock).is_err() {
                    return;
                }
                let state = conn.process_new_packets().unwrap();
                conn.write_tls(&mut sock).unwrap();
                if state.plaintext_bytes_to_read() > 0 {
                    got += conn.reader().read(&mut echo[got..]).unwrap();
                }
            }
            conn.writer().write_all(&echo).unwrap();
            conn.write_tls(&mut sock).unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let rng = ring::rand::SystemRandom::new();
        let result = connect(
            stream,
            HandshakeParams {
                spec: &test_spec(),
                server_name,
                alpn: Some(&["http/1.1"]),
                verifier,
                rng: &rng,
            },
        )
        .await;

        match result {
            Ok(mut tls) => {
                tls.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                tls.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
                server.await.unwrap();
                Ok(())
            }
            Err(err) => {
                // Give the server thread a moment to observe the abort.
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
                Err(err)
            }
        }
    }

    // ── interop: verification against a real rustls server ────────────────

    #[tokio::test]
    async fn verifies_valid_chain_and_sni() {
        let (ca_cert, _, leaf_cert, leaf_key) = ca_and_leaf();
        let verifier = WebPkiVerifier::from_ca_der(ca_cert.der()).unwrap();
        connect_server(&verifier, "localhost", &leaf_cert, &leaf_key)
            .await
            .unwrap();
    }

    /// An expired certificate is its own typed cause (`CertExpired`), not a
    /// generic `Verify`: the purge policy reads the difference (spec §7).
    #[tokio::test]
    async fn rejects_expired_leaf_with_its_own_cause() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "leas expired test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        // A window that closed years ago: webpki answers `CertExpired`.
        leaf_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2020, 2, 1);
        let issuer = rcgen::Issuer::new(ca_params, &ca_key);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        let verifier = WebPkiVerifier::from_ca_der(ca_cert.der()).unwrap();
        let err = connect_server(&verifier, "localhost", &leaf_cert, &leaf_key)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TlsError::CertExpired(_)),
            "an expired chain is its own typed cause: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_wrong_sni() {
        let (ca_cert, _, leaf_cert, leaf_key) = ca_and_leaf();
        let verifier = WebPkiVerifier::from_ca_der(ca_cert.der()).unwrap();
        let err = connect_server(&verifier, "wrong.example", &leaf_cert, &leaf_key)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TlsError::CertNotValidForName(_)),
            "a name mismatch is its own typed cause, not a generic verify failure: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_self_signed() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        // A self-signed server cert is not in the trust store (webpki-roots),
        // so the chain cannot build to any root.
        let verifier = WebPkiVerifier::webpki_roots();
        let err = connect_server(
            &verifier,
            "localhost",
            &certified.cert,
            &certified.signing_key,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TlsError::Verify(_)), "got: {err}");
    }

    #[tokio::test]
    async fn pin_sha256_matches_leaf_spki() {
        let (ca_cert, _, leaf_cert, leaf_key) = ca_and_leaf();
        let pin = spki_pin(&leaf_key);

        // Correct pin + wrong SNI: passes because pin mode skips chain and SAN.
        let verifier = WebPkiVerifier::from_ca_der(ca_cert.der())
            .unwrap()
            .with_pin(pin);
        connect_server(&verifier, "wrong.example", &leaf_cert, &leaf_key)
            .await
            .unwrap();

        // Wrong pin: fails even for the valid hostname.
        let verifier = WebPkiVerifier::from_ca_der(ca_cert.der())
            .unwrap()
            .with_pin([0u8; 32]);
        let err = connect_server(&verifier, "localhost", &leaf_cert, &leaf_key)
            .await
            .unwrap_err();
        assert!(matches!(err, TlsError::Verify(_)), "got: {err}");
    }

    #[tokio::test]
    async fn pin_accepts_self_signed_when_spki_matches() {
        // The strongest v2rayN-semantics proof: a self-signed server is
        // accepted when the pin matches, because the chain is never checked.
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let pin = spki_pin(&certified.signing_key);
        let verifier = WebPkiVerifier::webpki_roots().with_pin(pin);
        connect_server(
            &verifier,
            "localhost",
            &certified.cert,
            &certified.signing_key,
        )
        .await
        .unwrap();
    }

    /// Regression guard (review P2): pin mode must still reject a forged
    /// `CertificateVerify`. The leaf SPKI hashes to the pin, but the
    /// signature was made by a *different* key, so verification must fail.
    /// This test fails if `verify_certificate_verify` is dropped from the
    /// pin branch.
    #[test]
    fn pin_mode_rejects_forged_certificate_verify() {
        let (_, _, leaf_cert, leaf_key) = ca_and_leaf();
        let pin = spki_pin(&leaf_key);

        // Forge the signature with a second, unrelated ECDSA P-256 key.
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let forger = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();

        // The transcript is arbitrary here; the signature covers the padded
        // RFC 8446 §4.4.3 message built from it.
        let transcript = b"ClientHello..Certificate";
        let transcript_hash = ring::digest::digest(&ring::digest::SHA256, &transcript[..])
            .as_ref()
            .to_vec();
        let mut message = Vec::with_capacity(64 + super::SERVER_CV_CONTEXT.len() + 32);
        message.resize(64, 0x20);
        message.extend_from_slice(super::SERVER_CV_CONTEXT);
        message.extend_from_slice(&transcript_hash);
        let forged_sig = forger.sign(&rng, &message).unwrap();

        let mut body = Vec::with_capacity(4 + forged_sig.as_ref().len());
        body.extend_from_slice(&0x0403u16.to_be_bytes());
        body.extend_from_slice(
            &u16::try_from(forged_sig.as_ref().len())
                .unwrap()
                .to_be_bytes(),
        );
        body.extend_from_slice(forged_sig.as_ref());

        let ctx = VerifyContext {
            chain: &[leaf_cert.der().to_vec()],
            sni: "localhost",
            version: TlsVersion::Tls13,
            suite: CipherSuiteId::Aes128GcmSha256,
            signature_scheme: 0x0403,
            signature: &body[4..],
            signed_data: transcript,
        };

        let verifier = WebPkiVerifier::from_roots(Vec::new()).with_pin(pin);
        let err = verifier.verify(&ctx).unwrap_err();
        assert!(matches!(err, TlsError::Verify(_)), "got: {err}");
    }

    #[test]
    fn leaf_spki_matches_rcgen_public_key_der() {
        // `EndEntityCert::subject_public_key_info()` (via Deref) must return
        // the same bytes the key's own SPKI carries.
        let (_, _, leaf_cert, leaf_key) = ca_and_leaf();
        let der = rustls_pki_types::CertificateDer::from(leaf_cert.der().to_vec());
        let ee = webpki::EndEntityCert::try_from(&der).unwrap();
        assert_eq!(
            ee.subject_public_key_info().as_ref(),
            leaf_key.subject_public_key_info()
        );
    }

    #[test]
    fn rejects_unknown_signature_scheme() {
        let (_, _, leaf_cert, _) = ca_and_leaf();
        let der = rustls_pki_types::CertificateDer::from(leaf_cert.der().to_vec());
        let ee = webpki::EndEntityCert::try_from(&der).unwrap();
        let ctx = VerifyContext {
            chain: &[],
            sni: "localhost",
            version: TlsVersion::Tls13,
            suite: CipherSuiteId::Aes128GcmSha256,
            signature_scheme: 0x1234,
            signature: &[],
            signed_data: &[],
        };
        let err = verify_certificate_verify(&ee, &ctx).unwrap_err();
        assert!(matches!(err, TlsError::Verify(_)), "got: {err}");
    }
}
