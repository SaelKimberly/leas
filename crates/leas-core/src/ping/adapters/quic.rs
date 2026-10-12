use super::{FastPingAdapter, IoFailure, PingCapability, PingError};
use async_trait::async_trait;
use leas_proto::ProtocolKind;
use std::sync::Arc;
use std::time::Duration;

/// QUIC handshake ping. Supports TUIC, Hysteria, Hysteria2.
/// Opens a QUIC connection to the server endpoint, measures handshake time.
#[derive(Debug)]
pub struct QuicPingAdapter;

#[async_trait]
impl FastPingAdapter for QuicPingAdapter {
    fn transport(&self) -> PingCapability {
        PingCapability::Quic
    }

    fn name(&self) -> &'static str {
        "QUIC"
    }

    fn supports(&self, protocol: ProtocolKind) -> bool {
        matches!(
            protocol,
            ProtocolKind::Tuic | ProtocolKind::Hysteria | ProtocolKind::Hysteria2
        )
    }

    async fn ping(&self, host: &str, port: u16, timeout: Duration) -> Result<Duration, PingError> {
        // DNS resolve (quinn requires SocketAddr)
        let addr = tokio::net::lookup_host(format!("{host}:{port}"))
            .await
            .map_err(|e| PingError::Io(IoFailure::from(e).prefixed("DNS")))?
            .next()
            .ok_or_else(|| PingError::Io(IoFailure::msg("DNS returned no addresses")))?;

        // TLS config skipping cert verification (proxy self-signed certs)
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PermissiveVerifier))
            .with_no_client_auth();

        let quic_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(crypto))
                .map_err(|e| PingError::Other(format!("QUIC config: {e}")))?,
        ));

        let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| PingError::Io(IoFailure::from(e).prefixed("endpoint")))?;

        let start = std::time::Instant::now();
        let connecting = endpoint
            .connect_with(quic_config, addr, host)
            .map_err(|e| PingError::Other(format!("connect: {e}")))?;

        let conn = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| PingError::Timeout(timeout))?
            .map_err(|e| PingError::Other(format!("handshake: {e}")))?;

        let latency = start.elapsed();
        conn.close(0u32.into(), b"ping");
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(latency)
    }
}

/// Accepts any server certificate. Required because proxy servers use self-signed certs.
#[derive(Debug)]
struct PermissiveVerifier;

impl rustls::client::danger::ServerCertVerifier for PermissiveVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}
