//! QUIC dial helpers shared by the xhttp h3 arm and the hysteria2 client.
//!
//! quinn's TLS is internal rustls (spec §5.2 — the engine TLS never wraps
//! QUIC), so the trust anchors and cert verification live on the rustls
//! side here, exactly as they did for xhttp. This is the ONE QUIC TLS
//! construction — the hysteria2 client consumes the same verifier setup as
//! the h3 arm instead of building a second convention.
// The test seam's `thread_local!` initializer is already a `const` block, but
// `missing_const_for_thread_local` fires on it anyway — the windows-gnu false
// positive in clippy#17566. An `allow` on the macro invocation itself is
// ignored (it produces its own `unused_attributes` warning), so the
// suppression sits at module level, where it reaches the expansion.
#![allow(
    clippy::missing_const_for_thread_local,
    reason = "false positive on an already-const initializer: clippy#17566"
)]

use std::net::SocketAddr;
use std::sync::Arc;

use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};

/// rustls `ServerCertVerifier` for the `insecure` TLS option: skips the
/// certificate chain walk but still verifies the handshake signatures (xray
/// `allowInsecure` semantics — the QUIC session stays sound, only the
/// identity check is dropped).
#[derive(Debug)]
pub(crate) struct SkipServerVerify {
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// Test/e2e override: a QUIC-dial trust anchor trusting exactly one CA (the
// harness CA) — the counterpart of `security::fingerprint::set_test_ca` for
// quinn's internal rustls. Thread-local: each `#[tokio::test]` runs on its
// own OS thread with its own harness CA, so parallel e2e cases can't
// clobber each other's trust store. Production builds use webpki-roots and
// carry no test state.
#[cfg(any(test, feature = "e2e-support"))]
std::thread_local! {
    static TEST_CA: std::cell::RefCell<Option<rustls::pki_types::CertificateDer<'static>>> =
        const { std::cell::RefCell::new(None) };
}

/// Install a test-only QUIC trust anchor trusting exactly `ca_der`
/// (test/e2e harness).
#[doc(hidden)]
#[cfg(any(test, feature = "e2e-support"))]
pub fn set_test_ca(ca_der: &[u8]) {
    let der = rustls::pki_types::CertificateDer::from(ca_der.to_vec());
    TEST_CA.with(|c| *c.borrow_mut() = Some(der));
}

/// rustls client config for a QUIC dial.
///
/// ALPN `alpn`, early data enabled (0-RTT), and cert verification mirroring
/// the TLS opts: `insecure` skips the chain walk, otherwise webpki-roots run
/// (with the harness CA replacing the trust anchor in test/e2e builds).
pub fn quic_tls_config(
    ctx: &LinkContext,
    alpn: &[u8],
) -> Result<rustls::ClientConfig, NativeError> {
    let insecure = ctx
        .tls_opts()
        .ok()
        .flatten()
        .and_then(|o| o.insecure)
        .unwrap_or(false);
    // One `ClientConfig` per (trust mode, ALPN) for the process. Building one
    // parses the whole webpki root store — ~40 KiB of allocations — and every
    // feed-wide probe dial did it again: 13 670 failed QUIC dials held 541 MiB
    // live under `transport::quic`, because a failed handshake retains its
    // endpoint for the 300 s idle timeout this transport config sets.
    //
    // Test/e2e builds keep the per-call build: the harness CA is a
    // thread-local that changes between tests.
    #[cfg(not(any(test, feature = "e2e-support")))]
    let key = (insecure, alpn.to_vec());
    #[cfg(not(any(test, feature = "e2e-support")))]
    if let Some(cached) = tls_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
    {
        return Ok(cached.clone());
    }
    let mut tls = if insecure {
        let algorithms = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerify { algorithms }))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        #[cfg(any(test, feature = "e2e-support"))]
        match TEST_CA.with(|c| c.borrow().clone()) {
            Some(ca) => roots
                .add(ca)
                .map_err(|e| NativeError::Config(format!("QUIC test CA: {e}")))?,
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        #[cfg(not(any(test, feature = "e2e-support")))]
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls.alpn_protocols = vec![alpn.to_vec()];
    tls.enable_early_data = true;
    #[cfg(not(any(test, feature = "e2e-support")))]
    tls_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, tls.clone());
    Ok(tls)
}

/// Build-once cache behind [`quic_tls_config`].
#[cfg(not(any(test, feature = "e2e-support")))]
fn tls_cache()
-> &'static std::sync::Mutex<std::collections::HashMap<(bool, Vec<u8>), rustls::ClientConfig>> {
    static CACHE: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<(bool, Vec<u8>), rustls::ClientConfig>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    &CACHE
}

/// Convert the rustls config into a quinn `ClientConfig` with a long idle
/// timeout + keepalive (hysteria2 and xray both keep idle QUIC tunnels alive
/// ~300s — quinn's 30s default would kill them mid-session).
///
/// QUIC DATAGRAM frames (the hysteria2 UDP relay) ride quinn's own default
/// `datagram_receive_buffer_size` — `Some(STREAM_RWND)` in
/// `quinn-proto/src/config/transport.rs`, which is also what gates SENDING
/// datagrams; clearing it would disable the relay in both directions.
#[must_use]
pub(crate) fn quinn_client_config(tls: rustls::ClientConfig) -> quinn::ClientConfig {
    let mut quic = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .expect("rustls QUIC config conversion"),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_mins(5))
                .expect("300s idle timeout fits a VarInt"),
        ))
        .keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    quic.transport_config(Arc::new(transport));
    quic
}

/// Bind a QUIC client endpoint on the same address family as the server.
///
/// ONE endpoint per family, shared by every dial. A fresh `Endpoint::client`
/// allocates a ~188 KiB receive buffer (quinn sizes it
/// `max_udp_payload_size × GRO segments × BATCH_SIZE`), and a feed-wide probe
/// runs these dials hundreds per second: the h3-only lab peaked at 202 MiB
/// live in `client_endpoint`, and the full-feed run held 541 MiB under
/// `transport::quic`. One UDP socket multiplexes every connection (quinn
/// routes by connection id), so the buffer is paid once instead of per dial.
/// The obfuscated hysteria2 socket is a different wrapper and still binds per
/// dial (see `protocol::hysteria2::quic::client_endpoint`).
///
/// Test and e2e builds bind per dial: the shared endpoint's driver task lives
/// on the runtime that created it, and those harnesses create one runtime per
/// case.
#[must_use]
pub(crate) fn client_endpoint(server_addr: SocketAddr) -> quinn::Endpoint {
    #[cfg(any(test, feature = "e2e-support"))]
    {
        let bind: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().expect("static ipv6 bind addr")
        } else {
            "0.0.0.0:0".parse().expect("static ipv4 bind addr")
        };
        quinn::Endpoint::client(bind).expect("quic client endpoint bind")
    }
    #[cfg(not(any(test, feature = "e2e-support")))]
    {
        use std::sync::LazyLock;
        static V4: LazyLock<quinn::Endpoint> = LazyLock::new(|| {
            quinn::Endpoint::client("0.0.0.0:0".parse().expect("static ipv4 bind addr"))
                .expect("quic client endpoint bind")
        });
        static V6: LazyLock<quinn::Endpoint> = LazyLock::new(|| {
            quinn::Endpoint::client("[::]:0".parse().expect("static ipv6 bind addr"))
                .expect("quic client endpoint bind")
        });
        if server_addr.is_ipv6() {
            V6.clone()
        } else {
            V4.clone()
        }
    }
}

/// Complete a QUIC client handshake to `addr` with `server_name` SNI,
/// bounded by [`timeouts::DIAL`]. Tries 0-RTT first (a fresh connection
/// without a ticket falls back to the full handshake — xray `DialEarly`).
pub(crate) async fn connect(
    endpoint: &quinn::Endpoint,
    config: quinn::ClientConfig,
    addr: SocketAddr,
    server_name: &str,
    step: &'static str,
) -> Result<quinn::Connection, NativeError> {
    let connecting = endpoint
        .connect_with(config, addr, server_name)
        .map_err(|e| NativeError::Dial(format!("{step} connect: {e}")))?;
    let conn = match connecting.into_0rtt() {
        Ok((conn, _accepted)) => conn,
        Err(connecting) => {
            let limit = timeouts::DIAL;
            tokio::time::timeout(limit, connecting)
                .await
                .map_err(|_| NativeError::Timeout { step, limit })?
                .map_err(|e| NativeError::Dial(format!("{step} handshake: {e}")))?
        }
    };
    Ok(conn)
}
