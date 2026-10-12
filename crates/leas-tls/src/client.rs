//! Unified client API: one `TlsConfig` + `connect`.
//!
//! Covers plain TLS (any fingerprint identity, verifier seam) and REALITY
//! (any identity via `SpecProvisioner`, Spider-X fallback). The single entry
//! the native layer and external engine users call.

use std::sync::Arc;

use crate::error::Result;
use crate::fingerprints::{Browser, Fingerprint};
use crate::handshake::{self, HandshakeParams, ServerVerifier};
use crate::reality;
use crate::reality::{HelloProvisioner, RealityParams, SpiderConfig};
use crate::record::stream::TlsStream;
use crate::{SecureRandom, Stream};

/// The security mode of a connect.
pub enum TlsMode {
    /// Plain TLS 1.3, fingerprint-shaped hello.
    Plain {
        /// Fingerprint identity; `None` → `Fingerprint::default_for(Browser::Chrome)`.
        fingerprint: Option<Fingerprint>,
        /// Server-authentication seam (`WebPkiVerifier` or a test verifier).
        verifier: Arc<dyn ServerVerifier>,
    },
    /// REALITY: fingerprint-shaped hello + sealed session id + HMAC/Ed25519
    /// server auth; Spider-X fallback on auth failure.
    Reality {
        /// `SpecProvisioner::from(&Fingerprint)` for a browser shape, or any
        /// custom `HelloProvisioner`.
        provisioner: Arc<dyn HelloProvisioner>,
        /// The server's static X25519 public key (decoded `pbk`).
        public_key: [u8; 32],
        /// The REALITY short id (≤8 bytes).
        short_id: Vec<u8>,
        /// Spider-X fallback behavior on auth failure.
        spider: SpiderConfig,
    },
}

/// A fully specified TLS/REALITY connect.
pub struct TlsConfig {
    pub mode: TlsMode,
    /// SNI (the `server_name` extension and verifier host).
    pub server_name: String,
    /// ALPN protocols to offer; `None`/empty uses the profile's own list
    /// (REALITY forces h2 + http/1.1).
    pub alpn: Option<Vec<Vec<u8>>>,
    /// Config-driven curve preferences (wire curve IDs, e.g. from the
    /// proto's `parse_curve_names`); applied to the plain-TLS spec's
    /// `supported_groups`/`key_share` via
    /// [`crate::spec::apply_curve_preferences`]. `None`/empty keeps the
    /// profile's list. REALITY provisioners own their hello shape and
    /// ignore this.
    pub curves: Option<Vec<u16>>,
    /// Random source; `SystemRandom` default.
    pub rng: Arc<dyn SecureRandom>,
}

impl TlsConfig {
    #[must_use]
    pub fn plain(
        fingerprint: Option<Fingerprint>,
        verifier: Arc<dyn ServerVerifier>,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            mode: TlsMode::Plain {
                fingerprint,
                verifier,
            },
            server_name: server_name.into(),
            alpn: None,
            curves: None,
            rng: Arc::new(ring::rand::SystemRandom::new()),
        }
    }

    #[must_use]
    pub fn reality(
        provisioner: Arc<dyn HelloProvisioner>,
        public_key: [u8; 32],
        short_id: Vec<u8>,
        spider: SpiderConfig,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            mode: TlsMode::Reality {
                provisioner,
                public_key,
                short_id,
                spider,
            },
            server_name: server_name.into(),
            alpn: None,
            curves: None,
            rng: Arc::new(ring::rand::SystemRandom::new()),
        }
    }
}

/// Run a TLS/REALITY connect over `stream`, dispatching on `config.mode`.
pub async fn connect<S: Stream + 'static>(stream: S, config: &TlsConfig) -> Result<TlsStream<S>> {
    match &config.mode {
        TlsMode::Plain {
            fingerprint,
            verifier,
        } => {
            let fp = fingerprint
                .clone()
                .unwrap_or_else(|| Fingerprint::default_for(Browser::Chrome));
            let resolved = fp
                .resolve()
                .map_err(|e| crate::error::TlsError::Handshake(e.to_string()))?;
            let spec = match config.curves.as_deref() {
                Some(curves) if !curves.is_empty() => {
                    crate::spec::apply_curve_preferences(&resolved.spec, curves)
                }
                _ => resolved.spec,
            };
            let alpn: Option<Vec<&str>> = config
                .alpn
                .as_ref()
                .map(|list| {
                    list.iter()
                        .map(|p| {
                            std::str::from_utf8(p).map_err(|e| {
                                crate::error::TlsError::Handshake(format!(
                                    "invalid ALPN bytes: {e}"
                                ))
                            })
                        })
                        .collect::<Result<Vec<&str>>>()
                })
                .transpose()?;
            let tls = handshake::connect(
                stream,
                HandshakeParams {
                    spec: &spec,
                    server_name: &config.server_name,
                    alpn: alpn.as_deref(),
                    verifier: verifier.as_ref(),
                    rng: config.rng.as_ref(),
                },
            )
            .await?;
            Ok(tls)
        }
        TlsMode::Reality {
            provisioner,
            public_key,
            short_id,
            spider,
        } => {
            reality::connect_reality(
                stream,
                RealityParams {
                    server_name: &config.server_name,
                    public_key,
                    short_id,
                    provisioner: provisioner.as_ref(),
                    rng: config.rng.as_ref(),
                    spider,
                },
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Arc;

    use super::{TlsConfig, TlsMode, connect};
    use crate::error::TlsError;
    use crate::fingerprints::{Browser, Fingerprint};
    use crate::handshake::ServerVerifier;
    use crate::reality::{SpecProvisioner, SpiderConfig};
    use crate::verify::WebPkiVerifier;
    use parking_lot::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The engine's insecure trust mode: accepts any server (used exactly
    /// like native's `verifier_for` when `insecure` is set).
    fn insecure_verifier() -> Arc<dyn ServerVerifier> {
        Arc::new(WebPkiVerifier::webpki_roots().with_insecure(true))
    }

    fn server_config(cert: &rcgen::Certificate, key: &rcgen::KeyPair) -> rustls::ServerConfig {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        // Workspace feature unification compiles rustls with BOTH backends
        // (ring via our crates, aws-lc-rs via other workspace members), so
        // rustls cannot auto-select a provider here — install ring
        // explicitly. Idempotent: a concurrent/earlier install returns
        // `Err`, ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap()
    }

    /// Spawns a recording rustls TLS server on a blocking thread.
    ///
    /// After the handshake it appends every decrypted plaintext byte to
    /// `recorded` (bounded to the first 512 bytes) and, once it has seen
    /// application data, echoes `pong` back so the client's round-trip
    /// completes. It keeps draining reads (tolerating a client close or
    /// reset) so the client never wedges on TCP backpressure.
    fn spawn_recording_tls_server(recorded: Arc<Mutex<Vec<u8>>>) -> std::net::SocketAddr {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = server_config(&certified.cert, &certified.signing_key);

        tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let timeout = std::time::Duration::from_secs(15);
            sock.set_read_timeout(Some(timeout)).unwrap();
            sock.set_write_timeout(Some(timeout)).unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut sock).unwrap();
            }

            let mut replied = false;
            // A client close (0) or reset (Err) ends the session.
            while let Ok(read) = conn.read_tls(&mut sock) {
                if read == 0 {
                    break;
                }
                let state = conn.process_new_packets().unwrap();
                if state.plaintext_bytes_to_read() > 0 {
                    let mut buf = vec![0u8; state.plaintext_bytes_to_read()];
                    // The buffer is exactly the available plaintext, so a
                    // blocking read_exact cannot stall.
                    conn.reader().read_exact(&mut buf).unwrap();
                    {
                        let mut rec = recorded.lock();
                        let take = buf.len().min(512usize.saturating_sub(rec.len()));
                        rec.extend_from_slice(&buf[..take]);
                    }
                    if !replied {
                        conn.writer().write_all(b"pong").unwrap();
                        conn.write_tls(&mut sock).unwrap();
                        replied = true;
                    }
                }
            }
        });

        addr
    }

    /// The public plain entry with `fingerprint: None` must default to the
    /// latest-Chrome hello, complete the handshake against a real
    /// rustls server, and round-trip application bytes.
    #[tokio::test]
    async fn plain_default_profile_connects() {
        let recorded: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let addr = spawn_recording_tls_server(recorded.clone());

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let config = TlsConfig::plain(None, insecure_verifier(), "localhost");
        let mut conn = connect(tcp, &config).await.unwrap();

        conn.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        conn.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");

        let bytes = recorded.lock().clone();
        assert!(
            bytes.windows(4).any(|w| w == b"ping"),
            "server must have received the client's application data"
        );
    }

    /// The public reality entry against a plain TLS server must surface
    /// [`TlsError::RealityFallback`] (the caller's spider signal), proving
    /// the Reality arm + fallback path run through `connect`.
    #[tokio::test]
    async fn reality_mode_against_plain_server_is_fallback() {
        let recorded: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let addr = spawn_recording_tls_server(recorded.clone());
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let config = TlsConfig::reality(
            Arc::new(SpecProvisioner::from(
                &Fingerprint::new(Browser::Chrome).with_version(130),
            )),
            [0xAB; 32],
            vec![],
            SpiderConfig::default(),
            "localhost",
        );
        let result = connect(tcp, &config).await;
        assert!(
            matches!(result, Err(TlsError::RealityFallback)),
            "expected RealityFallback, got an unexpected handshake result"
        );
    }

    /// The ALPN override's UTF-8 validation must reject non-UTF-8 protocol
    /// bytes before any I/O happens.
    #[tokio::test]
    async fn plain_mode_rejects_invalid_alpn_bytes() {
        let (client, _server) = tokio::io::duplex(64);
        let config = TlsConfig {
            mode: TlsMode::Plain {
                fingerprint: None,
                verifier: insecure_verifier(),
            },
            server_name: "localhost".to_string(),
            alpn: Some(vec![vec![0xFF]]),
            curves: None,
            rng: Arc::new(ring::rand::SystemRandom::new()),
        };
        let result = connect(client, &config).await;
        assert!(
            matches!(result, Err(TlsError::Handshake(_))),
            "non-UTF-8 ALPN bytes must be rejected before the handshake"
        );
    }
}
