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
        /// `SpecProvisioner::try_from(&Fingerprint)` for a browser shape, or any
        /// custom `HelloProvisioner`.
        provisioner: Arc<dyn HelloProvisioner>,
        /// The server's static X25519 public key (decoded `pbk`).
        public_key: [u8; 32],
        /// The REALITY short id (≤8 bytes).
        short_id: Vec<u8>,
        /// REALITY's ML-DSA-65 verification key (1952 bytes) when the profile
        /// carries `pqv`; `None` keeps the HMAC+Ed25519 rule alone.
        mldsa65_verify: Option<Vec<u8>>,
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
        mldsa65_verify: Option<Vec<u8>>,
        spider: SpiderConfig,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            mode: TlsMode::Reality {
                provisioner,
                public_key,
                short_id,
                mldsa65_verify,
                spider,
            },
            server_name: server_name.into(),
            alpn: None,
            curves: None,
            rng: Arc::new(ring::rand::SystemRandom::new()),
        }
    }
}

/// Whether this identity permutes its extension order.
///
/// Chromium (Chrome/Edge/Brave/Opera/Samsung) from major 108; the resolved
/// row fills in a version when the query left it unset, so a bare
/// `Browser::Chrome` follows its roster row's major.
fn permutes_extensions(requested: &Fingerprint, resolved: &Fingerprint) -> bool {
    let chromium = matches!(
        resolved.browser,
        Browser::Chrome
            | Browser::Edge
            | Browser::Brave
            | Browser::Opera
            | Browser::SamsungInternet
    );
    let major = resolved.version.or(requested.version).unwrap_or(0);
    chromium && major >= 108
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
            // ALPN protocol names are opaque bytes (RFC 7301 §3.1) — the
            // config already carries them that way, so no encoding check.
            let alpn: Option<Vec<&[u8]>> = config
                .alpn
                .as_ref()
                .map(|list| list.iter().map(Vec::as_slice).collect());
            // Extension permutation is an identity property, not a spec one:
            // Chromium permutes from Chrome 108 (Platform Status 5124606246518784),
            // Firefox's default build and Safari do not.
            let permute = permutes_extensions(&fp, &resolved.fingerprint);
            let tls = handshake::connect_with_permutation(
                stream,
                HandshakeParams {
                    spec: &spec,
                    server_name: &config.server_name,
                    alpn: alpn.as_deref(),
                    verifier: verifier.as_ref(),
                    rng: config.rng.as_ref(),
                },
                permute,
            )
            .await?;
            Ok(tls)
        }
        TlsMode::Reality {
            provisioner,
            public_key,
            short_id,
            mldsa65_verify,
            spider,
        } => {
            reality::connect_reality(
                stream,
                RealityParams {
                    server_name: &config.server_name,
                    public_key,
                    short_id,
                    provisioner: provisioner.as_ref(),
                    mldsa65_verify: mldsa65_verify.as_deref(),
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
            Arc::new(
                SpecProvisioner::try_from(&Fingerprint::new(Browser::Chrome).with_version(130))
                    .expect("chrome 130 resolves"),
            ),
            [0xAB; 32],
            vec![],
            None,
            SpiderConfig::default(),
            "localhost",
        );
        let result = connect(tcp, &config).await;
        assert!(
            matches!(result, Err(TlsError::RealityFallback)),
            "expected RealityFallback, got an unexpected handshake result"
        );
    }

    /// RFC 7301 §3.1: a protocol name is an opaque byte string, so a
    /// non-UTF-8 ALPN entry must reach the wire verbatim instead of being
    /// rejected at connect time.
    #[tokio::test]
    async fn plain_mode_carries_opaque_alpn_bytes_to_the_wire() {
        let (client, mut server) = tokio::io::duplex(8192);
        let config = TlsConfig {
            mode: TlsMode::Plain {
                fingerprint: None,
                verifier: insecure_verifier(),
            },
            server_name: "localhost".to_string(),
            alpn: Some(vec![vec![0xFF, 0x00]]),
            curves: None,
            rng: Arc::new(ring::rand::SystemRandom::new()),
        };
        let handshake = tokio::spawn(async move { connect(client, &config).await });

        let mut buf = vec![0u8; 8192];
        let n = server.read(&mut buf).await.unwrap();
        drop(server);
        let outcome = handshake.await.expect("the connect task must not panic");
        assert!(
            n > 5,
            "the client must have written a ClientHello record, got {n} bytes \
             (connect ok: {})",
            outcome.is_ok()
        );

        // Record header (5) then the ClientHello handshake message.
        let hello = crate::hello::parse::parse_hello(&buf[5..n]).expect("parse ClientHello");
        assert_eq!(
            hello.extension(0x0010).expect("alpn"),
            &[0x00, 0x03, 0x02, 0xFF, 0x00],
            "the opaque protocol bytes must be framed as list_len || len || bytes"
        );
    }

    #[test]
    fn extension_permutation_is_family_and_era_scoped() {
        use crate::fingerprints::Browser;
        let fp = |browser, version: Option<u16>| Fingerprint {
            browser,
            version,
            os: None,
            device: None,
        };
        // Chromium from 108 permutes; 107 does not.
        assert!(super::permutes_extensions(
            &fp(Browser::Chrome, Some(108)),
            &fp(Browser::Chrome, Some(108)),
        ));
        assert!(!super::permutes_extensions(
            &fp(Browser::Chrome, Some(107)),
            &fp(Browser::Chrome, Some(107)),
        ));
        // Every Chromium brand follows the same rule.
        for brand in [
            Browser::Edge,
            Browser::Brave,
            Browser::Opera,
            Browser::SamsungInternet,
        ] {
            assert!(super::permutes_extensions(
                &fp(brand, Some(140)),
                &fp(brand, Some(140))
            ));
        }
        // Firefox (default NSS build) and Safari stay fixed-order, whatever
        // the version.
        assert!(!super::permutes_extensions(
            &fp(Browser::Firefox, Some(150)),
            &fp(Browser::Firefox, Some(150)),
        ));
        assert!(!super::permutes_extensions(
            &fp(Browser::Safari, Some(26)),
            &fp(Browser::Safari, Some(26)),
        ));
        // The resolved row's major wins when the query left it unset.
        assert!(super::permutes_extensions(
            &fp(Browser::Chrome, None),
            &fp(Browser::Chrome, Some(131)),
        ));
        assert!(!super::permutes_extensions(
            &fp(Browser::Chrome, None),
            &fp(Browser::Chrome, Some(93)),
        ));
    }
}
