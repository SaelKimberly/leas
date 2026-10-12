//! REALITY protocol module: fingerprint-shaped `ClientHello` provisioning,
//! the ring port of the shoes REALITY client, and the 9-step wire contract.
//!
//! Wire contract (modeled on `shoes/src/reality/`, MIT; adapted to
//! xtls/reality 2025-10+ keyshare semantics):
//! 1. X25519 keypair; the `ClientHello.random` (32 B) is the protocol
//!    random — `[0..20]` is the HKDF salt, `[20..32]` the AES-GCM nonce.
//! 2. `auth_shared` = `ECDH(client_priv`, `server_pub` from `pbk`) — the
//!    REALITY auth key. Since 2025-10 the server's TLS keyshare is a fresh
//!    *ephemeral* key (the static key authenticates only), so the TLS 1.3
//!    key schedule uses `ECDH(client_priv`, `server_keyshare`) instead.
//! 3. `auth_key` = HKDF-SHA256(auth_shared, salt = random[0..20], info b"REALITY").
//! 4. `SessionId` plaintext 16 B = version(1,8,0) + pad(1) + timestamp u32
//!    BE + `short_id` (≤8 bytes, zero-padded).
//! 5. `ClientHello`: Chrome-133 fingerprint, SNI steal target, X25519
//!    keyshare, suites 0x1301-03, ALPN h2+http/1.1.
//! 6. AAD = hello with `SessionId` zeroed; nonce = random[20..32];
//!    `SessionId` = AES-256-GCM(auth_key, nonce, plaintext, aad).
//! 7. Restore `SessionId` (builder-returned range, never hardcoded offset).
//! 8. Server auth (port `reality_client_verify.rs`): cert signature field ==
//!    HMAC-SHA512(auth_key, `ed25519_pub`), Ed25519 `CertificateVerify` over
//!    the transcript. No PKI chain check.
//! 9. TLS 1.3 key schedule + `Finished` (server `Finished` MAC checked,
//!    client `Finished` sent), then app records via [`TlsStream`].

pub mod auth;
pub mod messages;
pub mod spider;
pub mod verify;

use std::ops::Range;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::SecureRandom;
use crate::crypto::X25519KeyPair;
use crate::crypto::mlkem::Mlkem768;
use crate::error::{Result, TlsError};
use crate::fingerprints::Fingerprint;
use crate::handshake::{AuthOutcome, ServerAuth, drive};
use crate::hello::{BuildParams, build_hello};
use crate::record::stream::TlsStream;
use crate::spec::{ClientHelloSpec, ExtensionSpec, KeyShareGroup, SessionIdSpec};

/// The `ClientHello` ALPN list REALITY always offers.
const REALITY_ALPN: &[&str] = &["h2", "http/1.1"];

// ── Provisioner contract ───────────────────────────────────────────────────

/// A fingerprint-shaped `ClientHello` that the REALITY connector fills in:
/// keyshare, SNI, random and `SessionId` are injected at connect time.
pub trait HelloProvisioner: Send + Sync {
    /// Returns the bare `ClientHello` plus the `SessionId` byte range.
    /// The returned range is computed by the builder — never hardcoded.
    fn provision(&self, params: &HelloProvisionParams<'_>) -> Result<ProvisionedHello>;

    /// Whether the provisioned `ClientHello` offers a hybrid ML-KEM key
    /// share. The conservative default `true` keeps the connector
    /// generating an ML-KEM-768 key pair (a custom provisioner may embed
    /// a hybrid entry invisible to us); [`SpecProvisioner`] overrides
    /// with the actual spec check so classical-only profiles skip the
    /// keygen entirely.
    fn offers_hybrid_key_share(&self) -> bool {
        true
    }
}

/// Inputs the REALITY connector hands to a provisioner.
pub struct HelloProvisionParams<'a> {
    /// The SNI steal target (the `server_name` extension host).
    pub server_name: &'a str,
    /// ALPN protocols to offer; `None` uses the spec's own list.
    pub alpn: Option<&'a [&'a str]>,
    /// The connector's X25519 public key, injected into `key_share`.
    pub x25519_pub: &'a [u8; 32],
    /// The connector's ML-KEM-768 encapsulation key (1184 bytes) when the
    /// spec's `key_share` carries a hybrid entry.
    pub mlkem768_pub: Option<&'a [u8]>,
    /// Random source for the GREASE values and the client random.
    pub rng: &'a dyn SecureRandom,
}

/// A provisioned `ClientHello` (handshake bytes, no record header).
pub struct ProvisionedHello {
    /// Handshake message (`type 0x01` + 3-byte length + body) with the
    /// `AuthPayload` slot zeroed.
    pub handshake_bytes: Vec<u8>,
    /// Byte range of the `SessionId` field within `handshake_bytes`.
    pub session_id_range: Range<usize>,
}

impl ProvisionedHello {
    /// The `SessionId` bytes (the REALITY auth payload slot). The server's
    /// `ServerHello` must echo them exactly (RFC 8446 §4.1.3).
    #[must_use]
    pub fn session_id(&self) -> &[u8] {
        &self.handshake_bytes[self.session_id_range.clone()]
    }
}

/// The wire-exact `chrome_130` spec with the X25519MLKEM768 key share (and
/// its `supported_groups` entry) restored. Real Chrome 130+ sends the
/// hybrid share; the JA4-driven profile omits it because JA3/JA4 do not
/// fingerprint key shares. Grafting it back keeps REALITY's post-quantum
/// path alive after the roster reduction dropped the Chrome-133 preset.
fn fixed_chrome_spec() -> ClientHelloSpec {
    let mut spec = crate::profiles::hand_selected::chrome_130();
    for ext in &mut spec.extensions {
        match ext {
            ExtensionSpec::SupportedGroups(groups) => {
                groups.insert(1, 0x11EC); // x25519mlkem768, after GREASE
            }
            ExtensionSpec::KeyShare(groups) => {
                groups.insert(1, KeyShareGroup::X25519Mlkem768);
            }
            _ => {}
        }
    }
    spec
}

/// Fixed Chrome-shaped provisioner (first engine; ported from shoes).
///
/// Serves the surviving wire-exact Chrome desktop spec
/// (`profiles::hand_selected::chrome_130` plus the hybrid key share — see
/// [`fixed_chrome_spec`]). The Chrome-133 hand profile was dropped in the
/// roster reduction.
pub struct FixedChrome133;

/// A `HelloProvisioner` shaped by any concrete hello spec: REALITY's
/// auth payload rides the session-id slot of the given spec.
pub struct SpecProvisioner {
    spec_source: Box<dyn Fn() -> ClientHelloSpec + Send + Sync>,
}

impl SpecProvisioner {
    /// Shapes the provisioner from a spec-producing closure.
    #[must_use]
    pub fn new(spec_source: impl Fn() -> ClientHelloSpec + Send + Sync + 'static) -> Self {
        Self {
            spec_source: Box::new(spec_source),
        }
    }
}

impl From<&Fingerprint> for SpecProvisioner {
    fn from(fp: &Fingerprint) -> Self {
        // REALITY provisioning needs a concrete hello; unknown identities
        // panic here by contract (resolve errors are a configuration bug —
        // validated upstream when the fingerprint was configured).
        let spec_source = {
            let fp = fp.clone();
            move || fp.resolve().expect("fingerprint must resolve").spec
        };
        Self::new(spec_source)
    }
}

impl HelloProvisioner for SpecProvisioner {
    fn provision(&self, params: &HelloProvisionParams<'_>) -> Result<ProvisionedHello> {
        let mut spec = (self.spec_source)();
        spec.session_id = SessionIdSpec::AuthPayload { len: 32 };
        let built = build_hello(
            &spec,
            &BuildParams {
                server_name: params.server_name,
                alpn: params.alpn,
                x25519_pub: params.x25519_pub,
                mlkem768_pub: params.mlkem768_pub,
                rng: params.rng,
            },
        )?;
        let session_id_range = built
            .session_id_range
            .ok_or_else(|| TlsError::Spec("spec must use SessionIdSpec::AuthPayload".into()))?;
        Ok(ProvisionedHello {
            handshake_bytes: built.handshake_bytes,
            session_id_range,
        })
    }

    fn offers_hybrid_key_share(&self) -> bool {
        (self.spec_source)().extensions.iter().any(|ext| {
            matches!(
                ext,
                ExtensionSpec::KeyShare(groups)
                    if groups.iter().any(|g| matches!(
                        g,
                        KeyShareGroup::X25519Mlkem768
                            | KeyShareGroup::Secp256r1Mlkem768
                            | KeyShareGroup::Secp384r1Mlkem1024
                    ))
            )
        })
    }
}

impl HelloProvisioner for FixedChrome133 {
    fn provision(&self, params: &HelloProvisionParams<'_>) -> Result<ProvisionedHello> {
        SpecProvisioner::new(fixed_chrome_spec).provision(params)
    }
}

// ── Spider session ─────────────────────────────────────────────────────────

/// Bounded spider session configuration for the REALITY fallback path.
///
/// When the server fails REALITY auth (a real certificate — transparent
/// proxy / possible MITM or redirection), the engine surfaces
/// [`TlsError::RealityFallback`] and the caller may re-connect as a plain
/// browser to the steal target: the "spider" walks `paths` with
/// `request_interval` between requests, `max_gets` requests per path
/// (bounded, mirroring xray's anti-probing). The values are defaults only;
/// `connect_reality` spawns the spider task (see [`spider`]) on the
/// fallback path.
#[derive(Clone)]
pub struct SpiderConfig {
    /// Paths from the URL `spx`; default `["/"]`.
    pub paths: Vec<String>,
    /// Bounded spider session (GETs before close); default 4.
    pub max_gets: usize,
    /// Delay between GETs; default 1s.
    pub request_interval: std::time::Duration,
}

impl Default for SpiderConfig {
    fn default() -> Self {
        Self {
            paths: vec!["/".to_string()],
            max_gets: 4,
            request_interval: std::time::Duration::from_secs(1),
        }
    }
}

// ── Connector ──────────────────────────────────────────────────────────────

/// Connection-level inputs for [`connect_reality`].
pub struct RealityParams<'a> {
    /// The SNI steal target.
    pub server_name: &'a str,
    /// The server's static X25519 public key (decoded `pbk`).
    pub public_key: &'a [u8; 32],
    /// REALITY short id, ≤8 bytes.
    pub short_id: &'a [u8],
    /// The `ClientHello` fingerprint provisioner.
    pub provisioner: &'a dyn HelloProvisioner,
    /// Random source — the crate's [`SecureRandom`] seam. ring's
    /// `SystemRandom` coerces via the blanket impl; tests implement the
    /// trait directly for fixed-seed vectors.
    pub rng: &'a dyn SecureRandom,
    /// Spider session for the fallback path (defaults are fine; customize
    /// `paths`/`max_gets`/`request_interval` for a different walk).
    pub spider: &'a SpiderConfig,
}

/// Performs the full REALITY client handshake over `stream`, returning a
/// record-framed application-data stream.
///
/// Implements the 9-step wire contract above: the REALITY session-id seal
/// (steps 1–5) runs here, then the shared [`drive`] takes over with a
/// [`ServerAuth::Reality`] dispatch — the HMAC/Ed25519 server auth in place
/// of the plain-TLS verifier seam. A server flight that fails REALITY auth
/// (a real certificate) is reported as [`TlsError::RealityFallback`], not a
/// hard error: the caller may fall back to the spider session.
pub async fn connect_reality<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    params: RealityParams<'_>,
) -> Result<TlsStream<S>> {
    // 1. Ephemeral X25519 key pair (the ClientHello keyshare). The
    //    connector draws no randomness of its own: the client random inside
    //    the provisioned hello *is* the REALITY random.
    let keypair = X25519KeyPair::generate(params.rng)?;

    // 1b. Ephemeral ML-KEM-768 key pair: only when the provisioner's spec
    //     offers a hybrid key-share entry (the Chrome-133 family does) —
    //     the encapsulation key then flows into the provisioned key share.
    //     Classical-only profiles skip the ~100 µs keygen entirely.
    let (pq_public, pq_secret) = if params.provisioner.offers_hybrid_key_share() {
        let (pk, sk) = Mlkem768::generate_keypair();
        (Some(pk), Some(sk))
    } else {
        (None, None)
    };

    // 2. Provision the Chrome-133-shaped ClientHello with a zeroed
    //    AuthPayload slot; the connector's keyshare and rng flow through.
    let mut hello = params.provisioner.provision(&HelloProvisionParams {
        server_name: params.server_name,
        alpn: Some(REALITY_ALPN),
        x25519_pub: &keypair.public_key(),
        mlkem768_pub: pq_public
            .as_ref()
            .map(crate::crypto::mlkem::PublicKey::as_bytes),
        rng: params.rng,
    })?;
    let client_random = messages::extract_client_random(&hello.handshake_bytes)?;

    // 3. SessionId plaintext: version(1,8,0) || pad(0) || timestamp ||
    //    short_id (≤8 bytes, zero-padded).
    let timestamp = messages::now_timestamp()?;
    let plaintext = messages::build_session_id_plaintext(timestamp, params.short_id)?;

    // 4. ECDH with the server's static public key → the REALITY auth key.
    //    (The TLS 1.3 key schedule below uses the server's *ephemeral*
    //    keyshare instead — xtls/reality 2025-10+ no longer reuses the
    //    static key as the TLS keyshare.)
    let auth_shared = keypair.agree(params.public_key)?;
    let auth_key = auth::derive_auth_key(&auth_shared, &client_random[..20], b"REALITY")?;

    // 5. Seal the SessionId (AAD = the hello with the slot zeroed, i.e. the
    //    provisioned bytes) and splice it into the builder-returned range.
    messages::seal_and_splice(&mut hello, &plaintext, &auth_key, &client_random[20..])?;

    // 6. Drive the handshake: the shared `drive()` writes the ClientHello
    //    record, reads the ServerHello (which must echo the sealed session
    //    id — the REALITY auth payload), derives the TLS 1.3 key schedule
    //    over the wire ClientHello, and dispatches the REALITY server auth
    //    (certificate HMAC + Ed25519 CertificateVerify over the transcript,
    //    no PKI chain). Any auth failure means the server is not REALITY —
    //    a real certificate (transparent proxy / possible MITM or
    //    redirection) — which surfaces as [`AuthOutcome::RealityFallback`]
    //    rather than a hard error, matching xray's `!Verified` handling.
    let (tls, outcome) = drive(
        stream,
        &hello.handshake_bytes,
        hello.session_id(),
        keypair,
        pq_secret.as_ref(),
        params.server_name,
        &[],
        ServerAuth::Reality {
            auth_key: &auth_key,
        },
    )
    .await?;
    match outcome {
        AuthOutcome::Ok => Ok(tls),
        AuthOutcome::RealityFallback => {
            // The TLS session to the real site is established and usable —
            // hand it to the Spider-X task so the connection looks like a
            // browsing session, then report the fallback to the caller.
            let spider = params.spider.clone();
            let sni = params.server_name.to_string();
            tokio::spawn(spider::run(tls, spider, sni));
            Err(TlsError::RealityFallback)
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::io::{Read, Write};
    use std::sync::Arc;

    use super::*;
    use crate::hello::parse::parse_hello;
    use crate::http2;
    use parking_lot::Mutex;

    /// Builds the RFC 8446 §4.4.3 signed content over a 32-byte transcript
    /// hash on the stack (test fixture signer).
    fn signed_content_fixture(transcript_hash: &[u8; 32]) -> [u8; 64 + 33 + 1 + 32] {
        let mut out = [0u8; 64 + 33 + 1 + 32];
        out[..64].copy_from_slice(&[0x20u8; 64]);
        out[64..64 + 33].copy_from_slice(b"TLS 1.3, server CertificateVerify");
        out[64 + 33] = 0x00;
        out[64 + 33 + 1..].copy_from_slice(transcript_hash);
        out
    }

    /// The Chrome-133 provisioner lays out a valid `ClientHello` with a
    /// 32-byte zeroed `AuthPayload` slot at the reported range.
    #[test]
    fn fixed_chrome133_provisioner_builds_auth_payload_hello() {
        let rng = ring::rand::SystemRandom::new();
        let (mlkem_pk, _) = Mlkem768::generate_keypair();
        let hello = FixedChrome133
            .provision(&HelloProvisionParams {
                server_name: "www.microsoft.com",
                alpn: Some(REALITY_ALPN),
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: Some(mlkem_pk.as_bytes()),
                rng: &rng,
            })
            .unwrap();

        assert_eq!(hello.session_id_range.len(), 32);
        assert!(hello.session_id_range.end <= hello.handshake_bytes.len());

        let parsed = parse_hello(&hello.handshake_bytes).unwrap();

        // The AuthPayload slot is in the legacy session id, currently zeroed.
        assert_eq!(
            &hello.handshake_bytes[hello.session_id_range.clone()],
            &[0u8; 32]
        );
        assert_eq!(parsed.session_id, vec![0u8; 32]);

        // Chrome-133 surface: TLS 1.3 suites, X25519 keyshare carrying the
        // connector's public key, SNI steal target, ALPN h2 + http/1.1.
        for suite in [0x1301u16, 0x1302, 0x1303] {
            assert!(
                parsed.cipher_suites.contains(&suite),
                "missing cipher suite {suite:#06x}"
            );
        }
        let key_share = parsed.extension(0x0033).expect("key_share extension");
        assert!(
            key_share.windows(32).any(|w| w == [0xAB; 32]),
            "key_share must carry the connector's X25519 public key"
        );
        let sni = parsed.extension(0x0000).expect("server_name extension");
        assert!(
            sni.windows(b"www.microsoft.com".len())
                .any(|w| w == b"www.microsoft.com"),
            "SNI must carry the steal target"
        );
        let alpn = parsed.extension(0x0010).expect("ALPN extension");
        assert!(alpn.windows(2).any(|w| w == b"h2"), "ALPN must offer h2");
        assert!(
            alpn.windows(8).any(|w| w == b"http/1.1"),
            "ALPN must offer http/1.1"
        );
    }

    /// Deterministic RNG feeding back a fixed byte sequence (same shape as
    /// `hello::tests::FixedRandom`), so two provision calls draw identical
    /// bytes and the golden-equality assertion is meaningful.
    struct FixedRandom {
        bytes: Vec<u8>,
        pos: AtomicUsize,
    }

    impl SecureRandom for FixedRandom {
        fn fill(&self, dest: &mut [u8]) -> std::result::Result<(), ring::error::Unspecified> {
            let mut pos = self.pos.load(Ordering::Relaxed);
            for b in dest.iter_mut() {
                *b = *self.bytes.get(pos).ok_or(ring::error::Unspecified)?;
                pos += 1;
            }
            self.pos.store(pos, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn fixed_chrome_provisioner_keeps_hybrid_share_and_chrome130_ja4() {
        // The roster reduction dropped the Chrome-133 preset; the fixed
        // provisioner now shapes the surviving chrome_130 spec with the
        // X25519MLKEM768 key share grafted back (see `fixed_chrome_spec`).
        // Assert both halves of that contract: the hello still offers the
        // 1216-byte hybrid share (REALITY's PQ path), and its JA4-relevant
        // wire — cipher set, extension ids, signature-alg order — still
        // matches the chrome_130 profile exactly (JA3/JA4 do not
        // fingerprint key shares, so the graft is invisible to them).
        use crate::crypto::fingerprint::ja3::Ja3Fields;
        use crate::crypto::fingerprint::ja4::full_ja4;

        let (mlkem_pk, _) = Mlkem768::generate_keypair();
        let rng = FixedRandom {
            bytes: vec![0x42; 128],
            pos: AtomicUsize::new(0),
        };
        let fixed = FixedChrome133
            .provision(&HelloProvisionParams {
                server_name: "www.microsoft.com",
                alpn: Some(REALITY_ALPN),
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: Some(mlkem_pk.as_bytes()),
                rng: &rng,
            })
            .unwrap();

        let parsed = parse_hello(&fixed.handshake_bytes).unwrap();
        let ks_ext = parsed.extension(0x0033).unwrap();
        let list_len = u16::from_be_bytes([ks_ext[0], ks_ext[1]]) as usize;
        let mut off = 2usize;
        let mut saw_hybrid = false;
        while off + 4 <= (2 + list_len).min(ks_ext.len()) {
            let group = u16::from_be_bytes([ks_ext[off], ks_ext[off + 1]]);
            let kx_len = u16::from_be_bytes([ks_ext[off + 2], ks_ext[off + 3]]) as usize;
            if group == 0x11EC {
                assert_eq!(kx_len, 1216, "X25519MLKEM768 share must be 1184 + 32 bytes");
                saw_hybrid = true;
            }
            off += 4 + kx_len;
        }
        assert!(
            saw_hybrid,
            "fixed provisioner must offer the X25519MLKEM768 key share"
        );

        // The grafted hybrid share pushes the record past the 512-byte
        // padding target, so the builder omits the padding extension —
        // exactly what a real Chrome 130+ hello with a hybrid share looks
        // like. Compare JA4 modulo padding, which is never fingerprinted.
        let mut profile_spec = crate::profiles::hand_selected::chrome_130();
        profile_spec
            .extensions
            .retain(|e| !matches!(e, ExtensionSpec::Padding));
        let profile_ja4 = full_ja4(&Ja3Fields::from_spec(&profile_spec));
        assert_eq!(
            full_ja4(&Ja3Fields::from(&parsed)),
            profile_ja4,
            "fixed provisioner must preserve the chrome_130 JA4"
        );
    }

    /// A plain rustls server (no REALITY on the wire): echoes the client's
    /// legacy session id (RFC 8446 §4.1.3) and serves a real self-signed
    /// certificate. Workspace feature unification compiles rustls with BOTH
    /// backends, so install the ring provider explicitly (idempotent).
    fn plain_tls_server_config(
        cert: &rcgen::Certificate,
        key: &rcgen::KeyPair,
    ) -> rustls::ServerConfig {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let _ = rustls::crypto::ring::default_provider().install_default();
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap()
    }

    /// Spawns the plain rustls server on a blocking thread, recording every
    /// decrypted post-handshake byte (the spider's HTTP/2 plaintext) into
    /// `recorded` — bounded to the first 512 bytes, then keeps draining
    /// reads so the spider's writes never wedge on TCP backpressure.
    ///
    /// After the handshake it sends its own empty SETTINGS (RFC 7540 §3.5),
    /// ACKs the client's SETTINGS, and answers every `END_STREAM` HEADERS
    /// with an empty HEADERS + `END_STREAM` on the same stream (a 204-style
    /// reply) so the spider's GETs complete promptly. The handshake itself
    /// completes because `drive()` sends the client `Finished` even on the
    /// fallback path.
    fn spawn_recording_plain_tls_server(recorded: Arc<Mutex<Vec<u8>>>) -> std::net::SocketAddr {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = plain_tls_server_config(&certified.cert, &certified.signing_key);

        tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let timeout = std::time::Duration::from_secs(15);
            sock.set_read_timeout(Some(timeout)).unwrap();
            sock.set_write_timeout(Some(timeout)).unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut sock).is_err() {
                    return;
                }
            }
            // Server connection preface: our own empty SETTINGS.
            conn.writer()
                .write_all(&http2::make_frame(http2::FRAME_SETTINGS, 0, 0, &[]))
                .unwrap();
            conn.write_tls(&mut sock).unwrap();

            // Decrypted HTTP/2 plaintext: 24-byte preface, then 9-byte
            // frame header + payload; `off` is the parse cursor.
            let mut plain = Vec::new();
            let mut off = 0usize;
            loop {
                if conn.read_tls(&mut sock).unwrap() == 0 {
                    break; // the spider task finished and closed the connection
                }
                let state = conn.process_new_packets().unwrap();
                if state.plaintext_bytes_to_read() > 0 {
                    let mut buf = vec![0u8; state.plaintext_bytes_to_read()];
                    // The buffer is exactly the available plaintext, so a
                    // blocking read_exact cannot stall.
                    conn.reader().read_exact(&mut buf).unwrap();
                    plain.extend_from_slice(&buf);
                }

                // Record everything new since the last parse pass, bounded.
                {
                    let mut rec = recorded.lock();
                    let take = (plain.len() - off).min(512usize.saturating_sub(rec.len()));
                    rec.extend_from_slice(&plain[off..off + take]);
                }

                // Skip the client preface (may span several reads).
                if off < http2::PREFACE.len() {
                    if plain.len() < http2::PREFACE.len() {
                        continue;
                    }
                    off = http2::PREFACE.len();
                }

                // Parse complete frames and reply per RFC 7540.
                loop {
                    if plain.len() - off < 9 {
                        break; // incomplete frame header
                    }
                    let len = (usize::from(plain[off]) << 16)
                        | (usize::from(plain[off + 1]) << 8)
                        | usize::from(plain[off + 2]);
                    let frame_len = 9usize + len;
                    if plain.len() - off < frame_len {
                        break; // incomplete frame payload
                    }
                    let ftype = plain[off + 3];
                    let flags = plain[off + 4];
                    let stream_id = u32::from_be_bytes([
                        plain[off + 5] & 0x7F,
                        plain[off + 6],
                        plain[off + 7],
                        plain[off + 8],
                    ]);
                    off += frame_len;
                    match ftype {
                        http2::FRAME_SETTINGS if flags & http2::FLAG_ACK == 0 => {
                            conn.writer()
                                .write_all(&http2::make_frame(
                                    http2::FRAME_SETTINGS,
                                    http2::FLAG_ACK,
                                    0,
                                    &[],
                                ))
                                .unwrap();
                            conn.write_tls(&mut sock).unwrap();
                        }
                        http2::FRAME_HEADERS if flags & http2::FLAG_END_STREAM != 0 => {
                            conn.writer()
                                .write_all(&http2::make_frame(
                                    http2::FRAME_HEADERS,
                                    http2::FLAG_END_STREAM | http2::FLAG_END_HEADERS,
                                    stream_id,
                                    &[],
                                ))
                                .unwrap();
                            conn.write_tls(&mut sock).unwrap();
                        }
                        _ => {}
                    }
                }
            }
        });

        addr
    }

    /// A REALITY-mode client against a plain TLS server must yield
    /// [`TlsError::RealityFallback`], not a hard error: the server echoes
    /// the sealed session id, so the handshake proceeds to the
    /// `CertificateVerify`, where the REALITY HMAC check fails on the real
    /// certificate — the fallback signal the caller needs.
    #[tokio::test]
    async fn reality_against_plain_tls_server_is_fallback() {
        let recorded: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let addr = spawn_recording_plain_tls_server(recorded.clone());

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let rng = ring::rand::SystemRandom::new();
        let result = connect_reality(
            tcp,
            RealityParams {
                server_name: "localhost",
                public_key: &[0xAB; 32],
                short_id: &[],
                provisioner: &FixedChrome133,
                rng: &rng,
                spider: &SpiderConfig::default(),
            },
        )
        .await;
        assert!(
            matches!(result, Err(TlsError::RealityFallback)),
            "expected RealityFallback, got an unexpected handshake result"
        );

        // The spawned Spider-X session must keep the established TLS
        // session alive: poll the recorded bytes (up to 5s) for the HTTP/2
        // client preface AND the first GET's HEADERS frame (stream 1) — a
        // spider that dies after the preface (e.g. an HPACK encoding panic)
        // must fail this assertion. The guard is scoped to a block so it
        // never spans the await below.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let spider_traffic = {
                let bytes = recorded.lock();
                let preface = bytes
                    .windows(http2::PREFACE.len())
                    .any(|w| w == http2::PREFACE);
                // Frame header layout (RFC 7540 §4.1): type at offset 3,
                // stream id at offsets 5..9.
                let headers_stream1 = bytes.windows(9).any(|w| {
                    w[3] == http2::FRAME_HEADERS
                        && u32::from_be_bytes(w[5..9].try_into().unwrap()) == 1
                });
                drop(bytes);
                preface && headers_stream1
            };
            if spider_traffic {
                break;
            }
            assert!(
                std::time::Instant::now() <= deadline,
                "spider never sent preface + HEADERS(stream 1) to the dest"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// A REALITY handshake over the X25519MLKEM768 hybrid group (xray
    /// `reality.go:79` / sing-box `reality_client.go:136` semantics): a
    /// fake REALITY server double reads the client's 1216-byte hybrid key
    /// share, encapsulates to the ML-KEM-768 public key, feeds
    /// `classical || pq` through the key schedule, and authenticates with
    /// a REALITY-stamped Ed25519 certificate (`HMAC-SHA512(auth_key,
    /// ed25519_pub)` signature field + `CertificateVerify` over the
    /// transcript). Client success (`Ok`, not `RealityFallback`) plus the
    /// encrypted echo proves the PQ path engaged and both sides derived
    /// matching traffic keys.
    #[tokio::test]
    async fn reality_hybrid_handshake_completes_against_fake_pq_server() {
        use crate::crypto::mlkem::PublicKey as MlkemPublicKey;
        use crate::crypto::{AeadKey, CipherSuiteId, KeySchedule, X25519KeyPair};
        use crate::handshake::make_hs_msg;
        use crate::record::{
            CONTENT_APPLICATION_DATA, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY,
            HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_SERVER_HELLO, aead_aad,
        };
        use ring::hmac;
        use ring::signature::{Ed25519KeyPair, KeyPair as _};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const AEAD_TAG_LEN: usize = 16;

        let suite = CipherSuiteId::Aes128GcmSha256;
        let rng = ring::rand::SystemRandom::new();

        // The server's static REALITY identity key (the client's `pbk`).
        let static_kp = X25519KeyPair::generate(&rng).unwrap();

        let (client_stream, mut server_side) = tokio::io::duplex(64 * 1024);
        let static_pub = static_kp.public_key();
        let server_rng = ring::rand::SystemRandom::new();
        let server = tokio::spawn(async move {
            // Read the ClientHello record; pull the hybrid key share.
            let mut hdr = [0u8; 5];
            server_side.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 0x16);
            let mut ch = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
            server_side.read_exact(&mut ch).await.unwrap();
            let parsed = parse_hello(&ch).unwrap();
            let ks_ext = parsed.extension(0x0033).unwrap();
            // Walk the key-share list and find the X25519MLKEM768 entry
            // (curve 4588 / 0x11EC): Go wire order — mlkem_pk(1184) first,
            // x25519_pub(32) last.
            let list_len = u16::from_be_bytes([ks_ext[0], ks_ext[1]]) as usize;
            let mut off = 2usize;
            let end = 2 + list_len;
            let mut client_x25519 = None;
            let mut client_mlkem_pk = None;
            while off + 4 <= end.min(ks_ext.len()) {
                let group = u16::from_be_bytes([ks_ext[off], ks_ext[off + 1]]);
                let kx_len = u16::from_be_bytes([ks_ext[off + 2], ks_ext[off + 3]]) as usize;
                let share = &ks_ext[off + 4..off + 4 + kx_len];
                if group == 0x11EC {
                    assert_eq!(kx_len, 1216, "X25519MLKEM768 share must be 1184 + 32 bytes");
                    client_mlkem_pk = Some(MlkemPublicKey::from_bytes(&share[..1184]).unwrap());
                    client_x25519 = Some(share[1184..].try_into().unwrap());
                }
                off += 4 + kx_len;
            }
            let (client_x25519, client_mlkem_pk) = (
                client_x25519.expect("ClientHello must offer the X25519MLKEM768 key share"),
                client_mlkem_pk.unwrap(),
            );

            // REALITY auth key: ECDH(static_priv, client_keyshare) with
            // salt = client_random[..20] — mirrors derive on the client.
            let random = messages::extract_client_random(&ch).unwrap();
            let auth_shared = static_kp.agree(&client_x25519).unwrap();
            let auth_key = auth::derive_auth_key(&auth_shared, &random[..20], b"REALITY").unwrap();

            // TLS ephemeral keyshare + PQ encapsulation (hybrid contract).
            let tls_kp = X25519KeyPair::generate(&server_rng).unwrap();
            let classical = tls_kp.agree(&client_x25519).unwrap();
            let (ct, pq_ss) = Mlkem768::encapsulate(&client_mlkem_pk).unwrap();

            // ServerHello: key_share group 11ec, share = ct(1088) || pub(32)
            // (Go wire order).
            let mut sh_body = Vec::new();
            sh_body.extend_from_slice(&0x0303u16.to_be_bytes());
            sh_body.extend_from_slice(&[0x5A; 32]);
            sh_body.push(u8::try_from(parsed.session_id.len()).unwrap());
            sh_body.extend_from_slice(&parsed.session_id);
            sh_body.extend_from_slice(&0x1301u16.to_be_bytes());
            sh_body.push(0); // compression method
            let mut kse = Vec::new();
            kse.extend_from_slice(&0x0033u16.to_be_bytes());
            kse.extend_from_slice(&1124u16.to_be_bytes()); // 4 + 1120
            kse.extend_from_slice(&0x11ECu16.to_be_bytes());
            kse.extend_from_slice(&1120u16.to_be_bytes());
            kse.extend_from_slice(ct.as_bytes());
            kse.extend_from_slice(&tls_kp.public_key());
            // ext_list_len = supported_versions(6) + key_share.
            sh_body.extend_from_slice(&u16::try_from(6 + kse.len()).unwrap().to_be_bytes());
            sh_body.extend_from_slice(&0x002bu16.to_be_bytes());
            sh_body.extend_from_slice(&0x0002u16.to_be_bytes());
            sh_body.extend_from_slice(&0x0304u16.to_be_bytes());
            sh_body.extend_from_slice(&kse);
            let sh_msg = make_hs_msg(HS_SERVER_HELLO, &sh_body);
            let mut rec = vec![0x16, 0x03, 0x03];
            rec.extend_from_slice(&u16::try_from(sh_msg.len()).unwrap().to_be_bytes());
            rec.extend_from_slice(&sh_msg);
            server_side.write_all(&rec).await.unwrap();

            // Key schedule over `pq || classical` (Go hybrid contract) —
            // 64 bytes for X25519MLKEM768.
            let mut combined = pq_ss.as_bytes().to_vec();
            combined.extend_from_slice(classical.as_slice());
            assert_eq!(combined.len(), 64);
            let mut sk = KeySchedule::new(suite);
            sk.add_transcript(&ch);
            sk.add_transcript(&sh_msg);
            let hs_secret = sk.handshake_secret(&combined).unwrap();
            let (_client_hs_ts, server_hs_ts) =
                sk.handshake_traffic_secrets(&hs_secret[..32]).unwrap();
            let server_hs_key = AeadKey::new(suite, &server_hs_ts[..32]).unwrap();

            // A REAL Ed25519 certificate stamped with the REALITY HMAC.
            let rcgen_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let params =
                rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
            let mut cert_der = params.self_signed(&rcgen_key).unwrap().der().to_vec();
            let signing_key = Ed25519KeyPair::from_pkcs8(rcgen_key.serialized_der()).unwrap();
            let sig_offset = crate::reality::verify::extract_certificate_signature(&cert_der)
                .unwrap()
                .as_ptr() as usize
                - cert_der.as_ptr() as usize;
            let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, auth_key.as_slice());
            let tag = hmac::sign(&hmac_key, signing_key.public_key().as_ref());
            cert_der[sig_offset..sig_offset + 64].copy_from_slice(tag.as_ref());

            // Encrypted flight: EE + Certificate + CertificateVerify
            // (Ed25519 over the transcript) + Finished (real MAC).
            let ee_msg = make_hs_msg(HS_ENCRYPTED_EXTENSIONS, &[0x00, 0x00]);
            let entry_len = 3 + cert_der.len() + 2;
            let mut cert_body = Vec::new();
            cert_body.push(0x00); // certificate_request_context length
            cert_body.extend_from_slice(&u32::try_from(entry_len).unwrap().to_be_bytes()[1..]);
            cert_body.extend_from_slice(&u32::try_from(cert_der.len()).unwrap().to_be_bytes()[1..]);
            cert_body.extend_from_slice(&cert_der);
            cert_body.extend_from_slice(&[0x00, 0x00]); // per-cert extensions
            let cert_msg = make_hs_msg(HS_CERTIFICATE, &cert_body);

            let mut transcript = Vec::new();
            transcript.extend_from_slice(&ch);
            transcript.extend_from_slice(&sh_msg);
            transcript.extend_from_slice(&ee_msg);
            transcript.extend_from_slice(&cert_msg);
            let transcript_hash = ring::digest::digest(&ring::digest::SHA256, &transcript);
            let th: [u8; 32] = transcript_hash.as_ref().try_into().unwrap();
            let signed_content = signed_content_fixture(&th);
            let cv_sig = signing_key.sign(&signed_content);
            let mut cv_body = Vec::new();
            cv_body.extend_from_slice(&0x0807u16.to_be_bytes());
            cv_body.extend_from_slice(&0x0040u16.to_be_bytes());
            cv_body.extend_from_slice(cv_sig.as_ref());
            let cv_msg = make_hs_msg(HS_CERTIFICATE_VERIFY, &cv_body);

            sk.add_transcript(&ee_msg);
            sk.add_transcript(&cert_msg);
            sk.add_transcript(&cv_msg);
            let sf_key = sk.finished_key(&server_hs_ts[..32]).unwrap();
            let sf_wire = make_hs_msg(HS_FINISHED, &sk.finished_mac(&sf_key[..32]));
            // Frame the encrypted flight in place: the record header goes
            // first, then the flight plaintext, then `seal_in_place` turns
            // the tail into ciphertext — one copy of the flight, no
            // allocating twin, no `make_app_data_record` re-copy.
            let mut flight_rec = Vec::with_capacity(
                5 + ee_msg.len() + cert_msg.len() + cv_msg.len() + sf_wire.len() + 1 + AEAD_TAG_LEN,
            );
            flight_rec.extend_from_slice(&[0x17, 0x03, 0x03, 0, 0]);
            flight_rec.extend_from_slice(&ee_msg);
            flight_rec.extend_from_slice(&cert_msg);
            flight_rec.extend_from_slice(&cv_msg);
            flight_rec.extend_from_slice(&sf_wire);
            // The inner content type rides inside the AEAD plaintext
            // (RFC 8446 §5.2) — the record layer reads it from the last
            // plaintext byte.
            flight_rec.push(crate::record::CONTENT_HANDSHAKE);
            sk.add_transcript(&sf_wire);
            let ct_len = flight_rec.len() - 5 + AEAD_TAG_LEN;
            let flight_aad = aead_aad(ct_len);
            let ct_len_u16 = u16::try_from(ct_len).expect("test flight record fits u16");
            flight_rec[3..5].copy_from_slice(&ct_len_u16.to_be_bytes());
            server_hs_key
                .seal_in_place(0, &flight_aad, &mut flight_rec, 5)
                .unwrap();
            server_side.write_all(&flight_rec).await.unwrap();

            // Client Finished record — skip.
            let mut fin_hdr = [0u8; 5];
            server_side.read_exact(&mut fin_hdr).await.unwrap();
            let mut fin = vec![0u8; u16::from_be_bytes([fin_hdr[3], fin_hdr[4]]) as usize];
            server_side.read_exact(&mut fin).await.unwrap();

            // App traffic secrets; decrypt and echo the client's ping.
            let master = sk.master_secret(&hs_secret[..32]).unwrap();
            let (client_app_ts, server_app_ts) = sk.app_traffic_secrets(&master[..32]).unwrap();
            let client_app_key = AeadKey::new(suite, &client_app_ts[..32]).unwrap();
            let server_app_key = AeadKey::new(suite, &server_app_ts[..32]).unwrap();

            let mut ping_hdr = [0u8; 5];
            server_side.read_exact(&mut ping_hdr).await.unwrap();
            let mut ping_ct = vec![0u8; u16::from_be_bytes([ping_hdr[3], ping_hdr[4]]) as usize];
            server_side.read_exact(&mut ping_ct).await.unwrap();
            let plain_len = client_app_key
                .open_in_place(0, &aead_aad(ping_ct.len()), &mut ping_ct)
                .unwrap();
            assert!(ping_ct[..plain_len].starts_with(b"ping"));

            let mut inner = b"ping".to_vec();
            inner.push(CONTENT_APPLICATION_DATA);
            let echo_aad = aead_aad(inner.len() + AEAD_TAG_LEN);
            let mut echo_rec = Vec::with_capacity(5 + inner.len() + AEAD_TAG_LEN);
            echo_rec.extend_from_slice(&[0x17, 0x03, 0x03, 0, 0]);
            echo_rec.extend_from_slice(&inner);
            let echo_len = inner.len() + AEAD_TAG_LEN;
            let echo_len_u16 = u16::try_from(echo_len).expect("test echo record fits u16");
            echo_rec[3..5].copy_from_slice(&echo_len_u16.to_be_bytes());
            server_app_key
                .seal_in_place(0, &echo_aad, &mut echo_rec, 5)
                .unwrap();
            server_side.write_all(&echo_rec).await.unwrap();
        });

        // Bounded waits throughout: a server-side panic or a wire
        // mismatch must fail the test, never hang it.
        let mut handshake = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            connect_reality(
                client_stream,
                RealityParams {
                    server_name: "localhost",
                    public_key: &static_pub,
                    short_id: &[],
                    provisioner: &FixedChrome133,
                    rng: &rng,
                    spider: &SpiderConfig::default(),
                },
            ),
        )
        .await
        .expect("REALITY hybrid handshake timed out")
        .expect("REALITY hybrid handshake must authenticate (not fall back)");
        handshake.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            handshake.read_exact(&mut buf),
        )
        .await
        .expect("echo timed out")
        .unwrap();
        assert_eq!(&buf, b"ping");
        tokio::time::timeout(std::time::Duration::from_secs(10), server)
            .await
            .expect("server task timed out")
            .unwrap();
    }
}
