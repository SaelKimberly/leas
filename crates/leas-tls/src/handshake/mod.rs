//! TLS 1.3 client handshake (plain TLS, verifier seam).
//!
//! Port of `thirdparty/tls-fingerprint/src/handshake.rs`, adapted to the
//! crate's seams: the stream is generic (`AsyncRead + AsyncWrite + Unpin +
//! Send`), the key schedule carries its own transcript (crypto Task 5),
//! record reads go through `record::skip_ccs` (record Task 6), and the
//! established connection is a [`TlsStream`] (record Task 7). The two
//! deliberate Task-8 additions over the reference are:
//!
//! - **`HelloRetryRequest`** — a `ServerHello` whose random is the RFC 8446
//!   §4.1.4 magic value is recognised *before* the extension scan (its
//!   `key_share` carries only `selected_group`), and plain TLS retries exactly
//!   once: `ClientHello2` replays `ClientHello1`'s RNG draws, carries a NEW
//!   `key_share` plus the echoed cookie, and the transcript becomes
//!   `message_hash(ClientHello1) || HelloRetryRequest || ClientHello2 || …`
//!   (§4.4.1 — the HRR message itself is included). Under [`ServerAuth::Reality`] an
//!   HRR stays [`TlsError::HelloRetryRequest`] — the sealed session id is
//!   bound to the first hello (documented non-goal).
//! - **Verifier seam** — the certificate chain, the `CertificateVerify`
//!   signature scheme and raw body, and the transcript up to (excluding) the
//!   `CertificateVerify` are handed to [`ServerVerifier::verify`] before the
//!   handshake continues. Task 9 implements the real
//!   `WebPKI` verifier; [`AcceptAll`] is the test-only seam.
//!
//! Transcript accumulation follows the reference exactly — every raw
//! handshake message (`ClientHello` through `Finished`) is appended in wire
//! order, EXCEPT after a `HelloRetryRequest`, where `ClientHello1` is replaced
//! by its §4.4.1 `message_hash`; the client `Finished` and the application
//! traffic secrets are derived over `ClientHello..server Finished`
//! (RFC 8446 §4.4.4, §7.1).

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub mod tls12;

use crate::SecureRandom;
use crate::crypto::mlkem::{Ciphertext, Mlkem768, SecretKey as MlkemSecretKey};
use crate::crypto::{AeadKey, CipherSuiteId, KeySchedule, X25519KeyPair, tls12::Tls12Suite};
use crate::error::{Result, TlsError};
use crate::hello::{BuildParams, build_hello_ordered, to_record};
use crate::record::stream::{AppKeys, TlsStream};
use crate::record::{
    CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY,
    HS_COMPRESSED_CERTIFICATE, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_MESSAGE_HASH,
    HS_SERVER_HELLO, MAX_RECORD_PAYLOAD, aead_aad, parse_handshake_messages, skip_ccs,
};
use crate::spec::{ClientHelloSpec, ExtensionSpec, KeyShareGroup};

pub(crate) mod flight;
pub(crate) mod server_hello;

// The split is by subject, not visibility: the driver and the tests here use
// these exactly as if they were in this file.
pub(crate) use flight::*;
pub(crate) use server_hello::*;

// ── Verifier seam ──────────────────────────────────────────────────────────

/// Verifies the server's `CertificateVerify` signature over the handshake
/// transcript.
///
/// Task 9 implements the real `WebPKI` verifier; Task 8 hands it every raw
/// piece it needs. Per RFC 8446 §4.4.3 the `CertificateVerify` signature is
/// computed over the transcript up to but *excluding* the `CertificateVerify`
/// message itself, so the signed bytes are
/// `Hash(ClientHello .. Certificate)` — exactly the wire-order prefix
/// `transcript` carries (with the `CertificateVerify` deliberately not yet
/// appended).
pub trait ServerVerifier: Send + Sync {
    /// Returns `Ok(())` when the server identity is acceptable.
    fn verify(&self, ctx: &VerifyContext<'_>) -> Result<()>;
}

/// The negotiated TLS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.3 (RFC 8446).
    Tls13,
    /// TLS 1.2 (RFC 5246).
    Tls12,
}

/// Everything a verifier needs to authenticate the server.
pub struct VerifyContext<'a> {
    /// DER-encoded certificate chain, leaf first.
    pub chain: &'a [Vec<u8>],
    /// The `server_name` the client offered.
    pub sni: &'a str,
    /// The negotiated TLS version.
    pub version: TlsVersion,
    /// Cipher suite the server selected; only meaningful for TLS 1.3
    /// (its digest feeds the transcript hash for the `CertificateVerify`
    /// signature — TLS 1.2 signs raw data without a hash prefix).
    pub suite: CipherSuiteId,
    /// The `SignatureScheme` / `SignatureAndHashAlgorithm`.
    pub signature_scheme: u16,
    /// The raw signature bytes (TLS 1.3 `CertificateVerify` or TLS 1.2
    /// `ServerKeyExchange` signature).
    pub signature: &'a [u8],
    /// What the signature covers, typed by version so a TLS 1.3 verifier
    /// never has to hash and a TLS 1.2 verifier never gets a digest.
    pub signed: SignedData<'a>,
}

/// The signed content behind a `CertificateVerify` (TLS 1.3) or a
/// `ServerKeyExchange` (TLS 1.2).
#[derive(Debug, Clone, Copy)]
pub enum SignedData<'a> {
    /// TLS 1.3 (RFC 8446 §4.4.3): `Transcript-Hash(ClientHello ..
    /// Certificate)` — already hashed, `hash_len` bytes.
    Tls13Hash(&'a [u8]),
    /// TLS 1.2 (RFC 5246 §7.4.3): the raw
    /// `client_random || server_random || ServerECDHParams`.
    Tls12Raw(&'a [u8]),
}

/// Test-only verifier: accepts any server.
pub struct AcceptAll;

impl ServerVerifier for AcceptAll {
    fn verify(&self, _: &VerifyContext<'_>) -> Result<()> {
        Ok(())
    }
}

/// Connection-level inputs for [`connect`].
pub struct HandshakeParams<'a> {
    /// The `ClientHello` fingerprint spec.
    pub spec: &'a ClientHelloSpec,
    /// SNI host name, carried in the `server_name` extension and handed to
    /// the verifier.
    pub server_name: &'a str,
    /// ALPN protocols to offer; `None` uses the spec's own list. Protocol
    /// names are opaque bytes (RFC 7301 §3.1).
    pub alpn: Option<&'a [&'a [u8]]>,
    /// The server-authentication seam.
    pub verifier: &'a dyn ServerVerifier,
    /// Random source — the crate's [`SecureRandom`] seam. ring's
    /// `SystemRandom` coerces via the blanket impl; tests implement the
    /// trait directly for fixed-seed vectors.
    pub rng: &'a dyn SecureRandom,
}

// ── Constants ──────────────────────────────────────────────────────────────

/// RFC 8446 §4.1.4: the `ServerHello.random` that marks a
/// `HelloRetryRequest`.
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// `key_share` extension type (RFC 8446 §4.2.8).
const EXT_KEY_SHARE: u16 = 0x0033;
/// `supported_versions` extension type (RFC 8446 §4.2.1).
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// `cookie` extension type (RFC 8446 §4.2.2).
const EXT_COOKIE: u16 = 0x002c;
/// `application_layer_protocol_negotiation` extension type (RFC 7301).
const EXT_ALPN: u16 = 0x0010;

/// AEAD tag length for the TLS 1.3 AEADs in this engine (all 16 bytes).
const AEAD_TAG_LEN: usize = 16;

/// Maximum accumulated plaintext for the encrypted server flight, in bytes.
///
/// A single handshake message is at most `4 + 0xFF_FFFF` (type(1) +
/// length(3) + a uint24 body, RFC 8446 §4), so this cap admits every legal
/// message while bounding cross-record accumulation (RFC 8446 §5.1) against
/// unbounded growth.
pub(crate) const MAX_FLIGHT_BUFFER: usize = 4 + 0xFF_FFFF;

// ── Handshake driver ───────────────────────────────────────────────────────

/// The server-authentication strategy for the shared [`drive`] handshake.
///
/// [`drive`] is the common middle of `handshake::connect` and
/// `reality::connect_reality`: both write the same shape of `ClientHello`
/// record and derive the same TLS 1.3 key schedule; they differ only in
/// how the server's certificate flight is authenticated.
pub(crate) enum ServerAuth<'a> {
    /// Plain-TLS mode: hand the flight to a [`ServerVerifier`].
    Verifier(&'a dyn ServerVerifier),
    /// REALITY mode: authenticate with the REALITY auth key (HMAC +
    /// Ed25519 `CertificateVerify` over the transcript).
    Reality { auth_key: &'a [u8; 32] },
}

/// The result of the auth dispatch inside [`drive`].
pub(crate) enum AuthOutcome {
    /// The server flight authenticated under the chosen strategy; the
    /// handshake completes normally.
    Ok,
    /// REALITY mode: the flight failed REALITY auth, so the server is
    /// serving a real certificate (transparent proxy / possible MITM or
    /// redirection). The handshake still completes; the caller decides
    /// whether to fall back (xray's `!Verified` handling).
    RealityFallback,
}

/// What a plain-TLS caller must supply so [`drive`] can answer ONE
/// `HelloRetryRequest`.
///
/// `ClientHello2` is a *replay*, not a rebuild: the client random, GREASE
/// values, ECH grease and session id must stay byte-identical to
/// `ClientHello1` (RFC 8446 §4.1.2), so the caller builds `ClientHello1`
/// through a [`crate::hello::RecordingRng`] and the retry replays its draw stream.
pub(crate) struct RetrySupport<'a> {
    /// The spec `ClientHello1` was built from (the retry rewrites only its
    /// `key_share` and appends the cookie).
    pub(crate) spec: &'a ClientHelloSpec,
    /// SNI for the rebuilt hello.
    pub(crate) server_name: &'a str,
    /// ALPN override, if the caller set one.
    pub(crate) alpn: Option<&'a [&'a [u8]]>,
    /// The X25519 public key `ClientHello1` offered (re-used verbatim by a
    /// cookie-only retry, which changes no key share).
    pub(crate) x25519_pub: &'a [u8; 32],
    /// `ClientHello1`'s recorded RNG draws.
    pub(crate) draws: &'a crate::hello::RecordingRng<'a>,
    /// Extension-order policy of the identity (Chromium ≥108 permutes).
    pub(crate) permute_extensions: bool,
    /// Real randomness, used ONLY to mint the retry's fresh key share (never
    /// for the hello's GREASE/random, which come from `draws`).
    pub(crate) rng: &'a dyn crate::SecureRandom,
}

impl RetrySupport<'_> {
    /// Rebuilds `ClientHello2` for `hrr`.
    ///
    /// Returns the new hello plus the fresh key material its `key_share`
    /// carries (RFC 8446 §4.2.8.2 requires a NEW `KeyShareEntry`): the X25519
    /// key pair the caller must adopt, and — for a hybrid selection — the
    /// ML-KEM-768 secret key the key schedule must decapsulate with.
    #[allow(clippy::type_complexity)]
    pub(crate) fn rebuild(
        &self,
        hrr: &HrrData,
    ) -> Result<(
        crate::hello::BuiltHello,
        Option<X25519KeyPair>,
        Option<MlkemSecretKey>,
    )> {
        let group = match hrr.selected_group {
            None => None,
            Some(wire) => Some(keyshare_group_for(wire).ok_or_else(|| {
                TlsError::HelloRetryRequestUnsupported(format!(
                    "server requested key_share group 0x{wire:04X}, which this engine cannot produce \
                     (only X25519 0x001D and X25519MLKEM768 0x11EC are implemented)"
                ))
            })?),
        };
        if group.is_none() && hrr.cookie.is_none() {
            return Err(TlsError::Handshake(
                "HelloRetryRequest asked for neither a new key share nor a cookie".into(),
            ));
        }
        if let Some(group) = group.clone() {
            let wire = group.wire_id();
            if !offered_group(self.spec, wire) {
                return Err(TlsError::Handshake(format!(
                    "HelloRetryRequest selected group 0x{wire:04X}, which the ClientHello \
                     did not list in supported_groups (RFC 8446 §4.2.8.2, illegal_parameter)"
                )));
            }
            if offered_share(self.spec, wire) {
                return Err(TlsError::Handshake(format!(
                    "HelloRetryRequest selected group 0x{wire:04X}, which ClientHello1 \
                     already carried a key share for (RFC 8446 §4.2.8.2, illegal_parameter)"
                )));
            }
        }

        // RFC 8446 §4.2.8.2: `ClientHello2` MUST carry a NEW `KeyShareEntry`
        // for the selected group. The group can only have been selected if
        // `ClientHello1` did not already offer a share for it (checked above),
        // so both branches mint fresh key material: a new X25519 key pair, and
        // — for the hybrid group — a new ML-KEM-768 pair.
        let mut spec = self.spec.clone();
        let (x25519_pub, new_keypair) = match group {
            Some(_) => {
                let keypair = X25519KeyPair::generate(self.rng)?;
                (keypair.public_key(), Some(keypair))
            }
            // Cookie-only retry: the shares are unchanged, so the existing
            // key pair stays and no new share is sent.
            None => (*self.x25519_pub, None),
        };
        let (mlkem_pub, new_sk) = if group == Some(KeyShareGroup::X25519Mlkem768) {
            let (pk, sk) = Mlkem768::generate_keypair();
            (Some(pk.as_bytes().to_vec()), Some(sk))
        } else {
            (None, None)
        };
        if let Some(group) = group {
            spec.extensions =
                retry_extensions(&spec.extensions, Some(&group), hrr.cookie.as_deref());
        } else if let Some(cookie) = hrr.cookie.as_deref() {
            // A cookie-only retry keeps ClientHello1's key shares.
            spec.extensions = retry_extensions(&spec.extensions, None, Some(cookie));
        }

        let replay = crate::hello::ReplayRng::new(self.draws.recorded());
        let built = match build_hello_ordered(
            &spec,
            &BuildParams {
                server_name: self.server_name,
                alpn: self.alpn,
                x25519_pub: &x25519_pub,
                mlkem768_pub: mlkem_pub.as_deref(),
                rng: &replay,
            },
            self.permute_extensions,
        ) {
            Ok(built) => built,
            // The replay fails closed inside `fill`; report the divergence
            // itself rather than the generic draw error it surfaces as.
            Err(e) => {
                replay.check()?;
                return Err(e);
            }
        };
        replay.check()?;
        Ok((built, new_keypair, new_sk))
    }
}

/// Performs the shared TLS 1.3 client handshake over `stream`: writes the
/// `ClientHello` record, reads the `ServerHello` (skipping middlebox CCS
/// records; a `HelloRetryRequest` magic random triggers ONE retry when
/// `retry` is supplied — plain TLS only, see [`RetrySupport`] — and is a
/// [`TlsError::HelloRetryRequest`] otherwise), derives the handshake traffic secrets
/// with the *selected* suite, decrypts the server flight
/// (`EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`),
/// dispatches [`ServerAuth`], authenticates the server `Finished` MAC, sends
/// the client `Finished` (sealed with the client handshake key), derives the
/// application traffic secrets, and builds the [`TlsStream`].
///
/// The auth dispatch receives `Transcript-Hash(ClientHello .. Certificate)`
/// (or, after a retry, `message_hash(ClientHello1) ‖ ClientHello2 ‖ …`); the
/// key schedule holds the same transcript for the `Finished` MACs and the
/// application traffic secrets. `offered_session_id` must be the legacy
/// session id of the FIRST hello, which both `ServerHello` and
/// `HelloRetryRequest` must echo exactly (RFC 8446 §4.1.3, §4.1.4).
pub(crate) async fn drive<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    hello: &[u8],
    offered_session_id: &[u8],
    mut keypair: X25519KeyPair,
    // ML-KEM-768 secret key when the ClientHello offered a hybrid key
    // share; decapsulation runs only if the server actually selected the
    // hybrid group (its `key_share` then carries the ciphertext).
    mut mlkem_sk: Option<MlkemSecretKey>,
    server_name: &str,
    auth: ServerAuth<'_>,
    // `Some` when the caller can rebuild `ClientHello2` for one
    // HelloRetryRequest (plain TLS only — see [`RetrySupport`]).
    retry: Option<&RetrySupport<'_>>,
) -> Result<(TlsStream<S>, AuthOutcome)> {
    let mut stream = stream;

    // RFC 8446 §4.1.4: at most one retry. `first_hello` is kept because the
    // post-retry transcript starts with `message_hash(ClientHello1)`.
    let mut current_hello = hello.to_vec();
    let mut current_sid = offered_session_id.to_vec();
    let mut first_hello: Option<Vec<u8>> = None;
    let mut retry_message: Option<Vec<u8>> = None;
    let server_hello = loop {
        stream.write_all(&to_record(&current_hello)).await?;
        match read_server_hello(&mut stream, &current_sid).await? {
            ServerReply::Hello(sh) => break *sh,
            ServerReply::Retry(hrr) => {
                let Some(retry) = retry else {
                    return Err(TlsError::HelloRetryRequest);
                };
                if matches!(auth, ServerAuth::Reality { .. }) {
                    // REALITY authenticates the FIRST hello's sealed session
                    // id; a retried hello has no defined server behaviour, so
                    // this stays a typed error (documented non-goal).
                    return Err(TlsError::HelloRetryRequest);
                }
                if first_hello.is_some() {
                    return Err(TlsError::Handshake(
                        "server sent a second HelloRetryRequest; RFC 8446 §4.1.4 allows one".into(),
                    ));
                }
                let (rebuilt, new_keypair, new_sk) = retry.rebuild(&hrr)?;
                retry_message = Some(hrr.raw);
                first_hello = Some(std::mem::take(&mut current_hello));
                current_sid = rebuilt.session_id().to_vec();
                current_hello = rebuilt.handshake_bytes;
                // RFC 8446 §4.2.8.2: ClientHello2 carries a NEW share, so the
                // key schedule must use the new private half.
                if let Some(new_keypair) = new_keypair {
                    keypair = new_keypair;
                }
                if new_sk.is_some() {
                    mlkem_sk = new_sk;
                }
            }
        }
    };
    // TLS 1.2: dispatch to the separate 1.2 handshake driver.
    // REALITY (ServerAuth::Reality) is TLS 1.3 only — error if a REALITY
    // server negotiates 1.2.
    if server_hello.version == TlsVersion::Tls12 {
        match auth {
            ServerAuth::Reality { .. } => {
                // REALITY's whole authentication surface (sealed session id,
                // dual X25519 agreement, Ed25519 CertificateVerify) is TLS
                // 1.3-only, so 1.2 can never authenticate. A 1.2 ServerHello
                // to a REALITY hello is exactly the "real certificate"
                // situation the fallback exists for (transparent proxy or
                // redirected fronting host), so report it as such rather than
                // as a generic handshake error — the caller then runs the
                // Spider-X fallback instead of failing the dial.
                return Err(TlsError::RealityFallback);
            }
            ServerAuth::Verifier(verifier) => {
                let client_random: [u8; 32] = current_hello[6..38].try_into().expect("32 bytes");
                let pre_buffer = server_hello.pre_buffer.clone();
                return tls12::drive12(
                    stream,
                    &current_hello,
                    &client_random,
                    &server_hello,
                    pre_buffer,
                    &keypair,
                    server_name,
                    verifier,
                )
                .await;
            }
        }
    }
    let classical_shared = keypair.agree(&server_hello.peer_key.ok_or_else(|| {
        TlsError::Handshake("TLS 1.3 ServerHello has no key_share extension".into())
    })?)?;

    // Hybrid key exchange (Go crypto/tls X25519MLKEM768): the key-schedule
    // IKM is `mlkem_shared || classical_shared` — Go's
    // handshake_client_tls13 appends the ECDH secret AFTER the ML-KEM
    // shared secret (`sharedKey = append(mlkemShared, sharedKey...)`).
    let shared: Zeroizing<Vec<u8>> =
        match (mlkem_sk.as_ref(), server_hello.mlkem_ciphertext.as_ref()) {
            (Some(sk), Some(ct)) => {
                // The ciphertext was validated at parse; decapsulate it
                // directly — no second copy through a temp `Vec`.
                let pq_shared = Mlkem768::decapsulate(sk, ct);
                let mut combined = Zeroizing::new(Vec::with_capacity(classical_shared.len() + 32));
                combined.extend_from_slice(pq_shared.as_bytes());
                combined.extend_from_slice(classical_shared.as_slice());
                combined
            }
            _ => Zeroizing::new(classical_shared.to_vec()),
        };

    let hash_len = server_hello.suite.hash_len();
    let mut ks = KeySchedule::new(server_hello.suite);
    if let Some(ch1) = first_hello.as_deref() {
        // RFC 8446 §4.4.1: after a retry the transcript is
        //   message_hash(ClientHello1) || HelloRetryRequest || ClientHello2 || ...
        // — the HRR message itself is included, and ClientHello1 is replaced by
        // its synthetic hash. Omitting the HRR derives different traffic
        // secrets and the server flight fails to decrypt.
        let hash = ring::digest::digest(server_hello.suite.digest(), ch1);
        ks.add_transcript(&make_hs_msg(HS_MESSAGE_HASH, hash.as_ref()));
        let hrr = retry_message.as_deref().ok_or_else(|| {
            TlsError::Handshake("retry happened without a HelloRetryRequest transcript".into())
        })?;
        ks.add_transcript(hrr);
    }
    ks.add_transcript(&current_hello);
    ks.add_transcript(&server_hello.raw);
    let hs_secret = ks.handshake_secret(&shared)?;
    let (client_hs_ts, server_hs_ts) = ks.handshake_traffic_secrets(&hs_secret[..hash_len])?;
    let server_hs_key = AeadKey::new(server_hello.suite, &server_hs_ts[..hash_len])?;
    let client_hs_key = AeadKey::new(server_hello.suite, &client_hs_ts[..hash_len])?;

    // RFC 8879 §4: the server may only compress its Certificate with an
    // algorithm THIS ClientHello offered — so read it back from the hello we
    // actually sent (the retried one), never from a caller's belief about it.
    let offered_compress = compressed_algorithms(&current_hello);
    let flight = read_server_hs_messages(&mut stream, &server_hs_key, &offered_compress).await?;

    // The key schedule already accumulates `ClientHello .. Certificate`
    // verbatim — feeding it here (before the auth dispatch) makes its
    // arena the single transcript copy; the verifier below borrows it
    // instead of a second `hello + sh + ee + cert` buffer. Ordering is
    // unchanged (`ee, cert, cv, server Finished`), so the Finished MACs
    // and app secrets derive exactly as before (RFC 8446 §4.4.4, §7.1).
    ks.add_transcript(&flight.ee_raw);
    ks.add_transcript(&flight.cert_raw);
    // Transcript hash up to (excluding) CertificateVerify — the only thing
    // the auth dispatch needs (RFC 8446 §4.4.3); the raw bytes are gone.
    let (transcript_hash, transcript_hash_len) = ks.transcript_hash();

    let outcome = match auth {
        ServerAuth::Verifier(verifier) => {
            // `CertificateVerify` body = scheme(2) || sig_len(2) || sig. The
            // flight reader tolerates a missing CertificateVerify (empty
            // body), so slice fallibly: an on-path party that completes the
            // unauthenticated ECDH could otherwise panic the record loop.
            let signature = flight.cert_verify_body.get(4..).ok_or_else(|| {
                TlsError::Verify("server sent no CertificateVerify signature".into())
            })?;
            ensure_offered_sigalg(&current_hello, flight.signature_scheme)?;
            verifier.verify(&VerifyContext {
                chain: &flight.chain,
                sni: server_name,
                version: TlsVersion::Tls13,
                suite: server_hello.suite,
                signature_scheme: flight.signature_scheme,
                signature,
                signed: SignedData::Tls13Hash(&transcript_hash[..transcript_hash_len]),
            })?;
            AuthOutcome::Ok
        }
        ServerAuth::Reality { auth_key } => {
            let Some(cert_der) = flight.chain.first() else {
                return Err(TlsError::Verify(
                    "REALITY server sent no certificate".into(),
                ));
            };
            match crate::reality::verify::verify_server(
                cert_der,
                &flight.cv_raw,
                auth_key,
                &transcript_hash[..transcript_hash_len],
            ) {
                Ok(()) => AuthOutcome::Ok,
                // Any REALITY auth failure = a real certificate (transparent
                // proxy / possible MITM or redirection), matching xray's
                // `!Verified` handling.
                Err(_) => AuthOutcome::RealityFallback,
            }
        }
    };

    ks.add_transcript(&flight.cv_raw);
    let server_finished_key = ks.finished_key(&server_hs_ts[..hash_len])?;
    if ks.finished_mac(&server_finished_key[..hash_len]) != flight.sf_verify_data {
        return Err(TlsError::Handshake(
            "server Finished MAC mismatch — possible MITM or wrong key".into(),
        ));
    }

    let sf_raw = make_hs_msg(HS_FINISHED, &flight.sf_verify_data);
    ks.add_transcript(&sf_raw);
    let client_finished_key = ks.finished_key(&client_hs_ts[..hash_len])?;
    let client_finished_mac = ks.finished_mac(&client_finished_key[..hash_len]);
    // The client Finished record is framed in place: header placeholder,
    // inner plaintext, tag — one buffer, one copy of the plaintext, with
    // the seal happening inside the record buffer (no allocating twin,
    // no `make_app_data_record` re-copy).
    let cf_hs_msg = make_hs_msg(HS_FINISHED, &client_finished_mac);
    let ct_len = cf_hs_msg.len() + 1 + AEAD_TAG_LEN;
    let cf_aad = aead_aad(ct_len);
    let mut cf_record = Vec::with_capacity(5 + ct_len);
    cf_record.extend_from_slice(&[CONTENT_APPLICATION_DATA, 0x03, 0x03]);
    cf_record.extend_from_slice(
        &u16::try_from(ct_len)
            .map_err(|_| TlsError::Handshake("client Finished record too long".into()))?
            .to_be_bytes(),
    );
    cf_record.extend_from_slice(&cf_hs_msg);
    cf_record.push(CONTENT_HANDSHAKE);
    client_hs_key.seal_in_place(0, &cf_aad, &mut cf_record, 5)?;
    stream.write_all(&cf_record).await?;

    let master = ks.master_secret(&hs_secret[..hash_len])?;
    let (client_app_ts, server_app_ts) = ks.app_traffic_secrets(&master[..hash_len])?;
    let client_app_key = AeadKey::new(server_hello.suite, &client_app_ts[..hash_len])?;
    let server_app_key = AeadKey::new(server_hello.suite, &server_app_ts[..hash_len])?;
    let mut tls = TlsStream::new(stream, AppKeys::tls13(server_app_key, client_app_key));
    // KeyUpdate needs the traffic secrets themselves, not just the keys.
    tls.set_app_secrets(crate::record::stream::AppSecrets::new(
        server_hello.suite,
        &client_app_ts[..hash_len],
        &server_app_ts[..hash_len],
    ));
    tls.set_negotiated_alpn(flight.negotiated_alpn);
    tls.set_negotiated_hybrid(server_hello.mlkem_ciphertext.is_some());
    Ok((tls, outcome))
}

/// Performs the full TLS 1.3 client handshake over `stream`, returning a
/// record-framed application-data stream.
///
/// Generates an ephemeral X25519 key pair — plus an ML-KEM-768 key pair
/// when the spec's `key_share` carries a hybrid entry — builds the
/// `ClientHello` record (fingerprint from `params.spec`), and hands both to
/// the shared [`drive`] with a [`ServerAuth::Verifier`] dispatch.
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    params: HandshakeParams<'_>,
) -> Result<TlsStream<S>> {
    connect_with_permutation(stream, params, false).await
}

/// [`connect`] with an explicit extension-order policy.
///
/// `permute_extensions` belongs to the *identity*, not the spec: Chromium
/// permutes from Chrome 108 onward, Firefox's default build and Safari do not
/// (see [`crate::hello::build_hello_ordered`]). The flag is threaded here
/// rather than stored on every spec so the generated roster stays data-only.
pub async fn connect_with_permutation<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    params: HandshakeParams<'_>,
    permute_extensions: bool,
) -> Result<TlsStream<S>> {
    // The driver's future is large (it owns the flight buffers and the key
    // schedule); box it once per connection so every `.await` site stays
    // small (clippy::large_futures) at the cost of one allocation.
    Box::pin(connect_inner(stream, params, permute_extensions)).await
}

async fn connect_inner<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    params: HandshakeParams<'_>,
    permute_extensions: bool,
) -> Result<TlsStream<S>> {
    let keypair = X25519KeyPair::generate(params.rng)?;
    let x25519_pub = keypair.public_key();

    let offers_hybrid = params.spec.extensions.iter().any(|ext| {
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
    });
    let mlkem = if offers_hybrid {
        let (pk, sk) = Mlkem768::generate_keypair();
        (Some(pk), Some(sk))
    } else {
        (None, None)
    };

    // Record every RNG byte the first hello draws: a HelloRetryRequest rebuild
    // replays them so ClientHello2 differs only in `key_share`/`cookie`
    // (RFC 8446 §4.1.2) — the random, GREASE and session id must not change.
    let recording = crate::hello::RecordingRng::new(params.rng);
    let hello = build_hello_ordered(
        params.spec,
        &BuildParams {
            server_name: params.server_name,
            alpn: params.alpn,
            x25519_pub: &x25519_pub,
            mlkem768_pub: mlkem
                .0
                .as_ref()
                .map(crate::crypto::mlkem::PublicKey::as_bytes),
            rng: &recording,
        },
        permute_extensions,
    )?;
    let retry = RetrySupport {
        permute_extensions,
        spec: params.spec,
        server_name: params.server_name,
        alpn: params.alpn,
        x25519_pub: &x25519_pub,
        draws: &recording,
        rng: params.rng,
    };
    let (tls, _) = drive(
        stream,
        &hello.handshake_bytes,
        hello.session_id(),
        keypair,
        mlkem.1,
        params.server_name,
        ServerAuth::Verifier(params.verifier),
        Some(&retry),
    )
    .await?;
    Ok(tls)
}

/// RFC 8879 `compress_certificate` algorithms the given `ClientHello` offered
/// (`algorithms<2..2^8-2>`: a u8 byte length then u16 ids). Empty when the
/// hello carried no such extension.
fn compressed_algorithms(hello: &[u8]) -> Vec<u16> {
    let Some(body) = client_hello_extension(hello, 0x001B) else {
        return Vec::new();
    };
    let Some((&list_len, rest)) = body.split_first() else {
        return Vec::new();
    };
    let list_len = usize::from(list_len);
    if rest.len() != list_len {
        return Vec::new();
    }
    rest.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect()
}

/// Wire group id → the engine's key-share group, for a `HelloRetryRequest`.
const fn keyshare_group_for(wire: u16) -> Option<KeyShareGroup> {
    match wire {
        0x001D => Some(KeyShareGroup::X25519),
        0x11EC => Some(KeyShareGroup::X25519Mlkem768),
        _ => None,
    }
}

/// Whether `spec` listed `wire` in `supported_groups` (an absent extension
/// imposes no constraint — the hello offered nothing).
fn offered_group(spec: &ClientHelloSpec, wire: u16) -> bool {
    spec.extensions
        .iter()
        .find_map(|ext| match ext {
            ExtensionSpec::SupportedGroups(groups) => Some(groups.contains(&wire)),
            _ => None,
        })
        .unwrap_or(true)
}

/// Whether `spec`'s `key_share` already carried a share for `wire`.
///
/// RFC 8446 §4.2.8.2: a `HelloRetryRequest` must not select a group the client
/// already sent a share for, and a client which sees one MUST abort with
/// `illegal_parameter`.
fn offered_share(spec: &ClientHelloSpec, wire: u16) -> bool {
    spec.extensions
        .iter()
        .find_map(|ext| match ext {
            ExtensionSpec::KeyShare(groups) => Some(
                groups
                    .iter()
                    .any(|g| g.wire_id() == wire && !matches!(g, KeyShareGroup::Grease)),
            ),
            _ => None,
        })
        .unwrap_or(false)
}

/// `ClientHello2`'s extension list: `key_share` reduced to the selected group
/// (GREASE slots preserved — RFC 8701 values are chosen, not negotiated) and
/// the server's cookie inserted immediately after it, so the padding
/// extension that follows still lands the record on the 512-byte target.
fn retry_extensions(
    exts: &[ExtensionSpec],
    group: Option<&KeyShareGroup>,
    cookie: Option<&[u8]>,
) -> Vec<ExtensionSpec> {
    let group = group.cloned();
    let mut out = Vec::with_capacity(exts.len() + 1);
    let mut inserted = false;
    let mut saw_key_share = false;
    for ext in exts {
        if let ExtensionSpec::KeyShare(groups) = ext {
            saw_key_share = true;
            let shares = group.clone().map_or_else(
                || groups.clone(),
                |group| {
                    let mut shares: Vec<KeyShareGroup> = groups
                        .iter()
                        .filter(|g| matches!(g, KeyShareGroup::Grease))
                        .cloned()
                        .collect();
                    shares.push(group);
                    shares
                },
            );
            out.push(ExtensionSpec::KeyShare(shares));
            if let Some(cookie) = cookie {
                out.push(ExtensionSpec::Cookie(cookie.to_vec()));
                inserted = true;
            }
            continue;
        }
        out.push(ext.clone());
    }
    if !saw_key_share {
        // A caller-supplied spec with no `key_share` would otherwise answer the
        // HRR with a hello that has no share for the requested group at all.
        if let Some(group) = group {
            out.push(ExtensionSpec::KeyShare(vec![group]));
        }
    }
    if let (Some(cookie), false) = (cookie, inserted) {
        // Before `padding`, so the record still lands on the 512-byte target.
        let at = out
            .iter()
            .position(|e| matches!(e, ExtensionSpec::Padding))
            .unwrap_or(out.len());
        out.insert(at, ExtensionSpec::Cookie(cookie.to_vec()));
    }
    out
}

// ── ClientHello introspection ──────────────────────────────────────────────

/// Locate an extension body in the `ClientHello` handshake message `hello`.
///
/// The engine builds its own hello, so this is a read-back of what was
/// offered — the only way a server's choice can be checked against the
/// client's advertisement (RFC 5246 §7.4.3, RFC 8446 §4.4.3) without
/// threading every spec field through the driver. Returns `None` when the
/// hello is malformed, which callers treat as "nothing offered".
pub(crate) fn client_hello_extension(hello: &[u8], ty: u16) -> Option<&[u8]> {
    // type(1) len(3) legacy_version(2) random(32) session_id_len(1)
    let mut pos = 4 + 2 + 32;
    let sid_len = usize::from(*hello.get(pos)?);
    pos += 1 + sid_len;
    let cs_len = usize::from(u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]));
    pos += 2 + cs_len;
    let comp_len = usize::from(*hello.get(pos)?);
    pos += 1 + comp_len;
    let ext_len = usize::from(u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]));
    pos += 2;
    let exts = hello.get(pos..pos + ext_len)?;

    let mut at = 0usize;
    while at + 4 <= exts.len() {
        let ext_ty = u16::from_be_bytes([exts[at], exts[at + 1]]);
        let len = usize::from(u16::from_be_bytes([exts[at + 2], exts[at + 3]]));
        at += 4;
        let body = exts.get(at..at + len)?;
        if ext_ty == ty {
            return Some(body);
        }
        at += len;
    }
    None
}

/// Reject a server signature algorithm the `ClientHello` never offered.
///
/// RFC 5246 §7.4.3 and RFC 8446 §4.4.3 both require the server to sign with
/// a scheme from the client's `signature_algorithms`; accepting others also
/// breaks fingerprint fidelity (the profiles differ in what they advertise).
/// A hello without the extension imposes no constraint.
pub(crate) fn ensure_offered_sigalg(hello: &[u8], scheme: u16) -> Result<()> {
    let Some(body) = client_hello_extension(hello, 0x000D) else {
        return Ok(());
    };
    // `signature_algorithms`: list_len(2) || scheme(2)*
    let offered = body.get(2..).unwrap_or_default();
    let wanted = scheme.to_be_bytes();
    if offered.as_chunks::<2>().0.contains(&wanted) {
        return Ok(());
    }
    Err(TlsError::Verify(format!(
        "server signed with scheme 0x{scheme:04X}, which the `ClientHello` did not offer"
    )))
}

/// Parse a `ServerHello` body:
/// `version(2) || random(32) || sid_len(1) || sid || cipher(2) || comp(1) ||
/// ext_list_len(2) || extensions`.
///
/// `offered_session_id` is the legacy session id the client sent in its
/// `ClientHello`; the server's echo must match it exactly (RFC 8446 §4.1.3).
/// Result of parsing a `ServerHello`-shaped message.
enum ParsedReply {
    Hello(Box<ParsedServerHello>),
    Retry(HrrData),
}

fn parse_server_hello(body: &[u8], offered_session_id: &[u8]) -> Result<ParsedReply> {
    if body.len() < 38 {
        return Err(TlsError::Handshake("ServerHello body too short".into()));
    }
    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    if legacy_version != 0x0303 {
        return Err(TlsError::Handshake(format!(
            "ServerHello legacy_version is 0x{legacy_version:04X}, expected 0x0303"
        )));
    }
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&body[2..34]);
    // RFC 8446 §4.1.4: the HRR is a `ServerHello` whose random is a fixed
    // magic value. It must be recognised BEFORE the extension scan — an HRR's
    // `key_share` carries only `selected_group` (2 bytes), which the
    // ServerHello key-share parser would otherwise reject as "too short".
    let is_hrr = server_random == HRR_RANDOM;

    let session_id_len = usize::from(body[34]);
    let mut pos = 35 + session_id_len;
    if pos + 5 > body.len() {
        return Err(TlsError::Handshake(
            "ServerHello truncated at cipher suite".into(),
        ));
    }

    // Parse the session id — TLS 1.3 requires an exact echo (RFC 8446
    // §4.1.3), but TLS 1.2 servers may echo a different id or send an
    // empty one (RFC 5246 §7.4.1.2). The echo check runs after the version
    // is determined below.
    let session_id = &body[35..pos];

    let suite_wire = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 3; // cipher suite (2) + compression method (1)
    // Compression method must be 0x00 (null) for both versions.
    if body[pos - 1] != 0x00 {
        return Err(TlsError::Handshake(format!(
            "ServerHello compression method is 0x{:02X}, expected 0x00",
            body[pos - 1]
        )));
    }

    if pos + 2 > body.len() {
        return Err(TlsError::Handshake("ServerHello: no extensions".into()));
    }
    let ext_list_len = usize::from(u16::from_be_bytes([body[pos], body[pos + 1]]));
    pos += 2;
    let ext_end = pos + ext_list_len;
    if ext_end > body.len() {
        return Err(TlsError::Handshake(
            "ServerHello extensions truncated".into(),
        ));
    }

    // Parse extensions to determine version: TLS 1.3 servers include a
    // `supported_versions` extension with value 0x0304. TLS 1.2 servers
    // do not send this extension (it is a TLS 1.3-only extension).
    // First pass: find supported_versions and key_share.
    let mut has_supported_versions = false;
    let mut version_negotiated = 0u16;
    let mut peer_key = None;
    let mut mlkem_ciphertext = None;
    let mut ems = false;
    // HRR-only fields (RFC 8446 §4.1.4).
    let mut hrr_group = None;
    let mut hrr_cookie = None;

    // Scan the extension list body (relative to `pos`, which already points
    // past the 2-byte list-length field).
    let mut scan_pos = 0usize;
    while scan_pos + 4 <= ext_list_len {
        let ext_type = u16::from_be_bytes([body[pos + scan_pos], body[pos + scan_pos + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([
            body[pos + scan_pos + 2],
            body[pos + scan_pos + 3],
        ]));
        scan_pos += 4;
        if scan_pos + ext_len > ext_list_len {
            return Err(TlsError::Handshake(
                "ServerHello extension overruns list".into(),
            ));
        }
        let ext_data = &body[pos + scan_pos..pos + scan_pos + ext_len];
        scan_pos += ext_len;
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                if ext_data.len() == 2 {
                    version_negotiated = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                    has_supported_versions = true;
                }
            }
            EXT_COOKIE if is_hrr => {
                // RFC 8446 §4.2.2: `cookie<1..2^16-1>`.
                if ext_data.len() < 3 {
                    return Err(TlsError::Handshake(
                        "HelloRetryRequest cookie extension too short".into(),
                    ));
                }
                let len = usize::from(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                if len != ext_data.len() - 2 || len == 0 {
                    return Err(TlsError::Handshake(
                        "HelloRetryRequest cookie length does not match its body".into(),
                    ));
                }
                hrr_cookie = Some(ext_data[2..].to_vec());
            }
            EXT_KEY_SHARE if is_hrr => {
                // RFC 8446 §4.2.8.2: an HRR supplies only `selected_group`.
                if ext_data.len() != 2 {
                    return Err(TlsError::Handshake(format!(
                        "HelloRetryRequest key_share must be 2 bytes (selected_group), got {}",
                        ext_data.len()
                    )));
                }
                hrr_group = Some(u16::from_be_bytes([ext_data[0], ext_data[1]]));
            }
            EXT_KEY_SHARE => {
                if ext_data.len() < 4 {
                    return Err(TlsError::Handshake(
                        "ServerHello key_share extension too short".into(),
                    ));
                }
                let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                let key_len = usize::from(u16::from_be_bytes([ext_data[2], ext_data[3]]));
                match (group, key_len, ext_data.len()) {
                    (0x001D, 32, n) if n == 4 + key_len => {
                        peer_key = Some(ext_data[4..36].try_into().expect("32 bytes"));
                    }
                    (0x11EC, 1120, n) if n == 4 + key_len => {
                        mlkem_ciphertext = Some(
                            Ciphertext::from_bytes(&ext_data[4..4 + 1088])
                                .map_err(|e| TlsError::Handshake(e.to_string()))?,
                        );
                        peer_key = Some(ext_data[4 + 1088..].try_into().expect("32 bytes"));
                    }
                    (0x11EB | 0x11ED, ..) => {
                        return Err(TlsError::Handshake(
                            "ServerHello selected SecP256r1MLKEM768/SecP384r1MLKEM1024: no P-256/P-384 key exchange in this engine".into(),
                        ));
                    }
                    _ => {
                        return Err(TlsError::Handshake(format!(
                            "ServerHello key_share: group 0x{group:04X} key length {key_len}"
                        )));
                    }
                }
            }
            0x0017 => {
                // extended_master_secret (RFC 7627 §5.1): the extension_data
                // is EMPTY in both ClientHello and ServerHello — presence is
                // the server's agreement, not content.
                if !ext_data.is_empty() {
                    return Err(TlsError::Handshake(
                        "ServerHello extended_master_secret must have an empty body".into(),
                    ));
                }
                ems = true;
            }
            _ => {}
        }
    }

    if scan_pos != ext_list_len {
        return Err(TlsError::Handshake(
            "trailing garbage in ServerHello extension list".into(),
        ));
    }

    if is_hrr {
        // RFC 8446 §4.1.4: an HRR echoes the legacy session id, names TLS
        // 1.3 in `supported_versions`, and carries no key exchange.
        if session_id != offered_session_id {
            return Err(TlsError::Handshake(
                "HelloRetryRequest does not echo the offered session id".into(),
            ));
        }
        if !has_supported_versions || version_negotiated != 0x0304 {
            return Err(TlsError::Handshake(
                "HelloRetryRequest must select TLS 1.3 in supported_versions".into(),
            ));
        }
        return Ok(ParsedReply::Retry(HrrData {
            raw: Vec::new(),
            selected_group: hrr_group,
            cookie: hrr_cookie,
        }));
    }

    // Determine version from the supported_versions extension.
    if has_supported_versions && version_negotiated == 0x0304 {
        if session_id != offered_session_id {
            return Err(TlsError::Handshake(
                "ServerHello session id does not echo the offered one".into(),
            ));
        }
        let suite = CipherSuiteId::from_u16(suite_wire).ok_or_else(|| {
            TlsError::Handshake(format!(
                "server selected unsupported cipher suite 0x{suite_wire:04X}"
            ))
        })?;
        let peer_key = peer_key
            .ok_or_else(|| TlsError::Handshake("ServerHello has no key_share extension".into()))?;
        return Ok(ParsedReply::Hello(Box::new(ParsedServerHello {
            version: TlsVersion::Tls13,
            server_random,
            suite,
            suite12: None,
            peer_key: Some(peer_key),
            mlkem_ciphertext,
            ems: false,
        })));
    }
    // TLS 1.2: no supported_versions, or one naming a pre-1.3 version.
    if has_supported_versions && version_negotiated != 0x0303 {
        return Err(TlsError::Handshake(format!(
            "ServerHello negotiated version 0x{version_negotiated:04X}: only TLS 1.3 and TLS 1.2 are supported"
        )));
    }
    // RFC 8446 §4.1.3 downgrade protection: a TLS 1.3-capable server that
    // ends up negotiating 1.2 or below MUST set this sentinel in the last 8
    // bytes of its random, so a client that offered 1.3 can detect a forced
    // version drop. Every profile in this engine offers 1.3.
    if server_random[24..32] == *b"DOWNGRD\x01" || server_random[24..32] == *b"DOWNGRD\x00" {
        return Err(TlsError::Handshake(
            "ServerHello carries the RFC 8446 §4.1.3 downgrade sentinel: TLS 1.3 was suppressed"
                .into(),
        ));
    }
    // The cipher suite must be a TLS 1.2 AEAD suite. Session-id echo is
    // relaxed (TLS 1.2 servers may echo a different id or send none,
    // RFC 5246 §7.4.1.2).
    let suite12 = Tls12Suite::from_u16(suite_wire).ok_or_else(|| {
        TlsError::Handshake(format!(
            "TLS 1.2 server selected cipher suite 0x{suite_wire:04X}: only AEAD suites (ECDHE + AES-GCM/ChaCha20-Poly1305) are supported, CBC suites are not"
        ))
    })?;
    Ok(ParsedReply::Hello(Box::new(ParsedServerHello {
        version: TlsVersion::Tls12,
        server_random,
        suite: CipherSuiteId::Aes128GcmSha256, // placeholder, unused for 1.2
        suite12: Some(suite12),
        peer_key: None,
        mlkem_ciphertext: None,
        ems,
    })))
}

// ── Wire helpers ───────────────────────────────────────────────────────────

/// Wrap a handshake body as a raw handshake message: `type(1) || len(3) ||
/// body` (RFC 8446 §4).
pub(crate) fn make_hs_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(msg_type);
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    msg.extend_from_slice(&len.to_be_bytes()[1..]);
    msg.extend_from_slice(body);
    msg
}

/// Read a 3-byte big-endian length (RFC 8446 lengths are uint24).
fn u24(b: &[u8]) -> usize {
    (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
}

/// Remove TLS 1.3 record padding and extract the inner content type
/// (RFC 8446 §5.4): `actual_content || type_byte || optional zero padding`.
fn strip_padding(plaintext: &[u8]) -> Result<(u8, &[u8])> {
    let mut end = plaintext.len();
    while end > 0 && plaintext[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(TlsError::Handshake("all-zero TLSInnerPlaintext".into()));
    }
    let content_type = plaintext[end - 1];
    Ok((content_type, &plaintext[..end - 1]))
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        AEAD_TAG_LEN, AcceptAll, CONTENT_APPLICATION_DATA, HRR_RANDOM, HS_CERTIFICATE,
        HS_CERTIFICATE_VERIFY, HS_COMPRESSED_CERTIFICATE, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED,
        HS_MESSAGE_HASH, HS_SERVER_HELLO, HandshakeParams, ParsedReply, ParsedServerHello,
        TlsVersion, connect, decompress_bounded, decompress_certificate_message,
        ensure_offered_sigalg, make_hs_msg, parse_certificate_message, parse_certificate_verify,
        parse_encrypted_extensions, parse_server_hello, read_server_hs_messages,
    };
    use crate::crypto::{AeadKey, CipherSuiteId, KeySchedule};
    use crate::error::TlsError;
    use crate::hello::parse::parse_hello;
    use crate::hello::{BuildParams, build_hello};
    use crate::record::{CONTENT_HANDSHAKE, aead_aad};
    use crate::spec::{ClientHelloSpec, ExtensionSpec, KeyShareGroup, SessionIdSpec};
    use crate::verify::WebPkiVerifier;

    // ── helpers ────────────────────────────────────────────────────────────

    /// Decodes a hex string into bytes (test helper).
    fn decode_hex(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let mut hi = None;
        for b in s.bytes() {
            let v = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex digit: {b:#x}"),
            };
            match hi {
                None => hi = Some(v),
                Some(h) => {
                    out.push((h << 4) | v);
                    hi = None;
                }
            }
        }
        assert_eq!(hi, None, "hex string must have even length");
        out
    }

    /// RFC 8879 §4: the algorithms are read back from the hello we sent, so a
    /// REALITY hello built from a generated Chrome profile (which offers
    /// `brotli`/`zstd`) accepts a compressed Certificate instead of claiming
    /// it never offered one.
    #[rstest::rstest]
    #[case::offered(&[0x0002u16, 0x0003], &[0x0002, 0x0003])]
    #[case::absent_not_offered(&[], &[])]
    fn compressed_algorithms_are_read_from_the_hello(
        #[case] spec_algs: &[u16],
        #[case] expected: &[u16],
    ) {
        let mut extensions = vec![
            ExtensionSpec::ServerName,
            ExtensionSpec::SupportedGroups(vec![0x001D]),
            ExtensionSpec::KeyShare(vec![KeyShareGroup::X25519]),
            ExtensionSpec::SupportedVersions(vec![0x0304]),
        ];
        if !spec_algs.is_empty() {
            extensions.push(ExtensionSpec::CompressCertificate(spec_algs.to_vec()));
        }
        let spec = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions,
        };
        let rng = ring::rand::SystemRandom::new();
        let hello = crate::hello::build_hello(
            &spec,
            &crate::hello::BuildParams {
                server_name: "example.com",
                alpn: None,
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: None,
                rng: &rng,
            },
        )
        .expect("build hello");
        assert_eq!(
            super::compressed_algorithms(&hello.handshake_bytes),
            expected
        );
    }

    /// RFC 8446 §4.4.1: after a retry the transcript starts with the synthetic
    /// `message_hash` of `ClientHello1` — omitting it produces a `Finished`
    /// MAC the server rejects, which no offline `ServerHello` test would notice.
    #[test]
    fn retried_transcript_starts_with_the_message_hash_of_client_hello_one() {
        let ch1 = [0x01u8; 64];
        let ch2 = [0x02u8; 64];
        let sh2 = [0x03u8; 64];
        let suite = CipherSuiteId::Aes128GcmSha256;
        let ch1_hash = ring::digest::digest(suite.digest(), &ch1);

        let hrr = [0x04u8; 40];
        let mut ks = KeySchedule::new(suite);
        ks.add_transcript(&make_hs_msg(HS_MESSAGE_HASH, ch1_hash.as_ref()));
        ks.add_transcript(&hrr);
        ks.add_transcript(&ch2);
        ks.add_transcript(&sh2);

        // Hand-built reference: type 0xFE, 3-byte length, CH1 hash, then the
        // HRR and the two other messages — the RFC 8446 §4.4.1 byte sequence
        // is `message_hash || HelloRetryRequest || ClientHello2 || ...`.
        let mut reference = vec![HS_MESSAGE_HASH, 0x00, 0x00, 0x20];
        reference.extend_from_slice(ch1_hash.as_ref());
        reference.extend_from_slice(&hrr);
        reference.extend_from_slice(&ch2);
        reference.extend_from_slice(&sh2);
        let expected = ring::digest::digest(suite.digest(), &reference);

        let (got, len) = ks.transcript_hash();
        assert_eq!(
            &got[..len],
            expected.as_ref(),
            "message_hash, HRR, CH2, SH2 — the HRR itself is IN the transcript"
        );

        // Dropping the HelloRetryRequest message must change the transcript;
        // that omission makes the server flight fail to decrypt (caught by
        // `hello_retry_request_completes_against_a_rustls_server`).
        let mut without_hrr = KeySchedule::new(suite);
        without_hrr.add_transcript(&make_hs_msg(HS_MESSAGE_HASH, ch1_hash.as_ref()));
        without_hrr.add_transcript(&ch2);
        without_hrr.add_transcript(&sh2);
        let (missing, mlen) = without_hrr.transcript_hash();
        assert_ne!(&missing[..mlen], expected.as_ref());

        // The same messages WITHOUT the synthetic prefix must differ — this is
        // the regression the test exists for.
        let mut naive = KeySchedule::new(suite);
        naive.add_transcript(&ch1);
        naive.add_transcript(&ch2);
        naive.add_transcript(&sh2);
        let (wrong, wlen) = naive.transcript_hash();
        assert_ne!(&wrong[..wlen], expected.as_ref());
    }

    /// `parse_server_hello` for the ServerHello-only unit tests (an HRR
    /// where a `ServerHello` is expected is a test bug, not a result).
    fn parse_sh(body: &[u8], sid: &[u8]) -> crate::error::Result<Box<ParsedServerHello>> {
        match parse_server_hello(body, sid)? {
            ParsedReply::Hello(sh) => Ok(sh),
            ParsedReply::Retry(_) => panic!("expected a ServerHello, got a HelloRetryRequest"),
        }
    }

    /// A Chrome-flavoured spec with only TLS 1.3 suites/groups/versions, the
    /// minimal surface a rustls server needs to complete a 1-RTT handshake.
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
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap();
        // Advertise the protocol the client offers, so the EE carries an ALPN
        // selection the test can assert on.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config
    }

    // ── interop: our client vs a real rustls server ───────────────────────

    #[tokio::test]
    async fn handshake_completes_against_rustls_server() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = server_config(&certified.cert, &certified.signing_key);

        let server = tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut sock).unwrap();
            }
            // Read the client's 4-byte application data, echo it back, and
            // flush without issuing another blocking read.
            let mut echo = [0u8; 4];
            let mut got = 0;
            while got < echo.len() {
                conn.read_tls(&mut sock).unwrap();
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
        let mut tls = connect(
            stream,
            HandshakeParams {
                spec: &test_spec(),
                server_name: "localhost",
                alpn: Some(&[b"http/1.1"]),
                verifier: &AcceptAll,
                rng: &rng,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            tls.negotiated_alpn(),
            Some(b"http/1.1".as_slice()),
            "the server's ALPN selection is exposed, not discarded"
        );
        tls.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap();
    }

    /// End-to-end through a REAL retry: the client offers only the hybrid
    /// share, a ring-backed rustls server (which speaks x25519, not the hybrid)
    /// answers with a `HelloRetryRequest`, and the handshake must then COMPLETE —
    /// proving the `message_hash` transcript seed, the fresh key share and the
    /// switched key schedule, none of which the scripted tests can reach.
    #[tokio::test]
    async fn hello_retry_request_completes_against_a_rustls_server() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = server_config(&certified.cert, &certified.signing_key);

        let server = tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut sock).unwrap();
            }
            let mut echo = [0u8; 4];
            let mut got = 0;
            while got < echo.len() {
                conn.read_tls(&mut sock).unwrap();
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
        let spec = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![
                ExtensionSpec::ServerName,
                ExtensionSpec::SupportedGroups(vec![0x001D, 0x11EC]),
                // Only the hybrid share: x25519 is supported but NOT shared,
                // which is exactly the legal HelloRetryRequest trigger.
                ExtensionSpec::KeyShare(vec![KeyShareGroup::X25519Mlkem768]),
                ExtensionSpec::SupportedVersions(vec![0x0304, 0x0303]),
                ExtensionSpec::SignatureAlgorithms(vec![0x0403, 0x0804]),
                ExtensionSpec::Alpn(vec!["http/1.1".into()]),
            ],
        };
        let mut tls = connect(
            stream,
            HandshakeParams {
                spec: &spec,
                server_name: "localhost",
                alpn: Some(&[b"http/1.1"]),
                verifier: &AcceptAll,
                rng: &rng,
            },
        )
        .await
        .expect("the retried handshake must complete, not just rebuild a hello");

        assert_eq!(tls.negotiated_alpn(), Some(b"http/1.1".as_slice()));
        tls.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap();
    }

    // ── HelloRetryRequest (RFC 8446 §4.1.4 / §4.4.1) ───────────────────────

    /// Read one TLS record off the wire and return its payload.
    async fn read_record<R: tokio::io::AsyncRead + Unpin>(stream: &mut R) -> Vec<u8> {
        use tokio::io::AsyncReadExt as _;
        let mut hdr = [0u8; 5];
        stream.read_exact(&mut hdr).await.expect("record header");
        let len = usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.expect("record body");
        body
    }

    /// An HRR body (handshake header included) that echoes `session_id`.
    fn hrr_message(session_id: &[u8], group: Option<u16>, cookie: Option<&[u8]>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&HRR_RANDOM);
        body.push(u8::try_from(session_id.len()).unwrap());
        body.extend_from_slice(session_id);
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // cipher_suite
        body.push(0x00); // compression method
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions
        if let Some(group) = group {
            exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x02]);
            exts.extend_from_slice(&group.to_be_bytes());
        }
        if let Some(cookie) = cookie {
            exts.extend_from_slice(&[0x00, 0x2c]);
            exts.extend_from_slice(&u16::try_from(cookie.len() + 2).unwrap().to_be_bytes());
            exts.extend_from_slice(&u16::try_from(cookie.len()).unwrap().to_be_bytes());
            exts.extend_from_slice(cookie);
        }
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&exts);
        make_hs_msg(HS_SERVER_HELLO, &body)
    }

    /// A real HRR carries `selected_group` as a 2-byte `key_share` — the
    /// `ServerHello` key-share parser used to reject it as "too short", so the
    /// typed retry signal never fired.
    #[test]
    fn parse_server_hello_recognises_a_hint_bearing_hrr() {
        let msg = hrr_message(&[0x11; 32], Some(0x11EC), Some(b"c00k13"));
        match parse_server_hello(&msg[4..], &[0x11; 32]) {
            Ok(ParsedReply::Retry(hrr)) => {
                assert_eq!(hrr.selected_group, Some(0x11EC));
                assert_eq!(hrr.cookie.as_deref(), Some(b"c00k13".as_slice()));
            }
            Ok(ParsedReply::Hello(_)) => {
                panic!("an HRR magic random must not parse as a ServerHello")
            }
            Err(e) => panic!("a hint-bearing HRR must parse: {e:?}"),
        }
    }

    /// A cookie-only HRR (no `key_share`) is legal and must keep the offered
    /// key share in `ClientHello2`.
    #[test]
    fn parse_server_hello_recognises_a_cookie_only_hrr() {
        let msg = hrr_message(&[0x22; 32], None, Some(b"only-cookie"));
        match parse_server_hello(&msg[4..], &[0x22; 32]) {
            Ok(ParsedReply::Retry(hrr)) => {
                assert_eq!(hrr.selected_group, None);
                assert_eq!(hrr.cookie.as_deref(), Some(b"only-cookie".as_slice()));
            }
            Ok(ParsedReply::Hello(_)) => panic!("expected an HRR"),
            Err(e) => panic!("a cookie-only HRR must parse: {e:?}"),
        }
    }

    /// §4.1.4: the HRR must echo the offered legacy session id.
    #[test]
    fn parse_server_hello_rejects_an_hrr_that_does_not_echo_the_session_id() {
        let msg = hrr_message(&[0x33; 32], Some(0x001D), None);
        let Err(err) = parse_server_hello(&msg[4..], &[0x44; 32]) else {
            panic!("a mismatched session-id echo must be rejected");
        };
        assert!(
            err.to_string().contains("does not echo"),
            "expected the session-id echo error, got {err:?}"
        );
    }

    /// Guard against over-detection: a plain `ServerHello` whose `key_share` is
    /// truncated to 2 bytes is malformed, not an HRR.
    #[test]
    fn parse_server_hello_keeps_rejecting_a_short_key_share() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x1d]);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0xAB; 32]);
        body.push(0);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&exts);
        assert!(
            parse_server_hello(&body, &[]).is_err(),
            "a non-HRR ServerHello with a 2-byte key_share must stay an error"
        );
    }

    /// End-to-end: the scripted server sends an HRR asking for the hybrid
    /// group and a cookie; `ClientHello2` must keep `ClientHello1`'s random,
    /// session id and GREASE slot, change only `key_share`, and echo the
    /// cookie. The handshake then fails only because the scripted server
    /// hangs up — the assertion is on the bytes the client produced.
    #[tokio::test]
    async fn hello_retry_request_rebuilds_client_hello_two() {
        use tokio::io::AsyncWriteExt as _;

        let (client, mut server) = tokio::io::duplex(1 << 16);
        let spec = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![
                ExtensionSpec::ServerName,
                ExtensionSpec::SupportedGroups(vec![0x001D, 0x11EC]),
                ExtensionSpec::KeyShare(vec![KeyShareGroup::Grease, KeyShareGroup::X25519]),
                ExtensionSpec::SupportedVersions(vec![0x0304, 0x0303]),
                ExtensionSpec::SignatureAlgorithms(vec![0x0403]),
                ExtensionSpec::Padding,
            ],
        };
        let task = tokio::spawn(async move {
            let rng = ring::rand::SystemRandom::new();
            connect(
                client,
                HandshakeParams {
                    spec: &spec,
                    server_name: "example.com",
                    alpn: None,
                    verifier: &AcceptAll,
                    rng: &rng,
                },
            )
            .await
        });

        let ch1 = read_record(&mut server).await;
        let hello1 = parse_hello(&ch1).expect("CH1 parses");

        server
            .write_all(&super::to_record(&hrr_message(
                &hello1.session_id,
                Some(0x11EC),
                Some(b"srv-cookie"),
            )))
            .await
            .unwrap();

        let ch2 = read_record(&mut server).await;
        let hello2 = parse_hello(&ch2).expect("CH2 parses");
        drop(server);
        let outcome = task.await.expect("connect must not panic");
        assert!(outcome.is_err(), "the scripted server sends no ServerHello");

        assert_eq!(hello2.random, hello1.random, "the random must be replayed");
        assert_eq!(
            hello2.session_id, hello1.session_id,
            "the session id must be replayed"
        );
        assert_eq!(
            hello2.cipher_suites, hello1.cipher_suites,
            "cipher order is unchanged by a retry"
        );

        // RFC 8446 §4.2.8.2: ClientHello2's share must be NEW. The hybrid
        // entry ends with the X25519 public key, which must differ from the
        // one ClientHello1 sent.
        let x25519_of = |hello: &crate::hello::parse::ParsedClientHello, group: u16| -> Vec<u8> {
            let ks = hello.extension(0x0033).expect("key_share");
            let mut at = 2;
            while at + 4 <= ks.len() {
                let g = u16::from_be_bytes([ks[at], ks[at + 1]]);
                let klen = usize::from(u16::from_be_bytes([ks[at + 2], ks[at + 3]]));
                if g == group {
                    return ks[at + 4..at + 4 + klen].to_vec();
                }
                at += 4 + klen;
            }
            panic!("group 0x{group:04X} not in key_share");
        };
        assert_ne!(
            x25519_of(&hello1, 0x001D),
            &x25519_of(&hello2, 0x11EC)[1184..],
            "the retry must mint a NEW key share, not resend ClientHello1's"
        );

        // key_share: the CH1 GREASE slot is preserved, then exactly the
        // requested group (the GREASE value is drawn, so compare with CH1).
        let ch1_groups = keyshare_groups(&hello1);
        assert_eq!(ch1_groups.len(), 2, "CH1 offers a GREASE slot + x25519");
        assert_eq!(
            keyshare_groups(&hello2),
            vec![ch1_groups[0], 0x11EC],
            "the GREASE slot is replayed, then the selected group"
        );

        // cookie echoed verbatim, length-prefixed.
        assert_eq!(
            hello2.extension(0x002c).expect("cookie"),
            &[
                0x00, 0x0A, b's', b'r', b'v', b'-', b'c', b'o', b'o', b'k', b'i', b'e'
            ]
        );

        // Everything else is byte-identical (fingerprint fidelity), except
        // `padding` — RFC 8446 §4.1.2 allows its length to change, and it must
        // here: the cookie grows the hello and the padding keeps the record on
        // the 512-byte target.
        for (ty, body) in &hello1.extensions {
            if *ty == 0x0033 || *ty == 0x0015 {
                continue;
            }
            assert_eq!(
                hello2.extension(*ty),
                Some(body.as_slice()),
                "extension 0x{ty:04X} must not change across the retry"
            );
        }
        // No new extension types beyond `cookie`, and the cookie sits right
        // after `key_share` (so the padding that follows still owns the tail).
        let ch1_types: Vec<u16> = hello1.extensions.iter().map(|(t, _)| *t).collect();
        let ch2_types: Vec<u16> = hello2.extensions.iter().map(|(t, _)| *t).collect();
        let pos = |ty: u16| ch2_types.iter().position(|t| *t == ty);
        assert_eq!(
            pos(0x002c),
            pos(0x0033).map(|p| p + 1),
            "the cookie is inserted immediately after key_share"
        );
        for ty in &ch2_types {
            assert!(
                *ty == 0x002c || ch1_types.contains(ty),
                "extension 0x{ty:04X} appeared only in ClientHello2"
            );
        }

        // Padding still lands the CH2 record on the 512-byte target.
        // A hybrid share is ~1.2 KB, so the 512-byte record target is
        // unreachable and the padding extension is correctly omitted.
        assert!(ch2.len() + 5 > 512, "the hybrid share grows the hello");
        assert!(
            hello2.extension(0x0015).is_none(),
            "no padding if it cannot fit"
        );
    }

    /// The `key_share` group ids of a built `ClientHello`, in wire order.
    fn keyshare_groups(hello: &crate::hello::parse::ParsedClientHello) -> Vec<u16> {
        let ks = hello.extension(0x0033).expect("key_share");
        let list_len = usize::from(u16::from_be_bytes([ks[0], ks[1]]));
        assert_eq!(list_len, ks.len() - 2, "key_share list length");
        let mut groups = Vec::new();
        let mut at = 2;
        while at + 4 <= ks.len() {
            groups.push(u16::from_be_bytes([ks[at], ks[at + 1]]));
            let klen = usize::from(u16::from_be_bytes([ks[at + 2], ks[at + 3]]));
            at += 4 + klen;
        }
        groups
    }

    /// RFC 8446 §4.2.8.2: a server must not select a group `ClientHello1`
    /// already sent a share for — the client MUST abort with
    /// `illegal_parameter` and must not send `ClientHello2`.
    #[tokio::test]
    async fn hello_retry_request_selecting_an_offered_group_is_illegal() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (client, mut server) = tokio::io::duplex(1 << 16);
        let spec = test_spec();
        let task = tokio::spawn(async move {
            let rng = ring::rand::SystemRandom::new();
            connect(
                client,
                HandshakeParams {
                    spec: &spec,
                    server_name: "example.com",
                    alpn: None,
                    verifier: &AcceptAll,
                    rng: &rng,
                },
            )
            .await
        });

        let ch1 = read_record(&mut server).await;
        let hello1 = parse_hello(&ch1).expect("CH1 parses");
        assert!(
            keyshare_groups(&hello1).contains(&0x001D),
            "test_spec offers x25519, so selecting it is the illegal case"
        );
        server
            .write_all(&super::to_record(&hrr_message(
                &hello1.session_id,
                Some(0x001D),
                None,
            )))
            .await
            .unwrap();
        // Nothing more may arrive: the client aborts instead of retrying.
        let mut hdr = [0u8; 5];
        let trailing =
            tokio::time::timeout(std::time::Duration::from_millis(200), server.read(&mut hdr))
                .await;
        assert!(
            matches!(trailing, Ok(Ok(0)) | Err(_)),
            "the client must not send ClientHello2, got {trailing:?}"
        );
        drop(server);

        match task.await.expect("connect must not panic") {
            Err(TlsError::Handshake(detail)) => assert!(
                detail.contains("illegal_parameter"),
                "expected an illegal_parameter abort, got: {detail}"
            ),
            Err(other) => panic!("expected a handshake error, got {other:?}"),
            Ok(_) => panic!("expected an abort"),
        }
    }

    /// A classical retry (the group already offered) keeps the 512-byte
    /// record target: the cookie grows the hello and the padding shrinks.
    #[tokio::test]
    async fn hello_retry_request_with_x25519_keeps_the_512_byte_record() {
        use tokio::io::AsyncWriteExt as _;

        let (client, mut server) = tokio::io::duplex(1 << 16);
        // ClientHello1 offers only the HYBRID share, so a retry to plain
        // x25519 is legal (RFC 8446 §4.2.8.2 forbids re-selecting an already
        // offered group) and the replacement share is small enough to keep the
        // 512-byte record target.
        let spec = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![
                ExtensionSpec::ServerName,
                ExtensionSpec::SupportedGroups(vec![0x001D, 0x11EC]),
                ExtensionSpec::KeyShare(vec![KeyShareGroup::X25519Mlkem768]),
                ExtensionSpec::SupportedVersions(vec![0x0304, 0x0303]),
                ExtensionSpec::SignatureAlgorithms(vec![0x0403]),
                ExtensionSpec::Padding,
            ],
        };
        let task = tokio::spawn(async move {
            let rng = ring::rand::SystemRandom::new();
            connect(
                client,
                HandshakeParams {
                    spec: &spec,
                    server_name: "example.com",
                    alpn: None,
                    verifier: &AcceptAll,
                    rng: &rng,
                },
            )
            .await
        });

        let ch1 = read_record(&mut server).await;
        let hello1 = parse_hello(&ch1).expect("CH1 parses");
        // The hybrid share is ~1.2 KB, so CH1 itself cannot hit the target.
        assert!(ch1.len() + 5 > 512, "CH1 carries the hybrid share");
        server
            .write_all(&super::to_record(&hrr_message(
                &hello1.session_id,
                Some(0x001D),
                Some(b"pad-cookie"),
            )))
            .await
            .unwrap();
        let ch2 = read_record(&mut server).await;
        drop(server);
        let _ = task.await.expect("connect must not panic");

        assert_eq!(
            ch2.len() + 5,
            512,
            "the retried hello still hits the 512-byte record target"
        );
    }

    /// A retry the engine cannot answer (an unimplemented group) is a typed
    /// error, not a generic failure — and must not send a second hello.
    #[tokio::test]
    async fn hello_retry_request_for_an_unsupported_group_is_a_typed_error() {
        use tokio::io::AsyncWriteExt as _;

        let (client, mut server) = tokio::io::duplex(1 << 16);
        let spec = test_spec();
        let task = tokio::spawn(async move {
            let rng = ring::rand::SystemRandom::new();
            connect(
                client,
                HandshakeParams {
                    spec: &spec,
                    server_name: "example.com",
                    alpn: None,
                    verifier: &AcceptAll,
                    rng: &rng,
                },
            )
            .await
        });

        let ch1 = read_record(&mut server).await;
        let hello1 = parse_hello(&ch1).expect("CH1 parses");
        // 0x0017 = secp256r1: supported by neither the engine's key share nor
        // the spec's supported_groups.
        server
            .write_all(&super::to_record(&hrr_message(
                &hello1.session_id,
                Some(0x0017),
                None,
            )))
            .await
            .unwrap();
        drop(server);

        match task.await.expect("connect must not panic") {
            Err(TlsError::HelloRetryRequestUnsupported(_)) => {}
            Err(other) => panic!("expected a typed unsupported-group error, got {other:?}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    // ── parse unit tests (RFC 8448 §3 vectors) ────────────────────────────

    /// RFC 8448 §3 `ServerHello` handshake message (full, with 4-byte header):
    /// AES-128-GCM-SHA256, X25519 keyshare `c98288…e751f0f`.
    const SERVER_HELLO_VEC: &str = concat!(
        "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928",
        "00130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1",
        "dd69b1b04e751f0f002b00020304",
    );

    /// RFC 8448 §3 `Certificate` handshake message (full, with 4-byte header):
    /// one RSA self-signed certificate (`0x308201ac…`).
    const CERTIFICATE_VEC: &str = concat!(
        "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01",
        "010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a17",
        "0d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a",
        "864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c",
        "0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ce",
        "d43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef",
        "0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203",
        "010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a8648",
        "86f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2d",
        "f7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e",
        "67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8",
        "b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000",
    );

    /// RFC 8448 §3 `CertificateVerify` handshake message (full, with 4-byte
    /// header): `ecdsa_secp256r1_sha256` (0x0804), 128-byte signature.
    const CERTIFICATE_VERIFY_VEC: &str = concat!(
        "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8",
        "477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d",
        "4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be",
        "152a3da5043e063dda65cdf5aea20d53dfacd42f74f3",
    );

    #[test]
    fn parse_server_hello_extracts_suite_and_keyshare() {
        let msg = decode_hex(SERVER_HELLO_VEC);
        let sh = parse_sh(&msg[4..], &[]).unwrap();
        assert_eq!(sh.suite, crate::crypto::CipherSuiteId::Aes128GcmSha256);
        let expected: [u8; 32] =
            decode_hex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")
                .try_into()
                .unwrap();
        assert_eq!(sh.peer_key, Some(expected));

        // A non-0x0303 legacy_version is rejected by the parser itself.
        let mut bad = msg[4..].to_vec();
        bad[1] = 0x04;
        assert!(parse_sh(&bad, &[]).is_err());
    }

    /// A minimal TLS 1.3 `ServerHello` body: TLS 1.3 legacy version, 32
    /// `0xAB` random bytes, no session id, AES-128-GCM, no compression, a
    /// `supported_versions` extension (= 0x0304) and the given raw extension
    /// bytes.
    fn minimal_server_hello(exts: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0xAB; 32]);
        body.push(0); // session id length
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0); // compression method
        let mut supported_versions = Vec::new();
        supported_versions.extend_from_slice(&0x002bu16.to_be_bytes());
        supported_versions.extend_from_slice(&0x0002u16.to_be_bytes());
        supported_versions.extend_from_slice(&0x0304u16.to_be_bytes());
        let total = supported_versions.len() + exts.len();
        body.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        body.extend_from_slice(&supported_versions);
        body.extend_from_slice(exts);
        body
    }

    /// A `key_share` extension for X25519 (0x001D) with a 32-byte key.
    fn x25519_keyshare_ext(key: &[u8; 32]) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0033u16.to_be_bytes());
        ext.extend_from_slice(&0x0024u16.to_be_bytes()); // ext len 36
        ext.extend_from_slice(&0x001Du16.to_be_bytes()); // X25519
        ext.extend_from_slice(&0x0020u16.to_be_bytes()); // key len 32
        ext.extend_from_slice(key);
        ext
    }

    #[test]
    fn parse_server_hello_enforces_conformance_guards() {
        let key = [0x44u8; 32];
        let body = minimal_server_hello(&x25519_keyshare_ext(&key));
        assert_eq!(parse_sh(&body, &[]).unwrap().peer_key, Some(key));

        // A keyshare for a group other than X25519 is rejected outright.
        let mut wrong_group = x25519_keyshare_ext(&key);
        wrong_group[4] = 0x00;
        wrong_group[5] = 0x13; // secp256r1
        assert!(parse_sh(&minimal_server_hello(&wrong_group), &[]).is_err());

        // A keyshare whose key length is not 32 is rejected outright.
        let mut wrong_len = x25519_keyshare_ext(&key);
        wrong_len[6] = 0x00;
        wrong_len[7] = 0x10; // key len 16
        assert!(parse_sh(&minimal_server_hello(&wrong_len), &[]).is_err());

        // The session id echo must match the offered one exactly.
        let mut sid_body = minimal_server_hello(&x25519_keyshare_ext(&key));
        sid_body[34] = 32; // session id length
        sid_body.splice(35..35, std::iter::repeat_n(0x11u8, 32));
        assert_eq!(
            parse_sh(&sid_body, &[0x11; 32]).unwrap().peer_key,
            Some(key)
        );
        assert!(parse_sh(&sid_body, &[0x22; 32]).is_err());

        // Bytes left over inside the declared extension list are rejected.
        let mut padded = x25519_keyshare_ext(&key);
        padded.extend_from_slice(&[0x00, 0x00]);
        let mut garbage = Vec::new();
        garbage.extend_from_slice(&0x0303u16.to_be_bytes());
        garbage.extend_from_slice(&[0xAB; 32]);
        garbage.push(0);
        garbage.extend_from_slice(&0x1301u16.to_be_bytes());
        garbage.push(0);
        garbage.extend_from_slice(&u16::try_from(padded.len()).unwrap().to_be_bytes());
        garbage.extend_from_slice(&padded);
        assert!(parse_sh(&garbage, &[]).is_err());
    }

    #[test]
    fn parse_certificate_message_extracts_leaf_first_chain() {
        let msg = decode_hex(CERTIFICATE_VEC);
        let chain = parse_certificate_message(&msg[4..]).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].len(), 0x0000_01b0);
        assert_eq!(&chain[0][..2], &[0x30, 0x82]);

        // Two entries keep leaf-first order and tolerate per-cert extensions.
        let leaf = [0x30, 0x01, 0xAA];
        let root = [0x30, 0x01, 0xBB];
        let entry = |der: &[u8]| {
            let mut e = Vec::new();
            e.extend_from_slice(&u32::try_from(der.len()).unwrap().to_be_bytes()[1..]);
            e.extend_from_slice(der);
            e.extend_from_slice(&0x0002u16.to_be_bytes()); // 2 bytes of ext data
            e.extend_from_slice(&[0x00, 0x00]); // empty per-cert extensions
            e
        };
        let mut list = entry(&leaf);
        list.extend_from_slice(&entry(&root));
        let mut body = vec![0x00]; // no certificate_request_context
        body.extend_from_slice(&u32::try_from(list.len()).unwrap().to_be_bytes()[1..]);
        body.extend_from_slice(&list);
        let chain = parse_certificate_message(&body).unwrap();
        assert_eq!(chain, vec![leaf.to_vec(), root.to_vec()]);
    }

    /// A `Certificate` body carrying one DER-shaped entry per element.
    fn certificate_body(chain: &[&[u8]]) -> Vec<u8> {
        let mut list = Vec::new();
        for der in chain {
            list.extend_from_slice(&u32::try_from(der.len()).unwrap().to_be_bytes()[1..]);
            list.extend_from_slice(der);
            list.extend_from_slice(&0x0000u16.to_be_bytes()); // no per-cert extensions
        }
        let mut body = vec![0x00]; // no certificate_request_context
        body.extend_from_slice(&u32::try_from(list.len()).unwrap().to_be_bytes()[1..]);
        body.extend_from_slice(&list);
        body
    }

    /// A `CompressedCertificate` body (RFC 8879 §4):
    /// `algorithm(2) || uncompressed_length(3) || compressed<1..2^24-1>`.
    fn compressed_certificate_body(
        algorithm: u16,
        uncompressed_len: usize,
        compressed: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&algorithm.to_be_bytes());
        body.extend_from_slice(&u32::try_from(uncompressed_len).unwrap().to_be_bytes()[1..]);
        body.extend_from_slice(&u32::try_from(compressed.len()).unwrap().to_be_bytes()[1..]);
        body.extend_from_slice(compressed);
        body
    }

    /// Brotli-compresses `data` (the algorithm Cloudflare's edge selected for
    /// this engine's hello).
    fn brotli_compress(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    /// RFC 8879 §4: the payload is the Certificate BODY (no handshake header),
    /// it is compressed with the algorithm the `ClientHello` offered, and the
    /// two 3-byte lengths must agree with the actual bytes.
    #[test]
    fn compressed_certificate_decompresses_offered_algorithm() {
        let body = certificate_body(&[&[0x30, 0x01, 0xAA]]);

        // Brotli (0x0002) — what Cloudflare's edge picked for chrome_130.
        let msg = compressed_certificate_body(0x0002, body.len(), &brotli_compress(&body));
        assert_eq!(
            decompress_certificate_message(&msg, &[0x0002, 0x0003]).unwrap(),
            body
        );

        // zstd (0x0003) is advertised too and must decode identically.
        let compressed = zstd::stream::encode_all(&body[..], 3).unwrap();
        let msg = compressed_certificate_body(0x0003, body.len(), &compressed);
        assert_eq!(
            decompress_certificate_message(&msg, &[0x0002, 0x0003]).unwrap(),
            body
        );
    }

    #[test]
    fn compressed_certificate_rejects_unoffered_algorithm_and_length_lies() {
        let body = certificate_body(&[&[0x30, 0x01, 0xAA]]);
        let msg = compressed_certificate_body(0x0002, body.len(), &brotli_compress(&body));

        // The ClientHello offered only zstd: brotli is an unoffered selection.
        let err = decompress_certificate_message(&msg, &[0x0003]).unwrap_err();
        assert!(
            err.to_string().contains("did not offer"),
            "expected the unoffered-algorithm error, got: {err}"
        );

        // A declared uncompressed_length that lies about the payload aborts
        // the handshake (RFC 8879 §4 makes this `bad_certificate`).
        let mut lying = msg.clone();
        let declared = u32::try_from(body.len()).unwrap() + 7;
        lying[2..5].copy_from_slice(&declared.to_be_bytes()[1..]);
        let err = decompress_certificate_message(&lying, &[0x0002]).unwrap_err();
        assert!(
            err.to_string().contains("declares"),
            "expected the length-mismatch error, got: {err}"
        );

        // A compressed-vector length that disagrees with the body is refused
        // before any decoder runs.
        let mut truncated = msg;
        truncated.truncate(truncated.len() - 1);
        assert!(decompress_certificate_message(&truncated, &[0x0002]).is_err());
    }

    /// The flight reader must put the `CompressedCertificate` message AS SENT
    /// into the transcript: the server hashed that message, so a re-built
    /// `Certificate` would fail its Finished MAC (the `Finished MAC mismatch`
    /// the 2026-09-16 batch logged against every Cloudflare-fronted link).
    #[tokio::test]
    async fn server_flight_keeps_compressed_certificate_as_sent() {
        let suite = CipherSuiteId::Aes128GcmSha256;
        let key = AeadKey::from_key_bytes(suite, &[0x11; 16]).unwrap();

        let der = vec![0x30u8, 0x81, 26, 0xAA, 0xAA];
        let cert_body = certificate_body(&[&der]);
        let cc_body =
            compressed_certificate_body(0x0002, cert_body.len(), &brotli_compress(&cert_body));
        let cc_msg = make_hs_msg(HS_COMPRESSED_CERTIFICATE, &cc_body);

        let ee_msg = make_hs_msg(HS_ENCRYPTED_EXTENSIONS, &[0x00, 0x00]);
        let mut verify_body = Vec::new();
        verify_body.extend_from_slice(&0x0403u16.to_be_bytes());
        verify_body.extend_from_slice(&0x0040u16.to_be_bytes());
        verify_body.extend_from_slice(&[0xAA; 64]);
        let verify_msg = make_hs_msg(HS_CERTIFICATE_VERIFY, &verify_body);
        let finished_msg = make_hs_msg(HS_FINISHED, &[0xBB; 32]);

        let mut raw_flight = Vec::new();
        raw_flight.extend_from_slice(&ee_msg);
        raw_flight.extend_from_slice(&cc_msg);
        raw_flight.extend_from_slice(&verify_msg);
        raw_flight.extend_from_slice(&finished_msg);

        let (mut client_stream, mut server_side) = tokio::io::duplex(64 * 1024);
        write_encrypted_flight_chunk(&mut server_side, &key, 0, &raw_flight).await;

        let parsed = read_server_hs_messages(&mut client_stream, &key, &[0x0002, 0x0003])
            .await
            .unwrap();
        assert_eq!(parsed.chain, vec![der]);
        assert_eq!(parsed.cert_raw, cc_msg, "transcript must carry type 25");
        assert_eq!(parsed.sf_verify_data, vec![0xBB; 32]);
    }

    #[test]
    fn decompression_bomb_is_bounded() {
        // 8 MiB of zeros compresses to a few hundred bytes — a classic
        // decompression bomb. The bounded decompressor must refuse it
        // instead of inflating it into memory.
        let bomb: Vec<u8> = vec![0x00; 8 << 20];
        let compressed = brotli_compress(&bomb);
        assert!(compressed.len() < 1024, "bomb must compress small");

        let err = decompress_bounded(brotli::Decompressor::new(&compressed[..], 4096)).unwrap_err();
        assert!(
            err.to_string().contains("decompression bomb"),
            "expected the bound error, got: {err}"
        );

        // A valid (bounded) certificate payload still decompresses fine.
        let der = vec![0x30u8, 0x81, 26, 0xAA, 0xAA];
        assert_eq!(
            decompress_bounded(brotli::Decompressor::new(&brotli_compress(&der)[..], 4096))
                .unwrap()
                .unwrap(),
            der
        );
    }

    #[test]
    fn parse_certificate_verify_extracts_signature_scheme() {
        let msg = decode_hex(CERTIFICATE_VERIFY_VEC);
        assert_eq!(parse_certificate_verify(&msg[4..]).unwrap(), 0x0804);
    }

    #[test]
    fn parse_encrypted_extensions_validates_alpn_and_versions() {
        // supported_versions = 0x0304, ALPN = [h2].
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&[0x00, 0x03, 0x02, 0x03, 0x04]);
        let alpn = [0x00, 0x03, 0x02, b'h', b'2'];
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&u16::try_from(alpn.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&alpn);
        let mut body = Vec::new();
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&exts);
        assert_eq!(
            parse_encrypted_extensions(&body).unwrap(),
            Some(b"h2".to_vec()),
            "the selected protocol is returned, not discarded"
        );

        // RFC 7301 §3.1: the server selects exactly ONE protocol.
        let mut two = Vec::new();
        two.extend_from_slice(&0x002bu16.to_be_bytes());
        two.extend_from_slice(&[0x00, 0x03, 0x02, 0x03, 0x04]);
        two.extend_from_slice(&0x0010u16.to_be_bytes());
        two.extend_from_slice(&[
            0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ]);
        let mut two_body = Vec::new();
        two_body.extend_from_slice(&u16::try_from(two.len()).unwrap().to_be_bytes());
        two_body.extend_from_slice(&two);
        assert!(
            parse_encrypted_extensions(&two_body).is_err(),
            "a server that selects two protocols violates RFC 7301 §3.1"
        );

        // An empty EE is valid: no ALPN negotiated, no supported_versions.
        parse_encrypted_extensions(&[0x00, 0x00]).unwrap();

        // A declared extension list longer than its content is trailing
        // garbage and rejected.
        let mut garbage = vec![0x00, 0x05];
        garbage.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(parse_encrypted_extensions(&garbage).is_err());
    }

    #[test]
    fn parse_encrypted_extensions_rejects_unsupported_version() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&[0x00, 0x03, 0x02, 0x03, 0x03]); // TLS 1.2
        let mut body = Vec::new();
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&exts);
        assert!(parse_encrypted_extensions(&body).is_err());
    }

    // ── multi-record flight reassembly (RFC 8446 §5.1) ────────────────────

    /// Seal `chunk` as one TLS 1.3 record whose `TLSInnerPlaintext` is
    /// `chunk || CONTENT_HANDSHAKE` (no padding), under `key` with `seq`.
    async fn write_encrypted_flight_chunk<W: tokio::io::AsyncWrite + Unpin>(
        w: &mut W,
        key: &AeadKey,
        seq: u64,
        chunk: &[u8],
    ) {
        let mut inner = chunk.to_vec();
        inner.push(CONTENT_HANDSHAKE);
        let rec_len =
            u16::try_from(inner.len() + AEAD_TAG_LEN).expect("test flight chunk fits u16");
        let aad = aead_aad(inner.len() + AEAD_TAG_LEN);
        let mut record = Vec::with_capacity(5 + inner.len() + AEAD_TAG_LEN);
        record.extend_from_slice(&[CONTENT_APPLICATION_DATA, 0x03, 0x03]);
        record.extend_from_slice(&rec_len.to_be_bytes());
        record.extend_from_slice(&inner);
        key.seal_in_place(seq, &aad, &mut record, 5).unwrap();
        w.write_all(&record).await.unwrap();
    }

    #[tokio::test]
    async fn server_flight_parses_certificate_split_across_records() {
        let suite = CipherSuiteId::Aes128GcmSha256;
        let key = AeadKey::from_key_bytes(suite, &[0x11; 16]).unwrap();

        // A certificate chain larger than one record's 16 KiB plaintext, so
        // the Certificate handshake message MUST span two TLS records (the
        // rustls fragmentation a >16 KiB chain produces).
        let fake_cert = vec![0x30u8; 20_000];
        let mut entry = Vec::with_capacity(3 + fake_cert.len() + 2);
        entry.extend_from_slice(&u32::try_from(fake_cert.len()).unwrap().to_be_bytes()[1..]);
        entry.extend_from_slice(&fake_cert);
        entry.extend_from_slice(&0x0000u16.to_be_bytes()); // no per-cert extensions
        let mut cert_body = vec![0x00]; // no certificate_request_context
        cert_body.extend_from_slice(&u32::try_from(entry.len()).unwrap().to_be_bytes()[1..]);
        cert_body.extend_from_slice(&entry);
        let cert_msg = make_hs_msg(HS_CERTIFICATE, &cert_body);
        assert!(cert_msg.len() > 16_384, "Certificate must span records");

        let ee_msg = make_hs_msg(HS_ENCRYPTED_EXTENSIONS, &[0x00, 0x00]); // empty ext list
        let mut cv_body = Vec::new();
        cv_body.extend_from_slice(&0x0403u16.to_be_bytes()); // ecdsa_secp256r1_sha256
        cv_body.extend_from_slice(&0x0040u16.to_be_bytes());
        cv_body.extend_from_slice(&[0xAA; 64]);
        let cv_msg = make_hs_msg(HS_CERTIFICATE_VERIFY, &cv_body);
        let finished_msg = make_hs_msg(HS_FINISHED, &[0xBB; 32]);

        // Record 1 ends inside the Certificate message; record 2 carries the
        // remainder of the flight.
        let mut raw_flight = Vec::new();
        raw_flight.extend_from_slice(&ee_msg);
        raw_flight.extend_from_slice(&cert_msg);
        raw_flight.extend_from_slice(&cv_msg);
        raw_flight.extend_from_slice(&finished_msg);
        let split = ee_msg.len() + cert_msg.len() / 2;
        assert!(
            split < ee_msg.len() + cert_msg.len(),
            "split inside Certificate"
        );

        let (mut client_stream, mut server_side) = tokio::io::duplex(64 * 1024);
        write_encrypted_flight_chunk(&mut server_side, &key, 0, &raw_flight[..split]).await;
        write_encrypted_flight_chunk(&mut server_side, &key, 1, &raw_flight[split..]).await;

        let parsed = read_server_hs_messages(&mut client_stream, &key, &[])
            .await
            .unwrap();
        assert_eq!(parsed.chain.len(), 1);
        assert_eq!(parsed.chain[0], fake_cert);
        assert_eq!(parsed.signature_scheme, 0x0403);
        assert_eq!(parsed.cert_verify_body, cv_body);
        assert_eq!(parsed.sf_verify_data, vec![0xBB; 32]);
    }

    /// A server flight without `CertificateVerify` must not panic: the
    /// reader leaves `cert_verify_body` empty and [`drive`] slices it
    /// fallibly. The body is only reachable through unauthenticated ECDHE
    /// handshake keys, so an on-path party could otherwise abort the task
    /// (denial of service) before any MAC check runs.
    #[tokio::test]
    async fn server_flight_without_certificate_verify_yields_empty_signature() {
        let suite = CipherSuiteId::Aes128GcmSha256;
        let key = AeadKey::from_key_bytes(suite, &[0x11; 16]).unwrap();
        let ee_msg = make_hs_msg(HS_ENCRYPTED_EXTENSIONS, &[0x00, 0x00]);
        let cert_msg = make_hs_msg(HS_CERTIFICATE, &[0x00, 0x00, 0x00, 0x00]);
        let finished_msg = make_hs_msg(HS_FINISHED, &[0xBB; 32]);
        let mut raw_flight = ee_msg;
        raw_flight.extend_from_slice(&cert_msg);
        raw_flight.extend_from_slice(&finished_msg);

        let (mut client_stream, mut server_side) = tokio::io::duplex(8 * 1024);
        write_encrypted_flight_chunk(&mut server_side, &key, 0, &raw_flight).await;
        let parsed = read_server_hs_messages(&mut client_stream, &key, &[])
            .await
            .unwrap();
        assert_eq!(parsed.cert_verify_body.len(), 0);
        assert!(
            parsed.cert_verify_body.get(4..).is_none(),
            "the caller must find no signature instead of panicking on [4..]"
        );
    }

    // ── hybrid X25519MLKEM768 handshake (fake PQ server double) ───────────

    /// A loopback server double that negotiates X25519MLKEM768: it
    /// encapsulates to the client's ML-KEM-768 key share, feeds
    /// `classical || pq` through the same key schedule, and proves both
    /// sides derived matching traffic keys by an encrypted app-data echo.
    #[tokio::test]
    async fn hybrid_handshake_completes_against_fake_pq_server() {
        use crate::crypto::X25519KeyPair;
        use crate::crypto::mlkem::{Mlkem768, PublicKey as MlkemPublicKey};
        use crate::hello::parse::parse_hello;

        let suite = CipherSuiteId::Aes128GcmSha256;
        let mut spec = test_spec();
        for ext in &mut spec.extensions {
            match ext {
                ExtensionSpec::SupportedGroups(groups) => *groups = vec![0x11EC, 0x001D],
                ExtensionSpec::KeyShare(groups) => *groups = vec![KeyShareGroup::X25519Mlkem768],
                _ => {}
            }
        }

        let (client_stream, mut server_side) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            // Read the ClientHello record and pull the hybrid key share.
            let mut hdr = [0u8; 5];
            server_side.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 0x16);
            let mut ch = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
            server_side.read_exact(&mut ch).await.unwrap();
            let parsed = parse_hello(&ch).unwrap();
            let ks_ext = parsed.extension(0x0033).unwrap();
            // list_len(2) + entry(group 11ec, kx_len 04c0, 1216 bytes) in
            // the Go wire order: ML-KEM ek (1184) first, X25519 pub last.
            assert_eq!(&ks_ext[..4], &[0x04, 0xc4, 0x11, 0xec]);
            let client_mlkem_pk = MlkemPublicKey::from_bytes(&ks_ext[6..6 + 1184]).unwrap();
            let client_x25519: [u8; 32] = ks_ext[6 + 1184..6 + 1216].try_into().unwrap();

            // Classical + PQ shared secrets, exactly as a real hybrid server.
            let rng = ring::rand::SystemRandom::new();
            let server_kp = X25519KeyPair::generate(&rng).unwrap();
            let classical = server_kp.agree(&client_x25519).unwrap();
            let (ct, pq_ss) = Mlkem768::encapsulate(&client_mlkem_pk).unwrap();

            // ServerHello: key_share group 11ec, share = ct(1088) || pub(32).
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
            // Go wire order: ct (1088) first, X25519 pub (32) last.
            kse.extend_from_slice(ct.as_bytes());
            kse.extend_from_slice(&server_kp.public_key());
            // ext_list_len first, then extensions in order:
            // supported_versions (6 bytes) + key_share (kse).
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

            // Key schedule over `pq || classical` — the Go hybrid contract.
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

            // Encrypted flight with a REAL server Finished MAC.
            let ee_msg = make_hs_msg(HS_ENCRYPTED_EXTENSIONS, &[0x00, 0x00]);
            let cert_msg = make_hs_msg(
                HS_CERTIFICATE,
                &[
                    0x00, // no certificate_request_context
                    0x00, 0x00, 0x08, // certificate_list length
                    0x00, 0x00, 0x03, 0x30, 0x01, 0xAA, 0x00, 0x00, // one entry
                ],
            );
            let mut cv_body = Vec::new();
            cv_body.extend_from_slice(&0x0403u16.to_be_bytes()); // ecdsa_secp256r1_sha256
            cv_body.extend_from_slice(&0x0040u16.to_be_bytes());
            cv_body.extend_from_slice(&[0xAA; 64]);
            let cv_msg = make_hs_msg(HS_CERTIFICATE_VERIFY, &cv_body);
            sk.add_transcript(&ee_msg);
            sk.add_transcript(&cert_msg);
            sk.add_transcript(&cv_msg);
            let sf_key = sk.finished_key(&server_hs_ts[..32]).unwrap();
            let sf_wire = make_hs_msg(HS_FINISHED, &sk.finished_mac(&sf_key[..32]));
            let mut flight = Vec::new();
            flight.extend_from_slice(&ee_msg);
            flight.extend_from_slice(&cert_msg);
            flight.extend_from_slice(&cv_msg);
            flight.extend_from_slice(&sf_wire);
            sk.add_transcript(&sf_wire);
            write_encrypted_flight_chunk(&mut server_side, &server_hs_key, 0, &flight).await;

            // Client Finished record (seq 0 under the client hs key) — skip.
            let mut fin_hdr = [0u8; 5];
            server_side.read_exact(&mut fin_hdr).await.unwrap();
            let mut fin = vec![0u8; u16::from_be_bytes([fin_hdr[3], fin_hdr[4]]) as usize];
            server_side.read_exact(&mut fin).await.unwrap();
            let master = sk.master_secret(&hs_secret[..32]).unwrap();
            let (client_app_ts, server_app_ts) = sk.app_traffic_secrets(&master[..32]).unwrap();
            let client_app_key = AeadKey::new(suite, &client_app_ts[..32]).unwrap();
            let server_app_key = AeadKey::new(suite, &server_app_ts[..32]).unwrap();

            // App traffic secrets; decrypt and echo the client's ping.
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
            let rec_len =
                u16::try_from(inner.len() + AEAD_TAG_LEN).expect("test echo record fits u16");
            let aad = aead_aad(inner.len() + AEAD_TAG_LEN);
            let mut record = Vec::with_capacity(5 + inner.len() + AEAD_TAG_LEN);
            record.extend_from_slice(&[CONTENT_APPLICATION_DATA, 0x03, 0x03]);
            record.extend_from_slice(&rec_len.to_be_bytes());
            record.extend_from_slice(&inner);
            server_app_key
                .seal_in_place(0, &aad, &mut record, 5)
                .unwrap();
            server_side.write_all(&record).await.unwrap();
        });

        let rng = ring::rand::SystemRandom::new();
        let mut tls = connect(
            client_stream,
            HandshakeParams {
                spec: &spec,
                server_name: "localhost",
                alpn: None,
                verifier: &AcceptAll,
                rng: &rng,
            },
        )
        .await
        .unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap();
    }

    // ── TLS 1.2 interop (rustls server restricted to TLS 1.2) ────────────

    /// A spec offering both TLS 1.2 and 1.3 suites and versions — what a
    /// real browser sends, including the two extensions that change the
    /// TLS 1.2 wire flow: `extended_master_secret` (RFC 7627, empty body —
    /// changes the master-secret derivation) and `status_request` (which
    /// makes a stapling server insert `CertificateStatus` into the flight,
    /// so the transcript must hash messages the client does not interpret).
    fn tls12_spec() -> ClientHelloSpec {
        ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
            ],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![
                ExtensionSpec::ServerName,
                ExtensionSpec::Raw {
                    ty: 0x0017,
                    data: Vec::new(),
                },
                ExtensionSpec::SupportedGroups(vec![0x001D]),
                ExtensionSpec::KeyShare(vec![KeyShareGroup::X25519]),
                ExtensionSpec::SupportedVersions(vec![0x0304, 0x0303]),
                ExtensionSpec::SignatureAlgorithms(vec![
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                ]),
                ExtensionSpec::Alpn(vec!["h2".into(), "http/1.1".into()]),
                ExtensionSpec::StatusRequest,
                ExtensionSpec::EcPointFormats,
                ExtensionSpec::SessionTicket,
                ExtensionSpec::PskKeyExchangeModes,
            ],
        }
    }

    /// A rustls `ServerConfig` restricted to TLS 1.2 only.
    fn tls12_server_config(
        cert: &rcgen::Certificate,
        key: &rcgen::KeyPair,
    ) -> rustls::ServerConfig {
        tls12_server_config_with(cert, key, None, false)
    }

    /// A TLS-1.2-only rustls server, optionally restricted to a single
    /// cipher suite and optionally issuing session tickets.
    ///
    /// Both knobs exercise wire shapes the default config hides: a
    /// ChaCha20-Poly1305 suite uses the RFC 7905 nonce construction (12-byte
    /// implicit IV, no explicit nonce), and a ticketer makes the server send
    /// a PLAINTEXT `NewSessionTicket` before its `ChangeCipherSpec`.
    fn tls12_server_config_with(
        cert: &rcgen::Certificate,
        key: &rcgen::KeyPair,
        suite: Option<rustls::SupportedCipherSuite>,
        tickets: bool,
    ) -> rustls::ServerConfig {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut provider = rustls::crypto::ring::default_provider();
        if let Some(suite) = suite {
            provider.cipher_suites = vec![suite];
        }
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap();
        if tickets {
            cfg.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
        }
        cfg
    }

    /// Drive a rustls `ServerConnection` to completion over an async tokio
    /// stream, then echo the first 4 plaintext bytes back. Rustls is a
    /// push/pull API (feed bytes via `read_tls`, drain via `write_tls`), so
    /// the loop flushes output, reads input, and processes until the echo is
    /// written. This handles TLS 1.2's multi-round-trip handshake (`ClientHello`
    /// → flight → CKE → Finished) without blocking I/O.
    async fn rustls_server_echo(mut stream: tokio::net::TcpStream, conn: rustls::ServerConnection) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut conn = conn;
        let mut plain: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            // Flush any TLS output rustls has queued.
            let mut out = Vec::new();
            conn.write_tls(&mut out).unwrap();
            if !out.is_empty() {
                stream.write_all(&out).await.unwrap();
            }
            // The echo is the last thing this server does, so one shot is
            // enough — no "already echoed" state to track.
            if plain.len() >= 4 {
                let echo = plain[..4].to_vec();
                conn.writer().write_all(&echo).unwrap();
                let mut o2 = Vec::new();
                conn.write_tls(&mut o2).unwrap();
                if !o2.is_empty() {
                    stream.write_all(&o2).await.unwrap();
                }
                return;
            }
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                return;
            }
            conn.read_tls(&mut std::io::Cursor::new(&buf[..n])).unwrap();
            let state = conn.process_new_packets().unwrap();
            if state.plaintext_bytes_to_read() > 0 {
                let mut p = vec![0u8; state.plaintext_bytes_to_read()];
                conn.reader().read_exact(&mut p).unwrap();
                plain.extend_from_slice(&p);
            }
        }
    }

    /// The engine's TLS 1.2 client must complete a full handshake against a
    /// real rustls TLS-1.2-only server and round-trip application bytes.
    /// This exercises the TLS 1.2 PRF, key block, AEAD record layer, and
    /// Finished verification end-to-end.
    #[tokio::test]
    async fn tls12_handshake_completes_against_rustls_server() {
        // rcgen defaults to an ECDSA P-256 key, so rustls selects
        // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B) with an
        // ecdsa_secp256r1_sha256 ServerKeyExchange signature.
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let cfg = tls12_server_config(&certified.cert, &certified.signing_key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            rustls_server_echo(stream, conn).await;
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let rng = ring::rand::SystemRandom::new();
        let mut tls = connect(
            stream,
            HandshakeParams {
                spec: &tls12_spec(),
                server_name: "localhost",
                alpn: Some(&[b"http/1.1"]),
                verifier: &AcceptAll,
                rng: &rng,
            },
        )
        .await
        .unwrap();

        tls.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap();
    }

    /// TLS 1.2 with real certificate verification: the `WebPkiVerifier` must
    /// validate the chain AND the `ServerKeyExchange` ECDSA signature (an
    /// actual rustls ECDSA P-256 signature over
    /// `client_random || server_random || ServerECDHParams`). This fails if
    /// the TLS 1.2 signature path is wrong.
    #[tokio::test]
    async fn tls12_handshake_verifies_server_signature() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let cfg = tls12_server_config(&certified.cert, &certified.signing_key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            rustls_server_echo(stream, conn).await;
        });

        // Trust the self-signed cert as a root: chain + SKE signature check.
        let verifier = WebPkiVerifier::from_ca_der(certified.cert.der()).unwrap();
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let rng = ring::rand::SystemRandom::new();
        let mut tls = connect(
            stream,
            HandshakeParams {
                spec: &tls12_spec(),
                server_name: "localhost",
                alpn: Some(&[b"http/1.1"]),
                verifier: &verifier,
                rng: &rng,
            },
        )
        .await
        .unwrap();

        tls.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap();
    }

    /// A TLS-1.2-only rustls server restricted to one key-exchange group: the
    /// knob that makes the server pick a curve the client did not put first.
    fn tls12_server_config_kx(
        cert: &rcgen::Certificate,
        key: &rcgen::KeyPair,
        kx_groups: &[&'static dyn rustls::crypto::SupportedKxGroup],
    ) -> rustls::ServerConfig {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = kx_groups.to_vec();
        rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap()
    }

    /// RFC 4492 ECDHE with secp256r1: a server that offers only P-256 is common
    /// among TLS-1.2-only hosts, and the engine's X25519-only SKE path aborted
    /// with "unsupported named curve 0x0017" where OpenSSL completed the
    /// handshake (reproduced live 2026-09-15; see `parse_ske`). The server here
    /// offers P-256 alone, so the round trip can only complete through the
    /// P-256 agreement.
    #[tokio::test]
    async fn tls12_secp256r1_server_key_exchange() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let cfg = tls12_server_config_kx(
            &certified.cert,
            &certified.signing_key,
            &[rustls::crypto::ring::kx_group::SECP256R1],
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            rustls_server_echo(stream, conn).await;
        });

        // X25519 first, P-256 second — the server's own preference decides.
        let mut spec = tls12_spec();
        for ext in &mut spec.extensions {
            if let ExtensionSpec::SupportedGroups(groups) = ext {
                *groups = vec![0x001D, 0x0017];
            }
        }

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let rng = ring::rand::SystemRandom::new();
        let mut tls = connect(
            stream,
            HandshakeParams {
                spec: &spec,
                server_name: "localhost",
                alpn: Some(&[b"http/1.1"]),
                verifier: &AcceptAll,
                rng: &rng,
            },
        )
        .await
        .unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap();
    }

    /// Run one TLS 1.2 echo handshake against a rustls server built with
    /// `suite`/`tickets`, returning nothing but panicking on any failure.
    async fn tls12_echo_roundtrip(suite: Option<rustls::SupportedCipherSuite>, tickets: bool) {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let cfg = tls12_server_config_with(&certified.cert, &certified.signing_key, suite, tickets);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            rustls_server_echo(stream, conn).await;
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let rng = ring::rand::SystemRandom::new();
        let mut tls = connect(
            stream,
            HandshakeParams {
                spec: &tls12_spec(),
                server_name: "localhost",
                alpn: Some(&[b"http/1.1"]),
                verifier: &AcceptAll,
                rng: &rng,
            },
        )
        .await
        .unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap();
    }

    /// RFC 7905: the ChaCha20-Poly1305 suites carry a 12-byte implicit IV
    /// and NO explicit per-record nonce. Modelling them like AES-GCM
    /// (explicit nonce, no IV) derives a short key block and prefixes every
    /// record with 12 bytes the peer reads as ciphertext, so this handshake
    /// is the regression test for the nonce geometry.
    #[tokio::test]
    async fn tls12_chacha20_poly1305_roundtrip() {
        tls12_echo_roundtrip(
            Some(rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
            false,
        )
        .await;
    }

    /// RFC 5077 §3.3: in TLS 1.2 `NewSessionTicket` is a PLAINTEXT handshake
    /// record sent BEFORE the server's `ChangeCipherSpec`, and it is covered
    /// by both `Finished` MACs. Treating it as the encrypted Finished (or
    /// omitting it from the transcript) breaks the handshake against any
    /// ticket-issuing server — the default for nginx and most CDNs.
    #[tokio::test]
    async fn tls12_handshake_with_session_ticket() {
        tls12_echo_roundtrip(None, true).await;
    }

    /// RFC 8446 §4.1.3: a `ServerHello` that negotiates TLS 1.2 while carrying
    /// the `DOWNGRD` sentinel in the last 8 bytes of its random means a
    /// TLS 1.3-capable server was forced down; the client must abort.
    #[test]
    fn tls12_downgrade_sentinel_is_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        let mut random = [0x11u8; 32];
        random[24..].copy_from_slice(b"DOWNGRD\x01");
        body.extend_from_slice(&random);
        body.push(0); // empty session id
        body.extend_from_slice(&0xc02bu16.to_be_bytes()); // ECDHE_ECDSA_AES128_GCM
        body.push(0); // null compression
        body.extend_from_slice(&0u16.to_be_bytes()); // no extensions
        let err = parse_sh(&body, &[]).unwrap_err();
        assert!(
            matches!(&err, TlsError::Handshake(m) if m.contains("downgrade sentinel")),
            "expected downgrade rejection, got {err:?}"
        );
    }

    /// RFC 7627 §5.1: the `ServerHello` `extended_master_secret` body is empty
    /// and its mere presence is the acknowledgement. Requiring a non-empty
    /// body silently selects the legacy master secret and breaks every
    /// handshake with a conforming server.
    #[test]
    fn empty_extended_master_secret_extension_is_an_ack() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x22u8; 32]);
        body.push(0);
        body.extend_from_slice(&0xc02bu16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&4u16.to_be_bytes()); // one empty extension
        body.extend_from_slice(&0x0017u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        let parsed = parse_sh(&body, &[]).unwrap();
        assert_eq!(parsed.version, TlsVersion::Tls12);
        assert!(parsed.ems, "empty EMS extension must be read as an ack");
    }

    /// A server signature scheme the `ClientHello` never offered must be
    /// refused (RFC 5246 §7.4.3, RFC 8446 §4.4.3).
    #[test]
    fn unoffered_signature_scheme_is_rejected() {
        let rng = ring::rand::SystemRandom::new();
        let hello = build_hello(
            &tls12_spec(),
            &BuildParams {
                server_name: "localhost",
                alpn: None,
                x25519_pub: &[0x33u8; 32],
                mlkem768_pub: None,
                rng: &rng,
            },
        )
        .unwrap();
        // 0x0403 is in tls12_spec's signature_algorithms; 0x0203 (SHA-1) is not.
        ensure_offered_sigalg(&hello.handshake_bytes, 0x0403).unwrap();
        assert!(ensure_offered_sigalg(&hello.handshake_bytes, 0x0203).is_err());
    }
}
