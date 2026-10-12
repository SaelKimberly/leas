//! TLS 1.3 client handshake (plain TLS, verifier seam).
//!
//! Port of `thirdparty/tls-fingerprint/src/handshake.rs`, adapted to the
//! crate's seams: the stream is generic (`AsyncRead + AsyncWrite + Unpin +
//! Send`), the key schedule carries its own transcript (crypto Task 5),
//! record reads go through `record::skip_ccs` (record Task 6), and the
//! established connection is a [`TlsStream`] (record Task 7). The two
//! deliberate Task-8 additions over the reference are:
//!
//! - **HRR detection** — a `ServerHello` whose random is the RFC 8446 §4.1.4
//!   magic value is reported as [`TlsError::HelloRetryRequest`] instead of
//!   being misparsed as a missing `key_share`.
//! - **Verifier seam** — the certificate chain, the `CertificateVerify`
//!   signature scheme and raw body, and the transcript up to (excluding) the
//!   `CertificateVerify` are handed to [`ServerVerifier::verify`] before the
//!   handshake continues. Task 9 implements the real
//!   `WebPKI` verifier; [`AcceptAll`] is the test-only seam.
//!
//! Transcript accumulation follows the reference exactly: every raw
//! handshake message (`ClientHello` through `Finished`) is appended in wire
//! order; the client `Finished` and the application traffic secrets are
//! derived over `ClientHello..server Finished` (RFC 8446 §4.4.4, §7.1).

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub mod tls12;

use crate::SecureRandom;
use crate::crypto::mlkem::{Ciphertext, Mlkem768, SecretKey as MlkemSecretKey};
use crate::crypto::{AeadKey, CipherSuiteId, KeySchedule, X25519KeyPair, tls12::Tls12Suite};
use crate::error::{Result, TlsError};
use crate::hello::{BuildParams, build_hello, to_record};
use crate::record::stream::{AppKeys, TlsStream};
use crate::record::{
    CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY,
    HS_COMPRESSED_CERTIFICATE, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_SERVER_HELLO,
    MAX_RECORD_PAYLOAD, aead_aad, parse_handshake_messages, skip_ccs,
};
use crate::spec::{ClientHelloSpec, ExtensionSpec, KeyShareGroup};

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
    /// The data covered by the signature: for TLS 1.3, the transcript
    /// up to (excluding) `CertificateVerify`; for TLS 1.2, the raw
    /// `client_random || server_random || ServerECDHParams`.
    pub signed_data: &'a [u8],
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
    /// ALPN protocols to offer; `None` uses the spec's own list.
    pub alpn: Option<&'a [&'a str]>,
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

/// Performs the shared TLS 1.3 client handshake over `stream`: writes the
/// `ClientHello` record, reads the `ServerHello` (skipping middlebox CCS
/// records; a `HelloRetryRequest` magic random is rejected with
/// [`TlsError::HelloRetryRequest`]), derives the handshake traffic secrets
/// with the *selected* suite, decrypts the server flight
/// (`EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`),
/// dispatches [`ServerAuth`], authenticates the server `Finished` MAC, sends
/// the client `Finished` (sealed with the client handshake key), derives the
/// application traffic secrets, and builds the [`TlsStream`].
///
/// The `transcript` (`ClientHello .. Certificate`) is consumed only by the
/// auth dispatch — the key schedule carries its own transcript
/// (`KeySchedule::add_transcript`) for the `Finished` MACs and app secrets.
/// `offered_session_id` must be the legacy session id of `hello`; the
/// `offered_session_id` must be the legacy session id of `hello`; the
/// server's `ServerHello` must echo it exactly (RFC 8446 §4.1.3).
pub(crate) async fn drive<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    hello: &[u8],
    offered_session_id: &[u8],
    keypair: X25519KeyPair,
    // ML-KEM-768 secret key when the ClientHello offered a hybrid key
    // share; decapsulation runs only if the server actually selected the
    // hybrid group (its `key_share` then carries the ciphertext).
    mlkem_sk: Option<&MlkemSecretKey>,
    server_name: &str,
    // RFC 8879 `compress_certificate` algorithms the ClientHello offered
    // (0x0001 zlib, 0x0002 brotli, 0x0003 zstd). Empty when the hello
    // advertised none; the server then must not compress its Certificate.
    offered_compress: &[u16],
    auth: ServerAuth<'_>,
) -> Result<(TlsStream<S>, AuthOutcome)> {
    let mut stream = stream;
    stream.write_all(&to_record(hello)).await?;

    let mut server_hello = read_server_hello(&mut stream, offered_session_id).await?;
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
                let client_random: [u8; 32] = hello[6..38].try_into().expect("32 bytes");
                let pre_buffer = std::mem::take(&mut server_hello.pre_buffer);
                return tls12::drive12(
                    stream,
                    hello,
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
    let shared: Zeroizing<Vec<u8>> = match (mlkem_sk, server_hello.mlkem_ciphertext.as_ref()) {
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
    ks.add_transcript(hello);
    ks.add_transcript(&server_hello.raw);
    let hs_secret = ks.handshake_secret(&shared)?;
    let (client_hs_ts, server_hs_ts) = ks.handshake_traffic_secrets(&hs_secret[..hash_len])?;
    let server_hs_key = AeadKey::new(server_hello.suite, &server_hs_ts[..hash_len])?;
    let client_hs_key = AeadKey::new(server_hello.suite, &client_hs_ts[..hash_len])?;

    let flight = read_server_hs_messages(&mut stream, &server_hs_key, offered_compress).await?;

    // The key schedule already accumulates `ClientHello .. Certificate`
    // verbatim — feeding it here (before the auth dispatch) makes its
    // arena the single transcript copy; the verifier below borrows it
    // instead of a second `hello + sh + ee + cert` buffer. Ordering is
    // unchanged (`ee, cert, cv, server Finished`), so the Finished MACs
    // and app secrets derive exactly as before (RFC 8446 §4.4.4, §7.1).
    ks.add_transcript(&flight.ee_raw);
    ks.add_transcript(&flight.cert_raw);
    // Transcript up to (excluding) CertificateVerify — consumed only by the
    // auth dispatch below (RFC 8446 §4.4.3).
    let transcript = ks.transcript_bytes();

    let outcome = match auth {
        ServerAuth::Verifier(verifier) => {
            // `CertificateVerify` body = scheme(2) || sig_len(2) || sig. The
            // flight reader tolerates a missing CertificateVerify (empty
            // body), so slice fallibly: an on-path party that completes the
            // unauthenticated ECDH could otherwise panic the record loop.
            let signature = flight.cert_verify_body.get(4..).ok_or_else(|| {
                TlsError::Verify("server sent no CertificateVerify signature".into())
            })?;
            ensure_offered_sigalg(hello, flight.signature_scheme)?;
            verifier.verify(&VerifyContext {
                chain: &flight.chain,
                sni: server_name,
                version: TlsVersion::Tls13,
                suite: server_hello.suite,
                signature_scheme: flight.signature_scheme,
                signature,
                signed_data: transcript,
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
                transcript,
                server_hello.suite.digest(),
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

    let hello = build_hello(
        params.spec,
        &BuildParams {
            server_name: params.server_name,
            alpn: params.alpn,
            x25519_pub: &x25519_pub,
            mlkem768_pub: mlkem
                .0
                .as_ref()
                .map(crate::crypto::mlkem::PublicKey::as_bytes),
            rng: params.rng,
        },
    )?;
    let offered_compress: Vec<u16> = params
        .spec
        .extensions
        .iter()
        .find_map(|ext| match ext {
            ExtensionSpec::CompressCertificate(algs) => Some(algs.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let (tls, _) = drive(
        stream,
        &hello.handshake_bytes,
        hello.session_id(),
        keypair,
        mlkem.1.as_ref(),
        params.server_name,
        &offered_compress,
        ServerAuth::Verifier(params.verifier),
    )
    .await?;
    Ok(tls)
}

// ── ServerHello ────────────────────────────────────────────────────────────

/// A parsed `ServerHello` — carries fields for both TLS 1.3 and 1.2.
pub(crate) struct ServerHelloData {
    /// The raw handshake message (type + length + body), for the transcript.
    pub(crate) raw: Vec<u8>,
    /// Handshake bytes after the `ServerHello` in the same record (valid in
    /// TLS 1.2, RFC 5246 §6.2.1 — a server may pack `ServerHello` + the rest
    /// of the flight into one record). Consumed by the TLS 1.2 flight
    /// reader; empty for TLS 1.3 (`ServerHello` is always alone).
    pub(crate) pre_buffer: Vec<u8>,
    /// The negotiated version.
    pub(crate) version: TlsVersion,
    /// The server's 32-byte random.
    pub(crate) server_random: [u8; 32],
    /// The server's classical (X25519) public key from `key_share` (TLS 1.3).
    pub(crate) peer_key: Option<[u8; 32]>,
    /// The ML-KEM ciphertext from the server's hybrid key share (TLS 1.3),
    /// validated at parse so the handshake decapsulates it with no re-copy.
    pub(crate) mlkem_ciphertext: Option<Ciphertext>,
    /// The cipher suite the server selected (TLS 1.3).
    pub(crate) suite: CipherSuiteId,
    /// The cipher suite the server selected (TLS 1.2).
    pub(crate) suite12: Option<Tls12Suite>,
    /// Whether the server echoed `extended_master_secret` (TLS 1.2).
    pub(crate) ems: bool,
}

/// The `ServerHello` body fields the engine needs.
#[derive(Debug)]
struct ParsedServerHello {
    version: TlsVersion,
    server_random: [u8; 32],
    suite: CipherSuiteId,
    suite12: Option<Tls12Suite>,
    peer_key: Option<[u8; 32]>,
    mlkem_ciphertext: Option<Ciphertext>,
    ems: bool,
}

/// Read and parse the `ServerHello` record, skipping CCS records. The
/// server must echo the offered legacy session id (RFC 8446 §4.1.3).
pub(crate) async fn read_server_hello<S>(
    stream: &mut S,
    offered_session_id: &[u8],
) -> Result<ServerHelloData>
where
    S: AsyncRead + Unpin,
{
    let rec = skip_ccs(stream).await?;
    if rec.content_type != CONTENT_HANDSHAKE {
        return Err(TlsError::Handshake(format!(
            "expected Handshake record (0x16), got 0x{:02X}",
            rec.content_type
        )));
    }
    let (parsed, first_total) = {
        let msgs = parse_handshake_messages(&rec.payload)?;
        let (msg_type, body) = msgs
            .into_iter()
            .next()
            .ok_or_else(|| TlsError::Handshake("empty record for ServerHello".into()))?;
        if msg_type != HS_SERVER_HELLO {
            return Err(TlsError::Handshake(format!(
                "expected ServerHello (0x02), got 0x{msg_type:02X}"
            )));
        }
        let parsed = parse_server_hello(body, offered_session_id)?;
        // TLS 1.2 may pack subsequent handshake messages after the
        // ServerHello in the same record; preserve those bytes for the
        // flight reader.
        (parsed, 4 + body.len())
    };
    let mut payload = rec.payload;
    let raw = payload[..first_total].to_vec();
    let pre_buffer = payload.split_off(first_total);
    Ok(ServerHelloData {
        raw,
        pre_buffer,
        version: parsed.version,
        server_random: parsed.server_random,
        peer_key: parsed.peer_key,
        mlkem_ciphertext: parsed.mlkem_ciphertext,
        suite: parsed.suite,
        suite12: parsed.suite12,
        ems: parsed.ems,
    })
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
fn parse_server_hello(body: &[u8], offered_session_id: &[u8]) -> Result<ParsedServerHello> {
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

    // Determine version from the supported_versions extension.
    if has_supported_versions && version_negotiated == 0x0304 {
        // TLS 1.3: verify the HRR magic and enforce session-id echo.
        if server_random == HRR_RANDOM {
            return Err(TlsError::HelloRetryRequest);
        }
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
        return Ok(ParsedServerHello {
            version: TlsVersion::Tls13,
            server_random,
            suite,
            suite12: None,
            peer_key: Some(peer_key),
            mlkem_ciphertext,
            ems: false,
        });
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
    Ok(ParsedServerHello {
        version: TlsVersion::Tls12,
        server_random,
        suite: CipherSuiteId::Aes128GcmSha256, // placeholder, unused for 1.2
        suite12: Some(suite12),
        peer_key: None,
        mlkem_ciphertext: None,
        ems,
    })
}

// ── Encrypted server flight ────────────────────────────────────────────────

/// The parsed server flight: raw messages for the transcript plus the values
/// the verifier seam and client `Finished` need.
pub(crate) struct ServerFlight {
    pub(crate) ee_raw: Vec<u8>,
    pub(crate) cert_raw: Vec<u8>,
    pub(crate) cv_raw: Vec<u8>,
    pub(crate) sf_verify_data: Vec<u8>,
    /// DER certificates, leaf first.
    pub(crate) chain: Vec<Vec<u8>>,
    /// The `signature_scheme` from `CertificateVerify`.
    signature_scheme: u16,
    /// The raw `CertificateVerify` body (scheme + signature).
    cert_verify_body: Vec<u8>,
}

/// Read and decrypt the encrypted server handshake records
/// (`EncryptedExtensions` … `Finished`) with `server_hs_key`, sequencing
/// from zero.
///
/// RFC 8446 §5.1 allows a handshake message to span records (rustls
/// fragments plaintext at 16 KiB, so a certificate chain larger than one
/// record is split) and a single record to carry several complete messages.
/// Decrypted plaintext is therefore accumulated into a buffer and each
/// message is consumed only once its full `type(1) || length(3) || body` is
/// present; a record may hold a partial message, several complete messages,
/// or a message continuing into the next record.
pub(crate) async fn read_server_hs_messages<S>(
    stream: &mut S,
    server_hs_key: &AeadKey,
    // RFC 8879 `compress_certificate` algorithms the ClientHello offered.
    offered_compress: &[u16],
) -> Result<ServerFlight>
where
    S: AsyncRead + Unpin,
{
    let mut ee_raw: Option<Vec<u8>> = None;
    let mut cert_raw: Option<Vec<u8>> = None;
    let mut cv_raw: Option<Vec<u8>> = None;
    let mut finished_data: Option<Vec<u8>> = None;
    let mut chain: Option<Vec<Vec<u8>>> = None;
    let mut signature_scheme = 0u16;
    let mut cert_verify_body = Vec::new();
    let mut seq = 0u64;
    // The reassembly buffer is pre-sized to one full record (like
    // `TlsStream::rec_buf`): single-record flights never regrow it, and
    // multi-record flights amortize into the same allocation.
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_RECORD_PAYLOAD);

    loop {
        // Consume every complete handshake message buffered so far.
        let mut consumed = 0usize;
        while buf.len() >= consumed + 4 {
            let msg_len = u24(&buf[consumed + 1..consumed + 4]);
            let total = 4 + msg_len;
            if buf.len() < consumed + total {
                break; // body incomplete — wait for the next record
            }
            let msg_type = buf[consumed];
            // One copy: the raw message already sits contiguous in `buf`
            // (`type || len || body`), so slice it out directly instead of
            // copying the body and re-encoding the header.
            let raw = buf[consumed..consumed + total].to_vec();
            let body = &raw[4..];
            consumed += total;
            match msg_type {
                HS_ENCRYPTED_EXTENSIONS => {
                    parse_encrypted_extensions(body)?;
                    ee_raw = Some(raw);
                }
                HS_CERTIFICATE => {
                    chain = Some(parse_certificate_message(body)?);
                    cert_raw = Some(raw);
                }
                HS_COMPRESSED_CERTIFICATE => {
                    // RFC 8879 §4: the compressed Certificate replaces the
                    // plain one; the decompressed payload is the Certificate
                    // BODY (rustls parses it the same way — no 4-byte
                    // handshake header inside).
                    let cert_body = decompress_certificate_message(body, offered_compress)?;
                    chain = Some(parse_certificate_message(&cert_body)?);
                    // The transcript carries the message AS SENT: the server
                    // hashed the `CompressedCertificate`, not a re-built
                    // `Certificate` (hashing a rebuilt one fails its Finished
                    // MAC — verified against Cloudflare's edge).
                    cert_raw = Some(raw);
                }
                HS_CERTIFICATE_VERIFY => {
                    signature_scheme = parse_certificate_verify(body)?;
                    cert_verify_body = body.to_vec();
                    cv_raw = Some(raw);
                }
                HS_FINISHED => finished_data = Some(body.to_vec()),
                _ => {} // unknown handshake messages are skipped
            }

            if finished_data.is_some() {
                // The server flight ends with Finished; any later messages
                // (e.g. NewSessionTicket) are not part of the flight, and a
                // buffered remainder is intentionally left unconsumed.
                return Ok(ServerFlight {
                    ee_raw: ee_raw
                        .ok_or_else(|| TlsError::Handshake("missing EncryptedExtensions".into()))?,
                    cert_raw: cert_raw.unwrap_or_else(|| make_hs_msg(HS_CERTIFICATE, &[])),
                    cv_raw: cv_raw.unwrap_or_else(|| make_hs_msg(HS_CERTIFICATE_VERIFY, &[])),
                    sf_verify_data: finished_data
                        .ok_or_else(|| TlsError::Handshake("missing server Finished".into()))?,
                    chain: chain.unwrap_or_default(),
                    signature_scheme,
                    cert_verify_body,
                });
            }
        }
        buf.drain(..consumed);

        let rec = skip_ccs(stream).await?;
        if rec.content_type != CONTENT_APPLICATION_DATA {
            return Err(TlsError::Handshake(format!(
                "expected encrypted record (0x17), got 0x{:02X}",
                rec.content_type
            )));
        }

        let aad = aead_aad(rec.payload.len());
        let mut payload = rec.payload;
        let plain_len = server_hs_key.open_in_place(seq, &aad, &mut payload)?;
        seq += 1;

        let (content_type, hs_data) = strip_padding(&payload[..plain_len])?;
        if content_type != CONTENT_HANDSHAKE {
            continue;
        }
        if buf.len() + hs_data.len() > MAX_FLIGHT_BUFFER {
            return Err(TlsError::Handshake(
                "server flight exceeds the 16 MiB reassembly bound".into(),
            ));
        }
        buf.extend_from_slice(hs_data);
    }
}

/// Parse an `EncryptedExtensions` body:
/// `ext_list_len(2) || extensions`.
///
/// The `supported_versions` extension (when present) must be TLS 1.3, and
/// the ALPN extension must be well-formed; neither value has a consumer in
/// the Task-8 seams yet, so both are validated and discarded.
fn parse_encrypted_extensions(body: &[u8]) -> Result<()> {
    if body.len() < 2 {
        return Err(TlsError::Handshake("EncryptedExtensions too short".into()));
    }
    let ext_list_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let ext_end = 2 + ext_list_len;
    if ext_end > body.len() {
        return Err(TlsError::Handshake("EncryptedExtensions truncated".into()));
    }
    let mut pos = 2;
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([body[pos + 2], body[pos + 3]]));
        pos += 4;
        if pos + ext_len > ext_end {
            return Err(TlsError::Handshake(
                "EncryptedExtensions extension overruns list".into(),
            ));
        }
        let ext_data = &body[pos..pos + ext_len];
        pos += ext_len;
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                // uint8 length (always 2) || uint16 version.
                if ext_data.len() != 3 || usize::from(ext_data[0]) != 2 {
                    return Err(TlsError::Handshake(
                        "malformed supported_versions in EncryptedExtensions".into(),
                    ));
                }
                let version = u16::from_be_bytes([ext_data[1], ext_data[2]]);
                if version != 0x0304 {
                    return Err(TlsError::Handshake(format!(
                        "server negotiated TLS version 0x{version:04X}, expected 0x0304"
                    )));
                }
            }
            EXT_ALPN => {
                // uint16 list length || (uint8 len || protocol)*.
                if ext_data.len() < 2 {
                    return Err(TlsError::Handshake(
                        "malformed ALPN in EncryptedExtensions".into(),
                    ));
                }
                let list_len = usize::from(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                if ext_data.len() != 2 + list_len {
                    return Err(TlsError::Handshake(
                        "ALPN protocol list length mismatch".into(),
                    ));
                }
                let mut p = 2;
                while p < ext_data.len() {
                    let proto_len = usize::from(ext_data[p]);
                    p += 1;
                    if p + proto_len > ext_data.len() {
                        return Err(TlsError::Handshake(
                            "ALPN protocol entry overruns list".into(),
                        ));
                    }
                    p += proto_len;
                }
            }
            _ => {}
        }
    }
    if pos != ext_end {
        return Err(TlsError::Handshake(
            "trailing garbage in EncryptedExtensions extension list".into(),
        ));
    }
    Ok(())
}

/// Parse a `Certificate` body:
/// `cert_req_ctx_len(1) || ctx || certificate_list_len(3) || certificate_list`.
///
/// Each list entry is `cert_data_len(3) || cert_data || extensions_len(2) ||
/// extensions`; returns the DER chain, leaf first. This is the body of a
/// `Certificate` message (or of the payload a `CompressedCertificate`
/// decompressed to — RFC 8879 §4 compresses this very body, so there is no
/// per-entry compression to undo here).
fn parse_certificate_message(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    if body.len() < 4 {
        return Err(TlsError::Handshake("Certificate message too short".into()));
    }
    let ctx_len = usize::from(body[0]);
    let mut pos = 1 + ctx_len;
    if pos + 3 > body.len() {
        return Err(TlsError::Handshake(
            "Certificate list length truncated".into(),
        ));
    }
    let list_len = u24(&body[pos..pos + 3]);
    pos += 3;
    let list_end = pos + list_len;
    if list_end > body.len() {
        return Err(TlsError::Handshake("Certificate list truncated".into()));
    }

    let mut chain = Vec::new();
    while pos < list_end {
        if pos + 3 > list_end {
            return Err(TlsError::Handshake(
                "certificate entry length truncated".into(),
            ));
        }
        let cert_len = u24(&body[pos..pos + 3]);
        pos += 3;
        if pos + cert_len > list_end {
            return Err(TlsError::Handshake("certificate data truncated".into()));
        }
        chain.push(body[pos..pos + cert_len].to_vec());
        pos += cert_len;
        if pos + 2 > list_end {
            return Err(TlsError::Handshake(
                "certificate extensions length truncated".into(),
            ));
        }
        let ext_len = usize::from(u16::from_be_bytes([body[pos], body[pos + 1]]));
        pos += 2 + ext_len;
        if pos > list_end {
            return Err(TlsError::Handshake(
                "certificate extensions overrun list".into(),
            ));
        }
    }
    Ok(chain)
}

/// Decompress one RFC 8879 `CompressedCertificate` payload.
///
/// `offered` is the `ClientHello`'s `compress_certificate` algorithm list (RFC
/// 8879 §7.3: 1 zlib, 2 brotli, 3 zstd); a server that selects anything else
/// is misbehaving and the message is rejected, as rustls does with
/// `bad_certificate`. Decompression is bounded ([`MAX_CERT_BYTES`]): a
/// server-supplied blob may not expand without limit.
fn decompress_certificate_message(body: &[u8], offered: &[u16]) -> Result<Vec<u8>> {
    // algorithm(2) || uncompressed_length(3) || compressed<1..2^24-1>
    if body.len() < 8 {
        return Err(TlsError::Handshake(
            "CompressedCertificate too short".into(),
        ));
    }
    let algorithm = u16::from_be_bytes([body[0], body[1]]);
    let uncompressed_len = u24(&body[2..5]);
    let compressed_len = u24(&body[5..8]);
    if body.len() != 8 + compressed_len {
        return Err(TlsError::Handshake(format!(
            "CompressedCertificate declares {compressed_len} compressed bytes, got {}",
            body.len() - 8
        )));
    }
    if !offered.contains(&algorithm) {
        return Err(TlsError::Handshake(format!(
            "server compressed the Certificate with algorithm 0x{algorithm:04X}, which the \
             ClientHello did not offer"
        )));
    }
    let data = &body[8..];
    let decompressed = match algorithm {
        0x0001 => decompress_bounded(flate2::read::ZlibDecoder::new(data))?,
        0x0002 => decompress_bounded(brotli::Decompressor::new(data, 4096))?,
        0x0003 => match zstd::stream::read::Decoder::new(data) {
            Ok(decoder) => decompress_bounded(decoder)?,
            Err(_) => None,
        },
        _ => None,
    }
    .ok_or_else(|| {
        TlsError::Handshake(format!(
            "CompressedCertificate algorithm 0x{algorithm:04X} did not decode"
        ))
    })?;
    if decompressed.len() != uncompressed_len {
        return Err(TlsError::Handshake(format!(
            "CompressedCertificate declares {uncompressed_len} uncompressed bytes, got {}",
            decompressed.len()
        )));
    }
    Ok(decompressed)
}

/// Maximum decompressed size of one RFC 8879 Certificate payload.
const MAX_CERT_BYTES: u64 = 1 << 20;

/// Decompress `reader` into at most [`MAX_CERT_BYTES`] bytes.
///
/// `Ok(None)` when the input is not a valid stream for the selected
/// algorithm; `Err` when the stream inflates past the bound (decompression
/// bomb).
fn decompress_bounded<R: std::io::Read>(mut reader: R) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let mut out = Vec::new();
    if reader
        .by_ref()
        .take(MAX_CERT_BYTES + 1)
        .read_to_end(&mut out)
        .is_err()
    {
        return Ok(None);
    }
    if out.len() as u64 > MAX_CERT_BYTES {
        return Err(TlsError::Handshake(
            "certificate decompression exceeds the 1 MiB bound (decompression bomb)".into(),
        ));
    }
    Ok(Some(out))
}

/// Parse a `CertificateVerify` body: `signature_scheme(2) ||
/// signature_len(2) || signature`; returns the signature scheme.
fn parse_certificate_verify(body: &[u8]) -> Result<u16> {
    if body.len() < 4 {
        return Err(TlsError::Handshake("CertificateVerify too short".into()));
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = usize::from(u16::from_be_bytes([body[2], body[3]]));
    if body.len() != 4 + sig_len {
        return Err(TlsError::Handshake(
            "CertificateVerify signature length mismatch".into(),
        ));
    }
    Ok(scheme)
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
        HS_SERVER_HELLO, HandshakeParams, TlsVersion, connect, decompress_bounded,
        decompress_certificate_message, ensure_offered_sigalg, make_hs_msg,
        parse_certificate_message, parse_certificate_verify, parse_encrypted_extensions,
        parse_server_hello, read_server_hs_messages,
    };
    use crate::crypto::{AeadKey, CipherSuiteId, KeySchedule};
    use crate::error::TlsError;
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
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap()
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
                alpn: Some(&["http/1.1"]),
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

    // ── HRR detection ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn server_hello_with_hrr_magic_is_rejected() {
        let (client_stream, mut server_side) = tokio::io::duplex(8192);

        // A minimal HRR ServerHello: magic random, no extensions (a real HRR
        // carries no key_share for the rejected group).
        let mut body = Vec::with_capacity(40);
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&HRR_RANDOM);
        body.push(0); // session id length
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0); // compression method
        // supported_versions = 0x0304 (a real HRR carries this)
        body.extend_from_slice(&0x0006u16.to_be_bytes()); // list length 6
        body.extend_from_slice(&0x002bu16.to_be_bytes());
        body.extend_from_slice(&0x0002u16.to_be_bytes());
        body.extend_from_slice(&0x0304u16.to_be_bytes());
        let mut sh_msg = vec![HS_SERVER_HELLO];
        let len = u32::try_from(body.len()).unwrap();
        sh_msg.extend_from_slice(&len.to_be_bytes()[1..]);
        sh_msg.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&u16::try_from(sh_msg.len()).unwrap().to_be_bytes());
        rec.extend_from_slice(&sh_msg);
        server_side.write_all(&rec).await.unwrap();

        let rng = ring::rand::SystemRandom::new();
        let result = connect(
            client_stream,
            HandshakeParams {
                spec: &test_spec(),
                server_name: "localhost",
                alpn: None,
                verifier: &AcceptAll,
                rng: &rng,
            },
        )
        .await;
        match result {
            Err(TlsError::HelloRetryRequest) => {}
            Err(e) => panic!("expected HelloRetryRequest, got {e:?}"),
            Ok(_) => panic!("expected HelloRetryRequest, got a TLS stream"),
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
        let sh = parse_server_hello(&msg[4..], &[]).unwrap();
        assert_eq!(sh.suite, crate::crypto::CipherSuiteId::Aes128GcmSha256);
        let expected: [u8; 32] =
            decode_hex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")
                .try_into()
                .unwrap();
        assert_eq!(sh.peer_key, Some(expected));

        // A non-0x0303 legacy_version is rejected by the parser itself.
        let mut bad = msg[4..].to_vec();
        bad[1] = 0x04;
        assert!(parse_server_hello(&bad, &[]).is_err());
    }

    #[test]
    fn parse_server_hello_rejects_hrr_magic() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&HRR_RANDOM);
        body.extend_from_slice(&[
            0x00, 0x13, 0x01, 0x00, 0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        ]);
        let Err(err) = parse_server_hello(&body, &[]) else {
            panic!("expected HelloRetryRequest, got a parsed ServerHello");
        };
        assert!(matches!(err, TlsError::HelloRetryRequest));
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
        assert_eq!(parse_server_hello(&body, &[]).unwrap().peer_key, Some(key));

        // A keyshare for a group other than X25519 is rejected outright.
        let mut wrong_group = x25519_keyshare_ext(&key);
        wrong_group[4] = 0x00;
        wrong_group[5] = 0x13; // secp256r1
        assert!(parse_server_hello(&minimal_server_hello(&wrong_group), &[]).is_err());

        // A keyshare whose key length is not 32 is rejected outright.
        let mut wrong_len = x25519_keyshare_ext(&key);
        wrong_len[6] = 0x00;
        wrong_len[7] = 0x10; // key len 16
        assert!(parse_server_hello(&minimal_server_hello(&wrong_len), &[]).is_err());

        // The session id echo must match the offered one exactly.
        let mut sid_body = minimal_server_hello(&x25519_keyshare_ext(&key));
        sid_body[34] = 32; // session id length
        sid_body.splice(35..35, std::iter::repeat_n(0x11u8, 32));
        assert_eq!(
            parse_server_hello(&sid_body, &[0x11; 32]).unwrap().peer_key,
            Some(key)
        );
        assert!(parse_server_hello(&sid_body, &[0x22; 32]).is_err());

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
        assert!(parse_server_hello(&garbage, &[]).is_err());
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
        // supported_versions = 0x0304, ALPN = [h2, http/1.1].
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&[0x00, 0x03, 0x02, 0x03, 0x04]);
        let alpn = [
            0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&u16::try_from(alpn.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&alpn);
        let mut body = Vec::new();
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&exts);
        parse_encrypted_extensions(&body).unwrap();

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
        assert!(parsed.cert_verify_body.is_empty());
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
                alpn: Some(&["http/1.1"]),
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
                alpn: Some(&["http/1.1"]),
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
                alpn: Some(&["http/1.1"]),
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
                alpn: Some(&["http/1.1"]),
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
        let err = parse_server_hello(&body, &[]).unwrap_err();
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
        let parsed = parse_server_hello(&body, &[]).unwrap();
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
