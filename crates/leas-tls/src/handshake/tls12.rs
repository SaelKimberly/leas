//! TLS 1.2 client handshake (ECDHE + AEAD, no CBC).
//!
//! Implemented as a standalone function, called from the shared `drive()`
//! after the `ServerHello` version is detected as TLS 1.2. The flow mirrors
//! RFC 5246 (with ECDHE from RFC 4492/8422): the `ClientHello` has already
//! been written, so this module reads the server flight (Certificate,
//! `ServerKeyExchange`, `ServerHelloDone`), sends the client key exchange,
//! CCS, and Finished, and verifies the server's Finished.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::crypto::tls12::{
    Tls12Suite, finished_verify_data, key_block, master_secret, master_secret_ems,
};
use crate::crypto::{AeadKey, CipherSuiteId, X25519KeyPair};
use crate::error::{Result, TlsError};
use crate::handshake::{ServerVerifier, TlsVersion, VerifyContext};
use crate::record::stream::{AppKeys, Tls12Aead, TlsStream};
use crate::record::{
    AEAD_TAG_LEN, CONTENT_CHANGE_CIPHER_SPEC, CONTENT_HANDSHAKE, aead_aad_12,
    make_handshake_record, parse_handshake_messages, read_record, skip_ccs,
};

// ── TLS 1.2 handshake message types (RFC 5246) ─────────────────────────────
const HS_NEW_SESSION_TICKET: u8 = 0x04;
const HS_CERTIFICATE: u8 = 0x0B;
const HS_SERVER_KEY_EXCHANGE: u8 = 0x0C;
const HS_CERTIFICATE_REQUEST: u8 = 0x0D;
const HS_SERVER_HELLO_DONE: u8 = 0x0E;
const HS_CLIENT_KEY_EXCHANGE: u8 = 0x10;
const HS_FINISHED: u8 = 0x14;

// ── Named curves (RFC 4492 §5.1.1) ─────────────────────────────────────────
/// X25519 (RFC 8422 §5.4) — keys and points are 32 bytes.
const CURVE_X25519: u16 = 0x001D;
/// secp256r1 / NIST P-256 — uncompressed points are 65 bytes.
const CURVE_SECP256R1: u16 = 0x0017;

// ── Server flight ──────────────────────────────────────────────────────────

struct ServerFlight {
    /// Every handshake message of the flight, verbatim and in arrival order.
    ///
    /// The `Finished` MACs cover the concatenation of ALL handshake messages
    /// (RFC 5246 §7.4.9), including ones this client does not interpret —
    /// `CertificateStatus` (OCSP stapling, which every shipped fingerprint
    /// requests) above all. Rebuilding the transcript from a fixed list of
    /// recognised messages silently drops those and breaks both MACs.
    transcript: Vec<u8>,
    chain: Vec<Vec<u8>>,
    ske: Ske,
}

struct Ske {
    /// The server's ephemeral named curve (RFC 4492): 0x001D X25519, 0x0017
    /// secp256r1.
    curve: u16,
    /// The server's ephemeral public point exactly as sent: 32 bytes for
    /// X25519, 65 uncompressed bytes for secp256r1.
    server_point: Vec<u8>,
    /// The `SignatureAndHashAlgorithm` from the SKE (RFC 5246 §7.4.3).
    sigalg: u16,
    /// The raw signature bytes.
    signature: Vec<u8>,
    /// The `ServerECDHParams` bytes (the portion signed, excluding the
    /// signature algorithm and signature itself).
    params: Vec<u8>,
}

/// Read the server's plaintext flight (Certificate … `ServerHelloDone`) from
/// the wire, skipping interleaved CCS records. Accumulates every handshake
/// message into the transcript and parses the ones the client needs.
async fn read_server_flight<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut buf: Vec<u8>,
) -> Result<ServerFlight> {
    let mut transcript: Vec<u8> = Vec::new();
    let mut chain: Option<Vec<Vec<u8>>> = None;
    let mut ske: Option<Ske> = None;

    loop {
        // Consume every complete handshake message buffered so far.
        let mut consumed = 0usize;
        while buf.len() >= consumed + 4 {
            let msg_len = u24(&buf[consumed + 1..consumed + 4]);
            let total = 4 + msg_len;
            if buf.len() < consumed + total {
                break;
            }
            let msg_type = buf[consumed];
            let body = &buf[consumed + 4..consumed + total];
            transcript.extend_from_slice(&buf[consumed..consumed + total]);
            consumed += total;

            match msg_type {
                HS_CERTIFICATE => chain = Some(parse_cert_12(body)?),
                HS_SERVER_KEY_EXCHANGE => ske = Some(parse_ske(body)?),
                HS_CERTIFICATE_REQUEST => {
                    // Answering requires a client Certificate +
                    // CertificateVerify, which this engine does not have;
                    // continuing would fail the server's own verification.
                    return Err(TlsError::Handshake(
                        "TLS 1.2 server requested a client certificate: mutual TLS is not supported"
                            .into(),
                    ));
                }
                HS_SERVER_HELLO_DONE => {
                    return Ok(ServerFlight {
                        transcript,
                        chain: chain.ok_or_else(|| {
                            TlsError::Handshake("TLS 1.2 server sent no Certificate".into())
                        })?,
                        ske: ske.ok_or_else(|| {
                            TlsError::Handshake("TLS 1.2 server sent no ServerKeyExchange".into())
                        })?,
                    });
                }
                _ => {}
            }
        }
        buf.drain(..consumed);

        let rec = skip_ccs(stream).await?;
        if rec.content_type != CONTENT_HANDSHAKE {
            return Err(TlsError::Handshake(format!(
                "expected TLS 1.2 handshake record (0x16), got 0x{:02X}",
                rec.content_type
            )));
        }
        if buf.len() + rec.payload.len() > crate::handshake::MAX_FLIGHT_BUFFER {
            return Err(TlsError::Handshake(
                "TLS 1.2 server flight exceeds the 16 MiB reassembly bound".into(),
            ));
        }
        buf.extend_from_slice(&rec.payload);
    }
}

/// Parse a TLS 1.2 Certificate message body (RFC 5246 §7.4.2):
/// `list_len(3) || (cert_len(3) || cert)*` — no per-cert extensions
/// (unlike TLS 1.3).
fn parse_cert_12(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    if body.len() < 3 {
        return Err(TlsError::Handshake("TLS 1.2 Certificate too short".into()));
    }
    let list_len = u24(&body[..3]);
    let mut pos = 3usize;
    let end = pos + list_len;
    if end > body.len() {
        return Err(TlsError::Handshake(
            "TLS 1.2 Certificate list truncated".into(),
        ));
    }
    let mut chain = Vec::new();
    while pos < end {
        if pos + 3 > end {
            return Err(TlsError::Handshake(
                "TLS 1.2 certificate entry length truncated".into(),
            ));
        }
        let cert_len = u24(&body[pos..pos + 3]);
        pos += 3;
        if pos + cert_len > end {
            return Err(TlsError::Handshake(
                "TLS 1.2 certificate data truncated".into(),
            ));
        }
        chain.push(body[pos..pos + cert_len].to_vec());
        pos += cert_len;
    }
    Ok(chain)
}

/// Parse a TLS 1.2 ECDHE `ServerKeyExchange` (RFC 4492 §5.4):
/// `curve_type(1) || named_curve(2) || pubkey_len(1) || pubkey ||
/// sigalg(2) || sig_len(2) || sig`.
///
/// X25519 (0x001D) and secp256r1 (0x0017) are supported. A server that offers
/// only P-256 is common on TLS-1.2 hosts, and refusing it fails the handshake
/// outright (reproduced live 2026-09-15: OpenSSL completed the handshake while
/// this engine aborted with "only X25519 is supported").
fn parse_ske(body: &[u8]) -> Result<Ske> {
    if body.is_empty() {
        return Err(TlsError::Handshake(
            "TLS 1.2 ServerKeyExchange body empty".into(),
        ));
    }
    // curve_type 3 = named_curve (RFC 4492 §5.4). Explicit prime/char2
    // curves (1, 2) are refused: arbitrary curve parameters are never
    // validated here and no mainstream server offers them.
    let curve_type = body[0];
    if curve_type != 3 {
        return Err(TlsError::Handshake(format!(
            "TLS 1.2 ServerKeyExchange: curve type {curve_type}, only named_curve (3) is supported"
        )));
    }
    if body.len() < 4 {
        return Err(TlsError::Handshake(
            "TLS 1.2 ServerKeyExchange truncated at curve info".into(),
        ));
    }
    let curve = u16::from_be_bytes([body[1], body[2]]);
    let expected_len = match curve {
        CURVE_X25519 => 32,
        CURVE_SECP256R1 => 65,
        other => {
            return Err(TlsError::Handshake(format!(
                "TLS 1.2 ServerKeyExchange: unsupported named curve 0x{other:04X}, only X25519 (0x001D) and secp256r1 (0x0017) are supported"
            )));
        }
    };
    let pub_len = usize::from(body[3]);
    if pub_len != expected_len || body.len() < 4 + pub_len + 4 {
        return Err(TlsError::Handshake(format!(
            "TLS 1.2 ServerKeyExchange: curve 0x{curve:04X} needs a {expected_len}-byte point, got {pub_len}"
        )));
    }
    let server_point = body[4..4 + pub_len].to_vec();
    if curve == CURVE_SECP256R1 && server_point[0] != 0x04 {
        return Err(TlsError::Handshake(
            "TLS 1.2 ServerKeyExchange: secp256r1 needs an uncompressed point (0x04)".into(),
        ));
    }
    let params_end = 4 + pub_len;
    let params = body[..params_end].to_vec();

    let sigalg = u16::from_be_bytes([body[params_end], body[params_end + 1]]);
    let sig_len = usize::from(u16::from_be_bytes([
        body[params_end + 2],
        body[params_end + 3],
    ]));
    if body.len() != params_end + 4 + sig_len {
        return Err(TlsError::Handshake(
            "TLS 1.2 ServerKeyExchange signature length mismatch".into(),
        ));
    }
    let signature = body[params_end + 4..].to_vec();
    Ok(Ske {
        curve,
        server_point,
        sigalg,
        signature,
        params,
    })
}

/// Read a 3-byte big-endian length (RFC 8446 lengths are uint24).
fn u24(b: &[u8]) -> usize {
    (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
}

/// Map a TLS 1.2 suite to a `CipherSuiteId` for AEAD key construction
/// (both use the same ring AEAD algorithm).
const fn to_ciphersuite(suite: Tls12Suite) -> CipherSuiteId {
    match suite {
        Tls12Suite::EcdheRsaAes128GcmSha256 | Tls12Suite::EcdheEcdsaAes128GcmSha256 => {
            CipherSuiteId::Aes128GcmSha256
        }
        Tls12Suite::EcdheRsaAes256GcmSha384 | Tls12Suite::EcdheEcdsaAes256GcmSha384 => {
            CipherSuiteId::Aes256GcmSha384
        }
        Tls12Suite::EcdheRsaChacha20Poly1305Sha256
        | Tls12Suite::EcdheEcdsaChacha20Poly1305Sha256 => CipherSuiteId::Chacha20Poly1305Sha256,
    }
}

/// The TLS 1.2 client handshake, continuing after the `ClientHello` has been
/// written and the `ServerHello` has been read.
///
/// `client_random` is the 32 bytes at offset 6 of the `ClientHello`
/// handshake message (after the 4-byte handshake header and 2-byte legacy
/// version).
pub(crate) async fn drive12<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut stream: S,
    hello: &[u8],
    client_random: &[u8; 32],
    server_hello: &super::ServerHelloData,
    pre_buffer: Vec<u8>,
    keypair: &X25519KeyPair,
    server_name: &str,
    verifier: &dyn ServerVerifier,
) -> Result<(TlsStream<S>, crate::handshake::AuthOutcome)> {
    let suite = server_hello
        .suite12
        .ok_or_else(|| TlsError::Handshake("TLS 1.2 handshake path has no suite".into()))?;
    let server_random = server_hello.server_random;
    // RFC 7627 §5.3: a client that offered `extended_master_secret` MUST
    // abort when the server does not echo it — the legacy master secret is
    // what the triple-handshake attack exploits.
    let ems = if crate::handshake::client_hello_extension(hello, 0x0017).is_some() {
        if !server_hello.ems {
            return Err(TlsError::Handshake(
                "TLS 1.2 server did not echo extended_master_secret (RFC 7627)".into(),
            ));
        }
        true
    } else {
        server_hello.ems
    };

    // 1. Read the server flight (Certificate … ServerHelloDone), consuming
    //    any handshake messages already buffered in the ServerHello record.
    let flight = read_server_flight(&mut stream, pre_buffer).await?;

    // 2. Transcript = ClientHello || ServerHello || the whole server flight
    //    verbatim (every message, including ones not interpreted here).
    let mut transcript = Vec::new();
    transcript.extend_from_slice(hello);
    transcript.extend_from_slice(&server_hello.raw);
    transcript.extend_from_slice(&flight.transcript);

    // 3. Verify the SKE signature via the verifier seam. The scheme must be
    //    one the ClientHello offered (RFC 5246 §7.4.3).
    crate::handshake::ensure_offered_sigalg(hello, flight.ske.sigalg)?;
    let signed_data = {
        let mut sd = Vec::with_capacity(64 + flight.ske.params.len());
        sd.extend_from_slice(client_random);
        sd.extend_from_slice(&server_random);
        sd.extend_from_slice(&flight.ske.params);
        sd
    };
    let cs = to_ciphersuite(suite);
    verifier.verify(&VerifyContext {
        chain: &flight.chain,
        sni: server_name,
        version: TlsVersion::Tls12,
        suite: cs,
        signature_scheme: flight.ske.sigalg,
        signature: &flight.ske.signature,
        signed_data: &signed_data,
    })?;

    // 4./5. ECDHE shared secret + the client's public point, per curve.
    //
    // X25519 reuses the hello's key pair (a TLS 1.2 server ignores the 1.3
    // `key_share`, so the pair is free to serve both roles). secp256r1 has no
    // such pair: the engine's key material is X25519-only, so the ephemeral
    // P-256 key is generated here, once, for this handshake — ring owns it and
    // consumes it in the agreement. Both curves yield a 32-byte premaster (the
    // raw x-coordinate), so the key schedule is unchanged.
    let (premaster, cke_body) = match flight.ske.curve {
        CURVE_X25519 => {
            let server_pub: [u8; 32] =
                flight.ske.server_point.as_slice().try_into().map_err(|_| {
                    TlsError::Handshake("TLS 1.2 X25519 point is not 32 bytes".into())
                })?;
            let premaster = keypair.agree(&server_pub)?;
            let mut body = Vec::with_capacity(33);
            body.push(32);
            body.extend_from_slice(&keypair.public_key());
            (premaster, body)
        }
        CURVE_SECP256R1 => {
            use ring::agreement::{
                ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral,
            };
            let rng = ring::rand::SystemRandom::new();
            let ephemeral = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
                .map_err(|e| TlsError::Crypto(format!("P-256 key generation failed: {e}")))?;
            let public = ephemeral
                .compute_public_key()
                .map_err(|e| TlsError::Crypto(format!("P-256 public key failed: {e}")))?;
            let public = public.as_ref().to_vec();
            let peer = UnparsedPublicKey::new(&ECDH_P256, &flight.ske.server_point);
            // The raw ECDH output is the 32-byte x-coordinate — the same shape
            // the X25519 arm produces, so the key schedule stays curve-blind.
            let secret: Option<Zeroizing<[u8; 32]>> = agree_ephemeral(ephemeral, &peer, |secret| {
                <[u8; 32]>::try_from(secret).ok().map(Zeroizing::new)
            })
            .map_err(|_| TlsError::Handshake("P-256 agreement failed".into()))?;
            let secret = secret
                .ok_or_else(|| TlsError::Handshake("P-256 shared secret is not 32 bytes".into()))?;
            let mut body = Vec::with_capacity(1 + public.len());
            body.push(u8::try_from(public.len()).unwrap_or(u8::MAX));
            body.extend_from_slice(&public);
            (secret, body)
        }
        other => {
            return Err(TlsError::Handshake(format!(
                "TLS 1.2 ServerKeyExchange: unsupported named curve 0x{other:04X}"
            )));
        }
    };
    let cke_raw = crate::handshake::make_hs_msg(HS_CLIENT_KEY_EXCHANGE, &cke_body);
    transcript.extend_from_slice(&cke_raw);

    // 6. Handshake hash (for both the EMS master secret and client Finished).
    let handshake_hash = ring::digest::digest(suite.prf_digest(), &transcript)
        .as_ref()
        .to_vec();

    // 7. Master secret.
    let master = if ems {
        master_secret_ems(suite, premaster.as_slice(), &handshake_hash)
    } else {
        master_secret(suite, premaster.as_slice(), client_random, &server_random)
    };

    // 8. Key block → per-direction keys + fixed IVs. The IV width is
    //    suite-dependent: 4 bytes for AES-GCM, 12 for ChaCha20-Poly1305
    //    (RFC 7905 §2), which is why the block is sliced, not fixed-size.
    let kb = key_block(suite, &master, &server_random, client_random);
    let k = suite.key_len();
    let fi = suite.fixed_iv_len();
    if kb.len() < 2 * k + 2 * fi {
        return Err(TlsError::Crypto("TLS 1.2 key block too short".into()));
    }
    let client_key_bytes = &kb[..k];
    let server_key_bytes = &kb[k..2 * k];
    let client_iv = &kb[2 * k..2 * k + fi];
    let server_iv = &kb[2 * k + fi..2 * k + 2 * fi];

    let (aead_for_client, aead_for_server) = build_aeads(suite, client_iv, server_iv)?;

    let client_write_key = AeadKey::from_key_bytes(cs, client_key_bytes)?;
    let server_write_key = AeadKey::from_key_bytes(cs, server_key_bytes)?;

    // 9. Send ClientKeyExchange (plaintext handshake record).
    stream
        .write_all(&make_handshake_record(HS_CLIENT_KEY_EXCHANGE, &cke_body))
        .await?;

    // 10. Send ChangeCipherSpec.
    stream
        .write_all(&[CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01])
        .await?;

    // 11. Client Finished (encrypted with client_write_key, seq=0), framed
    // in place: header, explicit nonce, plaintext, tag — one buffer, with
    // the seal happening inside the record buffer.
    let cf_verify = finished_verify_data(suite, &master, b"client finished", &handshake_hash);
    let cf_hs = crate::handshake::make_hs_msg(HS_FINISHED, &cf_verify);
    let cf_explicit = aead_for_client.explicit_nonce(0);
    let cf_nonce = aead_for_client.nonce(0, cf_explicit.as_slice())?;
    let cf_aad = aead_aad_12(0, CONTENT_HANDSHAKE, cf_hs.len());
    let cf_ct_len = cf_hs.len() + AEAD_TAG_LEN;
    let cf_body_len = cf_explicit.as_slice().len() + cf_ct_len;
    let mut cf_record = Vec::with_capacity(5 + cf_body_len);
    cf_record.push(CONTENT_HANDSHAKE);
    cf_record.extend_from_slice(&0x0303u16.to_be_bytes());
    cf_record.extend_from_slice(&u16::try_from(cf_body_len).unwrap_or(u16::MAX).to_be_bytes());
    let cf_pt_start = cf_record.len() + cf_explicit.as_slice().len();
    cf_record.extend_from_slice(cf_explicit.as_slice());
    cf_record.extend_from_slice(&cf_hs);
    client_write_key.seal_in_place_with_nonce(cf_nonce, &cf_aad, &mut cf_record, cf_pt_start)?;
    stream.write_all(&cf_record).await?;
    transcript.extend_from_slice(&cf_hs);

    // 12. Read the server's closing flight. RFC 5077 §3.3 puts
    //    `NewSessionTicket` in it as a PLAINTEXT handshake record BEFORE the
    //    server's ChangeCipherSpec (unlike TLS 1.3, where the ticket follows
    //    Finished), and it is covered by both Finished MACs — so it must be
    //    appended to the transcript before `verify_data` is computed.
    let mut ccs_seen = false;
    let sf_plain = loop {
        let rec = read_record(&mut stream).await?;
        match rec.content_type {
            CONTENT_CHANGE_CIPHER_SPEC => {
                if ccs_seen {
                    return Err(TlsError::Handshake(
                        "TLS 1.2 server sent a second ChangeCipherSpec".into(),
                    ));
                }
                ccs_seen = true;
            }
            CONTENT_HANDSHAKE if !ccs_seen => {
                for (msg_type, body) in parse_handshake_messages(&rec.payload)? {
                    if msg_type != HS_NEW_SESSION_TICKET {
                        return Err(TlsError::Handshake(format!(
                            "unexpected plaintext TLS 1.2 handshake message 0x{msg_type:02X} before the server ChangeCipherSpec"
                        )));
                    }
                    transcript.extend_from_slice(&crate::handshake::make_hs_msg(msg_type, body));
                }
            }
            CONTENT_HANDSHAKE => {
                let explicit_len = aead_for_server.explicit_nonce_len();
                if rec.payload.len() < explicit_len + AEAD_TAG_LEN {
                    return Err(TlsError::Handshake(
                        "TLS 1.2 server Finished record too short".into(),
                    ));
                }
                // Open inside the record buffer: the explicit nonce is only
                // borrowed for the nonce build, then the ciphertext tail is
                // decrypted in place and the nonce prefix drained — no
                // `to_vec` pair, no allocating twin.
                let mut payload = rec.payload;
                let sf_nonce = aead_for_server
                    .nonce(0, &payload[..explicit_len])
                    .map_err(|e| TlsError::Handshake(e.to_string()))?;
                let sf_plaintext_len = payload.len() - explicit_len - AEAD_TAG_LEN;
                let sf_aad = aead_aad_12(0, CONTENT_HANDSHAKE, sf_plaintext_len);
                let plain_len = server_write_key.open_in_place_with_nonce(
                    sf_nonce,
                    &sf_aad,
                    &mut payload[explicit_len..],
                )?;
                payload.drain(..explicit_len);
                payload.truncate(plain_len);
                break payload;
            }
            other => {
                return Err(TlsError::Handshake(format!(
                    "expected TLS 1.2 server handshake record (0x16), got 0x{other:02X}"
                )));
            }
        }
    };
    if !ccs_seen {
        return Err(TlsError::Handshake(
            "TLS 1.2 server Finished arrived without a ChangeCipherSpec".into(),
        ));
    }

    let sf_hash = ring::digest::digest(suite.prf_digest(), &transcript)
        .as_ref()
        .to_vec();
    let expected_sf = finished_verify_data(suite, &master, b"server finished", &sf_hash);

    // The server Finished is a single handshake message.
    let msgs = parse_handshake_messages(&sf_plain)?;
    let (sf_type, sf_body) = msgs.into_iter().next().ok_or_else(|| {
        TlsError::Handshake("TLS 1.2 server Finished: no handshake messages".into())
    })?;
    if sf_type != HS_FINISHED {
        return Err(TlsError::Handshake(format!(
            "TLS 1.2 expected server Finished (0x14), got 0x{sf_type:02X}"
        )));
    }
    if sf_body != expected_sf.as_slice() {
        return Err(TlsError::Handshake(
            "TLS 1.2 server Finished MAC mismatch — possible MITM or wrong key".into(),
        ));
    }

    // 13. Build the TLS stream.
    let tls = TlsStream::new(
        stream,
        AppKeys::tls12(
            server_write_key,
            client_write_key,
            aead_for_server,
            aead_for_client,
        ),
    );
    Ok((tls, crate::handshake::AuthOutcome::Ok))
}

/// Build the per-direction [`Tls12Aead`] from the key block's fixed IVs.
///
/// Widths come from [`Tls12Suite::fixed_iv_len`]; a mismatch means the key
/// block and the nonce geometry disagree, which is a bug, not a wire event.
fn build_aeads(
    suite: Tls12Suite,
    client_iv: &[u8],
    server_iv: &[u8],
) -> Result<(Tls12Aead, Tls12Aead)> {
    let widths = |iv: &[u8]| -> Result<[u8; 4]> {
        iv.try_into()
            .map_err(|_| TlsError::Crypto("TLS 1.2 AES-GCM fixed IV is not 4 bytes".into()))
    };
    let wide = |iv: &[u8]| -> Result<[u8; 12]> {
        iv.try_into()
            .map_err(|_| TlsError::Crypto("TLS 1.2 ChaCha20 fixed IV is not 12 bytes".into()))
    };
    Ok(match suite {
        Tls12Suite::EcdheRsaAes128GcmSha256
        | Tls12Suite::EcdheEcdsaAes128GcmSha256
        | Tls12Suite::EcdheRsaAes256GcmSha384
        | Tls12Suite::EcdheEcdsaAes256GcmSha384 => (
            Tls12Aead::AesGcm {
                fixed_iv: widths(client_iv)?,
            },
            Tls12Aead::AesGcm {
                fixed_iv: widths(server_iv)?,
            },
        ),
        Tls12Suite::EcdheRsaChacha20Poly1305Sha256
        | Tls12Suite::EcdheEcdsaChacha20Poly1305Sha256 => (
            Tls12Aead::Chacha20Poly1305 {
                fixed_iv: wide(client_iv)?,
            },
            Tls12Aead::Chacha20Poly1305 {
                fixed_iv: wide(server_iv)?,
            },
        ),
    })
}
