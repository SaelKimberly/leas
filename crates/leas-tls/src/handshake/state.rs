//! Sans-I/O TLS handshake state machine.
//!
//! Bytes in (`feed`), bytes out (`poll_transmit`). No socket, no async runtime,
//! and no `tokio` import. TLS 1.3 (plain, HRR, ECH, REALITY) completes here;
//! TLS 1.2 is handed off as a typed value because its driver still lives in
//! `handshake::tls12` (the adapter replays the consumed bytes into it).

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::crypto::mlkem::{Mlkem768, SecretKey as MlkemSecretKey};
use crate::crypto::tls12::Tls12Suite;
use crate::crypto::{AeadKey, KeySchedule, MAX_HASH_LEN, X25519KeyPair};
use crate::error::{Result, TlsError};
use crate::hello::parse::parse_hello;
use crate::hello::to_record;
use crate::record::stream::{AppKeys, AppSecrets};
use crate::record::{
    CONTENT_APPLICATION_DATA, CONTENT_CHANGE_CIPHER_SPEC, CONTENT_HANDSHAKE, HS_FINISHED,
    HS_MESSAGE_HASH, HS_SERVER_HELLO, MAX_RECORD_PAYLOAD, aead_aad, parse_handshake_messages,
};

use super::flight::{FlightAccumulator, ServerFlight};
use super::server_hello::{HrrData, ServerHelloData};
use super::{
    AEAD_TAG_LEN, AuthOutcome, ParsedReply, RetrySupport, ServerAuth, TlsVersion, VerifyContext,
    compressed_algorithms, ensure_offered_alpn, ensure_offered_key_share, ensure_offered_sigalg,
    make_hs_msg, parse_server_hello,
};

/// Negotiated state after a TLS 1.3 handshake.
pub(crate) struct Established {
    pub keys: AppKeys,
    pub secrets: Option<AppSecrets>,
    pub alpn: Option<Vec<u8>>,
    pub hybrid: bool,
    pub auth: AuthOutcome,
    pub resumed: bool,
}

/// A `TLS 1.2` `ServerHello` plus every byte after it, for the async 1.2 driver.
pub(crate) struct Tls12Handoff {
    pub server_hello: ServerHelloData,
    pub pre_buffer: Vec<u8>,
    pub current_hello: Vec<u8>,
    pub keypair: X25519KeyPair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    SendHello,
    AwaitServerHello,
    AwaitFlight,
    Done,
}

/// One client handshake as a byte-driven state machine.
pub(crate) struct Handshake<'a> {
    phase: Phase,
    inbuf: Vec<u8>,
    out: Vec<u8>,
    current_hello: Vec<u8>,
    wire_hello: Vec<u8>,
    current_sid: Vec<u8>,
    first_hello: Option<Vec<u8>>,
    retry_message: Option<Vec<u8>>,
    hrr_selected: Option<u16>,
    keypair: Option<X25519KeyPair>,
    mlkem_sk: Option<MlkemSecretKey>,
    server_name: &'a str,
    auth: ServerAuth<'a>,
    retry: Option<&'a RetrySupport<'a>>,
    ech: Option<(&'a [u8], &'a crate::ech::EchState)>,
    server_hello: Option<ServerHelloData>,
    ks: Option<KeySchedule>,
    hash_len: usize,
    hs_secret: Zeroizing<[u8; MAX_HASH_LEN]>,
    psk: Option<Zeroizing<Vec<u8>>>,
    resumed: bool,
    server_hs_key: Option<AeadKey>,
    client_hs_key: Option<AeadKey>,
    server_hs_ts: Zeroizing<[u8; MAX_HASH_LEN]>,
    client_hs_ts: Zeroizing<[u8; MAX_HASH_LEN]>,
    flight: Option<FlightAccumulator>,
    flight_seq: u64,
    established: Option<Established>,
    handoff: Option<Tls12Handoff>,
}

impl<'a> Handshake<'a> {
    /// Start from the built `ClientHello`.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) fn new(
        hello: &[u8],
        offered_session_id: &[u8],
        keypair: X25519KeyPair,
        mlkem_sk: Option<MlkemSecretKey>,
        server_name: &'a str,
        auth: ServerAuth<'a>,
        retry: Option<&'a RetrySupport<'a>>,
        ech: Option<(&'a [u8], &'a crate::ech::EchState)>,
        psk: Option<Zeroizing<Vec<u8>>>,
    ) -> Self {
        Self {
            phase: Phase::SendHello,
            inbuf: Vec::new(),
            out: Vec::new(),
            current_hello: hello.to_vec(),
            wire_hello: ech.map_or_else(|| hello.to_vec(), |(wire, _)| wire.to_vec()),
            current_sid: offered_session_id.to_vec(),
            first_hello: None,
            retry_message: None,
            hrr_selected: None,
            keypair: Some(keypair),
            mlkem_sk,
            server_name,
            auth,
            retry,
            ech,
            server_hello: None,
            ks: None,
            hash_len: 0,
            hs_secret: Zeroizing::new([0; MAX_HASH_LEN]),
            psk,
            resumed: false,
            server_hs_key: None,
            client_hs_key: None,
            server_hs_ts: Zeroizing::new([0; MAX_HASH_LEN]),
            client_hs_ts: Zeroizing::new([0; MAX_HASH_LEN]),
            flight: None,
            flight_seq: 0,
            established: None,
            handoff: None,
        }
    }

    /// Emit the first `ClientHello` (the named start transition).
    pub(crate) fn start(&mut self) -> Result<()> {
        self.pump()
    }

    /// Feed wire bytes. Processes every complete record available.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        self.inbuf.extend_from_slice(bytes);
        self.pump()
    }

    /// Drain bytes the handshake wants written.
    pub(crate) fn poll_transmit(&mut self, out: &mut Vec<u8>) -> bool {
        if self.out.is_empty() {
            return false;
        }
        out.append(&mut self.out);
        true
    }

    /// The completed TLS 1.3 state, once available.
    pub(crate) const fn take_established(&mut self) -> Option<Established> {
        self.established.take()
    }

    /// The TLS 1.2 handoff, once the server selected 1.2.
    pub(crate) const fn take_handoff(&mut self) -> Option<Tls12Handoff> {
        self.handoff.take()
    }

    fn pump(&mut self) -> Result<()> {
        loop {
            match self.phase {
                Phase::SendHello => {
                    self.out.extend_from_slice(&to_record(&self.wire_hello));
                    self.phase = Phase::AwaitServerHello;
                }
                Phase::AwaitServerHello => {
                    let Some((ty, payload)) = take_record(&mut self.inbuf)? else {
                        return Ok(());
                    };
                    if ty == CONTENT_CHANGE_CIPHER_SPEC {
                        continue;
                    }
                    if ty == crate::record::CONTENT_ALERT && payload.len() >= 2 {
                        return Err(TlsError::Handshake(format!(
                            "alert: {} {}",
                            payload[0], payload[1]
                        )));
                    }
                    if ty != CONTENT_HANDSHAKE {
                        return Err(TlsError::Handshake(format!(
                            "expected Handshake record (0x16), got 0x{ty:02X}"
                        )));
                    }
                    let sent = parse_hello(&self.current_hello)?;
                    let offered: Vec<u16> = parse_hello(&self.wire_hello)?
                        .extensions
                        .iter()
                        .map(|(ty, _)| *ty)
                        .collect();
                    let (raw, body, pre) = first_handshake_message(&payload)?;
                    if body.is_empty() {
                        return Err(TlsError::Handshake("empty ServerHello record".into()));
                    }
                    match parse_server_hello(body, &self.current_sid, Some(&offered))? {
                        ParsedReply::Retry(hrr) => self.handle_retry(&hrr, &raw)?,
                        ParsedReply::Hello(sh) => {
                            if !pre.is_empty() {
                                self.inbuf.splice(0..0, pre);
                            }
                            let data = ServerHelloData {
                                raw,
                                version: sh.version,
                                server_random: sh.server_random,
                                peer_key: sh.peer_key,
                                mlkem_ciphertext: sh.mlkem_ciphertext,
                                key_share_group: sh.key_share_group,
                                suite: sh.suite,
                                suite12: sh.suite12,
                                ems: sh.ems,
                                alpn: sh.alpn,
                                psk_selected: sh.psk_selected,
                            };
                            let selected = data
                                .suite12
                                .map_or_else(|| data.suite.to_u16(), Tls12Suite::to_u16);
                            super::ensure_offered_suite(&sent.cipher_suites, selected)?;
                            self.handle_server_hello(data)?;
                        }
                    }
                }
                Phase::AwaitFlight => {
                    let Some((ty, payload)) = take_record(&mut self.inbuf)? else {
                        return Ok(());
                    };
                    if ty == CONTENT_CHANGE_CIPHER_SPEC {
                        continue;
                    }
                    if ty == crate::record::CONTENT_ALERT && payload.len() >= 2 {
                        return Err(TlsError::Handshake(format!(
                            "alert: {} {}",
                            payload[0], payload[1]
                        )));
                    }
                    if ty != CONTENT_APPLICATION_DATA {
                        return Err(TlsError::Handshake(format!(
                            "expected encrypted record (0x17), got 0x{ty:02X}"
                        )));
                    }
                    let key = self
                        .server_hs_key
                        .as_ref()
                        .ok_or_else(|| TlsError::Handshake("server key missing".into()))?;
                    let mut payload = payload;
                    let plain =
                        key.open_in_place(self.flight_seq, &aead_aad(payload.len()), &mut payload)?;
                    self.flight_seq += 1;
                    let (inner, data) = crate::record::engine::strip_padding(&payload[..plain])?;
                    if inner != CONTENT_HANDSHAKE {
                        continue;
                    }
                    let acc = self
                        .flight
                        .as_mut()
                        .ok_or_else(|| TlsError::Handshake("flight accumulator missing".into()))?;
                    if let Some(flight) = acc.push_plain(data)? {
                        self.finish(&flight)?;
                    }
                }
                Phase::Done => return Ok(()),
            }
        }
    }

    fn handle_retry(&mut self, hrr: &HrrData, raw: &[u8]) -> Result<()> {
        let Some(retry) = self.retry else {
            return Err(TlsError::HelloRetryRequest);
        };
        if matches!(self.auth, ServerAuth::Reality { .. }) || self.psk.is_some() {
            // A resumed hello's binder is bound to ClientHello1; retrying it
            // is a documented non-goal (fail closed rather than drop the PSK).
            return Err(TlsError::HelloRetryRequest);
        }
        if self.first_hello.is_some() {
            return Err(TlsError::Handshake(
                "server sent a second HelloRetryRequest".into(),
            ));
        }
        self.hrr_selected = hrr.selected_group;
        let (rebuilt, new_kp, new_sk) = retry.rebuild(hrr)?;
        self.retry_message = Some(raw.to_vec());
        self.first_hello = Some(std::mem::take(&mut self.current_hello));
        self.current_sid = rebuilt.session_id().to_vec();
        self.wire_hello = rebuilt.handshake_bytes.clone();
        self.current_hello = rebuilt.handshake_bytes;
        if let Some(kp) = new_kp {
            self.keypair = Some(kp);
        }
        if new_sk.is_some() {
            self.mlkem_sk = new_sk;
        }
        self.phase = Phase::SendHello;
        Ok(())
    }

    fn handle_server_hello(&mut self, sh: ServerHelloData) -> Result<()> {
        if let Some(wire) = sh.key_share_group {
            ensure_offered_key_share(&self.current_hello, self.hrr_selected, wire)?;
        }
        if let Some((_, state)) = self.ech {
            let expected = state.confirm(sh.suite.digest(), &sh.raw)?;
            let mut diff = 0u8;
            for (a, b) in sh.server_random[24..32].iter().zip(expected.iter()) {
                diff |= a ^ b;
            }
            if diff != 0 {
                return Err(TlsError::Handshake(
                    "server rejected the encrypted client hello (ECH)".into(),
                ));
            }
        }
        ensure_offered_alpn(&self.current_hello, sh.alpn.as_deref())?;
        if sh.version == TlsVersion::Tls12 {
            let pre_buffer = std::mem::take(&mut self.inbuf);
            let keypair = self
                .keypair
                .take()
                .ok_or_else(|| TlsError::Handshake("key pair missing for TLS 1.2".into()))?;
            self.handoff = Some(Tls12Handoff {
                server_hello: sh,
                pre_buffer,
                current_hello: std::mem::take(&mut self.current_hello),
                keypair,
            });
            self.phase = Phase::Done;
            return Ok(());
        }
        if sh.alpn.is_some() {
            return Err(TlsError::Handshake(
                "TLS 1.3 ServerHello carried ALPN".into(),
            ));
        }
        let keypair = self
            .keypair
            .as_ref()
            .ok_or_else(|| TlsError::Handshake("key pair missing".into()))?;
        let classical =
            keypair.agree(&sh.peer_key.ok_or_else(|| {
                TlsError::Handshake("TLS 1.3 ServerHello has no key_share".into())
            })?)?;
        let shared: Zeroizing<Vec<u8>> =
            match (self.mlkem_sk.as_ref(), sh.mlkem_ciphertext.as_ref()) {
                (Some(sk), Some(ct)) => {
                    let pq = Mlkem768::decapsulate(sk, ct);
                    let mut combined = Zeroizing::new(Vec::with_capacity(classical.len() + 32));
                    combined.extend_from_slice(pq.as_bytes());
                    combined.extend_from_slice(classical.as_slice());
                    combined
                }
                _ => Zeroizing::new(classical.to_vec()),
            };
        let hash_len = sh.suite.hash_len();
        let mut ks = KeySchedule::new(sh.suite);
        if let Some(ch1) = self.first_hello.as_deref() {
            let hash = ring::digest::digest(sh.suite.digest(), ch1);
            ks.add_transcript(&make_hs_msg(HS_MESSAGE_HASH, hash.as_ref()));
            let hrr = self.retry_message.as_deref().ok_or_else(|| {
                TlsError::Handshake("retry without a HelloRetryRequest transcript".into())
            })?;
            ks.add_transcript(hrr);
        }
        ks.add_transcript(&self.current_hello);
        ks.add_transcript(&sh.raw);
        if sh.psk_selected && self.psk.is_none() {
            return Err(TlsError::Handshake(
                "server selected a PSK the client did not offer".into(),
            ));
        }
        self.resumed = sh.psk_selected;
        let psk = if sh.psk_selected {
            self.psk.as_ref().map(|p| p.as_slice())
        } else {
            None
        };
        let hs_secret = ks.handshake_secret_with_psk(&shared, psk)?;
        let (client_ts, server_ts) = ks.handshake_traffic_secrets(&hs_secret[..hash_len])?;
        self.server_hs_key = Some(AeadKey::new(sh.suite, &server_ts[..hash_len])?);
        self.client_hs_key = Some(AeadKey::new(sh.suite, &client_ts[..hash_len])?);
        self.hs_secret = hs_secret;
        self.server_hs_ts = server_ts;
        self.client_hs_ts = client_ts;
        let offered = compressed_algorithms(&self.current_hello);
        self.flight = Some(FlightAccumulator::new(&offered));
        self.ks = Some(ks);
        self.hash_len = hash_len;
        self.server_hello = Some(sh);
        self.phase = Phase::AwaitFlight;
        Ok(())
    }

    fn finish(&mut self, flight: &ServerFlight) -> Result<()> {
        let sh = self
            .server_hello
            .take()
            .ok_or_else(|| TlsError::Handshake("server hello missing".into()))?;
        let mut ks = self
            .ks
            .take()
            .ok_or_else(|| TlsError::Handshake("key schedule missing".into()))?;
        ensure_offered_alpn(&self.current_hello, flight.negotiated_alpn.as_deref())?;
        ks.add_transcript(&flight.ee_raw);
        if !self.resumed {
            ks.add_transcript(&flight.cert_raw);
        }
        let (th, th_len) = ks.transcript_hash();
        let outcome = if self.resumed {
            AuthOutcome::Ok
        } else {
            match self.auth {
                ServerAuth::Verifier(verifier) => {
                    let signature = flight.cert_verify_body.get(4..).ok_or_else(|| {
                        TlsError::Verify("server sent no CertificateVerify signature".into())
                    })?;
                    ensure_offered_sigalg(&self.current_hello, flight.signature_scheme)?;
                    verifier.verify(&VerifyContext {
                        chain: &flight.chain,
                        sni: self.server_name,
                        version: TlsVersion::Tls13,
                        suite: sh.suite,
                        signature_scheme: flight.signature_scheme,
                        signature,
                        signed: super::SignedData::Tls13Hash(&th[..th_len]),
                    })?;
                    AuthOutcome::Ok
                }
                ServerAuth::Reality { auth_key, mldsa65 } => {
                    let Some(cert) = flight.chain.first() else {
                        return Err(TlsError::Verify(
                            "REALITY server sent no certificate".into(),
                        ));
                    };
                    let mldsa = mldsa65.map(|public_key| crate::reality::verify::Mldsa65 {
                        public_key,
                        client_hello: &self.current_hello,
                        server_hello: &sh.raw,
                    });
                    match crate::reality::verify::verify_server(
                        cert,
                        &flight.cv_raw,
                        auth_key,
                        &th[..th_len],
                        mldsa.as_ref(),
                    ) {
                        Ok(()) => AuthOutcome::Ok,
                        Err(_) => AuthOutcome::RealityFallback,
                    }
                }
            }
        };
        if !self.resumed {
            ks.add_transcript(&flight.cv_raw);
        }
        let server_finished_key = ks.finished_key(&self.server_hs_ts[..self.hash_len])?;
        if !bool::from(
            ks.finished_mac(&server_finished_key[..self.hash_len])
                .ct_eq(&flight.sf_verify_data),
        ) {
            return Err(TlsError::Handshake("server Finished MAC mismatch".into()));
        }
        ks.add_transcript(&make_hs_msg(HS_FINISHED, &flight.sf_verify_data));
        // Client EncryptedExtensions (ALPS) is handshake-key protected, hashed
        // before the client Finished, and carries the client settings blob
        // (empty for h2). Only after the server acknowledged ALPS.
        let mut hs_write_seq = 0u64;
        if flight.server_alps.is_some()
            && flight.negotiated_alpn.is_some()
            && let Some((ty, _)) = client_alps(&self.current_hello)
        {
            let key = self
                .client_hs_key
                .as_ref()
                .ok_or_else(|| TlsError::Handshake("client handshake key missing".into()))?;
            let (msg, record) = seal_client_ee(key, ty, &[], hs_write_seq)?;
            ks.add_transcript(&msg);
            self.out.extend_from_slice(&record);
            hs_write_seq += 1;
        }
        let client_finished_key = ks.finished_key(&self.client_hs_ts[..self.hash_len])?;
        let mac = ks.finished_mac(&client_finished_key[..self.hash_len]);
        let msg = make_hs_msg(HS_FINISHED, &mac);
        let ct_len = msg.len() + 1 + AEAD_TAG_LEN;
        let mut record = Vec::with_capacity(5 + ct_len);
        record.extend_from_slice(&[CONTENT_APPLICATION_DATA, 0x03, 0x03]);
        record.extend_from_slice(
            &u16::try_from(ct_len)
                .map_err(|_| TlsError::Handshake("client Finished too long".into()))?
                .to_be_bytes(),
        );
        record.extend_from_slice(&msg);
        record.push(CONTENT_HANDSHAKE);
        self.client_hs_key
            .as_ref()
            .ok_or_else(|| TlsError::Handshake("client handshake key missing".into()))?
            .seal_in_place(hs_write_seq, &aead_aad(ct_len), &mut record, 5)?;
        self.out.extend_from_slice(&record);

        let master = ks.master_secret(&self.hs_secret[..self.hash_len])?;
        let (client_app_ts, server_app_ts) = ks.app_traffic_secrets(&master[..self.hash_len])?;
        let client_key = AeadKey::new(sh.suite, &client_app_ts[..self.hash_len])?;
        let server_key = AeadKey::new(sh.suite, &server_app_ts[..self.hash_len])?;
        // `resumption_master_secret` covers ClientHello..client Finished.
        ks.add_transcript(&make_hs_msg(HS_FINISHED, &mac));
        let res_master = ks.derive_secret(&master[..self.hash_len], "res master")?;
        let secrets = AppSecrets::new(
            sh.suite,
            &client_app_ts[..self.hash_len],
            &server_app_ts[..self.hash_len],
        )
        .with_resumption_master(&res_master[..self.hash_len]);
        let keys = AppKeys::tls13(server_key, client_key);
        self.established = Some(Established {
            keys,
            secrets: Some(secrets),
            alpn: flight.negotiated_alpn.clone(),
            hybrid: sh.mlkem_ciphertext.is_some(),
            auth: outcome,
            resumed: self.resumed,
        });
        self.phase = Phase::Done;
        Ok(())
    }
}

fn seal_client_ee(key: &AeadKey, ty: u16, body: &[u8], seq: u64) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&ty.to_be_bytes());
    ext.extend_from_slice(
        &u16::try_from(body.len())
            .map_err(|_| TlsError::Handshake("ALPS body too long".into()))?
            .to_be_bytes(),
    );
    ext.extend_from_slice(body);
    let mut ee = Vec::with_capacity(2 + ext.len());
    ee.extend_from_slice(
        &u16::try_from(ext.len())
            .map_err(|_| TlsError::Handshake("ALPS extension list too long".into()))?
            .to_be_bytes(),
    );
    ee.extend_from_slice(&ext);
    let msg = make_hs_msg(0x08, &ee);
    let ct_len = msg.len() + 1 + AEAD_TAG_LEN;
    let mut record = Vec::with_capacity(5 + ct_len);
    record.extend_from_slice(&[CONTENT_APPLICATION_DATA, 0x03, 0x03]);
    record.extend_from_slice(
        &u16::try_from(ct_len)
            .map_err(|_| TlsError::Handshake("ALPS record too long".into()))?
            .to_be_bytes(),
    );
    record.extend_from_slice(&msg);
    record.push(CONTENT_HANDSHAKE);
    key.seal_in_place(seq, &aead_aad(ct_len), &mut record, 5)?;
    Ok((msg, record))
}
fn client_alps(hello: &[u8]) -> Option<(u16, Vec<u8>)> {
    for ty in [0x44cd, 0x4469] {
        if let Some(body) = super::client_hello_extension(hello, ty) {
            return Some((ty, body.to_vec()));
        }
    }
    None
}

fn take_record(inbuf: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>> {
    if inbuf.len() < 5 {
        return Ok(None);
    }
    let ty = inbuf[0];
    if let Some(text) =
        crate::record::cleartext_hello_answer([inbuf[0], inbuf[1], inbuf[2], inbuf[3], inbuf[4]])
    {
        return Err(TlsError::CleartextPeer(format!("{text:?}")));
    }
    let len = usize::from(u16::from_be_bytes([inbuf[3], inbuf[4]]));
    if len > MAX_RECORD_PAYLOAD {
        return Err(TlsError::Handshake(format!(
            "TLS record too large: {len} bytes"
        )));
    }
    if inbuf.len() < 5 + len {
        return Ok(None);
    }
    let payload = inbuf[5..5 + len].to_vec();
    inbuf.drain(..5 + len);
    Ok(Some((ty, payload)))
}

fn first_handshake_message(payload: &[u8]) -> Result<(Vec<u8>, &[u8], Vec<u8>)> {
    let msgs = parse_handshake_messages(payload)?;
    let (ty, body) = msgs
        .first()
        .ok_or_else(|| TlsError::Handshake("empty handshake record".into()))?;
    if *ty != HS_SERVER_HELLO {
        return Err(TlsError::Handshake(format!(
            "expected ServerHello (0x02), got 0x{ty:02X}"
        )));
    }
    let total = 4 + body.len();
    Ok((
        payload[..total].to_vec(),
        &payload[4..total],
        payload[total..].to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;

    use super::*;
    use crate::handshake::AcceptAll;
    use crate::hello::{BuildParams, RecordingRng, build_hello_ordered};
    use crate::record::make_handshake_record;
    use crate::spec::{ClientHelloSpec, ExtensionSpec, KeyShareGroup, SessionIdSpec};

    fn spec() -> ClientHelloSpec {
        ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301, 0xc02f],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![
                ExtensionSpec::ServerName,
                ExtensionSpec::SupportedGroups(vec![0x001D, 0x11EC]),
                ExtensionSpec::KeyShare(vec![KeyShareGroup::X25519]),
                ExtensionSpec::SupportedVersions(vec![0x0304, 0x0303]),
                ExtensionSpec::SignatureAlgorithms(vec![0x0403]),
                ExtensionSpec::Alpn(vec!["h2".into()]),
                ExtensionSpec::Raw {
                    ty: 0x0017,
                    data: Vec::new(),
                },
            ],
        }
    }

    fn hello_and_keypair() -> (
        crate::hello::BuiltHello,
        X25519KeyPair,
        RecordingRng<'static>,
        [u8; 32],
    ) {
        let rng = Box::leak(Box::new(SystemRandom::new()));
        let keypair = X25519KeyPair::generate(rng).unwrap();
        let pubkey = keypair.public_key();
        let recording = RecordingRng::new(rng);
        let hello = build_hello_ordered(
            &spec(),
            &BuildParams {
                server_name: "localhost",
                alpn: None,
                x25519_pub: &pubkey,
                mlkem768_pub: None,
                rng: &recording,
            },
            false,
        )
        .unwrap();
        (hello, keypair, recording, pubkey)
    }

    fn tls12_server_hello(sid: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(u8::try_from(sid.len()).unwrap());
        body.extend_from_slice(sid);
        body.extend_from_slice(&0xc02fu16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0x0017u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        make_handshake_record(HS_SERVER_HELLO, &body)
    }

    #[test]
    fn tls12_server_hello_hands_off() {
        let (hello, keypair, recording, pubkey) = hello_and_keypair();
        let retry = RetrySupport {
            permute_extensions: false,
            spec: &spec(),
            server_name: "localhost",
            alpn: None,
            x25519_pub: &pubkey,
            draws: &recording,
            rng: &SystemRandom::new(),
        };
        let mut state = Handshake::new(
            &hello.handshake_bytes,
            hello.session_id(),
            keypair,
            None,
            "localhost",
            ServerAuth::Verifier(&AcceptAll),
            Some(&retry),
            None,
            None,
        );
        state.start().unwrap();
        let mut out = Vec::new();
        assert!(state.poll_transmit(&mut out), "ClientHello must be queued");
        let record = tls12_server_hello(hello.session_id());
        // Deliver in two pieces: nothing may be handed off early.
        state.feed(&record[..7]).unwrap();
        assert!(state.take_handoff().is_none());
        state.feed(&record[7..]).unwrap();
        let handoff = state.take_handoff().expect("TLS 1.2 handoff");
        assert!(handoff.server_hello.suite12.is_some());
        assert_eq!(handoff.pre_buffer.len(), 0);
        assert_eq!(handoff.current_hello, hello.handshake_bytes);
    }

    #[test]
    fn arbitrary_bytes_never_panic_or_grow_unbounded() {
        let (hello, keypair, recording, pubkey) = hello_and_keypair();
        let retry = RetrySupport {
            permute_extensions: false,
            spec: &spec(),
            server_name: "localhost",
            alpn: None,
            x25519_pub: &pubkey,
            draws: &recording,
            rng: &SystemRandom::new(),
        };
        let mut state = Handshake::new(
            &hello.handshake_bytes,
            hello.session_id(),
            keypair,
            None,
            "localhost",
            ServerAuth::Verifier(&AcceptAll),
            Some(&retry),
            None,
            None,
        );
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut total_out = 0usize;
        for _ in 0..512 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let len = usize::try_from(seed % 64).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from((seed >> (i % 8 * 8)) & 0xff).unwrap())
                .collect();
            let _ = state.feed(&bytes);
            let mut out = Vec::new();
            state.poll_transmit(&mut out);
            total_out += out.len();
            assert!(
                total_out <= 256 * 1024,
                "state machine output grew without bound"
            );
            if state.take_established().is_some() || state.take_handoff().is_some() {
                break;
            }
        }
    }

    #[test]
    fn alps_record_uses_the_handshake_key_and_an_empty_blob() {
        let key = AeadKey::from_key_bytes(crate::crypto::CipherSuiteId::Aes128GcmSha256, &[7; 16])
            .unwrap();
        let (msg, mut record) = seal_client_ee(&key, 0x44cd, &[], 0).unwrap();
        assert_eq!(msg[0], 0x08, "client EncryptedExtensions");
        let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
        let mut body = record.split_off(5);
        assert_eq!(body.len(), len);
        let plain = key.open_in_place(0, &aead_aad(len), &mut body).unwrap();
        let (inner, content) = crate::record::engine::strip_padding(&body[..plain]).unwrap();
        assert_eq!(inner, CONTENT_HANDSHAKE);
        assert_eq!(&content[6..10], &[0x44, 0xcd, 0x00, 0x00]);
    }

    #[test]
    fn chrome_hello_carries_alps() {
        let rng = SystemRandom::new();
        let keypair = X25519KeyPair::generate(&rng).unwrap();
        let recording = RecordingRng::new(&rng);
        let hello = build_hello_ordered(
            &crate::profiles::hand_selected::chrome_130(),
            &BuildParams {
                server_name: "localhost",
                alpn: None,
                x25519_pub: &keypair.public_key(),
                mlkem768_pub: None,
                rng: &recording,
            },
            false,
        )
        .unwrap();
        let parsed = crate::hello::parse::parse_hello(&hello.handshake_bytes).unwrap();
        assert!(
            parsed.extension(0x002d).is_some(),
            "Chrome hello must offer psk_key_exchange_modes"
        );
        let (ty, body) = client_alps(&hello.handshake_bytes).expect("chrome offers ALPS");
        assert!(ty == 0x4469 || ty == 0x44cd);
        assert_ne!(body.len(), 0);
    }

    #[test]
    fn server_selecting_an_unoffered_psk_is_rejected() {
        let (hello, keypair, recording, pubkey) = hello_and_keypair();
        let retry = RetrySupport {
            permute_extensions: false,
            spec: &spec(),
            server_name: "localhost",
            alpn: None,
            x25519_pub: &pubkey,
            draws: &recording,
            rng: &SystemRandom::new(),
        };
        let mut state = Handshake::new(
            &hello.handshake_bytes,
            hello.session_id(),
            keypair,
            None,
            "localhost",
            ServerAuth::Verifier(&AcceptAll),
            Some(&retry),
            None,
            None,
        );
        state.start().unwrap();
        let mut out = Vec::new();
        state.poll_transmit(&mut out);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(u8::try_from(hello.session_id().len()).unwrap());
        body.extend_from_slice(hello.session_id());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        let key_share = {
            let mut d = vec![0x00, 0x1D, 0x00, 0x20];
            d.extend_from_slice(&[0x44; 32]);
            d
        };
        let exts = [
            (0x002bu16, vec![0x03, 0x04]),
            (0x0033u16, key_share),
            (0x0029u16, vec![0x00, 0x00]),
        ];
        let mut ext_bytes = Vec::new();
        for (ty, data) in exts {
            ext_bytes.extend_from_slice(&ty.to_be_bytes());
            ext_bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            ext_bytes.extend_from_slice(&data);
        }
        body.extend_from_slice(&u16::try_from(ext_bytes.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&ext_bytes);
        let err = state
            .feed(&make_handshake_record(HS_SERVER_HELLO, &body))
            .unwrap_err();
        assert!(
            err.to_string().contains("did not offer")
                || err.to_string().contains("unsolicited extension 0x0029"),
            "{err}"
        );
    }

    #[test]
    fn ech_rejection_is_terminal() {
        let (hello, keypair, recording, pubkey) = hello_and_keypair();
        let retry = RetrySupport {
            permute_extensions: false,
            spec: &spec(),
            server_name: "localhost",
            alpn: None,
            x25519_pub: &pubkey,
            draws: &recording,
            rng: &SystemRandom::new(),
        };
        let ech = crate::ech::EchState {
            inner_random: [0x33; 32],
            inner_hello: hello.handshake_bytes.clone(),
        };
        let outer = hello.handshake_bytes.clone();
        let mut state = Handshake::new(
            &hello.handshake_bytes,
            hello.session_id(),
            keypair,
            None,
            "localhost",
            ServerAuth::Verifier(&AcceptAll),
            Some(&retry),
            Some((&outer, &ech)),
            None,
        );
        state.start().unwrap();
        let mut out = Vec::new();
        state.poll_transmit(&mut out);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(u8::try_from(hello.session_id().len()).unwrap());
        body.extend_from_slice(hello.session_id());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        let exts = [
            (0x002bu16, vec![0x03, 0x04]),
            (0x0033u16, {
                let mut d = vec![0x00, 0x1D, 0x00, 0x20];
                d.extend_from_slice(&[0x44; 32]);
                d
            }),
        ];
        let mut ext_bytes = Vec::new();
        for (ty, data) in exts {
            ext_bytes.extend_from_slice(&ty.to_be_bytes());
            ext_bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            ext_bytes.extend_from_slice(&data);
        }
        body.extend_from_slice(&u16::try_from(ext_bytes.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&ext_bytes);
        let err = state
            .feed(&make_handshake_record(HS_SERVER_HELLO, &body))
            .unwrap_err();
        assert!(err.to_string().contains("encrypted client hello"), "{err}");
    }

    #[test]
    fn hello_retry_request_queues_client_hello_two() {
        let (hello, keypair, recording, pubkey) = hello_and_keypair();
        let retry_spec = spec();
        let retry = RetrySupport {
            permute_extensions: false,
            spec: &retry_spec,
            server_name: "localhost",
            alpn: None,
            x25519_pub: &pubkey,
            draws: &recording,
            rng: &SystemRandom::new(),
        };
        let mut state = Handshake::new(
            &hello.handshake_bytes,
            hello.session_id(),
            keypair,
            None,
            "localhost",
            ServerAuth::Verifier(&AcceptAll),
            Some(&retry),
            None,
            None,
        );
        state.start().unwrap();
        let mut out = Vec::new();
        state.poll_transmit(&mut out);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&crate::handshake::HRR_RANDOM);
        body.push(u8::try_from(hello.session_id().len()).unwrap());
        body.extend_from_slice(hello.session_id());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        let exts = [(0x002bu16, vec![0x03, 0x04]), (0x0033u16, vec![0x11, 0xEC])];
        let mut ext_bytes = Vec::new();
        for (ty, data) in exts {
            ext_bytes.extend_from_slice(&ty.to_be_bytes());
            ext_bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            ext_bytes.extend_from_slice(&data);
        }
        body.extend_from_slice(&u16::try_from(ext_bytes.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&ext_bytes);
        state
            .feed(&make_handshake_record(HS_SERVER_HELLO, &body))
            .unwrap();
        out.clear();
        assert!(state.poll_transmit(&mut out), "ClientHello2 must be queued");
        assert!(out.len() > 5);
        assert!(state.take_established().is_none());
    }
}
