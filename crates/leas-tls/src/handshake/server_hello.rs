//! `ServerHello` / `HelloRetryRequest` parsing and record reading.

use super::{
    AsyncRead, CONTENT_HANDSHAKE, Ciphertext, CipherSuiteId, HS_SERVER_HELLO, ParsedReply, Result,
    Tls12Suite, TlsError, TlsVersion, parse_handshake_messages, parse_server_hello, skip_ccs,
};

// ── ServerHello ────────────────────────────────────────────────────────────

/// A parsed `ServerHello` — carries fields for both TLS 1.3 and 1.2.
pub struct ServerHelloData {
    /// The raw handshake message (type + length + body), for the transcript.
    pub raw: Vec<u8>,
    /// Handshake bytes after the `ServerHello` in the same record (valid in
    /// TLS 1.2, RFC 5246 §6.2.1 — a server may pack `ServerHello` + the rest
    /// of the flight into one record). Consumed by the TLS 1.2 flight
    /// reader; empty for TLS 1.3 (`ServerHello` is always alone).
    pub pre_buffer: Vec<u8>,
    /// The negotiated version.
    pub version: TlsVersion,
    /// The server's 32-byte random.
    pub server_random: [u8; 32],
    /// The server's classical (X25519) public key from `key_share` (TLS 1.3).
    pub peer_key: Option<[u8; 32]>,
    /// The ML-KEM ciphertext from the server's hybrid key share (TLS 1.3),
    /// validated at parse so the handshake decapsulates it with no re-copy.
    pub mlkem_ciphertext: Option<Ciphertext>,
    /// The cipher suite the server selected (TLS 1.3).
    pub suite: CipherSuiteId,
    /// The cipher suite the server selected (TLS 1.2).
    pub suite12: Option<Tls12Suite>,
    /// Whether the server echoed `extended_master_secret` (TLS 1.2).
    pub ems: bool,
}

/// The `ServerHello` body fields the engine needs.
#[derive(Debug)]
pub struct ParsedServerHello {
    pub version: TlsVersion,
    pub server_random: [u8; 32],
    pub suite: CipherSuiteId,
    pub suite12: Option<Tls12Suite>,
    pub peer_key: Option<[u8; 32]>,
    pub mlkem_ciphertext: Option<Ciphertext>,
    pub ems: bool,
}

/// A parsed `HelloRetryRequest` (RFC 8446 §4.1.4): the server wants a
/// different key-exchange group and/or wants us to echo a cookie.
#[derive(Debug)]
pub struct HrrData {
    /// The raw handshake message (type + length + body): RFC 8446 §4.4.1 puts
    /// the `HelloRetryRequest` itself in the transcript.
    pub raw: Vec<u8>,
    /// The group the server wants a `key_share` for (RFC 8446 §4.2.8.2: an
    /// HRR carries only `selected_group`, no key exchange).
    pub selected_group: Option<u16>,
    /// The opaque cookie to echo in `ClientHello2` (RFC 8446 §4.2.2).
    pub cookie: Option<Vec<u8>>,
}

/// What the record after the `ClientHello` turned out to be.
pub enum ServerReply {
    /// A real `ServerHello` — the handshake continues.
    Hello(Box<ServerHelloData>),
    /// A `HelloRetryRequest` — one retry may follow.
    Retry(HrrData),
}

/// Read and parse the `ServerHello` record, skipping CCS records. The
/// server must echo the offered legacy session id (RFC 8446 §4.1.3).
pub async fn read_server_hello<S>(
    stream: &mut S,
    offered_session_id: &[u8],
) -> Result<ServerReply>
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
    match parsed {
        ParsedReply::Retry(hrr) => Ok(ServerReply::Retry(HrrData { raw, ..hrr })),
        ParsedReply::Hello(parsed) => Ok(ServerReply::Hello(Box::new(ServerHelloData {
            raw,
            pre_buffer,
            version: parsed.version,
            server_random: parsed.server_random,
            peer_key: parsed.peer_key,
            mlkem_ciphertext: parsed.mlkem_ciphertext,
            suite: parsed.suite,
            suite12: parsed.suite12,
            ems: parsed.ems,
        }))),
    }
}
