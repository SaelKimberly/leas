//! `DNSCrypt` v2 client for server stamps (`sdns://` protocol `0x01`).
//!
//! The construction is fixed by <https://dnscrypt.info/protocol> and the
//! reference implementation in `thirdparty/dnscrypt` (AdguardTeam/dnscrypt).
//! The AEAD is `NaCl` secretbox — `Poly1305` over the ciphertext alone, tag first —
//! which no `RustCrypto` AEAD crate provides: `chacha20poly1305` follows RFC 8439,
//! whose `Poly1305` input includes the length blocks. Cause C1 in
//! `docs/reference/crypto-dependencies.md`; the vectors below are Go-generated
//! from that reference implementation.
//!
//! Server stamps only: Anonymized `DNSCrypt` relays (`0x81`) are out of scope.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use futures_util::StreamExt;
use hickory_resolver::ConnectionProvider;
use hickory_resolver::PoolContext;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::{DnsExchange, DnsHandle, DnsResponseStream};
use hickory_resolver::proto::op::{DnsRequest, DnsResponse, Message, Query};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, UnparsedPublicKey as SignatureKey};
use salsa20::XSalsa20;
use salsa20::cipher::consts::U10;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use zeroize::Zeroizing;

use crate::stamp_addr_allowed;

/// Protocol byte of a `DNSCrypt` server stamp.
const STAMP_DNSCRYPT: u8 = 0x01;
/// Stamp property bits required of every resolver this client installs.
const PROP_NO_LOGS: u64 = 0x02;
const PROP_NO_FILTER: u64 = 0x04;
/// Port used when a stamp names no port.
const DEFAULT_PORT: u16 = 443;

/// Prefix of every `DNSCrypt` resolver response.
const RESOLVER_MAGIC: [u8; 8] = *b"r6fnvWj8";
/// Queries are padded to a multiple of this, and to at least [`QUERY_MIN_PAD`].
const PAD_BLOCK: usize = 64;
const QUERY_MIN_PAD: usize = 256;
/// A DNS header plus the root question.
const MIN_DNS_PACKET: usize = 17;
const UDP_BUF_SIZE: usize = 4096;

/// A `DNSCrypt` resolver endpoint from a server stamp.
#[derive(Clone, Debug)]
pub struct DnsCryptServer {
    pub(crate) addr: SocketAddr,
    pub(crate) provider_name: String,
    pub(crate) provider_pk: [u8; 32],
}

/// Decodes a `sdns://` `DNSCrypt` server stamp.
///
/// Returns `None` for any other stamp kind, for a stamp whose properties do not
/// claim no logs and no filtering, and for an address the local-use policy
/// refuses (the same policy [`crate::stamp_addr_allowed`] applies).
pub fn parse_stamp(stamp: &str) -> Option<DnsCryptServer> {
    let bytes = URL_SAFE_NO_PAD
        .decode(stamp.strip_prefix("sdns://")?)
        .ok()?;
    let (&protocol, rest) = bytes.split_first()?;
    if protocol != STAMP_DNSCRYPT {
        return None;
    }
    let (props, mut rest) = rest.split_first_chunk::<8>()?;
    let props = u64::from_le_bytes(*props);
    if props & (PROP_NO_LOGS | PROP_NO_FILTER) != (PROP_NO_LOGS | PROP_NO_FILTER) {
        return None;
    }
    let addr = std::str::from_utf8(length_prefixed(&mut rest)?).ok()?;
    let addr = parse_addr(addr)?;
    if !addr.is_ipv4() || !stamp_addr_allowed(addr.ip()) {
        return None;
    }
    let provider_pk: [u8; 32] = length_prefixed(&mut rest)?.try_into().ok()?;
    let provider_name = std::str::from_utf8(length_prefixed(&mut rest)?)
        .ok()?
        .to_owned();
    if !rest.is_empty() {
        return None;
    }
    Some(DnsCryptServer {
        addr,
        provider_name,
        provider_pk,
    })
}

fn length_prefixed<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (&len, tail) = rest.split_first()?;
    let (head, tail) = tail.split_at_checked(usize::from(len))?;
    *rest = tail;
    Some(head)
}

/// `1.2.3.4[:port]` or `[v6][:port]`; the stamp omits the default port.
fn parse_addr(raw: &str) -> Option<SocketAddr> {
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Some(addr);
    }
    raw.parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, DEFAULT_PORT))
}

/// The AEAD construction a certificate selects, ordered by preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Suite {
    XSalsa20Poly1305,
    XChaCha20Poly1305,
}

/// A signature-verified resolver certificate.
#[derive(Clone, Copy, Debug)]
struct Cert {
    resolver_pk: [u8; 32],
    client_magic: [u8; 8],
    serial: u32,
    ts_end: u32,
    suite: Suite,
}

/// Parses and verifies a 124-byte certificate against the stamp's provider key.
///
/// Layout: `"DNSC" | es-version u16 | minor u16 | signature[64] | resolver-pk[32]
/// | client-magic[8] | serial u32 | ts-start u32 | ts-end u32`; the signature
/// covers everything after it.
fn parse_cert(raw: &[u8], provider_pk: &[u8; 32], now: u64) -> Option<Cert> {
    if raw.len() < 124 || raw.get(..4)? != b"DNSC" {
        return None;
    }
    let suite = match raw.get(4..6)? {
        [0x00, 0x01] => Suite::XSalsa20Poly1305,
        [0x00, 0x02] => Suite::XChaCha20Poly1305,
        _ => return None,
    };
    SignatureKey::new(&ED25519, provider_pk)
        .verify(raw.get(72..)?, raw.get(8..72)?)
        .ok()?;
    let be_u32 = |at: usize| Some(u32::from_be_bytes(raw.get(at..at + 4)?.try_into().ok()?));
    let (ts_start, ts_end) = (be_u32(116)?, be_u32(120)?);
    if now < u64::from(ts_start) || now > u64::from(ts_end) {
        return None;
    }
    Some(Cert {
        resolver_pk: raw.get(72..104)?.try_into().ok()?,
        client_magic: raw.get(104..112)?.try_into().ok()?,
        serial: be_u32(112)?,
        ts_end,
        suite,
    })
}

impl Suite {
    /// Derives the session key from the raw `X25519` secret: `HSalsa20` /
    /// `HChaCha20` over an all-zero input, as `crypto_box_beforenm` does.
    fn derive_key(self, shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let zero = [0u8; 16];
        let key = match self {
            Self::XChaCha20Poly1305 => {
                chacha20::hchacha::<chacha20::R20>(shared.into(), (&zero).into())
            }
            Self::XSalsa20Poly1305 => salsa20::hsalsa::<U10>(shared.into(), (&zero).into()),
        };
        Zeroizing::new(key.into())
    }

    /// Encrypts with `NaCl` secretbox: `tag[16] | ciphertext`.
    fn seal(self, key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Vec<u8> {
        match self {
            Self::XChaCha20Poly1305 => {
                seal_with(XChaCha20::new(key.into(), nonce.into()), plaintext)
            }
            Self::XSalsa20Poly1305 => seal_with(XSalsa20::new(key.into(), nonce.into()), plaintext),
        }
    }

    fn open(self, key: &[u8; 32], nonce: &[u8; 24], sealed: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::XChaCha20Poly1305 => open_with(XChaCha20::new(key.into(), nonce.into()), sealed),
            Self::XSalsa20Poly1305 => open_with(XSalsa20::new(key.into(), nonce.into()), sealed),
        }
    }
}

/// The first 32 keystream bytes are the one-time `Poly1305` key.
fn poly_key(cipher: &mut impl StreamCipher) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(key.as_mut());
    key
}

fn seal_with(mut cipher: impl StreamCipher, plaintext: &[u8]) -> Vec<u8> {
    let key = poly_key(&mut cipher);
    let mut out = vec![0u8; 16];
    out.extend_from_slice(plaintext);
    let (tag, body) = out.split_at_mut(16);
    cipher.apply_keystream(body);
    let mac = Poly1305::new((&*key).into()).compute_unpadded(body);
    tag.copy_from_slice(&mac);
    out
}

fn open_with(mut cipher: impl StreamCipher, sealed: &[u8]) -> Option<Vec<u8>> {
    let (tag, body) = sealed.split_first_chunk::<16>()?;
    let key = poly_key(&mut cipher);
    let expected = Poly1305::new((&*key).into()).compute_unpadded(body);
    if !bool::from(tag.ct_eq(&expected)) {
        return None;
    }
    let mut plaintext = body.to_vec();
    cipher.apply_keystream(&mut plaintext);
    Some(plaintext)
}

/// `ISO/IEC 7816-4` padding: `0x80` then zeros, to a multiple of 64 and at least
/// 256 bytes (the spec's UDP minimum; the reference client pads TCP the same).
fn pad(packet: &[u8]) -> Vec<u8> {
    let mut padded = Vec::with_capacity(packet.len().max(QUERY_MIN_PAD) + PAD_BLOCK);
    padded.extend_from_slice(packet);
    padded.push(0x80);
    while padded.len() % PAD_BLOCK != 0 || padded.len() < QUERY_MIN_PAD {
        padded.push(0);
    }
    padded
}

fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let end = padded.iter().rposition(|&b| b != 0)?;
    if padded[end] != 0x80 || end < MIN_DNS_PACKET {
        return None;
    }
    Some(&padded[..end])
}

/// One established resolver session: keys, magic and certificate expiry.
struct Session {
    addr: SocketAddr,
    client_pk: [u8; 32],
    client_magic: [u8; 8],
    shared_key: Zeroizing<[u8; 32]>,
    suite: Suite,
    ts_end: u32,
}

impl Session {
    fn new(addr: SocketAddr, cert: &Cert) -> Option<Self> {
        let rng = SystemRandom::new();
        let ephemeral = EphemeralPrivateKey::generate(&agreement::X25519, &rng).ok()?;
        let client_pk = ephemeral
            .compute_public_key()
            .ok()?
            .as_ref()
            .try_into()
            .ok()?;
        let peer = UnparsedPublicKey::new(&agreement::X25519, cert.resolver_pk);
        let shared: [u8; 32] =
            agreement::agree_ephemeral(ephemeral, &peer, |secret| secret.try_into().ok())
                .ok()??;
        Some(Self {
            addr,
            client_pk,
            client_magic: cert.client_magic,
            shared_key: cert.suite.derive_key(&shared),
            suite: cert.suite,
            ts_end: cert.ts_end,
        })
    }

    fn is_valid_at(&self, now: u64) -> bool {
        now < u64::from(self.ts_end)
    }

    /// Builds the encrypted query for `packet` under `nonce`.
    ///
    /// Layout: `client-magic | client-pk | client-nonce[..12] | AE(padded)`.
    fn encrypt_query(&self, packet: &[u8], nonce: &[u8; 24]) -> Vec<u8> {
        let padded = pad(packet);
        let mut out = Vec::with_capacity(52 + padded.len() + 16);
        out.extend_from_slice(&self.client_magic);
        out.extend_from_slice(&self.client_pk);
        out.extend_from_slice(&nonce[..12]);
        out.extend_from_slice(&self.suite.seal(&self.shared_key, nonce, &padded));
        out
    }

    /// Verifies the resolver magic and nonce echo, then decrypts and unpads.
    fn decrypt_response(&self, response: &[u8], client_nonce: &[u8; 24]) -> Option<Vec<u8>> {
        let rest = response.strip_prefix(&RESOLVER_MAGIC)?;
        let (nonce, sealed) = rest.split_first_chunk::<24>()?;
        if nonce[..12] != client_nonce[..12] {
            return None;
        }
        let plain = self.suite.open(&self.shared_key, nonce, sealed)?;
        unpad(&plain).map(<[u8]>::to_vec)
    }

    /// Sends `packet`, falling back to TCP on a network failure or truncation.
    ///
    /// `budget` is hickory's per-request timeout: the UDP attempt gets half,
    /// the TCP retry a full one, because a TCP-only network must still reach a
    /// distant resolver. A dead resolver therefore costs at most 1.5x the pool
    /// timeout, not the multi-second UDP+TCP sequence it would otherwise.
    async fn exchange(&self, packet: &[u8], budget: Duration) -> anyhow::Result<Vec<u8>> {
        let udp_budget = budget / 2;
        let nonce = fresh_nonce()?;
        let request = self.encrypt_query(packet, &nonce);
        if let Ok(response) = udp_exchange(self.addr, &request, udp_budget).await
            && let Some(plain) = self.decrypt_response(&response, &nonce)
            && !is_truncated(&plain)
        {
            return Ok(plain);
        }
        // A fresh nonce per attempt: one nonce is sealed once per key.
        let nonce = fresh_nonce()?;
        let request = self.encrypt_query(packet, &nonce);
        if budget.is_zero() {
            bail!("DNSCrypt exchange budget exhausted");
        }
        let response = tcp_exchange(self.addr, &request, budget).await?;
        self.decrypt_response(&response, &nonce)
            .ok_or_else(|| anyhow!("DNSCrypt response failed authentication"))
    }
}

/// A retryable transport failure. The pool's per-round match continues only
/// on `Io`/`NoConnections`/`Timeout` and records an SRTT failure for them;
/// `NetError::Msg` would abort the whole round instead of failing over.
fn transport_error(message: impl Into<String>) -> NetError {
    NetError::Io(Arc::new(io::Error::other(message.into())))
}

fn fresh_nonce() -> anyhow::Result<[u8; 24]> {
    let mut nonce = [0u8; 24];
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    nonce[..8].copy_from_slice(&u64::try_from(nanos).unwrap_or(u64::MAX).to_be_bytes());
    SystemRandom::new()
        .fill(&mut nonce[8..12])
        .map_err(|_| anyhow!("OS random generator unavailable"))?;
    Ok(nonce)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The TC bit of a DNS header.
fn is_truncated(packet: &[u8]) -> bool {
    packet.get(2).is_some_and(|flags| flags & 0x02 != 0)
}

async fn udp_exchange(
    addr: SocketAddr,
    request: &[u8],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(addr).await?;
    socket.send(request).await?;
    let mut buf = vec![0u8; UDP_BUF_SIZE];
    let len = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .context("DNSCrypt UDP timeout")??;
    buf.truncate(len);
    Ok(buf)
}

async fn tcp_exchange(
    addr: SocketAddr,
    request: &[u8],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    // The whole exchange is bounded, not just the connect: a resolver that
    // completes the handshake and then stalls must not wedge the lookup.
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await?;
        let len = u16::try_from(request.len()).context("DNSCrypt query over 64 KiB")?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(request).await?;
        let mut len_bytes = [0u8; 2];
        stream.read_exact(&mut len_bytes).await?;
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len_bytes))];
        stream.read_exact(&mut buf).await?;
        Ok::<Vec<u8>, anyhow::Error>(buf)
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .context("DNSCrypt TCP timeout")?
}

/// Fetches and verifies the resolver certificate over plain DNS.
async fn fetch_cert(server: &DnsCryptServer, timeout: Duration) -> anyhow::Result<Cert> {
    let name = Name::from_ascii(provider_fqdn(&server.provider_name))?;
    let mut message = Message::query();
    message.add_query(Query::query(name, RecordType::TXT));
    let query = message.to_vec()?;
    let response = match udp_exchange(server.addr, &query, timeout).await {
        Ok(response) if !is_truncated(&response) => response,
        _ => tcp_exchange(server.addr, &query, timeout).await?,
    };
    let message = Message::from_vec(&response).context("certificate response is not DNS")?;
    let now = unix_now();
    let mut best: Option<Cert> = None;
    for record in &message.answers {
        let RData::TXT(txt) = &record.data else {
            continue;
        };
        let mut raw = Vec::new();
        for segment in &txt.txt_data {
            raw.extend_from_slice(segment);
        }
        let Some(cert) = parse_cert(&raw, &server.provider_pk, now) else {
            continue;
        };
        if best.is_none_or(|current| (cert.serial, cert.suite) > (current.serial, current.suite)) {
            best = Some(cert);
        }
    }
    best.ok_or_else(|| anyhow!("no valid certificate for {}", server.provider_name))
}

fn provider_fqdn(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.'))
}

/// Fetches and verifies the certificate from one resolver. The UDP attempt
/// and the TCP fallback each get `timeout`, so a UDP-blocking network still
/// establishes; this runs once per connection, not per query.
async fn establish(server: &DnsCryptServer, timeout: Duration) -> anyhow::Result<Session> {
    let cert = fetch_cert(server, timeout).await?;
    Session::new(server.addr, &cert).ok_or_else(|| anyhow!("key agreement failed"))
}

/// The hickory name server entry that routes this resolver through
/// [`DnsCryptProvider`]. The protocol tag is a placeholder: the provider keys
/// on `(ip, port)` and never dials it as plain DNS. It is `Tcp`, not `Udp`,
/// because hickory sets its pool-wide `disable_udp` policy on any truncated
/// answer; a `Udp` tag would let one truncation retire every `DNSCrypt` server.
pub fn name_server_config(server: &DnsCryptServer) -> NameServerConfig {
    let mut connection = ConnectionConfig::tcp();
    connection.port = server.addr.port();
    NameServerConfig::new(server.addr.ip(), true, vec![connection])
}

/// A hickory connection speaking `DNSCrypt` to one resolver.
#[derive(Clone)]
pub struct DnsCryptHandle {
    addr: SocketAddr,
    session: Arc<Session>,
    /// hickory's per-request timeout, from [`PoolContext::options`].
    timeout: Duration,
}

impl DnsHandle for DnsCryptHandle {
    type Response = DnsResponseStream;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let this = self.clone();
        DnsResponseStream::from(Box::pin(async move { this.exchange(request).await }))
    }
}

impl DnsCryptHandle {
    async fn exchange(&self, request: DnsRequest) -> Result<DnsResponse, NetError> {
        if !self.session.is_valid_at(unix_now()) {
            // A failed connection is dropped by the name server, so the next
            // query re-fetches the certificate.
            return Err(transport_error("DNSCrypt certificate expired"));
        }
        let (message, _) = request.into_parts();
        let id = message.metadata.id;
        let query = message.to_vec().map_err(NetError::from)?;
        let plain = self
            .session
            .exchange(&query, self.timeout)
            .await
            .map_err(|error| transport_error(format!("DNSCrypt {}: {error:#}", self.addr)))?;
        let response = Message::from_vec(&plain)
            .map_err(|error| transport_error(format!("DNSCrypt answer is not DNS: {error}")))?;
        if response.metadata.id != id {
            return Err(transport_error("DNSCrypt response id mismatch"));
        }
        DnsResponse::from_message(response)
            .map_err(|error| transport_error(format!("DNSCrypt answer is not a response: {error}")))
    }
}

/// hickory [`ConnectionProvider`]: `DNSCrypt` for the endpoints in `servers`,
/// the stock transports for every other name server in the same pool.
#[derive(Clone)]
pub struct DnsCryptProvider {
    servers: Arc<HashMap<(IpAddr, u16), DnsCryptServer>>,
    runtime: TokioRuntimeProvider,
}

impl DnsCryptProvider {
    /// The `DNSCrypt` endpoint for a hickory name server, or `None` when the
    /// endpoint is served by the native transport.
    fn route(&self, ip: IpAddr, port: u16) -> Option<&DnsCryptServer> {
        self.servers.get(&(ip, port))
    }

    pub(crate) fn new(servers: &[DnsCryptServer]) -> Self {
        Self {
            servers: Arc::new(
                servers
                    .iter()
                    .map(|server| ((server.addr.ip(), server.addr.port()), server.clone()))
                    .collect(),
            ),
            runtime: TokioRuntimeProvider::default(),
        }
    }
}

impl ConnectionProvider for DnsCryptProvider {
    type Conn = HybridConn;
    type FutureConn = Pin<Box<dyn Future<Output = Result<Self::Conn, NetError>> + Send>>;
    type RuntimeProvider = TokioRuntimeProvider;

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        // The tag distinguishes our synthetic DNSCrypt entry from a native
        // one at the same endpoint: only `Tcp` is the placeholder.
        if matches!(config.protocol, ProtocolConfig::Tcp)
            && let Some(server) = self.route(ip, config.port).cloned()
        {
            let timeout = cx.options.timeout;
            return Ok(Box::pin(async move {
                let session = establish(&server, timeout).await.map_err(|error| {
                    transport_error(format!("DNSCrypt {}: {error:#}", server.addr))
                })?;
                Ok(HybridConn::DnsCrypt(DnsCryptHandle {
                    addr: server.addr,
                    session: Arc::new(session),
                    timeout,
                }))
            }));
        }
        let native = self.runtime.new_connection(ip, config, cx)?;
        Ok(Box::pin(
            async move { Ok(HybridConn::Native(native.await?)) },
        ))
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
}

/// One name server connection: hickory's own transport or `DNSCrypt`.
#[derive(Clone)]
pub enum HybridConn {
    Native(DnsExchange<TokioRuntimeProvider>),
    DnsCrypt(DnsCryptHandle),
}

impl DnsHandle for HybridConn {
    type Response = DnsResponseStream;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        match self {
            Self::Native(exchange) => {
                let mut responses = exchange.send(request);
                DnsResponseStream::from(Box::pin(async move {
                    responses.next().await.unwrap_or(Err(NetError::Timeout))
                }))
            }
            Self::DnsCrypt(handle) => handle.send(request),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
        hex_bytes(hex).try_into().expect("array length")
    }

    /// The OpenDNS certificate shipped by the reference implementation.
    const OPENDNS_CERT: &str = "444e534300010000c8e2453a489ccb2586da7f5da8ef1b750b24bf08efb0468511aba1db9a8e69a40aef1166a86453d266c5c2a9ab77f939bd319b3c82da402f9b1776992364180488b4e44b35e964b490bddabae825a24b0415a08be19d7ddb87a33cd77edf8e2f7163373861576f6f5dddb8605dddb8605fbeebe0";
    const OPENDNS_PROVIDER_PK: &str =
        "b7351140206f225d3e2bd822d7fd691ea1c33cc8d6668d0cbe04bfabca43fb79";
    const OPENDNS_VALID_AT: u64 = 1_580_000_000;

    /// A published `AdGuard` `DNSCrypt` stamp (`2.dnscrypt.unfiltered.ns1.adguard.com`).
    const ADGUARD_STAMP: &str = "sdns://AQcAAAAAAAAAEjk0LjE0MC4xNC4xNDA6NTQ0MyC16ETWuDo-PhJo62gfvqcN48X6aNvWiBQdvy7AZrLa-iUyLmRuc2NyeXB0LnVuZmlsdGVyZWQubnMxLmFkZ3VhcmQuY29t";
    /// A published `Quad9` stamp whose properties are `DNSSEC|NO_LOGS` only.
    const QUAD9_STAMP: &str = "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0";

    fn build_stamp(protocol: u8, props: u64, addr: &str, pk: &[u8], name: &str) -> String {
        let mut bytes = vec![protocol];
        bytes.extend_from_slice(&props.to_le_bytes());
        for field in [addr.as_bytes(), pk, name.as_bytes()] {
            bytes.push(u8::try_from(field.len()).expect("field length"));
            bytes.extend_from_slice(field);
        }
        format!("sdns://{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    #[test]
    fn stamp_parses_the_published_adguard_stamp() {
        let server = parse_stamp(ADGUARD_STAMP).expect("AdGuard stamp must parse");
        assert_eq!(server.addr, "94.140.14.140:5443".parse().expect("addr"));
        assert_eq!(
            server.provider_name,
            "2.dnscrypt.unfiltered.ns1.adguard.com"
        );
        assert_eq!(
            server.provider_pk,
            hex_array::<32>("b5e844d6b83a3e3e1268eb681fbea70de3c5fa68dbd688141dbf2ec066b2dafa")
        );
    }

    #[test]
    fn stamp_refuses_other_kinds_and_policy_violations() {
        let pk = hex_bytes(OPENDNS_PROVIDER_PK);
        // A DoH protocol byte, a loopback address, and missing
        // NO_LOGS|NO_FILTER are all refused.
        assert!(parse_stamp(&build_stamp(0x02, 7, "1.1.1.1", &pk, "x")).is_none());
        assert!(parse_stamp(&build_stamp(0x01, 7, "127.0.0.1:443", &pk, "x")).is_none());
        assert!(parse_stamp(&build_stamp(0x01, 0x03, "1.1.1.1", &pk, "x")).is_none());
        // The published Quad9 stamp is DNSSEC|NO_LOGS only; the policy requires
        // NO_FILTER too, matching the DoH/DoT/DoQ parser.
        assert!(parse_stamp(QUAD9_STAMP).is_none());
        assert!(parse_stamp(&build_stamp(0x01, 7, "1.1.1.1", &pk, "x")).is_some());
    }

    /// The provider keys on `(ip, port)`: that is what routes a hickory name
    /// server into `DNSCrypt` instead of the native transport.
    #[test]
    fn provider_routes_by_endpoint_and_tags_name_servers() {
        use hickory_resolver::config::ProtocolConfig;

        let server = DnsCryptServer {
            addr: "192.0.2.1:5443".parse().expect("addr"),
            provider_name: "2.dnscrypt-cert.example".to_owned(),
            provider_pk: [0x42; 32],
        };
        let provider = DnsCryptProvider::new(std::slice::from_ref(&server));
        assert_eq!(
            provider
                .route(server.addr.ip(), server.addr.port())
                .map(|found| found.addr),
            Some(server.addr)
        );
        // Same IP, different port; different IP, same port: both native.
        assert!(provider.route(server.addr.ip(), 443).is_none());
        assert!(
            provider
                .route("192.0.2.2".parse().expect("ip"), server.addr.port())
                .is_none()
        );

        let config = name_server_config(&server);
        assert_eq!(config.ip, server.addr.ip());
        assert_eq!(config.connections.len(), 1);
        assert_eq!(config.connections[0].port, server.addr.port());
        // Tcp, not Udp: hickory's pool-wide `disable_udp` must not retire the
        // whole DNSCrypt fleet on one truncated answer.
        assert!(matches!(
            config.connections[0].protocol,
            ProtocolConfig::Tcp
        ));
    }

    #[test]
    fn certificate_verifies_the_reference_vector() {
        let raw = hex_bytes(OPENDNS_CERT);
        let provider_pk = hex_array::<32>(OPENDNS_PROVIDER_PK);
        let cert = parse_cert(&raw, &provider_pk, OPENDNS_VALID_AT).expect("cert must verify");
        assert_eq!(cert.suite, Suite::XSalsa20Poly1305);
        assert_eq!(cert.serial, 1_574_811_744);
        assert_eq!(cert.ts_end, 1_606_347_744);
        assert_eq!(cert.client_magic, hex_array::<8>("7163373861576f6f"));
        assert_eq!(
            cert.resolver_pk,
            hex_array::<32>("88b4e44b35e964b490bddabae825a24b0415a08be19d7ddb87a33cd77edf8e2f")
        );
        // A wrong provider key, an expired certificate and a tampered signature
        // are all refused.
        assert!(parse_cert(&raw, &[0x42; 32], OPENDNS_VALID_AT).is_none());
        assert!(parse_cert(&raw, &provider_pk, 1_606_347_745).is_none());
        let mut tampered = raw;
        tampered[80] ^= 1;
        assert!(parse_cert(&tampered, &provider_pk, OPENDNS_VALID_AT).is_none());
    }

    /// Fixed `X25519` keypair from the Go generator: `sk = 1..=32`, peer
    /// `sk = 0xa0..0xbf`.
    const CLIENT_PK: &str = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
    const XSALSA_KEY: &str = "be2a85ab99cae8251db5dd19afeee3a14e1cdb0e871a06d4d65f0596e7b30906";
    const XCHACHA_KEY: &str = "b4f84d96ae7b9614011f0db0b96a70afe02ff37eda17785de4ee59f08d75c2f5";

    #[test]
    fn shared_key_derivation_matches_the_go_vectors() {
        let shared =
            hex_array::<32>("caa14fedd7bf6bb2504b5c4df39c84b9c8e6848b6e06d9d0fbbc5eabcaaa1759");
        assert_eq!(
            &*Suite::XSalsa20Poly1305.derive_key(&shared),
            &hex_array::<32>(XSALSA_KEY)
        );
        assert_eq!(
            &*Suite::XChaCha20Poly1305.derive_key(&shared),
            &hex_array::<32>(XCHACHA_KEY)
        );
    }

    #[test]
    fn secretbox_matches_the_go_vectors() {
        let key =
            hex_array::<32>("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        let nonce = hex_array::<24>("101112131415161718191a1b1c1d1e1f2021222324252627");
        let plain = b"the quick brown fox jumps over the lazy dog";
        let salsa = hex_bytes(
            "013fdd5dbcfb7d120fde25f0964e089aca03383e869cb9b635763141a34a485e93e0315988e2a73ada59d021b8cf61ea986288ddf2625f1f302534",
        );
        let chacha = hex_bytes(
            "9ba4cb05a6629ab952126de62130428d7cd303f9f7e86e0a8c2a61e3d4ddc57bbed02f8fb8688e2b7f10ae40564dbf0b3a2ec92f60863702381e3b",
        );
        assert_eq!(Suite::XSalsa20Poly1305.seal(&key, &nonce, plain), salsa);
        assert_eq!(Suite::XChaCha20Poly1305.seal(&key, &nonce, plain), chacha);
        assert_eq!(
            Suite::XSalsa20Poly1305.open(&key, &nonce, &salsa),
            Some(plain.to_vec())
        );
        assert_eq!(
            Suite::XChaCha20Poly1305.open(&key, &nonce, &chacha),
            Some(plain.to_vec())
        );
        let mut tampered = chacha;
        tampered[20] ^= 1;
        assert!(
            Suite::XChaCha20Poly1305
                .open(&key, &nonce, &tampered)
                .is_none()
        );
    }

    fn session(suite: Suite, key: &str, magic: &str) -> Session {
        Session {
            addr: "192.0.2.1:443".parse().expect("addr"),
            client_pk: hex_array::<32>(CLIENT_PK),
            client_magic: hex_array::<8>(magic),
            shared_key: Zeroizing::new(hex_array::<32>(key)),
            suite,
            ts_end: u32::MAX,
        }
    }

    const QUERY_PACKET: &str = "0102030405060708090a0b0c00010001000000000000";
    const QUERY_NONCE: &str = "101112131415161718191a1b1c1d1e1f2021222324252627";
    const RESPONSE_NONCE: &str = "101112131415161718191a1b8c8d8e8f9091929394959697";

    #[test]
    fn encrypted_query_matches_the_go_vectors() {
        let packet = hex_bytes(QUERY_PACKET);
        let nonce = hex_array::<24>(QUERY_NONCE);
        let chacha = session(Suite::XChaCha20Poly1305, XCHACHA_KEY, "0102030405060708");
        let salsa = session(Suite::XSalsa20Poly1305, XSALSA_KEY, "0102030405060708");
        assert_eq!(
            chacha.encrypt_query(&packet, &nonce),
            hex_bytes(
                "010203040506070807a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c101112131415161718191a1b2b1c3413454f9f4254812202c6c8cf6994ac738cff41eb52ef2024a659053130893ad73d5ca4ce21cc4d2a8c3a4d0da5a16c71626830cf417482540048d7d3164a68df1f2977f7b7a5df48604aa246db80ada51adb1a7dc2d20ee005a8f2e54191154b9e5692d6e79d562e95cfd40a386fc66bd8a34af2ac2b7d85fc189efcfb188b2c436590109a5a6fdaf91e57b0703055471e3368c1cf6e221c2000028c56f79c5950bc3b38ef041ada2ae867dcca3dbdc38ca3ff76734f02ab58c0d540167dc87fda9fa744018da226d76411abe8eaa0ed72d47fedde486607e22ad5221ee7988469f198e4ba63283c36a3d959d34a21e04555842cdc7e5744e721b9577fa2322e76cc9f09c215213992a1156b04"
            )
        );
        assert_eq!(
            salsa.encrypt_query(&packet, &nonce),
            hex_bytes(
                "010203040506070807a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c101112131415161718191a1b23defe0f83e07572c31c54ffd00c8f6b2a855be42fe1b6415d8ee10c494416dcb6a9e6513336fa0da13ff64242d411513ac66fbdcd5312c9718cebc33557fe3778bc57d9c352290a73d8654b0184a011f4f3ee684f62a0cdcd1bb9da11b93ea1c55158d9ae725e95dc43c32de57fe77307d9a344b8a81da6223a9d9e2306c91491b48e2782ade96072a26091eca8cdcf76884b5c062462eaf251c91e221f3eb56439cd8384668a167bc063c3ba0ee9ab41174e763628c269974345d26fcba508aeabb71c9074c96e61621ffd6332967af07629184c780e56f44b6b5a80077302d855a159902340c21b6ca37803ea6bd5b7030f28011d8ddd96e503406d7c2c87173f69290767bd7d1fc75d18f314d211"
            )
        );
    }

    #[test]
    fn response_decrypts_and_checks_the_nonce_echo() {
        let nonce = hex_array::<24>(RESPONSE_NONCE);
        let chacha = session(Suite::XChaCha20Poly1305, XCHACHA_KEY, "0102030405060708");
        let salsa = session(Suite::XSalsa20Poly1305, XSALSA_KEY, "0102030405060708");
        let expected = hex_bytes(QUERY_PACKET);
        let chacha_response = hex_bytes(
            "7236666e76576a38101112131415161718191a1b8c8d8e8f9091929394959697b4452938e273bb5a9cb96e315d83704e1ead1ca46bd41fb0ddf074cf2e1fa821219d04a1663af8d77c57f2c5c3a682d2fc7aa16c36ffbe504474982df6bfa5290ebfdfad50d6775f55b0de173c08c3cc80eba1d10f543517270843c946b7b1240a6f244f51c11c33ed4ec410d527922ea66efdc604f9c54cf157eab59349a32cdb3c742caec7d41115345835e336bf4dca5638d86e0fc9c6a2b0fffe0bdca94e49da06dbd5afc921bd5038cbc52b592f45db8551842be590ebc9fd6d9fb341bc0e00a3880c0146f5b9e0ec4d883ffea0271943822976d801c3fead857bb57f98f3f88b3dbc6dfdec79581dbe02699db26bda4ec7bdff78c50a4acf60503fb4539c4124c2ff3dda1bc0c4003ab404a25e",
        );
        let salsa_response = hex_bytes(
            "7236666e76576a38101112131415161718191a1b8c8d8e8f9091929394959697abc44b76c10a48e24bb80a7e56abf88bea534be43d37b89015e217e1fa7894920d788890282195d587bbb7ea725a32299e0d6896decde2710deb8371c89ea6276651f2af6ab3f962630e559527cf1fec2eed64dcb43fded462e51ad79f0b02666b7e97dd7a9c6db730801d3bde82c6b62930bb7c99106b3d62bf47faf8cb7680491a20834e20894fa8a2a3c20583753e282c30d2003a9eae93c7a1723394b07beda971b4ae8e8184cc1e45ee1fc88282ca2c63f1f9e5a75937705750d30b15a707e16f63c712edff3be0e4117178d1dc1cbe7f900f3e0fcf4b479ba7c2c4977e937ec7ae989794b16dddc375c6d7b3064b1c6afe6940e6efb3afcf6ba2ae7fa40af8f64e9357e4db5738d647e4fa7bc1",
        );
        assert_eq!(
            chacha.decrypt_response(&chacha_response, &nonce),
            Some(expected.clone())
        );
        assert_eq!(
            salsa.decrypt_response(&salsa_response, &nonce),
            Some(expected)
        );
        // A nonce echo from another query must be refused.
        let mut other = nonce;
        other[0] ^= 1;
        assert!(chacha.decrypt_response(&chacha_response, &other).is_none());
    }

    /// A peer that accepts the TCP connection and then stalls must hit the
    /// exchange deadline instead of wedging the lookup.
    #[tokio::test]
    async fn tcp_exchange_times_out_when_the_peer_stalls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::mem::drop(tokio::spawn(async move {
            let _stream = listener.accept().await;
            std::future::pending::<()>().await;
        }));
        let started = std::time::Instant::now();
        let error = tcp_exchange(addr, b"query", Duration::from_millis(100))
            .await
            .expect_err("a stalled peer must time out");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the exchange must be bounded, took {:?}",
            started.elapsed()
        );
        assert!(error.to_string().contains("timeout"), "{error}");
    }

    #[test]
    fn padding_is_iso7816_4_and_bounded() {
        for len in [0, 1, 16, 17, 63, 64, 200, 255, 256, 1000] {
            let padded = pad(&vec![0xaa; len]);
            assert_eq!(padded.len() % PAD_BLOCK, 0, "multiple of 64 at len {len}");
            assert!(padded.len() >= QUERY_MIN_PAD, "at least 256 at len {len}");
            assert_eq!(padded[len], 0x80, "0x80 follows the packet");
            assert!(padded[len + 1..].iter().all(|&b| b == 0));
            // A payload shorter than a DNS header plus the root question
            // cannot be a query, so unpad refuses it.
            let expected = (len >= MIN_DNS_PACKET).then(|| vec![0xaa; len]);
            assert_eq!(unpad(&padded), expected.as_deref());
        }
        // Missing 0x80, a non-zero after it, and a payload below the minimum
        // DNS packet are all refused.
        assert!(unpad(&[0u8; 256]).is_none());
        assert!(unpad(&[0xaa; 17]).is_none());
        let mut bad = vec![0u8; 256];
        bad[100] = 0x80;
        bad[200] = 1;
        assert!(unpad(&bad).is_none());
        let mut short = vec![0u8; 256];
        short[16] = 0x80;
        assert!(unpad(&short).is_none());
    }
}
