//! `ServerHello` / `HelloRetryRequest` parsing and record reading.

use super::{CipherSuiteId, Ciphertext, Tls12Suite, TlsVersion};

// ── ServerHello ────────────────────────────────────────────────────────────

/// A parsed `ServerHello` — carries fields for both TLS 1.3 and 1.2.
pub struct ServerHelloData {
    /// The raw handshake message (type + length + body), for the transcript.
    pub raw: Vec<u8>,
    /// The negotiated version.
    pub version: TlsVersion,
    /// The server's 32-byte random.
    pub server_random: [u8; 32],
    /// The server's classical (X25519) public key from `key_share` (TLS 1.3).
    pub peer_key: Option<[u8; 32]>,
    /// The ML-KEM ciphertext from the server's hybrid key share (TLS 1.3),
    /// validated at parse so the handshake decapsulates it with no re-copy.
    pub mlkem_ciphertext: Option<Ciphertext>,
    /// The `key_share` group the server selected (RFC 8446 §4.2.8); `None`
    /// when the server sent no share (TLS 1.2). Validated against the hello
    /// before it is used.
    pub key_share_group: Option<u16>,
    /// The cipher suite the server selected (TLS 1.3).
    pub suite: CipherSuiteId,
    /// The cipher suite the server selected (TLS 1.2).
    pub suite12: Option<Tls12Suite>,
    /// Whether the server echoed `extended_master_secret` (TLS 1.2).
    pub ems: bool,
    /// The ALPN protocol the server selected in its `ServerHello`
    /// (TLS 1.2; TLS 1.3 carries it in `EncryptedExtensions`).
    pub alpn: Option<Vec<u8>>,
    /// Whether the server selected the offered PSK.
    pub psk_selected: bool,
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
    /// The `key_share` group the server selected (RFC 8446 §4.2.8). Checked
    /// against what the client offered (and the HRR's `selected_group`); a
    /// server answering with a group the hello never listed is a protocol
    /// error, never a silent classical fallback.
    pub key_share_group: Option<u16>,
    pub ems: bool,
    /// The ALPN protocol selected in the `ServerHello` (TLS 1.2), or `None`.
    pub alpn: Option<Vec<u8>>,
    /// Whether the server selected the offered PSK.
    pub psk_selected: bool,
}

/// A parsed `HelloRetryRequest` (RFC 8446 §4.1.4): the server wants a
/// different key-exchange group and/or wants us to echo a cookie.
#[derive(Debug)]
pub struct HrrData {
    /// The group the server wants a `key_share` for (RFC 8446 §4.2.8.2: an
    /// HRR carries only `selected_group`, no key exchange).
    pub selected_group: Option<u16>,
    /// The opaque cookie to echo in `ClientHello2` (RFC 8446 §4.2.2).
    pub cookie: Option<Vec<u8>>,
}
