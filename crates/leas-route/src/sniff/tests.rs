use super::{
    QUIC_VERSION_V1, QUIC_VERSION_V2, QuicSniffProgress, QuicSniffer, SniffResult, SniffedProtocol,
    probe,
};
use std::path::Path;
/// Builds a full TLS record wrapping a minimal `ClientHello` carrying `sni`.
/// The `minimal_client_hello` helper below builds the raw handshake (QUIC
/// CRYPTO shape); this adds the TLS record header so the TLS arm walks it.
fn build_client_hello_with_sni(sni: &[u8]) -> Vec<u8> {
    let hello = minimal_client_hello(std::str::from_utf8(sni).expect("test SNI must be ASCII"));
    let mut record = vec![0x16, 0x03, 0x01]; // handshake, TLS 1.0+
    record.extend_from_slice(
        &u16::try_from(hello.len())
            .expect("test hello fits u16")
            .to_be_bytes(),
    );
    record.extend_from_slice(&hello);
    record
}

/// TLS-arm-only probe: asserts the record walks as TLS and returns the
/// result with its SNI still borrowing the caller's prefix.
fn sniff_tls(bytes: &[u8]) -> Option<SniffResult<'_>> {
    let r = probe(bytes);
    assert_eq!(r.as_ref().map(|r| r.protocol), Some(SniffedProtocol::Tls));
    r
}

#[test]
fn sniff_sni_borrows_prefix() {
    let pkt = build_client_hello_with_sni(b"example.com");
    let r = sniff_tls(&pkt).unwrap();
    assert_eq!(r.sni_as_str(), "example.com"); // no owned String in hot struct
}

/// Deterministic RNG feeding back a fixed byte sequence (same shape as the
/// `leas-tls` hello tests).
struct FixedRandom {
    bytes: Vec<u8>,
}

impl leas_tls::SecureRandom for FixedRandom {
    fn fill(&self, dest: &mut [u8]) -> Result<(), ring::error::Unspecified> {
        dest.iter_mut().enumerate().for_each(|(i, b)| {
            *b = self.bytes[i % self.bytes.len()];
        });
        Ok(())
    }
}

/// Renders the `chrome_130` hand-profile hello to wire bytes via the
/// `leas-tls` public API and persists it as
/// `tests/fixtures/tls_hello_chrome.bin` (commit alongside). Deterministic:
/// fixed RNG material, fixed key share. The file is loaded when present;
/// re-run any test with `RENDER_FIXTURE=1` to force a re-render and
/// overwrite (provenance re-check: output must be byte-identical).
fn fixture_bytes() -> Vec<u8> {
    use leas_tls::hello::{BuildParams, build_hello};

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls_hello_chrome.bin");
    if std::env::var_os("RENDER_FIXTURE").is_none()
        && let Ok(existing) = std::fs::read(&path)
    {
        return existing;
    }
    // Deterministic inputs: RNG bytes 0x42 (every GREASE draw lands on
    // 0x2A2A; random + session id all 0x42), X25519 key [0xAB; 32].
    let rng = FixedRandom {
        bytes: vec![0x42; 128],
    };
    let spec = leas_tls::profiles::hand_selected::chrome_130();
    let hello = build_hello(
        &spec,
        &BuildParams {
            server_name: "example.com",
            alpn: Some(&["h2", "http/1.1"]),
            x25519_pub: &[0xAB; 32],
            mlkem768_pub: None,
            rng: &rng,
        },
    )
    .expect("chrome_130 spec must render");
    let record = hello.record_bytes;
    match std::fs::create_dir_all(path.parent().unwrap())
        .and_then(|()| std::fs::write(&path, &record))
    {
        Ok(()) => {}
        Err(e) => panic!("write tls fixture: {e}"),
    }
    record
}

#[test]
fn tls_hello_yields_tls_with_sni_target_example_com() {
    let fixture = fixture_bytes();
    // The renderer SNI is "example.com" (see BuildParams above).
    let result = probe(&fixture).expect("chrome hello must sniff as TLS");
    assert_eq!(result.protocol, SniffedProtocol::Tls);
    assert_eq!(result.host.as_deref(), Some("example.com"));
}

#[test]
fn sni_carries_wire_case() {
    // Case preservation from the wire: SNI bytes returned unmodified.
    // Locate the host bytes by walking the hello (not raw searching),
    // overwrite them with mixed case, and expect probe to return exactly
    // the mixed-case string.
    // Host byte offset in the fixture: record(5) + hs hdr(4) + ver(2) +
    // random(32) + sid_len(1) + sid(32) + cs_len(2) + ciphers(32) +
    // comp_len(1) + comp(1) + ext_len(2) = 113; first ext is GREASE
    // (4 hdr + 1 val = 5); SNI ext: ty(2) len(2) list_len(2) + type(1) +
    // host_len(2) = 9 → walk total 128 = host start, len 11 ("example.com").
    const HOST_OFF: usize = 128;
    let mut hello = fixture_bytes();
    let result = probe(&hello).expect("parses");
    assert_eq!(result.host.as_deref(), Some("example.com"));

    let mixed = b"ExAmPlE.COM";
    hello[HOST_OFF..HOST_OFF + mixed.len()].copy_from_slice(mixed);
    let result = probe(&hello).expect("mutated hello still parses");
    assert_eq!(result.host.as_deref(), Some("ExAmPlE.COM"));
}

#[test]
fn http_get_request_yields_http_host_case_insensitive_and_trimmed() {
    let req = b"GET /path HTTP/1.1\r\nUser-Agent: x\r\nHOST:  \tExample.COM:8443  \r\n\r\n";
    let result = probe(req).expect("http request must sniff");
    assert_eq!(result.protocol, SniffedProtocol::Http);
    // Name matched case-insensitively; value trimmed, case preserved.
    assert_eq!(result.host.as_deref(), Some("Example.COM:8443"));
}

#[test]
fn http_response_is_not_a_request() {
    let resp = b"HTTP/1.1 200 OK\r\nHost: example.com\r\n\r\n";
    assert_eq!(probe(resp), None);
}

#[test]
fn garbage_returns_none() {
    assert_eq!(probe(b"\x00\x01\x02\x03garbage"), None);
    assert_eq!(probe(b"\xff\xff\xff\xff"), None);
    assert_eq!(probe(b""), None);
}

#[test]
fn host_header_in_body_is_not_sniffed() {
    // A request with no Host header whose BODY contains a "host:" line:
    // the header scan must stop at the blank line, yielding None —
    // never the attacker-controlled body line.
    let req = b"POST /x HTTP/1.1\r\nContent-Length: 20\r\n\r\nhost: attacker.com\r\n";
    assert_eq!(probe(req), None);
    // Real header + decoy body line: header wins.
    let req = b"POST /x HTTP/1.1\r\nHost: real.example\r\n\r\nhost: attacker.com\r\n";
    let result = probe(req).expect("parses");
    assert_eq!(result.host.as_deref(), Some("real.example"));
}

#[test]
fn truncated_hello_returns_none() {
    let full = fixture_bytes();
    // Every prefix must return None, never panic.
    for cut in 1..full.len() {
        assert_eq!(probe(&full[..cut]), None, "prefix of {cut} bytes sniffed");
    }
}

#[test]
fn hello_field_len_overrun_returns_none() {
    // Valid outer hs_len, but a field length extends past the remaining
    // bytes: the inner Reader takes must yield None (covers the
    // take_len ?=>None arms the outer hs_end gate otherwise hides).
    let mut hello = fixture_bytes();
    // Extensions block length (u16 BE at 112, walked: 9 hdr + 2 ver +
    // 32 random + 1 sid_len + 32 sid + 2 cs_len + 32 ciphers + 1 comp_len
    // + 1 comp): blow it up past the remaining slice.
    hello[112] = 0xFF;
    hello[113] = 0xFF;
    assert_eq!(probe(&hello), None);
    // Same for the session-id length: valid header, sid claims 255 bytes
    // where only 32 remain inside the handshake body.
    let mut hello = fixture_bytes();
    hello[43] = 0xFF;
    assert_eq!(probe(&hello), None);
}

#[test]
fn truncated_http_returns_none() {
    assert_eq!(probe(b"GET / HTTP/1.1\r\n"), None);
    assert_eq!(probe(b"GET / HTTP/1.1\r\nHost: e.com\r\n"), None);
}

#[test]
fn oversized_slice_returns_none_early() {
    let big = vec![0x42u8; 64 * 1024 + 1];
    assert_eq!(probe(&big), None);
    // Exactly 64 KiB is allowed through (then garbage ⇒ None).
    let ok = vec![0x42u8; 64 * 1024];
    assert_eq!(probe(&ok), None);
}

#[test]
fn tls_record_wrong_version_returns_none() {
    let mut hello = fixture_bytes();
    hello[1] = 0x02; // record version 0x0200 < 0x0301
    assert_eq!(probe(&hello), None);
}

#[test]
fn tls_non_client_hello_handshake_type_returns_none() {
    let mut hello = fixture_bytes();
    hello[5] = 0x02; // server hello type, not client hello (byte 5, after record header)
    assert_eq!(probe(&hello), None);
}

#[test]
fn tls_hello_without_sni_yields_tls_with_no_host() {
    let mut hello = vec![
        0x16, 0x03, 0x01, // record: handshake, TLS 1.0+
        0x00, 0x2f, // record length 47
        0x01, 0x00, 0x00, 0x2b, // handshake: client hello, 43 bytes
        0x03, 0x03, // legacy version
    ];
    hello.extend_from_slice(&[0x00; 32]); // random
    hello.push(0x00); // session id len
    hello.extend_from_slice(&0x0002u16.to_be_bytes()); // ciphers len
    hello.extend_from_slice(&0x1301u16.to_be_bytes()); // one cipher
    hello.push(0x01); // compression len
    hello.push(0x00); // null compression
    hello.extend_from_slice(&0x0000u16.to_be_bytes()); // extensions len
    let result = probe(&hello).expect("valid hello");
    assert_eq!(result.protocol, SniffedProtocol::Tls);
    assert_eq!(result.host, None);
}

#[test]
fn sni_with_non_ascii_rejected() {
    // Hand-built hello carrying a non-ASCII server_name — must return
    // None (indeterminate), never panic or emit invalid UTF-8.
    let host = [0xFFu8; 4];
    let mut sni_ext = 0x0000u16.to_be_bytes().to_vec();
    sni_ext.extend_from_slice(&u16::try_from(5 + host.len()).unwrap().to_be_bytes());
    sni_ext.extend_from_slice(&u16::try_from(1 + 2 + host.len()).unwrap().to_be_bytes());
    sni_ext.push(0x00); // host_name
    sni_ext.extend_from_slice(&u16::try_from(host.len()).unwrap().to_be_bytes());
    sni_ext.extend_from_slice(&host);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x00; 32]);
    body.push(0x00); // sid len
    body.extend_from_slice(&0x0002u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(0x01);
    body.push(0x00);
    body.extend_from_slice(&u16::try_from(sni_ext.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&sni_ext);

    let mut hello = vec![0x16, 0x03, 0x01];
    hello.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    hello.push(0x01);
    let body_len = u32::try_from(body.len()).unwrap();
    hello.extend_from_slice(&body_len.to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    assert_eq!(probe(&hello), None);
}

#[test]
fn sniff_result_is_debug_clone_eq() {
    let r = probe(b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n").unwrap();
    let r2 = r.clone();
    assert_eq!(r, r2);
    assert!(format!("{r:?}").contains("Http"));
}

/// Loads one of the real-traffic QUIC `Initial` fixtures (captured from
/// quic-go, ported from xray's `common/protocol/quic/sniff_test.go`).
fn quic_fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap_or_else(|e| panic!("read quic fixture {name}: {e}"))
}

#[test]
fn quic_initial_yields_quic_with_sni_target_www_google_com() {
    // Real quic-go client `Initial` packet carrying a TLS ClientHello with
    // SNI `www.google.com` (xray sniff_test.go fixture).
    let pkt = quic_fixture("quic_initial_google.bin");
    let r = probe(&pkt).expect("real quic packet must sniff as QUIC");
    assert_eq!(r.protocol, SniffedProtocol::Quic);
    assert_eq!(r.host.as_deref(), Some("www.google.com"));
}

#[test]
fn quic_incomplete_hello_returns_none() {
    // The `play.google.com` hello spans two coalesced `Initial` packets; the
    // first packet alone does not carry the whole ClientHello (the SNI host
    // is split mid-name), so it must be indeterminate — never a truncated
    // host.
    let pkt = quic_fixture("quic_initial_play_part1.bin");
    assert_eq!(probe(&pkt), None, "partial hello must not yield a host");
}

#[test]
fn quic_hello_split_across_packets_assembles_sni() {
    // Both coalesced `Initial` packets carry the complete ClientHello; the
    // CRYPTO stream reassembled across them yields the full SNI.
    let pkt = quic_fixture("quic_initial_play_full.bin");
    let r = probe(&pkt).expect("coalesced quic packets must sniff");
    assert_eq!(r.protocol, SniffedProtocol::Quic);
    assert_eq!(r.host.as_deref(), Some("play.google.com"));
}

#[test]
fn quic_garbage_and_short_slices_return_none() {
    // Not a long-header packet: indeterminate.
    assert_eq!(probe(b"\x00\x01\x02\x03"), None);
    assert_eq!(
        probe(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
            .unwrap()
            .protocol,
        SniffedProtocol::Http
    );
    // A real packet truncated mid-header is indeterminate, not a panic.
    let pkt = quic_fixture("quic_initial_google.bin");
    assert_eq!(probe(&pkt[..3]), None);
    assert_eq!(probe(&pkt[..8]), None);
    // Unsupported version (e.g. a future QUIC version byte) is indeterminate.
    let mut bad = pkt;
    bad[1..5].copy_from_slice(&0xfeed_faceu32.to_be_bytes());
    assert_eq!(probe(&bad), None);
}

#[test]
fn quic_scid_length_overflow_returns_none_not_panic() {
    // Long-header Initial with an SCID length byte that exceeds the
    // remaining slice.  The unchecked `p[1 + scid_len..]` slice used to
    // panic here (regression: sniff.rs:230); the DCID of the same shape was
    // already bounds-checked.  Must be indeterminate, never a panic.
    let pkt = [0xc3, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff];
    assert_eq!(probe(&pkt), None);
    let pkt = [0xc3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x11, 0x22];
    assert_eq!(probe(&pkt), None);
}

/// Forges a single-packet QUIC `Initial` datagram for any version the
/// sniffer supports: one `CRYPTO` frame carrying `crypto_data` at
/// `crypto_offset`, PADDING to a plausible size, keys derived from `dcid`
/// with the version's salt + labels, HP-protected and AEAD-sealed. Same
/// recipe as xray's `sniff_test.go` fixtures.
fn forge_initial(version: u32, dcid: &[u8], crypto_offset: u64, crypto_data: &[u8]) -> Vec<u8> {
    let params = super::version_params(version).expect("test version must be supported");
    forge_initial_with(
        version,
        params.salt,
        params.key_label,
        params.iv_label,
        params.hp_label,
        params.initial_type,
        dcid,
        crypto_offset,
        crypto_data,
    )
}

/// Forges a single-packet QUIC `Initial` datagram with explicit
/// version-derived parameters. v2 tests pass RFC 9369 literals here so a
/// drift in the production [`super::version_params`] table fails decryption
/// instead of passing self-consistently.
fn forge_initial_with(
    version: u32,
    salt: &[u8; 20],
    key_label: &[u8],
    iv_label: &[u8],
    hp_label: &[u8],
    initial_type: u8,
    dcid: &[u8],
    crypto_offset: u64,
    crypto_data: &[u8],
) -> Vec<u8> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    fn expand_label(secret: &[u8], label: &[u8], out: &mut [u8]) {
        let mut info = Vec::new();
        info.extend_from_slice(&u16::try_from(out.len()).expect("small").to_be_bytes());
        info.push(u8::try_from(6 + label.len()).expect("small"));
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(0);
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
        let mut ctx = ring::hmac::Context::with_key(&key);
        ctx.update(&info);
        ctx.update(&[1]);
        let tag = ctx.sign();
        out.copy_from_slice(&tag.as_ref()[..out.len()]);
    }
    fn varint8(v: u64) -> [u8; 8] {
        let mut b = v.to_be_bytes();
        b[0] |= 0xc0;
        b
    }

    let initial_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, salt);
    let initial_secret = ring::hmac::sign(&initial_key, dcid);
    let mut cs = [0u8; 32];
    expand_label(initial_secret.as_ref(), b"client in", &mut cs);
    let mut key = [0u8; 16];
    expand_label(&cs, key_label, &mut key);
    let mut iv = [0u8; 12];
    expand_label(&cs, iv_label, &mut iv);
    let mut hp = [0u8; 16];
    expand_label(&cs, hp_label, &mut hp);

    let mut frames = vec![0x06u8]; // CRYPTO
    frames.extend_from_slice(&varint8(crypto_offset));
    frames.extend_from_slice(&varint8(u64::try_from(crypto_data.len()).expect("small")));
    frames.extend_from_slice(crypto_data);
    frames.resize(frames.len() + 32, 0x00); // PADDING

    let pn_len = 4usize;
    let length = pn_len + frames.len() + 16; // pn + ciphertext + tag
    let mut hdr = vec![0xc0 | (initial_type << 4) | 0x03]; // long, fixed, Initial, 4-byte pn
    hdr.extend_from_slice(&version.to_be_bytes());
    hdr.push(u8::try_from(dcid.len()).expect("dcid <= 255"));
    hdr.extend_from_slice(dcid);
    hdr.push(0); // scid len
    hdr.push(0); // token len varint = 0
    hdr.extend_from_slice(&(u16::try_from(length).expect("small") | 0x4000).to_be_bytes());
    let pn_off = hdr.len();
    hdr.extend_from_slice(&[0u8; 4]); // packet number 0

    let mut payload = frames;
    let aead = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key).unwrap(),
    );
    aead.seal_in_place_append_tag(
        ring::aead::Nonce::assume_unique_for_key(iv),
        ring::aead::Aad::from(&hdr),
        &mut payload,
    )
    .unwrap();

    let mut pkt = hdr;
    pkt.extend_from_slice(&payload);
    // Header protection.
    let sample: [u8; 16] = pkt[pn_off + 4..pn_off + 20].try_into().unwrap();
    let mut mask = [0u8; 16];
    aes::Aes128::new_from_slice(&hp)
        .unwrap()
        .encrypt_block_b2b((&sample).into(), (&mut mask).into());
    pkt[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        pkt[pn_off + i] ^= mask[1 + i];
    }
    pkt
}

/// Builds a minimal TLS 1.3 `ClientHello` handshake message (raw, no TLS
/// record header — the QUIC CRYPTO stream shape) carrying the given SNI.
fn minimal_client_hello(sni: &str) -> Vec<u8> {
    let mut sni_ext = 0x0000u16.to_be_bytes().to_vec(); // server_name
    sni_ext.extend_from_slice(&u16::try_from(5 + sni.len()).unwrap().to_be_bytes()); // ext len
    sni_ext.extend_from_slice(&u16::try_from(1 + 2 + sni.len()).unwrap().to_be_bytes()); // list len
    sni_ext.push(0x00); // host_name
    sni_ext.extend_from_slice(&u16::try_from(sni.len()).unwrap().to_be_bytes());
    sni_ext.extend_from_slice(sni.as_bytes());

    let mut body = vec![0x03, 0x03]; // legacy_version
    body.extend_from_slice(&[0x00; 32]); // random
    body.push(0x00); // session id len
    body.extend_from_slice(&0x0002u16.to_be_bytes()); // ciphers len
    body.extend_from_slice(&0x1301u16.to_be_bytes()); // one cipher
    body.push(0x01); // compression len
    body.push(0x00); // null
    body.extend_from_slice(&u16::try_from(sni_ext.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&sni_ext);

    let mut hello = vec![0x01]; // ClientHello
    hello.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]); // 3-byte len
    hello.extend_from_slice(&body);
    hello
}

/// RFC 9369 §3.3.1 initial salt — hardcoded independently of the production
/// table so a typo in [`super::QUIC_SALT_V2`] fails the v2 sniff tests
/// instead of passing self-consistently.
const V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Forges a v2 `Initial` datagram with RFC 9369 literals (v2 salt, quicv2
/// labels, Initial type 0b01) — independent of the production
/// `version_params` table, so a production drift fails decryption.
fn forge_v2_initial(dcid: &[u8], crypto_offset: u64, crypto_data: &[u8]) -> Vec<u8> {
    forge_initial_with(
        QUIC_VERSION_V2,
        &V2_SALT,
        b"quicv2 key",
        b"quicv2 iv",
        b"quicv2 hp",
        1,
        dcid,
        crypto_offset,
        crypto_data,
    )
}

#[test]
fn quic_crypto_offset_is_capped_not_allocated() {
    // A CRYPTO frame with a huge offset used to `crypto.resize(end)` an
    // attacker-chosen size — a 1 TiB allocation aborts the process
    // (regression: the cap now lives in `decrypt_initial_packet` before the
    // resize).  The reassembly span must be capped at MAX_CRYPTO_LEN and
    // reported indeterminate.
    for offset in [1u64 << 20, 1u64 << 40, (1u64 << 62) - 1] {
        let pkt = forge_initial(QUIC_VERSION_V1, &[0u8; 8], offset, &[0x01]);
        assert_eq!(
            probe(&pkt),
            None,
            "offset {offset} must be refused, not allocated"
        );
    }
    // Sanity: the forged packet is well-formed — a small offset decrypts
    // and is accepted into the (incomplete) hello, still yielding None.
    let pkt = forge_initial(QUIC_VERSION_V1, &[0u8; 8], 64, &[0x01]);
    assert_eq!(probe(&pkt), None);
}

#[test]
fn quic_v2_initial_yields_quic_with_sni() {
    // RFC 9369: version 0x6b3343cf, v2 salt, "quicv2 *" HKDF labels, and an
    // Initial packet type of 0b01 (v1 uses 0b00). Forged with RFC literals
    // independent of the production table — a production drift fails here.
    let hello = minimal_client_hello("example.com");
    let d = forge_v2_initial(&[0u8; 8], 0, &hello);
    let r = probe(&d).expect("v2 Initial must sniff as QUIC");
    assert_eq!(r.protocol, SniffedProtocol::Quic);
    assert_eq!(r.host.as_deref(), Some("example.com"));
}

#[test]
fn quic_version_mismatch_returns_none() {
    // The version field is load-bearing: it selects the Initial packet type
    // (RFC 9369 §3.2) and the salt/labels (§3.3), so a packet forged for one
    // version is indeterminate under the other (either a non-Initial type or
    // a failed decrypt).
    let hello = minimal_client_hello("example.com");
    let mut v1 = forge_initial(QUIC_VERSION_V1, &[0u8; 8], 0, &hello);
    v1[1..5].copy_from_slice(&QUIC_VERSION_V2.to_be_bytes());
    assert_eq!(probe(&v1), None);
    let mut v2 = forge_v2_initial(&[0u8; 8], 0, &hello);
    v2[1..5].copy_from_slice(&QUIC_VERSION_V1.to_be_bytes());
    assert_eq!(probe(&v2), None);
}

#[test]
fn quic_hello_split_across_datagrams_assembles_sni() {
    // The ClientHello split across TWO v1 datagrams: the stateful sniffer
    // accumulates CRYPTO across feeds and resolves once the handshake
    // message is complete. The single-shot `probe` on the partial datagram
    // stays indeterminate.
    let hello = minimal_client_hello("example.com");
    let (a, b) = hello.split_at(hello.len() / 2);
    let d1 = forge_initial(QUIC_VERSION_V1, &[0u8; 8], 0, a);
    let d2 = forge_initial(QUIC_VERSION_V1, &[0u8; 8], a.len() as u64, b);
    assert_eq!(probe(&d1), None, "partial hello must not yield a host");

    let mut s = QuicSniffer::new();
    assert_eq!(s.feed(&d1), QuicSniffProgress::NeedMore);
    match s.feed(&d2) {
        QuicSniffProgress::Done(r) => {
            assert_eq!(r.protocol, SniffedProtocol::Quic);
            assert_eq!(r.host.as_deref(), Some("example.com"));
        }
        other => panic!("expected Done, got {other:?}"),
    }
}

#[test]
fn quic_v2_hello_split_across_datagrams_assembles_sni() {
    // Same split over the v2 wire format.
    let hello = minimal_client_hello("example.com");
    let (a, b) = hello.split_at(hello.len() / 2);
    let d1 = forge_v2_initial(&[0u8; 8], 0, a);
    let d2 = forge_v2_initial(&[0u8; 8], a.len() as u64, b);

    let mut s = QuicSniffer::new();
    assert_eq!(s.feed(&d1), QuicSniffProgress::NeedMore);
    match s.feed(&d2) {
        QuicSniffProgress::Done(r) => {
            assert_eq!(r.protocol, SniffedProtocol::Quic);
            assert_eq!(r.host.as_deref(), Some("example.com"));
        }
        other => panic!("expected Done, got {other:?}"),
    }
}

#[test]
fn quic_sniffer_rejects_version_switch() {
    // A datagram with a different version than the first is a different
    // connection — the reassembly must not mix it in.
    let hello = minimal_client_hello("example.com");
    let (a, b) = hello.split_at(hello.len() / 2);
    let d1 = forge_initial(QUIC_VERSION_V1, &[0u8; 8], 0, a);
    let d2 = forge_v2_initial(&[0u8; 8], a.len() as u64, b);
    let mut s = QuicSniffer::new();
    assert_eq!(s.feed(&d1), QuicSniffProgress::NeedMore);
    assert_eq!(s.feed(&d2), QuicSniffProgress::Indeterminate);
}

#[test]
fn quic_sniffer_rejects_dcid_switch() {
    // A datagram with a different DCID is a different connection (5-tuple
    // reuse) — rejected rather than merged into the reassembly.
    let hello = minimal_client_hello("example.com");
    let (a, b) = hello.split_at(hello.len() / 2);
    let d1 = forge_initial(QUIC_VERSION_V1, &[0u8; 8], 0, a);
    let d2 = forge_initial(QUIC_VERSION_V1, &[0x42; 8], a.len() as u64, b);
    let mut s = QuicSniffer::new();
    assert_eq!(s.feed(&d1), QuicSniffProgress::NeedMore);
    assert_eq!(s.feed(&d2), QuicSniffProgress::Indeterminate);
}

#[test]
fn quic_sniffer_garbage_or_empty_first_datagram_is_indeterminate() {
    // A flow that never opens with an Initial packet is not a sniffable
    // QUIC start: garbage and empty datagrams are indeterminate, never
    // NeedMore (which would keep a dead flow feeding forever).
    let mut s = QuicSniffer::new();
    assert_eq!(
        s.feed(b"\x00\x01\x02\x03"),
        QuicSniffProgress::Indeterminate
    );
    assert_eq!(s.feed(b""), QuicSniffProgress::Indeterminate);
    // Oversize datagrams are refused outright.
    let big = vec![0x00u8; 64 * 1024 + 1];
    assert_eq!(s.feed(&big), QuicSniffProgress::Indeterminate);
}

#[test]
fn quic_v2_constants_match_rfc9369() {
    // Independent pin on the production v2 table: a typo in QUIC_SALT_V2,
    // the quicv2 labels, or the Initial type would otherwise pass every
    // sniff test (the forge and the sniffer would drift together).
    let p = super::version_params(QUIC_VERSION_V2).expect("v2 supported");
    assert_eq!(*p.salt, V2_SALT);
    assert_eq!(p.key_label, b"quicv2 key");
    assert_eq!(p.iv_label, b"quicv2 iv");
    assert_eq!(p.hp_label, b"quicv2 hp");
    assert_eq!(p.initial_type, 1);
    // v1/draft-29 keep the v1 labels and Initial type 0b00.
    let v1 = super::version_params(QUIC_VERSION_V1).expect("v1 supported");
    assert_eq!(v1.key_label, b"quic key");
    assert_eq!(v1.iv_label, b"quic iv");
    assert_eq!(v1.hp_label, b"quic hp");
    assert_eq!(v1.initial_type, 0);
}

/// Minimal TLS 1.3 `ClientHello` (raw handshake bytes) with no extensions —
/// a complete hello whose SNI is absent.
fn minimal_client_hello_no_sni() -> Vec<u8> {
    let mut body = vec![0x03, 0x03]; // legacy_version
    body.extend_from_slice(&[0x00; 32]); // random
    body.push(0x00); // session id len
    body.extend_from_slice(&0x0002u16.to_be_bytes()); // ciphers len
    body.extend_from_slice(&0x1301u16.to_be_bytes()); // one cipher
    body.push(0x01); // compression len
    body.push(0x00); // null
    body.extend_from_slice(&0x0000u16.to_be_bytes()); // empty extensions
    let mut hello = vec![0x01]; // ClientHello
    hello.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]); // 3-byte len
    hello.extend_from_slice(&body);
    hello
}

#[test]
fn quic_hello_without_sni_split_across_datagrams_resolves_no_host() {
    // A complete hello with no SNI extension split across datagrams must
    // end Done with host None (not linger NeedMore forever).
    let hello = minimal_client_hello_no_sni();
    let (a, b) = hello.split_at(hello.len() / 2);
    let d1 = forge_initial(QUIC_VERSION_V1, &[0u8; 8], 0, a);
    let d2 = forge_initial(QUIC_VERSION_V1, &[0u8; 8], a.len() as u64, b);
    let mut s = QuicSniffer::new();
    assert_eq!(s.feed(&d1), QuicSniffProgress::NeedMore);
    match s.feed(&d2) {
        QuicSniffProgress::Done(r) => {
            assert_eq!(r.protocol, SniffedProtocol::Quic);
            assert_eq!(r.host, None);
        }
        other => panic!("expected Done, got {other:?}"),
    }
}

#[test]
fn quic_out_of_order_crypto_offsets_are_reassembled() {
    // CRYPTO frames may arrive tail-first: the reassembly fills offset
    // holes with zeros and completes once the hello is exact-filled.
    let hello = minimal_client_hello("example.com");
    let (a, b) = hello.split_at(hello.len() / 2);
    let tail = forge_initial(QUIC_VERSION_V1, &[0u8; 8], a.len() as u64, b);
    let head = forge_initial(QUIC_VERSION_V1, &[0u8; 8], 0, a);
    let mut s = QuicSniffer::new();
    assert_eq!(s.feed(&tail), QuicSniffProgress::NeedMore);
    match s.feed(&head) {
        QuicSniffProgress::Done(r) => assert_eq!(r.host.as_deref(), Some("example.com")),
        other => panic!("expected Done, got {other:?}"),
    }
}

#[test]
fn quic_sniffer_stays_done_after_refeed() {
    // Completion is sticky: a later datagram whose CRYPTO extends past the
    // hello must keep the resolved answer, never un-complete to NeedMore.
    let hello = minimal_client_hello("example.com");
    let (a, b) = hello.split_at(hello.len() / 2);
    let d1 = forge_initial(QUIC_VERSION_V1, &[0u8; 8], 0, a);
    let d2 = forge_initial(QUIC_VERSION_V1, &[0u8; 8], a.len() as u64, b);
    let extra = forge_initial(
        QUIC_VERSION_V1,
        &[0u8; 8],
        hello.len() as u64,
        &[0xde, 0xad],
    );
    let mut s = QuicSniffer::new();
    assert_eq!(s.feed(&d1), QuicSniffProgress::NeedMore);
    let QuicSniffProgress::Done(first) = s.feed(&d2) else {
        panic!("expected Done");
    };
    assert_eq!(first.host.as_deref(), Some("example.com"));
    match s.feed(&extra) {
        QuicSniffProgress::Done(r) => assert_eq!(r.host.as_deref(), Some("example.com")),
        other => panic!("post-Done feed must stay Done, got {other:?}"),
    }
}
