//! Hermetic Shadowsocks codec benches: what one chunk and one datagram cost
//! the client on its hot path, plus the per-connection subkey derivation.
//!
//! No feature gate, no core binary, no network, no sockets — `cargo criterion
//! -p leas-native --bench ss_codec` always measures, in CI and on a cold
//! box alike.
//!
//! # Sizes (stated once; every row below measures one of them)
//!
//! * **classic TCP chunk** — `MAX_CHUNK = 0x3FFF` (16383) plaintext bytes per
//!   frame (`protocol/ss/stream.rs`); one frame is TWO AEAD seals, the 2-byte
//!   BE length then the payload, wire
//!   `[2B len + 16B tag][ct(payload) + 16B tag]`.
//! * **2022 TCP chunk** — `MAX_PAYLOAD = 0xFFFF` (65535) plaintext bytes per
//!   frame (`protocol/ss/stream2022.rs`), same two-seal wire shape.
//! * **SS datagram** — a 65000-byte payload, the cap `ss::udp::MAX_PAYLOAD`
//!   puts on one UDP send. The datagram additionally carries the SOCKS5
//!   port-last address (7 bytes for IPv4) inside the sealed body.
//!
//! # What is hoisted, and what is drawn per iteration
//!
//! * **TCP rows**: the subkey is derived once per connection (`Half::new`
//!   from the client salt) and every chunk reuses it, so these rows hoist one
//!   `stream_subkey` call out of the timed loop. The derivation itself is
//!   measured by `kdf/*`, once per connection.
//! * **classic UDP rows**: the codec derives a fresh subkey for EVERY
//!   datagram from a fresh random salt (`ss::udp::seal_datagram_into`), so the
//!   `seal` row draws a real CSPRNG salt per iteration (ring, the same source
//!   `crate::rand::fill_nonsecret` pools) and derives the subkey in the loop;
//!   the `open` row derives its subkey per iteration from the received
//!   packet's salt, as `open_datagram` does.
//! * **2022 UDP rows**: one session subkey is cached per session
//!   (`Ss2022WriterState::subkey`), so these rows hoist it; the per-datagram
//!   part is the AES-ECB separate header (AES methods, key schedule included
//!   — production rebuilds the cipher per datagram) or the 24-byte random
//!   nonce (`ChaCha` method), plus the body seal.
//!
//! # The rows mirror the codecs, they do not call them
//!
//! Every codec that would do this work is private to the crate, so each row
//! reproduces the call sequence with the same public primitives at the same
//! sizes rather than calling into it:
//!
//! * **TCP chunk rows** mirror `ss::stream::SsStream::push_chunks` and
//!   `ss::stream2022::Ss2022Stream::push_chunks`: two `seal_into` and two
//!   counter hand-outs per frame, sealed straight into a reused buffer. The
//!   only delta is that they do not loop `chunks()` (one frame per row) and
//!   keep no `SsStream` state around the seals (the salt prefix, the flush
//!   position, the `sealed` count) — the per-frame crypto and buffer work is
//!   the same.
//! * **UDP rows** mirror `ss::udp::{seal_datagram_into, open_datagram,
//!   Ss2022WriterState, Ss2022ReaderState}` with `stream_subkey`,
//!   `SsAead::{seal_into, open}`, `write_addr_port_last` /
//!   `decode_addr_port_last` and the `aes` crate's ECB for the 2022 separate
//!   header. Deltas, stated rather than hidden: the classic UDP **seal** row
//!   pays one `Zeroizing<Vec<u8>>` allocation + wipe per datagram that
//!   production's `pub(crate)` `stream_subkey_into` into reused scratch does
//!   not (the **open** row matches production — `open_datagram` calls
//!   `stream_subkey` too), and the 2022 open rows skip the ≤2-slot
//!   session-table lookup plus the `parse_server_body` byte checks (no
//!   crypto, below this row's resolution).
//!
//! A change to the wire shape will therefore not move these rows; a change to
//! the crypto or the buffer handling will.

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockCipherDecrypt as _, BlockCipherEncrypt as _, KeyInit as _};
use aes::{Aes128, Aes256};
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main};
use leas_native::addr::{Host, TargetAddr, decode_addr_port_last, write_addr_port_last};
use leas_native::crypto::aead::{NonceCounter, SsAead};
use leas_native::protocol::ss::method::{SsFamily, SsMethod, password_key, stream_subkey};
use ring::rand::{SecureRandom as _, SystemRandom};

type Group<'a> = BenchmarkGroup<'a, WallTime>;

/// `ss::stream::MAX_CHUNK`: the classic AEAD frame's payload cap.
const CLASSIC_CHUNK: usize = 0x3FFF;

/// `ss::stream2022::MAX_PAYLOAD`: the 2022 frame's payload cap.
const S2022_CHUNK: usize = 0xFFFF;

/// `ss::udp::MAX_PAYLOAD`: the cap on one datagram's payload.
const UDP_PAYLOAD: usize = 65_000;

/// One chunk's length field plus its tag: `[2B BE len][16B tag]`.
const LEN_SEAL: usize = 2 + 16;

/// `ss::udp::SEPARATE_HEADER_LEN`: `session_id BE8 ‖ packet_id BE8`.
const SEPARATE_HEADER: usize = 16;

/// `ss::udp::CHACHA_NONCE_LEN`: the 2022 `ChaCha` UDP (`XChaCha20`) nonce.
const UDP_CHACHA_NONCE: usize = 24;

/// IPv4 `ATYP|addr|port` in the SOCKS5 port-last form both codecs use.
const IPV4_ADDR: usize = 1 + 4 + 2;

/// The 2022 client main header's fixed part: `type | ts BE8 | pad_len u16be`.
const S2022_CLIENT_FIXED: usize = 1 + 8 + 2;

/// The 2022 server main header's fixed part — the client header plus the
/// echoed `client_session_id BE8` (spec §3.2.3).
const S2022_SERVER_FIXED: usize = S2022_CLIENT_FIXED + 8;

/// The classic password every AEAD row derives its master key from
/// (`evp_bytes_to_key_md5`, unconditional).
const CLASSIC_PASSWORD: &str = "bench-password";

/// The 2022-blake3 PSK the 32-byte methods take (base64, 32 bytes decoded) —
/// the same constant the e2e harness uses.
const S2022_PSK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// The client's 2022 session id: the salt of its session subkey.
const S2022_SESSION_ID: u64 = 0x0102_0304_0506_0708;

/// The server's session id the open rows replay.
const S2022_SERVER_ID: u64 = 0x1122_3344_5566_7788;

/// The four classic ciphers `SsMethod` exposes, with their row names.
const fn classic_ciphers() -> [(&'static str, SsAead); 4] {
    [
        ("aes-128-gcm", SsAead::Aes128Gcm),
        ("aes-256-gcm", SsAead::Aes256Gcm),
        ("chacha20-ietf-poly1305", SsAead::ChaCha20Poly1305),
        ("xchacha20-ietf-poly1305", SsAead::XChaCha20Poly1305),
    ]
}

/// Seconds since the UNIX epoch — `ss::udp::now_unix_secs`; production stamps
/// every 2022 datagram, so the rows pay the clock read the same way.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the UNIX epoch")
        .as_secs()
}

/// The 2022 body AEAD nonce: the **plaintext** separate header's `[4..16]`
/// (`ss::udp::separate_header_nonce`), never the encrypted wire block.
fn separate_nonce(session_id: u64, packet_id: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&session_id.to_be_bytes()[4..]);
    nonce[4..].copy_from_slice(&packet_id.to_be_bytes());
    nonce
}

/// AES-ECB of one block under the PSK — the 2022 separate header's cipher
/// (`ss::udp::aes_ecb_encrypt`), key schedule included because production
/// builds the cipher per datagram.
fn aes_ecb_encrypt(aead: SsAead, psk: &[u8], block: &mut [u8; SEPARATE_HEADER]) {
    let out = match aead {
        SsAead::Aes128Gcm => {
            let cipher = Aes128::new_from_slice(psk).expect("AES-128 PSK is 16 bytes");
            let mut out = [0u8; SEPARATE_HEADER];
            cipher.encrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        SsAead::Aes256Gcm => {
            let cipher = Aes256::new_from_slice(psk).expect("AES-256 PSK is 32 bytes");
            let mut out = [0u8; SEPARATE_HEADER];
            cipher.encrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        other => unreachable!("{other:?} has no Shadowsocks-2022 separate header"),
    };
    *block = out;
}

/// [`aes_ecb_encrypt`]'s inverse (`ss::udp::aes_ecb_decrypt`), the reader's
/// side of the separate header.
fn aes_ecb_decrypt(aead: SsAead, psk: &[u8], block: &mut [u8; SEPARATE_HEADER]) {
    let out = match aead {
        SsAead::Aes128Gcm => {
            let cipher = Aes128::new_from_slice(psk).expect("AES-128 PSK is 16 bytes");
            let mut out = [0u8; SEPARATE_HEADER];
            cipher.decrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        SsAead::Aes256Gcm => {
            let cipher = Aes256::new_from_slice(psk).expect("AES-256 PSK is 32 bytes");
            let mut out = [0u8; SEPARATE_HEADER];
            cipher.decrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        other => unreachable!("{other:?} has no Shadowsocks-2022 separate header"),
    };
    *block = out;
}

/// The wire separate header (`ss::udp::separate_header_aes`).
fn separate_header(
    aead: SsAead,
    psk: &[u8],
    session_id: u64,
    packet_id: u64,
) -> [u8; SEPARATE_HEADER] {
    let mut header = [0u8; SEPARATE_HEADER];
    header[..8].copy_from_slice(&session_id.to_be_bytes());
    header[8..].copy_from_slice(&packet_id.to_be_bytes());
    aes_ecb_encrypt(aead, psk, &mut header);
    header
}

/// The 2022 body AEAD of a UDP datagram (`ss::udp::udp_cipher`): the `ChaCha`
/// method's UDP cipher is XChaCha20-Poly1305 even though its TCP stream is
/// ChaCha20-Poly1305 (spec §4.1).
const fn udp_cipher(method: SsMethod) -> SsAead {
    match method.aead {
        SsAead::ChaCha20Poly1305 => SsAead::XChaCha20Poly1305,
        other => other,
    }
}

/// The client→server 2022 main header + address + payload
/// (`ss::udp::client_body`). Real traffic always carries a payload, so the
/// keep-alive padding branch (payload-less datagrams only) is not reproduced.
fn s2022_client_body(dest: &TargetAddr, payload: &[u8], out: &mut Vec<u8>) {
    out.push(0); // `ss::udp::HEADER_TYPE_CLIENT_PACKET`
    out.extend_from_slice(&now_unix_secs().to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    write_addr_port_last(out, dest).expect("an IPv4 address encodes");
    out.extend_from_slice(payload);
}

/// A server→client 2022 body (spec §3.2.3), i.e. the shape
/// `ss::udp::parse_server_body` parses — the crate never writes one, so the
/// open rows' input is built here.
fn s2022_server_body(dest: &TargetAddr, client_session_id: u64, payload: &[u8], out: &mut Vec<u8>) {
    out.push(1); // `ss::udp::HEADER_TYPE_SERVER_PACKET`
    out.extend_from_slice(&now_unix_secs().to_be_bytes());
    out.extend_from_slice(&client_session_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    write_addr_port_last(out, dest).expect("an IPv4 address encodes");
    out.extend_from_slice(payload);
}

/// The benchmark target's destination: a loopback IPv4 target, so the wire
/// address is the 7-byte form both codecs' datagrams carry.
fn bench_dest() -> TargetAddr {
    TargetAddr::new(Host::Ip(Ipv4Addr::LOCALHOST.into()), 443)
}

/// The two-seal chunk framing rows both editions share: `seal` builds
/// `[2B len + tag][ct + tag]` into a reused buffer, `open` parses the frame
/// built once at setup with the same two counter nonces a writer would use.
fn chunk_rows(
    group: &mut Group<'_>,
    prefix: &str,
    name: &str,
    aead: SsAead,
    subkey: &[u8],
    payload: &[u8],
) {
    let len = u16::try_from(payload.len())
        .expect("a chunk fits the 2-byte length field")
        .to_be_bytes();
    group.throughput(Throughput::Bytes(
        u64::try_from(payload.len()).expect("payload length fits u64"),
    ));

    let mut out = Vec::with_capacity(LEN_SEAL + payload.len() + aead.tag_len());
    let mut seal_nonce = NonceCounter::new(aead.nonce_len());
    group.bench_function(format!("{prefix}/{name}/seal"), |b| {
        b.iter(|| {
            out.clear();
            aead.seal_into(subkey, seal_nonce.next_nonce(), b"", &len, &mut out)
                .expect("seal the length");
            aead.seal_into(subkey, seal_nonce.next_nonce(), b"", payload, &mut out)
                .expect("seal the payload");
            black_box(&out);
        });
    });

    // The frame the open row parses. Built here with its own counter so the
    // open loop starts at nonce 0, exactly as a reader does at the start of a
    // stream.
    let mut frame = Vec::with_capacity(LEN_SEAL + payload.len() + aead.tag_len());
    let mut framing_nonce = NonceCounter::new(aead.nonce_len());
    aead.seal_into(subkey, framing_nonce.next_nonce(), b"", &len, &mut frame)
        .expect("seal the length");
    aead.seal_into(subkey, framing_nonce.next_nonce(), b"", payload, &mut frame)
        .expect("seal the payload");

    let mut opened = Vec::with_capacity(payload.len());
    group.bench_function(format!("{prefix}/{name}/open"), |b| {
        b.iter(|| {
            // A fresh read direction per iteration: the counter starts at
            // zero again, so both opens draw the nonces the frame was sealed
            // with (0 for the length, 1 for the payload). `NonceCounter::new`
            // is a 24-byte array on the stack — no allocation.
            let mut nonce = NonceCounter::new(aead.nonce_len());
            opened.clear();
            aead.open_into(
                subkey,
                nonce.next_nonce(),
                b"",
                &frame[..LEN_SEAL],
                &mut opened,
            )
            .expect("open the length");
            aead.open_into(
                subkey,
                nonce.next_nonce(),
                b"",
                &frame[LEN_SEAL..],
                &mut opened,
            )
            .expect("open the payload");
            black_box(&opened);
        });
    });
}

/// Classic AEAD TCP chunks (`ss::stream::SsStream::push_chunks`): HKDF-SHA1
/// subkey, `MAX_CHUNK` payload per frame, two seals and two counter nonces.
fn classic_chunks(group: &mut Group<'_>) {
    let payload = vec![0xABu8; CLASSIC_CHUNK];
    for (name, aead) in classic_ciphers() {
        let method = SsMethod {
            aead,
            family: SsFamily::Classic,
        };
        // Per-cipher master key and client salt, exactly as `connect` derives
        // them: `EVP_BytesToKey` truncated to `key_len` (16/24/32) and
        // `salt_len = max(16, key_len)`. One subkey per connection:
        // `Half::new(method, key, client_salt)`.
        let key = password_key(method, CLASSIC_PASSWORD).expect("classic key");
        let salt = vec![0x33u8; aead.salt_len()];
        let subkey = stream_subkey(method, &key, &salt);
        chunk_rows(group, "classic", name, aead, &subkey, &payload);
    }
}

/// 2022-blake3 TCP chunks (`ss::stream2022::Ss2022Stream::push_chunks`): the
/// same two-seal framing at the 0xFFFF payload cap, subkey from BLAKE3.
fn s2022_chunks(group: &mut Group<'_>) {
    let payload = vec![0xABu8; S2022_CHUNK];
    // One subkey per connection: `Half::new(method, psk, client_salt)`, the
    // 32-byte salt the 2022 handshake sends before its header chunks.
    let salt = [0x44u8; 32];
    for name in ["2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"] {
        let method = SsMethod::from_method(name).expect("2022 method");
        let psk = password_key(method, S2022_PSK).expect("2022 PSK");
        let subkey = stream_subkey(method, &psk, &salt);
        chunk_rows(group, "s2022", name, method.aead, &subkey, &payload);
    }
}

/// Per-connection subkey derivation, once per connection and never per chunk
/// or packet: `kdf/hkdf_sha1` is the classic AEAD subkey, `kdf/blake3` the
/// 2022 one. Both return an owned `Zeroizing<Vec<u8>>` the connection then
/// holds, so the row includes the one allocation and the wipe on drop.
fn kdf_rows(group: &mut Group<'_>) {
    group.throughput(Throughput::Elements(1));
    let classic = SsMethod::from_method("aes-256-gcm").expect("classic");
    let s2022 = SsMethod::from_method("2022-blake3-aes-256-gcm").expect("2022");
    let classic_key = password_key(classic, CLASSIC_PASSWORD).expect("classic key");
    let psk = password_key(s2022, S2022_PSK).expect("2022 PSK");
    let salt = [0x22u8; 32];
    group.bench_function("kdf/hkdf_sha1", |b| {
        b.iter(|| stream_subkey(classic, &classic_key, &salt));
    });
    group.bench_function("kdf/blake3", |b| {
        b.iter(|| stream_subkey(s2022, &psk, &salt));
    });
}

/// The classic datagram send path (`ss::udp::seal_datagram_into`): draw a
/// fresh salt, derive a fresh HKDF subkey, seal `addr ‖ payload` under the
/// all-zero nonce, and write `salt ‖ seal` into a reused packet buffer.
fn udp_classic_seal(
    group: &mut Group<'_>,
    name: &str,
    method: SsMethod,
    key: &[u8],
    dest: &TargetAddr,
    payload: &[u8],
    rng: &SystemRandom,
) {
    let aead = method.aead;
    let salt_len = aead.salt_len();
    let zero_nonce = [0u8; UDP_CHACHA_NONCE];
    let nonce = &zero_nonce[..aead.nonce_len()];
    let mut salt = vec![0u8; salt_len];
    let mut packet = Vec::with_capacity(salt_len + IPV4_ADDR + payload.len() + aead.tag_len());
    let mut body = Vec::with_capacity(IPV4_ADDR + payload.len());
    group.throughput(Throughput::Bytes(
        u64::try_from(payload.len()).expect("payload length fits u64"),
    ));
    group.bench_function(format!("udp/classic/{name}/seal"), |b| {
        b.iter(|| {
            // Production fills the salt through `crate::rand::fill_nonsecret`
            // (the pooled `getrandom`), which adds a pool read, not entropy.
            rng.fill(&mut salt).expect("system rng");
            let subkey = stream_subkey(method, key, &salt);
            packet.clear();
            body.clear();
            packet.extend_from_slice(&salt);
            write_addr_port_last(&mut body, dest).expect("an IPv4 address encodes");
            body.extend_from_slice(payload);
            aead.seal_into(&subkey, nonce, b"", &body, &mut packet)
                .expect("seal the datagram");
            black_box(&packet);
        });
    });
}

/// The classic datagram receive path (`ss::udp::open_datagram`): salt →
/// subkey → open → decode the address the authenticated body carries.
fn udp_classic_open(
    group: &mut Group<'_>,
    name: &str,
    method: SsMethod,
    key: &[u8],
    dest: &TargetAddr,
    payload: &[u8],
) {
    let aead = method.aead;
    let salt_len = aead.salt_len();
    let zero_nonce = [0u8; UDP_CHACHA_NONCE];
    let nonce = &zero_nonce[..aead.nonce_len()];
    // The peer's datagram: the same shape the seal row produces, built once
    // outside the timed loop (only the fresh salt draw is a seal-side cost).
    let mut body = Vec::with_capacity(IPV4_ADDR + payload.len());
    write_addr_port_last(&mut body, dest).expect("an IPv4 address encodes");
    body.extend_from_slice(payload);
    let salt = vec![0x55u8; salt_len];
    let packet: Vec<u8> = {
        let subkey = stream_subkey(method, key, &salt);
        let mut packet = Vec::with_capacity(salt_len + body.len() + aead.tag_len());
        packet.extend_from_slice(&salt);
        aead.seal_into(&subkey, nonce, b"", &body, &mut packet)
            .expect("seal the datagram");
        packet
    };
    group.throughput(Throughput::Bytes(
        u64::try_from(payload.len()).expect("payload length fits u64"),
    ));
    group.bench_function(format!("udp/classic/{name}/open"), |b| {
        b.iter(|| {
            let subkey = stream_subkey(method, key, &packet[..salt_len]);
            let body = aead
                .open(&subkey, nonce, b"", &packet[salt_len..])
                .expect("open the datagram");
            let (origin, tail) = decode_addr_port_last(&body).expect("a decodable address");
            black_box((origin, tail.to_vec()));
        });
    });
}

/// The 2022 AES datagram send path (`Ss2022WriterState::seal`): the
/// AES-ECB separate header on the wire, the body sealed with the session
/// subkey under the plaintext header's `[4..16]` nonce.
fn udp_s2022_aes_seal(
    group: &mut Group<'_>,
    method: SsMethod,
    psk: &[u8],
    dest: &TargetAddr,
    payload: &[u8],
) {
    let aead = method.aead;
    // One subkey per session: `udp_session_subkey(method, psk, client_id)`.
    let subkey = stream_subkey(method, psk, &S2022_SESSION_ID.to_be_bytes());
    let mut body = Vec::with_capacity(S2022_CLIENT_FIXED + IPV4_ADDR + payload.len());
    let mut packet =
        Vec::with_capacity(SEPARATE_HEADER + S2022_CLIENT_FIXED + IPV4_ADDR + payload.len() + 16);
    let mut packet_id = 0u64;
    group.throughput(Throughput::Bytes(
        u64::try_from(payload.len()).expect("payload length fits u64"),
    ));
    group.bench_function("udp/s2022-aes/seal", |b| {
        b.iter(|| {
            let id = packet_id;
            let nonce = separate_nonce(S2022_SESSION_ID, id);
            let header = separate_header(aead, psk, S2022_SESSION_ID, id);
            packet.clear();
            body.clear();
            packet.extend_from_slice(&header);
            s2022_client_body(dest, payload, &mut body);
            aead.seal_into(&subkey, &nonce, b"", &body, &mut packet)
                .expect("seal the datagram");
            packet_id = packet_id.wrapping_add(1);
            black_box(&packet);
        });
    });
}

/// The 2022 AES datagram receive path's known-session branch
/// (`Ss2022ReaderState::open_aes`): decrypt the separate header, open the
/// body with the session subkey under the recovered nonce, decode the address
/// the authenticated body carries.
fn udp_s2022_aes_open(
    group: &mut Group<'_>,
    method: SsMethod,
    psk: &[u8],
    dest: &TargetAddr,
    payload: &[u8],
) {
    let aead = method.aead;
    let server_subkey = stream_subkey(method, psk, &S2022_SERVER_ID.to_be_bytes());
    let packet_id = 7u64;
    let packet = {
        let mut body = Vec::with_capacity(S2022_SERVER_FIXED + IPV4_ADDR + payload.len());
        s2022_server_body(dest, S2022_SESSION_ID, payload, &mut body);
        let mut packet = separate_header(aead, psk, S2022_SERVER_ID, packet_id).to_vec();
        aead.seal_into(
            &server_subkey,
            &separate_nonce(S2022_SERVER_ID, packet_id),
            b"",
            &body,
            &mut packet,
        )
        .expect("seal the datagram");
        packet
    };
    group.throughput(Throughput::Bytes(
        u64::try_from(payload.len()).expect("payload length fits u64"),
    ));
    group.bench_function("udp/s2022-aes/open", |b| {
        b.iter(|| {
            let mut header: [u8; SEPARATE_HEADER] = packet[..SEPARATE_HEADER]
                .try_into()
                .expect("the header is one AES block");
            aes_ecb_decrypt(aead, psk, &mut header);
            let server_id = u64::from_be_bytes(header[..8].try_into().expect("8 bytes"));
            let id = u64::from_be_bytes(header[8..].try_into().expect("8 bytes"));
            let body = aead
                .open(
                    &server_subkey,
                    &separate_nonce(server_id, id),
                    b"",
                    &packet[SEPARATE_HEADER..],
                )
                .expect("open the datagram");
            let (origin, tail) =
                decode_addr_port_last(&body[S2022_SERVER_FIXED..]).expect("a decodable address");
            black_box((server_id, id, origin, tail.to_vec()));
        });
    });
}

/// The 2022 `ChaCha` datagram send path (`Ss2022WriterState::seal`, `ChaCha`
/// arm): a 24-byte random nonce leads, the ids merge into the sealed body,
/// and the PSK seals it directly (spec §4.1 uses XChaCha20-Poly1305 here,
/// not the stream's ChaCha20-Poly1305).
fn udp_s2022_chacha_seal(
    group: &mut Group<'_>,
    method: SsMethod,
    psk: &[u8],
    dest: &TargetAddr,
    payload: &[u8],
    rng: &SystemRandom,
) {
    let aead = udp_cipher(method);
    let mut nonce = [0u8; UDP_CHACHA_NONCE];
    let mut body = Vec::with_capacity(2 * 8 + S2022_CLIENT_FIXED + IPV4_ADDR + payload.len());
    let mut packet = Vec::with_capacity(
        UDP_CHACHA_NONCE + 2 * 8 + S2022_CLIENT_FIXED + IPV4_ADDR + payload.len() + 16,
    );
    let mut packet_id = 0u64;
    group.throughput(Throughput::Bytes(
        u64::try_from(payload.len()).expect("payload length fits u64"),
    ));
    group.bench_function("udp/s2022-chacha/seal", |b| {
        b.iter(|| {
            let id = packet_id;
            rng.fill(&mut nonce).expect("system rng");
            packet.clear();
            body.clear();
            packet.extend_from_slice(&nonce);
            body.extend_from_slice(&S2022_SESSION_ID.to_be_bytes());
            body.extend_from_slice(&id.to_be_bytes());
            s2022_client_body(dest, payload, &mut body);
            aead.seal_into(psk, &nonce, b"", &body, &mut packet)
                .expect("seal the datagram");
            packet_id = packet_id.wrapping_add(1);
            black_box(&packet);
        });
    });
}

/// The 2022 `ChaCha` datagram receive path (`Ss2022ReaderState::open_chacha`):
/// the leading nonce opens the body, and the ids only exist inside the
/// authenticated plaintext.
fn udp_s2022_chacha_open(
    group: &mut Group<'_>,
    method: SsMethod,
    psk: &[u8],
    dest: &TargetAddr,
    payload: &[u8],
) {
    let aead = udp_cipher(method);
    let packet_id = 7u64;
    let packet = {
        let nonce = [0x66u8; UDP_CHACHA_NONCE];
        let mut plain = Vec::with_capacity(2 * 8 + S2022_SERVER_FIXED + IPV4_ADDR + payload.len());
        plain.extend_from_slice(&S2022_SERVER_ID.to_be_bytes());
        plain.extend_from_slice(&packet_id.to_be_bytes());
        s2022_server_body(dest, S2022_SESSION_ID, payload, &mut plain);
        let mut packet = nonce.to_vec();
        aead.seal_into(psk, &nonce, b"", &plain, &mut packet)
            .expect("seal the datagram");
        packet
    };
    group.throughput(Throughput::Bytes(
        u64::try_from(payload.len()).expect("payload length fits u64"),
    ));
    group.bench_function("udp/s2022-chacha/open", |b| {
        b.iter(|| {
            let (nonce, sealed) = packet.split_at(UDP_CHACHA_NONCE);
            let plain = aead
                .open(psk, nonce, b"", sealed)
                .expect("open the datagram");
            let server_id = u64::from_be_bytes(plain[..8].try_into().expect("8 bytes"));
            let id = u64::from_be_bytes(plain[8..16].try_into().expect("8 bytes"));
            let (origin, tail) = decode_addr_port_last(&plain[2 * 8 + S2022_SERVER_FIXED..])
                .expect("a decodable address");
            black_box((server_id, id, origin, tail.to_vec()));
        });
    });
}

/// The classic datagram rows: the two classic ciphers with an e2e UDP row.
fn udp_classic_rows(group: &mut Group<'_>) {
    let dest = bench_dest();
    let payload = vec![0xABu8; UDP_PAYLOAD];
    let rng = SystemRandom::new();
    for (name, aead) in [
        ("aes-256-gcm", SsAead::Aes256Gcm),
        ("chacha20-ietf-poly1305", SsAead::ChaCha20Poly1305),
    ] {
        let method = SsMethod {
            aead,
            family: SsFamily::Classic,
        };
        let key = password_key(method, CLASSIC_PASSWORD).expect("classic key");
        udp_classic_seal(group, name, method, &key, &dest, &payload, &rng);
        udp_classic_open(group, name, method, &key, &dest, &payload);
    }
}

/// Both 2022 UDP rows: the AES method's separate header against the `ChaCha`
/// method's leading nonce (spec §4.1's two constructions).
fn udp_s2022_rows(group: &mut Group<'_>) {
    let dest = bench_dest();
    let payload = vec![0xABu8; UDP_PAYLOAD];
    let rng = SystemRandom::new();
    let aes = SsMethod::from_method("2022-blake3-aes-256-gcm").expect("2022 AES method");
    let chacha =
        SsMethod::from_method("2022-blake3-chacha20-poly1305").expect("2022 ChaCha method");
    let aes_psk = password_key(aes, S2022_PSK).expect("2022 AES PSK");
    let chacha_psk = password_key(chacha, S2022_PSK).expect("2022 ChaCha PSK");
    udp_s2022_aes_seal(group, aes, &aes_psk, &dest, &payload);
    udp_s2022_aes_open(group, aes, &aes_psk, &dest, &payload);
    udp_s2022_chacha_seal(group, chacha, &chacha_psk, &dest, &payload, &rng);
    udp_s2022_chacha_open(group, chacha, &chacha_psk, &dest, &payload);
}

fn criterion_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("ss_codec");
    classic_chunks(&mut group);
    s2022_chunks(&mut group);
    kdf_rows(&mut group);
    udp_classic_rows(&mut group);
    udp_s2022_rows(&mut group);
    group.finish();
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
