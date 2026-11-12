//! Exact allocation-count gate for leas hot paths.
//!
//! Run with `cargo run --release -p leas-hotpath` (or `just hotpath`). Each row
//! drives one real code path with a counting global allocator installed and
//! asserts the allocation count it is allowed to cost. A breach exits non-zero
//! and names the row.
//!
//! Wall-clock time is not measured and not gated: a duration on a shared
//! runner is a distribution, an allocation count is a fact.
//!
//! The rows reach only public surfaces, on purpose. A path that is `pub(crate)`
//! (`protocol::vless::vision`, the mux frame codec, the relay copy loop) is not
//! measured here — this crate never asks the library to expose a hook for a
//! benchmark.

mod alloc_count;

use std::process::ExitCode;

use alloc_count::{Counting, Counts, measure_async};
use leas_native::addr::{Host, TargetAddr};
use leas_native::protocol::vless::header::{CMD_TCP, encode_request};
use leas_native::protocol::vless::stream::VlessClientStream;
use leas_tls::crypto::{AeadKey, CipherSuiteId};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The `flow=xtls-rprx-vision` addon as it goes on the wire: protobuf field 1,
/// 16-byte string. The encoder is `pub(crate)`, so the row states the bytes.
const VISION_ADDONS: [u8; 18] = [
    0x0a, 0x10, b'x', b't', b'l', b's', b'-', b'r', b'p', b'r', b'x', b'-', b'v', b'i', b's', b'i',
    b'o', b'n',
];

/// Payload size for the row that measures the VLESS response-header peel.
const PEEL_PAYLOAD: usize = 1024;
/// Plaintext size for the record rows: one TLS 1.3 record's worth.
const RECORD_PLAINTEXT: usize = 16 * 1024;
/// The five-byte TLS record header that sits outside the AEAD input.
const RECORD_HEADER: [u8; 5] = [0x17, 0x03, 0x03, 0x40, 0x00];

#[global_allocator]
static ALLOC: Counting = Counting;

/// One measured row: what was observed and what it is allowed to cost.
struct Row {
    name: &'static str,
    counts: Counts,
    max_allocs: usize,
    max_reallocs: usize,
    max_zeroed: usize,
}

impl Row {
    const fn passed(&self) -> bool {
        self.counts.allocs <= self.max_allocs
            && self.counts.reallocs <= self.max_reallocs
            && self.counts.zeroed <= self.max_zeroed
    }
}

fn main() -> ExitCode {
    if cfg!(debug_assertions) {
        eprintln!("run with --release: a debug build measures debug code");
        return ExitCode::FAILURE;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let rows = runtime.block_on(run());
    report(&rows)
}

async fn run() -> Vec<Row> {
    vec![
        vless_header_row().await,
        vless_header_vision_row().await,
        vless_peel_row().await,
        tls_seal_row().await,
        tls_open_row().await,
    ]
}

/// `encode_request` builds the header into its own `Vec`: an IPv4 target fits
/// the initial 32-byte capacity, so one allocation and no grow is the whole
/// budget. A `String`, a `format!` or a second buffer shows up as a breach.
async fn vless_header_row() -> Row {
    let uuid = [0x5a_u8; 16];
    let target = TargetAddr::new(Host::new("127.0.0.1"), 443);
    let (_header_len, counts) = measure_async(async move {
        let header = encode_request(&uuid, &target, CMD_TCP, None).expect("encode header");
        header.len()
    })
    .await;
    Row {
        name: "vless/header/tcp-ipv4",
        counts,
        max_allocs: 1,
        max_reallocs: 0,
        max_zeroed: 0,
    }
}

/// The same encoder with the Vision addon: the header reserves room for the
/// addons up front, so a flow connect does not realloc the header it is about
/// to write.
async fn vless_header_vision_row() -> Row {
    let uuid = [0x5a_u8; 16];
    let target = TargetAddr::new(Host::new("127.0.0.1"), 443);
    let addons = VISION_ADDONS;
    let (_header_len, counts) = measure_async(async move {
        let header = encode_request(&uuid, &target, CMD_TCP, Some(&addons)).expect("encode header");
        header.len()
    })
    .await;
    Row {
        name: "vless/header/tcp-ipv4-vision",
        counts,
        max_allocs: 1,
        max_reallocs: 0,
        max_zeroed: 0,
    }
}

/// The peel reads into a stack scratch on its one header-bearing read and
/// passes through afterwards; the row buffers are allocated before the
/// measurement so only the peel's own work is counted.
async fn vless_peel_row() -> Row {
    let (client, mut server) = tokio::io::duplex(4096);
    let mut response = Vec::with_capacity(2 + PEEL_PAYLOAD);
    response.extend_from_slice(&[0x00, 0x00]); // version, addon_len
    response.resize(2 + PEEL_PAYLOAD, 0x41);
    server.write_all(&response).await.expect("prefill duplex");
    server.flush().await.expect("flush duplex");

    let mut stream = VlessClientStream::new(Box::new(client));
    let mut buf = vec![0_u8; PEEL_PAYLOAD];
    let (read_len, counts) =
        measure_async(async move { stream.read(&mut buf).await.expect("read through peel") }).await;
    drop(server);
    assert_eq!(read_len, PEEL_PAYLOAD, "the peel swallowed payload bytes");
    Row {
        name: "vless/peel/1k",
        counts,
        max_allocs: 0,
        max_reallocs: 0,
        max_zeroed: 0,
    }
}

/// The production record path seals in place into a caller-framed buffer
/// (`AeadKey::seal_in_place`); nothing in it may allocate. The buffer is
/// reserved for body plus tag before the measurement, so a `realloc` would be
/// a breach too.
async fn tls_seal_row() -> Row {
    let key = record_key();
    let mut record = Vec::with_capacity(RECORD_HEADER.len() + RECORD_PLAINTEXT + 16);
    record.extend_from_slice(&RECORD_HEADER);
    record.resize(RECORD_HEADER.len() + RECORD_PLAINTEXT, 0x5a);
    let body_start = RECORD_HEADER.len();
    let ((), counts) = measure_async(async {
        key.seal_in_place(0, &RECORD_HEADER, &mut record, body_start)
            .expect("seal record");
    })
    .await;
    Row {
        name: "tls13/seal/16k-in-place",
        counts,
        max_allocs: 0,
        max_reallocs: 0,
        max_zeroed: 0,
    }
}

/// The matching open. The record is sealed before the measurement; opening it
/// in place must cost nothing.
async fn tls_open_row() -> Row {
    let key = record_key();
    let mut sealed = Vec::with_capacity(RECORD_HEADER.len() + RECORD_PLAINTEXT + 16);
    sealed.extend_from_slice(&RECORD_HEADER);
    sealed.resize(RECORD_HEADER.len() + RECORD_PLAINTEXT, 0x5a);
    key.seal_in_place(0, &RECORD_HEADER, &mut sealed, RECORD_HEADER.len())
        .expect("seal record");
    // The open works on the ciphertext body, which the record header does not
    // cover as AEAD input; the aad is the header either way.
    let mut body = sealed.split_off(RECORD_HEADER.len());

    let (plain_len, counts) = measure_async(async {
        key.open_in_place(0, &RECORD_HEADER, &mut body)
            .expect("open record")
    })
    .await;
    assert_eq!(plain_len, RECORD_PLAINTEXT, "opened record length");
    Row {
        name: "tls13/open/16k-in-place",
        counts,
        max_allocs: 0,
        max_reallocs: 0,
        max_zeroed: 0,
    }
}

fn record_key() -> AeadKey {
    AeadKey::from_key_bytes(CipherSuiteId::Aes128GcmSha256, &[0x42_u8; 16])
        .expect("a 16-byte key for AES-128-GCM")
}

fn report(rows: &[Row]) -> ExitCode {
    let mut failed = 0_usize;
    println!(
        "{:<26} {:>8} {:>8} {:>9} {:>7}  verdict",
        "row", "allocs", "realloc", "zeroed", "bytes"
    );
    for row in rows {
        let passed = row.passed();
        if !passed {
            failed += 1;
        }
        println!(
            "{:<26} {:>3}/{:<4} {:>3}/{:<4} {:>4}/{:<4} {:>7}  {}",
            row.name,
            row.counts.allocs,
            row.max_allocs,
            row.counts.reallocs,
            row.max_reallocs,
            row.counts.zeroed,
            row.max_zeroed,
            row.counts.bytes,
            if passed { "ok" } else { "FAIL" },
        );
    }
    if failed == 0 {
        println!("\n{} row(s) within budget", rows.len());
        ExitCode::SUCCESS
    } else {
        eprintln!("\n{failed} row(s) over budget");
        ExitCode::FAILURE
    }
}
