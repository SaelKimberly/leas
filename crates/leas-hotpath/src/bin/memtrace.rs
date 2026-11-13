//! Drive real leas code paths under the tracing allocator and write the
//! per-module memory artifacts.
//!
//! `cargo run --release -p leas-hotpath --bin memtrace -- [header|record|all] [iterations]`
//!
//! Unlike the allocation-count gate in `main.rs` this accepts a debug build: it
//! asserts nothing, it reports. Counts stay exact in either profile; the
//! artifact's header carries the duration so a slow run explains itself.

use std::hint::black_box;
use std::path::Path;
use std::process::ExitCode;

use leas_memtrace::TracingAllocator;
use leas_native::addr::{Host, TargetAddr};
use leas_native::protocol::vless::header::{CMD_TCP, encode_request};
use leas_tls::crypto::{AeadKey, CipherSuiteId};

#[global_allocator]
static ALLOC: TracingAllocator = TracingAllocator::new();

/// Only these crates' modules are attributed; `leas-hotpath`'s own frames are
/// the driver, not the measurement.
const ROOTS: &[&str] = &["leas_native", "leas_tls"];

/// The `flow=xtls-rprx-vision` addon as it goes on the wire (the encoder is
/// `pub(crate)`, so the row states the bytes).
const VISION_ADDONS: [u8; 18] = [
    0x0a, 0x10, b'x', b't', b'l', b's', b'-', b'r', b'p', b'r', b'x', b'-', b'v', b'i', b's', b'i',
    b'o', b'n',
];

/// The five-byte TLS record header that sits outside the AEAD input.
const RECORD_HEADER: [u8; 5] = [0x17, 0x03, 0x03, 0x40, 0x00];
const RECORD_PLAINTEXT: usize = 16 * 1024;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let workload = args.next().unwrap_or_else(|| "all".to_owned());
    let iterations: usize = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1000);
    let dir = std::env::var("LEAS_MEM_TRACE_DIR").unwrap_or_else(|_| "target/mem-trace".to_owned());

    leas_memtrace::start(ROOTS, 0);
    match workload.as_str() {
        "header" => header_workload(iterations),
        "record" => record_workload(iterations),
        "all" => {
            header_workload(iterations);
            record_workload(iterations);
        }
        other => {
            eprintln!("unknown workload {other}: expected header | record | all");
            return ExitCode::FAILURE;
        }
    }

    let artifacts = match leas_memtrace::write(Path::new(&dir), &workload) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            eprintln!("memtrace: artifact not written: {error}");
            return ExitCode::FAILURE;
        }
    };
    report(&workload, iterations, &artifacts);
    ExitCode::SUCCESS
}

/// VLESS request headers, the allocation the count gate already budgets: the
/// artifact shows which module pays for it.
fn header_workload(iterations: usize) {
    let uuid = [0x5a_u8; 16];
    let target = TargetAddr::new(Host::new("127.0.0.1"), 443);
    for _ in 0..iterations {
        let header =
            encode_request(&uuid, &target, CMD_TCP, Some(&VISION_ADDONS)).expect("encode header");
        black_box(header.len());
    }
}

/// TLS 1.3 record seal + open, the encryption path every proxied byte crosses.
fn record_workload(iterations: usize) {
    let key = AeadKey::from_key_bytes(CipherSuiteId::Aes128GcmSha256, &[0x42_u8; 16])
        .expect("a 16-byte key for AES-128-GCM");
    let plaintext = vec![0x5a_u8; RECORD_PLAINTEXT];
    for sequence in 0..iterations {
        let mut record = Vec::with_capacity(RECORD_HEADER.len() + RECORD_PLAINTEXT + 16);
        record.extend_from_slice(&RECORD_HEADER);
        record.extend_from_slice(&plaintext);
        let sequence = u64::try_from(sequence).unwrap_or(0);
        key.seal_in_place(sequence, &RECORD_HEADER, &mut record, RECORD_HEADER.len())
            .expect("seal record");
        let mut body = record.split_off(RECORD_HEADER.len());
        let opened = key
            .open_in_place(sequence, &RECORD_HEADER, &mut body)
            .expect("open record");
        black_box(opened);
    }
}

fn report(workload: &str, iterations: usize, artifacts: &leas_memtrace::Artifacts) {
    println!("workload: {workload} x {iterations} (this process only)");
    println!("artifact: {}", artifacts.text.display());
    let snapshot = &artifacts.snapshot;
    let mut rows = snapshot.rows.clone();
    // The interesting column here is the peak: the live set at the end of a
    // loop is a snapshot of the allocator, not of the workload.
    rows.sort_by(|a, b| {
        b.peak_live_bytes
            .cmp(&a.peak_live_bytes)
            .then_with(|| b.total_bytes.cmp(&a.total_bytes))
    });
    println!(
        "{:<52} {:>10} {:>10} {:>10}",
        "module", "peak B", "total B", "allocs"
    );
    for row in rows.iter().take(10) {
        println!(
            "{:<52} {:>10} {:>10} {:>10}",
            row.name, row.peak_live_bytes, row.total_bytes, row.total_count
        );
    }
    println!(
        "cache: hits {} resolves {} evictions {}",
        snapshot.cache.hits, snapshot.cache.resolves, snapshot.cache.evictions
    );
}
