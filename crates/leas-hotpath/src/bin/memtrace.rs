//! Drive real leas code paths under the tracing allocator and write the
//! per-module memory artifacts.
//!
//! ```text
//! cargo run --release -p leas-hotpath --bin memtrace -- \
//!     [header|connect|geosite|record|all] [iterations]
//! ```
//!
//! `geosite` measures the geo loader in isolation and requires `LEAS_GEOSITE_PATH`
//! (a `geosite.dat`) and `LEAS_GEOSITE_CODES` (comma-separated category tokens);
//! it refuses to run without them, because a workload that silently measured
//! nothing would be worse than none.
//!
//! Unlike the allocation-count gate in `main.rs` this accepts a debug build: it
//! asserts nothing, it reports. Counts stay exact in either profile; the
//! artifact's header carries the duration so a slow run explains itself.

use std::hint::black_box;
use std::path::Path;
use std::process::ExitCode;

use leas_memtrace::TracingAllocator;
use leas_native::addr::{Host, TargetAddr};
use leas_native::protocol::vless::header::{
    CMD_TCP, HEADER_RESERVE, encode_addons, encode_request, encode_request_into,
};
use leas_tls::crypto::{AeadKey, CipherSuiteId};

#[global_allocator]
static ALLOC: TracingAllocator = TracingAllocator::new();

/// Only these crates' modules are attributed; `leas-hotpath`'s own frames are
/// the driver, not the measurement.
const ROOTS: &[&str] = &["leas_geoip", "leas_native", "leas_tls"];

/// The `flow=xtls-rprx-vision` addon as it goes on the wire (the encoder is
/// `pub(crate)`, so the row states the bytes).
const VISION_ADDONS: [u8; 18] = [
    0x0a, 0x10, b'x', b't', b'l', b's', b'-', b'r', b'p', b'r', b'x', b'-', b'v', b'i', b's', b'i',
    b'o', b'n',
];

/// The five-byte TLS record header that sits outside the AEAD input.
const RECORD_HEADER: [u8; 5] = [0x17, 0x03, 0x03, 0x40, 0x00];
const RECORD_PLAINTEXT: usize = 16 * 1024;

#[allow(clippy::too_many_lines)]
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
        "connect" => connect_workload(iterations),
        "geosite" => {
            let code = geosite_workload(iterations);
            if code != ExitCode::SUCCESS {
                return code;
            }
        }
        "record" => record_workload(iterations),
        "all" => {
            header_workload(iterations);
            connect_workload(iterations);
            record_workload(iterations);
        }
        other => {
            eprintln!(
                "unknown workload {other}: expected header | connect | geosite | record | all"
            );
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

/// The connect shape a Vision tunnel actually builds: the request header is
/// appended to the buffer `HeaderFirst` will own, with the addons handed over
/// as a constant slice. One allocation per connect is the budget.
fn connect_workload(iterations: usize) {
    let uuid = [0x5a_u8; 16];
    let target = TargetAddr::new(Host::new("127.0.0.1"), 443);
    for _ in 0..iterations {
        let mut header = Vec::with_capacity(HEADER_RESERVE);
        encode_request_into(
            &mut header,
            &uuid,
            &target,
            CMD_TCP,
            encode_addons(Some("xtls-rprx-vision")),
        )
        .expect("encode header");
        black_box(header.len());
    }
}

/// The geosite loader in isolation: one `load_geosite` call per iteration for the
/// categories named in `LEAS_GEOSITE_CODES` (comma-separated). `LEAS_GEOSITE_PATH`
/// points at the dataset; both are required, because a workload that silently
/// measured nothing would be worse than no workload.
fn geosite_workload(iterations: usize) -> ExitCode {
    let Ok(path) = std::env::var("LEAS_GEOSITE_PATH") else {
        eprintln!("geosite: set LEAS_GEOSITE_PATH to a geosite.dat");
        return ExitCode::FAILURE;
    };
    let codes: Vec<String> = std::env::var("LEAS_GEOSITE_CODES")
        .unwrap_or_default()
        .split(',')
        .map(|code| code.trim().to_owned())
        .filter(|code| !code.is_empty())
        .collect();
    if codes.is_empty() {
        eprintln!("geosite: set LEAS_GEOSITE_CODES to a comma-separated token list");
        return ExitCode::FAILURE;
    }
    let path = Path::new(&path);
    for _ in 0..iterations {
        let loaded = leas_geoip::geodata::load_geosite(path, &codes).expect("load geosite");
        black_box(loaded.len());
    }
    ExitCode::SUCCESS
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
