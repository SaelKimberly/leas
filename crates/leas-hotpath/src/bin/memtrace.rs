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
//! `memtrace compare <a.json> <b.json> [--force]` diffs two artifacts instead of
//! running a workload: per-module Δallocations/Δbytes, biggest change first. It
//! refuses runs whose `schema`, `rev` or roots differ unless forced, because a
//! delta across builds is not a delta of the change under review.
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
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("compare") {
        return compare(&argv);
    }
    let workload = argv.first().cloned().unwrap_or_else(|| "all".to_owned());
    let iterations: usize = argv
        .get(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(1000);
    let dir = std::env::var("LEAS_MEM_TRACE_DIR").unwrap_or_else(|_| "target/mem-trace".to_owned());

    if !leas_memtrace::start_with(ROOTS, 0, &[("bin", "memtrace")]) {
        eprintln!("memtrace: a trace window is already running; reusing it");
    }
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

/// `memtrace compare a.json b.json [--force]`: per-module deltas between two
/// artifacts, sorted by absolute allocation change.
///
/// Refuses to diff runs whose `rev`, `schema` or roots differ, because a delta
/// across builds is not a delta of the change under review (`--force` overrides).
fn compare(args: &[String]) -> ExitCode {
    let paths: Vec<&String> = args.iter().skip(1).filter(|a| *a != "--force").collect();
    let force = args.iter().any(|a| a == "--force");
    let [left, right] = paths.as_slice() else {
        eprintln!("usage: memtrace compare <a.json> <b.json> [--force]");
        return ExitCode::FAILURE;
    };
    let load = |path: &str| -> Result<serde_json::Value, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
    };
    let (Ok(a), Ok(b)) = (load(left), load(right)) else {
        return ExitCode::FAILURE;
    };
    for key in ["schema", "rev"] {
        if a.get(key) != b.get(key) && !force {
            eprintln!(
                "compare: {key} differs ({:?} vs {:?}); pass --force to diff anyway",
                a.get(key),
                b.get(key)
            );
            return ExitCode::FAILURE;
        }
    }
    if a.get("roots") != b.get("roots") && !force {
        eprintln!("compare: roots differ; pass --force to diff anyway");
        return ExitCode::FAILURE;
    }
    println!(
        "compare: {} vs {}",
        a["scope"].as_str().unwrap_or("a"),
        b["scope"].as_str().unwrap_or("b")
    );
    println!(
        "rev: {} | {}   allocs: {} -> {}",
        a["rev"].as_str().unwrap_or("?"),
        b["rev"].as_str().unwrap_or("?"),
        a["totals"]["allocs"],
        b["totals"]["allocs"]
    );
    let rows = |doc: &serde_json::Value| -> std::collections::HashMap<String, (i64, i64)> {
        doc["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| {
                Some((
                    row["name"].as_str()?.to_owned(),
                    (row["total_count"].as_i64()?, row["total_bytes"].as_i64()?),
                ))
            })
            .collect()
    };
    let deltas = compare_deltas(&rows(&a), &rows(&b));
    println!("\n{:<46} {:>12} {:>12}", "module", "Δ allocs", "Δ bytes");
    for (name, count, bytes) in deltas.iter().take(25) {
        println!("{name:<46} {count:>12} {bytes:>12}");
    }
    ExitCode::SUCCESS
}

/// Per-module `(name, Δallocs, Δbytes)` between two row maps, biggest
/// allocation change first. A module that appears in only one artifact is a
/// delta from zero, which is the interesting case after a refactor.
fn compare_deltas(
    a: &std::collections::HashMap<String, (i64, i64)>,
    b: &std::collections::HashMap<String, (i64, i64)>,
) -> Vec<(String, i64, i64)> {
    let mut names: Vec<&String> = a.keys().chain(b.keys()).collect();
    names.sort_unstable();
    names.dedup();
    let mut deltas: Vec<(String, i64, i64)> = names
        .into_iter()
        .map(|name| {
            let (ca, ba) = a.get(name).copied().unwrap_or((0, 0));
            let (cb, bb) = b.get(name).copied().unwrap_or((0, 0));
            (name.clone(), cb - ca, bb - ba)
        })
        .filter(|(_, ca, ba)| *ca != 0 || *ba != 0)
        .collect();
    deltas.sort_by(|x, y| y.1.abs().cmp(&x.1.abs()).then_with(|| x.0.cmp(&y.0)));
    deltas
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

#[cfg(test)]
mod tests {
    use super::compare_deltas;
    use std::collections::HashMap;

    fn rows(entries: &[(&str, i64, i64)]) -> HashMap<String, (i64, i64)> {
        entries
            .iter()
            .map(|(name, allocs, bytes)| ((*name).to_owned(), (*allocs, *bytes)))
            .collect()
    }

    /// A module that disappears is a delta to zero, and the biggest allocation
    /// change sorts first — the table exists to answer "what changed".
    #[test]
    fn deltas_cover_added_removed_and_changed_modules() {
        let a = rows(&[("leas::a", 100, 1000), ("leas::gone", 40, 400)]);
        let b = rows(&[("leas::a", 130, 1300), ("leas::new", 7, 70)]);
        let deltas = compare_deltas(&a, &b);
        assert_eq!(
            deltas,
            vec![
                ("leas::gone".to_owned(), -40, -400),
                ("leas::a".to_owned(), 30, 300),
                ("leas::new".to_owned(), 7, 70),
            ]
        );
    }

    /// An unchanged run is an empty table, not a list of zeros.
    #[test]
    fn identical_runs_produce_no_rows() {
        let rows = rows(&[("leas::a", 10, 100)]);
        let deltas: Vec<(String, i64, i64)> = compare_deltas(&rows, &rows);
        assert_eq!(deltas.len(), 0, "an unchanged run must not list rows");
    }
}
