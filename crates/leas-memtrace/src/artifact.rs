//! Artifacts: a JSON document, a human table and an inferno/flamegraph folded
//! stack file, all from one [`Snapshot`].
//!
//! Every artifact states the same facts in its header — process scope, window
//! duration, root filter, minimum size, cache counters — because a memory table
//! without them is read as a whole-application picture, which it is not.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use crate::UNTRACED_ROW;
use crate::attrib;
use crate::table::{
    ALLOCS, ATTRIBUTED, CACHE_EVICTIONS, CACHE_HITS, CACHE_RESOLVES, DEALLOCS, FRAMES_WALKED,
    LIVE_BYTES, OVERFLOWED, PEAK_LIVE_BYTES,
};

/// Short git revision of the build, stamped by `build.rs`; `unknown` outside a
/// checkout (a published crate, a packaged source tree).
pub const REV: &str = match option_env!("LEAS_GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

/// The allocator a traced build runs on: the tracer wraps `System`, so counts
/// are allocator-independent while live/peak bytes are not comparable with a
/// mimalloc release.
pub const ALLOCATOR: &str = "system";

/// One symbol row of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    /// Bytes currently allocated through this module.
    pub live_bytes: usize,
    /// Live allocations charged to this module.
    pub live_count: usize,
    /// High-water mark of `live_bytes`.
    pub peak_live_bytes: usize,
    /// Bytes ever allocated here, freed or not.
    pub total_bytes: usize,
    /// Allocations ever made here.
    pub total_count: usize,
}

/// Whole-window counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Totals {
    pub live_bytes: usize,
    pub peak_live_bytes: usize,
    pub allocs: usize,
    pub deallocs: usize,
    /// Frames the capture walked over the window. The mean is a cost metric of
    /// the walk, and it divides by `attributed`, not by `allocs`: allocations
    /// under `min_bytes` and the tracer's own never enter the walk.
    pub frames_walked: usize,
    /// Allocations that entered the walk.
    pub attributed: usize,
}

/// How well the instruction-pointer cache performed. A `resolves` count that
/// keeps climbing means eviction churn; a flat one means it works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheCounters {
    pub hits: usize,
    pub resolves: usize,
    pub evictions: usize,
}

/// Everything one point-in-time report contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub pid: u32,
    pub duration: Duration,
    pub roots: &'static [&'static str],
    pub min_bytes: usize,
    pub rows: Vec<Row>,
    pub folded: Vec<(String, usize)>,
    pub totals: Totals,
    pub cache: CacheCounters,
    /// Instruction-pointer resolutions refused by a full symbol slab. Charged
    /// to `<untraced>`; a count, because one refusal is noise and thousands are
    /// a collapsed attribution.
    pub overflowed: u64,
    /// Unit identity echoed from [`crate::start_with`].
    pub metadata: &'static [(&'static str, &'static str)],
    /// Which weight the folded stacks carry: `live` or `allocs`.
    pub fold: &'static str,
}

/// Where [`write`] put the three files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifacts {
    pub json: PathBuf,
    pub text: PathBuf,
    pub folded: PathBuf,
    /// Exactly what the files contain, so a caller printing a summary cannot
    /// drift from the artifact by taking a second snapshot.
    pub snapshot: Snapshot,
}

/// Read the current counters. `None` before [`crate::start`].
#[must_use]
#[allow(
    clippy::significant_drop_tightening,
    reason = "the registry guard must span both the row and the folded passes; it is released before the snapshot is assembled"
)]
pub fn snapshot() -> Option<Snapshot> {
    // The report's own `String`s, sorts and joins are not the subject. Holding
    // the tracer guard makes them untagged, so the rows and the allocator's
    // live total stay reconciled.
    let _reporter = attrib::enter();
    let state = attrib::state()?;
    // One lock scope, so the registry guard is released before the snapshot is
    // assembled (a returning-value `Snapshot` must not hold it).
    let (rows, folded) = {
        let registry = state
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rows = Vec::new();
        for (index, stats) in state.stats.iter().enumerate() {
            let (live, count, peak, total, total_count) = stats.row();
            if index == 0 {
                rows.push(Row {
                    name: UNTRACED_ROW.to_owned(),
                    live_bytes: live,
                    live_count: count,
                    peak_live_bytes: peak,
                    total_bytes: total,
                    total_count,
                });
                continue;
            }
            if count == 0 && total_count == 0 {
                continue;
            }
            let Some(id) = u32::try_from(index).ok() else {
                continue;
            };
            let Some(name) = registry.name(id) else {
                continue;
            };
            rows.push(Row {
                name: name.to_owned(),
                live_bytes: live,
                live_count: count,
                peak_live_bytes: peak,
                total_bytes: total,
                total_count,
            });
        }
        // Live bytes first: the question the artifact answers is "who is holding
        // memory now", not "who allocated most historically".
        rows.sort_by(|a, b| {
            b.live_bytes
                .cmp(&a.live_bytes)
                .then_with(|| b.peak_live_bytes.cmp(&a.peak_live_bytes))
                .then_with(|| a.name.cmp(&b.name))
        });

        // `LEAS_MEM_TRACE_FOLD=allocs` ranks the folded stacks by allocation
        // count instead of live bytes: per-frame temporaries hold nothing at the
        // snapshot, so only their count can place them.
        let weight_allocs = fold_allocs();
        let mut folded: Vec<(String, usize)> = registry
            .folded()
            .iter()
            .filter_map(|(&id, path)| {
                if path.is_empty() {
                    return None;
                }
                let (live, _, peak, _, allocs) = state.stats.get(usize::try_from(id).ok()?)?.row();
                let weight = folded_weight(live, peak, allocs, weight_allocs);
                if weight == 0 {
                    return None;
                }
                // Recorded innermost-first; a folded stack is root-first.
                let mut names: Vec<&str> = path.iter().map(String::as_str).collect();
                names.reverse();
                Some((names.join(";"), weight))
            })
            .collect();
        folded.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        (rows, folded)
    };

    Some(Snapshot {
        pid: std::process::id(),
        duration: state.started.elapsed(),
        roots: state.roots,
        min_bytes: state.min_bytes,
        rows,
        folded,
        totals: Totals {
            live_bytes: LIVE_BYTES.load(Relaxed),
            peak_live_bytes: PEAK_LIVE_BYTES.load(Relaxed),
            allocs: ALLOCS.load(Relaxed),
            deallocs: DEALLOCS.load(Relaxed),
            frames_walked: FRAMES_WALKED.load(Relaxed),
            attributed: ATTRIBUTED.load(Relaxed),
        },
        cache: CacheCounters {
            hits: CACHE_HITS.load(Relaxed),
            resolves: CACHE_RESOLVES.load(Relaxed),
            evictions: CACHE_EVICTIONS.load(Relaxed),
        },
        overflowed: OVERFLOWED.load(Relaxed),
        metadata: state.metadata,
        fold: if fold_allocs() { "allocs" } else { "live" },
    })
}

/// Write the JSON, text and folded artifacts for `label` into `dir`.
///
/// The file stem carries the pid so concurrent runs do not overwrite each
/// other's evidence.
pub fn write(dir: &Path, label: &str) -> io::Result<Artifacts> {
    // Rendering and fs work allocate too; none of it belongs in the numbers.
    let _reporter = attrib::enter();
    let snapshot =
        snapshot().ok_or_else(|| io::Error::other("memtrace: tracing is not started"))?;
    fs::create_dir_all(dir)?;
    let stem = format!("{label}-{}", snapshot.pid);
    let artifacts = Artifacts {
        json: dir.join(format!("{stem}.json")),
        text: dir.join(format!("{stem}.txt")),
        folded: dir.join(format!("{stem}.folded")),
        snapshot: snapshot.clone(),
    };
    fs::write(&artifacts.json, render_json(&snapshot))?;
    fs::write(&artifacts.text, render_text(&snapshot))?;
    fs::write(&artifacts.folded, render_folded(&snapshot))?;
    Ok(artifacts)
}

fn render_json(snapshot: &Snapshot) -> String {
    let rows: Vec<serde_json::Value> = snapshot
        .rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "name": row.name,
                "live_bytes": row.live_bytes,
                "live_count": row.live_count,
                "peak_live_bytes": row.peak_live_bytes,
                "total_bytes": row.total_bytes,
                "total_count": row.total_count,
            })
        })
        .collect();
    let folded: Vec<serde_json::Value> = snapshot
        .folded
        .iter()
        .map(|(stack, live)| serde_json::json!({ "stack": stack, "live_bytes": live }))
        .collect();
    let document = serde_json::json!({
        // 2: `totals.frames_walked` and the identity fields T2 adds; readers
        // that do not know the version must not guess at a mismatch.
        "schema": 2,
        "scope": format!("process {}", snapshot.pid),
        "note": "current process only; child processes are not traced",
        "rev": REV,
        "allocator": ALLOCATOR,
        "fold": snapshot.fold,
        "metadata": snapshot
            .metadata
            .iter()
            .map(|(key, value)| serde_json::json!({ "key": key, "value": value }))
            .collect::<Vec<_>>(),
        "duration_ms": snapshot.duration.as_millis(),
        "roots": snapshot.roots,
        "min_bytes": snapshot.min_bytes,
        "totals": {
            "live_bytes": snapshot.totals.live_bytes,
            "peak_live_bytes": snapshot.totals.peak_live_bytes,
            "allocs": snapshot.totals.allocs,
            "deallocs": snapshot.totals.deallocs,
            "frames_walked": snapshot.totals.frames_walked,
            "attributed": snapshot.totals.attributed,
        },
        "cache": {
            "hits": snapshot.cache.hits,
            "resolves": snapshot.cache.resolves,
            "evictions": snapshot.cache.evictions,
        },
        "symbols_overflowed": snapshot.overflowed,
        "rows": rows,
        "folded": folded,
    });
    let mut out = serde_json::to_string_pretty(&document).unwrap_or_default();
    out.push('\n');
    out
}

fn render_text(snapshot: &Snapshot) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# leas mem-trace");
    let _ = writeln!(
        out,
        "scope: process {} (child processes are not traced)",
        snapshot.pid
    );
    let _ = writeln!(out, "duration: {:.3}s", snapshot.duration.as_secs_f64());
    let _ = writeln!(out, "rev: {REV}");
    let _ = writeln!(
        out,
        "allocator: {ALLOCATOR} (counts are allocator-independent)"
    );
    let _ = writeln!(out, "fold: {}", snapshot.fold);
    for (key, value) in snapshot.metadata {
        let _ = writeln!(out, "{key}: {value}");
    }
    let _ = writeln!(out, "roots: {}", snapshot.roots.join(", "));
    let _ = writeln!(out, "min_bytes: {}", snapshot.min_bytes);
    let _ = writeln!(
        out,
        "cache: hits {} resolves {} evictions {}",
        snapshot.cache.hits, snapshot.cache.resolves, snapshot.cache.evictions
    );
    // A diagnostic mean over the allocations that actually walked: the ones
    // under `min_bytes` and the tracer's own never enter `frame`. The precision
    // loss of a usize->f64 mean is irrelevant here.
    #[allow(clippy::cast_precision_loss)]
    let per_attributed = if snapshot.totals.attributed == 0 {
        0.0
    } else {
        snapshot.totals.frames_walked as f64 / snapshot.totals.attributed as f64
    };
    let _ = writeln!(
        out,
        "capture: frames walked {} over {} attributed allocation(s) ({per_attributed:.2} each)",
        snapshot.totals.frames_walked, snapshot.totals.attributed
    );
    let _ = writeln!(
        out,
        "totals: live {} B peak {} B allocs {} deallocs {}",
        snapshot.totals.live_bytes,
        snapshot.totals.peak_live_bytes,
        snapshot.totals.allocs,
        snapshot.totals.deallocs
    );
    if snapshot.overflowed > 0 {
        let _ = writeln!(
            out,
            "warning: the symbol slab filled up; {} instruction-pointer resolution(s) were charged to {UNTRACED_ROW}",
            snapshot.overflowed
        );
    }
    let _ = writeln!(
        out,
        "\n{:<46} {:>12} {:>9} {:>12} {:>12} {:>9}",
        "module", "live B", "live #", "peak B", "total B", "total #"
    );
    for row in &snapshot.rows {
        let _ = writeln!(
            out,
            "{:<46} {:>12} {:>9} {:>12} {:>12} {:>9}",
            row.name,
            row.live_bytes,
            row.live_count,
            row.peak_live_bytes,
            row.total_bytes,
            row.total_count
        );
    }

    // The live sort hides churn: a row that allocates and frees fast holds
    // nothing at the snapshot and would fall off the page. Rank by count too.
    let mut by_count: Vec<&Row> = snapshot.rows.iter().collect();
    by_count.sort_by(|a, b| {
        b.total_count
            .cmp(&a.total_count)
            .then_with(|| b.total_bytes.cmp(&a.total_bytes))
    });
    let _ = writeln!(out, "\nby allocations (top 10)");
    let _ = writeln!(out, "{:<46} {:>12} {:>12}", "module", "total #", "total B");
    for row in by_count.iter().take(10) {
        let _ = writeln!(
            out,
            "{:<46} {:>12} {:>12}",
            row.name, row.total_count, row.total_bytes
        );
    }

    // Crate rollup: the row names are module paths, so the first segment is the
    // crate. It answers "which crate is expensive" without reading 20 rows.
    let mut crates: Vec<(String, usize, usize, usize)> = Vec::new();
    for row in &snapshot.rows {
        if row.name == UNTRACED_ROW {
            continue;
        }
        let krate = row.name.split("::").next().unwrap_or(&row.name).to_owned();
        match crates.iter_mut().find(|(name, ..)| *name == krate) {
            Some(slot) => {
                slot.1 += row.live_bytes;
                slot.2 += row.total_bytes;
                slot.3 += row.total_count;
            }
            None => crates.push((krate, row.live_bytes, row.total_bytes, row.total_count)),
        }
    }
    crates.sort_by_key(|slot| std::cmp::Reverse(slot.3));
    let _ = writeln!(out, "\nby crate");
    let _ = writeln!(
        out,
        "{:<26} {:>12} {:>12} {:>12}",
        "crate", "live B", "total B", "total #"
    );
    for (name, live, total, count) in &crates {
        let _ = writeln!(out, "{name:<26} {live:>12} {total:>12} {count:>12}");
    }
    out
}

/// Whether `LEAS_MEM_TRACE_FOLD=allocs` asks for allocation-weighted stacks.
fn fold_allocs() -> bool {
    std::env::var("LEAS_MEM_TRACE_FOLD").is_ok_and(|mode| mode == "allocs")
}

/// The number a folded stack is ranked by: live bytes, peak when the workload
/// released everything, or the symbol's allocation count in `allocs` mode.
const fn folded_weight(live: usize, peak: usize, allocs: usize, allocs_mode: bool) -> usize {
    if allocs_mode {
        allocs
    } else if live > 0 {
        live
    } else {
        peak
    }
}

fn render_folded(snapshot: &Snapshot) -> String {
    let mut out = String::new();
    for (stack, live) in &snapshot.folded {
        let _ = writeln!(out, "{stack} {live}");
    }
    out
}

/// Write `tick-<n>` artifacts every `secs` seconds from a background thread.
///
/// A run that is killed never reaches its exit boundary, and this session lost
/// exactly that way: the interval copy is the evidence a SIGTERM leaves behind.
/// `max` caps the directory (oldest first); `0` keeps every tick. A tick is
/// three file writes plus a directory scan, so a 1 s interval is a debugging
/// tool, not a profiler.
///
/// # Errors
/// `dir` must be usable by the first write.
pub fn spawn_interval_writer(dir: PathBuf, secs: u64, max: usize) -> io::Result<()> {
    if secs == 0 {
        return Ok(());
    }
    fs::create_dir_all(&dir)?;
    std::thread::Builder::new()
        .name("memtrace-interval".to_owned())
        .spawn(move || {
            let mut tick = 0_u64;
            loop {
                std::thread::sleep(Duration::from_secs(secs));
                tick += 1;
                let label = format!("tick-{tick:04}");
                let _ = write(&dir, &label);
                if max > 0 {
                    prune_ticks(&dir, max);
                }
            }
        })?;
    Ok(())
}

/// Keep only the newest `max` interval artifacts, by *stem*: each tick writes
/// three files, and counting files instead of stems deleted two thirds of every
/// tick it meant to keep.
fn prune_ticks(dir: &Path, max: usize) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut ticks: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("tick-") && name.ends_with(".json")
        })
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .collect();
    if ticks.len() <= max {
        return;
    }
    ticks.sort_by_key(|(modified, _)| *modified);
    let excess = ticks.len() - max;
    for (_, path) in ticks.into_iter().take(excess) {
        let _ = fs::remove_file(&path);
        let stem = path.with_extension("");
        let _ = fs::remove_file(stem.with_extension("txt"));
        let _ = fs::remove_file(stem.with_extension("folded"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folded_weight_prefers_live_then_peak_unless_allocs_mode() {
        assert_eq!(folded_weight(120, 500, 40, false), 120, "live wins");
        assert_eq!(folded_weight(0, 500, 40, false), 500, "peak stands in");
        assert_eq!(folded_weight(120, 500, 40, true), 40, "allocs mode");
        assert_eq!(
            folded_weight(120, 500, 0, true),
            0,
            "a symbol with no allocation has no row"
        );
    }

    /// Pruning counts *stems*, not files: each tick writes three files, and a
    /// file-counting prune deletes every tick it meant to keep. This pins the
    /// deterministic half; the writer's loop itself is exercised by the
    /// existence check below.
    #[test]
    fn prune_keeps_the_newest_ticks_by_stem() {
        let dir = std::env::temp_dir().join(format!("memtrace-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for tick in 1..=5 {
            for ext in ["json", "txt", "folded"] {
                let path = dir.join(format!("tick-{tick:04}-1.{ext}"));
                std::fs::write(&path, b"x").unwrap();
                // Stagger the mtimes so "newest" is deterministic.
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        super::prune_ticks(&dir, 2);
        let mut stems: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.strip_suffix(".json").map(str::to_owned)
            })
            .collect();
        stems.sort();
        assert_eq!(stems, vec!["tick-0004-1", "tick-0005-1"]);
        let files = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(files, 6, "each kept stem keeps all three files");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The writer must actually write: one bounded existence check, because a
    /// zero-second interval returns early and would prove nothing.
    #[test]
    fn interval_writer_writes_a_tick() {
        let dir = std::env::temp_dir().join(format!("memtrace-ticks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        if !crate::attrib::is_started() {
            assert!(crate::attrib::start(&["leas_memtrace"], 0));
        }
        super::spawn_interval_writer(dir.clone(), 1, 3).expect("interval writer");
        let mut tick = None;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(200));
            tick = std::fs::read_dir(&dir)
                .unwrap_or_else(|_| std::fs::read_dir(".").unwrap())
                .flatten()
                .map(|entry| entry.path())
                .find(|path| path.extension().is_some_and(|ext| ext == "json"));
            if tick.is_some() {
                break;
            }
        }
        assert!(
            tick.is_some(),
            "the interval writer produced no tick in 10 s"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn snapshot_with(rows: Vec<Row>, folded: Vec<(String, usize)>) -> Snapshot {
        Snapshot {
            pid: 4242,
            duration: Duration::from_millis(1500),
            roots: &["leas"],
            min_bytes: 0,
            rows,
            folded,
            totals: Totals {
                live_bytes: 3072,
                peak_live_bytes: 4096,
                allocs: 10,
                deallocs: 2,
                frames_walked: 40,
                attributed: 8,
            },
            cache: CacheCounters {
                hits: 900,
                resolves: 12,
                evictions: 3,
            },
            overflowed: 0,
            metadata: &[("features", "mem-trace")],
            fold: "live",
        }
    }

    fn row(name: &str, live: usize) -> Row {
        Row {
            name: name.to_owned(),
            live_bytes: live,
            live_count: 1,
            peak_live_bytes: live,
            total_bytes: live,
            total_count: 1,
        }
    }

    #[test]
    fn json_names_the_scope_and_carries_every_row() {
        let snapshot = snapshot_with(
            vec![row("leas::ops::ping", 2048), row(UNTRACED_ROW, 1024)],
            vec![("leas::ops::ping;leas::ui".to_owned(), 2048)],
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&render_json(&snapshot)).expect("valid json");
        assert_eq!(parsed["scope"], "process 4242");
        assert_eq!(parsed["cache"]["resolves"], 12);
        assert_eq!(parsed["rows"][0]["name"], "leas::ops::ping");
        assert_eq!(parsed["folded"][0]["live_bytes"], 2048);
    }

    #[test]
    fn text_header_states_the_process_scope() {
        let out = render_text(&snapshot_with(vec![row("leas::ops::ping", 8)], Vec::new()));
        assert!(out.contains("scope: process 4242"), "{out}");
        assert!(out.contains("leas::ops::ping"), "{out}");
    }

    /// The folded file is the input `inferno`/`flamegraph.pl` expects: one
    /// `a;b;c <bytes>` line per stack, root first.
    #[test]
    fn folded_lines_are_stack_then_bytes() {
        let snapshot = snapshot_with(
            Vec::new(),
            vec![("leas::ops::ping;leas::db::write".to_owned(), 1234)],
        );
        assert_eq!(
            render_folded(&snapshot),
            "leas::ops::ping;leas::db::write 1234\n"
        );
    }
}
