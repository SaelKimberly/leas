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
    ALLOCS, CACHE_EVICTIONS, CACHE_HITS, CACHE_RESOLVES, DEALLOCS, LIVE_BYTES, OVERFLOWED,
    PEAK_LIVE_BYTES,
};

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
    pub overflowed: bool,
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

        let mut folded: Vec<(String, usize)> = registry
            .folded()
            .iter()
            .filter_map(|(&id, path)| {
                if path.is_empty() {
                    return None;
                }
                let (live, _, peak, _, _) = state.stats.get(usize::try_from(id).ok()?)?.row();
                // A workload that released everything still has a story: its stack
                // held `peak` bytes. Live wins when it is non-zero.
                let bytes = if live > 0 { live } else { peak };
                if bytes == 0 {
                    return None;
                }
                // Recorded innermost-first; a folded stack is root-first.
                let mut names: Vec<&str> = path.iter().map(String::as_str).collect();
                names.reverse();
                Some((names.join(";"), bytes))
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
        },
        cache: CacheCounters {
            hits: CACHE_HITS.load(Relaxed),
            resolves: CACHE_RESOLVES.load(Relaxed),
            evictions: CACHE_EVICTIONS.load(Relaxed),
        },
        overflowed: OVERFLOWED.load(Relaxed),
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
        "scope": format!("process {}", snapshot.pid),
        "note": "current process only; child processes are not traced",
        "duration_ms": snapshot.duration.as_millis(),
        "roots": snapshot.roots,
        "min_bytes": snapshot.min_bytes,
        "totals": {
            "live_bytes": snapshot.totals.live_bytes,
            "peak_live_bytes": snapshot.totals.peak_live_bytes,
            "allocs": snapshot.totals.allocs,
            "deallocs": snapshot.totals.deallocs,
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
    let _ = writeln!(out, "roots: {}", snapshot.roots.join(", "));
    let _ = writeln!(out, "min_bytes: {}", snapshot.min_bytes);
    let _ = writeln!(
        out,
        "cache: hits {} resolves {} evictions {}",
        snapshot.cache.hits, snapshot.cache.resolves, snapshot.cache.evictions
    );
    let _ = writeln!(
        out,
        "totals: live {} B peak {} B allocs {} deallocs {}",
        snapshot.totals.live_bytes,
        snapshot.totals.peak_live_bytes,
        snapshot.totals.allocs,
        snapshot.totals.deallocs
    );
    if snapshot.overflowed {
        let _ = writeln!(
            out,
            "warning: the symbol slab filled up; overflow was charged to {UNTRACED_ROW}"
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
    out
}

fn render_folded(snapshot: &Snapshot) -> String {
    let mut out = String::new();
    for (stack, live) in &snapshot.folded {
        let _ = writeln!(out, "{stack} {live}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
            },
            cache: CacheCounters {
                hits: 900,
                resolves: 12,
                evictions: 3,
            },
            overflowed: false,
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
