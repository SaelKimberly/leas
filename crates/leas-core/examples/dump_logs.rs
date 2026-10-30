//! Dump the persisted log store (`logs.lmdb`) as readable lines.
//!
//! The TUI's Logs tab exports the SAME read — `HeedLogStorage::read_all_older_than`
//! — to the clipboard (`crates/leas/src/ui/logs.rs::copy_all_filtered`). This
//! example is that read to stdout or a file, for analysis outside the TUI; it
//! never re-parses LMDB itself.
//!
//! Usage:
//!
//! ```text
//! cargo run -p leas-core --example dump_logs -- [<store-dir> [<out-file>]]
//! ```
//!
//! `store-dir` defaults to the app's store (`%APPDATA%/leas/logs.lmdb` on
//! Windows, `$XDG_CONFIG_HOME/leas/logs.lmdb` or `~/.config/leas/logs.lmdb`
//! elsewhere) and `out-file` defaults to stdout.
//!
//! Line format: `YYYY-MM-DD HH:MM:SS.mmm [level] [target] message`, one entry
//! per line — newlines inside a message are escaped as `\n` so an entry never
//! spans lines.

use std::error::Error;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use leas_core::log_heed::HeedLogStorage;

/// Ceiling on one dump, matching the TUI export's intent (it is 200k there).
const MAX_LINES: usize = 1_000_000;

/// Entries read per backward page.
const PAGE: usize = 5_000;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let store = args.next().unwrap_or_else(default_store);
    if !store.join("data.mdb").is_file() {
        return Err(format!("no LMDB store at {} (data.mdb missing)", store.display()).into());
    }
    let out = args.next();

    let storage = HeedLogStorage::new(&store)?;
    let messages = storage.read_all_older_than(u64::MAX, PAGE, MAX_LINES)?;

    let mut text = String::new();
    for msg in &messages {
        let message: String = msg.message.chars().filter(|c| !c.is_control()).collect();
        writeln!(
            text,
            "{} [{}] [{}] {}",
            fmt_ts(msg.timestamp_nanos),
            msg.level,
            msg.target,
            message
        )?;
    }

    if let Some(path) = out {
        std::fs::write(path, &text)?;
    } else {
        print!("{text}");
    }
    eprintln!("{} entries from {}", messages.len(), store.display());
    Ok(())
}

/// The app's log store directory, resolved without a `dirs` dependency.
fn default_store() -> PathBuf {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config")))
        .unwrap_or_default();
    config.join("leas").join("logs.lmdb")
}

/// `YYYY-MM-DD HH:MM:SS.mmm` in UTC from nanoseconds since the epoch.
fn fmt_ts(nanos: u64) -> String {
    let secs = nanos / 1_000_000_000;
    let millis = (nanos % 1_000_000_000) / 1_000_000;
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}.{millis:03}",
        rem / 3_600,
        rem / 60 % 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to `(year, month, day)`; Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}
