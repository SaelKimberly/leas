//! Binary-core resolution + version sanity for the e2e pipeline.
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreKind {
    Xray,
    SingBox,
    Mihomo,
}

impl CoreKind {
    /// Host binary file name (`xray.exe` on Windows).
    #[must_use]
    pub fn bin_name(self) -> String {
        let base = match self {
            Self::Xray => "xray",
            Self::SingBox => "sing-box",
            Self::Mihomo => "mihomo",
        };
        format!("{base}{}", std::env::consts::EXE_SUFFIX)
    }
}

/// A resolved, version-checked core binary.
#[derive(Debug, Clone)]
pub struct CoreUnderTest {
    pub kind: CoreKind,
    pub bin: PathBuf,
    pub version: String,
}

impl CoreUnderTest {
    /// Resolve the binary from the runtime `LEAS_CORE_BIN_DIR` or, when that
    /// is unset, from the directory `build.rs` baked into the crate. Probe
    /// its version and sanity-check it against `expected_version` (substring
    /// match).
    pub fn resolve(kind: CoreKind, expected_version: &str) -> Result<Self, String> {
        let dir = match std::env::var("LEAS_CORE_BIN_DIR") {
            Ok(dir) => dir,
            Err(_) => match option_env!("LEAS_ORACLES_CORE_DIR") {
                Some(dir) => dir.to_owned(),
                None => {
                    return Err(format!(
                        "no core directory: set LEAS_CORE_BIN_DIR, or build with \
                         leas-oracles' build.rs enabled (it fetches the pinned cores into \
                         OUT_DIR/core-bin); the missing binary is {}",
                        kind.bin_name()
                    ));
                }
            },
        };
        let bin = PathBuf::from(dir).join(kind.bin_name());
        if !bin.is_file() {
            return Err(format!(
                "no '{}' binary at {}",
                kind.bin_name(),
                bin.display()
            ));
        }
        let actual = probe_version(&bin, kind)?;
        if !check_version(&actual, expected_version) {
            return Err(format!(
                "core version mismatch: want {expected_version:?}, got {actual:?}"
            ));
        }
        Ok(Self {
            kind,
            bin,
            version: actual,
        })
    }
}

/// Probe the version string: exact probe per kind, bounded to 15s.
/// xray: `-version`; sing-box: `version`; mihomo: `-v` (which prints
/// `Mihomo Meta v1.19.33 linux amd64 …`, so the pin's substring match works).
/// A hang is a bug → timeout error.
/// The bound is generous because Windows AV can take seconds to scan a ~45 MB
/// core on its first execution.
fn probe_version(bin: &std::path::Path, kind: CoreKind) -> Result<String, String> {
    let flag = match kind {
        CoreKind::Xray => "-version",
        CoreKind::SingBox => "version",
        CoreKind::Mihomo => "-v",
    };
    // `Command::output()` can hang; run it on a std thread and bound the wait.
    let (tx, rx) = std::sync::mpsc::channel();
    let cmd_bin = bin.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(Command::new(&cmd_bin).arg(flag).output());
    });
    let out = rx
        .recv_timeout(Duration::from_secs(15))
        .map_err(|_| format!("version probe timed out for {}", bin.display()))?
        .map_err(|e| format!("failed to run {}: {e}", bin.display()))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let text = text.trim();
    if text.is_empty() {
        return Err(format!("no version output from {}", bin.display()));
    }
    Ok(text.to_string())
}

/// Loose sanity: the reported version contains the expected one.
#[must_use]
pub fn check_version(actual: &str, want: &str) -> bool {
    actual.contains(want)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_substring_matches() {
        assert!(check_version("Xray 26.3.27 (Xray-core 26.3.27)", "26.3.27"));
        assert!(check_version("sing-box 1.13.16", "1.13.16"));
        assert!(!check_version("sing-box 1.12.0", "1.13.16"));
    }
}
