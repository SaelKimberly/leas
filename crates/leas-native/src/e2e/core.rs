//! Binary-core resolution + version sanity for the e2e pipeline.
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreKind {
    Xray,
    SingBox,
}

impl CoreKind {
    /// Binary file name inside `LEAS_CORE_BIN_DIR`.
    #[must_use]
    pub const fn bin_name(self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::SingBox => "sing-box",
        }
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
    /// Resolve from `LEAS_CORE_BIN_DIR/<bin_name>`, probe its version,
    /// and sanity-check it against `expected_version` (substring match).
    pub fn resolve(kind: CoreKind, expected_version: &str) -> Result<Self, String> {
        Self::resolve_from(kind, expected_version, "LEAS_CORE_BIN_DIR")
    }

    /// Resolve from an arbitrary env-named directory.
    ///
    /// Exists so a SECOND pinned peer can coexist with the suite's baseline
    /// without re-pinning it: the pq-enc differential targets a peer built from
    /// `thirdparty/Xray-core` HEAD, and pointing the baseline env at it would
    /// re-baseline every row in the suite (and restate its compatibility claim).
    pub fn resolve_from(
        kind: CoreKind,
        expected_version: &str,
        dir_env: &str,
    ) -> Result<Self, String> {
        let dir = std::env::var(dir_env).map_err(|_| format!("{dir_env} is not set"))?;
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

/// Probe the version string: exact probe per kind, bounded to 5s.
/// xray: `-version`; sing-box: `version`. A hang is a bug → timeout error.
fn probe_version(bin: &std::path::Path, kind: CoreKind) -> Result<String, String> {
    let flag = match kind {
        CoreKind::Xray => "-version",
        CoreKind::SingBox => "version",
    };
    // `Command::output()` can hang; run it on a std thread and bound the wait.
    let (tx, rx) = std::sync::mpsc::channel();
    let cmd_bin = bin.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(Command::new(&cmd_bin).arg(flag).output());
    });
    let out = rx
        .recv_timeout(Duration::from_secs(5))
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
