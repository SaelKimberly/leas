//! The pinned oracle cores: versions, release asset names, and SHA-256.
//!
//! This module is std-only on purpose: `build.rs` includes it with
//! `#[path = "src/pins.rs"]` and the lib re-exports the same body, so the
//! version constants, the asset naming, the checksums and the download URL
//! cannot drift apart.
//!
//! Pinned to the newest release tag of each project (sing-box can be a
//! pre-release: the suite tracks the current line, not the stable one).
//! Bumping is a two-step edit: change the constants here, then run
//! `just oracles-pins <xray> <singbox>` and paste the printed eight-row table.
//! A bump may red some e2e rows; that is accepted and triaged separately
//! (spec D17).

/// A real server core the e2e suite can launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Core {
    Xray,
    SingBox,
}

/// Pinned Xray-core release.
pub const XRAY_VERSION: &str = "26.11.9";
/// Pinned sing-box release.
///
/// A pre-release: the oracles track the newest upstream tag, and 1.15 is the
/// current line (spec D17).
pub const SINGBOX_VERSION: &str = "1.15.0-alpha.13";

const XRAY_REPO: &str = "https://github.com/XTLS/Xray-core/releases/download";
const SINGBOX_REPO: &str = "https://github.com/SagerNet/sing-box/releases/download";

/// The upstream release asset filename for `(core, os, arch)`.
///
/// `None` for a platform this workspace does not claim (spec D7:
/// linux/windows × `x86_64`/`aarch64`). `Xray` publishes `Xray-<os>-<suffix>.zip`
/// with `64`/`arm64-v8a`; sing-box publishes
/// `sing-box-<version>-<os>-<arch>.tar.gz` (linux) or `.zip` (windows).
#[must_use]
pub fn asset_name(core: Core, os: &str, arch: &str) -> Option<String> {
    let name = match (core, os, arch) {
        (Core::Xray, "linux", "x86_64") => "Xray-linux-64.zip".to_string(),
        (Core::Xray, "windows", "x86_64") => "Xray-windows-64.zip".to_string(),
        (Core::Xray, "linux", "aarch64") => "Xray-linux-arm64-v8a.zip".to_string(),
        (Core::Xray, "windows", "aarch64") => "Xray-windows-arm64-v8a.zip".to_string(),
        (Core::SingBox, "linux", "x86_64") => {
            format!("sing-box-{SINGBOX_VERSION}-linux-amd64.tar.gz")
        }
        (Core::SingBox, "windows", "x86_64") => {
            format!("sing-box-{SINGBOX_VERSION}-windows-amd64.zip")
        }
        (Core::SingBox, "linux", "aarch64") => {
            format!("sing-box-{SINGBOX_VERSION}-linux-arm64.tar.gz")
        }
        (Core::SingBox, "windows", "aarch64") => {
            format!("sing-box-{SINGBOX_VERSION}-windows-arm64.zip")
        }
        _ => return None,
    };
    Some(name)
}

/// The pinned release version for `core`.
#[must_use]
pub const fn version(core: Core) -> &'static str {
    match core {
        Core::Xray => XRAY_VERSION,
        Core::SingBox => SINGBOX_VERSION,
    }
}

/// The expected SHA-256 (lowercase hex) of the asset for `(core, os, arch)`.
///
/// Read from the GitHub release API (`assets[].digest`) on 2026-11-09.
#[must_use]
pub fn sha256(core: Core, os: &str, arch: &str) -> Option<&'static str> {
    match (core, os, arch) {
        (Core::Xray, "linux", "x86_64") => {
            Some("b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82")
        }
        (Core::Xray, "windows", "x86_64") => {
            Some("1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d")
        }
        (Core::Xray, "linux", "aarch64") => {
            Some("64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be")
        }
        (Core::Xray, "windows", "aarch64") => {
            Some("9fdd48ff890e54ffdc37f92df9037c940fe4d4f914755b70cc644b97e9678a83")
        }
        (Core::SingBox, "linux", "x86_64") => {
            Some("bfc39f643a5ecc1b702c5723ff662e61dde813f12b3af0d0cfce4f629ff74047")
        }
        (Core::SingBox, "windows", "x86_64") => {
            Some("7cff6a39687a12d51b289bd57a203723629eb8fd42f6668601b4484456436bc9")
        }
        (Core::SingBox, "linux", "aarch64") => {
            Some("6347b1405ec7e1b02fbed77f3b9ae12ba494cc3eb9f47c4adb6877c807a64bf5")
        }
        (Core::SingBox, "windows", "aarch64") => {
            Some("38aa9f309f1be70619e5160aa74d38a0803a5c7340be143381db8143c964f657")
        }
        _ => None,
    }
}

/// The full download URL for `(core, os, arch)`.
#[must_use]
pub fn url(core: Core, os: &str, arch: &str) -> Option<String> {
    let repo = match core {
        Core::Xray => XRAY_REPO,
        Core::SingBox => SINGBOX_REPO,
    };
    let name = asset_name(core, os, arch)?;
    Some(format!("{repo}/v{}/{name}", version(core)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platforms_have_no_pin() {
        assert!(asset_name(Core::Xray, "macos", "x86_64").is_none());
        assert!(asset_name(Core::SingBox, "linux", "riscv64").is_none());
        assert!(sha256(Core::Xray, "freebsd", "x86_64").is_none());
        assert!(url(Core::SingBox, "macos", "aarch64").is_none());
    }

    #[test]
    fn supported_platforms_have_a_name_hash_and_url() {
        for (os, arch) in [("linux", "x86_64"), ("windows", "aarch64")] {
            for core in [Core::Xray, Core::SingBox] {
                assert!(asset_name(core, os, arch).is_some());
                assert!(sha256(core, os, arch).is_some_and(|h| h.len() == 64));
                let url = url(core, os, arch).expect("supported");
                assert!(url.contains(&format!("/v{}/", version(core))));
                assert!(url.ends_with(&asset_name(core, os, arch).unwrap()));
            }
        }
    }
}
