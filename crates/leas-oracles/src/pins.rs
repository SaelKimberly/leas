//! The pinned oracle cores: versions, release asset names, and SHA-256.
//!
//! This module is std-only on purpose: `build.rs` includes it with
//! `#[path = "src/pins.rs"]` and the lib re-exports the same body, so the
//! version constants, the asset naming, the checksums and the download URL
//! cannot drift apart.
//!
//! Pinned to the latest stable release of each project. Bumping is a two-step
//! edit: change the constants here, then run `just oracles-pins <xray>
//! <singbox>` and paste the printed eight-row table. A bump may red some e2e
//! rows; that is accepted and triaged separately (spec D17).

/// A real server core the e2e suite can launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Core {
    Xray,
    SingBox,
}

/// Pinned Xray-core release.
pub const XRAY_VERSION: &str = "26.3.27";
/// Pinned sing-box release.
pub const SINGBOX_VERSION: &str = "1.13.16";

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
/// Read from the GitHub release API (`assets[].digest`) on 2026-11-07.
#[must_use]
pub fn sha256(core: Core, os: &str, arch: &str) -> Option<&'static str> {
    match (core, os, arch) {
        (Core::Xray, "linux", "x86_64") => {
            Some("23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae")
        }
        (Core::Xray, "windows", "x86_64") => {
            Some("d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad")
        }
        (Core::Xray, "linux", "aarch64") => {
            Some("4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c")
        }
        (Core::Xray, "windows", "aarch64") => {
            Some("35d4ed6ec21224fb22b07c2c3f672e2350cd536f2c74d309150175a76365ea88")
        }
        (Core::SingBox, "linux", "x86_64") => {
            Some("e37c312859dfa84cba148f41072ff6369f08361ae91d622dc1fd3aab49611a8d")
        }
        (Core::SingBox, "windows", "x86_64") => {
            Some("6cbf90ec4ee87122ffce09b73928fb31e763bc1c75a119f79c61d24734c78807")
        }
        (Core::SingBox, "linux", "aarch64") => {
            Some("d587fb00bdc3c044227f35d15d154f271bc75108475091eda2542e4b82bb2949")
        }
        (Core::SingBox, "windows", "aarch64") => {
            Some("8412e9751a776a1cd5138fde8a6b60784af91b0fe596cba1b6efcd05144ef511")
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
