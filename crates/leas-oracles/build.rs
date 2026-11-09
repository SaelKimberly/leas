//! Build-time fetch of the pinned oracle cores.
//!
//! Runs only when `leas-oracles` itself is built (it is excluded from
//! `default-members`). Order:
//!
//! 1. `LEAS_CORE_BIN_DIR` set → bake that directory, fetch nothing.
//! 2. `LEAS_ORACLES_SKIP_DOWNLOAD` set → no fetch, no env (compile-check only).
//! 3. Otherwise download the pinned asset for this host into
//!    `OUT_DIR/core-bin`, verify its SHA-256, extract it, and bake
//!    `LEAS_ORACLES_CORE_DIR`.
//!
//! A fetch/verify/extract failure is fatal: a test binary that silently has no
//! cores would fail later with a much less useful message.

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

#[path = "src/pins.rs"]
mod pins;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Oracle adapters' gRPC Stats client (moved from `leas-core`): `protox`
    // parses the .proto in-process, so `protoc` is not a build prerequisite.
    let fds = protox::compile(["proto/stats.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .build_server(false)
        .compile_fds(fds)?;

    println!("cargo:rerun-if-changed=src/pins.rs");
    println!("cargo:rerun-if-changed=proto/stats.proto");
    println!("cargo:rerun-if-env-changed=LEAS_CORE_BIN_DIR");
    println!("cargo:rerun-if-env-changed=LEAS_ORACLES_SKIP_DOWNLOAD");
    println!("cargo:rerun-if-env-changed=LEAS_ORACLES_PROXY");

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let bin_dir = out.join("core-bin");

    if let Ok(dir) = env::var("LEAS_CORE_BIN_DIR") {
        // The runtime override wins in `CoreUnderTest::resolve`; baking it as
        // well keeps a build-time-only value usable by the test process.
        println!("cargo:rustc-env=LEAS_ORACLES_CORE_DIR={dir}");
        return Ok(());
    }
    if env::var_os("LEAS_ORACLES_SKIP_DOWNLOAD").is_some() {
        return Ok(());
    }

    let os = env::consts::OS;
    let arch = env::consts::ARCH;
    for core in [pins::Core::Xray, pins::Core::SingBox, pins::Core::Mihomo] {
        let asset = pins::asset_name(core, os, arch).unwrap_or_else(|| {
            panic!(
                "leas-oracles: no pinned {core:?} asset for {os}/{arch}; \
                 supported hosts are linux/windows × x86_64/aarch64"
            )
        });
        let dest = bin_dir.join(bin_file(core));
        let want = pins::sha256(core, os, arch).expect("asset and checksum tables agree");
        // The marker ties the cached binary to its expected hash, so a pin
        // bump re-fetches even though `OUT_DIR` survived `cargo clean`-less
        // rebuilds.
        let marker = bin_dir.join(format!(".{}.sha256", bin_file(core)));
        if dest.is_file() && fs::read_to_string(&marker).ok().as_deref() == Some(want) {
            continue;
        }
        let url = pins::url(core, os, arch).expect("asset and URL tables agree");

        let bytes = fetch(&url);
        let got = hex(&Sha256::digest(&bytes));
        assert!(
            got == want,
            "leas-oracles: {url}\n  sha256 mismatch: expected {want}, got {got}\n  \
             update the table with `just oracles-pins <xray> <singbox> <mihomo>`"
        );

        fs::create_dir_all(&bin_dir).expect("create core-bin");
        // Dispatch on the asset's own shape, not on which core it belongs to:
        // the shape is the contract `pins::tests::archive_shape_matches_the_extractor`
        // holds (mihomo ships the bare binary as a gzip, sing-box a tarball,
        // everything else a zip), so a future asset that changes container
        // cannot be silently read by the wrong extractor.
        let ext = Path::new(&asset).extension().and_then(OsStr::to_str);
        let stem_is_tar = Path::new(&asset)
            .file_stem()
            .and_then(OsStr::to_str)
            .is_some_and(|stem| stem.split('.').next_back() == Some("tar"));
        match ext {
            Some("zip") => extract_zip(&bytes, core, &dest),
            Some("gz") if stem_is_tar => extract_tar_gz(&bytes, core, &dest),
            Some("gz") => extract_gz(&bytes, &dest),
            _ => panic!("leas-oracles: unrecognised asset shape: {asset}"),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))
                .expect("chmod core binary");
        }
        fs::write(&marker, want).expect("write pin marker");
    }

    println!(
        "cargo:rustc-env=LEAS_ORACLES_CORE_DIR={}",
        bin_dir.display()
    );
    Ok(())
}

/// The binary file name for `core` on this host (with `.exe` on Windows).
fn bin_file(core: pins::Core) -> String {
    let base = match core {
        pins::Core::Xray => "xray",
        pins::Core::SingBox => "sing-box",
        pins::Core::Mihomo => "mihomo",
    };
    format!("{base}{}", env::consts::EXE_SUFFIX)
}

/// Download `url` into memory. Release assets exceed ureq's 10 MiB default
/// body limit, so the limit is raised explicitly. A proxy in the environment
/// (`ALL_PROXY`/`HTTPS_PROXY`, including a `socks5://` URL) is honoured: on a
/// locked-down workstation that is the only way to reach GitHub, and the
/// proxy resolves the hostname.
fn fetch(url: &str) -> Vec<u8> {
    let mut config = ureq::Agent::config_builder();
    if let Some(proxy) = proxy_from_env() {
        config = config.proxy(Some(proxy));
    }
    let agent: ureq::Agent = config.build().into();
    let mut response = agent
        .get(url)
        .call()
        .unwrap_or_else(|e| panic!("leas-oracles: GET {url}: {e}"));
    response
        .body_mut()
        .with_config()
        .limit(128 * 1024 * 1024)
        .read_to_vec()
        .unwrap_or_else(|e| panic!("leas-oracles: read {url}: {e}"))
}

/// The proxy to use, if any. `LEAS_ORACLES_PROXY` wins (the explicit escape
/// hatch for locked-down workstations); the common proxy variables are tried
/// next, including `socks5://` URLs (the `socks-proxy` feature is enabled).
fn proxy_from_env() -> Option<ureq::Proxy> {
    for var in [
        "LEAS_ORACLES_PROXY",
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        // An empty value is how several shells spell "no proxy"; ureq rejects
        // it as a URL, and treating it as a broken proxy turns a clean
        // environment into a build failure.
        let Ok(url) = env::var(var).map(|v| v.trim().to_owned()) else {
            continue;
        };
        if url.is_empty() {
            continue;
        }
        match ureq::Proxy::new(&url) {
            Ok(proxy) => return Some(proxy),
            Err(e) => eprintln!("leas-oracles: {var}={url} is not a usable proxy: {e}"),
        }
    }
    None
}

/// Extract the entry whose basename is the host's binary name.
fn extract_zip(bytes: &[u8], core: pins::Core, dest: &Path) {
    let target = bin_file(core);
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).expect("leas-oracles: invalid zip archive");
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .expect("leas-oracles: unreadable zip entry");
        let name = entry
            .name()
            .expect("leas-oracles: unreadable zip entry name");
        if Path::new(name.as_ref()).file_name() == Some(OsStr::new(&target)) {
            let mut out = fs::File::create(dest).expect("create core binary");
            std::io::copy(&mut entry, &mut out).expect("write core binary");
            return;
        }
    }
    panic!("leas-oracles: {target} not found in the zip archive");
}

fn extract_tar_gz(bytes: &[u8], core: pins::Core, dest: &Path) {
    let target = bin_file(core);
    let decoder = flate2::read::GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    for entry in archive
        .entries()
        .expect("leas-oracles: invalid tar archive")
    {
        let mut entry = entry.expect("leas-oracles: unreadable tar entry");
        let is_target = entry
            .path()
            .is_ok_and(|p| p.file_name() == Some(OsStr::new(&target)));
        if is_target {
            let mut out = fs::File::create(dest).expect("create core binary");
            std::io::copy(&mut entry, &mut out).expect("write core binary");
            return;
        }
    }
    panic!("leas-oracles: {target} not found in the tarball");
}

/// A gzip asset that *is* the binary (mihomo's linux releases).
fn extract_gz(bytes: &[u8], dest: &Path) {
    let mut decoder = flate2::read::GzDecoder::new(Cursor::new(bytes));
    let mut out = fs::File::create(dest).expect("create core binary");
    std::io::copy(&mut decoder, &mut out).expect("write core binary");
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
