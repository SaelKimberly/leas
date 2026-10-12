//! Generated JA4-faithful profile roster, one module per browser
//! family.
//!
//! Each family module holds `spec!` declarations and a `GENERATED`
//! registry; `GENERATED` here is the merged slice consumed by the
//! resolver and the offline JA4 gate (later tasks).
//!
//! Emitter output (`gen_specs.py --emit`); do not edit by hand.

pub mod chrome;
pub mod chrome_android;
pub mod fallback;
pub mod firefox;
pub mod okhttp;
pub mod safari;
pub mod safari_ios;

use crate::fingerprints::{Browser, Device, Os};
use crate::spec::ClientHelloSpec;

/// One generated roster entry: identity, registered source JA4 and
/// the spec builder. `name` doubles as the spec function id.
#[derive(Debug, Clone, Copy)]
pub struct GenEntry {
    pub name: &'static str,
    pub browser: Browser,
    pub os: Option<Os>,
    pub device: Device,
    pub major: u16,
    pub ja4: &'static str,
    pub spec_fn: fn() -> ClientHelloSpec,
}

/// Every generated profile, family by family (module order).
#[rustfmt::skip]
pub const GENERATED: &[GenEntry] = &[
    // chrome: 19 entries
    chrome::GENERATED[0],
    chrome::GENERATED[1],
    chrome::GENERATED[2],
    chrome::GENERATED[3],
    chrome::GENERATED[4],
    chrome::GENERATED[5],
    chrome::GENERATED[6],
    chrome::GENERATED[7],
    chrome::GENERATED[8],
    chrome::GENERATED[9],
    chrome::GENERATED[10],
    chrome::GENERATED[11],
    chrome::GENERATED[12],
    chrome::GENERATED[13],
    chrome::GENERATED[14],
    chrome::GENERATED[15],
    chrome::GENERATED[16],
    chrome::GENERATED[17],
    chrome::GENERATED[18],
    // firefox: 9 entries
    firefox::GENERATED[0],
    firefox::GENERATED[1],
    firefox::GENERATED[2],
    firefox::GENERATED[3],
    firefox::GENERATED[4],
    firefox::GENERATED[5],
    firefox::GENERATED[6],
    firefox::GENERATED[7],
    firefox::GENERATED[8],
    // safari: 6 entries
    safari::GENERATED[0],
    safari::GENERATED[1],
    safari::GENERATED[2],
    safari::GENERATED[3],
    safari::GENERATED[4],
    safari::GENERATED[5],
    // chrome_android: 16 entries
    chrome_android::GENERATED[0],
    chrome_android::GENERATED[1],
    chrome_android::GENERATED[2],
    chrome_android::GENERATED[3],
    chrome_android::GENERATED[4],
    chrome_android::GENERATED[5],
    chrome_android::GENERATED[6],
    chrome_android::GENERATED[7],
    chrome_android::GENERATED[8],
    chrome_android::GENERATED[9],
    chrome_android::GENERATED[10],
    chrome_android::GENERATED[11],
    chrome_android::GENERATED[12],
    chrome_android::GENERATED[13],
    chrome_android::GENERATED[14],
    chrome_android::GENERATED[15],
    // safari_ios: 19 entries
    safari_ios::GENERATED[0],
    safari_ios::GENERATED[1],
    safari_ios::GENERATED[2],
    safari_ios::GENERATED[3],
    safari_ios::GENERATED[4],
    safari_ios::GENERATED[5],
    safari_ios::GENERATED[6],
    safari_ios::GENERATED[7],
    safari_ios::GENERATED[8],
    safari_ios::GENERATED[9],
    safari_ios::GENERATED[10],
    safari_ios::GENERATED[11],
    safari_ios::GENERATED[12],
    safari_ios::GENERATED[13],
    safari_ios::GENERATED[14],
    safari_ios::GENERATED[15],
    safari_ios::GENERATED[16],
    safari_ios::GENERATED[17],
    safari_ios::GENERATED[18],
];
