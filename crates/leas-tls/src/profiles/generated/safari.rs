//! Safari hellos on macOS and desktop (the `safari` wire template)
//!
//! Emitter output (`gen_specs.py --emit`); do not edit by hand.
//! Regeneration is byte-deterministic (`--selftest` verifies the
//! committed files match a fresh render).

use super::GenEntry;
use crate::fingerprints::{Browser, Device, Os};

#[rustfmt::skip]
pub const GENERATED: &[GenEntry] = &[
    GenEntry {
        name: "safari_16_macos_desktop",
        browser: Browser::Safari,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 16,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: safari_16_macos_desktop,
    },
    GenEntry {
        name: "safari_26_macos_desktop",
        browser: Browser::Safari,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 26,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: safari_26_macos_desktop,
    },
    GenEntry {
        name: "safari_12_macos_desktop",
        browser: Browser::Safari,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 12,
        ja4: "t13d170900_5b57614c22b0_97f8aa674fd9",
        spec_fn: safari_12_macos_desktop,
    },
    GenEntry {
        name: "safari_12_windows_desktop",
        browser: Browser::Safari,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 12,
        ja4: "t13d1716h2_5b57614c22b0_eeeea6562960",
        spec_fn: safari_12_windows_desktop,
    },
    GenEntry {
        name: "safari_12_windows_desktop_2",
        browser: Browser::Safari,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 12,
        ja4: "t13d201100_314f1408a5a6_e5728521abd4",
        spec_fn: safari_12_windows_desktop_2,
    },
    GenEntry {
        name: "safari_5_windows_desktop",
        browser: Browser::Safari,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 5,
        ja4: "t13d301000_1d37bd780c83_a29327ec888c",
        spec_fn: safari_5_windows_desktop,
    },
];

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17175
#[rustfmt::skip]
spec! {
    safari_16_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc014, 0xc013,
             0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521], ecpf,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          ticket, appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35850
#[rustfmt::skip]
spec! {
    safari_26_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc014, 0xc013,
             0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521], ecpf,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          ticket, raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d170900_5b57614c22b0_97f8aa674fd9 obs=8606
#[rustfmt::skip]
spec! {
    safari_12_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, reneg, groups[x25519, p256, p384, p521], ecpf, status, sct, keyshare[x25519],
          versions[0x0304, 0x0303],
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
}

// ja4=t13d1716h2_5b57614c22b0_eeeea6562960 obs=1218
#[rustfmt::skip]
spec! {
    safari_12_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521], ecpf,
          alpn["h2", "http/1.1"], status, keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201],
          compress[brotli], rslimit[16385],
          raw[0x0022, "001604030503060308040805080604010501060102030201"], ticket, ech,
}

// ja4=t13d201100_314f1408a5a6_e5728521abd4 obs=82
#[rustfmt::skip]
spec! {
    safari_12_windows_desktop_2,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc023, 0xc027,
             0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521], ecpf, status, sct,
          keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
          raw[0x0032, "0018080404030807080508060401050106010503060302010203"],
}

// ja4=t13d301000_1d37bd780c83_a29327ec888c obs=1185
#[rustfmt::skip]
spec! {
    safari_5_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc024, 0xc023,
             0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035,
             0x002f, 0x0033, 0x0039, 0x0067, 0x006b, 0x009e, 0x009f, 0xccaa,
    session: empty,
    exts: sni, raw[0x0017, ""], groups[x25519, p256, p384, p521], ecpf, keyshare[x25519],
          versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602],
          padding, raw[0x0016, ""],
}
