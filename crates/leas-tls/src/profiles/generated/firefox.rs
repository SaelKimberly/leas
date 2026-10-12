//! Firefox hellos (the `firefox` wire template)
//!
//! Emitter output (`gen_specs.py --emit`); do not edit by hand.
//! Regeneration is byte-deterministic (`--selftest` verifies the
//! committed files match a fresh render).

use super::GenEntry;
use crate::fingerprints::{Browser, Device, Os};

#[rustfmt::skip]
pub const GENERATED: &[GenEntry] = &[
    GenEntry {
        name: "firefox_150_macos_desktop",
        browser: Browser::Firefox,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 150,
        ja4: "t13d131000_f57a46bbacb6_e7c285222651",
        spec_fn: firefox_150_macos_desktop,
    },
    GenEntry {
        name: "firefox_139_windows_desktop",
        browser: Browser::Firefox,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 139,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: firefox_139_windows_desktop,
    },
    GenEntry {
        name: "firefox_148_macos_desktop",
        browser: Browser::Firefox,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 148,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: firefox_148_macos_desktop,
    },
    GenEntry {
        name: "firefox_148_windows_desktop",
        browser: Browser::Firefox,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 148,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: firefox_148_windows_desktop,
    },
    GenEntry {
        name: "firefox_149_android_desktop_2",
        browser: Browser::Firefox,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 149,
        ja4: "t13d1715h2_5b57614c22b0_5c2c66f702b0",
        spec_fn: firefox_149_android_desktop_2,
    },
    GenEntry {
        name: "firefox_150_android_desktop",
        browser: Browser::Firefox,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 150,
        ja4: "t13d1716h2_5b57614c22b0_eeeea6562960",
        spec_fn: firefox_150_android_desktop,
    },
    GenEntry {
        name: "firefox_149_macos_desktop",
        browser: Browser::Firefox,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 149,
        ja4: "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
        spec_fn: firefox_149_macos_desktop,
    },
    GenEntry {
        name: "firefox_144_android_desktop_5",
        browser: Browser::Firefox,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 144,
        ja4: "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
        spec_fn: firefox_144_android_desktop_5,
    },
    GenEntry {
        name: "firefox_125_windows_desktop",
        browser: Browser::Firefox,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 125,
        ja4: "t13d3012h2_1d37bd780c83_b26ce05bbdd6",
        spec_fn: firefox_125_windows_desktop,
    },
];

// ja4=t13d131000_f57a46bbacb6_e7c285222651 obs=8713
#[rustfmt::skip]
spec! {
    firefox_150_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521, 0x0100, 0x0101], ecpf,
          status, keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
          sct,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17179
#[rustfmt::skip]
spec! {
    firefox_139_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x002f, 0x0035, 0x009c, 0x009d,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521, 0x0100, 0x0101], ecpf,
          ticket, alpn["h2", "http/1.1"], status, keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], psk,
          compress[brotli], sct, appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35850
#[rustfmt::skip]
spec! {
    firefox_148_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x002f, 0x0035, 0x009c, 0x009d,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521, 0x0100, 0x0101], ecpf,
          ticket, alpn["h2", "http/1.1"], status, keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], psk,
          compress[brotli], sct, raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35852
#[rustfmt::skip]
spec! {
    firefox_148_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x002f, 0x0035, 0x009c, 0x009d,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521, 0x0100, 0x0101], ecpf,
          ticket, alpn["h2", "http/1.1"], status, keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], psk,
          compress[brotli], sct, raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1715h2_5b57614c22b0_5c2c66f702b0 obs=1951
#[rustfmt::skip]
spec! {
    firefox_149_android_desktop_2,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x002f, 0x0035, 0x009c, 0x009d, 0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521, 0x0100, 0x0101], ecpf,
          ticket, alpn["h2", "http/1.1"], status, keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201],
          psk, rslimit[16385], raw[0x0022, "001604030503060308040805080604010501060102030201"], ech,
}

// ja4=t13d1716h2_5b57614c22b0_eeeea6562960 obs=1218
#[rustfmt::skip]
spec! {
    firefox_150_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x002f, 0x0035, 0x009c, 0x009d, 0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521, 0x0100, 0x0101], ecpf,
          ticket, alpn["h2", "http/1.1"], status, keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201],
          psk, compress[brotli], rslimit[16385],
          raw[0x0022, "001604030503060308040805080604010501060102030201"], ech,
}

// ja4=t13d1717h2_5b57614c22b0_3cbfd9057e0d obs=6092
#[rustfmt::skip]
spec! {
    firefox_149_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x002f, 0x0035, 0x009c, 0x009d, 0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521, 0x0100, 0x0101], ecpf,
          ticket, alpn["h2", "http/1.1"], status, keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201],
          psk, compress[brotli], sct, rslimit[16385],
          raw[0x0022, "001604030503060308040805080604010501060102030201"], ech,
}

// ja4=t13d1717h2_5b57614c22b0_3cbfd9057e0d obs=5968
#[rustfmt::skip]
spec! {
    firefox_144_android_desktop_5,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x002f, 0x0035, 0x009c, 0x009d, 0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384, p521, 0x0100, 0x0101], ecpf,
          ticket, alpn["h2", "http/1.1"], status, keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201],
          psk, compress[brotli], sct, rslimit[16385],
          raw[0x0022, "001604030503060308040805080604010501060102030201"], ech,
}

// ja4=t13d3012h2_1d37bd780c83_b26ce05bbdd6 obs=28316
#[rustfmt::skip]
spec! {
    firefox_125_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x002f, 0x0035, 0x0033, 0x0039, 0x003c, 0x003d, 0x0067, 0x006b, 0x009c, 0x009d, 0x009e,
             0x009f, 0xc009, 0xc00a, 0xc023, 0xc024, 0xc027, 0xc028, 0xccaa,
    session: random32,
    exts: sni, raw[0x0017, ""], groups[x25519, p256, p384, p521, 0x0100, 0x0101], ecpf,
          alpn["h2", "http/1.1"], keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602],
          psk, padding, raw[0x0016, ""], raw[0x0031, ""],
}
