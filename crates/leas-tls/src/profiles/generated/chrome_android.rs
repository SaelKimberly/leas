//! Chromium family Android hellos (the `chrome_android` wire template)
//!
//! Emitter output (`gen_specs.py --emit`); do not edit by hand.
//! Regeneration is byte-deterministic (`--selftest` verifies the
//! committed files match a fresh render).

use super::GenEntry;
use crate::fingerprints::{Browser, Device, Os};

#[rustfmt::skip]
pub const GENERATED: &[GenEntry] = &[
    GenEntry {
        name: "opera_80_android_desktop",
        browser: Browser::Opera,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 80,
        ja4: "t13d131000_f57a46bbacb6_e7c285222651",
        spec_fn: opera_80_android_desktop,
    },
    GenEntry {
        name: "chrome_131_android_tablet",
        browser: Browser::Chrome,
        os: Some(Os::Android),
        device: Device::Tablet,
        major: 131,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: chrome_131_android_tablet,
    },
    GenEntry {
        name: "edge_134_android_desktop",
        browser: Browser::Edge,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 134,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: edge_134_android_desktop,
    },
    GenEntry {
        name: "opera_88_android_desktop",
        browser: Browser::Opera,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 88,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: opera_88_android_desktop,
    },
    GenEntry {
        name: "samsung_28_android_desktop",
        browser: Browser::SamsungInternet,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 28,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: samsung_28_android_desktop,
    },
    GenEntry {
        name: "chrome_134_android_desktop",
        browser: Browser::Chrome,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 134,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: chrome_134_android_desktop,
    },
    GenEntry {
        name: "edge_144_android_tablet",
        browser: Browser::Edge,
        os: Some(Os::Android),
        device: Device::Tablet,
        major: 144,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: edge_144_android_tablet,
    },
    GenEntry {
        name: "opera_96_android_desktop",
        browser: Browser::Opera,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 96,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: opera_96_android_desktop,
    },
    GenEntry {
        name: "edge_146_android_desktop",
        browser: Browser::Edge,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 146,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: edge_146_android_desktop,
    },
    GenEntry {
        name: "chrome_147_android_tablet",
        browser: Browser::Chrome,
        os: Some(Os::Android),
        device: Device::Tablet,
        major: 147,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: chrome_147_android_tablet,
    },
    GenEntry {
        name: "chrome_148_android_desktop",
        browser: Browser::Chrome,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 148,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: chrome_148_android_desktop,
    },
    GenEntry {
        name: "samsung_29_android_desktop",
        browser: Browser::SamsungInternet,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 29,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: samsung_29_android_desktop,
    },
    GenEntry {
        name: "samsung_17_android_desktop",
        browser: Browser::SamsungInternet,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 17,
        ja4: "t13d170900_5b57614c22b0_97f8aa674fd9",
        spec_fn: samsung_17_android_desktop,
    },
    GenEntry {
        name: "chrome_141_android_desktop_3",
        browser: Browser::Chrome,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 141,
        ja4: "t13d171300_5b57614c22b0_43ade6aba3df",
        spec_fn: chrome_141_android_desktop_3,
    },
    GenEntry {
        name: "edge_121_android_desktop",
        browser: Browser::Edge,
        os: Some(Os::Android),
        device: Device::Desktop,
        major: 121,
        ja4: "t13d3012h2_1d37bd780c83_b26ce05bbdd6",
        spec_fn: edge_121_android_desktop,
    },
    GenEntry {
        name: "chrome_83_android_tablet",
        browser: Browser::Chrome,
        os: Some(Os::Android),
        device: Device::Tablet,
        major: 83,
        ja4: "t13d3013h2_1d37bd780c83_1b3407e2c936",
        spec_fn: chrome_83_android_tablet,
    },
];

// ja4=t13d131000_f57a46bbacb6_e7c285222651 obs=8722
#[rustfmt::skip]
spec! {
    opera_80_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, status, sct,
          keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17173
#[rustfmt::skip]
spec! {
    chrome_131_android_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17173
#[rustfmt::skip]
spec! {
    edge_134_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17173
#[rustfmt::skip]
spec! {
    opera_88_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17177
#[rustfmt::skip]
spec! {
    samsung_28_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17173
#[rustfmt::skip]
spec! {
    chrome_134_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35851
#[rustfmt::skip]
spec! {
    edge_144_android_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35850
#[rustfmt::skip]
spec! {
    opera_96_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35852
#[rustfmt::skip]
spec! {
    edge_146_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35850
#[rustfmt::skip]
spec! {
    chrome_147_android_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35861
#[rustfmt::skip]
spec! {
    chrome_148_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35866
#[rustfmt::skip]
spec! {
    samsung_29_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status, sct, keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], compress[brotli],
          raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d170900_5b57614c22b0_97f8aa674fd9 obs=8606
#[rustfmt::skip]
spec! {
    samsung_17_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035, 0xc009, 0xc00a,
    session: random32,
    exts: sni, reneg, groups[x25519, p256, p384], ecpf, status, sct, keyshare[x25519],
          versions[0x0304, 0x0303],
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
}

// ja4=t13d171300_5b57614c22b0_43ade6aba3df obs=17931
#[rustfmt::skip]
spec! {
    chrome_141_android_desktop_3,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035, 0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], ecpf, ticket, status, sct,
          keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201], padding,
}

// ja4=t13d3012h2_1d37bd780c83_b26ce05bbdd6 obs=28316
#[rustfmt::skip]
spec! {
    edge_121_android_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035, 0x0033, 0x0039, 0x003c, 0x003d, 0x0067, 0x006b, 0x009e,
             0x009f, 0xc009, 0xc00a, 0xc023, 0xc024, 0xc027, 0xc028, 0xccaa,
    session: random32,
    exts: sni, raw[0x0017, ""], groups[x25519, p256, p384], ecpf, alpn["h2", "http/1.1"],
          keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602],
          padding, raw[0x0016, ""], raw[0x0031, ""],
}

// ja4=t13d3013h2_1d37bd780c83_1b3407e2c936 obs=4456
#[rustfmt::skip]
spec! {
    chrome_83_android_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035, 0x0033, 0x0039, 0x003c, 0x003d, 0x0067, 0x006b, 0x009e,
             0x009f, 0xc009, 0xc00a, 0xc023, 0xc024, 0xc027, 0xc028, 0xccaa,
    session: random32,
    exts: sni, raw[0x0017, ""], groups[x25519, p256, p384], ecpf, alpn["h2", "http/1.1"],
          keyshare[x25519], psk, versions[0x0304, 0x0303],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0203, 0x0301, 0x0201, 0x0302, 0x0202, 0x0402, 0x0502, 0x0602],
          padding, raw[0x0016, ""], raw[0x0031, ""], raw[0x3374, ""],
}
