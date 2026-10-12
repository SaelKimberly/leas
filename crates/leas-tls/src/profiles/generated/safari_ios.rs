//! `WebKit` hellos on iOS (the `safari_ios` wire template; `WKWebView` reality)
//!
//! Emitter output (`gen_specs.py --emit`); do not edit by hand.
//! Regeneration is byte-deterministic (`--selftest` verifies the
//! committed files match a fresh render).

use super::GenEntry;
use crate::fingerprints::{Browser, Device, Os};

#[rustfmt::skip]
pub const GENERATED: &[GenEntry] = &[
    GenEntry {
        name: "safari_17_ios_tablet",
        browser: Browser::Safari,
        os: Some(Os::Ios),
        device: Device::Tablet,
        major: 17,
        ja4: "t13d131000_f57a46bbacb6_e7c285222651",
        spec_fn: safari_17_ios_tablet,
    },
    GenEntry {
        name: "safari_18_ios_phone",
        browser: Browser::Safari,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 18,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: safari_18_ios_phone,
    },
    GenEntry {
        name: "chrome_143_ios_phone",
        browser: Browser::Chrome,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 143,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: chrome_143_ios_phone,
    },
    GenEntry {
        name: "safari_6_ios_tablet",
        browser: Browser::Safari,
        os: Some(Os::Ios),
        device: Device::Tablet,
        major: 6,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: safari_6_ios_tablet,
    },
    GenEntry {
        name: "safari_26_ios_phone",
        browser: Browser::Safari,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 26,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: safari_26_ios_phone,
    },
    GenEntry {
        name: "chrome_133_ios_phone",
        browser: Browser::Chrome,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 133,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: chrome_133_ios_phone,
    },
    GenEntry {
        name: "safari_9_ios_phone",
        browser: Browser::Safari,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 9,
        ja4: "t13d170900_5b57614c22b0_97f8aa674fd9",
        spec_fn: safari_9_ios_phone,
    },
    GenEntry {
        name: "firefox_138_ios_phone",
        browser: Browser::Firefox,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 138,
        ja4: "t13d1712ht_ab0a1bf427ad_b26ce05bbdd6",
        spec_fn: firefox_138_ios_phone,
    },
    GenEntry {
        name: "chrome_146_ios_tablet",
        browser: Browser::Chrome,
        os: Some(Os::Ios),
        device: Device::Tablet,
        major: 146,
        ja4: "t13d1713h2_5b57614c22b0_7f0f34a4126d",
        spec_fn: chrome_146_ios_tablet,
    },
    GenEntry {
        name: "chrome_141_ios_tablet",
        browser: Browser::Chrome,
        os: Some(Os::Ios),
        device: Device::Tablet,
        major: 141,
        ja4: "t13d1714h2_5b57614c22b0_14788d8d241b",
        spec_fn: chrome_141_ios_tablet,
    },
    GenEntry {
        name: "edge_131_ios_tablet",
        browser: Browser::Edge,
        os: Some(Os::Ios),
        device: Device::Tablet,
        major: 131,
        ja4: "t13d1714h2_5b57614c22b0_14788d8d241b",
        spec_fn: edge_131_ios_tablet,
    },
    GenEntry {
        name: "safari_18_ios_tablet",
        browser: Browser::Safari,
        os: Some(Os::Ios),
        device: Device::Tablet,
        major: 18,
        ja4: "t13d1714h2_5b57614c22b0_14788d8d241b",
        spec_fn: safari_18_ios_tablet,
    },
    GenEntry {
        name: "chrome_144_ios_phone_2",
        browser: Browser::Chrome,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 144,
        ja4: "t13d1714h2_5b57614c22b0_14788d8d241b",
        spec_fn: chrome_144_ios_phone_2,
    },
    GenEntry {
        name: "edge_143_ios_phone_2",
        browser: Browser::Edge,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 143,
        ja4: "t13d1714h2_5b57614c22b0_14788d8d241b",
        spec_fn: edge_143_ios_phone_2,
    },
    GenEntry {
        name: "firefox_137_ios_phone",
        browser: Browser::Firefox,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 137,
        ja4: "t13d1714h2_5b57614c22b0_14788d8d241b",
        spec_fn: firefox_137_ios_phone,
    },
    GenEntry {
        name: "chrome_148_ios_tablet",
        browser: Browser::Chrome,
        os: Some(Os::Ios),
        device: Device::Tablet,
        major: 148,
        ja4: "t13d1714h2_5b57614c22b0_e42f34c56612",
        spec_fn: chrome_148_ios_tablet,
    },
    GenEntry {
        name: "edge_143_ios_phone_3",
        browser: Browser::Edge,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 143,
        ja4: "t13d1714h2_5b57614c22b0_e42f34c56612",
        spec_fn: edge_143_ios_phone_3,
    },
    GenEntry {
        name: "firefox_146_ios_phone_2",
        browser: Browser::Firefox,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 146,
        ja4: "t13d1714h2_5b57614c22b0_e42f34c56612",
        spec_fn: firefox_146_ios_phone_2,
    },
    GenEntry {
        name: "edge_121_ios_phone",
        browser: Browser::Edge,
        os: Some(Os::Ios),
        device: Device::Phone,
        major: 121,
        ja4: "t13d3012h2_1d37bd780c83_b26ce05bbdd6",
        spec_fn: edge_121_ios_phone,
    },
];

// ja4=t13d131000_f57a46bbacb6_e7c285222651 obs=8712
#[rustfmt::skip]
spec! {
    safari_17_ios_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], status, keyshare[x25519],
          versions[0x0304, 0x0303],
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
          ecpf, sct,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17173
#[rustfmt::skip]
spec! {
    safari_18_ios_phone,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc014, 0xc013,
             0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], ecpf, sct,
          compress[brotli], ticket, appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17174
#[rustfmt::skip]
spec! {
    chrome_143_ios_phone,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc014, 0xc013,
             0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], ecpf, sct,
          compress[brotli], ticket, appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35850
#[rustfmt::skip]
spec! {
    safari_6_ios_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc014, 0xc013,
             0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], ecpf, sct,
          compress[brotli], ticket, raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35856
#[rustfmt::skip]
spec! {
    safari_26_ios_phone,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc014, 0xc013,
             0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], ecpf, sct,
          compress[brotli], ticket, raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35851
#[rustfmt::skip]
spec! {
    chrome_133_ios_phone,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc014, 0xc013,
             0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], ecpf, sct,
          compress[brotli], ticket, raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d170900_5b57614c22b0_97f8aa674fd9 obs=8606
#[rustfmt::skip]
spec! {
    safari_9_ios_phone,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, reneg, groups[x25519, p256, p384], status, keyshare[x25519], versions[0x0304, 0x0303],
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
          ecpf, sct,
}

// ja4=t13d1712ht_ab0a1bf427ad_b26ce05bbdd6 obs=760
#[rustfmt::skip]
spec! {
    firefox_138_ios_phone,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc024, 0xc023,
             0xc028, 0xc027, 0x0067, 0x006b, 0x009e, 0x009f,
    session: empty,
    exts: sni, raw[0x0017, ""], groups[x25519, p256, p384], alpn["http/1.1"], keyshare[x25519],
          versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602],
          ecpf, padding, raw[0x0016, ""], raw[0x0031, ""],
}

// ja4=t13d1713h2_5b57614c22b0_7f0f34a4126d obs=1136
#[rustfmt::skip]
spec! {
    chrome_146_ios_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
          ecpf, sct, compress[brotli],
}

// ja4=t13d1714h2_5b57614c22b0_14788d8d241b obs=2638
#[rustfmt::skip]
spec! {
    chrome_141_ios_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
          ecpf, sct, padding, compress[brotli],
}

// ja4=t13d1714h2_5b57614c22b0_14788d8d241b obs=2639
#[rustfmt::skip]
spec! {
    edge_131_ios_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
          ecpf, sct, padding, compress[brotli],
}

// ja4=t13d1714h2_5b57614c22b0_14788d8d241b obs=2645
#[rustfmt::skip]
spec! {
    safari_18_ios_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
          ecpf, sct, padding, compress[brotli],
}

// ja4=t13d1714h2_5b57614c22b0_14788d8d241b obs=2638
#[rustfmt::skip]
spec! {
    chrome_144_ios_phone_2,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
          ecpf, sct, padding, compress[brotli],
}

// ja4=t13d1714h2_5b57614c22b0_14788d8d241b obs=2638
#[rustfmt::skip]
spec! {
    edge_143_ios_phone_2,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
          ecpf, sct, padding, compress[brotli],
}

// ja4=t13d1714h2_5b57614c22b0_14788d8d241b obs=2638
#[rustfmt::skip]
spec! {
    firefox_137_ios_phone,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
          ecpf, sct, padding, compress[brotli],
}

// ja4=t13d1714h2_5b57614c22b0_e42f34c56612 obs=1794
#[rustfmt::skip]
spec! {
    chrome_148_ios_tablet,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
          ecpf, sct, padding, compress[brotli],
}

// ja4=t13d1714h2_5b57614c22b0_e42f34c56612 obs=1806
#[rustfmt::skip]
spec! {
    edge_143_ios_phone_3,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
          ecpf, sct, padding, compress[brotli],
}

// ja4=t13d1714h2_5b57614c22b0_e42f34c56612 obs=1796
#[rustfmt::skip]
spec! {
    firefox_146_ios_phone_2,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009,
             0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
    session: empty,
    exts: sni, raw[0x0017, ""], reneg, groups[x25519, p256, p384], alpn["h2", "http/1.1"], status,
          keyshare[x25519], versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
          ecpf, sct, padding, compress[brotli],
}

// ja4=t13d3012h2_1d37bd780c83_b26ce05bbdd6 obs=28316
#[rustfmt::skip]
spec! {
    edge_121_ios_phone,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc024, 0xc023,
             0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035,
             0x002f, 0x0033, 0x0039, 0x0067, 0x006b, 0x009e, 0x009f, 0xccaa,
    session: empty,
    exts: sni, raw[0x0017, ""], groups[x25519, p256, p384], alpn["h2", "http/1.1"], keyshare[x25519],
          versions[0x0304, 0x0303], psk,
          sigalgs[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602],
          ecpf, padding, raw[0x0016, ""], raw[0x0031, ""],
}
