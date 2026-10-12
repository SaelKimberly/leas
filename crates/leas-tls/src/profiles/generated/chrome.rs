//! Chromium family desktop hellos (Chrome, Edge, Opera, Brave, Samsung Internet; the `chrome_desktop` wire template)
//!
//! Emitter output (`gen_specs.py --emit`); do not edit by hand.
//! Regeneration is byte-deterministic (`--selftest` verifies the
//! committed files match a fresh render).

use super::GenEntry;
use crate::fingerprints::{Browser, Device, Os};

#[rustfmt::skip]
pub const GENERATED: &[GenEntry] = &[
    GenEntry {
        name: "opera_98_macos_desktop",
        browser: Browser::Opera,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 98,
        ja4: "t13d131000_f57a46bbacb6_e7c285222651",
        spec_fn: opera_98_macos_desktop,
    },
    GenEntry {
        name: "chrome_115_macos_desktop",
        browser: Browser::Chrome,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 115,
        ja4: "t13d131000_f57a46bbacb6_e7c285222651",
        spec_fn: chrome_115_macos_desktop,
    },
    GenEntry {
        name: "edge_112_macos_desktop",
        browser: Browser::Edge,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 112,
        ja4: "t13d131000_f57a46bbacb6_e7c285222651",
        spec_fn: edge_112_macos_desktop,
    },
    GenEntry {
        name: "opera_97_windows_desktop",
        browser: Browser::Opera,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 97,
        ja4: "t13d131000_f57a46bbacb6_e7c285222651",
        spec_fn: opera_97_windows_desktop,
    },
    GenEntry {
        name: "brave_126_windows_desktop",
        browser: Browser::Brave,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 126,
        ja4: "t13d131100_f57a46bbacb6_e5728521abd4",
        spec_fn: brave_126_windows_desktop,
    },
    GenEntry {
        name: "edge_128_windows_desktop",
        browser: Browser::Edge,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 128,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: edge_128_windows_desktop,
    },
    GenEntry {
        name: "chrome_122_macos_desktop",
        browser: Browser::Chrome,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 122,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: chrome_122_macos_desktop,
    },
    GenEntry {
        name: "edge_132_macos_desktop",
        browser: Browser::Edge,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 132,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: edge_132_macos_desktop,
    },
    GenEntry {
        name: "opera_119_macos_desktop",
        browser: Browser::Opera,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 119,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: opera_119_macos_desktop,
    },
    GenEntry {
        name: "opera_128_windows_desktop",
        browser: Browser::Opera,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 128,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: opera_128_windows_desktop,
    },
    GenEntry {
        name: "chrome_143_windows_desktop",
        browser: Browser::Chrome,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 143,
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        spec_fn: chrome_143_windows_desktop,
    },
    GenEntry {
        name: "opera_130_macos_desktop",
        browser: Browser::Opera,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 130,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: opera_130_macos_desktop,
    },
    GenEntry {
        name: "edge_148_macos_desktop",
        browser: Browser::Edge,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 148,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: edge_148_macos_desktop,
    },
    GenEntry {
        name: "chrome_149_macos_desktop",
        browser: Browser::Chrome,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 149,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: chrome_149_macos_desktop,
    },
    GenEntry {
        name: "opera_130_windows_desktop",
        browser: Browser::Opera,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 130,
        ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        spec_fn: opera_130_windows_desktop,
    },
    GenEntry {
        name: "edge_121_windows_desktop",
        browser: Browser::Edge,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 121,
        ja4: "t13d3012h2_1d37bd780c83_b26ce05bbdd6",
        spec_fn: edge_121_windows_desktop,
    },
    GenEntry {
        name: "chrome_93_windows_desktop",
        browser: Browser::Chrome,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 93,
        ja4: "t13d3013h2_1d37bd780c83_1b3407e2c936",
        spec_fn: chrome_93_windows_desktop,
    },
    GenEntry {
        name: "brave_90_macos_desktop",
        browser: Browser::Brave,
        os: Some(Os::MacOs),
        device: Device::Desktop,
        major: 90,
        ja4: "t13d4312ht_36cd39a4fcc1_58ed7828516f",
        spec_fn: brave_90_macos_desktop,
    },
    GenEntry {
        name: "brave_89_windows_desktop",
        browser: Browser::Brave,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 89,
        ja4: "t13d4312ht_36cd39a4fcc1_58ed7828516f",
        spec_fn: brave_89_windows_desktop,
    },
];

// ja4=t13d131000_f57a46bbacb6_e7c285222651 obs=8722
#[rustfmt::skip]
spec! {
    opera_98_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, status,
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
          sct, keyshare[mlkem768, x25519], versions[0x0304, 0x0303],
}

// ja4=t13d131000_f57a46bbacb6_e7c285222651 obs=8722
#[rustfmt::skip]
spec! {
    chrome_115_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, status,
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
          sct, keyshare[mlkem768, x25519], versions[0x0304, 0x0303],
}

// ja4=t13d131000_f57a46bbacb6_e7c285222651 obs=8714
#[rustfmt::skip]
spec! {
    edge_112_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, status,
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
          sct, keyshare[mlkem768, x25519], versions[0x0304, 0x0303],
}

// ja4=t13d131000_f57a46bbacb6_e7c285222651 obs=8716
#[rustfmt::skip]
spec! {
    opera_97_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, status,
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
          sct, keyshare[mlkem768, x25519], versions[0x0304, 0x0303],
}

// ja4=t13d131100_f57a46bbacb6_e5728521abd4 obs=259
#[rustfmt::skip]
spec! {
    brave_126_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0xc009, 0xc00a,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, status,
          sigalgs[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
          sct, keyshare[mlkem768, x25519], versions[0x0304, 0x0303],
          raw[0x0032, "0018080404030807080508060401050106010503060302010203"],
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17282
#[rustfmt::skip]
spec! {
    edge_128_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], sct,
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], compress[brotli, zstd],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17196
#[rustfmt::skip]
spec! {
    chrome_122_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], sct,
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], compress[brotli, zstd],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17180
#[rustfmt::skip]
spec! {
    edge_132_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], sct,
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], compress[brotli, zstd],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17173
#[rustfmt::skip]
spec! {
    opera_119_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], sct,
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], compress[brotli, zstd],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17173
#[rustfmt::skip]
spec! {
    opera_128_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], sct,
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], compress[brotli, zstd],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_02713d6af862 obs=17173
#[rustfmt::skip]
spec! {
    chrome_143_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], sct,
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], compress[brotli, zstd],
          appsettings["h2", "http/1.1"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35850
#[rustfmt::skip]
spec! {
    opera_130_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], sct,
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], compress[brotli, zstd],
          raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35854
#[rustfmt::skip]
spec! {
    edge_148_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], sct,
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], compress[brotli, zstd],
          raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35851
#[rustfmt::skip]
spec! {
    chrome_149_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], sct,
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], compress[brotli, zstd],
          raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd obs=35870
#[rustfmt::skip]
spec! {
    opera_130_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035,
    session: random32,
    exts: sni, raw[0x0017, ""], reneg, groups[mlkem768, x25519, p256, p384], ecpf, ticket,
          alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], sct,
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], compress[brotli, zstd],
          raw[0x44cd, "000c02683208687474702f312e31"], ech,
}

// ja4=t13d3012h2_1d37bd780c83_b26ce05bbdd6 obs=28320
#[rustfmt::skip]
spec! {
    edge_121_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035, 0x0033, 0x0039, 0x003c, 0x003d, 0x0067, 0x006b, 0x009e,
             0x009f, 0xc009, 0xc00a, 0xc023, 0xc024, 0xc027, 0xc028, 0xccaa,
    session: random32,
    exts: sni, raw[0x0017, ""], groups[mlkem768, x25519, p256, p384], ecpf, alpn["h2", "http/1.1"],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602],
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], padding, raw[0x0016, ""],
          raw[0x0031, ""],
}

// ja4=t13d3013h2_1d37bd780c83_1b3407e2c936 obs=4456
#[rustfmt::skip]
spec! {
    chrome_93_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035, 0x0033, 0x0039, 0x003c, 0x003d, 0x0067, 0x006b, 0x009e,
             0x009f, 0xc009, 0xc00a, 0xc023, 0xc024, 0xc027, 0xc028, 0xccaa,
    session: random32,
    exts: sni, raw[0x0017, ""], groups[mlkem768, x25519, p256, p384], ecpf, alpn["h2", "http/1.1"],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0203, 0x0301, 0x0201, 0x0302, 0x0202, 0x0402, 0x0502, 0x0602],
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], padding, raw[0x0016, ""],
          raw[0x0031, ""], raw[0x3374, ""],
}

// ja4=t13d4312ht_36cd39a4fcc1_58ed7828516f obs=1565
#[rustfmt::skip]
spec! {
    brave_90_macos_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035, 0x0033, 0x0039, 0x003c, 0x003d, 0x0067, 0x006b, 0x009e,
             0x009f, 0x1304, 0xc009, 0xc00a, 0xc023, 0xc024, 0xc027, 0xc028, 0xc09c, 0xc09d, 0xc09e,
             0xc09f, 0xc0a0, 0xc0a1, 0xc0a2, 0xc0a3, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af, 0xccaa,
    session: random32,
    exts: sni, raw[0x0017, ""], groups[mlkem768, x25519, p256, p384], ecpf, alpn["http/1.1"],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x0804, 0x080a, 0x0805, 0x080b, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0203, 0x0201],
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], padding, raw[0x0016, ""],
          raw[0x0031, ""],
}

// ja4=t13d4312ht_36cd39a4fcc1_58ed7828516f obs=1567
#[rustfmt::skip]
spec! {
    brave_89_windows_desktop,
    ciphers: 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
             0x009c, 0x009d, 0x002f, 0x0035, 0x0033, 0x0039, 0x003c, 0x003d, 0x0067, 0x006b, 0x009e,
             0x009f, 0x1304, 0xc009, 0xc00a, 0xc023, 0xc024, 0xc027, 0xc028, 0xc09c, 0xc09d, 0xc09e,
             0xc09f, 0xc0a0, 0xc0a1, 0xc0a2, 0xc0a3, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af, 0xccaa,
    session: random32,
    exts: sni, raw[0x0017, ""], groups[mlkem768, x25519, p256, p384], ecpf, alpn["http/1.1"],
          sigalgs[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x0804, 0x080a, 0x0805, 0x080b, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0203, 0x0201],
          keyshare[mlkem768, x25519], psk, versions[0x0304, 0x0303], padding, raw[0x0016, ""],
          raw[0x0031, ""],
}
