//! The surviving hand-transcribed profiles, declared via `spec!`.
//!
//! Two wire-exact profiles remain after the JA4 roster reduction: Chrome
//! 130 (Windows desktop) and Edge 106 (Windows desktop). Both were
//! transcribed byte-for-byte into `spec!` tokens from the original hand
//! modules (`profiles/chrome.rs` and `profiles/edge106.rs`, since
//! deleted); the equality is pinned by the (now removed) equivalence test
//! `hand_selected_matches_original_wire_bytes`.
//!
//! GREASE rules: the GREASE cipher is first, `supported_groups` and
//! `supported_versions` carry a GREASE slot, and each profile closes with
//! a standalone GREASE extension (Edge 106 carries two — one at the head
//! of the extension list, one before padding — Chrome 130 only the head
//! one). `raw[0x0017, ""]` is the empty `extended_master_secret` body and
//! `appsettings["h2"]` the ALPS-for-h2 body; `compress[...]` uses the
//! literal ids so the values match the originals exactly.

spec! {
    chrome_130,
    ciphers: GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c,
             0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
             0x002f, 0x0035,
    session: random32,
    exts: grease, sni, raw[0x0017, ""], reneg,
          groups[grease, x25519, p256, p384],
          ecpf, ticket, alpn["h2", "http/1.1"], status,
          sct, keyshare[grease, x25519], psk,
          versions[grease, 0x0304, 0x0303], compress[0x0002, 0x0003],
          appsettings["h2"],
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
                  0x0806, 0x0601],
          padding
}

spec! {
    edge_106,
    ciphers: GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c,
             0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
             0x002f, 0x0035,
    session: random32,
    exts: grease, sni, raw[0x0017, ""], reneg,
          groups[grease, x25519, p256, p384],
          ecpf, ticket, alpn["h2", "http/1.1"], status,
          sigalgs[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
                  0x0806, 0x0601],
          sct, keyshare[grease, x25519], psk,
          versions[grease, 0x0304, 0x0303], compress[0x0003],
          appsettings["h2"],
          grease, padding
}
