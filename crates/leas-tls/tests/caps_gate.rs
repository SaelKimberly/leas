//! Roster-wide gate: each `GenEntry.caps` must equal what the emitted hello
//! actually carries.
//!
//! The mask is compile-time knowledge about the declared profile; this test
//! recomputes it from the wire bytes built with a fixed RNG (GREASE excluded),
//! so a stale constant or a generator change fails here.

use leas_tls::SecureRandom;
use leas_tls::fingerprints::{Browser, Device, Fingerprint};
use leas_tls::hello::parse::parse_hello;
use leas_tls::hello::{BuildParams, build_hello};
use leas_tls::profiles::generated::GENERATED;
use leas_tls::profiles::hand_selected::{CHROME_130_CAPS, EDGE_106_CAPS, chrome_130, edge_106};
use leas_tls::spec::caps::{ExtKind, GroupKind, HelloCaps, SigKind};

type HandRow = (
    &'static str,
    fn() -> leas_tls::spec::ClientHelloSpec,
    HelloCaps,
);

struct FixedRng(std::sync::atomic::AtomicU8);

impl FixedRng {
    const fn new() -> Self {
        Self(std::sync::atomic::AtomicU8::new(0))
    }
}

impl SecureRandom for FixedRng {
    fn fill(&self, dest: &mut [u8]) -> Result<(), ring::error::Unspecified> {
        for byte in dest {
            *byte = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }
}

const fn grease(ty: u16) -> bool {
    ty & 0x0f0f == 0x0a0a && (ty >> 8) == (ty & 0xff)
}

fn ext_bits(ty: u16) -> u64 {
    let bit = |k: ExtKind| k.bit();
    match ty {
        0x0000 => bit(ExtKind::ServerName),
        0x000d => bit(ExtKind::SignatureAlgorithms),
        0x000a => bit(ExtKind::SupportedGroups),
        0x0033 => bit(ExtKind::KeyShare),
        0x002b => bit(ExtKind::SupportedVersions),
        0x0010 => bit(ExtKind::Alpn),
        0x000b => bit(ExtKind::EcPointFormats),
        0x0023 => bit(ExtKind::SessionTicket),
        0x002d => bit(ExtKind::PskKeyExchangeModes),
        0x0005 => bit(ExtKind::StatusRequest),
        0x0012 => bit(ExtKind::SignedCertificateTimestamp),
        0xff01 => bit(ExtKind::RenegotiationInfo),
        0x0016 => bit(ExtKind::EncryptThenMac),
        0x0022 => bit(ExtKind::DelegatedCredentials),
        0x0031 => bit(ExtKind::PostHandshakeAuth),
        0x0032 => bit(ExtKind::SignatureAlgorithmsCert),
        0x001b => bit(ExtKind::CompressCertificate),
        0x4469 => bit(ExtKind::ApplicationSettingsOld),
        0x44cd => bit(ExtKind::ApplicationSettings),
        0x001c => bit(ExtKind::RecordSizeLimit),
        0x0015 => bit(ExtKind::Padding),
        0xfe0d => bit(ExtKind::EncryptedClientHello),
        0x0017 => bit(ExtKind::ExtendedMasterSecret),
        t if grease(t) => bit(ExtKind::Grease),
        _ => 0,
    }
}

const fn sig_bit(scheme: u16) -> u32 {
    let kind = match scheme {
        0x0403 => SigKind::EcdsaP256Sha256,
        0x0503 => SigKind::EcdsaP384Sha384,
        0x0603 => SigKind::EcdsaP521Sha512,
        0x0401 => SigKind::RsaPkcs1Sha256,
        0x0501 => SigKind::RsaPkcs1Sha384,
        0x0601 => SigKind::RsaPkcs1Sha512,
        0x0804 => SigKind::RsaPssSha256,
        0x0805 => SigKind::RsaPssSha384,
        0x0806 => SigKind::RsaPssSha512,
        0x0809 => SigKind::RsaPssPssSha256,
        0x080a => SigKind::RsaPssPssSha384,
        0x080b => SigKind::RsaPssPssSha512,
        0x0807 => SigKind::Ed25519,
        0x0808 => SigKind::Ed448,
        0x0402 => SigKind::DsaSha256,
        0x0502 => SigKind::DsaSha384,
        0x0602 => SigKind::DsaSha512,
        0x0203 => SigKind::EcdsaSha1,
        0x0201 => SigKind::RsaPkcs1Sha1,
        0x0904 => SigKind::Mldsa44,
        0x0905 => SigKind::Mldsa65,
        0x0906 => SigKind::Mldsa87,
        0x0202 => SigKind::DsaSha1,
        0x0301 => SigKind::RsaPkcs1Sha224,
        0x0302 => SigKind::DsaSha224,
        0x0303 => SigKind::EcdsaSha224,
        _ => return 0,
    };
    kind.bit()
}

const fn group_bit(group: u16) -> u64 {
    let kind = match group {
        0x001d => GroupKind::X25519,
        0x0017 => GroupKind::P256,
        0x0018 => GroupKind::P384,
        0x11ec => GroupKind::X25519Mlkem768,
        0x0019 => GroupKind::P521,
        0x0100 => GroupKind::Ffdhe2048,
        0x0101 => GroupKind::Ffdhe3072,
        t if grease(t) => GroupKind::Grease,
        _ => return 0,
    };
    kind.bit()
}

fn u16_list(body: &[u8]) -> Vec<u16> {
    let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    body[2..2 + len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_be_bytes(*p))
        .collect()
}

fn compute(spec: &leas_tls::spec::ClientHelloSpec) -> HelloCaps {
    let mlkem = vec![0x22u8; 1184];
    let hello = build_hello(
        spec,
        &BuildParams {
            server_name: "example.com",
            alpn: None,
            x25519_pub: &[0x11; 32],
            mlkem768_pub: Some(&mlkem),
            rng: &FixedRng::new(),
        },
    )
    .unwrap();
    let parsed = parse_hello(&hello.handshake_bytes).unwrap();
    let mut caps = HelloCaps {
        ext: 0,
        ciphers: 0,
        sigalgs: 0,
        groups: 0,
        keyshare: 0,
        session_id_len: u8::try_from(parsed.session_id.len()).unwrap_or(0),
    };
    for (ty, body) in &parsed.extensions {
        caps.ext |= ext_bits(*ty);
        match *ty {
            0x000d => {
                for s in u16_list(body) {
                    caps.sigalgs |= sig_bit(s);
                }
            }
            0x000a => {
                for g in u16_list(body) {
                    caps.groups |= group_bit(g);
                }
            }
            0x0033 => {
                // KeyShare: list_len(2), then (group u16, key_len u16, key)*
                let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
                let mut at = 2;
                while at + 4 <= 2 + len {
                    let g = u16::from_be_bytes([body[at], body[at + 1]]);
                    let klen = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
                    caps.keyshare |= group_bit(g);
                    at += 4 + klen;
                }
            }
            _ => {}
        }
    }
    for c in &parsed.cipher_suites {
        caps.ciphers |= match *c {
            0x1301 => 1,
            0x1302 => 2,
            0x1303 => 4,
            t if grease(t) => 8,
            _ => 0,
        };
    }
    caps
}

#[test]
fn every_generated_cap_matches_its_emitted_hello() {
    for entry in GENERATED {
        assert_eq!(compute(&(entry.spec_fn)()), entry.caps, "{}", entry.name);
    }
    let hand: [HandRow; 2] = [
        ("chrome_130", chrome_130, CHROME_130_CAPS),
        ("edge_106", edge_106, EDGE_106_CAPS),
    ];
    for (name, spec, caps) in hand {
        assert_eq!(compute(&spec()), caps, "{name}");
    }
}

#[test]
fn hand_profiles_expose_caps_through_resolution() {
    let chrome = Fingerprint::new(Browser::Chrome)
        .with_version(130)
        .with_device(Device::Desktop)
        .resolve_shared()
        .unwrap();
    assert!(chrome.caps.has_alps());
    assert!(chrome.caps.has_ext(ExtKind::Padding));
    assert!(chrome.caps.offers_group(GroupKind::X25519));
    assert!(chrome.caps.offers_tls13_aead());
    assert!(chrome.caps.offers_sigalg(SigKind::RsaPssSha256));
}

/// The REALITY filter's caps predicate must agree with the spec-level rule
/// for every roster row, so the O(1) path cannot drift from the source.
#[test]
fn reality_caps_match_the_spec_rule() {
    for entry in GENERATED {
        let spec = (entry.spec_fn)();
        let by_caps = entry.caps.offers_tls13_aead()
            && entry.caps.session_id_len == 32
            && entry.caps.shares_group(GroupKind::X25519);
        assert_eq!(by_caps, spec.reality_eligible(), "{}", entry.name);
    }
}

/// Resumption changes the declared hello shape (`pre_shared_key`); the resumed
/// JA4 is a separate value and the default roster goldens stay untouched.
#[test]
fn resumed_shape_has_its_own_ja4() {
    use leas_tls::crypto::fingerprint::ja3::Ja3Fields;
    use leas_tls::crypto::fingerprint::ja4::full_ja4;
    use leas_tls::spec::ExtensionSpec;

    let base_spec = chrome_130();
    let mut resumed_spec = base_spec.clone();
    resumed_spec.extensions.push(ExtensionSpec::Raw {
        ty: 0x0029,
        data: Vec::new(),
    });
    let base = full_ja4(&Ja3Fields::from_spec(&base_spec));
    let resumed = full_ja4(&Ja3Fields::from_spec(&resumed_spec));
    assert_ne!(base, resumed, "pre_shared_key must change the JA4");
    // Pinned opt-in shape; the default roster value is asserted elsewhere.
    assert_eq!(resumed, "t13d1517h2_8daaf6152771_6cdcb247c39b");
}
