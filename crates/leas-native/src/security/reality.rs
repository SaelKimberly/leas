//! REALITY client support: provisioner choice + config decoders for the
//! engine's `TlsMode::Reality` arm.
//!
//! `wrap()` routes `TlsConfig::Reality` here: this module decodes the
//! REALITY opts (`pbk`/`sid`) from the link's security config, selects the
//! `HelloProvisioner` (default: [`FixedChrome133`], or a caller-supplied
//! custom provisioner via `NativeConnectParams::reality_provisioner`), and
//! the full client handshake — fingerprint-shaped `ClientHello` with a
//! sealed `SessionId`, X25519 auth key, HMAC/Ed25519 server auth — runs in
//! `leas_tls::client::connect`.

use std::sync::Arc;

use base64::Engine as _;

use crate::error::NativeError;

pub use leas_tls::reality::{FixedChrome133, HelloProvisioner, SpecProvisioner, SpiderConfig};

/// Chosen provisioner for a REALITY connect.
#[derive(Clone, Default)]
pub enum HelloProvisionerChoice {
    #[default]
    FixedChrome133,
    Custom(Arc<dyn HelloProvisioner>),
}

impl std::fmt::Debug for HelloProvisionerChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FixedChrome133 => f.write_str("FixedChrome133"),
            // `dyn HelloProvisioner` is deliberately not `Debug`; the
            // concrete provisioner is observable through the type itself.
            Self::Custom(_) => f.write_str("Custom(..)"),
        }
    }
}

/// Decode a REALITY `pbk` (base64url, no padding — Xray's `privateKey`
/// encoding) to its 32 bytes.
///
/// Every failure here is a CONFIG defect (`NativeError::Config` →
/// `FailureEvidence::ConfigDefect` → `PurgeReason::ConfigInvalid`), never a
/// `Reality` error: the server was never reached, so the row proves nothing
/// about the peer. A `Reality` error would be purged as `RealityFallback` —
/// "the server is not REALITY / a possible MITM" — which is a verdict about the
/// wrong thing entirely.
pub(crate) fn decode_pbk(s: &str) -> Result<[u8; 32], NativeError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| NativeError::Config(format!("invalid pbk base64url: {e}")))?;
    let pbk: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NativeError::Config("pbk must decode to 32 bytes".into()))?;
    Ok(pbk)
}

/// Decode a REALITY short id (hex, ≤8 bytes) to its bytes.
///
/// Same rule as [`decode_pbk`]: a malformed short id is a config defect, not a
/// peer verdict.
pub(crate) fn decode_sid(s: &str) -> Result<Vec<u8>, NativeError> {
    if s.len() > 16 || !s.len().is_multiple_of(2) {
        return Err(NativeError::Config(format!(
            "short id {s:?} must be hex, at most 8 bytes"
        )));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| NativeError::Config(format!("invalid short id {s:?}: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A malformed `pbk`/`sid` is a CONFIG defect, and the test asserts what
    /// the failure *proves* rather than which variant carries it: these rows
    /// used to report `RealityFallback`, so a broken config was permanently
    /// purged as "the server is not REALITY / a possible MITM" — a verdict
    /// about the peer when the peer was never reached.
    #[test]
    fn malformed_reality_material_proves_a_config_defect_not_a_peer_verdict() {
        use crate::error::FailureEvidence;
        for err in [
            decode_pbk("!!!").expect_err("not base64"),
            decode_pbk("Zm9vYmFy").expect_err("6 bytes"),
            decode_sid("abc").expect_err("odd length"),
            decode_sid("001122334455667788").expect_err("9 bytes"),
            decode_sid("zz").expect_err("not hex"),
        ] {
            assert_eq!(
                err.evidence(),
                Some(FailureEvidence::ConfigDefect),
                "{err:?} must not be read as a peer verdict"
            );
        }
    }

    #[test]
    fn decode_pbk_accepts_base64url_32_bytes() {
        let pbk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xABu8; 32]);
        assert_eq!(decode_pbk(&pbk).unwrap(), [0xAB; 32]);
    }

    #[test]
    fn decode_pbk_rejects_short_and_malformed() {
        assert!(decode_pbk("Zm9vYmFy").is_err()); // 6 bytes
        assert!(decode_pbk("!!!").is_err()); // not base64
    }

    #[test]
    fn decode_sid_accepts_hex_up_to_8_bytes() {
        assert_eq!(
            decode_sid("0011223344556677").unwrap(),
            vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
        assert_eq!(decode_sid("ab").unwrap(), vec![0xAB]);
        assert_eq!(decode_sid("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_sid_rejects_odd_length_and_too_long() {
        assert!(decode_sid("abc").is_err());
        assert!(decode_sid("001122334455667788").is_err()); // 9 bytes
        assert!(decode_sid("zz").is_err()); // not hex
    }

    #[test]
    fn provisioner_choice_defaults_to_fixed_chrome133() {
        let choice = HelloProvisionerChoice::default();
        assert_eq!(format!("{choice:?}"), "FixedChrome133");
    }
}
