//! Compositional fingerprint builder (the foundation layer; catalog
//! selection is sugar over this).

use crate::fingerprints::error::FingerprintError;
use crate::fingerprints::query::Fingerprint;
use crate::spec::grease::is_grease;
use crate::spec::{ClientHelloSpec, ExtensionSpec};

/// Sentinel for GREASE extensions (no fixed wire type).
const GREASE_TYPE_SENTINEL: u16 = 0xFFFF;

/// What happens to GREASE slots in the built hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GreasePolicy {
    /// Preserve the base profile's GREASE placement (default).
    #[default]
    Keep,
    /// Remove GREASE cipher slots and extensions entirely (for
    /// GREASE-intolerant servers).
    Strip,
}

/// Builds a `ClientHelloSpec` from a resolved base plus typed overrides.
///
/// Overrides apply in call order; each validates immediately where cheap
/// (empty lists) and finally at `build()` (duplicates, parseability).
/// [`GreasePolicy`] is likewise stored and applied inside `build()` —
/// after every override, so stripping sees the FINAL lists (eager
/// application would let a later `override_ciphers` reintroduce GREASE
/// values past the policy).
#[derive(Debug, Clone)]
pub struct FingerprintBuilder {
    spec: ClientHelloSpec,
    grease: GreasePolicy,
    missing: Option<String>,
}

impl FingerprintBuilder {
    /// Resolves `fingerprint` strictly, then wraps its spec for overriding.
    ///
    /// # Errors
    /// [`FingerprintError::Unknown`] when the identity has no table row.
    pub fn new(fingerprint: &Fingerprint) -> Result<Self, FingerprintError> {
        Ok(Self {
            spec: fingerprint.resolve()?.spec,
            grease: GreasePolicy::default(),
            missing: None,
        })
    }

    /// Replaces the whole cipher list. GREASE placeholders allowed; empty rejected.
    #[must_use]
    pub fn override_ciphers(mut self, ciphers: &[u16]) -> Self {
        self.spec.cipher_suites = ciphers.to_vec();
        self
    }

    /// Replaces the whole ordered extension list (order is
    /// fingerprint-critical). Convenience mutators below are usually better.
    #[must_use]
    pub fn override_extensions(mut self, extensions: Vec<ExtensionSpec>) -> Self {
        self.spec.extensions = extensions;
        self
    }

    /// Config-driven curve preferences (xray `CurvePreferences` mirror):
    /// replaces `supported_groups`, rebuilds `key_share` shares.
    #[must_use]
    pub fn curves(mut self, curves: &[u16]) -> Self {
        self.spec = crate::spec::apply_curve_preferences(&self.spec, curves);
        self
    }

    /// Find-and-replace the ALPN extension; keeps position in the list.
    #[must_use]
    pub fn alpn(mut self, protos: &[&str]) -> Self {
        let protos: Vec<String> = protos.iter().map(|p| (*p).to_string()).collect();
        self.replace_one(
            |e| matches!(e, ExtensionSpec::Alpn(_)),
            || ExtensionSpec::Alpn(protos.clone()),
            "base spec has no ALPN extension",
        );
        self
    }

    /// Find-and-replace `signature_algorithms`.
    #[must_use]
    pub fn sig_algorithms(mut self, schemes: &[u16]) -> Self {
        self.replace_one(
            |e| matches!(e, ExtensionSpec::SignatureAlgorithms(_)),
            || ExtensionSpec::SignatureAlgorithms(schemes.to_vec()),
            "base spec has no signature_algorithms extension",
        );
        self
    }

    /// GREASE handling policy; stored and applied at `build()`.
    #[must_use]
    pub const fn grease(mut self, policy: GreasePolicy) -> Self {
        self.grease = policy;
        self
    }

    /// Validates and returns the built spec.
    ///
    /// # Errors
    /// [`FingerprintError::InvalidOverride`] on a missing base extension,
    /// an empty cipher list, or duplicate extension types.
    pub fn build(mut self) -> Result<ClientHelloSpec, FingerprintError> {
        if let Some(msg) = self.missing {
            return Err(FingerprintError::InvalidOverride(msg));
        }
        if self.grease == GreasePolicy::Strip {
            self.spec.cipher_suites.retain(|&c| !is_grease(c));
            self.spec
                .extensions
                .retain(|e| !matches!(e, ExtensionSpec::Grease));
        }
        if self.spec.cipher_suites.is_empty() {
            return Err(FingerprintError::InvalidOverride(
                "cipher list is empty".into(),
            ));
        }
        let mut seen: Vec<u16> = Vec::with_capacity(self.spec.extensions.len());
        for ext in &self.spec.extensions {
            let ty = extension_type(ext);
            if ty == GREASE_TYPE_SENTINEL {
                continue; // multiple GREASE extensions are legal
            }
            if seen.contains(&ty) {
                return Err(FingerprintError::InvalidOverride(format!(
                    "duplicate extension 0x{ty:04x}"
                )));
            }
            seen.push(ty);
        }
        Ok(self.spec)
    }

    fn replace_one(
        &mut self,
        pred: impl Fn(&ExtensionSpec) -> bool,
        make: impl FnOnce() -> ExtensionSpec,
        missing_msg: &str,
    ) {
        match self.spec.extensions.iter_mut().find(|e| pred(e)) {
            Some(slot) => *slot = make(),
            // Missing base extension is a deferred error surfaced at build().
            None => {
                self.missing = Some(missing_msg.to_string());
            }
        }
    }
}

/// Wire type of an extension for validation purposes.
const fn extension_type(ext: &ExtensionSpec) -> u16 {
    match ext {
        ExtensionSpec::ServerName => 0x0000,
        ExtensionSpec::SupportedGroups(_) => 0x000A,
        ExtensionSpec::KeyShare(_) => 0x0033,
        ExtensionSpec::SupportedVersions(_) => 0x002B,
        ExtensionSpec::SignatureAlgorithms(_) => 0x000D,
        ExtensionSpec::Alpn(_) => 0x0010,
        ExtensionSpec::EcPointFormats => 0x000B,
        ExtensionSpec::SessionTicket => 0x0023,
        ExtensionSpec::PskKeyExchangeModes => 0x002D,
        ExtensionSpec::StatusRequest => 0x0005,
        ExtensionSpec::SignedCertificateTimestamp => 0x0012,
        ExtensionSpec::RenegotiationInfo => 0xFF01,
        ExtensionSpec::CompressCertificate(_) => 0x001B,
        ExtensionSpec::ApplicationSettings(_) => 0x4469,
        ExtensionSpec::RecordSizeLimit(_) => 0x001C,
        ExtensionSpec::Padding => 0x0015,
        ExtensionSpec::Grease => GREASE_TYPE_SENTINEL,
        ExtensionSpec::EchGrease => 0xFE0D,
        ExtensionSpec::Raw { ty, .. } => *ty,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprints::query::Browser;

    fn base() -> FingerprintBuilder {
        FingerprintBuilder::new(&Fingerprint::new(Browser::Chrome).with_version(130)).unwrap()
    }

    #[test]
    fn overrides_ciphers_replace_entirely() {
        let spec = base().override_ciphers(&[0x1301, 0x1302]).build().unwrap();
        assert_eq!(spec.cipher_suites, vec![0x1301, 0x1302]);
    }

    #[test]
    fn empty_cipher_override_rejected() {
        let err = base().override_ciphers(&[]).build().unwrap_err();
        assert!(matches!(err, FingerprintError::InvalidOverride(_)));
    }

    #[test]
    fn alpn_replaces_existing_extension() {
        let spec = base().alpn(&["h2", "http/1.1"]).build().unwrap();
        assert!(spec.extensions.iter().any(|e| matches!(
            e, ExtensionSpec::Alpn(p) if p == &["h2".to_string(), "http/1.1".to_string()]
        )));
        // exactly one Alpn extension
        assert_eq!(
            spec.extensions
                .iter()
                .filter(|e| matches!(e, ExtensionSpec::Alpn(_)))
                .count(),
            1
        );
    }

    #[test]
    fn duplicate_extensions_rejected_after_override() {
        let dup =
            base().override_extensions(vec![ExtensionSpec::ServerName, ExtensionSpec::ServerName]);
        let err = dup.build().unwrap_err();
        assert!(matches!(err, FingerprintError::InvalidOverride(msg) if msg.contains("duplicate")));
    }

    #[test]
    fn curves_delegates_to_apply_curve_preferences() {
        let curves = [0x001Du16, 0x11EC];
        let built = base().curves(&curves).build().unwrap();
        let direct = crate::spec::apply_curve_preferences(
            &Fingerprint::new(Browser::Chrome)
                .with_version(130)
                .resolve()
                .unwrap()
                .spec,
            &curves,
        );
        assert_eq!(built, direct);
    }

    #[test]
    fn grease_strip_applies_to_later_overrides() {
        // Policy is applied in build(), AFTER overrides — a GREASE value
        // introduced by override_ciphers must still be stripped.
        let spec = base()
            .grease(GreasePolicy::Strip)
            .override_ciphers(&[0xCACA, 0x1301])
            .build()
            .unwrap();
        assert_eq!(spec.cipher_suites, vec![0x1301]);
    }

    #[test]
    fn grease_strip_removes_grease_variants() {
        let spec = base().grease(GreasePolicy::Strip).build().unwrap();
        assert!(
            !spec
                .cipher_suites
                .iter()
                .any(|&c| crate::spec::grease::is_grease(c))
        );
        assert!(
            !spec
                .extensions
                .iter()
                .any(|e| matches!(e, ExtensionSpec::Grease))
        );
    }

    #[test]
    fn macos_safari_resolves_before_building() {
        // builder resolves strictly — unknown combos fail at construction.
        // Chrome 200 is above every chrome row in both tiers; 2 would now
        // resolve (hand chrome_130 band absorbs down to 0).
        let err = FingerprintBuilder::new(&Fingerprint::new(Browser::Chrome).with_version(200));
        assert!(err.is_err());
    }
}
