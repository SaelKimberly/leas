//! Compile-time description of what a declared roster profile advertises.
//!
//! This is a sidecar to [`ClientHelloSpec`](crate::spec::ClientHelloSpec), not
//! a replacement: the spec stays the wire-order source of truth, while these
//! masks answer the per-dial "does this profile offer X?" questions in O(1)
//! with no `Vec` scan.
//!
//! Scope is the **declared** roster profile. Per-connection mutations
//! (`apply_curve_preferences`, REALITY's hybrid graft, HRR/ECH rebuilds) are
//! applied after resolution; code must not read these masks as if they
//! described the mutated spec.

/// Extension types the roster can emit, as dense bit positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtKind {
    ServerName,
    SignatureAlgorithms,
    SupportedGroups,
    KeyShare,
    SupportedVersions,
    Alpn,
    EcPointFormats,
    SessionTicket,
    PskKeyExchangeModes,
    StatusRequest,
    SignedCertificateTimestamp,
    RenegotiationInfo,
    CompressCertificate,
    ApplicationSettingsOld,
    ApplicationSettings,
    RecordSizeLimit,
    Padding,
    EncryptedClientHello,
    ExtendedMasterSecret,
    Grease,
    EncryptThenMac,
    DelegatedCredentials,
    PostHandshakeAuth,
    SignatureAlgorithmsCert,
}

impl ExtKind {
    /// Bit for this kind.
    #[must_use]
    pub const fn bit(self) -> u64 {
        1u64 << (self as u32)
    }
}

/// Dense signature-scheme positions (the schemes the roster can emit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SigKind {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    RsaPssPssSha256,
    RsaPssPssSha384,
    RsaPssPssSha512,
    Ed25519,
    Ed448,
    DsaSha256,
    DsaSha384,
    DsaSha512,
    EcdsaSha1,
    RsaPkcs1Sha1,
    Mldsa44,
    Mldsa65,
    Mldsa87,
    DsaSha1,
    RsaPkcs1Sha224,
    DsaSha224,
    EcdsaSha224,
}

impl SigKind {
    /// Bit for this scheme.
    #[must_use]
    pub const fn bit(self) -> u32 {
        1u32 << (self as u32)
    }
}

/// Dense group positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GroupKind {
    Grease,
    X25519,
    P256,
    P384,
    X25519Mlkem768,
    P521,
    Ffdhe2048,
    Ffdhe3072,
}

impl GroupKind {
    /// Bit for this group.
    #[must_use]
    pub const fn bit(self) -> u64 {
        1u64 << (self as u32)
    }
}

/// What one declared profile advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloCaps {
    /// `ExtKind` bits.
    pub ext: u64,
    /// TLS 1.3 cipher suites (0x1301/0x1302/0x1303) and the GREASE slot.
    pub ciphers: u8,
    /// `SigKind` bits.
    pub sigalgs: u32,
    /// `GroupKind` bits from `supported_groups`.
    pub groups: u64,
    /// `GroupKind` bits from `key_share`.
    pub keyshare: u64,
    /// Declared legacy session-id length (32 for the TLS 1.3 default).
    pub session_id_len: u8,
}

/// A profile with no advertised extension, suite, scheme or group.
pub const EMPTY: HelloCaps = HelloCaps {
    ext: 0,
    ciphers: 0,
    sigalgs: 0,
    groups: 0,
    keyshare: 0,
    session_id_len: 0,
};

impl HelloCaps {
    /// Empty mask.
    #[must_use]
    pub const fn empty() -> Self {
        EMPTY
    }

    /// Add extension bits.
    #[must_use]
    pub const fn with_ext(mut self, bits: u64) -> Self {
        self.ext |= bits;
        self
    }

    /// Add cipher-suite bits.
    #[must_use]
    pub const fn with_ciphers(mut self, bits: u8) -> Self {
        self.ciphers |= bits;
        self
    }

    /// Add signature-scheme bits.
    #[must_use]
    pub const fn with_sigalgs(mut self, bits: u32) -> Self {
        self.sigalgs |= bits;
        self
    }

    /// Add group bits.
    #[must_use]
    pub const fn with_groups(mut self, bits: u64) -> Self {
        self.groups |= bits;
        self
    }

    /// Add `key_share` group bits.
    #[must_use]
    pub const fn with_keyshare(mut self, bits: u64) -> Self {
        self.keyshare |= bits;
        self
    }

    /// Whether the declared profile carries `kind`.
    #[must_use]
    pub const fn has_ext(self, kind: ExtKind) -> bool {
        self.ext & kind.bit() != 0
    }

    /// Whether the declared profile advertises `kind`.
    #[must_use]
    pub const fn offers_sigalg(self, kind: SigKind) -> bool {
        self.sigalgs & kind.bit() != 0
    }

    /// Whether the declared profile offers `kind`.
    #[must_use]
    pub const fn offers_group(self, kind: GroupKind) -> bool {
        self.groups & kind.bit() != 0
    }

    /// Whether the declared profile sends a `key_share` for `kind`.
    #[must_use]
    pub const fn shares_group(self, kind: GroupKind) -> bool {
        self.keyshare & kind.bit() != 0
    }

    /// Whether the declared profile advertises a TLS 1.3 AEAD suite.
    #[must_use]
    pub const fn offers_tls13_aead(self) -> bool {
        self.ciphers & 0b111 != 0
    }

    /// Whether the declared profile advertises ALPS (either codepoint).
    #[must_use]
    pub const fn has_alps(self) -> bool {
        self.has_ext(ExtKind::ApplicationSettingsOld) || self.has_ext(ExtKind::ApplicationSettings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_are_dense_and_distinct() {
        assert_eq!(ExtKind::ServerName.bit(), 1);
        assert_ne!(ExtKind::Padding.bit(), ExtKind::Alpn.bit());
        assert_eq!(
            EMPTY
                .with_ext(ExtKind::Alpn.bit())
                .with_ext(ExtKind::Padding.bit())
                .ext
                .count_ones(),
            2
        );
        assert!(
            EMPTY
                .with_sigalgs(SigKind::Ed25519.bit())
                .offers_sigalg(SigKind::Ed25519)
        );
        assert!(!EMPTY.offers_group(GroupKind::X25519));
    }
}
