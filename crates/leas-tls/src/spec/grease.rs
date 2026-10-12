//! GREASE (Generate Random Extensions And Sustain Extensibility) values.
//!
//! RFC 8701 defines GREASE values with equal high and low bytes
//! (`0x0A0A`, `0x1A1A`, ..., `0xFAFA`). Browsers sprinkle them into
//! `ClientHello`s to keep the ecosystem extensible; we mirror that.

use crate::error::TlsError;

/// The placeholder value specs write for a GREASE slot.
pub const GREASE_PLACEHOLDER: u16 = 0xCACA;

/// Returns `true` if `v` is one of the 16 RFC 8701 GREASE values.
///
/// The valid range is `0x0A0A` to `0xFAFA`; equal-byte values like `0x0000`
/// are not in it.
#[must_use]
pub const fn is_grease(v: u16) -> bool {
    (v >> 8) == (v & 0xFF) && (v & 0x0F) == 0x0A
}

/// Picks a GREASE value uniformly from the 16 valid values
/// (`0x0A0A`, `0x1A1A`, ..., `0xFAFA`).
pub fn random_grease(rng: &dyn ring::rand::SecureRandom) -> Result<u16, TlsError> {
    let mut byte = [0u8; 1];
    rng.fill(&mut byte)
        .map_err(|_| TlsError::Crypto("random grease failed".to_string()))?;
    // The low nibble indexes the 16 GREASE byte values 0x0A..0xFA.
    let b = 0x0A + (byte[0] & 0x0F) * 0x10;
    Ok((u16::from(b) << 8) | u16::from(b))
}
