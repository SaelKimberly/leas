//! `VMess` record obfuscation: Xray's `ShakeSizeParser`
//! (`proxy/vmess/encoding/auth.go:35-70`, MIT).
//!
//! With `RequestOptionChunkMasking` (`0x04`) the 2-byte record size field is
//! Calls are mixed with a `SHAKE128` keystream seeded by that direction's body IV; with
//! `RequestOptionGlobalPadding` (`0x08`) every record also carries
//! `next() % 64` **cleartext** padding bytes after the ciphertext, whose
//! length is drawn from the SAME keystream — so the length is never on the
//! wire and both peers must consume the stream in lockstep.
//!
//! Draw order per record is fixed by Go `AuthenticationWriter.seal`
//! (`common/crypto/auth.go:249-273`): padding length first, then the size
//! mask. A client that swaps them desynchronises after the first record.

use shake::{ExtendableOutput, Shake128, Shake128Reader, Update, XofReader};

/// Xray's `MaxPaddingLen` (`auth.go:68-70`).
pub const PADDING_MAX: usize = 64;

/// One direction's keystream state. `Clone` exists so a record that is
/// sealed but never reaches the wire can be rolled back — the keystream is
/// irreversible, so the only way back is a snapshot.
#[derive(Clone)]
pub struct ShakeSizeParser {
    reader: Shake128Reader,
}

impl ShakeSizeParser {
    /// Seed with that direction's body IV (Go `NewShakeSizeParser(nonce)`).
    #[must_use]
    pub fn new(seed: &[u8; 16]) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(seed);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// The next 2 keystream bytes, big-endian (Go `next()`).
    fn next(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.reader.read(&mut b);
        u16::from_be_bytes(b)
    }

    /// Padding length for the NEXT record (`next() % 64`).
    pub fn next_padding(&mut self) -> usize {
        usize::from(self.next() % 64)
    }

    /// Mask a size field (encoder side).
    pub fn encode(&mut self, size: u16) -> [u8; 2] {
        (self.next() ^ size).to_be_bytes()
    }

    /// Unmask a size field (decoder side).
    pub fn decode(&mut self, field: u16) -> u16 {
        self.next() ^ field
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent oracle: `hashlib.shake_128(seed).digest()` (OpenSSL), not a
    /// round trip through this module. Seeded with 16 x 0x11 the first two
    /// big-endian u16s are 44679 and 39250 — so the FIRST record pads by
    /// `44679 % 64 = 7` and masks 0x1234 into 0x8B66.
    #[test]
    fn keystream_matches_an_independent_shake128() {
        let mut p = ShakeSizeParser::new(&[0x11; 16]);
        let pad = p.next_padding();
        let masked = p.encode(0x1234);
        assert_eq!(pad, 7, "padding is drawn first");
        assert_eq!(masked, [0x8b, 0x66], "the mask is drawn second");
    }

    /// A swapped draw order desynchronises after the first record, so pin the
    /// second record's draws too (seed 16 x 0x5A: 16771 then 740).
    #[test]
    fn the_stream_advances_two_bytes_per_draw() {
        let mut p = ShakeSizeParser::new(&[0x5a; 16]);
        assert_eq!(p.next_padding(), 16771 % 64);
        assert_eq!(p.encode(0), 740u16.to_be_bytes());
    }

    #[test]
    fn decode_inverts_encode_over_a_stream() {
        let seed = [0x77u8; 16];
        let mut enc = ShakeSizeParser::new(&seed);
        let mut dec = ShakeSizeParser::new(&seed);
        for size in [0u16, 16, 1024, 65_535] {
            let pad_enc = enc.next_padding();
            let field = enc.encode(size);
            let pad_dec = dec.next_padding();
            assert_eq!(pad_enc, pad_dec);
            assert_eq!(dec.decode(u16::from_be_bytes(field)), size);
        }
    }
}
