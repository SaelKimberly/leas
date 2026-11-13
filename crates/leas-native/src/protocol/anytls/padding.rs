//! `AnyTLS` padding scheme.
//!
//! The scheme is a small text table the server can replace at runtime
//! (`cmdUpdatePaddingScheme`). Its shape, taken verbatim from
//! `thirdparty/anytls-go/proxy/padding/padding.go`:
//!
//! ```text
//! stop=8
//! 0=30-30
//! 1=100-400
//! ...
//! ```
//!
//! `stop` is the number of writes padding applies to (packets `0..stop`);
//! per-packet rows are comma-separated `min-max` ranges, or `c` — the check
//! mark: if no user payload remains, stop emitting the rest of the row.
//! Ranges are half-open (`[min, max)`, exactly the reference's
//! `rand.Int(max-min)+min`), and a length is the TLS plaintext size of one
//! write.
//!
//! `padding0` (packet 0) is special: it is the length that trails the
//! authentication hash before the session loop starts, so it is the first
//! range of row `0`.

use std::collections::HashMap;

use md5::{Digest, Md5};

use crate::rand;

/// The stock scheme every client starts with.
pub const DEFAULT_SCHEME: &[u8] = b"stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

/// One resolved row step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Emit a write of this plaintext size (payload first, then `cmdWaste`).
    Size(usize),
    /// Stop the row early when no payload remains.
    Check,
}

/// A parsed padding scheme.
#[derive(Debug, Clone)]
pub struct PaddingScheme {
    md5_hex: String,
    stop: u32,
    rows: HashMap<u32, Vec<Range>>,
}

#[derive(Debug, Clone, Copy)]
enum Range {
    MinMax(u16, u16),
    Check,
}

impl PaddingScheme {
    /// The process-wide default scheme.
    #[must_use]
    pub fn default_scheme() -> &'static Self {
        static DEFAULT: std::sync::LazyLock<PaddingScheme> = std::sync::LazyLock::new(|| {
            PaddingScheme::parse(DEFAULT_SCHEME).expect("the built-in AnyTLS padding scheme parses")
        });
        &DEFAULT
    }

    /// Parse a server-supplied scheme. `None` when it has no usable `stop`
    /// (the reference rejects the update) — an unparseable scheme must never
    /// replace a working one.
    #[must_use]
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut stop = None;
        let mut rows = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            if key == "stop" {
                stop = Some(value.trim().parse::<u32>().ok()?);
                continue;
            }
            let Some(packet) = key.parse::<u32>().ok() else {
                continue;
            };
            let mut steps = Vec::new();
            for part in value.split(',') {
                let part = part.trim();
                if part == "c" {
                    steps.push(Range::Check);
                    continue;
                }
                let Some((lo, hi)) = part.split_once('-') else {
                    continue;
                };
                let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) else {
                    continue;
                };
                let (lo, hi) = (lo.min(hi), lo.max(hi));
                if lo == 0 {
                    continue;
                }
                steps.push(Range::MinMax(lo, hi));
            }
            rows.insert(packet, steps);
        }
        let stop = stop?;
        Some(Self {
            md5_hex: hex_md5(raw),
            stop,
            rows,
        })
    }

    /// Lowercase hex md5 of [`Self::raw`] — the `padding-md5` settings value.
    #[must_use]
    pub fn md5_hex(&self) -> &str {
        &self.md5_hex
    }

    /// How many writes padding applies to (`pkt < stop`).
    #[must_use]
    pub const fn stop(&self) -> u32 {
        self.stop
    }

    /// The padding0 length (the first solved step of row 0), or 0 when the
    /// scheme does not pad the authentication write.
    #[must_use]
    pub fn padding0_len(&self) -> usize {
        self.draw(0)
            .into_iter()
            .find_map(|step| match step {
                Step::Size(size) => Some(size),
                Step::Check => None,
            })
            .unwrap_or(0)
    }

    /// Resolve the row for packet `pkt` into concrete write sizes.
    ///
    /// Ranges are drawn fresh on every call; `c` marks are preserved in
    /// position so the writer can stop at the right point. An absent row
    /// draws nothing (the reference sends the write unpadded).
    #[must_use]
    pub fn draw(&self, pkt: u32) -> Vec<Step> {
        let Some(row) = self.rows.get(&pkt) else {
            return Vec::new();
        };
        row.iter()
            .map(|range| match *range {
                Range::Check => Step::Check,
                Range::MinMax(lo, hi) => {
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "a drawn size is within a u16 range by construction"
                    )]
                    let size = if lo == hi {
                        usize::from(lo)
                    } else {
                        // Half-open `[lo, hi)`: `hi > lo` here.
                        let span = u32::from(hi - lo);
                        usize::from(lo) + rand::u32_below(span) as usize
                    };
                    Step::Size(size)
                }
            })
            .collect()
    }
}

/// Lowercase hex md5 of `bytes`.
fn hex_md5(bytes: &[u8]) -> String {
    let digest = Md5::digest(bytes);
    let mut out = String::with_capacity(32);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_matches_the_reference_digest() {
        let scheme = PaddingScheme::default_scheme();
        assert_eq!(scheme.stop(), 8);
        assert_eq!(scheme.md5_hex(), "75cff2ad89aadf5e257059ee571ebe11");
        // Exact-row draw is deterministic and equals the declared size.
        assert_eq!(scheme.draw(0), vec![Step::Size(30)]);
        // padding0 is the authentication trailer length.
        assert_eq!(scheme.padding0_len(), 30);
    }

    #[test]
    fn draw_keeps_check_marks_and_range_bounds() {
        let scheme = PaddingScheme::default_scheme();
        let row2 = scheme.draw(2);
        assert_eq!(row2.len(), 9);
        assert_eq!(row2[1], Step::Check);
        assert_eq!(row2[3], Step::Check);
        for step in &row2 {
            if let Step::Size(size) = step {
                assert!((*size == 0) || (400..1000).contains(size), "{size}");
            }
        }
        // Row 1 is one random size in [100, 400).
        match scheme.draw(1).as_slice() {
            [Step::Size(size)] => assert!((100..400).contains(size), "{size}"),
            other => panic!("unexpected row 1: {other:?}"),
        }
        // Beyond `stop` there is no row.
        assert_eq!(scheme.draw(8), Vec::new());
    }

    #[test]
    fn parse_rejects_a_scheme_without_stop_and_ignores_bad_rows() {
        assert!(PaddingScheme::parse(b"0=30-30").is_none());
        assert!(PaddingScheme::parse(b"stop=x").is_none());
        let scheme = PaddingScheme::parse(b"stop=2\n0=30-30\n1=bogus,50-40\n").expect("parses");
        assert_eq!(scheme.stop(), 2);
        // `50-40` is clamped to `40-50` (the reference normalises the pair).
        match scheme.draw(1).as_slice() {
            [Step::Size(size)] => assert!((40..50).contains(size), "{size}"),
            other => panic!("unexpected row 1: {other:?}"),
        }
    }
}
