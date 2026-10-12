const ACCEPT: usize = 12;
const REJECT: usize = 0;

/// SAFETY: The decode below function relies on the correctness of these
/// equivalence classes.
#[rustfmt::skip]
const CLASSES: [u8; 256] = [
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
   7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
   8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  10,3,3,3,3,3,3,3,3,3,3,3,3,4,3,3, 11,6,6,6,5,8,8,8,8,8,8,8,8,8,8,8,
];

/// SAFETY: The decode below function relies on the correctness of this state
/// machine.
#[rustfmt::skip]
const STATES_FORWARD: [u8; 108] = [
  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,
  12, 0,  24, 36, 60, 96, 84, 0,  0, 0,  48, 72,
  0,  12, 0,  0,  0,  0,  0,  12, 0, 12, 0,  0,
  0,  24, 0,  0,  0,  0,  0,  24, 0, 24, 0,  0,
  0,  0,  0,  0,  0,  0,  0,  24, 0, 0,  0,  0,
  0,  24, 0,  0,  0,  0,  0,  0,  0, 24, 0,  0,
  0,  0,  0,  0,  0,  0,  0,  36, 0, 36, 0,  0,
  0,  36, 0,  0,  0,  0,  0,  36, 0, 36, 0,  0,
  0,  36, 0,  0,  0,  0,  0,  0,  0, 0,  0,  0,
];
const fn decode_step(state: &mut usize, cp: &mut u32, b: u8) {
    let class = CLASSES[b as usize];
    let b = b as u32;
    if *state == ACCEPT {
        *cp = (0xFF >> class) & b;
    } else {
        *cp = (b & 0b0011_1111) | (*cp << 6);
    }
    *state = STATES_FORWARD[*state + class as usize] as usize;
}

/// Decode a single character from the given slice.
const fn decode(slice: &[u8]) -> (Option<char>, usize) {
    match slice {
        [] => return (None, 0),

        &[
            b'%',
            c1 @ (b'A'..=b'F' | b'a'..=b'f' | b'0'..=b'9'),
            c2 @ (b'A'..=b'F' | b'a'..=b'f' | b'0'..=b'9'),
            ..,
        ] => {
            let c1 = match c1 {
                b'A'..=b'F' => c1 - const { b'A' - 10 },
                b'a'..=b'f' => c1 - const { b'a' - 10 },
                _ => c1 - b'0',
            };
            let c2 = match c2 {
                b'A'..=b'F' => c2 - const { b'A' - 10 },
                b'a'..=b'f' => c2 - const { b'a' - 10 },
                _ => c2 - b'0',
            };
            let c = (c1 << 4) | c2;
            return (Some(c as char), 3);
        }
        &[c @ ..0x80, ..] => {
            return (Some(c as char), 1);
        }
        _ => (),
    }

    let (mut state, mut cp, mut i) = (ACCEPT, 0, 0);
    loop {
        if i == slice.len() {
            break;
        }
        decode_step(&mut state, &mut cp, slice[i]);
        i += 1;

        if state == ACCEPT {
            // SAFETY: This is safe because `decode_step` guarantees that
            // `cp` is a valid Unicode scalar value in an ACCEPT state.
            let ch = unsafe { char::from_u32_unchecked(cp) };
            return (Some(ch), i);
        } else if state == REJECT {
            // At this point, we always want to advance at least one byte.
            return match i.saturating_sub(1) {
                0 => (None, 1),
                n => (None, n),
            };
        }
    }
    (None, i)
}
const fn char_advance(slice: &mut &[u8], state: &mut usize) -> Option<char> {
    let (ch, n) = decode(slice);
    if let Some(c) = ch {
        *slice = unsafe { core::slice::from_raw_parts(slice.as_ptr().add(n), slice.len() - n) };
        *state += n;
        Some(c)
    } else {
        // Consume the bytes decode examined even when it rejects: a
        // truncated multibyte tail (raw cut mid-sequence) must yield the
        // remaining chars, not wedge the iterator returning None forever.
        if n > 0 {
            *slice = unsafe { core::slice::from_raw_parts(slice.as_ptr().add(n), slice.len() - n) };
            *state += n;
        }
        None
    }
}
#[cfg_attr(test, derive(Debug))]
pub(super) struct AutoChars<'a> {
    slice: &'a [u8],
    last_e: usize,
}

impl AutoChars<'_> {
    pub(super) const fn next(&mut self) -> Option<char> {
        char_advance(&mut self.slice, &mut self.last_e)
    }
}
impl<'a> AutoChars<'a> {
    pub(super) const fn new(slice: &'a [u8]) -> Self {
        Self { slice, last_e: 0 }
    }
    pub const fn remaining(&self) -> &'a [u8] {
        self.slice
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_auto_chars() {
        use super::AutoChars;

        // Test percent-decoding
        let mut ac = AutoChars::new(b"%A5abc");
        assert_eq!(ac.next(), Some('¥'));
        assert_eq!(ac.next(), Some('a'));
        assert_eq!(ac.next(), Some('b'));
        assert_eq!(ac.next(), Some('c'));
        assert_eq!(ac.next(), None);
        assert!(ac.remaining().is_empty());

        // Test raw bytes
        let mut ac = AutoChars::new(b"hello");
        assert_eq!(ac.next(), Some('h'));
        assert_eq!(ac.next(), Some('e'));
        assert_eq!(ac.remaining(), b"llo");

        // Test invalid percent treated as literal
        let mut ac = AutoChars::new(b"%XY");
        assert_eq!(ac.next(), Some('%'));

        // Test truncated percent
        let mut ac = AutoChars::new(b"%A");
        assert_eq!(ac.next(), Some('%'));

        // Test empty
        let mut ac = AutoChars::new(b"");
        assert_eq!(ac.next(), None);
        assert!(ac.remaining().is_empty());

        // Truncated multibyte tail: the sequence can never complete, so the
        // bytes are consumed (with one replacement char surfaced by callers
        // mapping None+remaining to invalid) and iteration terminates — a
        // stuck iterator would spin any retry loop forever.
        let mut ac = AutoChars::new(b"ok\xF0\x9F");
        assert_eq!(ac.next(), Some('o'));
        assert_eq!(ac.next(), Some('k'));
        assert_eq!(ac.next(), None);
        assert!(ac.remaining().is_empty(), "truncated tail must be consumed");
    }

    /// Exhaustion fuzz: for EVERY 1..=4-byte truncated prefix of a multibyte
    /// sequence, iteration must terminate with an empty remainder — a prefix
    /// that made `AutoChars` return `None` without consuming would spin any
    /// retry loop forever. Also asserts the remainder shrinks monotonically.
    #[test]
    fn auto_chars_terminates_on_every_truncated_prefix() {
        use super::AutoChars;

        let leads = 0xC2_u8..=0xF4;
        let conts = [0x80_u8, 0x90, 0xA0, 0xBF];
        for lead in leads {
            for len in 1..=4_usize {
                // Build every prefix shape: lead alone, lead + conts, lead +
                // mixed cont/ascii, lead + conts + truncated continuation.
                for &c1 in &conts {
                    for &c2 in std::iter::once(&0x80_u8).chain(&conts) {
                        let mut bytes = vec![lead, c1, c2];
                        bytes.truncate(len.min(3));
                        if len == 4 {
                            bytes.push(0x80);
                        }
                        let mut ac = AutoChars::new(&bytes);
                        let mut prev_len = bytes.len();
                        let mut steps = 0;
                        // Drain contract: next() must eventually consume every
                        // byte — advance may pause (None with bytes left, a
                        // hard-invalid tail), but remaining() must shrink every
                        // call until empty. An advance==0 None here is the wedge
                        // shape this test exists to forbid.
                        while !ac.remaining().is_empty() {
                            let _ = ac.next();
                            steps += 1;
                            assert!(
                                steps <= bytes.len(),
                                "drain exceeded byte count for {bytes:?}"
                            );
                            let rem = ac.remaining().len();
                            assert!(rem < prev_len, "remainder must shrink for {bytes:?}");
                            prev_len = rem;
                        }
                    }
                }
            }
        }
    }
}
