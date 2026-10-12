use std::{ops::Range, str::FromStr};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum PortDecl {
    Single(u16),
    Range(Range<u16>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    ports: Vec<PortDecl>,
    total: usize,
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, p) in self.ports.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            match p {
                PortDecl::Single(p) => f.write_str(p.to_string().as_ref())?,
                PortDecl::Range(Range { start, end }) => {
                    f.write_str(start.to_string().as_ref())?;
                    f.write_str("-")?;
                    f.write_str(end.to_string().as_ref())?;
                }
            }
        }
        Ok(())
    }
}

impl PortSpec {
    /// Upper bound on the ports one spec may represent. A share URL is one
    /// line of untrusted input; without a cap `hysteria2://h:1-65535` expands to
    /// a 65 536-entry list in memory and in the store (finding f15).
    pub const MAX_PORTS: u16 = 4096;

    pub const fn new() -> Self {
        Self {
            ports: Vec::new(),
            total: 0,
        }
    }
    pub fn new_with(port: u16) -> Self {
        Self {
            ports: vec![PortDecl::Single(port)],
            total: 1,
        }
    }

    pub fn add(&mut self, port: u16) -> bool {
        if self.total >= usize::from(Self::MAX_PORTS) {
            return false; // port budget exhausted — refuse to grow further
        }
        for decl in &self.ports {
            match decl {
                &PortDecl::Single(p) if p == port => return false,
                PortDecl::Range(r) if r.contains(&port) => return false,
                _ => {}
            }
        }

        self.ports.push(PortDecl::Single(port));
        self.total += 1;
        true
    }
    pub fn add_range(&mut self, range: Range<u16>) {
        // `end` is inclusive, so a range is empty only when it descends
        // (`"2000-1000"`). The old arithmetic `end - start` underflowed on that
        // input — panicking in debug, persisting an inconsistent spec in release
        // (finding f14). A descending range contributes nothing, so the caller's
        // empty-spec check rejects the URL.
        if range.start > range.end {
            return;
        }
        // Bound one range's contribution so an absurd span cannot expand into a
        // 65 536-entry list (finding f15).
        if usize::from(range.end) - usize::from(range.start) + 1 > usize::from(Self::MAX_PORTS) {
            return;
        }
        // Coalesce every decl that touches the new range into one span: ranges whose
        // port sets intersect it (end-inclusive touch, so a boundary port shared with
        // an adjacent range counts) and singles inside it are all removed and re-added
        // as a single merged range.
        let mut new_start = range.start;
        let mut new_end = range.end;
        let mut removed_len = 0usize;
        self.ports.retain_mut(|decl| match decl {
            &mut PortDecl::Single(p) if range.contains(&p) => {
                removed_len += 1;
                new_start = new_start.min(p);
                new_end = new_end.max(p);
                false
            }
            PortDecl::Range(r) if r.start <= range.end && r.end >= range.start => {
                removed_len += (usize::from(r.end) - usize::from(r.start)).saturating_add(1);
                new_start = new_start.min(r.start);
                new_end = new_end.max(r.end);
                false
            }
            _ => true,
        });
        self.total = self.total.saturating_sub(removed_len);
        // Range<u16> end is inclusive here: (end - start + 1) ports.
        self.total = self
            .total
            .saturating_add(usize::from(new_end) - usize::from(new_start) + 1);
        self.ports.push(PortDecl::Range(new_start..new_end));
    }

    pub const fn contains(&self, port: u16) -> bool {
        let arr = self.ports.as_slice();
        let mut idx = 0;
        while idx < arr.len() {
            match &arr[idx] {
                PortDecl::Single(p) if *p == port => return true,
                PortDecl::Range(r) if r.start <= port && port <= r.end => return true,
                _ => {}
            }
            idx += 1;
        }
        false
    }

    pub const fn length(&self) -> usize {
        let mut length = 0_usize;
        let mut idx = 0;
        let arr = self.ports.as_slice();
        while idx < arr.len() {
            match &arr[idx] {
                PortDecl::Single(_) => length += 1,
                PortDecl::Range(r) => {
                    let range_len = (r.end as u32 - r.start as u32 + 1) as usize;
                    length += range_len;
                }
            }
            idx += 1;
        }
        length
    }

    /// Get the first port
    pub const fn first(&self) -> Option<u16> {
        match *self.ports.as_slice() {
            [PortDecl::Single(p), ..] => Some(p),
            [PortDecl::Range(Range { start, .. }), ..] => Some(start),
            _ => None,
        }
    }

    /// Get the last port
    pub const fn last(&self) -> Option<u16> {
        match *self.ports.as_slice() {
            [.., PortDecl::Single(p)] => Some(p),
            [.., PortDecl::Range(Range { end, .. })] => Some(end),
            _ => None,
        }
    }

    pub fn sort(mut self) -> Self {
        self.ports.sort_by_key(|p| match p {
            PortDecl::Single(p) => *p,
            PortDecl::Range(r) => r.start,
        });
        self
    }

    pub fn iter(&self) -> impl Iterator<Item = u16> {
        PortSpecIter {
            spec: self,
            outer_idx: 0,
            inner_idx: 0,
        }
    }

    pub fn iter_raw(&self) -> impl Iterator<Item = &PortDecl> {
        self.ports.iter()
    }
}

impl FromStr for PortSpec {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut spec = Self::new();

        for decl in s.split(',') {
            if let Some((s, e)) = decl.split_once('-') {
                spec.add_range(s.parse()?..e.parse()?);
            } else {
                spec.add(decl.parse()?);
            }
        }
        Ok(spec.sort())
    }
}

struct PortSpecIter<'a> {
    spec: &'a PortSpec,
    outer_idx: usize,
    inner_idx: u32,
}

impl Iterator for PortSpecIter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        match self.spec.ports.get(self.outer_idx)? {
            PortDecl::Single(port) => {
                self.outer_idx += 1;
                Some(*port)
            }
            PortDecl::Range(r) => {
                let port = u32::from(r.start) + self.inner_idx;
                if port <= u32::from(r.end) {
                    self.inner_idx += 1;
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "port <= r.end <= u16::MAX by this branch"
                    )]
                    let port = port as u16;
                    Some(port)
                } else {
                    self.outer_idx += 1;
                    self.inner_idx = 0;
                    self.next()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_port_spec_contains_no_panic() {
        let spec = PortSpec::new();
        assert!(!spec.contains(80));
        assert_eq!(spec.length(), 0);
        assert!(spec.first().is_none());
        assert!(spec.last().is_none());
    }

    #[test]
    fn port_spec_range_inclusive_semantics() {
        let mut spec = PortSpec::new();
        spec.add_range(100..200);
        assert!(spec.contains(100)); // start
        assert!(spec.contains(200)); // end (was failing with exclusive)
        assert!(!spec.contains(99)); // below
        assert!(!spec.contains(201)); // above
        assert_eq!(spec.length(), 101);
        let collected: Vec<u16> = spec.iter().collect();
        assert_eq!(collected.len(), 101);
        assert_eq!(collected[0], 100);
        assert_eq!(collected[100], 200);
    }

    #[test]
    fn oversized_range_is_refused_by_the_port_budget() {
        // One untrusted URL line must not expand into a 65 536-entry port
        // list in memory and in the store (finding f15): an over-budget span
        // is refused, leaving the spec empty.
        let mut spec = PortSpec::new();
        spec.add_range(1..65535);
        assert_eq!(spec.length(), 0, "over-budget range must be refused");
        assert!(spec.iter().next().is_none());
        assert!(spec.first().is_none());

        // At exactly the budget the range is accepted.
        let mut ok = PortSpec::new();
        ok.add_range(1..PortSpec::MAX_PORTS);
        assert_eq!(ok.length(), usize::from(PortSpec::MAX_PORTS));
        assert_eq!(ok.iter().count(), usize::from(PortSpec::MAX_PORTS));
    }

    #[test]
    fn descending_range_contributes_nothing() {
        // "2000-1000": the old `end - start` underflowed (panic in debug,
        // inconsistent spec in release; finding f14). Built as a struct literal
        // so the intent survives `clippy::reversed_empty_ranges`.
        let mut spec = PortSpec::new();
        spec.add_range(std::ops::Range {
            start: 2000,
            end: 1000,
        });
        assert_eq!(spec.length(), 0);
        assert!(spec.first().is_none());

        // Through the public parse path too: an empty spec lets the caller
        // reject the URL rather than persisting port=start with no ports.
        let parsed: PortSpec = "2000-1000".parse().expect("parse must not panic");
        assert!(parsed.first().is_none());
        // A valid range still parses (end-inclusive: 1000..=2000).
        let ok: PortSpec = "1000-2000".parse().expect("parse");
        assert_eq!(ok.length(), 1001);
        assert_eq!(ok.first(), Some(1000));
    }

    #[test]
    fn add_range_coalesces_overlapping_decls() {
        let mut spec = PortSpec::new();
        spec.add_range(10..20);
        spec.add_range(30..40);
        spec.add_range(15..35);
        assert_eq!(spec.length(), 31, "10..=40 is 31 ports, no duplicates");
        assert_eq!(spec.total, 31, "total must match length");
        let mut all: Vec<u16> = spec.iter().collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 31);
        assert_eq!(all.first(), Some(&10));
        assert_eq!(*all.last().unwrap(), 40);
    }

    #[test]
    fn add_range_contained_range_preserves_total() {
        let mut spec = PortSpec::new();
        spec.add_range(1..10);
        spec.add_range(3..5);
        assert_eq!(spec.length(), 10);
        assert_eq!(spec.total, 10);
        assert_eq!(spec.iter().count(), 10);
        assert!(spec.contains(3));
        assert!(spec.contains(5));
        assert!(spec.contains(10));
    }

    #[test]
    fn add_range_coalesces_boundary_touching_ranges() {
        // Low range added first, then higher range sharing the boundary port.
        let mut a = PortSpec::new();
        a.add_range(20..30);
        a.add_range(30..40);
        assert_eq!(a.length(), 21, "20..=40 is 21 ports");
        assert_eq!(a.total, 21);
        assert_eq!(a.iter().count(), 21);
        assert_eq!(
            a.iter().filter(|&p| p == 30).count(),
            1,
            "shared port yielded once"
        );
        assert_eq!(a.iter_raw().count(), 1, "one coalesced span");

        // Higher range added first, then lower range touching at the shared port
        // (this order slipped through the old half-open predicate).
        let mut b = PortSpec::new();
        b.add_range(30..40);
        b.add_range(20..30);
        assert_eq!(b.length(), 21);
        assert_eq!(b.total, 21);
        assert_eq!(b.iter().count(), 21);
        assert_eq!(b.iter().filter(|&p| p == 30).count(), 1);
        assert_eq!(b.iter_raw().count(), 1);
    }

    #[test]
    fn full_u16_range_is_refused_and_iterator_never_wraps() {
        // The full u16 span would expand to a 65 536-entry list; the port
        // budget refuses it (finding f15).
        let mut refused = PortSpec::new();
        refused.add_range(0..65535);
        assert_eq!(refused.length(), 0);

        // Within the budget, a range still enumerates exactly start..=end
        // once (the iterator must not wrap at a boundary).
        let mut spec = PortSpec::new();
        spec.add_range(0..(PortSpec::MAX_PORTS - 1));
        assert_eq!(spec.length(), usize::from(PortSpec::MAX_PORTS));
        let all: Vec<u16> = spec.iter().collect();
        assert_eq!(all.len(), usize::from(PortSpec::MAX_PORTS));
        assert_eq!(all[0], 0);
        assert_eq!(*all.last().unwrap(), PortSpec::MAX_PORTS - 1);
    }
}
