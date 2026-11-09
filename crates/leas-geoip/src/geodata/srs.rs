//! sing-box binary rule-sets (`.srs`).
//!
//! Layout: `"SRS" | version(u8) | zlib( uvarint(count) | rule* )`. A rule is a
//! type byte (0 = default, 1 = logical) followed by typed items until
//! `0xFF | invert(u8)`.
//!
//! Only items that a proxy client can evaluate are accepted; anything else
//! (process names, Wi-Fi SSIDs, package names…) is refused instead of being
//! silently ignored, so a rule never matches more traffic than its author
//! intended.

use std::io::{BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{Context as _, anyhow, bail};
use flate2::read::ZlibDecoder;

const MAGIC: &[u8; 3] = b"SRS";
const MAX_VERSION: u8 = 5;
const MAX_DEPTH: usize = 32;
const MAX_RULES: u64 = 1 << 20;
const MAX_ITEMS: u64 = 1 << 24;

/// A loaded rule-set; it matches when any of its rules matches.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    /// Top-level rules, OR'ed.
    pub rules: Vec<Rule>,
}

/// One rule of a rule-set.
#[derive(Clone, Debug)]
pub enum Rule {
    /// A plain rule.
    Default(Box<DefaultRule>),
    /// `and` / `or` over nested rules, optionally inverted.
    Logical {
        /// `true` = and, `false` = or.
        and: bool,
        /// Nested rules.
        rules: Vec<Self>,
        /// Negate the result.
        invert: bool,
    },
}

/// A plain rule's conditions. Destination domain/CIDR items are one OR group;
/// every other group (source, ports, network) is `ANDed`.
#[derive(Clone, Debug, Default)]
pub struct DefaultRule {
    /// Destination domains (exact + suffix) in one succinct set.
    pub domains: Option<DomainSet>,
    /// Destination substrings.
    pub keywords: Vec<String>,
    /// Destination regexes.
    pub regexes: Vec<String>,
    /// Destination address ranges.
    pub ips: Vec<GeoRange>,
    /// Source address ranges.
    pub source_ips: Vec<GeoRange>,
    /// Destination ports.
    pub ports: Vec<(u16, u16)>,
    /// Source ports.
    pub source_ports: Vec<(u16, u16)>,
    /// Transport mask.
    pub network: Option<Networks>,
    /// Negate the whole rule.
    pub invert: bool,
}

/// Transport mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Networks {
    /// TCP flag.
    pub tcp: bool,
    /// UDP flag.
    pub udp: bool,
}

/// One inclusive address range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoRange {
    /// First address in the range.
    pub from: IpAddr,
    /// Last address in the range.
    pub to: IpAddr,
}

/// Loads one `.srs` file.
///
/// # Errors
/// I/O, bad magic/version, zlib, malformed item, or unsupported item errors.
pub fn load_rule_set(path: &Path) -> anyhow::Result<RuleSet> {
    let file =
        std::fs::File::open(path).with_context(|| format!("rule-set: open {}", path.display()))?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut magic = [0u8; 3];
    reader
        .read_exact(&mut magic)
        .with_context(|| format!("rule-set: {}", path.display()))?;
    if &magic != MAGIC {
        bail!(
            "{}: not a sing-box binary rule-set (bad magic)",
            path.display()
        );
    }
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] == 0 || version[0] > MAX_VERSION {
        bail!(
            "{}: unsupported rule-set version {}",
            path.display(),
            version[0]
        );
    }
    let mut decoder = ZlibDecoder::new(reader);
    let count =
        read_uvarint(&mut decoder).with_context(|| format!("rule-set: {}", path.display()))?;
    if count > MAX_RULES {
        bail!("{}: rule count {count} exceeds the cap", path.display());
    }
    let mut rules = Vec::with_capacity(usize::try_from(count)?);
    for index in 0..count {
        let rule = read_rule(&mut decoder, 0)
            .with_context(|| format!("{}: rule[{index}]", path.display()))?;
        rules.push(rule);
    }
    Ok(RuleSet { rules })
}

fn read_rule<R: Read>(reader: &mut R, depth: usize) -> anyhow::Result<Rule> {
    if depth > MAX_DEPTH {
        bail!("logical rules nested deeper than {MAX_DEPTH}");
    }
    match read_u8(reader)? {
        0 => Ok(Rule::Default(Box::new(read_default(reader)?))),
        1 => {
            let and = match read_u8(reader)? {
                0 => true,
                1 => false,
                mode => bail!("unknown logical mode {mode}"),
            };
            let count = read_uvarint(reader)?;
            if count > MAX_RULES {
                bail!("logical rule child count {count} exceeds the cap");
            }
            let mut rules = Vec::with_capacity(usize::try_from(count)?);
            for _ in 0..count {
                rules.push(read_rule(reader, depth + 1)?);
            }
            let invert = read_u8(reader)? != 0;
            Ok(Rule::Logical { and, rules, invert })
        }
        kind => bail!("unknown rule type {kind}"),
    }
}

fn read_default<R: Read>(reader: &mut R) -> anyhow::Result<DefaultRule> {
    let mut rule = DefaultRule::default();
    loop {
        match read_u8(reader)? {
            1 => {
                for token in read_strings(reader)? {
                    match token.as_str() {
                        "tcp" => {
                            rule.network
                                .get_or_insert(Networks {
                                    tcp: true,
                                    udp: false,
                                })
                                .tcp = true;
                        }
                        "udp" => {
                            rule.network
                                .get_or_insert(Networks {
                                    tcp: false,
                                    udp: false,
                                })
                                .udp = true;
                        }
                        other => bail!("unknown network {other:?}"),
                    }
                }
            }
            2 => rule.domains = Some(DomainSet::read(reader)?),
            3 => rule.keywords.extend(
                read_strings(reader)?
                    .into_iter()
                    .map(|s| s.to_ascii_lowercase()),
            ),
            4 => rule.regexes.extend(read_strings(reader)?),
            5 => rule.source_ips.extend(read_ip_set(reader)?),
            6 => rule.ips.extend(read_ip_set(reader)?),
            7 => rule
                .source_ports
                .extend(read_u16s(reader)?.into_iter().map(|p| (p, p))),
            8 => {
                for token in read_strings(reader)? {
                    rule.source_ports.push(parse_port_range(&token)?);
                }
            }
            9 => rule
                .ports
                .extend(read_u16s(reader)?.into_iter().map(|p| (p, p))),
            10 => {
                for token in read_strings(reader)? {
                    rule.ports.push(parse_port_range(&token)?);
                }
            }
            // `0xFF` terminates the item list; its byte is the invert flag.
            0xFF => {
                rule.invert = read_u8(reader)? != 0;
                return Ok(rule);
            }
            item => bail!("unsupported rule-set item {} ({})", item, item_name(item)),
        }
    }
}

const fn item_name(item: u8) -> &'static str {
    match item {
        0 => "query_type",
        11 | 12 | 17 => "process_name/path",
        13 | 23 => "package_name",
        14 => "wifi_ssid",
        15 => "wifi_bssid",
        16 => "adguard_domain",
        18 => "network_type",
        19 => "network_is_expensive",
        20 => "network_is_constrained",
        21 => "network_interface_address",
        22 => "default_interface_address",
        _ => "unknown",
    }
}

fn parse_port_range(token: &str) -> anyhow::Result<(u16, u16)> {
    let bad = || anyhow!("invalid port range {token:?}");
    let (start, end) = token.split_once(':').ok_or_else(bad)?;
    let start = if start.is_empty() {
        0
    } else {
        start.parse().map_err(|_| bad())?
    };
    let end = if end.is_empty() {
        u16::MAX
    } else {
        end.parse().map_err(|_| bad())?
    };
    if start > end {
        bail!("inverted port range {token:?}");
    }
    Ok((start, end))
}

fn read_u8<R: Read>(reader: &mut R) -> anyhow::Result<u8> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn read_uvarint<R: Read>(reader: &mut R) -> anyhow::Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        if shift >= 64 {
            bail!("rule-set: varint overflow");
        }
        let byte = read_u8(reader)?;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn read_strings<R: Read>(reader: &mut R) -> anyhow::Result<Vec<String>> {
    let count = read_uvarint(reader)?;
    if count > MAX_ITEMS {
        bail!("rule-set: string list of {count} exceeds the cap");
    }
    let mut out = Vec::with_capacity(usize::try_from(count)?);
    for _ in 0..count {
        out.push(read_string(reader)?);
    }
    Ok(out)
}

fn read_string<R: Read>(reader: &mut R) -> anyhow::Result<String> {
    let len = read_uvarint(reader)?;
    if len > MAX_ITEMS {
        bail!("rule-set: string of {len} bytes exceeds the cap");
    }
    let mut bytes = vec![0u8; usize::try_from(len)?];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|e| anyhow!("rule-set: invalid UTF-8: {e}"))
}

fn read_u16s<R: Read>(reader: &mut R) -> anyhow::Result<Vec<u16>> {
    let count = read_uvarint(reader)?;
    if count > MAX_ITEMS {
        bail!("rule-set: port list of {count} exceeds the cap");
    }
    let mut out = Vec::with_capacity(usize::try_from(count)?);
    for _ in 0..count {
        let mut bytes = [0u8; 2];
        reader.read_exact(&mut bytes)?;
        out.push(u16::from_be_bytes(bytes));
    }
    Ok(out)
}

fn read_address<R: Read>(reader: &mut R) -> anyhow::Result<IpAddr> {
    match read_uvarint(reader)? {
        4 => {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes)?;
            Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        16 => {
            let mut bytes = [0u8; 16];
            reader.read_exact(&mut bytes)?;
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        len => bail!("rule-set: bad address length {len}"),
    }
}

fn read_ip_set<R: Read>(reader: &mut R) -> anyhow::Result<Vec<GeoRange>> {
    if read_u8(reader)? != 1 {
        bail!("rule-set: unsupported ip-set version");
    }
    let mut count = [0u8; 8];
    reader.read_exact(&mut count)?;
    let count = u64::from_be_bytes(count);
    if count > MAX_ITEMS {
        bail!("rule-set: ip set of {count} ranges exceeds the cap");
    }
    let mut out = Vec::with_capacity(usize::try_from(count)?);
    for _ in 0..count {
        let from = read_address(reader)?;
        let to = read_address(reader)?;
        if from.is_ipv4() != to.is_ipv4() {
            bail!("rule-set: ip range mixes address families");
        }
        out.push(GeoRange { from, to });
    }
    Ok(out)
}

// ── Domain set (decoded from sing-box's compact reversed trie) ─────────

const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

/// A static set of domain keys decoded from the on-disk trie: exact entries,
/// plus suffixes (self + subdomains) and subdomain-only prefixes.
#[derive(Clone, Debug, Default)]
pub struct DomainSet {
    exact: KeySet,
    self_suffix: KeySet,
    sub_suffix: KeySet,
}

/// Sorted keys concatenated into one blob; `ends[i]` is the end offset of
/// key `i`. One allocation, no per-key `String`.
#[derive(Clone, Debug, Default)]
struct KeySet {
    blob: String,
    ends: Vec<u32>,
}

impl KeySet {
    fn new(mut keys: Vec<String>) -> Self {
        keys.sort_unstable();
        keys.dedup();
        let mut blob = String::new();
        let mut ends = Vec::with_capacity(keys.len());
        for key in keys {
            blob.push_str(&key);
            ends.push(u32::try_from(blob.len()).unwrap_or(u32::MAX));
        }
        Self { blob, ends }
    }

    fn at(&self, index: usize) -> &str {
        let start = if index == 0 {
            0
        } else {
            self.ends[index - 1] as usize
        };
        &self.blob[start..self.ends[index] as usize]
    }

    fn contains(&self, key: &str) -> bool {
        let (mut low, mut high) = (0usize, self.ends.len());
        while low < high {
            let mid = low.midpoint(high);
            match self.at(mid).cmp(key) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    /// Whether `host` or any parent label (when `allow_self`) is a key.
    fn suffix_hit(&self, host: &str, allow_self: bool) -> bool {
        if allow_self && self.contains(host) {
            return true;
        }
        let mut rest = host;
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            if self.contains(rest) {
                return true;
            }
        }
        false
    }
}

struct TrieNode {
    first_edge: u32,
    leaf: bool,
}

impl DomainSet {
    fn read<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let version = read_u8(reader)?;
        if version != 0 {
            bail!("rule-set: unsupported domain-set version {version}");
        }
        let leaves = read_u64s(reader)?;
        let bitmap = read_u64s(reader)?;
        let labels = read_bytes(reader)?;
        Self::decode(&leaves, &bitmap, &labels)
    }

    /// Decodes the on-disk unary-degree trie into materialized key sets.
    fn decode(leaves: &[u64], bitmap: &[u64], labels: &[u8]) -> anyhow::Result<Self> {
        let mut nodes: Vec<TrieNode> = Vec::new();
        let mut edges: Vec<(u8, u32)> = Vec::new();
        let mut label_index = 0usize;
        let mut bit = 0usize;
        let mut next_node = 1u32;
        while nodes.len() < next_node as usize {
            let first_edge = u32::try_from(edges.len())
                .map_err(|_| anyhow!("rule-set: domain trie too large"))?;
            let leaf = get_bit(leaves, nodes.len());
            loop {
                if bit >= bitmap.len() * 64 {
                    bail!("rule-set: truncated domain set");
                }
                if get_bit(bitmap, bit) {
                    bit += 1;
                    break;
                }
                let label = *labels
                    .get(label_index)
                    .ok_or_else(|| anyhow!("rule-set: truncated domain labels"))?;
                label_index += 1;
                edges.push((label, next_node));
                next_node = next_node
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("rule-set: domain trie too large"))?;
                bit += 1;
            }
            nodes.push(TrieNode { first_edge, leaf });
        }
        if label_index != labels.len() {
            bail!("rule-set: malformed domain set");
        }

        let mut exact = Vec::new();
        let mut self_suffix = Vec::new();
        let mut sub_suffix = Vec::new();
        let mut stack: Vec<(u32, Vec<u8>)> = vec![(0, Vec::new())];
        while let Some((id, path)) = stack.pop() {
            let node = &nodes[id as usize];
            if node.leaf && !path.is_empty() {
                exact.push(unreversed(&path)?);
            }
            let end = if (id as usize) + 1 < nodes.len() {
                nodes[id as usize + 1].first_edge
            } else {
                u32::try_from(edges.len())
                    .map_err(|_| anyhow!("rule-set: domain trie too large"))?
            };
            for edge in node.first_edge..end {
                let (label, child) = edges[edge as usize];
                match label {
                    ROOT_LABEL => {
                        if nodes[child as usize].leaf {
                            self_suffix.push(unreversed(&path)?);
                        }
                    }
                    PREFIX_LABEL => {
                        if nodes[child as usize].leaf {
                            sub_suffix.push(unreversed(&path)?);
                        }
                    }
                    _ => {
                        let mut next = path.clone();
                        next.push(label);
                        stack.push((child, next));
                    }
                }
            }
        }
        Ok(Self {
            exact: KeySet::new(exact),
            self_suffix: KeySet::new(self_suffix),
            sub_suffix: KeySet::new(sub_suffix),
        })
    }

    /// Whether `host` (any case) is covered.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let lowered = if host.chars().any(char::is_uppercase) {
            host.to_ascii_lowercase()
        } else {
            host.to_owned()
        };
        let host = lowered.as_str();
        self.exact.contains(host)
            || self.self_suffix.suffix_hit(host, true)
            || self.sub_suffix.suffix_hit(host, false)
    }

    #[cfg(test)]
    fn from_domains(exact: &[&str], suffix: &[&str]) -> Self {
        let exact_keys = exact.iter().map(|key| key.to_ascii_lowercase()).collect();
        let mut self_keys = Vec::new();
        let mut sub_keys = Vec::new();
        for entry in suffix {
            let entry = entry.to_ascii_lowercase();
            match entry.strip_prefix('.') {
                Some(sub) => sub_keys.push(sub.to_owned()),
                None => self_keys.push(entry),
            }
        }
        Self {
            exact: KeySet::new(exact_keys),
            self_suffix: KeySet::new(self_keys),
            sub_suffix: KeySet::new(sub_keys),
        }
    }
}

/// The forward domain for a reversed-byte trie path.
fn unreversed(path: &[u8]) -> anyhow::Result<String> {
    let text = std::str::from_utf8(path)
        .map_err(|error| anyhow!("rule-set: domain is not UTF-8: {error}"))?;
    Ok(text.chars().rev().collect())
}

fn get_bit(bitmap: &[u64], index: usize) -> bool {
    bitmap
        .get(index >> 6)
        .is_some_and(|word| word & (1 << (index & 63)) != 0)
}

fn read_u64s<R: Read>(reader: &mut R) -> anyhow::Result<Vec<u64>> {
    let count = read_uvarint(reader)?;
    if count > MAX_ITEMS {
        bail!("rule-set: list of {count} words exceeds the cap");
    }
    let mut out = Vec::with_capacity(usize::try_from(count)?);
    for _ in 0..count {
        let mut bytes = [0u8; 8];
        reader.read_exact(&mut bytes)?;
        out.push(u64::from_be_bytes(bytes));
    }
    Ok(out)
}

fn read_bytes<R: Read>(reader: &mut R) -> anyhow::Result<Vec<u8>> {
    let count = read_uvarint(reader)?;
    if count > MAX_ITEMS {
        bail!("rule-set: byte list of {count} exceeds the cap");
    }
    let mut out = vec![0u8; usize::try_from(count)?];
    reader.read_exact(&mut out)?;
    Ok(out)
}

#[cfg(test)]
fn uvarint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value & 0x7f).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write as _;

    /// One on-disk domain set: exact `full.example`, suffix `suffix.example`.
    const DOMAIN_SET: &[u8] = &[
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x6a,
        0xd5, 0x54, 0xaa, 0xaa, 0x13, 0x65, 0x6c, 0x70, 0x6d, 0x61, 0x78, 0x65, 0x2e, 0x6c, 0x78,
        0x6c, 0x69, 0x75, 0x66, 0x66, 0x66, 0x75, 0x73, 0x0a,
    ];

    fn ip_set(ranges: &[(IpAddr, IpAddr)]) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend_from_slice(&(ranges.len() as u64).to_be_bytes());
        for (from, to) in ranges {
            let bytes: Vec<u8> = match from {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            uvarint(bytes.len() as u64, &mut out);
            out.extend_from_slice(&bytes);
            let bytes: Vec<u8> = match to {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            uvarint(bytes.len() as u64, &mut out);
            out.extend_from_slice(&bytes);
        }
        out
    }

    fn string_item(id: u8, values: &[&str]) -> Vec<u8> {
        let mut out = vec![id];
        uvarint(values.len() as u64, &mut out);
        for value in values {
            uvarint(value.len() as u64, &mut out);
            out.extend_from_slice(value.as_bytes());
        }
        out
    }

    fn default_rule(items: &[Vec<u8>], invert: bool) -> Vec<u8> {
        let mut out = vec![0u8];
        for item in items {
            out.extend_from_slice(item);
        }
        out.push(0xFF);
        out.push(u8::from(invert));
        out
    }

    fn pack(rules: &[Vec<u8>], version: u8) -> Vec<u8> {
        let mut body = Vec::new();
        uvarint(rules.len() as u64, &mut body);
        for rule in rules {
            body.extend_from_slice(rule);
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&body).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut out = MAGIC.to_vec();
        out.push(version);
        out.extend_from_slice(&compressed);
        out
    }

    fn write(dir: &Path, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join("rules.srs");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn domain_set_matches_suffix_and_exact() {
        let set =
            DomainSet::from_domains(&["exact.org", "a.b.c"], &["example.com", ".only-subs.net"]);
        for (host, want) in [
            ("example.com", true),
            ("www.example.com", true),
            ("badexample.com", false),
            ("exact.org", true),
            ("www.exact.org", false),
            ("only-subs.net", false),
            ("x.only-subs.net", true),
            ("EXAMPLE.COM", true),
        ] {
            assert_eq!(set.matches(host), want, "{host}");
        }
    }

    #[test]
    fn parses_default_rule_items() {
        let dir = tempfile::tempdir().unwrap();
        let rule = default_rule(
            &[
                string_item(1, &["tcp"]),
                vec![2]
                    .into_iter()
                    .chain(DOMAIN_SET.iter().copied())
                    .collect(),
                string_item(3, &["Keyword"]),
                string_item(4, &[r"^ad\."]),
                vec![6]
                    .into_iter()
                    .chain(ip_set(&[(
                        "10.0.0.0".parse().unwrap(),
                        "10.0.0.255".parse().unwrap(),
                    )]))
                    .collect(),
                string_item(9, &[]), // replaced below by port items
                string_item(10, &["1000:2000", ":53"]),
            ],
            false,
        );
        let path = write(dir.path(), &pack(&[rule], 5));
        let set = load_rule_set(&path).unwrap();
        let Rule::Default(rule) = &set.rules[0] else {
            panic!("expected default rule");
        };
        assert_eq!(
            rule.network,
            Some(Networks {
                tcp: true,
                udp: false
            })
        );
        assert!(rule.domains.as_ref().unwrap().matches("full.example"));
        assert!(rule.domains.as_ref().unwrap().matches("a.suffix.example"));
        assert_eq!(rule.keywords, ["keyword"]);
        assert_eq!(rule.regexes, [r"^ad\."]);
        assert_eq!(rule.ips.len(), 1);
        assert_eq!(rule.ports, [(1000, 2000), (0, 53)]);
    }

    #[test]
    fn logical_rules_and_invert() {
        let dir = tempfile::tempdir().unwrap();
        let child = default_rule(&[string_item(3, &["x"])], false);
        let mut logical = vec![1u8, 0]; // `and`
        uvarint(1, &mut logical);
        logical.extend(child);
        logical.push(1); // invert
        let path = write(dir.path(), &pack(&[logical], 4));
        let Rule::Logical { and, rules, invert } = &load_rule_set(&path).unwrap().rules[0] else {
            panic!("expected logical rule");
        };
        assert!(*and);
        assert_eq!(rules.len(), 1);
        assert!(*invert);
    }

    #[test]
    fn unsupported_items_and_bad_headers_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let process = default_rule(&[string_item(11, &["curl"])], false);
        let err = load_rule_set(&write(dir.path(), &pack(&[process], 5))).unwrap_err();
        assert!(format!("{err:#}").contains("process_name/path"), "{err:#}");

        let dir2 = tempfile::tempdir().unwrap();
        let err = load_rule_set(&write(dir2.path(), b"nope")).unwrap_err();
        assert!(err.to_string().contains("bad magic"), "{err}");

        let dir3 = tempfile::tempdir().unwrap();
        let err = load_rule_set(&write(dir3.path(), &pack(&[], 6))).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");
    }
}
