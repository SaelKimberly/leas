//! Xray/v2ray geodata (`.dat`) reader.
//!
//! Wire schema (`geodat.proto`):
//!
//! ```text
//! GeoSiteList { repeated GeoSite entry = 1 }
//! GeoSite     { string code = 1; repeated Domain domain = 2 }
//! Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3 }
//!             Type: 0 Substr, 1 Regex, 2 Domain (self + subdomains), 3 Full
//! Attribute   { string key = 1; ... }
//! GeoIPList   { repeated GeoIP entry = 1 }
//! GeoIP       { string code = 1; repeated CIDR cidr = 2; bool reverse_match = 3 }
//! CIDR        { bytes ip = 1; uint32 prefix = 2 }
//! ```
//!
//! Entries are streamed: every top-level entry is read, its code is checked,
//! and only requested categories are decoded. Nothing is vendored; the files
//! come from the configured release URLs.

use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{Context as _, anyhow, bail};

/// Upper bound for one top-level entry (a code with many domains/CIDRs).
const MAX_ENTRY: u64 = 256 << 20;

/// Domains of one geosite category, split by the dat's own type tag.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GeoDomains {
    /// `Full` entries: exact host match.
    pub exact: Vec<String>,
    /// `Domain` entries: the bare host and every subdomain.
    pub suffix: Vec<String>,
    /// `Substr` entries.
    pub keywords: Vec<String>,
    /// `Regex` entries, verbatim (the engine compiles them).
    pub regexes: Vec<String>,
}

impl GeoDomains {
    /// Whether the category carries no rule.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.suffix.is_empty()
            && self.keywords.is_empty()
            && self.regexes.is_empty()
    }
}

/// One geoip address range, with the record's effective reverse flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoNet {
    /// Network address.
    pub addr: IpAddr,
    /// Prefix length in bits.
    pub prefix: u8,
    /// `true` = the category matches every address *outside* the prefix.
    pub reverse: bool,
}

#[derive(Debug, Clone)]
struct SiteToken {
    raw: String,
    code: String,
    attrs: Vec<String>,
}

#[derive(Debug, Clone)]
struct IpToken {
    raw: String,
    code: String,
    reverse: bool,
}

/// Strips any number of leading `!` (each flips the flag), mirroring the
/// mainstream parsers.
fn split_reverse(raw: &str) -> (bool, &str) {
    let mut reverse = false;
    let mut rest = raw.trim();
    while let Some(stripped) = rest.strip_prefix('!') {
        reverse = !reverse;
        rest = stripped;
    }
    (reverse, rest)
}

fn parse_site_token(raw: &str) -> anyhow::Result<SiteToken> {
    let (_reverse, rest) = split_reverse(raw);
    let mut parts = rest.split('@');
    let code = parts.next().unwrap_or_default().trim();
    if code.is_empty() {
        bail!("geosite token {raw:?}: empty code");
    }
    let mut attrs = Vec::new();
    for attr in parts {
        let attr = attr.trim();
        if attr.is_empty() {
            bail!("geosite token {raw:?}: empty attribute");
        }
        attrs.push(attr.to_ascii_lowercase());
    }
    Ok(SiteToken {
        raw: raw.to_owned(),
        code: code.to_ascii_lowercase(),
        attrs,
    })
}

fn parse_ip_token(raw: &str) -> anyhow::Result<IpToken> {
    let (reverse, rest) = split_reverse(raw);
    let code = rest.trim();
    if code.is_empty() {
        bail!("geoip token {raw:?}: empty code");
    }
    Ok(IpToken {
        raw: raw.to_owned(),
        code: code.to_ascii_lowercase(),
        reverse,
    })
}

/// Loads the requested geosite categories, one entry per token in request
/// order. A token is `[!]code[@attr...]` (attributes are `ANDed`); an unknown
/// category is an error naming the file and code.
///
/// # Errors
/// I/O, malformed-protobuf, empty token, and unknown-code errors.
pub fn load_geosite(path: &Path, tokens: &[String]) -> anyhow::Result<Vec<(String, GeoDomains)>> {
    let parsed = tokens
        .iter()
        .map(|t| parse_site_token(t))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let wanted: HashSet<&str> = parsed.iter().map(|t| t.code.as_str()).collect();
    let mut raw: HashMap<String, Vec<RawDomain>> = HashMap::new();
    scan_entries(path, |code, entry| {
        if !wanted.contains(code) {
            return Ok(());
        }
        let domains = decode_site_entry(entry)
            .with_context(|| format!("{}: category {code:?}", path.display()))?;
        raw.entry(code.to_owned()).or_default().extend(domains);
        Ok(())
    })?;
    if let Some(missing) = parsed.iter().find(|t| !raw.contains_key(&t.code)) {
        bail!("{}: no geosite category {:?}", path.display(), missing.code);
    }
    let mut out = Vec::with_capacity(parsed.len());
    for token in parsed {
        let mut domains = GeoDomains::default();
        for domain in &raw[&token.code] {
            if !token.attrs.iter().all(|want| domain.attrs.contains(want)) {
                continue;
            }
            match domain.kind {
                0 => domains.keywords.push(domain.value.to_ascii_lowercase()),
                1 => domains.regexes.push(domain.value.clone()),
                2 => domains.suffix.push(domain.value.to_ascii_lowercase()),
                3 => domains.exact.push(domain.value.to_ascii_lowercase()),
                _ => {}
            }
        }
        normalize(&mut domains);
        out.push((token.raw, domains));
    }
    Ok(out)
}

/// One lenient geoip load: the categories the file served, plus the requested
/// codes it does not carry (in request order).
#[derive(Debug, Default)]
pub struct GeoIpLoad {
    /// One entry per served token: the raw token and its ranges.
    pub loaded: Vec<(String, Vec<GeoNet>)>,
    /// Codes the file has no category for; the caller decides the fallback.
    pub missing: Vec<String>,
}

/// Loads the requested geoip categories, reporting the codes the file does not
/// carry instead of failing.
///
/// The engine uses the split to resolve an unknown country code from the
/// `GeoLite2` database (a per-token fallback), so a dataset that lacks country
/// categories still serves `geoip:<cc>` rules.
///
/// # Errors
/// I/O, malformed-protobuf, and empty-token errors. An unknown code is NOT an
/// error here (see [`load_geoip`] for the strict form).
pub fn load_geoip_lenient(path: &Path, tokens: &[String]) -> anyhow::Result<GeoIpLoad> {
    let parsed = tokens
        .iter()
        .map(|t| parse_ip_token(t))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let wanted: HashSet<&str> = parsed.iter().map(|t| t.code.as_str()).collect();
    let mut raw: HashMap<String, (Vec<(IpAddr, u8)>, bool)> = HashMap::new();
    scan_entries(path, |code, entry| {
        if !wanted.contains(code) {
            return Ok(());
        }
        let (cidrs, reverse) = decode_ip_entry(entry)
            .with_context(|| format!("{}: category {code:?}", path.display()))?;
        let slot = raw.entry(code.to_owned()).or_default();
        slot.0.extend(cidrs);
        slot.1 |= reverse;
        Ok(())
    })?;
    let mut out = GeoIpLoad::default();
    for token in parsed {
        let Some((cidrs, record_reverse)) = raw.get(&token.code) else {
            out.missing.push(token.code);
            continue;
        };
        let reverse = token.reverse ^ record_reverse;
        let nets = cidrs
            .iter()
            .map(|&(addr, prefix)| GeoNet {
                addr,
                prefix,
                reverse,
            })
            .collect();
        out.loaded.push((token.raw, nets));
    }
    Ok(out)
}

/// Loads the requested geoip categories, one entry per token in request order.
/// A token is `[!]code`; the returned `GeoNet.reverse` is the token flag XOR
/// the record's `reverse_match` (xray semantics).
///
/// # Errors
/// I/O, malformed-protobuf, empty token, and unknown-code errors.
pub fn load_geoip(path: &Path, tokens: &[String]) -> anyhow::Result<Vec<(String, Vec<GeoNet>)>> {
    let load = load_geoip_lenient(path, tokens)?;
    if let Some(missing) = load.missing.first() {
        bail!("{}: no geoip category {:?}", path.display(), missing);
    }
    Ok(load.loaded)
}

/// Every top-level category code; also the download validator (an empty,
/// trash, or truncated file is an error).
///
/// # Errors
/// I/O and malformed-protobuf errors.
pub fn validate(path: &Path) -> anyhow::Result<Vec<String>> {
    let mut codes = Vec::new();
    scan_entries(path, |code, _entry| {
        codes.push(code.to_owned());
        Ok(())
    })?;
    Ok(codes)
}

#[derive(Debug)]
struct RawDomain {
    kind: u64,
    value: String,
    attrs: Vec<String>,
}

/// Calls `f(code, entry_payload)` for every top-level entry.
fn scan_entries<F>(path: &Path, mut f: F) -> anyhow::Result<()>
where
    F: FnMut(&str, &[u8]) -> anyhow::Result<()>,
{
    let file =
        std::fs::File::open(path).with_context(|| format!("geodata: open {}", path.display()))?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut entries = 0usize;
    while let Some((num, wire)) =
        read_key(&mut reader).with_context(|| format!("geodata: {}", path.display()))?
    {
        if num == 1 && wire == 2 {
            let entry = read_len_delimited(&mut reader, MAX_ENTRY)
                .with_context(|| format!("geodata: {}", path.display()))?;
            let mut code = None;
            for field in Fields::new(&entry) {
                if let (1, Field::Bytes(bytes)) = field? {
                    code = Some(String::from_utf8_lossy(bytes).to_ascii_lowercase());
                    break;
                }
            }
            if let Some(code) = code {
                entries += 1;
                f(&code, &entry)?;
            }
        } else {
            skip(&mut reader, wire).with_context(|| format!("geodata: {}", path.display()))?;
        }
    }
    if entries == 0 {
        bail!("{}: no geodata entries", path.display());
    }
    Ok(())
}

fn decode_site_entry(entry: &[u8]) -> anyhow::Result<Vec<RawDomain>> {
    let mut out = Vec::new();
    for field in Fields::new(entry) {
        let (num, value) = field?;
        let Field::Bytes(bytes) = value else { continue };
        if num != 2 {
            continue;
        }
        let mut kind = 0u64;
        let mut text = None;
        let mut attrs = Vec::new();
        for field in Fields::new(bytes) {
            match field? {
                (1, Field::Varint(v)) => kind = v,
                (2, Field::Bytes(b)) => text = Some(String::from_utf8_lossy(b).into_owned()),
                (3, Field::Bytes(attribute)) => {
                    for field in Fields::new(attribute) {
                        if let (1, Field::Bytes(key)) = field? {
                            attrs.push(String::from_utf8_lossy(key).to_ascii_lowercase());
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(value) = text.filter(|v| !v.is_empty()) {
            out.push(RawDomain { kind, value, attrs });
        }
    }
    Ok(out)
}

fn decode_ip_entry(entry: &[u8]) -> anyhow::Result<(Vec<(IpAddr, u8)>, bool)> {
    let mut cidrs = Vec::new();
    let mut reverse = false;
    for field in Fields::new(entry) {
        match field? {
            (2, Field::Bytes(cidr)) => {
                let mut ip = None;
                let mut prefix = None;
                for field in Fields::new(cidr) {
                    match field? {
                        (1, Field::Bytes(bytes)) => {
                            ip = match bytes.len() {
                                4 => <[u8; 4]>::try_from(bytes)
                                    .ok()
                                    .map(|a| IpAddr::V4(Ipv4Addr::from(a))),
                                16 => <[u8; 16]>::try_from(bytes)
                                    .ok()
                                    .map(|a| IpAddr::V6(Ipv6Addr::from(a))),
                                _ => bail!("geoip: CIDR address is neither 4 nor 16 bytes"),
                            };
                        }
                        (2, Field::Varint(v)) => prefix = Some(v),
                        _ => {}
                    }
                }
                let (Some(addr), Some(prefix)) = (ip, prefix) else {
                    bail!("geoip: CIDR missing address or prefix");
                };
                let max = if addr.is_ipv4() { 32 } else { 128 };
                let prefix = u8::try_from(prefix)
                    .ok()
                    .filter(|p| *p <= max)
                    .ok_or_else(|| anyhow!("geoip: prefix length {prefix} exceeds /{max}"))?;
                cidrs.push((addr, prefix));
            }
            (3, Field::Varint(v)) => reverse = v != 0,
            _ => {}
        }
    }
    Ok((cidrs, reverse))
}

fn normalize(domains: &mut GeoDomains) {
    for list in [
        &mut domains.exact,
        &mut domains.suffix,
        &mut domains.keywords,
        &mut domains.regexes,
    ] {
        list.retain(|s| !s.is_empty());
        list.sort_unstable();
        list.dedup();
    }
}

// ── Minimal protobuf reading ───────────────────────────────────────────

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Other,
}

struct Fields<'a> {
    msg: &'a [u8],
}

impl<'a> Fields<'a> {
    const fn new(msg: &'a [u8]) -> Self {
        Self { msg }
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = anyhow::Result<(u64, Field<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.msg.is_empty() {
            return None;
        }
        let result = decode_field(self.msg);
        match result {
            Ok((num, field, rest)) => {
                self.msg = rest;
                Some(Ok((num, field)))
            }
            Err(e) => {
                self.msg = &[];
                Some(Err(e))
            }
        }
    }
}

fn decode_field(msg: &[u8]) -> anyhow::Result<(u64, Field<'_>, &[u8])> {
    let (key, rest) = read_uvarint_slice(msg).ok_or_else(|| anyhow!("truncated field key"))?;
    let num = key >> 3;
    let wire = (key & 7) as u8;
    match wire {
        0 => {
            let (v, rest) = read_uvarint_slice(rest).ok_or_else(|| anyhow!("truncated varint"))?;
            Ok((num, Field::Varint(v), rest))
        }
        2 => {
            let (len, rest) =
                read_uvarint_slice(rest).ok_or_else(|| anyhow!("truncated length"))?;
            let len = usize::try_from(len).map_err(|_| anyhow!("length overflow"))?;
            if len > rest.len() {
                bail!("truncated field");
            }
            let (bytes, rest) = rest.split_at(len);
            Ok((num, Field::Bytes(bytes), rest))
        }
        1 => {
            if rest.len() < 8 {
                bail!("truncated fixed64");
            }
            Ok((num, Field::Other, &rest[8..]))
        }
        5 => {
            if rest.len() < 4 {
                bail!("truncated fixed32");
            }
            Ok((num, Field::Other, &rest[4..]))
        }
        _ => bail!("unsupported protobuf wire type {wire}"),
    }
}

fn read_uvarint_slice(mut bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let (&byte, rest) = bytes.split_first()?;
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        bytes = rest;
        if byte & 0x80 == 0 {
            return Some((value, bytes));
        }
        shift += 7;
    }
}

fn read_key<R: Read>(reader: &mut R) -> anyhow::Result<Option<(u64, u8)>> {
    let mut first = [0u8; 1];
    if reader.read(&mut first)? == 0 {
        return Ok(None);
    }
    let mut value = u64::from(first[0] & 0x7f);
    let mut shift = 7u32;
    let mut byte = first[0];
    while byte & 0x80 != 0 {
        if shift >= 64 {
            bail!("geodata: varint overflow");
        }
        reader.read_exact(&mut first)?;
        byte = first[0];
        value |= u64::from(byte & 0x7f) << shift;
        shift += 7;
    }
    Ok(Some((value >> 3, (value & 7) as u8)))
}

fn read_uvarint<R: Read>(reader: &mut R) -> anyhow::Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        if shift >= 64 {
            bail!("geodata: varint overflow");
        }
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn read_len_delimited<R: Read>(reader: &mut R, cap: u64) -> anyhow::Result<Vec<u8>> {
    let len = read_uvarint(reader)?;
    if len > cap {
        bail!("geodata: entry of {len} bytes exceeds the {cap}-byte cap");
    }
    let mut bytes = vec![0u8; usize::try_from(len)?];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn skip<R: Read>(reader: &mut R, wire: u8) -> anyhow::Result<()> {
    match wire {
        0 => {
            read_uvarint(reader)?;
        }
        1 => {
            let mut bytes = [0u8; 8];
            reader.read_exact(&mut bytes)?;
        }
        2 => {
            let len = read_uvarint(reader)?;
            std::io::copy(&mut reader.take(len), &mut std::io::sink())?;
        }
        5 => {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes)?;
        }
        _ => bail!("geodata: unsupported protobuf wire type {wire}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uvarint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value & 0x7f).unwrap());
    }

    fn field_bytes(num: u64, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        uvarint((num << 3) | 2, &mut out);
        uvarint(bytes.len() as u64, &mut out);
        out.extend_from_slice(bytes);
        out
    }

    fn field_varint(num: u64, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        uvarint(num << 3, &mut out);
        uvarint(value, &mut out);
        out
    }

    fn attribute(key: &str) -> Vec<u8> {
        field_bytes(1, key.as_bytes())
    }

    fn domain(kind: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
        let mut out = field_varint(1, kind);
        out.extend(field_bytes(2, value.as_bytes()));
        for attr in attrs {
            out.extend(field_bytes(3, &attribute(attr)));
        }
        out
    }

    fn site_entry(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut out = field_bytes(1, code.as_bytes());
        for d in domains {
            out.extend(field_bytes(2, d));
        }
        out
    }

    fn geoip_entry(code: &str, cidrs: &[(IpAddr, u8)], reverse: bool) -> Vec<u8> {
        let mut out = field_bytes(1, code.as_bytes());
        for (addr, prefix) in cidrs {
            let mut cidr = field_bytes(1, &ip_bytes(*addr));
            cidr.extend(field_varint(2, u64::from(*prefix)));
            out.extend(field_bytes(2, &cidr));
        }
        if reverse {
            out.extend(field_varint(3, 1));
        }
        out
    }

    fn ip_bytes(addr: IpAddr) -> Vec<u8> {
        match addr {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        }
    }

    fn list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in entries {
            out.extend(field_bytes(1, entry));
        }
        out
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn tokens(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn geosite_types_and_attributes_map_and_filter() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = list(&[site_entry(
            "CN",
            &[
                domain(0, "baidu", &[]),
                domain(1, r"^ad\.", &[]),
                domain(2, "Example.COM", &[]),
                domain(3, "Exact.CN", &[]),
                domain(2, "ads.example.com", &["ads"]),
            ],
        )]);
        let path = write(dir.path(), "geosite.dat", &bytes);
        let loaded = load_geosite(&path, &tokens(&["cn"])).unwrap();
        assert_eq!(loaded.len(), 1);
        let (_, domains) = &loaded[0];
        assert_eq!(domains.keywords, ["baidu"]);
        assert_eq!(domains.regexes, [r"^ad\."]);
        assert_eq!(domains.suffix, ["ads.example.com", "example.com"]);
        assert_eq!(domains.exact, ["exact.cn"]);

        let filtered = load_geosite(&path, &tokens(&["CN@ADS"])).unwrap();
        assert_eq!(filtered[0].1.suffix, ["ads.example.com"]);
        assert_eq!(filtered[0].1.exact, Vec::<String>::new());
    }

    #[test]
    fn geosite_reverse_and_unknown_code() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "geosite.dat",
            &list(&[site_entry("cn", &[domain(3, "exact.cn", &[])])]),
        );
        let loaded = load_geosite(&path, &tokens(&["!cn"])).unwrap();
        assert_eq!(loaded[0].0, "!cn", "the raw token is returned verbatim");
        let err = load_geosite(&path, &tokens(&["nope"])).unwrap_err();
        assert!(err.to_string().contains("nope"), "{err}");
        assert!(err.to_string().contains("geosite.dat"), "{err}");
        assert!(load_geosite(&path, &tokens(&["cn@"])).is_err());
        assert!(load_geosite(&path, &tokens(&["@"])).is_err());
    }

    #[test]
    fn geoip_reverse_xor_and_unknown_code() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "geoip.dat",
            &list(&[
                geoip_entry("CN", &[("1.0.1.0".parse().unwrap(), 24)], false),
                geoip_entry("REV", &[("10.0.0.0".parse().unwrap(), 8)], true),
            ]),
        );
        let loaded = load_geoip(&path, &tokens(&["cn", "!cn", "rev", "!rev"])).unwrap();
        assert!(loaded[0].1.iter().all(|n| !n.reverse));
        assert!(loaded[1].1.iter().all(|n| n.reverse));
        assert!(loaded[2].1.iter().all(|n| n.reverse));
        assert!(loaded[3].1.iter().all(|n| !n.reverse));
        assert_eq!(loaded[0].1[0].addr, "1.0.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(loaded[0].1[0].prefix, 24);
        assert!(load_geoip(&path, &tokens(&["zz"])).is_err());
    }

    /// The lenient split is what lets an unknown country code be answered by
    /// the mmdb fallback; the strict form keeps its named error.
    #[test]
    fn geoip_lenient_splits_loaded_from_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "geoip.dat",
            &list(&[geoip_entry(
                "CN",
                &[("1.0.1.0".parse().unwrap(), 24)],
                false,
            )]),
        );
        let load = load_geoip_lenient(&path, &tokens(&["cn", "ir", "ru"])).unwrap();
        assert_eq!(load.loaded.len(), 1);
        assert_eq!(load.loaded[0].0, "cn");
        assert_eq!(load.missing, ["ir", "ru"]);
        let err = load_geoip(&path, &tokens(&["cn", "ir"])).unwrap_err();
        assert!(
            err.to_string().contains("no geoip category \"ir\""),
            "{err}"
        );
    }

    #[test]
    fn malformed_and_empty_files_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let empty = write(dir.path(), "empty.dat", &[]);
        assert!(validate(&empty).is_err());
        let junk = write(dir.path(), "junk.dat", b"<html>nope</html>");
        assert!(validate(&junk).is_err());

        let mut truncated = list(&[site_entry("cn", &[domain(3, "x.cn", &[])])]);
        truncated.truncate(truncated.len() - 2);
        let truncated = write(dir.path(), "truncated.dat", &truncated);
        assert!(validate(&truncated).is_err());

        let valid = write(
            dir.path(),
            "valid.dat",
            &list(&[site_entry("cn", &[]), site_entry("us", &[])]),
        );
        assert_eq!(validate(&valid).unwrap(), ["cn", "us"]);
    }

    #[test]
    fn skip_fields_carry_unknown_data() {
        let dir = tempfile::tempdir().unwrap();
        // A fixed64 (wire 1) and fixed32 (wire 5) field before the entry.
        let mut bytes = Vec::new();
        uvarint((9 << 3) | 1, &mut bytes);
        bytes.extend_from_slice(&[0u8; 8]);
        uvarint((10 << 3) | 5, &mut bytes);
        bytes.extend_from_slice(&[0u8; 4]);
        bytes.extend(list(&[site_entry("cn", &[])]));
        let path = write(dir.path(), "skip.dat", &bytes);
        assert_eq!(validate(&path).unwrap(), ["cn"]);
    }
}
