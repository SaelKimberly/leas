# GeoIP / GeoSite routing — implementation plan

- Date: 2026-11-09
- Slug: `geoip-geosite`
- Aegis path: `docs/aegis/plans/2026-11-09-geoip-geosite.md` (index row in `docs/aegis/INDEX.md`)
- Approved scope (user decisions, this session): geo rules drive **live traffic**; formats **v2ray `.dat` + sing-box `.srs` + MaxMind `.mmdb`**; **auto-download** from the configured URLs with periodic refresh; **fail closed** on a missing file, dataset, code, or rule-set.

## Aegis Visibility

This is core/contract work: it changes the routing IR, the engine's match semantics, the native-core server's outbound set, the subscription fetch gate, and adds a new data-acquisition owner. A durable plan is what keeps a fresh implementer from inventing semantics for geo tokens, missing data, and outbound tags.

## Goal

Routing rules can reference `geoip:<cc>`, `geosite:<code[@attr]>`, and sing-box `rule_set` sources. The data comes from the same artifacts the mainstream cores consume (Loyalsoldier `v2ray-rules-dat` by default, MaxMind GeoLite2 for mmdb mode, per-row `.srs` URLs). Geo rules decide native client traffic and subscription-source fetches. Any unresolvable geo reference fails compilation with a named error; it never falls through to the default route.

## Architecture (owner map)

```
config URLs / mode            leas-config::GeoConfig
        │
        ▼
leas::ops::geodata  ──downloads/validates──►  config_dir/{geoip.dat,geosite.dat,GeoLite2-City.mmdb,rule-sets/*.srs}
        │  builds IR rows (route_compile) + GeoSource
        ▼
leas-route::Engine::build_with_geo  ──►  compiled matchers (CIDR sets, domain sets, Sub(CompiledCond))
        │  Arc<Engine> cached in leas::AppState (EngineCell), rebuilt on rules/geo changes
        ├──► leas-native NativeCoreServer (live SOCKS/HTTP traffic, outbounds proxy/direct/block)
        └──► leas::ops::subscriptions::plan_http_route (subscription source fetch)
```

Parsers live in `leas-geoip::geodata` (neutral types, no dependency on `leas-route`); `leas-route` depends on `leas-geoip` under its `geoip` feature.

## Tech stack

Rust 2024 workspace. No new external crate except existing workspace crates: `flate2` (zlib in `.srs`), `sha2`+`hex` (rule-set cache key) added to `leas-geoip`; `flate2` added as a `leas-route` dev-dependency for `.srs` test fixtures. Protobuf `.dat` is decoded by a hand-written streaming decoder (no `prost`) written from `thirdparty/Xray-core/common/geodata/geodat.proto` and the wire format. `maxminddb 0.32` is already present.

Licensing boundary: `thirdparty/` trees are read-only behavioral references only — leas is MIT, while unbihex is BSL-1.1, sing-box and mihomo are GPL-3.0, and Xray-core is MPL-2.0. No code is copied from any of them; formats are implemented from the schema/docs and validated by tests over hand-encoded fixtures.

## Baseline / authority refs (read this session)

- `crates/leas-route/src/ir.rs`, `engine.rs`, `matchers.rs`, `resolve.rs`, `dns_adapter.rs`, `compiler/xray.rs`, `compiler/singbox.rs`
- `crates/leas-geoip/src/lib.rs` (mmdb lookup, heal, `fetch_geolite_to`, `stream_capped`, tests)
- `crates/leas/src/route_compile.rs`, `ops/subscriptions.rs`, `ops/settings.rs`, `state.rs`, `ops/connect.rs`, `ops/native_connect.rs`, `ui/settings.rs`, `ui/mod.rs`
- `crates/leas-native/src/server/mod.rs`, `inbound/mod.rs`, `inbound/outbound.rs`, `inbound/tests.rs`
- `crates/leas-config/src/app_config.rs` (`GeoConfig`), `crates/leas-db/src/models_toasty.rs` (`RoutingRule`)
- Upstream: `thirdparty/Xray-core/common/geodata/*` (`geodat.proto`, `rule_parser.go`, `geodat_loader.go`), `thirdparty/sing-box/common/srs/binary.go`, `thirdparty/sing-box/route/rule/rule_abstract.go`, `thirdparty/mihomo/component/geodata/*`, `thirdparty/unbihex/unbihex-engine/src/rules/{geodata,srs,succinct,ipset}.rs`
- Format facts confirmed: xray/mihomo geosite `Domain.Type` 0=Substr,1=Regex,2=Domain(self+subdomains),3=Full; `geosite:!code`, `geosite:code@attr` (all attrs AND), `geoip:!cc` / `!geoip:cc` reverse; GeoIP `.dat` record has `reverse_match` combined by XOR with the token's `!`; `.srs` = `"SRS"` + u8 version (≤5) + zlib(uvarint rule count + rules); srs item ids 0..24/0xFF as in `binary.go`; srs `ip_cidr` = u8 version 1 + u64be count + (from,to) pairs; `DomainSet` = u8 version + leaves u64 list + label bitmap u64 list + labels.

## Change Necessity

Data-only or config-only cannot express token→matcher resolution: the engine must own expanded CIDR/domain sets and rule-set subtrees at build time, and the native server must receive the compiled engine and expose `direct`/`block` outbounds. Minimum code boundary: `leas-geoip` (parsers + acquisition), `leas-route` (IR + engine + compilers), `leas` (config, orchestration, consumers), `leas-native` (server accepts an engine).

## Ripple Signal Triage

Shared contract changed: `MatchItem` (public IR, serde), `Engine::build_with_geo`, `NativeCoreServer` config, `GeoConfig`, `RoutingRule` interpretation (outbound tags), subscription fetch gate. Canonical owners: `leas-route` for match semantics, `leas::ops::geodata` for acquisition/lifecycle, `leas-native::server` for the outbound vocabulary. No fallback/duplicate owner is added; missing data is an error, not a second behavior. Retirement: the inert `geo_country` behavior and all "deferred"/"not supported yet" geo warnings are deleted in the same change.

## TDD Route

Mode `auto` → **strict for T1–T8, T13** (parser/matcher/contract behavior: write the listed test first, observe it fail, then implement), **light for T9–T12, T14–T15** (wiring: the listed focused test keeps it honest). No test may be deleted to make a task pass; update expectations only where the plan says the old behavior is retired.

## Requirement Ready Check

Scope, scenarios, acceptance evidence are fixed by the user answers above and the verification section. No open design decision remains; every task names files, exact symbols, and observable results.

---

## Tasks

### T1 — `leas-geoip`: shared download + validation helper

Files: `crates/leas-geoip/Cargo.toml`, `crates/leas-geoip/src/lib.rs`.

1. Add deps: `flate2.workspace = true`, `sha2.workspace = true` (feature `zeroize` per workspace default is fine), `hex.workspace = true`; dev-deps already include `tempfile`, `tokio`; add `rstest.workspace = true` only if table-driven tests are used.
2. Add:
   ```rust
   pub const MAX_GEO_DAT_BYTES: u64 = 64 * 1024 * 1024;
   pub const MAX_RULE_SET_BYTES: u64 = 32 * 1024 * 1024;

   /// Downloads `url` to `dest` atomically (temp file + rename), refusing a
   /// body over `max_bytes`, an empty body, a non-2xx status, and a body that
   /// `validate` rejects (validator runs on the temp file before the rename).
   pub async fn fetch_validated<F>(url: &str, dest: &std::path::Path, max_bytes: u64, validate: F) -> anyhow::Result<()>
   where F: FnOnce(&std::path::Path) -> anyhow::Result<()> + Send + 'static;

   /// Stable cache file name for a remote asset: lowercase hex SHA-256 of `url`.
   pub fn url_cache_key(url: &str) -> String;
   ```
   Reuse the existing streaming/cap code (`stream_capped`, UA `"leas"`); a body over the cap or an empty body must leave no file behind. Refactor the default mmdb fetcher `fetch_geolite_to` to call `fetch_validated(GEOLITE_DOWNLOAD, dest, MAX_GEOLITE_BYTES, |_| Ok(()))` so there is one streaming implementation.
3. Tests (temp dir + a local `TcpListener` that serves a body, same shape as `stream_capped_refuses_an_over_cap_body`):
   - `fetch_validated_writes_atomically_when_valid`;
   - `fetch_validated_keeps_old_file_when_validation_fails` (old bytes still readable);
   - `fetch_validated_rejects_empty_and_over_cap_bodies_without_a_file`;
   - `url_cache_key_is_64_lowercase_hex`.

### T2 — `leas-geoip::geodata`: v2ray `.dat` parser

Files: new `crates/leas-geoip/src/geodata/mod.rs`, `crates/leas-geoip/src/geodata/dat.rs`; register `pub mod geodata;` in `lib.rs`.

Neutral API (no `leas-route` types):
```rust
pub struct GeoDomains { pub exact: Vec<String>, pub suffix: Vec<String>, pub keywords: Vec<String>, pub regexes: Vec<String> }
impl GeoDomains { pub fn is_empty(&self) -> bool; }

pub struct GeoNet { pub addr: std::net::IpAddr, pub prefix: u8, pub reverse: bool }

/// One entry per requested token, in request order. Token grammar:
/// `[!]CODE` for geoip; `[!]CODE[@ATTR...]` for geosite (attrs AND, case-insensitive).
/// Unknown code => Err naming the file and code.
pub fn load_geosite(path: &Path, tokens: &[String]) -> anyhow::Result<Vec<(String, GeoDomains)>>;
pub fn load_geoip(path: &Path, tokens: &[String]) -> anyhow::Result<Vec<(String, Vec<GeoNet>)>>;

/// Top-level entry codes; also the download validator (rejects empty/garbage/truncated files).
pub fn validate(path: &Path) -> anyhow::Result<Vec<String>>;
```
Reverse-token evidence (settled, do not re-litigate): mihomo strips a leading `!` for **both** GEOSITE and GEOIP and wraps the matcher (`component/geodata/utils.go`: `NewNotDomainMatcherGroup` / `not`); xray strips `!` only for IP rules and has no geosite reverse. This implementation follows mihomo: `geosite:!code` is valid and means "domain not in the set"; an IP target with no host is never matched by a geosite item, reversed or not.

Implementation rules:
- Streaming protobuf: uvarint keys, wire types 0/1/2/5, skip unknown, `MAX_ENTRY = 256 << 20` per entry, `BufReader` 64 KiB. Field numbers per `geodat.proto` (top list field 1 = entry; entry field 1 = code; geosite field 2 = Domain{1 type,2 value,3 Attribute{1 key}}; geoip field 2 = CIDR{1 ip bytes,2 prefix}, field 3 = reverse_match bool).
- Codes/tokens lowercased with ASCII; `!` is accepted only as the first token char (also `geoip:!cc` is encoded by callers as the token `!cc`); empty code/attr is an error; `code@`/`@@` error.
- Type map: 0→`keywords` (ASCII-lowercased), 1→`regexes` (verbatim), 2→`suffix`, 3→`exact`; every vector lowercased where applicable then sorted+deduped.
- A `Domain(2)` entry means "this domain and subdomains"; keep it in `suffix` only — the engine adds suffix entries to `exact` so the bare host matches (same rule the xray compiler already applies to bare tokens).
- GeoIP: ip bytes must be 4 or 16, prefix ≤32/≤128; final `reverse = token_reverse XOR record.reverse_match`.
- Tests build fixtures in-code (`fn varint`, `fn len_field`, `fn varint_field`), no binary fixtures:
  - typed mapping (all four types);
  - attrs AND-filter and `!` reverse;
  - unknown code error text contains the code and path;
  - malformed/truncated and wire-type-5 field skip; empty file rejected by `validate`;
  - geoip reverse XOR (four combinations).

### T3 — `leas-geoip::geodata::srs`: sing-box binary rule-set parser

Files: new `crates/leas-geoip/src/geodata/srs.rs`.

Public types:
```rust
pub struct RuleSet { pub rules: Vec<Rule> }
pub enum Rule { Default(DefaultRule), Logical { and: bool, rules: Vec<Rule>, invert: bool } }
pub struct DefaultRule {
    pub domains: Option<DomainSet>, pub keywords: Vec<String>, pub regexes: Vec<String>,
    pub ips: Vec<GeoRange>, pub source_ips: Vec<GeoRange>,
    pub ports: Vec<(u16, u16)>, pub source_ports: Vec<(u16, u16)>,
    pub network: Option<Networks>, pub invert: bool,
}
pub struct Networks { pub tcp: bool, pub udp: bool }
pub struct GeoRange { pub from: std::net::IpAddr, pub to: std::net::IpAddr }
pub struct DomainSet { /* succinct LOUDS trie */ }
impl DomainSet { pub fn matches(&self, host: &str) -> bool; }

pub fn load_rule_set(path: &Path) -> anyhow::Result<RuleSet>;
```
Implementation rules:
- Magic `SRS`, version `1..=5` (else error), zlib (`flate2::read::ZlibDecoder`), uvarint rule count (cap `1<<20`), recursion depth ≤32.
- Items: 1 network (`tcp`/`udp` strings; anything else error), 2 domain set, 3 keywords, 4 regexes, 5 source_ip_cidr, 6 ip_cidr, 7 source_port, 8 source_port_range, 9 port (u16 list), 10 port_range (`"1000:2000"`, open ends clamp 0/u16::MAX), `0xFF` + invert byte terminates. Every other item id (0, 11–24) is an error naming the item (`query_type`, `process_name/path`, `package_name`, `wifi_ssid/bssid`, `network_type`, `adhoc`…) — never silently ignored.
- IP set: u8 version must be 1, then **u64 BE** count (cap `1<<24`), then pairs of length-prefixed addresses; merge is the engine's job.
- `DomainSet`: implement the LOUDS-style succinct trie from the documented sing-box rule-set binary layout (no code copied; behavior cross-checked against a real `.srs` sample in tests) — read version byte, `read_u64s` (uvarint count + BE u64s) for leaves and label bitmap, uvarint length + bytes for labels; validate `ones == zeros + 1` and `labels.len() == zeros`; `has()` walk: reversed key, `\n` root label = self+subdomains, `\r` prefix label = subdomains only. Write a test-only `build()` encoder under `#[cfg(test)]` for fixture generation.
- `matches(host)`: ASCII-lowercase the host only when an uppercase char is present (`Cow`), then the trie walk.
- Tests build `.srs` bytes with `flate2::write::ZlibEncoder` + the test-only `build()`:
  - default rule with domain set + keyword + regex + ip range + port/port_range + network;
  - logical `and`, `or`, and invert;
  - unsupported item (`process_name`) errors by name;
  - bad magic, version 6, truncated zlib error;
  - domain set semantics: exact, `\n` suffix matches self+subdomains, `\r` prefix matches subdomains only, dot-boundary (`xfoo.com` ≠ `foo.com`).

### T4 — `leas-geoip`: sync country lookup + load gate

File: `crates/leas-geoip/src/lib.rs`.

Add:
```rust
impl GeoIp {
    /// Ensure the mmdb is on disk and open (serialized like the first lookup).
    pub async fn ensure_loaded(&self) -> anyhow::Result<()>;
    /// Sync, cached country ISO code (lowercase) for routing decisions.
    /// Returns None when the db is not loaded yet or the IP has no country.
    pub fn country_sync(&self, ip: std::net::IpAddr) -> Option<std::sync::Arc<str>>;
    pub fn is_loaded(&self) -> bool;
}
```
`ensure_loaded` reuses the existing first-init block from `location_by_ip` (lock + `open_reader_healing` + `OnceCell::set`); `location_by_ip` calls it. `country_sync` uses a **separate** `moka::sync::Cache<IpAddr, Option<Arc<str>>>` (capacity 4096) so it cannot poison the location cache's `city_en`; on miss it decodes only `country.iso_code` from an already-loaded reader and returns `None` if `is_loaded()` is false.
Test: assert `country_sync` returns `None` before `ensure_loaded` on a temp path with no db; keep the existing network-gated `test_location_by_ip` and extend it to assert `ensure_loaded` + `country_sync("193.29.139.235") == Some("us")`-shaped non-empty country (`#[ignore]`, reason unchanged).

### T5 — `leas-route`: IR additions

Files: `crates/leas-route/src/ir.rs`, plus every literal site (run `grep -rn "MatchItem::Domain" --include=*.rs .`; today 20 occurrences in `leas-route/benches/decide.rs`, `ir.rs`, `engine.rs`, `compiler/{mod,xray,singbox}.rs`, `leas/src/route_compile.rs`, `leas-native/src/inbound/tests.rs`).

1. `MatchItem::Domain` gains `geosite: Vec<String>` (raw `[!]code[@attr...]` tokens, reserialized with `#[serde(default)]` not needed because this IR is not persisted; keep field order last). Every literal gets `geosite: Vec::new()` unless the test targets geo.
2. New variant:
   ```rust
   /// External sing-box rule-set sources, OR'ed. Keys are exactly the raw
   /// `file`/`url` strings; the caller resolves each to a local path in
   /// `GeoSource.rule_sets` before `Engine::build_with_geo`.
   RuleSet { files: Vec<String>, urls: Vec<String> },
   ```
3. Tag vocabulary shared by the engine and the native server:
   ```rust
   pub const PROXY_TAG: &str = "proxy";
   pub const DIRECT_TAG: &str = "direct";
   pub const BLOCK_TAG: &str = "block";
   ```
4. Doc comment on `geo_country`: tokens are country codes with optional leading `!` (reverse); `geosite` tokens likewise. Remove "inert/later task" wording.

### T6 — `leas-route`: geo source + fixture-independent matcher seam

Files: new `crates/leas-route/src/geo.rs`; `lib.rs` (`pub mod geo;`); `Cargo.toml`.

```rust
/// Country lookup seam so engine tests need no mmdb.
pub trait CountryLookup: Send + Sync {
    fn country(&self, ip: std::net::IpAddr) -> Option<std::sync::Arc<str>>;
}

#[derive(Clone, Default)]
pub struct GeoSource {
    pub geoip: Option<std::path::PathBuf>,                 // geoip.dat (CIDR mode)
    pub geosite: Option<std::path::PathBuf>,               // geosite.dat
    pub country: Option<std::sync::Arc<dyn CountryLookup>>, // mmdb mode
    pub rule_sets: std::collections::HashMap<String, std::path::PathBuf>,
}
#[cfg(feature = "geoip")]
impl CountryLookup for leas_geoip::GeoIp { fn country(&self, ip) -> Option<Arc<str>> { self.country_sync(ip) } }
```
`Cargo.toml`: `[features] default = ["geoip"]`, keep `dns = ["dep:leas-dns"]`, `geoip = ["dep:leas-geoip"]`; delete the `[package.metadata.cargo-machete] ignored = ["leas-geoip"]` block (the dependency is now visible). Add `[dev-dependencies] flate2.workspace = true`.
Tests: `GeoSource::default()` has no source; feature-off build path is covered by clippy `--all-features` and the default feature is on.

### T7 — `leas-route`: engine geo resolution and match semantics

Files: `crates/leas-route/src/engine.rs`, `crates/leas-route/src/matchers.rs`.

1. Add `CidrSetBuilder::insert_range(&mut self, from: IpAddr, to: IpAddr) -> Result<(), RouteError>` (same-family; pushes the inclusive range; reuses `merge_ranges`). Used for `.srs` ranges.
2. `Engine` API:
   ```rust
   pub fn build(rs: RuleSet) -> Result<Self, RouteError> { Self::build_with_geo(rs, &crate::geo::GeoSource::default()) }
   pub fn build_with_geo(rs: RuleSet, geo: &crate::geo::GeoSource) -> Result<Self, RouteError>
   ```
   All existing `Engine::build(...)` call sites stay untouched (74 today).
3. `compile_item` and `CompiledCond::build` take `&mut GeoCompiler<'_>` (`source: &GeoSource`, `srs_cache: HashMap<PathBuf, Arc<RuleSet>>`).
4. Resolved matchers:
   ```rust
   struct CompiledDomainItem { positive: CompiledDomain, negated: Vec<CompiledDomain> }
   enum GeoMatcher {
       None,
       Dat { positive: CidrSet, negated: Vec<CidrSet> },
       Mmdb { db: Arc<dyn CountryLookup>, positive: Vec<Arc<str>>, negated: Vec<Arc<str>> },
   }
   enum ItemMatcher {
       Domain(CompiledDomainItem),
       IpCidr { cidrs: CidrSet, private: bool, geo: GeoMatcher },
       SourceIpCidr { cidrs: CidrSet, private: bool, geo: GeoMatcher },
       ...
       /// Compiled external rule-set subtree (sing-box `.srs`).
       Sub(Box<CompiledCond>),
   }
   ```
5. `MatchItem::Domain` resolution: plain `exact/suffix/keywords/regexes` + non-reverse `geosite` tokens merge into `positive`; each reverse `geosite:!code` token is its own `negated` `CompiledDomain`. For `leas_geoip::geodata::load_geosite(path, tokens)`, merge `GeoDomains.suffix` into **both** `exact` and `suffix` (bare host + subdomains), `exact`→`exact`, `keywords`/`regexes`→same. Domain matching host selection:
   ```rust
   fn domain_host(meta: &ConnMeta) -> Option<&str> {
       match &meta.target.host {
           NetHost::Domain(d) => Some(d),
           NetHost::Ip(_) => meta.sni_host.as_deref(),   // sniffed SNI/DNS answer when present
       }
   }
   ```
   `positive.matches_domain(host) || negated.iter().any(|n| !n.matches_domain(host))`; an IP target with no `sni_host` matches no domain item (including reverse).
6. `MatchItem::IpCidr` / `SourceIpCidr`: parse `geo_country` tokens (`[!]code`); split `private` as today. Selection of data source: if `geo.geoip.is_some()` → `GeoMatcher::Dat` (one `load_geoip` call with all codes; merge non-reverse CIDRs into `positive`, each reverse code's set into `negated`). Else if `geo.country.is_some()` → `GeoMatcher::Mmdb` (positive/negated lowercase code lists). Else if any non-private geo code exists → `RouteError::Parse { rule_index, field: "geoip", message: "geoip:<code> needs geoip.dat or GeoLite2 (geoip_mode)" }`. Missing file/code errors from `leas_geoip` become `Parse { field: "geoip"|"geosite", message }` including the file and code.
   Matching: `cidrs.contains(ip) || (private && private_contains(ip)) || geo.positive.contains(ip) || geo.negated.iter().any(|s| !s.contains(ip))`; Mmdb: lookup once per candidate IP, `positive.contains(country)` or `negated.iter().any(|c| country.as_deref() != Some(c))`.
7. `MatchItem::RuleSet`: for each `files`/`urls` key, look up `geo.rule_sets`; a missing key is `Parse { field: "rule_set", message: "rule-set `<key>` was not prepared by the caller" }`; load via `leas_geoip::geodata::srs::load_rule_set` (cache by path) and compile to `CompiledCond` (see T8 semantics below). The item's matcher is `ItemMatcher::Sub(Box::new(CompiledCond::Any(each set's cond)))`; a rule-set whose all rules are `Default` uses `Cond::Any` over per-rule conds.
8. sing-box rule-set semantics (compile from `srs` types, not IR):
   - `Default`: destination group = `Any[All[domain item], All[ip item]]` where the domain item carries the raw `DomainSet` + keywords + regexes (new `ItemMatcher::SrsDomain { set: Option<Arc<DomainSet>>, extras: CompiledDomain }`) and the IP item is `IpCidr` built from `GeoRange`s; source group = source IP item; then `All[source-group?, SourcePorts?, destination-group?, Ports?, Network?]` (omit empty groups; `All(vec![])` = true). `invert` wraps the whole rule in `Invert`.
   - `Logical`: `All`/`Any` over child conds; `invert` wraps.
   - This mirrors sing-box `rule_abstract.go`: destination domain and destination `ip_cidr` are one OR group; source, ports, network are separate AND groups. The DNS-only "IPCIDR as source" quirk is not modeled.
9. `ItemMatcher` walk duties — every new variant must answer all three walks, or `needs_resolve`/decision paths silently under-match:

   | variant | `matches` | `walk_items` | `is_ip_bearing` |
   |---|---|---|---|
   | `Domain(CompiledDomainItem)` (negated sets included) | positive OR any `!negative` | visits itself | false (domain only) |
   | `IpCidr`/`SourceIpCidr` with `GeoMatcher::Dat`/`Mmdb` | CIDR/private/geo as above, one lookup per candidate IP | visits itself | true |
   | `Sub(Box<CompiledCond>)` | `inner.eval(meta)` | `inner.walk_items(f)` | `inner.walk_items(|m| m.is_ip_bearing())` |
   | `SrsDomain { set, extras }` | set OR `extras` on `domain_host(meta)` | visits itself | false |

   No new variant is a `Protocol` item, so `needs_sniff` is unchanged (UDP sniff gating stays as today). `needs_resolve` picks up the srs IP ranges through `IpCidr`/`is_ip_bearing`.
10. Normalization stays single-owner: `CompiledDomain::build` performs the lowercasing, dot-prefixing, and empty-suffix rejection. The parser lowercases+dedupes only so that duplicate geosite entries collapse before they reach the matcher; do not add another normalization/validation layer in the engine.
11. Delete the inert-geo test `private_cidr_matches_private_ranges_and_geo_country_is_inert` and the `#[allow(dead_code)]` on `geo_country`.
12. Tests (feature default on, temp files written by T2/T3 test-style encoders duplicated minimally in this test module — a 25-line varint/len-field writer and a `flate2` writer):
    - geosite dat token routes matching subdomain and bare host, other host falls through; reverse token flips the result;
    - geoip dat positive/reverse membership (reverse matches an IP outside the set);
    - mmdb mode with a fake `CountryLookup` map: membership + reverse, lookup called at most once per candidate IP;
    - domain rules use `sni_host` when the target is an IP; IP target without SNI matches neither positive nor negative;
    - `.srs` rule-set: domain+ip group OR, port gate AND, logical/invert, unsupported item → build error naming it;
    - missing `.dat`/code/rule-set key/tag → `RouteError::Parse` with `field` `geosite`/`geoip`/`rule_set` and the code/path in the message;
    - feature-off (`#[cfg(not(feature = "geoip"))]`): a geo item yields `RouteError::Unsupported("geo matching requires the geoip feature")`.

### T8 — `leas-route` compilers

Files: `crates/leas-route/src/compiler/xray.rs`, `compiler/singbox.rs` (+ their tests), `compiler/mod.rs` doc.

xray:
1. `DomainBucket` gains `geosite: Vec<String>`; `collect_domain` pushes `rest` for `geosite:<rest>` instead of erroring; `ext:`/`ext-domain:` stay unsupported.
2. `collect_ip`: strip an optional `!` prefix (reverse) and an optional `!` after `geoip:`; push `format!("{bang}{cc}")` where `bang` is `"!"` iff the final reverse is true; `private` stays non-reversed.
3. `DomainBucket::is_empty` includes `geosite`; rule `MatchItem::Domain` construction passes `geosite`.
4. Replace `unsupported_dat_geosite_is_positional_error` with `geosite_token_maps_to_ir_domains` (IR `geosite == ["cn"]`), and add a reverse-geoip IR assertion.

sing-box:
1. `route.rule_set` declarations → `HashMap<String, RuleSetRef>` where `struct RuleSetRef { files: Vec<String>, urls: Vec<String> }`. Rules: `type` must be `"local"` (needs `path`) or `"remote"` (needs `url`); `format` absent or `"binary"` (`"source"` → `RouteError::Unsupported("source rule-sets are not supported; use binary .srs")`); `type:"inline"` → same Unsupported; missing/duplicate tag → `Parse`; unknown declaration keys warn under `CONFIG_WARNING_INDEX`.
2. Remove the config-level "ignoring rule_set declarations" warning.
3. `check_rule`: drop the `rule_set` Unsupported arm; add `"rule_set"` to `KNOWN_RULE_KEYS` (array length 19).
4. Thread the declaration map through `compile_rule` → `collect_items` and `logical_cond`; in `collect_items`, `rule_set` array of tags → for each tag `files.extend`/`urls.extend`; unknown tag → `Parse { field: "rule_set", message: "unknown rule_set tag `<tag>`" }`; emit one `MatchItem::RuleSet { files, urls }`. A rule that has only `rule_set` is a valid condition.
5. Update the module mapping table and replace `brief_sample_rule_set_ref_is_unsupported` / `child_rule_set_ref_inside_logical_rule_is_unsupported` with positive tests: local path and remote URL produce IR; source format and inline are Unsupported; unknown tag is Parse.

### T9 — `leas-config`: geo mode

Files: `crates/leas-config/src/app_config.rs`, `crates/leas/src/ops/settings.rs`, `crates/leas/src/ui/settings.rs`.

```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoIpMode { #[default] Dat, Mmdb }

pub struct GeoConfig { /* existing fields */ #[serde(default)] pub geoip_mode: GeoIpMode }
```
Default impl sets `geoip_mode: GeoIpMode::Dat`.
- `ops/settings.rs` read map for `SpeedTest`: add the currently missing `("geoip_url", ...)` and `("geoip_mode", match mode { Dat => "dat", Mmdb => "mmdb" })`.
- Write branch: parse `"mmdb"` → `Mmdb`, anything else → `Dat`; at the end of the same branch call `state.spawn_routing_engine_rebuild();` (defined in T10).
- `ui/settings.rs` `SpeedTest` field defs: append `("geoip_mode", "GeoIP Mode", "Select:dat,mmdb")` after `geosite_url`.
- Test: serde round-trip default `Dat`; settings save with `geoip_mode=mmdb` sets the enum and triggers a rebuild (assert via a spy counter in T10's cell or just the enum; do not spawn network in tests — the rebuild runs against empty rules).

### T10 — `leas`: geo acquisition + engine lifecycle

Files: new `crates/leas/src/ops/geodata.rs`; `ops/mod.rs`; `state.rs`; `main.rs` only if a spawn must move.

Public surface:
```rust
pub struct EngineSlot { pub engine: Option<Arc<Engine>>, pub error: Option<String> }
pub type EngineCell = Arc<parking_lot::RwLock<EngineSlot>>;
pub fn config_dir() -> PathBuf; // dirs::config_dir().unwrap_or(".").join("leas")
pub fn new_cell() -> EngineCell;

/// Pure: which assets `rules` reference.
pub struct GeoNeeds { pub geosite: bool, pub geoip: bool, pub rule_files: Vec<String>, pub rule_urls: Vec<String> }
pub(crate) fn scan_rules(rules: &[RoutingRule]) -> GeoNeeds;

pub async fn compile_routing_engine(
    cfg: &AppConfig,
    rules: &[RoutingRule],
    geo_ip: Option<&Arc<leas_geoip::GeoIp>>,
    dns: Option<Arc<leas_dns::DnsResolver>>,
    dir: &Path,
    force_refresh: bool,
) -> anyhow::Result<Arc<Engine>>;

pub async fn rebuild(
    cell: &EngineCell,
    lock: &tokio::sync::Mutex<()>,
    cfg: &AppConfig,
    rules: &[RoutingRule],
    geo_ip: Option<&Arc<leas_geoip::GeoIp>>,
    dns: Option<Arc<leas_dns::DnsResolver>>,
    dir: &Path,
    force_refresh: bool,
);

/// Menu action: force-download referenced assets and rebuild now.
pub fn refresh_geo(state: &AppState);
/// Interval loop, only when `auto_update`; skipped first tick, exits on shutdown.
pub fn spawn_auto_update(cell: EngineCell, lock: Arc<tokio::sync::Mutex<()>>, cfg: AppConfig, geo_ip: Option<Arc<leas_geoip::GeoIp>>, dns: Option<Arc<leas_dns::DnsResolver>>, db: Arc<Database>, shutdown: Arc<AtomicBool>);
```
`scan_rules`: `geosite = any row.domains token starts_with("geosite:")`; `geoip = any row.ips token starts_with("geoip:")` after stripping one leading `!` and whose code (case-insensitive) != `private`; `rule_files` = every `row.rule_set_file`; `rule_urls` = every `row.rule_set_url`.

`compile_routing_engine`:
1. `dir/{geoip.dat, geosite.dat}`; `geosite` needed → if `force_refresh || !path.is_file()` → `leas_geoip::fetch_validated(&cfg.geo.geosite_url, &path, MAX_GEO_DAT_BYTES, |p| geodata::validate(p).map(drop))`; same for `geoip.dat` when mode is `Dat`.
2. Mode `Mmdb` + geoip needed → `geo_ip` must be `Some` (`anyhow::bail!("geoip_mode=mmdb needs the GeoLite2 database")`), then `ensure_loaded().await?`; set `GeoSource.country`.
3. Rule sets: for each needed url → `dir/rule-sets/<url_cache_key(url)>.srs`; download when absent/forced, validator `|p| geodata::srs::load_rule_set(p).map(drop)` with `MAX_RULE_SET_BYTES`. Insert `url → path`; insert every needed local file `file → PathBuf::from(file)`. A local file that does not exist is left to the engine build error (it names the path).
4. Compile rows in `sort_order` (caller passes `get_all_routing_rules` order): `rule_from_row(row, index)`; on `Err`, `tracing::warn!(target: "tui::ops::geodata", ...)` and skip that row (same policy the subscription path already uses); `warnings_from_row` are logged at `warn`.
5. `RuleSet { rules, default: Route { tag: PROXY_TAG }, resolve_strategy: IfNonMatch, probes: vec![] }`.
6. `tokio::task::spawn_blocking(move || Engine::build_with_geo(ruleset, &source)).await??`; then `with_resolver(Arc::new(DnsSinkAdapter { resolver }))` when `dns` is `Some`.

`rebuild`: acquire `lock`, call `compile_routing_engine`, write `cell` (`engine: Some`, `error: None` / `engine: None`, `error: Some(msg)`), log info/error. A failed build never leaves the previous engine installed (fail closed).

`refresh_geo(state)`: clone the inputs, `tokio::spawn(rebuild(..., force_refresh: true))`; logs the outcome.

`spawn_auto_update`: only if `cfg.geo.auto_update`; interval `Duration::from_secs(cfg.geo.update_interval_hours.max(1) * 3600)`; each tick `db.get_all_routing_rules().await`, then `rebuild(..., force_refresh: true)`; select on a 100 ms shutdown poll like `subscriptions::spawn_auto_update`.

`AppState`: add `pub routing_engine: EngineCell` and `pub routing_rebuild: Arc<tokio::sync::Mutex<()>>`; init `geodata::new_cell()` / `Arc::new(...)` in `AppState::new`; after the existing whitelist spawn, spawn the initial `rebuild(..., force_refresh: false)` and `spawn_auto_update(...)`. Add `pub fn spawn_routing_engine_rebuild(&self)` that snapshots (cfg, rules, geo_ip, dns, dir) and spawns `rebuild`; call it from `profiles::reload_routing_rules` after the rows load (so every delete/reorder/save path is covered).
Tests: `scan_rules` table (dat/geosite/private/rule-set/no rules); a `compile_routing_engine` test with a pre-placed empty-but-valid `.srs` (`b"SRS\x05\x78\x9c\x03\x00\x00\x00\x00\x01"`) and a bogus URL succeeds without network; a missing `.srs` URL with an unreachable HTTP URL errors and the cell keeps `engine: None`.

### T11 — `leas-native`: server accepts a compiled engine

Files: `crates/leas-native/src/server/mod.rs`, `crates/leas/src/ops/native_connect.rs`.

1. `ServerConfig` gains `pub engine: Arc<Engine>`; `pub fn new(listen, proxy, telemetry, engine: Arc<Engine>) -> Self` keeps `udp: true`.
2. `NativeCoreServer::start` removes its internal `Engine::build` and builds outbounds:
   ```rust
   let outbounds = vec![
       Outbound { tag: DIRECT_TAG.to_owned(), kind: OutboundKind::Direct },
       Outbound { tag: BLOCK_TAG.to_owned(), kind: OutboundKind::Block },
       Outbound { tag: PROXY_TAG.to_owned(), kind: OutboundKind::Proxy(Box::new(cfg.proxy)) },
   ];
   ```
   Import the tags from `leas_route::ir`; delete the local `PROXY_TAG`.
3. `run_native_session` gains `engine: Arc<Engine>` and passes it to `ServerConfig::new`; `connect.rs` supplies it (T12).
4. Update the module doc: the default route is proxy-all, but a supplied rule set may name `direct`/`block`/`proxy`.
5. Test in `server/mod.rs` (bind `127.0.0.1:0`): an engine with `default: Route { tag: "block" }` makes a SOCKS CONNECT answer `0x02`; an engine with `default: Route { tag: "direct" }` to a local echo listener relays. This proves the supplied engine and both non-proxy outbounds are live.

### T12 — `leas`: live routing wiring + fail closed

Files: `crates/leas/src/ops/connect.rs`, `state.rs`, `ops/native_connect.rs`.

- In `connect_to_profile`, before the task spawn, capture `cfg: AppConfig`, `rules: Vec<RoutingRule>`, `cell`, `lock`, `geo_ip`, `dns`, `dirs = geodata::config_dir()`.
- Inside the spawned task, before `run_native_session`:
  ```rust
  let engine = match geodata::engine_for_connect(&cell, &lock, &cfg, &rules, geo_ip.as_ref(), dns.clone(), &dirs).await {
      Ok(e) => e,
      Err(e) => { try_send_or_warn(&tx, CoreEvent::Error(format!("Routing rules failed to compile: {e}")), "routing_engine_error"); return; }
  };
  ```
  `engine_for_connect` (in `ops::geodata`): read the cell; if `engine` is `Some` return it; otherwise `rebuild(...)`, then return the engine or the slot error. It must never return a stale engine that was built for different rows — `reload_routing_rules`/settings saves clear/rebuild the cell (T10), and `engine_for_connect` rebuilds when the slot is empty or holds an error.
- A connect with an unresolvable geo rule therefore reports the `RouteError::Parse` text (file + code) and does not start a session. No silent proxy-all fallback.

### T13 — `leas`: DB rows → IR

Files: `crates/leas/src/route_compile.rs` (+ tests).

1. `match_items`: split `row.domains` into plain entries and `geosite:<code>` entries; `MatchItem::Domain { exact, suffix, keywords: vec![], regexes: vec![], geosite }`. A row whose domains are only `geosite:` still yields the item.
2. `ips`: strip one leading `!` as reverse; `private` (case-insensitive, after the `!`) still sets `private = true` and nothing else; other codes are pushed as `format!("{bang}{code}")`. `warnings_from_row` keeps warning only for entries that are neither CIDR nor `geoip:`.
3. New `MatchItem::RuleSet { files, urls }` from `row.rule_set_file` / `row.rule_set_url` (both present → both lists populated = OR). Remove the two "no native equivalent; ruleset refs deferred" warnings and their test assertions.
4. Outbound tag normalization in `rule_from_row`: `proxy` → `PROXY_TAG`, `direct`/`bypass` → `DIRECT_TAG`, `block`/`reject` → `BLOCK_TAG` (case-insensitive); any other tag → `Parse { field: "outbound_tag", message: "unknown outbound tag `<tag>`; native routing supports proxy/direct/block" }`.
5. Update the module doc mapping.
6. Tests: geosite-only row, mixed plain+geosite, `geoip:!cn`, `geoip:!private`, rule_set file+url, tag synonyms, unknown tag error, and the warning list without rule-set entries.

### T14 — `leas`: subscription source routing uses the shared engine

Files: `crates/leas/src/ops/subscriptions.rs`.

1. `plan_http_route(url, live, rules, engine: &geodata::EngineCell) -> FetchRoute`:
   - `live.is_none()` → `Direct`; `rules.is_empty()` → `Tunnel(live)` (unchanged).
   - slot read: `error` → `Refused(format!("routing rules failed to compile: {err}"))`; `engine: None` → `Refused("routing rules are still compiling".into())`.
   - otherwise build `ConnMeta` exactly as today and `engine.decide(&meta)`; `direct` → `Direct`, `block`/`reject` → `Refused(...)`, anything else (now only `proxy` after T13 normalization) → `Tunnel(live)`.
2. Thread `EngineCell` through `do_update_subscription` and `update_one_group`; pass `Arc::clone(&state.routing_engine)` at the three spawn sites (`update_one_group` caller in `update_all_subscriptions`, the manual refresh path, `spawn_auto_update`).
3. Tests: extend the existing `plan_http_route_cases` table with a cell holding (a) a `direct` engine, (b) a slot error, (c) an empty slot; assert the `Refused` messages name the compile error / "still compiling".

### T15 — `leas` UI: settings field + manual refresh

Files: `crates/leas/src/ui/settings.rs`, `crates/leas/src/ui/mod.rs`.

1. Settings `SpeedTest` field list: `("geoip_mode", "GeoIP Mode", "Select:dat,mmdb")` (T9 wrote the read/write sides).
2. `SPEED_TEST_MENU_ITEMS`: insert `SpeedTestMenuItem::Item("Update Geo Data")` after "Retry Failed DNS Lookups".
3. Handler: `"Update Geo Data" => crate::ops::geodata::refresh_geo(state),` (immediate; it spawns). No scheduler job — a queued task would need progress plumbing for no benefit.
4. No `menu_item_disabled` entry: the action is idempotent and serialized by the rebuild mutex.

---

## Critical files & anchors

- `crates/leas-route/src/engine.rs` — `ItemMatcher`, `CompiledCond`, `Engine::build`, `compile_item`; the whole geo contract lands here.
- `crates/leas-route/src/ir.rs` — `MatchItem::Domain`, new `RuleSet`, tag constants.
- `crates/leas-geoip/src/geodata/` — new parser owner; neutral types only (no `leas-route` import).
- `crates/leas/src/ops/geodata.rs` — new acquisition/lifecycle owner; `EngineCell` is the single routing-engine source of truth.
- `crates/leas-native/src/server/mod.rs` — outbound vocabulary (`proxy`/`direct`/`block`) and engine injection.

## Verification

Prerequisites: workspace root; network for the two `#[ignore]` rows; no running cores needed.

1. `cargo nextest run -p leas-geoip` — T1–T4 parser/fetch tests.
2. `cargo nextest run -p leas-route` — T5–T8 IR/engine/compiler tests (default feature includes `geoip`).
3. `cargo nextest run -p leas-native` — T11 server engine/outbound tests.
4. `cargo nextest run -p leas route_compile` and `cargo nextest run -p leas plan_http_route` — T13/T14.
5. `just quality-gate code` — fmt, clippy `-D warnings` over `--all-targets --all-features`, full nextest; this is the check that every `MatchItem::Domain` literal, match arm, and doc table was updated.
6. `cargo hakari generate` then `git diff --exit-code crates/leas-hakari` (manifest edits add `flate2`/`sha2`/`hex` edges); `just quality-gate deps` for machete/deny/audit.
7. Real-data parser smoke (network, `#[ignore]`): `cargo nextest run -p leas-geoip --run-ignored all geo_real_assets`. The test downloads the default `geoip_url`/`geosite_url` into a temp dir and asserts: `validate` succeeds; `load_geosite(geosite.dat, ["cn"])` has > 10 000 domains and matches `baidu.com` but not `google.com`; `load_geoip(geoip.dat, ["cn"])` has > 1 000 prefixes and contains `1.0.1.0` but not `8.8.8.8`.
8. Real-data end-to-end (network, `#[ignore]`): `cargo nextest run -p leas --run-ignored all geosite_cn_routes_direct`. Builds a `RoutingRule { domains: ["geosite:cn"], outbound_tag: "direct" }` plus `{ ips: ["geoip:cn"], outbound_tag: "direct" }`, calls `geodata::compile_routing_engine` against a temp config dir with the default URLs, then `Engine::decide`: `www.baidu.com` → `direct`, `www.google.com` → default `proxy`, `1.0.1.1` → `direct`, `8.8.8.8` → `proxy`. Second assertion: a `geosite:not-a-real-code` row makes `compile_routing_engine` return `Err` whose text contains `not-a-real-code`, and the cell keeps `engine: None`.
9. UI observation (manual, `cargo run`): Settings → Speed Test shows `GeoIP Mode` (`dat`/`mmdb`) and persists it across a reopen; the Speed Test menu shows `Update Geo Data`; selecting it writes a `tui::ops::geodata` log line with the rebuilt engine or the named error.

## Assumptions & contingencies

- **Live engine default resolution:** `ResolveStrategy::IfNonMatch` with the app DNS resolver, so a domain target can satisfy `geoip:` rules only after no earlier rule matched (xray's `IPIfNonMatch`). If this proves to delay every unmatched connection unacceptably, the fallback is `AsIs` plus a documented note that `geoip:` rules need an IP target; do not add a second config knob without asking.
- **mmdb mode semantics:** country membership comes from the same GeoLite2-City file used by endpoint enrichment; `geoip:private` remains the compiled private-range set in both modes. If the file is absent, mmdb mode is an error (no silent switch to `.dat`).
- **Config changes at runtime:** the geo auto-update loop captures `AppConfig` at spawn, like `subscriptions::spawn_auto_update`; a changed interval/URL takes effect on the next rebuild (saves do trigger a rebuild) or restart. Override only if the user asks.
- **Rule-set formats:** binary `.srs` only. `format:"source"` and `type:"inline"` are explicit `Unsupported` errors; adding source JSON later is a separate change.
- **Domain-set conversion:** `.dat` geosite `Domain` entries become `suffix`+`exact` in the engine (bare host + subdomains); `.srs` domain sets keep the succinct trie and its own self/subdomain semantics. These are equivalent for authored sets; do not "normalize" one into the other.
- **Download trust:** HTTPS to the configured URLs, UA `"leas"`, size caps, atomic rename, and a parse-validation before replace; no signature scheme is invented (none upstream ships one).
- **Startup:** the first engine rebuild is spawned, never awaited; a connect before it finishes rebuilds under the mutex and waits, then fails closed if the build fails.

## Execution notes (2026-11-09)

- **Domain-set representation (deviation from T3/T7):** the `.srs` domain set is decoded from the on-disk unary-degree trie into materialized sorted key sets (`KeySet { blob, ends }`) and matched by binary search / dot-boundary suffixes, instead of keeping the LOUDS bitmap and a rank/select walk in memory. Reason: licensing — the rank/select implementation would have been a derivation of BSL-1.1 `thirdparty/unbihex`; the replacement reads the same format but is independently written. Test fixtures now use one committed byte constant, not a test-only encoder.
- **Review fixes folded in:** `spawn_routing_engine_rebuild` clears the engine slot before spawning (fail closed during the rebuild) and snapshots carry a monotonic generation so an out-of-order older rebuild cannot install; a changed geo URL/mode calls the forced `refresh_geo` instead of a non-forced rebuild; a DB read error in `reload_routing_rules` keeps the previous rows instead of wiping them; the engine classifies reverse geosite tokens with the same `split_reverse` (trim + toggle) as the dat parser.
- **Refresh failure:** a failed forced download keeps the existing artifact and rebuilds from it; only a missing artifact fails the build.
