# Design: country rulesets and dataset compatibility

**Status**: implemented 2026-11-11.

## Goal

Routing is chosen per COUNTRY (`ru`, `cn`, `ir`) with a shipped `default` table
and a user `custom` table. Exactly one ruleset is active. The geo dataset
(`loyalsoldier`, `roscomvpn`) no longer selects rules — it only decides which
rules are compatible; an incompatible row is shown disabled and skipped at
compile instead of failing the engine.

## Decisions

- **D1 — A ruleset is per country, and exclusive.** Country × mode selects one
  active set; the other countries' custom rows stay stored and inactive.
- **D2 — `default` is code, `custom` is data.** The shipped tables live in
  `leas/src/ops/routing_defaults.rs` (RU from the `RoscomVPN` reference profile
  with torrent routed direct per its MIHOMO variant; CN from v2rayN's built-in
  whitelist; IR authored from the v2fly `category-ir` list — v2rayN ships no IR
  or RU ruleset, only `ExpectedIPs`). `custom` rows live in `routing_rules`.
- **D3 — Storage.** `routing_rules.ruleset` (`TEXT`, nullable, migration 20;
  `NULL` = a pre-ruleset row, treated as custom under every country). Ids of
  shipped rows are `preset:<country>:<nn>` with explicit `sort_order` appended
  below the user's rows; the seed is an upsert, so re-seeding is idempotent.
- **D4 — Mode.** `GeoConfig.ruleset: Option<RulesetMode>`; `None` means
  "never chosen" and resolves to `custom` when the database already holds rows,
  otherwise `default` — an upgrade never silently ignores a user's rules.
- **D5 — Compatibility gate.** At rebuild the datasets' category codes are
  listed (`leas_geoip::geodata::validate`, codes only) into `GeoInventory`.
  `geodata::incompatibility` is the single predicate used by both the pane
  (dim + `off`) and the build (skip + log). A rule whose `geoip:<cc>` is
  absent from the dataset but is a two-letter code stays servable through the
  GeoLite2 fallback; `geoip:private` is the engine's built-in set.
- **D6 — Per-token geoip fallback.** `GeoMatcher::Nets` resolves each token
  from `geoip.dat` first and from the country database second, accepting only
  ISO-3166 alpha-2 codes — anything else stays a named build error, so a typo
  is not silently disabled. The mmdb handle is attached in both `geoip_mode`s.
- **D7 — UI.** The Routing pane's first two lines are the ruleset header:
  `D` dataset, `C` country, `M` mode. `default` mode is read-only; `M` seeds
  the country's custom table from the shipped one on the first switch.
- **D8 — Dataset switching rewrites no rules.** A dataset change forces a
  refetch (both datasets share the artifact file names) and a rebuild; the
  active rules keep their rows and change only their compatibility.

## Non-goals

sing-box `.srs` datasets as a selector (needs per-code resolution and a code
manifest); per-service proxy groups; split DNS. Deferred with the data model
unchanged.

## Verification

`leas-route` 152 tests (fallback matrix: dat-served, mmdb-served, mixed-item,
reverse polarity, unreadable dataset, typo); `leas` ruleset tests (mode/country
selection, idempotent seed, compatibility predicate, default-table compile and
ordering); `leas-db` migration suite; workspace clippy `-D warnings` clean.
