# CompactStr across the workspace — implementation plan

Date: 2026-11-13
Evidence: `docs/research/2026-11-13-allocation-profile.md` (the `leas-memtrace` runs)
Domain: **in-memory string traffic** — `crates/leas-geoip`, `crates/leas-route`,
`crates/leas`, and `crates/leas-db` if a spike allows it
Execution route: **staged, inline per stage** — each stage is independently
shippable and independently gated.
`User confirmation required: no for C1/C2; yes for C3+` (C3 crosses into the render
loop and changes view types used by every screen).

## 1. Goal

Replace owned `String` with `compact_str::CompactString` in the **in-memory**
structures where a value is short and is copied, so the ~88% of geo domains that fit
inline (≤24 bytes) stop touching the allocator at all, and the UI's per-frame string
work stops allocating for short cells. No wire, schema, or on-disk change.

Acceptance is per stage, measured with the same instrument that found the problem:

| stage | metric (same 11 s boot run, same sandbox) | now | target |
| --- | --- | ---: | ---: |
| C1 | isolated `load_geosite` allocations per load (`memtrace geosite`, 14 categories) | **1 543** | ≤ 400 → **170 achieved** |
| C3 | `leas::ui` allocations | 2 476 911 | ≤ 1 200 000 |
| C4 (if allowed) | `leas::ops::profiles` allocations | 210 151 | ≤ 120 000 |

Session total for scale: 2 798 618 allocations. C3 is the only stage with a chance to
move that number materially; C1/C2 are correctness-of-model work with a bounded win.

## 2. Evidence

- Isolated loader, measured by the new workload (`target/release/memtrace geosite 20`
  with the 14 categories this machine's rules reference): **30 860 allocations for 20
  loads = 1 543 per load**, 180 735 B peak — i.e. ≈1 474 materialized domains plus map
  and per-entry overhead. That is the number C1 targets.
- App-level pipeline after the batching fix: `leas_geoip::geodata::dat` 1 590
  allocations (3 033 549 B churn) + `leas_route::engine` 25 (829 022 B) per build. The
  two views differ because the app's build and the isolated load do not run the same
  token set, and the engine row's 25 is not yet reconciled with a spec→matcher step
  that clones every suffix domain; the isolated number is the one C1 can move, and C2
  is conditional on the app A/B moving its row.
- The dataset this machine uses: 24 categories, 3 130 domains; **2 751 (87.9 %) are
  ≤24 bytes**, mean 15.8, max 72; a build materializes 1 474 of them (the 14
  categories the rules reference).
- `leas::ui` 2 476 911 allocations / 97 055 409 B churn in 11 s — per-frame work, the
  single largest row; `leas::ops::profiles` 210 151 / 18 199 785 B (page load + row
  projection); `leas-geoip` and `leas-route` together are 0.06 % of the session.
- Dependency: `compact_str = "0.10.0"` is **already** in
  `[workspace.dependencies]` (`Cargo.toml:102`) and `leas-native` already uses it
  (`host_key`/`ip_key` in `inbound/mod.rs`). `0.9.1` in the lock is transitive
  (ratatui); nothing to add, only `compact_str.workspace = true` per crate that opts in.

## 3. Why not "everywhere"

`CompactString` stores ≤24 bytes inline and allocates above that, in a 24-byte
struct — the same size as `String`. It wins where a value is **short and owned**; it
loses nothing where a value is long (it allocates, exactly like `String`) and is
pointless where the value is already shared (`Arc<str>` — the matcher tags, the
`Country` codes — or `&'static str`).

The measured ceiling on this machine: materializing every domain in the file would
save at most ~3 130 allocations (loader) plus their per-rule copies, against 2.8 M in
a session. The plan therefore sequences by measured mass, not by grep count.

## 4. Stages

### C0 — the type boundary (answered during planning)

1. **toasty models: impossible without a newtype, and not worth it.**
   `toasty-0.11.0/src/schema/field.rs` implements its `Field` trait through an
   `impl_field_primitive!` macro over `String`, `Uuid`, `bool`, `isize`, `usize` (plus
   a hand-written `Vec<u8>`); `CompactString` is not among them, and the trait and the
   type are both foreign, so the orphan rule forbids us from implementing it. A model
   column would need a local newtype wrapping `CompactString` plus `Field`/`Load`
   plumbing — a storage abstraction bought for a profiling win. **Decision: model
   rows (`Endpoint`, `ProfileStats`, `Protocol`) keep `String`.** C4 is scoped to
   derived view types only.
2. **serde.** Only needed where a converted type is serialized; the C1–C3 types are
   not, so the workspace dependency stays without the `serde` feature until a stage
   needs it (one line to add, not a blocker).

### C1 — geo loader (`crates/leas-geoip`)

C1.0 (done while planning): `memtrace geosite` — a workload that loads the dataset for
`LEAS_GEOSITE_CODES` from `LEAS_GEOSITE_PATH`, with `leas_geoip` added to the tracer's
roots, so the loader has an isolated, repeatable allocation number (1 543 per load).

Types: `GeoDomains::{exact,suffix,keywords,regexes}`, `RawDomain::{value,attrs}`,
`SiteToken::{raw,code,attrs}`, `IpToken::{raw,code}`.
Keep the `.dat` and `.srs` readers otherwise unchanged; `normalize()` (sort/dedup/
retain) is type-agnostic.

Acceptance: `cargo nextest run -p leas-geoip`, the existing byte-exact fixtures, and
`memtrace geosite 20` ≤ **400 allocations per load** (from 1 543): the 12 % of
domains longer than 24 bytes still allocate, the rest must not.

### C2 — matchers (`crates/leas-route`)

Types: `DomainRulesSpec::{exact,suffix,keywords,regexes}`, `CompiledDomain`'s two
`RapidHashSet<String>` sets, and the `DoubleArrayAhoCorasick` keyword build.
`CompactString: Borrow<str> + Hash + Eq + Ord` by construction, so `suffix_hit` keeps
probing with `&str` and the automaton builder takes the same `AsRef<[u8]>` items.

Acceptance: `cargo nextest run -p leas-route` (the geo tests assert exact match
semantics and error attribution), plus the app A/B. **Conditional:** the app's engine
row measured 25 allocations while `compile_domain_item` clones every suffix domain into
`exact`, and that split is not reconciled with the isolated loader's 1 543 — so C2
ships only if the A/B shows the engine row moving. If it stays ≤50 allocations after
C1, C2 is dropped with that evidence rather than merged for symmetry.

### C3 — render-side view types (`crates/leas/src/ui`)

Prerequisite: the instrument cannot say *which* call path owns the 2.47 M
allocations, because the folded artifact weights **live bytes** (and live is ~0 for
per-frame temporaries). Add one knob to `leas-memtrace` before spending effort here:

- `LEAS_MEM_TRACE_FOLD=allocs` → `artifact::snapshot` weights each folded stack by
  the symbol's total allocation count instead of live/peak (the counters already
  exist in `table::Stats`; ~5 lines in `artifact.rs`). Caution: the folded path is
  recorded per **symbol id**, so the weight is that symbol's own allocation count,
  not the whole stack's — enough to rank which symbol to convert first, not a
  per-frame call-path cost.

Then convert, in measured order: `DisplayRowData`/`PanelRow` fields (20 owned
`String`s per row, rebuilt on the dirty bits), the status bar and the log/host cells
that format per frame. Leave `format!` call sites that produce a value used once
(they still allocate once either way; `CompactString` as a `write!` target is the
conversion that pays).

Acceptance: `leas::ui` ≤ 1 200 000 in the same boot run, no visual change, and the
frame-rate behaviour unchanged (the same PTY script drives both runs).

### C4 — profiles projection (`crates/leas`) — derived rows only

`EndpointRow` wraps toasty models, and C0 closed the model path. What remains is the
projection's own layer: the `DisplayRowData`/`PanelRow` values C3 already converts,
plus whatever `profiles_query` materializes outside the models. No `leas-db` type
changes, no `Field` impl.

Acceptance: `leas::ops::profiles` ≤ 120 000, `leas` suite green.

### C5 — config/import (`crates/leas-config`) — only if a trace asks for it

No measurement currently puts import parsing in the top rows; the 109 `format!`/
`to_string` sites in that crate are mostly cold. Deferred with that reason.

## 5. Compatibility boundary

- No wire bytes, no schema, no `user_version`, no on-disk format.
- Public types of publishable crates change (`GeoDomains`, `DomainRulesSpec`); the
  workspace is at 0.1.0 and `publishing.md` is the release order, so this is a normal
  change, not a breaking one.
- `leas-hakari`: adding `compact_str.workspace = true` to more crates can add feature
  edges → `cargo hakari generate` after each manifest change; `just quality-gate deps`
  must stay green.

## 6. Verification (every stage)

`cargo fmt --all` · `cargo clippy --workspace --exclude leas-oracles --all-targets
--all-features -- -D warnings` · `cargo nextest run` (workspace Summary line) ·
`just hotpath` (must stay 5/5 — nothing here touches the vless/tls paths, so a change
is a finding) · the traced boot run for the stage's metric.

## 7. Risks

- **Wrong layer.** Converting the loader while the matcher still stores `String`
  re-materializes the value at the spec→matcher step; that is why C1 and C2 are one
  stage pair, not two.
- **Long values.** 12 % of geo domains exceed 24 bytes and keep allocating; the win is
  proportional to the short share, which is measured, not assumed.
- **toasty coupling (C4).** A model field type change is a database-adjacent change;
  the spike decides it before any edit, and the fallback (derived rows only) is a
  smaller but safe slice.
- **Cold-path churn.** Converting strings that are touched once per import is pure
  diff; the plan gates C5 on a measurement.
- **Feature surface.** `compact_str`'s `serde` feature is enabled once at the
  workspace level; leaving it off keeps the dependency smaller but blocks C4.

## 8. Retirement

Each stage converts a type completely — no `String`/`CompactString` duality, no
`From` shims kept "for later". `leas-native`'s existing `CompactString` use is the
only precedent and needs no change.

## Execution note (2026-11-13)

**C1 + C2 executed** (`GeoDomains::{exact,suffix,keywords,regexes}`,
`RawDomain.value`, `DomainRulesSpec`, `CompiledDomain`'s two sets, and the automaton
input are `CompactString`; IR literals convert once at the compile boundary).

Measured, same sandbox and workload:

| metric | before | after |
| --- | ---: | ---: |
| isolated loader (`memtrace geosite 20`, 14 categories) | 30 860 → 1 543/load | **3 400 → 170/load** (−89%) |
| app boot: `leas_geoip::geodata::dat` | 1 590 | **217** |
| app boot: `leas_route::engine` | 25 | **25** |
| app boot: geo pipeline (sum) | 1 615 | **242** (−85%) |
| app boot: session allocations | 2 798 618 | **2 773 182** |
| app boot: geo churn | 3 862 571 B | 3 844 259 B |

One intermediate finding paid for itself: the first version of `CompiledDomain::build`
lowercased every entry with `CompactString::to_lowercase`, which moved
`leas_route::engine` to **2 224** allocations — more than the loader saved. The fast
path (skip the copy when the value is already lowercase, the common case) put it back
to 25. The lesson is recorded here because the same trap applies to any later stage
that "just lowercases" a stored string.

**C3 closed by measurement — CompactStr is the wrong lever there.** The
allocs-weighted fold (`LEAS_MEM_TRACE_FOLD=allocs`, added with C3's prerequisite) puts
**2 476 918** allocations under `leas::ui` and only **32 177** under
`leas::ui::profiles`. The tracer charges an allocation to the innermost frame whose
module is a traced root (`attrib::row_for`), so work reached from `ui/mod.rs` is
charged to `leas::ui` even when the allocation happens in a dependency — that is where
the 2.47 M comes from, not from our string building. Precisely: it is "allocations
reachable from `ui/mod.rs`, mostly in non-workspace code (ratatui widgets, `Text`/
`Line`/`Span` construction, buffer writes)", not "2.47 M in ratatui" — frames resolve
by instruction pointer before attribution (`attrib::module_of`), so inlined or outlined
code can resolve to its caller, and `<untraced>` only counts stacks with no workspace
frame at all. Our own view-type strings are the 32 177: converting
`DisplayRowData`/`PanelRow` to `CompactString` would touch ~1 % of the UI mass for a
large diff.

The remaining lever on that mass is **rendering work per draw** (draw count, cell
count, styled-span construction), not the string type — a separate problem with its
own plan. No C3 code was written on a guess.

If that plan is picked up, the attribution order is: (a) a single-frame micro-harness
that calls `render` twice on a mock state under the tracer, which separates ratatui's
per-draw cost from ours in one number; (b) if per-draw dominates, the draw cadence and
cell count; (c) if per-event work dominates, `refresh_aggregates`, `poll_core_events`
and `reload_profiles_preserving_selection`, all defined in `ui/mod.rs`, which run
whenever a core event lands.

**C4/C5:** unchanged (C4 = derived rows only; C5 deferred).
