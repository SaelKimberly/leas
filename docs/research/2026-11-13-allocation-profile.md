# Allocation profile, 2026-11-13

First pass of the `leas-memtrace` instrument over the real application and the
two measured hot paths. It answers three questions: where the process allocates,
which of those sites are avoidable, and what each fix would buy. Numbers are
exact counts from the tracer (`TracingAllocator`, one snapshot per artifact); the
wall-clock durations are the run lengths, not a benchmark.

Status: instrument shipped in `crates/leas-memtrace` (§30 of
[`../architecture/decisions.md`](../architecture/decisions.md)); F1b, F1a, F2,
F5 and F6 are implemented in this tree (the geo work measured in
[Implemented](#implemented-2026-11-13)). F3 and F4 stay open, and the profile's
largest rows — `leas::ui` and `leas::ops::profiles` — are untouched.

## Sandbox correction (read first)

The first runs pointed `XDG_CONFIG_HOME` at a scratch directory and copied the
database into it, but the application resolves its data directory as
`dirs::config_dir().join("leas")` — so those runs silently opened a **fresh**
database and downloaded their own `geosite.dat` (10.9 MB) and `geoip.dat`
(15.7 MB). They measure a first-install app, not this machine's 64 577-endpoint
profile database. They are kept below as the worst case for the geo scan
multiplier: a 10.9 MB dataset makes each wasted scan expensive.

Every number in [Implemented](#implemented-2026-11-13) comes from the corrected
sandbox: the real `data.db` copied to `$HOME/.config/leas` (trimmed to 3 000
endpoints so the harness can drive it; the full database made the app stop
answering keys in this PTY driver), the real `config.json`, the real 66.8 KB
`geosite.dat` / 430 KB `geoip.dat`, the real `whitelist/` directory, and all ten
groups' `last_refreshed` pinned to "now" so no subscription refresh runs during
the measurement.

## Method

```sh
cargo build --release -p leas --features mem-trace          # system allocator + tracer
LEAS_MEM_TRACE_DIR=/tmp/trace target/release/leas           # artifacts at the exit boundary
cargo run --release -p leas-hotpath --bin memtrace -- all 5000
```

The application run used a throwaway sandbox: `HOME`, `XDG_CONFIG_HOME`,
`XDG_DATA_HOME`, `XDG_CACHE_HOME` and `XDG_STATE_HOME` pointed at a temporary
directory, into which `~/.config/leas/data.db` (83.8 MB, 64 577 endpoints,
`user_version` 20) plus `config.json` and the geo assets were **copied**. The
real installation was never opened for writing.

The app was driven through a PTY (200×50 cells) and quit with `q`, so the exit
artifacts are written after `AppState` is dropped. That makes `peak` the useful
column for a load that ends at shutdown: `live` at the exit snapshot is the
residue that survived, not the steady state.

## Where the bytes go

Run A: boot, then a Tab, five Down presses, PgDn/PgUp and three more Tabs; no
connect. 14.1 s.

| module | peak B | total B | allocs |
| --- | ---: | ---: | ---: |
| `<untraced>` | 5 416 056 | 76 727 478 | 32 380 |
| `leas_geoip::geodata::dat` | 5 259 925 | 28 126 791 | 5 473 |
| `leas_host_features` | 4 029 136 | 10 229 682 | 4 993 |
| `leas::ui` | 1 053 298 | 1 468 380 | 3 394 |
| `leas_geoip` | 882 278 | 1 481 636 | 1 590 |
| `leas::ops::geodata` | 441 137 | 6 349 292 | 6 953 |
| `leas_db::driver` | 218 016 | 2 161 884 | 18 316 |
| `leas::ui::details` | 45 592 | 153 912 | 1 319 |
| `leas_db::schema` | 29 828 | 44 917 | 169 |
| `leas::ui::profiles` | 23 152 | 131 988 | 432 |

Totals: `live 2 265 300`, `peak 9 909 131`, `allocs 76 449`, `deallocs 71 367`,
`cache: hits 1 594 577 / resolves 5 693 / evictions 416`.

Run B: boot, seven PageDown presses, five Tab presses, five Down presses;
19.0 s.
(Tab toggles pane focus — `ui/mod.rs:1211` — it does not open Settings; Settings is
the `,` popup.)

| module | peak B | total B | allocs |
| --- | ---: | ---: | ---: |
| `<untraced>` | 5 069 233 | 67 572 582 | 68 339 |
| `leas_geoip::geodata::dat` | 5 269 970 | **225 335 436** | **73 289** |
| `leas_geoip` | 1 055 298 | 1 453 880 | 1 752 |
| `leas::ops::geodata` | 703 107 | 3 296 287 | 4 594 |
| `leas::ui` | 1 052 898 | 1 456 730 | 3 516 |

Totals: `live 2 751 391`, `peak 10 861 844`, `allocs 153 523`.

The 13× jump in `geodata::dat` allocations (5 473 → 73 289) between runs A and B
was first read as UI navigation. It is not: run C — boot, one Tab, three arrow
presses, no page turns, no Settings — reproduces **73 289 allocations and
225 335 436 B exactly**, so the burst is deterministic and unrelated to the key
sequence, and it survives a 28-second run unchanged (73 289 at 10 s, 15 s, 19 s
and 28 s), so it is a one-time cost of the boot compile, not a loop. Finding F1b
identifies it in the compiler.

Those three runs are the fresh-install shape described above.

The corrected sandbox (real DB, real datasets), boot only, 11 s — `HEAD`:

| module | peak B | total B | allocs |
| --- | ---: | ---: | ---: |
| `leas::ops::profiles` | 5 017 193 | 18 199 785 | 210 151 |
| `leas_geoip::geodata::dat` | 2 288 303 | 5 871 462 | 3 878 |
| `leas::ops::enrich` | 286 773 | 455 577 | 2 509 |
| `leas::ops::geodata` | 71 419 | 74 012 | 41 |

Totals: `live 4 717 301`, `peak 10 853 976`, `allocs 2 783 464`. The profile
page load dominates (210 151 allocations for a 3 000-endpoint database, ~13 500
per second of session); the geo compile is 3 878 of 2.78 M.

**Status of these rows.** The geo figure is the pre-fix baseline: the batching
change (`Implemented`) took the pipeline to 1 615, and the CompactStr pass
(`docs/aegis/plans/2026-11-13-compactstr-cross-crate.md`) takes `geodata::dat` to
**217** and the whole pipeline to **242** per boot. The profile row is unchanged —
it is where this document's open work points.

Micro runs (`leas-hotpath`, 5 000 VLESS headers, 2 000 TLS records):

| workload | traced allocs | bytes | per operation |
| --- | ---: | ---: | --- |
| VLESS header encode | 5 000 | 250 000 | 1 alloc, 50 B |
| TLS 1.3 seal + open (16 KiB record) | 0 | 0 | in-place, no allocation |

A fourth workload (`memtrace geosite`) loads the dataset in isolation, which is what
the CompactStr plan targeted: 20 loads of the 14 categories this machine's rules
reference → 30 860 allocations = 1 543 per load, 180 735 B peak — ~1 474 materialized
domains plus map and per-entry overhead. After the CompactStr conversion in
`leas-geoip`/`leas-route` the same workload reports **3 400 = 170 per load (−89%)**,
and the app's geo pipeline drops from 1 615 to **242** allocations per boot while the
session total moves 2 798 618 → **2 773 182**.

The allocs-weighted fold (`LEAS_MEM_TRACE_FOLD=allocs`) also settles where the UI mass
is: `leas::ui` 2 476 918 allocations, `leas::ui::profiles` 32 177. Since the tracer charges an allocation to the innermost frame whose module is a traced
root, the first figure is "allocations reachable from `ui/mod.rs`, mostly in
non-workspace code (ratatui widgets, `Text`/`Line`/`Span` construction)" — not "in
ratatui": frames resolve by instruction pointer, so inlined code can resolve to its
caller, and `<untraced>` counts only stacks with no workspace frame at all. The second
figure is our own string building. Converting view types to
inline strings would touch ~1 % of that mass; the lever on the rest is per-draw render
work (draw count, cell count, styled spans), not the string type.

The record run's 4 001 allocations and 65.6 MB are the harness's own
`Vec::with_capacity` + `split_off`, charged to `<untraced>`; `leas_tls` allocated
nothing. The encryption path is allocation-free, which is the invariant to keep.

## Findings

### F1 — the routing engine recompiles more often than the inputs change

Two distinct facts, one measured and one read from the code.

**F1a (code, unmeasured).** `ui/settings.rs::load_selected_section` calls
`build_right_pane` on every selection move; `ops/settings.rs::build_right_pane`
handles the Routing group by calling `state.reload_routing_rules()`, which calls
`spawn_routing_engine_rebuild()` unconditionally (`ops/profiles.rs`). That clears
the engine slot (`EngineSlot::default()`) and runs `geodata::rebuild` →
`Engine::build_with_geo`, which re-validates and re-parses `geosite.dat`/
`geoip.dat`. Showing a pane therefore costs a full compile plus a fail-closed
routing window. No run has opened Settings yet (` ,` popup), so this path is read
from the code, not measured.

**F1b (measured).** Runs B and C both show 73 289 `geodata::dat` allocations and
225 335 436 B of churn, with an identical transient peak (5.27 MB). Identical
totals under two different key scripts mean the work is deterministic, and the
cause is in the compiler: `compile_domain_item` (`leas-route/src/engine.rs:787`)
calls `load_geosite(path, tokens)` **once per rule**, and each call rescans the
whole file. `compile_geo_country` (`engine.rs:847`) does the same for `geoip.dat`
via `load_geoip_lenient`. The profile database carries 14 rules with a `geosite:`
token and two geoip tokens, so one engine build performs 14 geosite scans plus one
per geoip-bearing rule (a rule's tokens share one scan); the measured 73 289
allocations are their sum (≈5.2k per scan, weighted by file size — `geosite.dat`
is 66.8 KB, `geoip.dat` 430 KB). `ensure_download` does **not**
re-validate an existing file, so the multiplier is exactly the number of
`load_*` calls, with no extra validation pass.

Run A (5 473, one scan) is recorded as an unexplained outlier: it ran against the
same database copy and the same config, and every later run — including two with
no key input at all and one twice as long — lands exactly on 73 289. The likely
difference is where that first process exited relative to the background compile;
it is stated as an observation, not a finding.

Proposal, in order of value:

1. **Batch the tokens, both loaders.** `load_geosite` and `load_geoip_lenient`
   already take `&[String]`; the compiler should collect every geosite and every
   geoip token across the rule set, scan each file once, and hand each rule its
   slice. 14+ scans → 2 is a −90% cut of this path with no change to the loaders.
2. **Stop allocating per entry in `scan_entries`.** `read_len_delimited` allocates
   a fresh `vec![0u8; len]` for every entry in the file and `scan_entries` builds
   a `String` for every entry's code just to test membership. Reuse one scratch
   buffer and compare the code bytes against the wanted set (lowercasing into a
   reused buffer) — both are per-entry allocations paid for entries that are
   thrown away.
3. **Memoize across rebuilds.** The parsed `GeoDomains` are a pure function of
   (file, tokens); today every rebuild re-parses. A memo keyed by path + mtime
   would make F1a's redundant rebuilds nearly free and would also fix the
   single-flight gap in `rebuild` (it takes the lock but never re-checks the slot
   after acquiring it, so several consumers that raced an empty slot each compile
   in turn).

For F1a's UI path, `reload_routing_rules` is now diff-aware: `RoutingRule`
derives `PartialEq` (all fields compared, no fingerprint needed) and the rebuild
is skipped only when the rows are unchanged and the slot already holds a result.
Still open from this proposal: keeping the previous engine installed while a
rebuild compiles, instead of clearing the slot first — so a redundant-looking
compile still has a short fail-closed window.

### F2 — the loader keeps two copies of every kept domain (medium value)

One scan of `geosite.dat` costs 5 259 925 B peak and 28 126 791 B of churn for
5 473 allocations. Beyond F1b's per-entry cost, the kept domains are materialized
twice: `decode_site_entry` allocates a `String` per domain value and a
`Vec<String>` of lowercased attributes, and `load_geosite` then copies each value
**again** into `GeoDomains` (`to_ascii_lowercase()` / `clone()`) while the
`raw: HashMap<String, Vec<RawDomain>>` intermediate is still alive.

Proposal: build `GeoDomains` directly inside the `scan_entries` callback (the
requested tokens and their attribute filters are known before the scan) and
lowercase in place on the owned `String`. Expected: roughly half the transient
peak and churn of a scan, no change to the steady state (the parsed strings die
once the matchers are compiled).

### F3 — geo compilation is eager at boot (medium value)

The routing engine is built in `AppState::new` even though its only consumers are
`engine_for_connect` and the import route gate. A session that never connects and
never imports pays the full 5.3 MB peak, ~28 MB of churn and the mmdb load. The
`EngineCell`/`engine_for_connect` seam already handles an empty slot by compiling
on demand, so this is mostly a matter of not calling `spawn_routing_engine_rebuild`
at startup (F1's fix keeps later rebuilds honest).

### F4 — the whitelist checker costs 4.0 MB at boot (medium value)

`leas_host_features::HostFeaturesChecker::new` is 4 029 136 B peak / 4 993 allocs
for a `HashSet<String>` of lowercased SNI hosts plus a bloom filter
(`leas-host-features/src/lib.rs`). It is only consulted by `ops::enrich`, and
`load` **downloads** the three files when they are missing, i.e. a fresh install
does network I/O during startup. These numbers come from the first-install runs
(where the sandbox had no `whitelist/` directory and the checker fetched it at
boot); the parse cost is the same with the files present — the corrected sandbox
loads them without downloading and no longer shows the row in the top ten.
Proposal: load on first enrich (behind the same
`Option<Arc<…>>` that already allows absence), and consider a sorted
`Vec<Box<str>>` + binary search for the exact check as a second step.

### F5 — one allocation per Vision connect (shipped)

Before: a Vision connect built an 18-byte addons `Vec` and a header `Vec` sized
to exactly the header, so the 21-byte camouflage frame that joins it reallocated
that same buffer; `.as_deref()` on the addons then copied it a second time.

Now: `encode_addons` returns the addon as a `&'static [u8]` (it is a wire
constant), and the connect path builds the header with `encode_request_into` into
the buffer `HeaderFirst` owns, reserved at `HEADER_RESERVE` = 96 bytes (the
longest header ≈56 + the camouflage frame 21), so the join never reallocs.
Plain (no-flow) connects were already one allocation and stay one.

Measured with the new `memtrace` workload: `target/release/memtrace connect 5000`
→ **5 000 allocations for 5 000 connect headers, 96 bytes reserved each** — one
per connect, and none for the addons. The full connect still has one growth when
the first payload (up to 16 KiB) joins the header; that is the single-record
property, not headroom the reserve can remove. With F6 shipped, the two relay
buffers are pooled, so a warm connect touches the allocator once (the header)
and a cold one also pays the pool's first two buffers.

### F6 — pooled relay buffers (shipped)

Each direction takes a 16 KiB buffer from a bounded free list and promotes to
64 KiB after a full read; `RelayBuf` returns its buffer on drop, and promotion
hands the small one back and takes a large one. The pool keeps at most 64
buffers per size class (2 MiB total), so it is a recycler, not an unbounded
cache: after warm-up a steady-state tunnel makes no allocator call for relay
traffic, and a cold process still allocates the first two buffers (plus one per
promotion beyond the pool).

The free lists are reserved to their cap when the pool is first used, so
returning a buffer never allocates — the return path runs from `Drop`, and
allocating while unwinding aborts.

Unit tests pin the contract: the same allocation comes back out of the pool, an
unknown size is dropped rather than pooled, the cap holds, and promotion swaps
size classes without demotion. This is not measured end to end — no tunnel was
traced — so the claim is the allocator-call count, not a wall-clock effect.

### F7 — measurement caveats worth fixing in the instrument (low value)

- The exit artifact is written after `AppState` is dropped, so `live` understates
  the steady state. A `job_boundary("idle")` after the first paint would give a
  steady-state snapshot; artifacts already carry the label.
- `<untraced>` (5.4 MB peak, 32 380 allocs) is tokio, ratatui and the turso
  driver. `LEAS_MEM_TRACE_MIN_BYTES=64` keeps the traced rows readable in a long
  session without changing what the workspace rows count.
- 416 cache evictions in 14 s against 65 536 slots: headroom is fine, but a run
  with heavy import traffic should re-check this before trusting the per-IP rows.

## Implemented (2026-11-13)

Four changes, all in this tree, verified by the cargo suite and by re-running the
same boot workload on the same sandbox.

| file | change |
| --- | --- |
| `leas-geoip/src/geodata/dat.rs` | `scan_entries` reuses one entry buffer and one code `String` across entries (`read_len_delimited_into`); `load_geosite` builds `GeoDomains` straight from the scan instead of a `raw: HashMap` it then copies; `load_geoip_lenient` accumulates per code in a slot vector instead of `HashMap<String, …>` |
| `leas-route/src/engine.rs` | `GeoCompiler::preload` collects every `geosite:`/`geoip:` token from the rule set (nested `Any`/`Invert` included, both `IpCidr` and `SourceIpCidr`) and scans each dataset **once**; `take_site`/`ip_load` serve rules from the cache, with a per-token fallback that keeps error attribution exact. `take_site` **removes** the cached entry and hands its vectors to the rule, so the preloaded parse is moved rather than cloned |
| `leas/src/ops/geodata.rs` | `rebuild` is single-flight: after the lock it returns when the same generation is already installed, so consumers that raced an empty slot do not each compile |
| `leas/src/ops/profiles.rs` | `reload_routing_rules` skips the rebuild when the rows are unchanged **and** the slot already holds a result (an empty slot is always filled — the route gate refuses a fetch while nothing is compiled) |

Measured on the corrected sandbox, same 11 s boot workload, `HEAD` versus this
tree. The engine module is included because the cache lives there: an earlier
draft cloned each cached category into the rule and moved `leas_route::engine`
from 6 to 9 154 allocations — **more** allocations overall than it removed. The
shipped `take_site` moves the vectors instead, and the module is back to 25.

| metric | before (`HEAD`) | after |
| --- | ---: | ---: |
| `leas_geoip::geodata::dat` allocations | 3 878 | **1 590** |
| `leas_route::engine` allocations | 6 | 25 |
| **geo pipeline allocations** | **3 884** | **1 615** (−58%) |
| `dat` churn | 5 871 462 B | 3 033 549 B |
| `engine` churn | 828 214 B | 829 022 B |
| **geo pipeline churn** | **6 699 676 B** | **3 862 571 B** (−42%) |
| geo pipeline peak | 2 288 303 B | **1 952 568 B** (−15%) |
| geosite scans per build | 14 | **1** |

The arithmetic is exact: one build is `14·a + b` before and `a + b` after, with
`a ≈ 176` allocations per `geosite.dat` scan and `b ≈ 1 414` for the single
`geoip.dat` scan (its 430 KB are decoded into ranges, which is why it dominates
both columns). The fix therefore removes 93% of the geosite path; the geoip path
was already one scan because only one rule carries a `geoip:` token. On the
first-install shape — where each geosite scan costs ~5.2k allocations instead of
176 — the same edit is what turns 73 289 into a single pass.

Tests added: `one_category_serves_every_rule_that_names_it` (a cached category
serves a positive and a reverse rule without leaking polarity),
`geo_tokens_are_collected_once_across_nested_rules` (collection sees nested
`Any`/`Invert`, dedupes, keeps the first rule index), and
`a_waiter_for_an_installed_generation_does_not_recompile` (single flight; a
forced refresh still rebuilds).

### Where this leaves the profile

This fix is not the app's top allocation path on a populated database, and the
report should say so: the same 11 s boot run allocates 2 476 911 times in
`leas::ui` (97 MB of churn — per-frame render work) and 210 151 times in
`leas::ops::profiles` (18 MB — one page load plus its row projection), against
1 615 for the whole geo pipeline. The geo compile was the largest *single
redundancy* (14 identical scans), not the largest consumer.

Still open, in the order the numbers now argue for them: `leas::ui` per-frame
work → `leas::ops::profiles` → F3 (lazy first-use compile) → F4 (whitelist
footprint/lazy load).
Memoizing the parsed `GeoDomains` across rebuilds (path + mtime) was **not**
implemented — the shipped cache is per-build only — so a rebuild still re-parses
each dataset once.

## Priority

| # | Change | Effect | Effort |
| --- | --- | --- | --- |
| ✅ F1b | Batch geo tokens, both loaders | shipped: −58% geo allocations, −42% churn, −15% peak | done |
| ✅ F1b | Reuse the entry buffer, no per-entry code `String` | shipped (inside the same change) | done |
| ✅ F1a | Diff-aware `reload_routing_rules` | shipped: no compile for an unchanged row set once the slot holds a result | done |
| ✅ F1a | Single-flight `rebuild` | shipped: one compile for N consumers racing an empty slot | done |
| F1b | Memoize the parsed `GeoDomains` by path + mtime | **not done** — the cache is per build, so a rebuild re-parses once | medium |
| ✅ F2 | Stream `GeoDomains` out of the scanner | shipped inside the same change (no `raw` map, one String per kept domain) | done |
| F3 | Compile the routing engine on first use | defers the whole geo pipeline (1 615 allocations, 1.95 MB peak) for sessions that never route | small |
| F4 | Lazy whitelist load + compact SNI set | defers 4.0 MB and the boot-time download | medium |
| ✅ F5 | VLESS header: constant addons + one caller-owned buffer | shipped: 2 → 1 alloc per Vision connect (measured: 5 000 allocs / 5 000 connects) | done |
| ✅ F6 | Relay buffer pool | shipped: 0 allocator calls per tunnel after warm-up, capped at 2 MiB | done |

## Steady state

After the boot compile the app is cheap: 143 464 allocations at 10 s versus
144 440 at 28 s — about 100 allocations per second while idle, which is the
render loop plus the DB monitor. The display-row cache (`ui/profiles.rs`, keyed
on `endpoints_gen` + selection + dirty bits) is doing its job; per-frame row
rebuilds are not a cost.

## Next measurements

Not covered here, in the order they matter: the import pipeline (subscription
fetch → decode → parse → dedup → write-behind), the ping batch scheduler, and a
live tunnel's relay.

The repo already has a driver for the first two: `crates/leas/src/ops/ping/flow_cost.rs`
is a `#[cfg(all(test, feature = "perf-lab"))]` lab that seeds a DB and runs
`run_batch`, `write_import_once` and `measure_page_scale` on the real code paths.
It cannot be traced as it stands — `leas-memtrace` is an optional dependency of
`leas`, so the test binary installs the default allocator and `start()` is
unreachable — which means a traced lab needs a `perf-lab`-gated dev-dependency and
its own `#[global_allocator]`. The relay needs the oracle cores. Note for any lab
run: allocations freed at a `job_boundary` drop out of `live`, so read `peak` and
`total`, not end-of-window `live`.

## Limits

What was **not** run, stated plainly:

- The Settings path in F1a is read from the code. No artifact exists for it: the
  one run that tried to navigate Settings hung on an ignored `q` after the parse
  burst had already been explained by F1b, and was not repeated.
- No connect, no import and no ping batch were traced, so F5's per-connect
  allocation count is read from `encode_request`/`HeaderFirst`/`RelayBuf` and not
  measured end to end, and F6's per-tunnel buffers are static reasoning.
- The run A outlier (one scan instead of ~16) is recorded, not explained.
- Attribution is by module path (release inlining makes function-level claims
  wrong), and the trace covers the traced process only: core children are
  invisible by construction.
