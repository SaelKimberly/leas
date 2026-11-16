# Import budget — Design Spec Brief

Date: 2026-10-02
Status: **draft — awaiting user decision on §6 (the defaults)**
Origin: `plans/2026-10-02-write-contention-and-dns-timing-fixes.md` task T11

---

## 1. Why this exists

The import path carries two hard-coded, unconfigurable budgets in
`ops/stream_import.rs::run_streaming_import`:

```rust
const MAX_FEED_BYTES: usize = 64 * 1024 * 1024;   // 64 MiB, decoded
const MAX_FEED_LINKS: usize = 200_000;
```

Neither is in `AppConfig`, neither has a settings row, and neither is documented anywhere except
the source. On 2026-10-01 a **90,688-profile** subscription hit the byte budget and was cut off:

```
Feed exceeded the 67108864-byte budget (67112960 bytes) — stopping with partial results
Subscription update failed: … the feed is incomplete, stored rows were kept: feed over the budget
```

The stored rows were kept (correct) and the group row was written `GroupStatus::Error` (correct),
but the Settings group list renders only the literal word `error` — the reason lives solely in the
activity log. A user with a large-but-legitimate feed has no way to raise the ceiling.

**No document in `docs/aegis/` owns import limits.** This brief creates the first owner.

## 2. Scope

Make the two budgets configurable, and make a truncated import *legible* in the UI. Nothing else.

Explicitly **out of scope**: streaming-vs-buffered import, chunk sizing (`PERSIST_CHUNK`), the
retry ladder, and any change to what happens to already-stored rows.

## 3. The shape

A new `ImportConfig` section on `AppConfig`, both fields `#[serde(default)]`:

| field | type | meaning |
| --- | --- | --- |
| `max_feed_bytes` | `u64` | decoded-feed ceiling; `0` disables the byte budget |
| `max_feed_links` | `usize` | stored-link ceiling; `0` disables the link budget |

`0` disables, because "unbounded" is a legitimate choice for a self-hosted feed and encoding it as
a magic `u64::MAX` makes the config file unreadable.

`run_streaming_import` takes the two values as parameters. **No behaviour change at the current
defaults** — see §6.

## 4. Compatibility boundary

- **No `SCHEMA_VERSION` bump.** Nothing here touches the database.
- **No rename.** These are new keys. `AGENTS.md` records that `ip_api_url` → `ip_provider` was a
  *breaking* change because `AppConfig::load` propagates a serde error and `main.rs` uses `?`; a new
  key with `#[serde(default)]` cannot fail that way, and there is no `deny_unknown_fields` anywhere.
- An existing `config.json` loads with the defaults, unchanged.

## 5. What the UI must show

`partial_import_message` already produces a good sentence. The gap is that the group list renders
only `error`. **Change:** the group list row renders the group's `error_message` (truncated) beneath
the status word, so the reason is visible where the red cell is.

The count semantics must stay honest and are a stated requirement of the message: `links` counts
what was **stored**, not what the feed held. On a budget breach the message already says
"after N link(s) stored — the feed is incomplete".

## 6. Open — the defaults (user decision)

Two questions, and I am not answering them unilaterally because both change what a user
experiences:

1. **Byte ceiling.** Keep **64 MiB** (no behaviour change, the status quo), or raise it?
   The 2026-10-01 feed that overflowed decoded to just over 64 MiB, so 64 MiB is *marginal* for a
   ~90k-profile subscription — 128 MiB would have covered it. A self-hosted feed can be far larger.
2. **Link ceiling.** Keep **200,000**, or raise it? 90,688 links fit, so this did not bind. It is a
   runaway guard, not a real limit today.

My recommendation, offered as a recommendation and not applied: **128 MiB / 200,000**. It keeps the
runaway guard, removes the marginal failure the run actually hit, and 128 MiB is still small enough
that the decoded buffer cannot exhaust memory on a normal machine.

**Correction (2026-11-16):** the last sentence above was wrong — no Settings section reads these
fields. They are `config.json`-only. See §9, which also supersedes the 128 MiB recommendation.

## 7. Verification

- A config round-trip test: a `config.json` with no `import` section loads with the defaults.
- An override test: `max_feed_bytes = 1024` cuts a feed off early and the outcome carries the
  budget reason through `ended_early` → `GroupStatus::Error` — i.e. it exercises the **existing**
  path (T5) rather than adding one.
- `0` disables: a feed over 0 bytes' worth still imports.
- `just quality-gate` green.

## 8. Retirement

No path is retired. The two function-local `const`s are removed and the values become parameters;
nothing else changes shape.

---

## 9. Decision (2026-11-16) — the ceiling is 256 MiB, and the auto-update path now honours it

A second real feed was cut off by the 64 MiB default:

```
Feed exceeded the 67108864-byte budget (67114816 bytes) — stopping with partial results
```

5,952 bytes over, on a feed the import was streaming correctly. The §6 question, left open, cost
another truncated import.

**The byte ceiling is not a memory guard, and the lab now says so.** `crates/leas/src/ops/stream_import.rs`
lab `perf_lab_a_feed_over_the_default_ceiling_imports_whole` (`--features perf-lab`, ignored) streams
a feed with the byte ceiling lifted:

| decoded feed | links | wall | peak RSS |
| --- | --- | --- | --- |
| 8 MiB | 27,855 | 2.3 s | 111 MiB |
| 80 MiB (3 KB per link) | 25,440 | 1.6 s | 99 MiB |
| 80 MiB (dense) | 277,444 | 140.7 s | 187 MiB |

10x the bytes at the same row count costs NOTHING in time or memory: the run holds one chunk plus the
batcher queue, and what does grow is per-row (the run-wide dedup sets and the persist windows), which
the link ceiling already bounds. So the byte ceiling's only job is to stop a junk stream that carries
no usable links — a wall-clock guard. A number below what a legitimate curated list decodes to
therefore buys no protection and costs data.

**Decisions.**

1. Default byte ceiling **64 MiB → 256 MiB** (`ImportConfig::default`, `leas-config`). Above any feed
   the 200,000-link ceiling admits at a real link density, so the byte guard can only fire on a feed
   that is byte-heavy relative to its links. The link ceiling stays 200,000.
2. **`spawn_auto_update` passed `ImportConfig::default()`** while the manual and batch paths passed
   `state.config.import` — a raised ceiling applied to a hand refresh and not to the scheduled one,
   which is exactly the path that runs unattended over a large feed. It now snapshots the same
   config. This was the defect that made "configure it" unreliable advice.
3. The truncation reason **names the knob and the ceiling in MiB** (`feed over the 256 MiB byte budget
   — raise import.max_feed_bytes (0 = unbounded)`), because the previous line was the only place the
   number existed and a group row could not tell a user what to change.
4. **Still not in Settings.** Raising the ceiling means editing `config.json`. A Settings →
   Subscriptions section was never implemented and is not implemented here; if a user-facing knob is
   wanted, it is its own change with its own tests.

**Verification.** `a_config_without_an_import_section_loads_with_the_previous_defaults` now asserts
the default is above every recorded truncation (67,114,816). The two budget tests that leaned on the
64 MiB default to force an early exit configure a 1 KiB ceiling instead, so the default is no longer
pinned by a 64 MiB allocation. The lab row above is the memory evidence; `cargo nextest run -p leas
-p leas-config` is the behavioural one.
