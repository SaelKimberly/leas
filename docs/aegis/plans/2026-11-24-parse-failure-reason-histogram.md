# Parse-failure reason histogram — implementation

## Goal

The 2026-11-24 log audit reads a window of 113 validation events in which
**87 339 links** were rejected as `other (parse)` (`docs/research/2026-11-24-log-and-failure-audit.md`
§7). The log deliberately withholds the message (it can carry the URL), so
all 87 339 collapse into one line — "parse error (details withheld: the
message can carry the URL)" — and a parser coverage gap in the feed is
invisible from the logs. The audit's stated highest-value observability
change is a **reason histogram** beside the count: the error class, never the
URL.

This plan adds that histogram: each `ParseError` variant contributes a static
tag (`invalid host`, `invalid conf`, `promotion`, …) counted per validation
run and printed beside the existing counters, bounded by the variant count.

## Architecture

- `leas-proto` owns the parse error (`proto_spec::ParseError`). It gains
  `reason() -> &'static str`: one static tag per variant, no payload.
- `leas-config` flattens a `ParseError` into `ImportError::Parse`. That
  variant keeps its text — which stays withheld from the log because it can
  carry the URL — and gains the static `reason`, so the histogram is filled
  where the rejection is counted (`file_profile`) without ever touching the
  URL.
- `ValidationSummary` counts the tags in a `BTreeMap<&'static str, usize>`
  (bounded by the number of variants, merged across streaming chunks like
  every other counter).
- The TUI's `CoreEvent::SubscriptionsUpdated` log line (`crates/leas/src/ops/events.rs`)
  appends `; parse reasons: <tag> <n>, …`.

## Tech Stack

Rust workspace (`leas-proto`, `leas-config`, `leas`), `tokio`/`nextest`. No
new dependency.

## Baseline / Authority Refs

- `docs/research/2026-11-24-log-and-failure-audit.md` §7 (reason histogram,
  `other (parse) 87 339`).
- `docs/aegis/plans/2026-11-24-writer-retry-budget-and-resolution-batch.md`
  (the previous round of this audit's fixes).
- Code: `crates/leas-proto/src/proto_spec/mod.rs` (`ParseError`),
  `crates/leas-config/src/import_export.rs` (`ImportError`,
  `ValidationSummary`, `file_profile` is in `subscription.rs`),
  `crates/leas/src/ops/events.rs` (the validation log line).

## Compatibility Boundary

`ImportError::Parse(String)` becomes `ImportError::Parse { reason, text }`.
It is a public enum of `leas-config`, but the workspace is its only consumer
(two sites: the `From<ParseError>` impl and one direct construction). The
Display text is unchanged in meaning; the summary's counters are unchanged.

## TDD Route

Mode `auto`, decision **strict** (behavior change in a shared, public parse
contract with a new field and a new log surface). Authority: this plan, per
the user's request to implement and verify the audit finding. Tests land with
the change (the workspace is not red-first by convention for additive
observability; the focused tests below are the acceptance).

## Tasks

1. `leas-proto`: `ParseError::reason()` returning a static tag per variant
   (`invalid host`, `invalid port`, `missing host`, `missing port`,
   `invalid userinfo`, `invalid hostport`, `missing conf`, `invalid conf`,
   `unknown`, `invalid structure`, `unsupported scheme`, `promotion`,
   `unimplemented`). Doc comment
   says: never the payload, which can carry the URL.
2. `leas-config`: `ImportError::Parse { reason: &'static str, text: String }`;
   the `From<ParseError>` arm sets `reason: e.reason()`; the one direct
   construction names `"missing scheme"`. Display renders `text` as before
   (`parse error: {text}`).
3. `ValidationSummary`: `pub parse_reasons: BTreeMap<&'static str, usize>`,
   `record_parse_reason(tag)`, `merge` sums the maps.
4. `file_profile`'s `ImportError::Parse` arm records the tag and keeps the
   withheld message verbatim (no URL).
5. `events.rs`: the message becomes `subscription_validation_message(summary)`
   (one builder, so the log line is testable) and appends the bounded
   histogram.
6. Tests: leas-config `subscription.rs` — a feed with two malformed URL
   classes yields the exact tag set and counts, the histogram total equals the
   parse rejection count of that feed (2), and the tag set is asserted
   verbatim (the `&'static str` type is what keeps URLs out); `merge` sums two
   chunk summaries. leas `ops::events` — the built line carries
   `; parse reasons: invalid userinfo 2, promotion 1` (BTreeMap order) and no
   suffix when the histogram is empty.

## Verification

- `cargo nextest run -p leas-config` and the two new rows by name
  (`parse_rejections_are_histogrammed_by_class`,
  `merged_summaries_sum_the_parse_histogram`).
- `cargo nextest run -p leas 'the_validation_line'` and `cargo nextest run -p leas 'ops::events'`.
- `cargo clippy -p leas-config -p leas -p leas-proto --all-targets --all-features -- -D warnings`;
  `cargo fmt --check`.

No full-suite run (user constraint).

## Risks

- Tag set grows with variants; the map is bounded by that count, so the log
  line cannot become a 90 k-entry wall.
- A wrong tag mapping misdirects a future investigation; the tags are
  asserted for two concrete inputs.

## Retirement

None: the histogram is additive. The old withheld-message line stays for every
parse rejection, alongside its class tag.

## Outcome

Implemented. `ParseError::reason()` tags every variant (`leas-proto`);
`ImportError::Parse` carries the tag beside its withheld text; `file_profile`
counts it; the validation log line appends, e.g.,
`; parse reasons: invalid conf 3, promotion 41`. Tests: two malformed classes
with exact tag counts and an exact tag set (the `&'static str` type is what
guarantees no URL can appear), a merge of two chunk summaries, and the log
line itself (`the_validation_line_names_the_parse_classes`, plus the
no-suffix case). Focused `leas-config` (252) and `leas` `ops::events` groups
green; scoped clippy and `fmt --check` clean.
