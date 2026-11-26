# Undialable-shape boundary, second pass — implementation

Date: 2026-11-26
Spec: [`specs/2026-11-26-undialable-shape-boundary-second-pass-design.md`](../specs/2026-11-26-undialable-shape-boundary-second-pass-design.md)
Status: **executed 2026-11-26.** Decisions taken: U1/U3/U5/U6 ship; D2 approved (all three
pins refuse legacy flows — sing-box verified at its pinned `sing-vmess` revision
`a0c58542bd9d`: `NewClient` accepts only `""`/`xtls-rprx-vision`); D3 approved; D1 stays
**no**.

Evidence: `leas-proto` 493/493, `leas-config` 265/265, `leas-db`
`invalid_shapes_are_retired_once` green (U1 arm, U6 rewrite-before-purge ordering, the
deprecated-flow verdict and all three marker stamps in one fixture), `leas`
`purge_label_outranks_the_untestable_marker` green.

`just quality-gate code` — **3/3 passed** on the final tree: fmt-check PASS, clippy PASS
(`--workspace --exclude leas-oracles --all-targets --all-features -D warnings`; the one
finding was `too_long_first_doc_paragraph` on the new `normalize_flow` doc, fixed), nextest
**3092 passed, 12 skipped** (2 slow) in 127 s.

## Task order and why

| T | Task | Crate | Depends |
| --- | --- | --- | --- |
| T1 | `is_undialable_shape` + the VLESS `encryption` arm; doc comment corrected (U1/U5) | `leas-proto` | — |
| T2 | `normalize_flow` collapses repeated `-udp443`; re-exported as `normalize_vless_flow` (U6) | `leas-proto` | — |
| T3 | `is_deprecated_shape` (flows outside `{vision, vision-udp443}`) (D2) | `leas-proto` | T2 |
| T4 | `rekey::normalize_flow_once` — rewrite stored flows, rekey identities — wired into `schema::migrate` **before** both purges, stamped on the fresh path | `leas-db` | T2 |
| T5 | `purge_invalid_shapes_once` marker 3 → 4; `purge_deprecated_flows_once` (`deprecated_flows_purged` v1), both via one shared helper | `leas-db` | T1, T3, T4 |
| T6 | `validate_vless_shape` refuses a flow outside the canonical pair (gate for D2) | `leas-config` | T3 |
| T7 | Cell precedence: `purged` before `untestable` (D3) + ADR 0003 amendment | `leas` + docs | — |
| T8 | Gate run, spec/INDEX status, `docs/reference/database.md` markers | docs | all |

Ordering constraint (load-bearing): T4's normalisation must run **before** T5's purges.
`schema::migrate` already runs `normalize_encryption_once`; the flow step lands beside it, and
`purge_*_once` keeps running from `Database::open`, i.e. after `migrate` returns. A doubled
suffix must be repaired, not retired.

## T1 — the predicate

- `proto_spec/mod.rs::is_undialable_shape`: the `Vless` arm returns
  `(flow.is_some() && !layered) || cfg.validate().is_err()`. One owner for the encryption rule
  (the parser's `normalize_vless_encryption` and `capability`'s `VlessConfig::validate` are the
  same law).
- Doc comment: keep "not a deprecation list", correct the flow example (no in-tree pin serves
  a legacy flow; the canonical-prefix-with-junk-suffix shape is mihomo-served and handled by
  `normalize_flow`, not by this predicate), point at `is_deprecated_shape` for the retirement
  class, keep the SS-cipher and `quic` examples.
- Tests (`rstest`, existing `transport_host_verdict` table untouched): encryption
  `aes-128-gcm` / `chacha20-poly1305` / `""` / `tls` / `non` / `ure=0` ⇒ true; valid mlkem
  string ⇒ false; absent / `none` / `auto` ⇒ false; plus one agreement row
  (`capability::vless_reason` refuses ⇒ predicate true) living in `leas-native`'s table.

## T2/T3 — normalisation and the deprecation predicate

- `normalize_flow(raw)`: `""`/`none` ⇒ `None` (unchanged); a value whose prefix is
  `xtls-rprx-vision` (case-insensitive on the prefix, lowercase suffix as feeds write it) with
  **one or more** `-udp443` suffixes ⇒ canonical `xtls-rprx-vision` / `xtls-rprx-vision-udp443`
  (collapsed, owned only when a repetition existed); everything else verbatim.
- `pub use vless::normalize_flow as normalize_vless_flow` beside `normalize_vless_encryption`.
- `is_deprecated_shape`: VLESS flow non-empty and not one of the canonical pair. Present on
  `proto_spec` next to `is_undialable_shape`, with a doc that says which ADR class it is.
- Tests: table over `normalize_flow` (`vision`, `vision-udp443`, doubled ×2/×3, `direct-udp443`
  unchanged, `visi` unchanged, `none`/empty ⇒ None); table over `is_deprecated_shape`.

## T4 — the flow-normalisation DATA step

- `rekey.rs`: `normalize_flow_once` / `stamp_flow_normalized`, marker
  `vless_flow_normalized` v1, `normalize_flow_in` mirroring `normalize_encryption_in`:
  read protocols, rewrite `vless.flow` through `leas_proto::proto_spec::normalize_vless_flow`,
  skip unchanged, `rebuild_identities`, stamp in the same transaction.
- Wire: `schema/mod.rs` existing-DB path next to `normalize_encryption_once`; migrate path
  likewise; fresh path `stamp_flow_normalized` beside `stamp_encryption_normalized`.
- Test: DB fixture with two doubled-suffix configs and one canonical row: after open the two
  are canonical, identities re-keyed, `profile_stats` rows still present, second open no-op
  (marker); a doubled row is **not** purged by either purge (ordering assertion).

## T5 — the purge steps

- Extract `purge_shapes_once(&self, marker: &str, version: i64, predicate: fn(&ProtocolConfig) -> bool)`
  from the current body; keep `stamp + scan + one transaction + rank refresh`.
- `purge_invalid_shapes_once` → `("invalid_shapes_purged", 4, is_undialable_shape)`.
- `purge_deprecated_flows_once` → `("deprecated_flows_purged", 1, is_deprecated_shape)`; called
  from `open` after the invalid-shape step (order between the two does not matter; both are
  idempotent and disjoint after T4).
- Tests: existing purge fixtures keep their verdicts; one new fixture per marker: the arm's
  row becomes `config_invalid` at bin 16, a valid row untouched, second open no-op.

## T6 — the gate

- `validate_vless_shape`: after the (unchanged) layer check, refuse a flow outside
  `{xtls-rprx-vision, xtls-rprx-vision-udp443}` with the value named. Update the two existing
  cases that assert `direct` + `tls` is accepted (S5's table) — that expectation is what D2
  retires.
- Tests: `direct`+tls refused, `direct`+none refused (layer message), `vision`+tls accepted,
  `vision-udp443`+reality accepted, `flow=none` still parses to absent and is accepted.

## T7 — the cell

- `test_cell_content`: `purged` branch before `untestable`; comments updated (the purge verdict
  is the later, stronger statement). Update the doc line that fixed the old precedence.
- Tests: `(untestable, purged)` table: both ⇒ purge label; untestable only ⇒ `[n-a]`; purged
  only ⇒ purge label; neither ⇒ existing path.
- ADR 0003: append an amendment recording the swap and its reason.

## T8 — close

- `just quality-gate code` (fmt + clippy `--workspace --exclude leas-oracles --all-targets
  --all-features -D warnings` + `cargo nextest run`).
- Update the spec's Status to implemented-with-notes, the INDEX row, and the marker list in
  `docs/reference/database.md` if it enumerates `app_meta` markers.
- Report the snapshot delta from the live DB copy (never the live file).

## Acceptance

1. `is_undialable_shape` refuses every encryption value the three pins refuse, and no in-tree
   flow shape it should not.
2. `is_deprecated_shape` matches exactly what `validate_vless_shape` now refuses at import.
3. The flow-normalisation step precedes both purges; a doubled suffix row survives as canonical.
4. Every purge step is idempotent (marker short-circuit) and leaves valid rows untouched.
5. `[n-a]` no longer masks a purge verdict.
6. Gate green.
