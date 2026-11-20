# 017 — When every token of a condition field is unrepresentable the field vanishes, so the rule silently matches MORE traffic

- **Location**: `crates/leas/src/route_compile.rs:164-256` (`match_items`: the
  three drop sites), `:42-49` (bare catch-all rejection),
  `crates/leas/src/ops/geodata.rs:452-471` (warn-and-continue at engine build),
  `:477-486` (default route is PROXY)
- **Severity**: medium
- **Status**: theory (code-proven; the shape is asserted by an existing test)

## Hypothesis

A stored routing row is compiled by dropping every condition token the IR
cannot represent, and then AND-ing what is left:

```rust
// route_compile.rs:161-163
/// Builds match items in the fixed contract order; only non-empty fields
/// produce items. Unparseable `ips` entries and unknown protocols/network
/// tokens are skipped here and reported by [`warnings_from_row`].
```

Dropping a token is not neutral. Each of these fields is OR-valued inside the
row — `ips` is a set of CIDRs, `network` a mask of stack tokens, `protocols` an
OR that `split_protocol_alternation` already lowers to `Cond::Any` (`:91-117`)
— while the fields are AND-ed with each other. Dropping one entry of a
multi-entry field therefore *narrows* it; dropping the field's last surviving
item deletes the constraint and turns `A AND B` into `A` — a rule that matches
strictly *more* traffic than the user wrote. Three shapes that drop the last
item:

| Row as stored | Compiled | Matches |
|---|---|---|
| `domains: [a.com]`, `protocols: [bittorrent]` | `All([Domain])`, `:252-256` | every connection to `a.com`, any protocol |
| `ips: ["oops"]`, `ports: [443]` | `All([Ports])`, `:209-215` | every host on port 443 |
| `domains: [a.com]`, `network: "icmp"` | `All([Domain])`, `:238-246` | `a.com` on tcp *and* udp |

The third is the sharpest: `network` builds an all-false `NetworkMask`, fills it
from the recognised tokens, and pushes the item only `if mask.tcp || mask.udp` —
so a field whose tokens are all unrecognised vanishes without any item at all.

Both narrowing cases are pinned by the same test module (`:663-690`, the
`tcp,banana` row): a field that keeps one token is fail-closed. The dangerous
case is exactly zero recognisable tokens in a field that was meant to
constrain — `protocols: [bittorrent]`, `network: "icmp"`, `ips: ["oops"]`.

If the row has nothing left, it is rejected outright (`items.is_empty()` →
"rule has no match conditions", `:43-49`), and `geodata.rs:468-471` logs
`routing rule {index} skipped` and continues. Either way the connection is
routed by whatever the next rule or the default says — and the default shipped
with every engine is `PROXY` (`geodata.rs:479`).

## Evidence

The behaviour is **deliberate and pinned by a test**, which is why this is
filed as a design issue and not a regression:

```rust
// route_compile.rs:642-652
fn unparseable_ip_entry_warns_not_errors() {
    let mut r = row();
    r.ips = vec!["not-a-cidr".to_string()];
    let rule = rule_from_row(&r, 0).unwrap();
    assert_eq!(items_of(&rule).len(), 1, "only the Domain item survives");
```

`warnings_from_row`'s doc says "never silently dropped" (`:120`), and the
warnings do reach `tracing::warn!` at build time (`geodata.rs:461-466`) — but
that is a *log line during an engine rebuild*. Nothing in the DB row, the
rules table, or the profile's support verdict changes, so the user's configured
policy and the enforced policy differ with no visible signal, and the difference
is in the fail-open direction.

This contradicts the project's own refusal principle, which the same repo applies
everywhere else: an undialable config is refused by name at ingestion
(`proto_spec::is_undialable_shape`, ADR 0018 D-C/D-F) rather than healed into
something dialable, and a geo code the dataset cannot serve disables its row via
`incompatibility` (`geodata.rs:308-345`) rather than compiling to a matcher that
never matches. Route conditions are the one place a token is healed by deletion.

## Why it matters

Routing rules are a policy boundary: they decide what is proxied, what goes
direct, and what is blocked. A row that widens silently can pull traffic into
the proxy that the user routed direct (bandwidth, and a latency failure that
looks like a network bug), or fail to block what the user blocked. The
connection is not mis-routed in a way that shows up as an error — it is
routed *by a rule the user did not write*.

## Fix sketch

Make an unrepresentable token a **verdict**, not a warning:

- `match_items` returns `Result<Vec<MatchItem>, RouteError>` and errors on an
  unrecognised `protocols`/`network` token whose field would otherwise vanish
  (an unparseable `ips` entry is safe to drop only when other CIDRs survive;
  make that rule explicit instead of incidental);
- `rule_from_row`'s `Err` then reaches the same place `incompatibility` already
  reaches — the row is disabled and named, and the profile reports it — instead
  of `geodata.rs:468-471`'s warn-and-continue;
- keep `warnings_from_row` for genuinely harmless legacy noise
  (`domain_strategy`), which is what its name implies.

If lenient compilation is a deliberate product decision (a partially working
policy beats no policy), the acceptable version is fail-**closed** on the
unrecognised field: keep the row, add a matcher that can never hold, so
`A AND unrepresentable` matches nothing and the user sees traffic that stops
rather than traffic that leaks.

## Related

- **014** — the same principle on the dial side: a caller deadline as the only
  bound is a silent degradation; the project's pattern is a named refusal.
- **010/011** (native-transport) — the counterpart in the transport builder:
  a plan input read from the wrong field dispatches the wrong arm. Here a
  condition input that fails to read is deleted rather than refused.
