# ADR 0018 — Deprecation grounds: measured absence or evidenced harm; a peer's refusal is never enough

Date: 2026-11-19.
Status: **accepted** (user decision, 2026-11-19; recorded here so code and specs cite
authority rather than a research note).
Spec: `docs/aegis/specs/2026-11-19-probe-truth-and-ingest-boundary-design.md` (S5 is the
first consumer).
Evidence: `docs/research/2026-11-19-real-test-funnel.md` §3.1 (the rule as stated), §3.2
(the graded inventory), §3.3 (why the flows went), §3.4 (the dial experiment).

## Context

This project is a client. It speaks to servers it does not control, and it is tested against
three pinned oracles — xray-core, sing-box, mihomo — plus, for specific classes, a
fourth implementation (v2fly for XTLS Direct). Upstream projects retire features on grounds
of their own: maintenance, a replacement, or a configuration model change. Three temptations
recur when a feed carries a shape the current codecs do not dial:

1. **Retire on one core's refusal.** xray 26.x refuses `xtls-rprx-direct` at config load;
   sing-box passes the flow to its client and mihomo dials any non-vision flow as plain
   VLESS. Treating the first as the verdict would retire a variant two peers still accept.
2. **Retire for size.** Dropping a transport or cipher because it is untidy shrinks the
   corpus: ws/grpc/HTTPUpgrade carry 64 043 of 120 405 links in the measured snapshot, and
   the SS stream ciphers xray dropped are served by sing-box.
3. **Confuse invalid with deprecated.** A flow with no TLS layer, or an `ss` "method" that is
   the literal string `null`, is not a variant of anything: no core can dial it. It is an
   invalid config, and its treatment is an ingestion question, not a deprecation one.

The 2026-11-19 flow investigation also shows what does *not* count: the circulating
"XTLS Direct is actively probeable" claim traces to the "233" analysis, which the project
author refuted on mechanism (the code path exists only after the server verifies the client
UUID); the Vision write-up's padding argument applies to unpadded TLS-in-TLS handshakes in
general, which `flow=""` rows share.

## Decisions

1. **D-A — Two grounds, and only two.** A protocol, config, cipher, flow or transport variant
   may be deprecated when (a) **large sources no longer carry it** — measured, per class, with
   the count recorded — or (b) **upstream designates it unsafe, harmful or highly detectable,
   with evidence.** Upstream removal alone, code size, or resource cost is not a ground.

2. **D-B — Peer refusal is never a ground, and one oracle is never the check.** A claim of
   the form "xray refuses it" decides nothing. Any peer statement is recorded as a matrix over
   all pinned oracles (accept/refuse, client and server side where they differ), and it is
   evidence about compatibility, not about safety.

3. **D-C — Invalid is not deprecated.** A shape no shipped codec can dial is refused at
   ingestion with a named reason (`ss` method outside the native set; a non-empty `flow`
   without a TLS/REALITY layer; an unparsable `encryption` value). It is not "retired": it
   never enters the store.

4. **D-D — Stored rows follow the verdict path.** Rows already imported that the current rule
   would refuse get a persisted verdict (`config_invalid`), move to Purgatory and are retired
   by its TTL. Nothing is deleted outright: the verdict is reversible by the app's own rules.

5. **D-E — The insecure class is evidence-only.** A variant is *insecure* only under D-A(b),
   and then it is refused at ingestion behind `parsing.reject_insecure` (the existing hook)
   while stored rows take a verdict. No variant in the 2026-11-19 inventory qualifies; the
   only safety-motivated ingest refusal in the tree today is `ss` method `none` on a cleartext
   wire.

6. **D-F — What the rule keeps.** While at least one pinned oracle serves a shape, the shape
   stays supported: the ws/gRPC/HTTPUpgrade transports xray only warns about, the SS stream
   ciphers sing-box serves, the non-vision VLESS flows sing-box and mihomo accept, the legacy
   VMess ciphers sing-box and mihomo serve, and the `quic` transport sing-box ships.

7. **D-G — Measured absence is a decision, not an inference.** A class may be retired under
   D-A(a) only after the count is recorded in the decision that does it (e.g. 25 non-vision
   flow links of 120 405). The research number alone does not retire anything.

## Consequences

- `validate_ss_config` and a new `validate_vless_shape` (`leas-config`) become the enforcement
  points for D-C; `capability` keeps refusing at dial for rows that predate them.
- A DATA step (marker-gated in `app_meta`) writes `config_invalid` for stored rows under D-D.
- Code review may reject a deletion that cites an upstream changelog without a D-A(b) finding,
  and may reject a gate flip that cites one core.
- A future variant whose peers are all gone is still implementable: the rule decides what may
  be *removed*, never what must not be *added*.
