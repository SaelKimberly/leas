# research/

Ad-hoc studies and evidence that informed decisions. Not authoritative.

| File | Contents |
| --- | --- |
| `amiabot-roster-report.md` | The TLS profile roster tested against Cloudflare's bot detector |
| `dry-normalization-plan.md` | A duplication-reduction study across proto/native/tls/app |
| `2026-11-13-allocation-profile.md` | First `leas-memtrace` pass over the app and the two hot paths: per-module peak/churn, and the six allocation sites worth changing |
| `2026-11-12-zeronet-zray-analysis.md` | Protocol and performance audit of `thirdparty/ZeroNet` @ `29e7a95` (Zray-core), with the adopt/reject verdicts behind four 2026-11-12 specs |
| `2026-11-16-turso-0.9-delta.md` | Turso 0.8.2 → 0.9.0-pre.5 delta, MVCC against WAL on the real workloads (CPU, RSS, disk), and the measured verdict on the orphan-purge anti-join and a `protocols` split |
| `2026-11-20-failure-pair-review.md` | The schema-22 `error_stage`/`error_cause` pair in the 2026-11-20 DB snapshot: 0 non-NULL pairs across 124 341 failure rows (the shared raw link writer never binds the two columns), the mapping's TLS-I/O wrap mislabels ~5 200 rows, `error_kind='name'` has no writer, `latency_auth` is 95.4 % Unknown / 0 Failed, and what the pair would let a report ask |
| `2026-11-20-log-review-real-test.md` | The same 2026-11-19/20 run read from the persisted log store: 93.6 % of the batch deferred by DNS queue starvation (36 645 timeouts, six-second cliffs), 85.7 % of tunnel connections reaped by the 30 s relay idle cap, 183 statements failing at the busy-timeout ceiling (purge sweep measured at 143.7 s contended vs 0.36 s cold on the same file), and the structured fields the log layer deliberately withholds |
| `2026-11-19-real-test-funnel.md` | The Real Test (All) over a 120 405-link DB: the 13-bucket outcome funnel (14 links completed a tunnel, 7 endpoints alive), a per-case inventory of the 752 "engine cannot test" links, which failure classes carry no verdict, a dial experiment on every non-vision-flow link (all dead; 27 of 29 invalid without TLS), and the nine changes that would make "working servers" an honest number |
