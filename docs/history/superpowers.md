# The pre-Aegis lineage (2026-07 → 2026-09)

Before the Aegis workspace existed (initialized 2026-09-11), design work lived in
`docs/superpowers/{specs,plans}`. Every one of those 53 files is superseded; the folders were
deleted (D12) and this note is the brief record. The full text survives in git history.

Read this to answer "was this designed before, and what supersedes it?".

| Design (superpowers) | Superseded by |
|---|---|
| `2026-07-09-profile-config-refactor` | `2026-08-05-typed-data-model` (then aegis endpoint-ip-storage / db-rewamp) |
| `2026-08-03-proto-identity` | `2026-08-05-typed-data-model`; identity later hardened by ADR 0007 |
| `2026-08-05-typed-data-model` | aegis `2026-09-15-endpoint-ip-storage`, `2026-10-06-db-rewamp`, `2026-10-08-db-adapter-and-migrations` |
| `2026-08-05-test-priority-sort` | aegis `2026-09-14-profiles-stored-sort-key` → `2026-10-01-static-config-weight` → `2026-10-09-stab-bin` |
| `2026-08-07-native-core-stub`, `2026-08-07-native-vmess-e2e-pipeline` | aegis `2026-09-14-native-ping-pipeline` (ADR 0004) |
| `2026-08-10-tls-mimicry-engine`, `2026-08-12-tls-reality-unified-api` | shipped `leas-tls`; see `docs/reference/native-core.md` |
| `2026-08-12-rstest-test-redesign` | landed; current test conventions |
| `2026-08-12-vless-transports-ws-grpc`, `2026-08-13-transports-xhttp-httpupgrade-v2rayhttp` | aegis `2026-09-23-ws-path-canonicalization` |
| `2026-08-13-vless-flow-vision`, `vless-mux`, `vless-udp-path`, `vless-xudp`, `vless-mkcp`, `vless-stream-one`, `vless-xhttp3` | shipped `leas-native` protocols; mux superseded by aegis `2026-09-30-ss-plugin` |
| `2026-08-19-vless-mlkem` | aegis `2026-09-18-crypto-dependency-hardening` (ADR 0007) |
| `2026-08-24-tls-fingerprint`, `ja4-spec-expansion`, `2026-08-25-ja4-roster-reduction` | shipped roster; `docs/reference/tls-fingerprint-roster.md` |
| `2026-08-27-native-routing-engine` | shipped `leas-route`; `docs/history/routing-engine-decision.md` |
| `2026-09-04-native-throughput-bench` | `benches/baseline.md` + `just bench` |
| `2026-09-07-memory-diet` | landed (bounded caches, `lru`) |
| `2026-09-10-native-shadowsocks` | shipped `leas-native` SS + 2022 |
| `2026-09-11-profiles-protocol-info-and-panel-window` | aegis `2026-09-11-profiles-page-query` |
| (plans) `2026-08-03-fix-review-findings` … `2026-08-25-tls-fingerprint-catalog` | the plans for the designs above |

The Aegis workspace (`docs/aegis/`) is the successor: `specs/`, `plans/`, `adr/`, `baseline/`.
