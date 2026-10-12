# Memory-diet baseline (Task 1)

- Date: 2026-09-07
- Base commit: e48730ae008a5bde54212e1aa961756f34d7bbd6
- Command: `just bench micro` (= `LEAS_BENCH_MB=4 LEAS_CORE_BIN_DIR=/tmp/core-bin`,
  then `cargo criterion` for `record`, `decide`, `dispatch`, `relay`)
- Source of numbers: mean estimate + throughput estimate from
  `.benchmarks/reports/<group>/<bench>/index.html` of this run.
- SKIP rows: none. All micro rows ran (record + decide + dispatch + relay need
  no core binaries). The `throughput` group is not part of `micro` and was not run.

## tls_record (`-p leas-tls --bench record`)

| bench | mean (est) | throughput (est) |
|---|---|---|
| aes128gcm_seal | 620.07 µs | 6.1944 GiB/s |
| aes128gcm_open | 753.85 µs | 5.2730 GiB/s |
| chacha20_seal | 1.8287 ms | 2.1301 GiB/s |
| chacha20_open | 1.9751 ms | 1.9778 GiB/s |

## decide (`-p leas-route --bench decide`)

| bench | mean (est) | throughput (est) |
|---|---|---|
| rules_0_miss | 19.547 ns | 51.006 Melem/s |
| rules_0_ip_hit | 19.825 ns | 50.445 Melem/s |
| rules_0_domain_hit | 19.406 ns | 51.191 Melem/s |
| rules_8_miss | 197.40 ns | 5.0963 Melem/s |
| rules_8_ip_hit | 93.129 ns | 10.958 Melem/s |
| rules_8_domain_hit | 155.37 ns | 6.4048 Melem/s |
| rules_64_miss | 1.1229 µs | 891.83 Kelem/s |
| rules_64_ip_hit | 559.98 ns | 1.8588 Melem/s |
| rules_64_domain_hit | 1.1240 µs | 896.69 Kelem/s |

## dispatch (`-p leas-native --bench dispatch`)

| bench | mean (est) | throughput (est) |
|---|---|---|
| static | 336.83 µs | 11.567 GiB/s |
| boxed | 350.88 µs | 11.150 GiB/s |

Console vs stored previous baseline: `dispatch/static` time +4.5720%
("Performance has regressed"), `dispatch/boxed` time +7.2043% (regressed).

## relay (`-p leas-native --features native-e2e --bench relay`)

| bench | mean (est) | throughput (est) |
|---|---|---|
| socks5-direct/send | 1.3696 ms | 2.8943 GiB/s |
| socks5-direct/recv | 1.4365 ms | 2.8297 GiB/s |
| socks5-udp/pps | 18.154 ms | 55.084 Kelem/s |

Console vs stored previous baseline: `socks5-direct/send` time +6.5261%
(regressed); `socks5-direct/recv` and `socks5-udp/pps` no change detected.

## proto alloc baseline (throwaway reference, not committed)

`cargo test -p leas-proto --lib -- --nocapture 2>&1 | head -20` → PASS
(343 passed, 0 failed; full tail confirms `test result: ok`).

Canonical-serialization call sites (record only, no code change):
- `crates/leas-proto/src/proto_spec/endpoint.rs:95-96`
  (`canonical_json`: `serde_json::to_value(&self.protocol)`)
- `crates/leas-proto/src/proto_spec/endpoint.rs:105`
  (`protocol_hash`: `serde_json::to_vec(&self.canonical_json())`)
- `crates/leas-proto/src/proto_spec/endpoint.rs:137`
  (`cred_hash`: `serde_json::to_string(&self.canonical_json())`)
