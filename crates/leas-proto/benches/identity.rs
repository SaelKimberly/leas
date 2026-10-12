//! Per-kind `ProtocolId` identity cost: `ParsedProto::identity_once()`.
//!
//! Hermetic — parses once, then measures only the identity traversal. The
//! point of the row is that identity is binary and allocation-free: the value
//! is a same-machine comparison against the pre-2026-09 canonical-JSON path
//! (~0.7–1.1 µs/call, two serializations + a `Value` tree per call), not an
//! absolute performance promise.

use criterion::{Criterion, criterion_group, criterion_main};
use leas_proto::proto_spec::ProtocolConfig;
use leas_proto::urlx::RawUrlX;

/// One representative config per shape: transport-heavy TLS, REALITY with
/// public params, grpc, QUIC transport, and a credential-only pair.
const SHAPES: &[(&str, &str)] = &[
    (
        "vless_ws_tls",
        "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@host.example:443?type=ws&security=tls&sni=a.example&path=%2Fws&host=a.example&fp=chrome&alpn=h2%2Chttp%2F1.1",
    ),
    (
        "vless_reality",
        "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@host.example:443?type=tcp&security=reality&sni=a.example&pbk=Zm9vYmFy&sid=0123abcd&spx=%2F&flow=xtls-rprx-vision&fp=chrome",
    ),
    (
        "trojan_grpc",
        "trojan://hunter2@host.example:443?type=grpc&security=tls&sni=a.example&serviceName=gs&alpn=h2",
    ),
    (
        "hysteria2",
        "hysteria2://hunter2@host.example:443?sni=a.example&obfs=salamander&obfs-password=x&alpn=h3",
    ),
    (
        "ss_2022",
        "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206c2VjcmV0@host.example:8388",
    ),
];

fn bench_identity(c: &mut Criterion) {
    let mut group = c.benchmark_group("proto/identity");
    for (name, url) in SHAPES {
        let parsed = ProtocolConfig::try_parse_proto(&RawUrlX::from(*url))
            .unwrap_or_else(|e| panic!("parse {name}: {e}"));
        group.bench_function(*name, |b| {
            b.iter(|| std::hint::black_box(parsed.identity_once()));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_identity);
criterion_main!(benches);
