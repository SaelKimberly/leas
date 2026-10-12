//! Throughput benches: bulk send/recv per native config (spec
//! `docs/superpowers/specs/2026-09-04-native-throughput-bench-design.md`).
#![cfg(feature = "native-e2e")]

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use leas_native::NativeTunnel;
use leas_native::e2e::{
    Aes128GcmVariant, CaseSpec, Certs, Chacha20Poly1305Variant, CoreKind, CoreUnderTest, E2eCase,
    FingerprintTls, Flow, NoTls, RealityTls, SINGBOX_VERSION, ServerEnv, XRAY_VERSION,
    generate_certs,
    harness::{
        CoreGuard, SinkServer, SourceServer, TlsEchoServer, free_port, spawn_core, spawn_sink,
        spawn_source, spawn_tls_echo,
    },
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn bench_mb() -> u64 {
    std::env::var("LEAS_BENCH_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(64)
}

fn resolve_or_skip(kind: CoreKind) -> Option<CoreUnderTest> {
    let want = match kind {
        CoreKind::Xray => XRAY_VERSION,
        CoreKind::SingBox => SINGBOX_VERSION,
    };
    match CoreUnderTest::resolve(kind, want) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("SKIP throughput benches: {e}");
            None
        }
    }
}

/// One matrix row: bench names are `{name}/send` + `{name}/recv`.
/// `build` is a fn (not a const value) because `CaseSpec` holds boxed
/// variants and is not const-constructible.
struct Row {
    name: &'static str,
    build: fn() -> CaseSpec,
    core: CoreKind,
}

fn rows() -> Vec<Row> {
    vec![
        Row {
            name: "vless/tcp/plain",
            build: || CaseSpec::vless().with_tls(Box::new(NoTls)),
            core: CoreKind::Xray,
        },
        Row {
            name: "vless/tcp/tls-chrome",
            build: || CaseSpec::vless().with_tls(Box::new(FingerprintTls("chrome"))),
            core: CoreKind::Xray,
        },
        Row {
            name: "vless/tcp/reality",
            build: || CaseSpec::vless().with_tls(Box::new(RealityTls::fresh())),
            core: CoreKind::Xray,
        },
        Row {
            name: "vless/vision+reality",
            build: || {
                CaseSpec::vless()
                    .with_flow(Flow::Vision)
                    .with_tls(Box::new(RealityTls::fresh()))
            },
            core: CoreKind::Xray,
        },
        Row {
            name: "vless/ws/plain",
            build: || {
                CaseSpec::vless()
                    .with_network("ws")
                    .with_tls(Box::new(NoTls))
            },
            core: CoreKind::Xray,
        },
        Row {
            name: "vless/grpc/tls-chrome",
            build: || {
                CaseSpec::vless()
                    .with_network("grpc")
                    .with_tls(Box::new(FingerprintTls("chrome")))
            },
            core: CoreKind::Xray,
        },
        Row {
            name: "vmess/tcp/aes",
            build: || CaseSpec::vmess(Aes128GcmVariant),
            core: CoreKind::Xray,
        },
        Row {
            name: "vmess/ws/chacha",
            build: || {
                CaseSpec::vmess(Chacha20Poly1305Variant)
                    .with_network("ws")
                    .with_tls(Box::new(FingerprintTls("chrome")))
            },
            core: CoreKind::Xray,
        },
        Row {
            name: "trojan/tcp/tls-chrome",
            build: || CaseSpec::trojan().with_tls(Box::new(FingerprintTls("chrome"))),
            core: CoreKind::Xray,
        },
        // Shadowsocks: `SsConfig` has no transport field, so every SS row is
        // the plain TCP dial. `NoTls` is the genuinely plain wire shape the
        // e2e matrix uses (`tests/shadowsocks.rs::ss`), not a TLS layer with
        // defaults. The four rows cover both cipher families — classic AEAD
        // (HKDF-SHA1 subkey) and 2022-blake3 (standalone header chunks) —
        // across both cores.
        Row {
            name: "ss/tcp/aead-aes-128-gcm",
            build: || CaseSpec::shadowsocks("aes-128-gcm").with_tls(Box::new(NoTls)),
            core: CoreKind::Xray,
        },
        Row {
            name: "ss/tcp/aead-chacha20-ietf-poly1305",
            build: || CaseSpec::shadowsocks("chacha20-ietf-poly1305").with_tls(Box::new(NoTls)),
            core: CoreKind::Xray,
        },
        Row {
            name: "ss/tcp/2022-blake3-aes-256-gcm",
            build: || CaseSpec::shadowsocks("2022-blake3-aes-256-gcm").with_tls(Box::new(NoTls)),
            core: CoreKind::Xray,
        },
        Row {
            name: "ss/tcp/2022-blake3-chacha20-poly1305",
            build: || {
                CaseSpec::shadowsocks("2022-blake3-chacha20-poly1305").with_tls(Box::new(NoTls))
            },
            core: CoreKind::SingBox,
        },
        // TCP path only (QUIC-stream tunnel via plain `connect`, same as the
        // e2e default row). The datagram `connect_udp` shape is out of scope:
        // no byte-stream, no sink/source target.
        Row {
            name: "hysteria2/tcp",
            build: || CaseSpec::hysteria2(None),
            core: CoreKind::SingBox,
        },
    ]
}

/// Bench direction: `Send` pushes bytes client→sink, `Recv` pulls bytes
/// source→client.
#[derive(Clone, Copy)]
enum Direction {
    Send,
    Recv,
}

/// Everything one bench holds for its row × direction: the core guard, the
/// tempdir (config + cert files), the byte-target holder, the REALITY dest,
/// and the connected tunnel. Holders are never read — their `Drop` impls
/// tear the servers down, so dropping one mid-bench kills the bench. Each
/// bench uses exactly one holder: `Held::Sink` for send (plus its received
/// byte counter for the goodput gate), `Held::Source` for recv.
enum Held {
    Sink(SinkServer),
    #[allow(dead_code)]
    Source(SourceServer),
}

struct RowSetup {
    _core: CoreGuard,
    _dir: tempfile::TempDir,
    held: Held,
    _tls_echo: TlsEchoServer,
    tunnel: NativeTunnel,
}

/// Spawn-once setup for one row × direction: byte target + REALITY dest +
/// core + one connected tunnel. The caller holds the returned setup until
/// its bench completes.
fn setup_row(
    rt: &tokio::runtime::Runtime,
    case: &CaseSpec,
    core: &CoreUnderTest,
    certs: &Certs,
    dirn: Direction,
) -> RowSetup {
    // `spawn_sink`/`spawn_source`/`spawn_tls_echo` use `tokio::spawn`
    // internally: they need an entered runtime context at spawn time. The
    // guard MUST drop before any `rt.block_on` — `block_on` panics inside
    // an entered context ("cannot start a runtime from within a runtime").
    // Spawned tasks keep running on the multi-thread workers after the
    // guard drops.
    let (held, target, tls_echo) = {
        let enter = rt.enter();
        let (held, target) = match dirn {
            Direction::Send => {
                let target = spawn_sink();
                let addr = target.addr;
                (Held::Sink(target), addr)
            }
            Direction::Recv => {
                let target = spawn_source();
                let addr = target.addr;
                (Held::Source(target), addr)
            }
        };
        // REALITY inbounds point their `dest`/`handshake` fallback at a real
        // TLS server (xtls/reality borrows the dest's TLS 1.3 `ServerHello`
        // flight — a plain echo cannot serve it), so every row spawns one.
        let tls_echo = spawn_tls_echo(certs);
        drop(enter);
        (held, target, tls_echo)
    };
    let dir = tempfile::tempdir().expect("bench tempdir");
    std::fs::write(dir.path().join("server.crt"), &certs.cert_pem).unwrap();
    std::fs::write(dir.path().join("server.key"), &certs.key_pem).unwrap();
    let port = free_port();
    let env = ServerEnv {
        port,
        certs,
        tmp: dir.path(),
        echo: target,
        tls_echo: tls_echo.addr,
        inner_tls_echo: None,
        udp_echo: None,
    };
    let config_json = case.server_config(core.kind, &env);
    let config_path = dir.path().join("config.json");
    std::fs::write(&config_path, &config_json).unwrap();
    let core_guard = spawn_core(
        &core.bin,
        core.kind,
        &config_path,
        port,
        case.is_udp_listener(),
    );
    case.client_trust(certs);
    let params = case.client_params(port, target);
    let mut tunnel = rt
        .block_on(leas_native::connect(params))
        .expect("bench connect");
    if matches!(dirn, Direction::Recv) {
        // gRPC primer: xray's `Tun` handler defers its 200 + response
        // stream until the first client DATA (grpc.rs:161-165) — a
        // read-only bench would pend forever. One byte opens the
        rt.block_on(async {
            use tokio::io::AsyncWriteExt as _;
            tunnel.write_all(&[0xABu8]).await.expect("bench primer");
            tunnel.flush().await.expect("bench primer flush");
        });
    }
    RowSetup {
        _core: core_guard,
        _dir: dir,
        held,
        _tls_echo: tls_echo,
        tunnel,
    }
}

fn criterion_benches(c: &mut Criterion) {
    // Multi-thread: sink/source accept loops are `tokio::spawn`ed at
    // setup (outside `block_on`) — a current-thread runtime would never
    // poll them and the send goodput-gate would spin forever.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("bench runtime");
    let n = bench_mb() * 1024 * 1024;
    let certs: Certs = generate_certs();
    let xray = resolve_or_skip(CoreKind::Xray);
    let sing = resolve_or_skip(CoreKind::SingBox);
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(n));
    group.measurement_time(Duration::from_secs(20));
    let payload = vec![0xABu8; 1024 * 1024];
    let iters = n / payload.len() as u64;
    for row in rows() {
        let core = match row.core {
            CoreKind::Xray => &xray,
            CoreKind::SingBox => &sing,
        };
        let Some(core) = core else {
            eprintln!("SKIP throughput {}: core missing", row.name);
            continue;
        };
        let case = (row.build)();
        // Send: push N client→sink per iter. `write_all` returns on local
        // buffering, so stay in the timed section until the sink counted N.
        let mut send = setup_row(&rt, &case, core, &certs, Direction::Send);
        let Held::Sink(byte_sink) = &send.held else {
            unreachable!("send setup holds a sink");
        };
        let send_name = format!("{}/send", row.name);
        group.bench_function(&send_name, |b| {
            b.iter(|| {
                rt.block_on(async {
                    use std::sync::atomic::Ordering;
                    let base = byte_sink.received.load(Ordering::SeqCst);
                    let want = base + n;
                    for _ in 0..iters {
                        send.tunnel.write_all(&payload).await.unwrap();
                    }
                    send.tunnel.flush().await.unwrap();
                    // Goodput gate: `write_all` returns on local buffering —
                    // stay in the timed section until the sink counted N.
                    while byte_sink.received.load(Ordering::SeqCst) < want {
                        tokio::task::yield_now().await;
                    }
                });
            });
        });
        drop(send);
        // Recv: the source streams infinite zeros on one reusable tunnel —
        // read exactly N per iter. N is a whole number of 1 MiB chunks
        // (`bench_mb` ≥ 1), so every iter is `chunks` full-buffer reads.
        let chunks = usize::try_from(iters).expect("bench chunks fit usize");
        let mut recv = setup_row(&rt, &case, core, &certs, Direction::Recv);
        let recv_name = format!("{}/recv", row.name);
        group.bench_function(&recv_name, |b| {
            let mut buf = vec![0u8; 1024 * 1024];
            b.iter(|| {
                rt.block_on(async {
                    for _ in 0..chunks {
                        recv.tunnel.read_exact(&mut buf).await.unwrap();
                    }
                });
            });
        });
        drop(recv);
    }
    group.finish();
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
