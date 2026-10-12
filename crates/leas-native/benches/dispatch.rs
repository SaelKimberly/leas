//! Dispatch benches: what the `Box<dyn Stream>` layer seam costs against a
//! statically typed stack of the same depth.
//!
//! Every production layer boundary is a `BoxStream` (`lib.rs:35-42`) and a
//! chain is 3-6 layers deep (`chain.rs` folds a runtime-length link list, so
//! the depth is not statically known). Both rows push the same byte volume
//! through four passthrough layers over the same `tokio::io::duplex` pair;
//! the only difference is whether those boundaries are monomorphized or
//! dynamically dispatched. The `boxed`/`static` median ratio is therefore the
//! vtable tax *per `poll_*`* — one poll per 16 KiB write here, not per byte.
//!
//! No feature gate, no core binary, no network: this target must build and
//! run with a bare `cargo bench -p leas-native --bench dispatch`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main};
use leas_native::BoxStream;
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf,
};

/// Bytes per write: the relay/transport chunk size everywhere in this crate.
const CHUNK: usize = 16 * 1024;

/// Passthrough layers per stack.
const DEPTH: usize = 4;
const _: () = assert!(
    DEPTH == 4,
    "`static_stack` is hand-nested exactly four deep"
);

fn bench_mb() -> u64 {
    std::env::var("LEAS_BENCH_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(64)
}

/// A layer that does nothing but forward every poll to its inner stream —
/// the cheapest possible stand-in for a real codec layer, so the measured
/// difference between the two rows is dispatch and nothing else.
struct Pass<S>(S);

impl<S: AsyncRead + Unpin> AsyncRead for Pass<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Pass<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Four `Pass` layers, monomorphized: `write_all` reaches the duplex through
/// direct (inlinable) calls.
const fn static_stack(inner: DuplexStream) -> Pass<Pass<Pass<Pass<DuplexStream>>>> {
    Pass(Pass(Pass(Pass(inner))))
}

/// Four `Pass` layers over a boxed base stream, each boundary a `BoxStream`
/// — the production shape (`chain.rs` boxes at every level, including the
/// base transport). One `write_all` costs `DEPTH + 1` indirect calls.
fn boxed_stack(inner: DuplexStream) -> BoxStream {
    let mut stack: BoxStream = Box::new(inner);
    for _ in 0..DEPTH {
        stack = Box::new(Pass(stack));
    }
    stack
}

/// A duplex pair whose peer half is drained by a spawned task: `write_all`
/// only makes progress because the reader consumes, so the bytes really
/// traverse every layer. Returns the near half plus the drain handle (abort
/// it when the row is done so it cannot compete with the next row).
fn drained_duplex(rt: &tokio::runtime::Runtime) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    let (near, mut far) = tokio::io::duplex(256 * 1024);
    let drain = rt.spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok(n) = far.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    });
    (near, drain)
}

/// The timed body, generic over the stack so both rows run byte-identical
/// logic: `chunks` × `CHUNK`-byte `write_all` plus one `flush` per iteration.
fn bench_push<S: AsyncWrite + Unpin>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: &tokio::runtime::Runtime,
    name: &str,
    mut stack: S,
    payload: &[u8],
    chunks: usize,
) {
    group.bench_function(name, |b| {
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..chunks {
                    stack.write_all(payload).await.expect("dispatch write");
                }
                stack.flush().await.expect("dispatch flush");
            });
        });
    });
}

fn criterion_benches(c: &mut Criterion) {
    // Multi-thread: the drain task must run on a worker while the bench
    // thread blocks in `write_all` — a current-thread runtime would deadlock
    // as soon as the duplex buffer filled.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("bench runtime");
    let n = bench_mb() * 1024 * 1024;
    let chunks = usize::try_from(n).expect("bench bytes fit usize") / CHUNK;
    let payload = vec![0xABu8; CHUNK];

    let mut group = c.benchmark_group("dispatch");
    group.throughput(Throughput::Bytes(n));

    let (near, drain) = drained_duplex(&rt);
    bench_push(
        &mut group,
        &rt,
        "static",
        static_stack(near),
        &payload,
        chunks,
    );
    drain.abort();

    let (near, drain) = drained_duplex(&rt);
    bench_push(
        &mut group,
        &rt,
        "boxed",
        boxed_stack(near),
        &payload,
        chunks,
    );
    drain.abort();

    group.finish();
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
