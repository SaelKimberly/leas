//! Relay bench: 64 KiB application writes through `TlsStream` over a duplex,
//! the shape the relay uses (`read` a window, `write_all` it to the tunnel).
//!
//! The record bench measures one 16 KiB record per call; this one measures the
//! relay's larger write, which today frames four records and therefore makes
//! four transport writes. It is the before/after row for batched sealing.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use leas_tls::crypto::{AeadKey, CipherSuiteId};
use leas_tls::record::stream::{AppKeys, TlsStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const CHUNK: usize = 64 * 1024;
const DUPLEX_CAP: usize = 512 * 1024;

fn keys() -> AppKeys {
    let key = AeadKey::from_key_bytes(CipherSuiteId::Aes128GcmSha256, &[0x11; 16]).unwrap();
    AppKeys::tls13(key.clone_key(), key)
}

fn bench_mb() -> u64 {
    std::env::var("LEAS_BENCH_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(64)
}

fn benches(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let n = usize::try_from(bench_mb() * 1024 * 1024).unwrap();

    let mut group = c.benchmark_group("tls_relay");
    group.throughput(Throughput::Bytes(n as u64));
    group.bench_function("write_64k", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (framer, mut peer) = tokio::io::duplex(DUPLEX_CAP);
                let mut stream = TlsStream::new(framer, keys());
                let drain = tokio::spawn(async move {
                    let mut sink = vec![0u8; CHUNK];
                    loop {
                        match peer.read(&mut sink).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                });
                let payload = vec![0xABu8; CHUNK];
                let mut sent = 0usize;
                while sent < n {
                    stream.write_all(&payload).await.unwrap();
                    sent += CHUNK;
                }
                stream.flush().await.unwrap();
                drop(stream);
                let _ = drain.await;
            });
        });
    });
    group.finish();
}

criterion_group!(benches_group, benches);
criterion_main!(benches_group);
