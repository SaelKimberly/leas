//! TLS record-layer benches: seal and open throughput in isolation.
//!
//! Deliberately transport- and handshake-free — a [`TlsStream`] over
//! `tokio::io::duplex` keyed from raw bytes, so the timed section holds
//! nothing but record framing, AEAD and the duplex copy. No network, no
//! certificates, no handshake, no core binaries: these rows always run.
//!
//! Shape follows `crates/leas-native/benches/throughput.rs`: setup once
//! outside `b.iter`, one shared multi-thread runtime, `rt.block_on` per
//! iteration, `Throughput::Bytes`, size from `LEAS_BENCH_MB`.

use std::sync::Arc;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use leas_tls::crypto::{AeadKey, CipherSuiteId};
use leas_tls::record::AEAD_TAG_LEN;
use leas_tls::record::stream::{AppKeys, TlsStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Plaintext per `write_all`: exactly one full TLS 1.3 record (2^14, RFC
/// 8446 §5.2), so every write is one seal and every record one open — the
/// per-record cost *is* the measurement.
const CHUNK: usize = 16 * 1024;

/// Duplex capacity: several records in flight, far under the payload, so the
/// peer task (drain for `seal`, feed for `open`) is actually exercised
/// instead of the pipe swallowing the whole transfer.
const DUPLEX_CAP: usize = 256 * 1024;

/// Wire bytes of one sealed 16 KiB record: 5-byte header + plaintext +
/// `TLSInnerPlaintext` content type + AEAD tag.
const RECORD_LEN: usize = 5 + CHUNK + 1 + AEAD_TAG_LEN;

fn bench_mb() -> u64 {
    std::env::var("LEAS_BENCH_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(64)
}

/// One cipher-suite row: bench names are `tls_record/{name}/seal` and
/// `tls_record/{name}/open`.
struct Suite {
    name: &'static str,
    id: CipherSuiteId,
    /// Raw record key, `id.key_len()` bytes.
    key_bytes: &'static [u8],
}

const SUITES: [Suite; 2] = [
    Suite {
        name: "aes128gcm",
        id: CipherSuiteId::Aes128GcmSha256,
        key_bytes: &[0x11; 16],
    },
    Suite {
        name: "chacha20",
        id: CipherSuiteId::Chacha20Poly1305Sha256,
        key_bytes: &[0x11; 32],
    },
];

/// Fresh TLS 1.3 record keys for `suite`, both directions on one secret.
///
/// A self-consistent pair is all an isolated record-layer bench needs, and it
/// is what lets the `open` rows build their input through the public API
/// alone: what one `TlsStream` seals, another opens. `AppKeys` is
/// deliberately not `Clone` (cloned key state would reuse nonces), so every
/// stream gets its own — two ring key expansions, against MiB of AEAD.
fn keys(suite: &Suite) -> AppKeys {
    let key = AeadKey::from_key_bytes(suite.id, suite.key_bytes).expect("bench record key");
    AppKeys::tls13(key.clone_key(), key)
}

/// The wire bytes of `chunks` sealed records, produced through the public API
/// only: write plaintext through a throwaway `TlsStream` and collect what the
/// peer duplex half yields. Built once per suite, outside every timed
/// section, then replayed by the `open` rows.
fn sealed_stream(rt: &tokio::runtime::Runtime, suite: &Suite, chunks: usize) -> Arc<Vec<u8>> {
    let (framer, mut peer) = tokio::io::duplex(DUPLEX_CAP);
    let mut source = TlsStream::new(framer, keys(suite));
    // Concurrent by necessity: the duplex is bounded, so the framer only
    // makes progress while the collector drains. Dropping `source` when the
    // task ends closes its half and gives the collector its EOF.
    let framing = rt.spawn(async move {
        let payload = vec![0xABu8; CHUNK];
        for _ in 0..chunks {
            source.write_all(&payload).await.expect("seal write");
        }
        source.flush().await.expect("seal flush");
    });
    let mut sealed = Vec::with_capacity(chunks * RECORD_LEN);
    rt.block_on(async {
        peer.read_to_end(&mut sealed)
            .await
            .expect("collect sealed records");
        framing.await.expect("framing task");
    });
    assert_eq!(
        sealed.len(),
        chunks * RECORD_LEN,
        "one record per {CHUNK}-byte write"
    );
    Arc::new(sealed)
}

fn criterion_benches(c: &mut Criterion) {
    // Multi-thread: every row pairs the benched stream with a peer task on
    // the other duplex half. A current-thread runtime would poll that task
    // only from inside `block_on`, and the bounded duplex would then stall
    // the bench body.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("bench runtime");
    let n = bench_mb() * 1024 * 1024;
    let total = usize::try_from(n).expect("bench byte count fits usize");
    // `bench_mb` is whole MiB and 16 KiB divides 1 MiB, so N is an exact
    // number of full records in both directions.
    let chunks = total / CHUNK;
    let mut group = c.benchmark_group("tls_record");
    group.throughput(Throughput::Bytes(n));
    for suite in &SUITES {
        // seal: N plaintext bytes in, framed records out. The peer half is
        // drained and discarded — nothing decrypts, so the row is the write
        // path only.
        let (client, peer) = tokio::io::duplex(DUPLEX_CAP);
        let drain = rt.spawn(async move {
            let mut peer = peer;
            let mut discard = vec![0u8; CHUNK];
            while peer.read(&mut discard).await.expect("drain records") > 0 {}
        });
        let mut sealer = TlsStream::new(client, keys(suite));
        let payload = vec![0xABu8; CHUNK];
        let seal_name = format!("{}/seal", suite.name);
        group.bench_function(&seal_name, |b| {
            b.iter(|| {
                rt.block_on(async {
                    for _ in 0..chunks {
                        sealer.write_all(&payload).await.unwrap();
                    }
                    sealer.flush().await.unwrap();
                });
            });
        });
        // Closing the stream's half is the drain task's EOF.
        drop(sealer);
        rt.block_on(drain).expect("drain task");

        // open: replay the pre-sealed stream. The reader's `read_seq` must
        // start at 0 for every replay, so the duplex, the feeder and the
        // `TlsStream` are per-iteration; the sealed bytes are not.
        let wire = sealed_stream(&rt, suite, chunks);
        let open_name = format!("{}/open", suite.name);
        group.bench_function(&open_name, |b| {
            let mut plain = vec![0u8; CHUNK];
            b.iter(|| {
                rt.block_on(async {
                    let (server, peer) = tokio::io::duplex(DUPLEX_CAP);
                    let feed = Arc::clone(&wire);
                    let feeder = tokio::spawn(async move {
                        let mut peer = peer;
                        peer.write_all(&feed).await.expect("feed sealed records");
                    });
                    let mut reader = TlsStream::new(server, keys(suite));
                    for _ in 0..chunks {
                        reader.read_exact(&mut plain).await.unwrap();
                    }
                    feeder.await.unwrap();
                });
            });
        });
    }
    group.finish();
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
