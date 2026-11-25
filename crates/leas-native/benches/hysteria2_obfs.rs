//! Hysteria2 obfuscation bench: Salamander's per-datagram transform and
//! Gecko's frame encoding.
//!
//! No sockets, no cores: `Salamander::obfuscate_into`/`deobfuscate_in_place`
//! are pure, and the payload sizes are the QUIC datagrams the client actually
//! handles (small ACK, 1200 B Initial, 1500 B path-MTU probe).
//!
//! The SIMD-engine question this bench answered (2026-11-25): the XOR slice is
//! ~9% of `obfuscate_into` at 1200 B (13.4 ns of 149.8 ns), so no XOR engine
//! can move the whole transform by 15%; `macerator` measured slower than
//! `wide` on the slice (18.7 ns vs 13.4 ns). `wide` stays; see
//! `docs/aegis/plans/2026-11-25-hysteria2-gecko-obfs.md` Outcome.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use leas_native::crypto::salamander::{SALT_LEN, Salamander};

const PAYLOAD_SIZES: [usize; 3] = [64, 1200, 1500];

fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("mod 251 fits u8"))
        .collect()
}

// `BenchmarkGroup::finish` consumes the group; the lint reads the binding as
// an early-droppable temporary.
#[allow(clippy::significant_drop_tightening)]
fn bench_salamander(c: &mut Criterion) {
    let ob = Salamander::new(b"bench-obfs-psk").expect("psk");
    let salt = [0x5a; SALT_LEN];

    let mut obfuscate = c.benchmark_group("hysteria2_salamander/obfuscate");
    for len in PAYLOAD_SIZES {
        let plain = payload(len);
        let mut wire = vec![0u8; len + SALT_LEN];
        obfuscate.throughput(Throughput::Bytes(len as u64));
        obfuscate.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter(|| ob.obfuscate_into(&salt, &plain, &mut wire));
        });
    }
    obfuscate.finish();

    let mut deobfuscate = c.benchmark_group("hysteria2_salamander/deobfuscate_in_place");
    for len in PAYLOAD_SIZES {
        let plain = payload(len);
        let mut wire = vec![0u8; len + SALT_LEN];
        ob.obfuscate_into(&salt, &plain, &mut wire);
        deobfuscate.throughput(Throughput::Bytes(len as u64));
        deobfuscate.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter_batched(
                || wire.clone(),
                |mut packet| {
                    let _ = ob.deobfuscate_in_place(&mut packet);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    deobfuscate.finish();
}

/// Gecko's frame shape over a 1200 B long header: 2/4/8 padded frames, the
/// encode step only (the salt is the Salamander group above).
#[allow(clippy::significant_drop_tightening)]
fn bench_gecko_frames(c: &mut Criterion) {
    use leas_native::crypto::gecko;

    let packet = payload(1200);
    let mut group = c.benchmark_group("hysteria2_gecko/frames");
    for chunks in [2_u8, 4, 8] {
        group.bench_with_input(BenchmarkId::from_parameter(chunks), &chunks, |b, _| {
            let mut scratch = vec![0u8; gecko::MAX_PACKET + 64];
            b.iter(|| {
                for idx in 0..chunks {
                    let chunk = &packet[gecko::chunk_range(packet.len(), chunks, idx)];
                    let pad = gecko::pad_len(chunk.len(), 512, 1200, u32::from(idx));
                    let h = gecko::FrameHeader {
                        pad_len: pad,
                        msg_id: 1,
                        chunk_idx: idx,
                        total_chunks: chunks,
                    };
                    let _ = gecko::encode_frame_into(h, chunk, &mut scratch, |p| p.fill(0x5a));
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_salamander, bench_gecko_frames);
criterion_main!(benches);
