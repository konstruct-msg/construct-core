//! Criterion executable: cargo run --release --example allocation_baseline -- --bench <filter>
#[path = "support/allocation_fixture.rs"]
mod fixture;

use construct_core::cfe::{self, CfeMessageType};
use construct_core::orchestration::IncomingEvent;
use criterion::{Criterion, criterion_group, criterion_main};
use fixture::*;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn payload(c: &mut Criterion) {
    let mut group = c.benchmark_group("payload");
    for len in [50, 512, 4096, 65536] {
        let mut pair = Pair::new();
        let plaintext = vec![b'a'; len];
        let event = pair.event(&plaintext, "measured");
        let IncomingEvent::MessageReceived { data: wire, .. } = &event else {
            unreachable!()
        };
        let d = construct_core::wire_payload::unpack(wire).unwrap();
        eprintln!(
            "FIXTURE payload/{len}: wire={} sealed={} suite={} epoch={} pq_field={} handshake={}",
            wire.len(),
            d.sealed_box.len(),
            d.suite_id,
            d.pq_message_epoch,
            d.pq_ratchet_field.is_some(),
            d.pqxdh_v2
        );
        assert_eq!(
            pair.bob.decrypt_bytes_for(&pair.alice_id, wire).unwrap(),
            plaintext
        );
        for (stage, passes, split) in [("P1", 1, false), ("P3", 3, false), ("P4", 3, true)] {
            group.bench_function(format!("{stage}/{len}"), |b| {
                b.iter(|| parse_stage(black_box(wire), passes, split))
            });
        }
        group.bench_function(format!("PE/{len}"), |b| {
            // Restored cores deliberately consult ACK DB on cache misses. Use live pairs so
            // PE measures the complete normal receive path, including its first parse.
            b.iter_custom(|iters| {
                let mut elapsed = Duration::ZERO;
                let mut remaining = iters;
                while remaining > 0 {
                    let n = remaining.min(128);
                    let mut live = Pair::new();
                    let probe = live.event(&plaintext, "probe");
                    validate_actions(&live.bob.handle_event(probe), &plaintext, "probe");
                    let events: Vec<_> = (0..n)
                        .map(|i| live.event(&plaintext, &format!("m{i}")))
                        .collect();
                    let before = live.bob.get_session_health(&live.alice_id).unwrap();
                    let start = Instant::now();
                    for event in events {
                        drop(black_box(live.bob.handle_event(black_box(event))));
                    }
                    elapsed += start.elapsed();
                    let after = live.bob.get_session_health(&live.alice_id).unwrap();
                    assert_eq!(after.messages_received, before.messages_received + n as u32);
                    assert_eq!(after.skipped_keys_count, 0);
                    assert_eq!(after.pq_skipped_keys_count, 0);
                    remaining -= n;
                }
                elapsed
            });
        });
    }
    group.finish();
}

fn saving(c: &mut Criterion) {
    let mut group = c.benchmark_group("save");
    for &(skipped, previous) in CASES {
        let pair = Pair::with_history(skipped, previous);
        verify_restore(&pair);
        if let Err(error) = delayed_sequence(&pair) {
            eprintln!("BASELINE delayed-sequence/k{skipped}_p{previous}: {error}");
        }
        let cfe = decode_session(&pair.bob, &pair.alice_id);
        eprintln!(
            "FIXTURE save/k{skipped}_p{previous}: cfe={} skipped={} pq_skipped={} previous={} epoch={}",
            pair.bob.export_session_cfe(&pair.alice_id).unwrap().len(),
            cfe.skipped.len(),
            cfe.pqr.as_ref().unwrap().skipped.len(),
            cfe.previous.len(),
            cfe.pqr.as_ref().unwrap().current_epoch
        );
        let ratchet = ratchet_from(cfe.clone());
        let serial = ratchet.to_serializable();
        let label = format!("k{skipped}_p{previous}");
        group.bench_function(format!("S1/{label}"), |b| {
            b.iter(|| drop(black_box(ratchet.to_serializable())))
        });
        group.bench_function(format!("S2/{label}"), |b| {
            b.iter(|| drop(black_box(serial.to_cfe_v1().unwrap())))
        });
        // S3/S4 encode the current state only, like S1/S2. SF includes previous states.
        let mut current = cfe.clone();
        current.previous.clear();
        group.bench_function(format!("S3/{label}"), |b| {
            b.iter(|| {
                drop(black_box(
                    rmp_serde::to_vec_named(black_box(&current)).unwrap(),
                ))
            })
        });
        group.bench_function(format!("S4/{label}"), |b| {
            b.iter(|| {
                drop(black_box(
                    cfe::encode(CfeMessageType::SessionState, black_box(&current)).unwrap(),
                ))
            })
        });
        group.bench_function(format!("SF/{label}"), |b| {
            b.iter(|| {
                drop(black_box(
                    pair.bob
                        .export_session_cfe(black_box(&pair.alice_id))
                        .unwrap(),
                ))
            })
        });
    }
    group.finish();
}

fn config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(30)
        .without_plots()
}

criterion_group! { name = benches; config = config(); targets = payload, saving }
criterion_main!(benches);
