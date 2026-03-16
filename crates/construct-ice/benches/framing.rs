use bytes::BytesMut;
use construct_ice::framing::encoder::FrameEncoder;
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_frame_encode(c: &mut Criterion) {
    let key = [0u8; 32];
    let nonce_prefix = [0u8; 16];
    let siphash_key = [0u8; 16];
    let siphash_iv = [0u8; 8];
    let payload = vec![0xab_u8; 1024];

    c.bench_function("encode 1KB frame", |b| {
        b.iter(|| {
            let mut encoder = FrameEncoder::new(&key, &nonce_prefix, &siphash_key, &siphash_iv);
            let mut dst = BytesMut::new();
            encoder.encode(&payload, &mut dst).unwrap();
        });
    });

    c.bench_function("encode 4KB payload (multi-frame)", |b| {
        let large = vec![0xab_u8; 4096];
        b.iter(|| {
            let mut encoder = FrameEncoder::new(&key, &nonce_prefix, &siphash_key, &siphash_iv);
            let mut dst = BytesMut::new();
            encoder.encode(&large, &mut dst).unwrap();
        });
    });
}

criterion_group!(benches, bench_frame_encode);
criterion_main!(benches);
