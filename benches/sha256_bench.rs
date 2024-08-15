use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fs_guard::sha256::{sha256, simd_sha256};

fn benchmark_sha256(c: &mut Criterion) {
    let data = vec![0u8; 1024]; // Example input data

    c.bench_function("SHA-256 without SIMD", |b| {
        b.iter(|| sha256(black_box(&data)))
    });

    c.bench_function("SHA-256 with SIMD", |b| {
        b.iter(|| simd_sha256(black_box(&data)))
    });
}

criterion_group!(benches, benchmark_sha256);
criterion_main!(benches);
