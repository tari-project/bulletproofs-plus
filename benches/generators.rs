#[macro_use]
extern crate criterion;

use criterion::{Criterion, SamplingMode};
use tari_bulletproofs_plus::{BulletproofGens, PedersenGens};

fn pc_gens(c: &mut Criterion) {
    c.bench_function("PedersenGens::new", |b|
        // Benchmark this code
        b.iter(PedersenGens::default));
}

fn bp_gens(c: &mut Criterion) {
    let mut group = c.benchmark_group("bp_gens");
    group.sampling_mode(SamplingMode::Flat);
    for size in (0..10).map(|i| 2 << i) {
        let label = format!("BulletproofGens::new - size {}", size);
        group.bench_function(&label, |b|
            // Benchmark this code
            b.iter(|| BulletproofGens::new(size, 1)));
    }
    group.finish();
}

criterion_group! {
    bp,
    bp_gens,
    pc_gens,
}

criterion_main!(bp);
