// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

#![allow(missing_docs)]

#[macro_use]
extern crate criterion;

use criterion::{Criterion, SamplingMode};
use curve25519_dalek::ristretto::RistrettoPoint;
use tari_bulletproofs_plus::{
    generators::pedersen_gens::ExtensionDegree,
    ristretto::create_pedersen_gens_with_extension_degree,
    BulletproofGens,
};

// Reduced spectrum of tests for the sake of CI bench tests
static EXTENSION_DEGREE: [ExtensionDegree; 2] = [ExtensionDegree::DefaultPedersen, ExtensionDegree::AddFiveBasePoints];
static BP_GENS_ARR: [usize; 5] = [0, 3, 5, 7, 9];
// To do a full spectrum of tests, use these constants instead
// static EXTENSION_DEGREE: [ExtensionDegree; 6] = [
//     ExtensionDegree::Zero,
//     ExtensionDegree::One,
//     ExtensionDegree::Two,
//     ExtensionDegree::Three,
//     ExtensionDegree::Four,
//     ExtensionDegree::Five,
// ];
// static BP_GENS_ARR: [usize; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

fn pc_gens(c: &mut Criterion) {
    let mut group = c.benchmark_group("PedersenGens");
    group.sampling_mode(SamplingMode::Flat);
    for extension_degree in &EXTENSION_DEGREE {
        let label = format!("PedersenGens::with_extension_degree({:?})", extension_degree);
        group.bench_function(&label, |b|
            // Benchmark this code
            b.iter(|| create_pedersen_gens_with_extension_degree(*extension_degree)));
    }
    group.finish();
}

fn bp_gens(c: &mut Criterion) {
    let mut group = c.benchmark_group("BulletproofGens");
    group.sampling_mode(SamplingMode::Flat);
    for size in BP_GENS_ARR.map(|i| 2 << i) {
        let label = format!("BulletproofGens::new - size {}", size);
        group.bench_function(&label, |b|
            // Benchmark this code
            b.iter(|| BulletproofGens::<RistrettoPoint>::new(size, 1)));
    }
    group.finish();
}

criterion_group! {
    name = pc_generators;
    config = Criterion::default();
    targets =
    pc_gens,
}

criterion_group! {
    name = bp_generators;
    config = Criterion::default();
    targets =
    bp_gens,
}

criterion_main!(pc_generators, bp_generators);
