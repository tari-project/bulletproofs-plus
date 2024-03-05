// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

#![allow(missing_docs)]

#[macro_use]
extern crate criterion;

use criterion::{Criterion, SamplingMode};
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha12Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use tari_bulletproofs_plus::{
    commitment_opening::CommitmentOpening,
    generators::pedersen_gens::ExtensionDegree,
    protocols::scalar_protocol::ScalarProtocol,
    range_parameters::RangeParameters,
    range_proof::{RangeProof, VerifyAction},
    range_statement::RangeStatement,
    range_witness::RangeWitness,
    ristretto,
    ristretto::RistrettoRangeProof,
};

// Reduced spectrum of tests for the sake of CI bench tests
static AGGREGATION_SIZES: [usize; 4] = [1, 2, 4, 8];
static BATCHED_SIZES: [usize; 4] = [1, 2, 4, 8];
static BIT_LENGTHS: [usize; 3] = [2, 4, 8];
static EXTENSION_DEGREE: [ExtensionDegree; 1] = [ExtensionDegree::DefaultPedersen];
static EXTRACT_MASKS: [VerifyAction; 1] = [VerifyAction::VerifyOnly];
// To do a full spectrum of tests, use these constants instead
// static AGGREGATION_SIZES: [usize; 6] = [1, 2, 4, 8, 16, 32];
// static BATCHED_SIZES: [usize; 9] = [1, 2, 4, 8, 16, 32, 64, 128, 256];
// static BIT_LENGTHS: [usize; 3] = [8, 16, 32];
// static EXTENSION_DEGREE: [ExtensionDegree; 3] = [ExtensionDegree::Zero, ExtensionDegree::Two, ExtensionDegree::Four];
// static EXTRACT_MASKS: [VerifyAction; 2] =  [VerifyAction::VerifyOnly, VerifyAction::RecoverOnly];

#[allow(clippy::arithmetic_side_effects)]
fn create_aggregated_rangeproof_helper(bit_length: usize, extension_degree: ExtensionDegree, c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof_creation");
    group.sampling_mode(SamplingMode::Flat);

    let mut rng = ChaCha12Rng::seed_from_u64(8675309); // for testing only!

    let transcript_label: &'static str = "BatchedRangeProofTest";
    #[allow(clippy::cast_possible_truncation)]
    let value_max = (1u128 << (bit_length - 1)) as u64;

    for aggregation_factor in AGGREGATION_SIZES {
        let label = format!(
            "Agg {}-bit BP+ create agg factor {} degree {:?}",
            bit_length, aggregation_factor, extension_degree
        );
        group.bench_function(&label, |b| {
            // 1. Generators
            let generators = RangeParameters::init(
                bit_length,
                aggregation_factor,
                ristretto::create_pedersen_gens_with_extension_degree(extension_degree),
            )
            .unwrap();

            // 2. Create witness data
            let mut commitments = vec![];
            let mut minimum_values = vec![];
            let mut openings = vec![];
            for _ in 0..aggregation_factor {
                let value = rng.as_rngcore().next_u64() % value_max; // introduces bias, but that's fine for testing
                minimum_values.push(Some(value / 3));
                let blindings = vec![Scalar::random_not_zero(&mut rng); extension_degree as usize];
                commitments.push(
                    generators
                        .pc_gens()
                        .commit(&Scalar::from(value), blindings.as_slice())
                        .unwrap(),
                );
                openings.push(CommitmentOpening::new(value, blindings.clone()));
            }
            let witness = RangeWitness::init(openings).unwrap();

            // 3. Generate the statement
            let seed_nonce = if aggregation_factor == 1 {
                Some(Scalar::random_not_zero(&mut rng))
            } else {
                None
            };
            let statement =
                RangeStatement::init(generators, commitments.clone(), minimum_values.clone(), seed_nonce).unwrap();

            // Benchmark this code
            b.iter(|| {
                // 4. Create the aggregated proof
                let _proof = RistrettoRangeProof::prove_with_rng(transcript_label, &statement, &witness, &mut rng);
            })
        });
    }
    group.finish();
}

fn create_aggregated_rangeproof_n_small(c: &mut Criterion) {
    for bit_length in BIT_LENGTHS {
        create_aggregated_rangeproof_helper(bit_length, ExtensionDegree::DefaultPedersen, c);
    }
}

fn create_aggregated_rangeproof_n_64(c: &mut Criterion) {
    for extension_degree in &EXTENSION_DEGREE {
        create_aggregated_rangeproof_helper(64, *extension_degree, c);
    }
}

#[allow(clippy::arithmetic_side_effects)]
fn verify_aggregated_rangeproof_helper(bit_length: usize, extension_degree: ExtensionDegree, c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof_verification");
    group.sampling_mode(SamplingMode::Flat);

    let mut rng = ChaCha12Rng::seed_from_u64(8675309); // for testing only!

    let transcript_label: &'static str = "BatchedRangeProofTest";
    #[allow(clippy::cast_possible_truncation)]
    let value_max = (1u128 << (bit_length - 1)) as u64;

    for aggregation_factor in AGGREGATION_SIZES {
        let pederson_gens = ristretto::create_pedersen_gens_with_extension_degree(extension_degree);
        let label = format!(
            "Agg {}-bit BP+ verify agg factor {} degree {:?}",
            bit_length, aggregation_factor, extension_degree
        );
        group.bench_function(&label, |b| {
            // 0. Batch data
            let mut statements = vec![];
            let mut proofs = vec![];
            let mut transcript_labels = vec![];

            // 1. Generators
            let generators = RangeParameters::init(bit_length, aggregation_factor, pederson_gens.clone()).unwrap();

            // 2. Create witness data
            let mut commitments = vec![];
            let mut minimum_values = vec![];
            let mut openings = vec![];
            for _ in 0..aggregation_factor {
                let value = rng.as_rngcore().next_u64() % value_max; // introduces bias, but that's fine for testing
                minimum_values.push(Some(value / 3));
                let blindings = vec![Scalar::random_not_zero(&mut rng); extension_degree as usize];
                commitments.push(
                    generators
                        .pc_gens()
                        .commit(&Scalar::from(value), blindings.as_slice())
                        .unwrap(),
                );
                openings.push(CommitmentOpening::new(value, blindings.clone()));
            }
            let witness = RangeWitness::init(openings).unwrap();

            // 3. Generate the statement
            let seed_nonce = if aggregation_factor == 1 {
                Some(Scalar::random_not_zero(&mut rng))
            } else {
                None
            };
            let statement =
                RangeStatement::init(generators, commitments.clone(), minimum_values.clone(), seed_nonce).unwrap();
            statements.push(statement.clone());
            transcript_labels.push(transcript_label);

            // 4. Create the proof
            let proof = RistrettoRangeProof::prove_with_rng(transcript_label, &statement, &witness, &mut rng).unwrap();
            proofs.push(proof);

            // Benchmark this code
            b.iter(|| {
                // 5. Verify the aggregated proof
                let _masks =
                    RangeProof::verify_batch(&transcript_labels, &statements, &proofs, VerifyAction::VerifyOnly)
                        .unwrap();
            });
        });
    }
    group.finish();
}

fn verify_aggregated_rangeproof_n_small(c: &mut Criterion) {
    for bit_length in BIT_LENGTHS {
        verify_aggregated_rangeproof_helper(bit_length, ExtensionDegree::DefaultPedersen, c);
    }
}

fn verify_aggregated_rangeproof_n_64(c: &mut Criterion) {
    for extension_degree in &EXTENSION_DEGREE {
        verify_aggregated_rangeproof_helper(64, *extension_degree, c);
    }
}

#[allow(clippy::arithmetic_side_effects)]
fn verify_batched_rangeproofs_helper(bit_length: usize, extension_degree: ExtensionDegree, c: &mut Criterion) {
    let mut group = c.benchmark_group("batched_range_proof_verification");
    group.sampling_mode(SamplingMode::Flat);

    let mut rng = ChaCha12Rng::seed_from_u64(8675309); // for testing only!

    let transcript_label: &'static str = "BatchedRangeProofTest";
    #[allow(clippy::cast_possible_truncation)]
    let value_max = (1u128 << (bit_length - 1)) as u64;

    for extract_masks in EXTRACT_MASKS {
        for number_of_range_proofs in BATCHED_SIZES {
            let label = format!(
                "Batched {}-bit BP+ verify {} deg {:?} masks {:?}",
                bit_length, number_of_range_proofs, extension_degree, extract_masks
            );

            // Generators
            let pc_gens = ristretto::create_pedersen_gens_with_extension_degree(extension_degree);
            let generators = RangeParameters::init(bit_length, 1, pc_gens).unwrap();

            group.bench_function(&label, |b| {
                // Batch data
                let mut statements = vec![];
                let mut proofs = vec![];
                let mut transcript_labels = vec![];

                for _ in 0..number_of_range_proofs {
                    // Witness data
                    let mut openings = vec![];
                    let value = rng.as_rngcore().next_u64() % value_max; // introduces bias, but that's fine for testing
                    let blindings = vec![Scalar::random_not_zero(&mut rng); extension_degree as usize];
                    openings.push(CommitmentOpening::new(value, blindings.clone()));
                    let witness = RangeWitness::init(openings).unwrap();

                    // Statement data
                    let seed_nonce = Some(Scalar::random_not_zero(&mut rng));
                    let statement = RangeStatement::init(
                        generators.clone(),
                        vec![generators
                            .pc_gens()
                            .commit(&Scalar::from(value), blindings.as_slice())
                            .unwrap()],
                        vec![Some(value / 3)],
                        seed_nonce,
                    )
                    .unwrap();
                    statements.push(statement.clone());
                    transcript_labels.push(transcript_label);

                    // Proof
                    let proof =
                        RistrettoRangeProof::prove_with_rng(transcript_label, &statement, &witness, &mut rng).unwrap();
                    proofs.push(proof);
                }

                // Benchmark this code
                b.iter(|| {
                    // Verify the entire batch of proofs
                    match extract_masks {
                        VerifyAction::VerifyOnly => {
                            let _masks = RangeProof::verify_batch(
                                &transcript_labels,
                                &statements,
                                &proofs,
                                VerifyAction::VerifyOnly,
                            )
                            .unwrap();
                        },
                        VerifyAction::RecoverOnly => {
                            let _masks = RangeProof::verify_batch(
                                &transcript_labels,
                                &statements,
                                &proofs,
                                VerifyAction::RecoverOnly,
                            )
                            .unwrap();
                        },
                        _ => {},
                    }
                });
            });
        }
    }
    group.finish();
}

fn verify_batched_rangeproof_n_64(c: &mut Criterion) {
    for extension_degree in &EXTENSION_DEGREE {
        verify_batched_rangeproofs_helper(64, *extension_degree, c);
    }
}

criterion_group! {
    name = create_rp;
    config = Criterion::default();
    targets =
    create_aggregated_rangeproof_n_small,
    create_aggregated_rangeproof_n_64,
}

criterion_group! {
    name = verify_rp;
    config = Criterion::default();
    targets =
    verify_aggregated_rangeproof_n_small,
    verify_aggregated_rangeproof_n_64,
}

criterion_group! {
    name = verify_batched_rp;
    config = Criterion::default();
    targets =
    verify_batched_rangeproof_n_64,
}

criterion_main!(create_rp, verify_rp, verify_batched_rp);
