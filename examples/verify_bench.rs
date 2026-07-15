// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Quick timing harness for batch verification performance work.
//! Run with: cargo run --release --example verify_bench

#![allow(missing_docs)]

use std::time::Instant;

use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha12Rng;
use rand_core::{Rng, SeedableRng};
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
use tari_merlin::Transcript;

const BIT_LENGTH: usize = 64;
const TRANSCRIPT_LABEL: &str = "VerifyBench";

struct Case {
    label: String,
    transcripts: Vec<Transcript>,
    statements: Vec<RangeStatement<curve25519_dalek::ristretto::RistrettoPoint>>,
    proofs: Vec<RistrettoRangeProof>,
    action: VerifyAction,
}

fn build_case(batch_size: usize, aggregation_factor: usize, action: VerifyAction, rng: &mut ChaCha12Rng) -> Case {
    let pc_gens = ristretto::create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen);
    let generators = RangeParameters::init(BIT_LENGTH, aggregation_factor, pc_gens).unwrap();

    let mut transcripts = Vec::new();
    let mut statements = Vec::new();
    let mut proofs = Vec::new();

    for _ in 0..batch_size {
        let mut commitments = Vec::new();
        let mut minimum_values = Vec::new();
        let mut openings = Vec::new();
        for _ in 0..aggregation_factor {
            let value = rng.next_u64() >> 1;
            minimum_values.push(Some(value / 3));
            let blindings = vec![Scalar::random_not_zero(rng)];
            commitments.push(
                generators
                    .pc_gens()
                    .commit(&Scalar::from(value), blindings.as_slice())
                    .unwrap(),
            );
            openings.push(CommitmentOpening::new(value, blindings));
        }
        let witness = RangeWitness::init(openings).unwrap();
        let seed_nonce = if aggregation_factor == 1 {
            Some(Scalar::random_not_zero(rng))
        } else {
            None
        };
        let statement = RangeStatement::init(generators.clone(), commitments, minimum_values, seed_nonce).unwrap();
        let mut transcript = Transcript::new(TRANSCRIPT_LABEL.as_bytes());
        transcripts.push(transcript.clone());
        let proof = RistrettoRangeProof::prove_with_rng(&mut transcript, &statement, &witness, rng).unwrap();
        statements.push(statement);
        proofs.push(proof);
    }

    Case {
        label: format!("batch={batch_size:>3} agg={aggregation_factor:>2} {action:?}"),
        transcripts,
        statements,
        proofs,
        action,
    }
}

fn run_case(case: &Case) -> f64 {
    // Warm up
    for _ in 0..2 {
        RangeProof::verify_batch(
            &mut case.transcripts.clone(),
            &case.statements,
            &case.proofs,
            case.action,
        )
        .unwrap();
    }

    // Choose iteration count so each case runs a reasonable total time
    let probe = Instant::now();
    RangeProof::verify_batch(
        &mut case.transcripts.clone(),
        &case.statements,
        &case.proofs,
        case.action,
    )
    .unwrap();
    let single = probe.elapsed().as_secs_f64();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let iters = ((1.0 / single).ceil() as usize).clamp(5, 200);

    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let mut transcripts = case.transcripts.clone();
        let start = Instant::now();
        let masks = RangeProof::verify_batch(&mut transcripts, &case.statements, &case.proofs, case.action).unwrap();
        samples.push(start.elapsed().as_secs_f64());
        std::hint::black_box(masks);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn main() {
    let mut rng = ChaCha12Rng::seed_from_u64(8675309);

    let mut cases = Vec::new();
    for batch_size in [1usize, 4, 16, 64, 256] {
        cases.push(build_case(batch_size, 1, VerifyAction::VerifyOnly, &mut rng));
    }
    for aggregation_factor in [2usize, 8, 16] {
        cases.push(build_case(1, aggregation_factor, VerifyAction::VerifyOnly, &mut rng));
    }
    cases.push(build_case(4, 16, VerifyAction::VerifyOnly, &mut rng));
    for batch_size in [16usize, 64] {
        cases.push(build_case(batch_size, 1, VerifyAction::RecoverOnly, &mut rng));
    }
    cases.push(build_case(64, 1, VerifyAction::RecoverAndVerify, &mut rng));

    println!("{:<40} {:>12}", "case", "median");
    for case in &cases {
        let median = run_case(case);
        println!("{:<40} {:>9.3} ms", case.label, median * 1e3);
    }
}
