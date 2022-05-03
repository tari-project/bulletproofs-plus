#[macro_use]
extern crate criterion;

use std::ops::Div;

use criterion::{Criterion, SamplingMode};
use curve25519_dalek::scalar::Scalar;
use rand::{self, Rng};
use tari_bulletproofs_plus::{
    commitment_opening::CommitmentOpening,
    protocols::scalar_protocol::ScalarProtocol,
    range_parameters::RangeParameters,
    range_proof::RangeProof,
    range_statement::RangeStatement,
    range_witness::RangeWitness,
};

static AGGREGATION_SIZES: [usize; 6] = [1, 2, 4, 8, 16, 32];

fn div_floor_u64(value: f64, divisor: f64) -> u64 {
    f64::floor((value as f64).div(divisor)) as u64
}

fn create_aggregated_rangeproof_helper(bit_length: usize, c: &mut Criterion) {
    let mut group = c.benchmark_group("rangeproof creation");
    group.sampling_mode(SamplingMode::Flat);

    let transcript_label: &'static str = "BatchedRangeProofTest";
    let (value_min, value_max) = (0u64, (1u128 << (bit_length - 1)) as u64);

    for aggregation_factor in AGGREGATION_SIZES {
        let label = format!(
            "Aggregated {}-bit range proof creation, aggregation factor {}",
            bit_length, aggregation_factor
        );
        group.bench_function(&label, move |b| {
            // 1. Generators
            let generators = RangeParameters::init(bit_length, aggregation_factor).unwrap();

            // 2. Create witness data
            let mut witness = RangeWitness::new(vec![]);
            let mut commitments = vec![];
            let mut minimum_values = vec![];
            let mut rng = rand::thread_rng();
            for _ in 0..aggregation_factor {
                let value = rng.gen_range(value_min..value_max);
                minimum_values.push(Some(div_floor_u64(value as f64, 3f64)));
                let blinding = Scalar::random_not_zero(&mut rng);
                commitments.push(generators.pc_gens().commit(Scalar::from(value), blinding));
                witness.openings.push(CommitmentOpening::new(value, blinding));
            }

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
                let _ = RangeProof::prove(transcript_label, &statement.clone(), &witness);
            })
        });
    }
    group.finish();
}

// fn create_aggregated_rangeproof_n_8(c: &mut Criterion) {
//     create_aggregated_rangeproof_helper(8, c);
// }
//
// fn create_aggregated_rangeproof_n_16(c: &mut Criterion) {
//     create_aggregated_rangeproof_helper(16, c);
// }
//
// fn create_aggregated_rangeproof_n_32(c: &mut Criterion) {
//     create_aggregated_rangeproof_helper(32, c);
// }

fn create_aggregated_rangeproof_n_64(c: &mut Criterion) {
    create_aggregated_rangeproof_helper(64, c);
}

fn verify_aggregated_rangeproof_helper(bit_length: usize, c: &mut Criterion) {
    let mut group = c.benchmark_group("rangeproof verification");
    group.sampling_mode(SamplingMode::Flat);

    let transcript_label: &'static str = "BatchedRangeProofTest";
    let (value_min, value_max) = (0u64, (1u128 << (bit_length - 1)) as u64);

    for aggregation_factor in AGGREGATION_SIZES {
        let label = format!(
            "Aggregated {}-bit range proof verification, aggregation factor {}",
            bit_length, aggregation_factor
        );
        group.bench_function(&label, move |b| {
            // 0.  Batch data
            let mut statements = vec![];
            let mut proofs = vec![];

            // 1. Generators
            let generators = RangeParameters::init(bit_length, aggregation_factor).unwrap();

            // 2. Create witness data
            let mut witness = RangeWitness::new(vec![]);
            let mut commitments = vec![];
            let mut minimum_values = vec![];
            let mut rng = rand::thread_rng();
            for _ in 0..aggregation_factor {
                let value = rng.gen_range(value_min..value_max);
                minimum_values.push(Some(div_floor_u64(value as f64, 3f64)));
                let blinding = Scalar::random_not_zero(&mut rng);
                commitments.push(generators.pc_gens().commit(Scalar::from(value), blinding));
                witness.openings.push(CommitmentOpening::new(value, blinding));
            }

            // 3. Generate the statement
            let seed_nonce = if aggregation_factor == 1 {
                Some(Scalar::random_not_zero(&mut rng))
            } else {
                None
            };
            let statement =
                RangeStatement::init(generators, commitments.clone(), minimum_values.clone(), seed_nonce).unwrap();
            statements.push(statement.clone());

            // 4. Create the proof
            let proof = RangeProof::prove(transcript_label, &statement, &witness);
            proofs.push(proof.unwrap());

            // Benchmark this code
            b.iter(|| {
                // 5. Verify the aggregated proof
                let _ = RangeProof::verify(transcript_label, &statements.clone(), &proofs.clone()).unwrap();
            });
        });
    }
    group.finish();
}

// fn verify_aggregated_rangeproof_n_8(c: &mut Criterion) {
//     verify_aggregated_rangeproof_helper(8, c);
// }
//
// fn verify_aggregated_rangeproof_n_16(c: &mut Criterion) {
//     verify_aggregated_rangeproof_helper(16, c);
// }
//
// fn verify_aggregated_rangeproof_n_32(c: &mut Criterion) {
//     verify_aggregated_rangeproof_helper(32, c);
// }

fn verify_aggregated_rangeproof_n_64(c: &mut Criterion) {
    verify_aggregated_rangeproof_helper(64, c);
}

fn verify_batched_rangeproofs_helper(bit_length: usize, c: &mut Criterion) {
    let mut group = c.benchmark_group("rangeproof verification");
    group.sampling_mode(SamplingMode::Flat);

    let transcript_label: &'static str = "BatchedRangeProofTest";
    let (value_min, value_max) = (0u64, (1u128 << (bit_length - 1)) as u64);

    let max_range_proofs = AGGREGATION_SIZES
        .to_vec()
        .iter()
        .fold(u32::MIN, |a, &b| a.max(b as u32));
    // 0.  Batch data
    let mut statements = vec![];
    let mut proofs = vec![];

    // 1. Generators
    let generators = RangeParameters::init(bit_length, 1).unwrap();

    let mut rng = rand::thread_rng();
    for _ in 0..max_range_proofs {
        // 2. Create witness data
        let mut witness = RangeWitness::new(vec![]);
        let value = rng.gen_range(value_min..value_max);
        let blinding = Scalar::random_not_zero(&mut rng);
        witness.openings.push(CommitmentOpening::new(value, blinding));

        // 3. Generate the statement
        let seed_nonce = Some(Scalar::random_not_zero(&mut rng));
        let statement = RangeStatement::init(
            generators.clone(),
            vec![generators.pc_gens().commit(Scalar::from(value), blinding)],
            vec![Some(div_floor_u64(value as f64, 3f64))],
            seed_nonce,
        )
        .unwrap();
        statements.push(statement.clone());

        // 4. Create the proof
        let proof = RangeProof::prove(transcript_label, &statement, &witness);
        proofs.push(proof.unwrap());
    }

    for number_of_range_proofs in AGGREGATION_SIZES {
        let label = format!(
            "Batched {}-bit range proof verification, {} single range proofs",
            bit_length, number_of_range_proofs
        );
        let statements = &statements[0..number_of_range_proofs];
        let proofs = &proofs[0..number_of_range_proofs];

        group.bench_function(&label, move |b| {
            // Benchmark this code
            b.iter(|| {
                // 5. Verify the entire batch of single proofs
                let _ = RangeProof::verify(transcript_label, statements, proofs).unwrap();
            });
        });
    }
    group.finish();
}

fn verify_batched_rangeproof_n_64(c: &mut Criterion) {
    verify_batched_rangeproofs_helper(64, c);
}

criterion_group! {
    name = create_rp;
    config = Criterion::default().sample_size(10);
    targets =
    // create_aggregated_rangeproof_n_8,
    // create_aggregated_rangeproof_n_16,
    // create_aggregated_rangeproof_n_32,
    create_aggregated_rangeproof_n_64,
}

criterion_group! {
    name = verify_rp;
    config = Criterion::default();
    targets =
    // verify_aggregated_rangeproof_n_8,
    // verify_aggregated_rangeproof_n_16,
    // verify_aggregated_rangeproof_n_32,
    verify_aggregated_rangeproof_n_64,
}

criterion_group! {
    name = verify_batched_rp;
    config = Criterion::default();
    targets =
    // verify_aggregated_rangeproof_n_8,
    // verify_aggregated_rangeproof_n_16,
    // verify_aggregated_rangeproof_n_32,
    verify_batched_rangeproof_n_64,
}

criterion_main!(create_rp, verify_rp, verify_batched_rp);
