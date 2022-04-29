// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::Rng;
use tari_bulletproofs_plus::{
    commitment_opening::CommitmentOpening,
    errors::ProofError,
    range_parameters::RangeParameters,
    range_proof::RangeProof,
    range_statement::RangeStatement,
    range_witness::RangeWitness,
    scalar_protocol::ScalarProtocol,
};

#[test]
fn test_non_aggregated_single_batch_multiple_bit_lengths() {
    let bit_lengths = vec![4, 16, 64];
    let batches = vec![1];
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::NoOffset,
    );
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::Intermediate,
    );
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::EqualToValue,
    );
    proof_batches(bit_lengths, batches, ProofOfMinimumValueStrategy::LargerThanValue);
}

#[test]
fn test_aggregated_single_batch_multiple_bit_lengths() {
    let bit_lengths = vec![2, 8, 32];
    let batches = vec![4];
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::NoOffset,
    );
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::Intermediate,
    );
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::EqualToValue,
    );
    proof_batches(bit_lengths, batches, ProofOfMinimumValueStrategy::LargerThanValue);
}

#[test]
fn test_non_aggregated_multiple_batches_single_bit_length() {
    let bit_lengths = vec![64];
    let batches = vec![1, 1, 1, 1, 1];
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::NoOffset,
    );
    // panic!("Hansie");
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::Intermediate,
    );
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::EqualToValue,
    );
    proof_batches(bit_lengths, batches, ProofOfMinimumValueStrategy::LargerThanValue);
}

#[test]
fn test_mixed_aggregation_multiple_batches_single_bit_length() {
    let bit_lengths = vec![64];
    let batches = vec![1, 2, 4, 8];
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::NoOffset,
    );
    // panic!("Hansie");
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::Intermediate,
    );
    proof_batches(
        bit_lengths.clone(),
        batches.clone(),
        ProofOfMinimumValueStrategy::EqualToValue,
    );
    proof_batches(bit_lengths, batches, ProofOfMinimumValueStrategy::LargerThanValue);
}

enum ProofOfMinimumValueStrategy {
    NoOffset,
    Intermediate,
    EqualToValue,
    LargerThanValue,
}

fn proof_batches(bit_lengths: Vec<usize>, batches: Vec<usize>, promise_strategy: ProofOfMinimumValueStrategy) {
    let mut rng = rand::thread_rng();
    let transcript_label: &'static str = "BatchedRangeProofTest";

    for bit_length in bit_lengths {
        // 0.  Batch data
        let mut private_masks: Vec<Option<Scalar>> = vec![];
        let mut public_masks: Vec<Option<Scalar>> = vec![];
        let mut statements_private = vec![];
        let mut statements_public = vec![];
        let mut proofs = vec![];

        let (value_min, value_max) = (0u64, (1u128 << (bit_length - 1)) as u64);
        for batch_size in batches.clone() {
            // 1. Generators
            let generators = RangeParameters::init(bit_length, batch_size).unwrap();

            // 2. Create witness data
            let mut witness = RangeWitness::new(vec![]);
            let mut commitments = vec![];
            let mut minimum_values = vec![];
            for m in 0..batch_size {
                let value = rng.gen_range(value_min..value_max);
                let minimum_value = match promise_strategy {
                    ProofOfMinimumValueStrategy::NoOffset => None,
                    ProofOfMinimumValueStrategy::Intermediate => Some(value / 3),
                    ProofOfMinimumValueStrategy::EqualToValue => Some(value),
                    ProofOfMinimumValueStrategy::LargerThanValue => Some(value + 1),
                };
                minimum_values.push(minimum_value);
                let blinding = Scalar::random_not_zero(&mut rng);
                commitments.push(generators.pc_gens().commit(Scalar::from(value), blinding));
                witness.openings.push(CommitmentOpening::new(value, blinding));
                if m == 0 {
                    if batch_size == 1 {
                        private_masks.push(Some(blinding));
                        public_masks.push(None);
                    } else {
                        private_masks.push(None);
                        public_masks.push(None);
                    }
                }
            }

            // 3. Generate the statement
            let seed_nonce = if batch_size == 1 {
                Some(Scalar::random_not_zero(&mut rng))
            } else {
                None
            };
            let private_statement = RangeStatement::init(
                generators.clone(),
                commitments.clone(),
                minimum_values.clone(),
                seed_nonce,
            )
            .unwrap();
            let public_statement =
                RangeStatement::init(generators.clone(), commitments, minimum_values.clone(), None).unwrap();

            // 4. Create the proofs
            let mut transcript = Transcript::new(transcript_label.as_bytes());

            let proof = RangeProof::prove(&mut transcript, &private_statement.clone(), &witness);
            match promise_strategy {
                ProofOfMinimumValueStrategy::LargerThanValue => match proof {
                    Ok(_) => {
                        panic!("Expected an error here")
                    },
                    Err(e) => match e {
                        ProofError::InvalidArgument(_) => {},
                        _ => {
                            panic!("Expected 'ProofError::InternalDataInconsistent'")
                        },
                    },
                },
                _ => {
                    statements_private.push(private_statement);
                    statements_public.push(public_statement);
                    proofs.push(proof.unwrap());
                },
            };
        }

        if !proofs.is_empty() {
            // 5. Verify the entire batch as the commitment owner, i.e. the prover self
            let recovered_private_masks =
                RangeProof::verify(transcript_label, &statements_private.clone(), &proofs.clone()).unwrap();
            assert_eq!(private_masks, recovered_private_masks);

            // 6. Verify the entire batch as public entity
            let recovered_public_masks = RangeProof::verify(transcript_label, &statements_public, &proofs).unwrap();
            assert_eq!(public_masks, recovered_public_masks);

            // 7. Try to recover the masks with incorrect seed_nonce values
            let mut compare = false;
            for statement in statements_private.clone() {
                if statement.seed_nonce.is_some() {
                    compare = true;
                    break;
                }
            }
            if compare {
                let mut statements_private_changed = vec![];
                for statement in statements_private.clone() {
                    statements_private_changed.push(RangeStatement {
                        generators: statement.generators.clone(),
                        commitments: statement.commitments.clone(),
                        commitments_compressed: statement.commitments_compressed.clone(),
                        minimum_value_promises: statement.minimum_value_promises.clone(),
                        seed_nonce: statement.seed_nonce.map(|seed_nonce| seed_nonce + Scalar::one()),
                    });
                }
                let recovered_private_masks_changed =
                    RangeProof::verify(transcript_label, &statements_private_changed, &proofs.clone()).unwrap();
                assert_ne!(private_masks, recovered_private_masks_changed);
            }

            // 8. Meddle with the minimum value promises
            let mut statements_public_changed = vec![];
            for statement in statements_public.clone() {
                statements_public_changed.push(RangeStatement {
                    generators: statement.generators.clone(),
                    commitments: statement.commitments.clone(),
                    commitments_compressed: statement.commitments_compressed.clone(),
                    minimum_value_promises: statement
                        .minimum_value_promises
                        .clone()
                        .iter()
                        .map(|promise| {
                            if let Some(value) = promise {
                                Some(value.saturating_add(1))
                            } else {
                                Some(1)
                            }
                        })
                        .collect(),
                    seed_nonce: statement.seed_nonce,
                });
            }
            match RangeProof::verify(transcript_label, &statements_public_changed, &proofs.clone()) {
                Ok(_) => {
                    panic!("Range proof should not verify")
                },
                Err(e) => match e {
                    ProofError::VerificationFailed(_) => {},
                    _ => {
                        panic!("Expected 'ProofError::VerificationFailed'")
                    },
                },
            };
        }
    }
}
