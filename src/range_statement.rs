// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ generators, vector of commitments, vector of optional minimum promised
//! values and a vector of optional seed nonces for mask recovery

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use zeroize::Zeroize;

use crate::{errors::ProofError, range_parameters::RangeParameters};

/// The range proof statement contains the generators, vector of commitments, vector of optional minimum promised
/// values and a vector of optional seed nonces for mask recovery
#[derive(Clone, Debug)]
pub struct RangeStatement {
    /// The generators and base points needed for a batch of range proofs
    pub generators: RangeParameters,
    /// The batch of commitments
    pub commitments: Vec<RistrettoPoint>,
    /// The batch of compressed commitments
    pub commitments_compressed: Vec<CompressedRistretto>,
    /// Optional minimum promised values
    pub minimum_value_promises: Vec<Option<u64>>,
    /// Optional seed nonces for mask recovery
    pub seed_nonce: Option<Scalar>,
}

impl RangeStatement {
    /// Initialize a new 'RangeStatement' with sanity checks
    pub fn init(
        generators: RangeParameters,
        commitments: Vec<RistrettoPoint>,
        minimum_value_promise: Vec<Option<u64>>,
        seed_nonce: Option<Scalar>,
    ) -> Result<RangeStatement, ProofError> {
        if !commitments.len().is_power_of_two() {
            return Err(ProofError::InvalidArgument(
                "Number of commitments must be a power of two".to_string(),
            ));
        }
        if !minimum_value_promise.len() == commitments.len() {
            return Err(ProofError::InvalidArgument(
                "Incorrect number of minimum value promises".to_string(),
            ));
        }
        if generators.batch_size() < commitments.len() {
            return Err(ProofError::InvalidArgument(
                "Not enough generators for this statement".to_string(),
            ));
        }
        if seed_nonce.is_some() && commitments.len() > 1 {
            return Err(ProofError::InvalidArgument(
                "Mask recovery is not supported with an aggregated statement".to_string(),
            ));
        }
        let mut commitments_compressed = Vec::with_capacity(commitments.len());
        for item in commitments.clone() {
            commitments_compressed.push(item.compress());
        }
        Ok(Self {
            generators,
            commitments,
            commitments_compressed,
            minimum_value_promises: minimum_value_promise,
            seed_nonce,
        })
    }
}

/// Overwrite secrets with null bytes when they go out of scope.
impl Drop for RangeStatement {
    fn drop(&mut self) {
        self.seed_nonce.zeroize();
    }
}
