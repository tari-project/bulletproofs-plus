// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ generators, vector of commitments, vector of optional minimum promised
//! values and a vector of optional seed nonces for mask recovery

use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

use crate::{
    errors::ProofError,
    range_parameters::RangeParameters,
    traits::{Compressable, FromUniformBytes},
};

/// The range proof statement contains the generators, vector of commitments, vector of optional minimum promised
/// values and a vector of optional seed nonces for mask recovery
#[derive(Clone)]
pub struct RangeStatement<P: Compressable> {
    /// The generators and base points needed for aggregating range proofs
    pub generators: RangeParameters<P>,
    /// The aggregated commitments
    pub commitments: Vec<P>,
    /// The aggregated compressed commitments
    pub commitments_compressed: Vec<P::Compressed>,
    /// Optional minimum promised values
    pub minimum_value_promises: Vec<Option<u64>>,
}

impl<P: Compressable + FromUniformBytes + Clone> RangeStatement<P> {
    /// Initialize a new 'RangeStatement' with sanity checks
    pub fn init(
        generators: RangeParameters<P>,
        commitments: Vec<P>,
        minimum_value_promises: Vec<Option<u64>>,
    ) -> Result<Self, ProofError> {
        if !commitments.len().is_power_of_two() {
            return Err(ProofError::InvalidArgument(
                "Number of commitments must be a power of two".to_string(),
            ));
        }
        if !minimum_value_promises.len() == commitments.len() {
            return Err(ProofError::InvalidArgument(
                "Incorrect number of minimum value promises".to_string(),
            ));
        }
        if generators.aggregation_factor() < commitments.len() {
            return Err(ProofError::InvalidArgument(
                "Not enough generators for this statement".to_string(),
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
            minimum_value_promises,
        })
    }
}

/// Range statements may come equipped with seed nonce pairs used for mask extraction by a designated verifier
/// They are kept separate from the statement to simplify proving operations
pub struct RangeSeedNonce {
    /// The seed nonce used for the helper's values
    pub seed_nonce: Scalar,
    /// The seed nonce used for the signer's value
    pub seed_nonce_alpha: Scalar,
}

/// Treat nonce seeds as secret data
impl Drop for RangeSeedNonce {
    fn drop(&mut self) {
        self.seed_nonce.zeroize();
        self.seed_nonce_alpha.zeroize();
    }
}
