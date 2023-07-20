// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ generators, vector of commitments, vector of optional minimum promised
//! values and a vector of optional seed nonces for mask recovery

use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

use crate::{
    errors::ProofError,
    range_parameters::RangeParameters,
    traits::{Compressable, FromUniformBytes, Precomputable},
};

/// The range proof statement contains the generators, vector of commitments, vector of optional minimum promised
/// values and a vector of optional seed nonces for mask recovery
#[derive(Clone)]
pub struct RangeStatement<P: Compressable + Precomputable> {
    /// The generators and base points needed for aggregating range proofs
    pub generators: RangeParameters<P>,
    /// The aggregated commitments
    pub commitments: Vec<P>,
    /// The aggregated compressed commitments
    pub commitments_compressed: Vec<P::Compressed>,
    /// Optional minimum promised values
    pub minimum_value_promises: Vec<Option<u64>>,
    /// Optional seed nonce for mask recovery
    pub seed_nonce: Option<Scalar>,
}

impl<P: Compressable + FromUniformBytes + Clone + Precomputable> RangeStatement<P> {
    /// Initialize a new 'RangeStatement' with sanity checks
    pub fn init(
        generators: RangeParameters<P>,
        commitments: Vec<P>,
        minimum_value_promises: Vec<Option<u64>>,
        seed_nonce: Option<Scalar>,
    ) -> Result<Self, ProofError> {
        if !commitments.len().is_power_of_two() {
            return Err(ProofError::InvalidArgument(
                "Number of commitments must be a power of two".to_string(),
            ));
        }
        if minimum_value_promises.len() != commitments.len() {
            return Err(ProofError::InvalidArgument(
                "Incorrect number of minimum value promises".to_string(),
            ));
        }
        if generators.aggregation_factor() < commitments.len() {
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
            minimum_value_promises,
            seed_nonce,
        })
    }
}

/// Overwrite secrets with null bytes when they go out of scope.
impl<P: Compressable + Precomputable> Drop for RangeStatement<P> {
    fn drop(&mut self) {
        self.seed_nonce.zeroize();
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::RistrettoPoint;

    use super::*;
    use crate::{
        generators::pedersen_gens::ExtensionDegree,
        range_parameters::RangeParameters,
        ristretto::create_pedersen_gens_with_extension_degree,
    };

    #[test]
    fn test_init_errors() {
        let p = RistrettoPoint::default();

        // Set up parameters
        let params = RangeParameters::init(
            64,
            2,
            create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen),
        )
        .unwrap();

        // Commitment vector length must be a power of two
        assert!(RangeStatement::init(params.clone(), vec![p; 3], vec![], None,).is_err());

        // Promises must match commitments in length
        assert!(RangeStatement::init(params.clone(), vec![p; 2], vec![None], None,).is_err());

        // Need enough generators for the commitments
        assert!(RangeStatement::init(params.clone(), vec![p; 4], vec![None; 4], None,).is_err());

        // Rewinding isn't supported for nontrivial aggregation
        assert!(RangeStatement::init(params.clone(), vec![p; 2], vec![None; 2], Some(Scalar::ONE),).is_err());
    }
}
