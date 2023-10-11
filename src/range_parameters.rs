// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ range parameters (generators and base points) needed for a batch of range proofs

use std::{
    fmt::{Debug, Formatter},
    sync::Arc,
};

use crate::{
    errors::ProofError,
    generators::{
        bulletproof_gens::BulletproofGens,
        pedersen_gens::{ExtensionDegree, PedersenGens},
    },
    range_proof::MAX_RANGE_PROOF_BIT_LENGTH,
    traits::{Compressable, FromUniformBytes, Precomputable},
};

/// Contains all the generators and base points needed for a batch of range proofs
#[derive(Clone)]
pub struct RangeParameters<P: Compressable + Precomputable> {
    /// Generators needed for aggregating up to `m` range proofs of up to `n` bits each.
    pub(crate) bp_gens: BulletproofGens<P>,
    /// The pair of base points for Pedersen commitments.
    pub(crate) pc_gens: PedersenGens<P>,
}

impl<P> RangeParameters<P>
where P: FromUniformBytes + Compressable + Clone + Precomputable
{
    /// Initialize a new 'RangeParameters' with sanity checks
    pub fn init(bit_length: usize, aggregation_factor: usize, pc_gens: PedersenGens<P>) -> Result<Self, ProofError> {
        if !aggregation_factor.is_power_of_two() {
            return Err(ProofError::InvalidArgument(
                "Aggregation factor size must be a power of two".to_string(),
            ));
        }
        if !bit_length.is_power_of_two() {
            return Err(ProofError::InvalidArgument(
                "Bit length must be a power of two".to_string(),
            ));
        }
        if bit_length > MAX_RANGE_PROOF_BIT_LENGTH {
            return Err(ProofError::InvalidArgument(format!(
                "Bit length must be <= {}",
                MAX_RANGE_PROOF_BIT_LENGTH
            )));
        }

        Ok(Self {
            bp_gens: BulletproofGens::new(bit_length, aggregation_factor)?,
            pc_gens,
        })
    }

    /// Return a reference to the non-public base point generators
    pub fn pc_gens(&self) -> &PedersenGens<P> {
        &self.pc_gens
    }

    /// Returns the aggregation factor
    pub fn aggregation_factor(&self) -> usize {
        self.bp_gens.party_capacity
    }

    /// Returns the bit length
    pub fn bit_length(&self) -> usize {
        self.bp_gens.gens_capacity
    }

    /// Returns the aggregation factor
    pub fn extension_degree(&self) -> ExtensionDegree {
        self.pc_gens.extension_degree
    }

    /// Returns the non-public value base point
    pub fn h_base(&self) -> &P {
        self.pc_gens.h_base()
    }

    /// Returns the non-public mask base points
    pub fn g_bases(&self) -> &[P] {
        &self.pc_gens.g_base_vec
    }

    /// Returns the non-public value compressed base point
    pub fn h_base_compressed(&self) -> P::Compressed {
        self.pc_gens.h_base_compressed()
    }

    /// Returns the non-public mask compressed base point
    pub fn g_bases_compressed(&self) -> &[P::Compressed] {
        &self.pc_gens.g_base_compressed_vec
    }

    /// Return the non-public value iterator to the bulletproof generators
    pub fn hi_base_iter(&self) -> impl Iterator<Item = &P> {
        self.bp_gens.h_iter(self.bit_length(), self.aggregation_factor())
    }

    /// Return the non-public mask iterator to the bulletproof generators
    pub fn gi_base_iter(&self) -> impl Iterator<Item = &P> {
        self.bp_gens.g_iter(self.bit_length(), self.aggregation_factor())
    }

    /// Return the interleaved precomputation tables
    pub fn precomp(&self) -> Arc<P::Precomputation> {
        self.bp_gens.precomp.clone()
    }
}

impl<P> Debug for RangeParameters<P>
where
    P: Compressable + Debug + Precomputable,
    P::Compressed: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeParameters")
            .field("pc_gens", &self.pc_gens)
            .field("bp_gens", &self.bp_gens)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ristretto::create_pedersen_gens_with_extension_degree;

    #[test]
    fn test_init_errors() {
        // Create some generators
        let gens = create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen);

        // Aggregation factor must be a power of two
        RangeParameters::init(64, 3, gens.clone()).unwrap_err();

        // Bit length must be a power of two
        RangeParameters::init(3, 4, gens.clone()).unwrap_err();

        // Bit length cannot be too large
        RangeParameters::init(2 * MAX_RANGE_PROOF_BIT_LENGTH, 4, gens.clone()).unwrap_err();
    }
}
