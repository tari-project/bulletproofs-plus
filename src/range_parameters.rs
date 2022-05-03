// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ range parameters (generators and base points) needed for a batch of range proofs

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

use crate::{
    errors::ProofError,
    generators::{bulletproof_gens::BulletproofGens, pedersen_gens::PedersenGens},
    range_proof::RangeProof,
};

/// Contains all the generators and base points needed for a batch of range proofs
#[derive(Clone, Debug)]
pub struct RangeParameters {
    /// Generators needed for aggregating up to `m` range proofs of up to `n` bits each.
    bp_gens: BulletproofGens,
    /// The pair of base points for Pedersen commitments.
    pc_gens: PedersenGens,
}

impl RangeParameters {
    /// Initialize a new 'RangeParameters' with sanity checks
    pub fn init(bit_length: usize, aggregation_factor: usize) -> Result<RangeParameters, ProofError> {
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
        if bit_length > RangeProof::MAX_BIT_LENGTH {
            return Err(ProofError::InvalidArgument(format!(
                "Bit length must be <= {}",
                RangeProof::MAX_BIT_LENGTH
            )));
        }

        Ok(Self {
            bp_gens: BulletproofGens::new(bit_length, aggregation_factor),
            pc_gens: PedersenGens::default(),
        })
    }

    /// Return a reference to the non-public bulletproof generators
    pub fn bp_gens(&self) -> &BulletproofGens {
        &self.bp_gens
    }

    /// Return a reference to the non-public base point generators
    pub fn pc_gens(&self) -> &PedersenGens {
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

    /// Returns the non-public value base point
    pub fn h_base(&self) -> RistrettoPoint {
        self.pc_gens.h_base
    }

    /// Returns the non-public mask base point
    pub fn g_base(&self) -> RistrettoPoint {
        self.pc_gens.g_base
    }

    /// Returns the non-public value compressed base point
    pub fn h_base_compressed(&self) -> CompressedRistretto {
        self.pc_gens.h_base_compressed
    }

    /// Returns the non-public mask compressed base point
    pub fn g_base_compressed(&self) -> CompressedRistretto {
        self.pc_gens.g_base_compressed
    }

    /// Return the non-public value iterator to the bulletproof generators
    pub fn hi_base_iter(&self) -> impl Iterator<Item = &RistrettoPoint> {
        self.bp_gens.h_iter(self.bit_length(), self.aggregation_factor())
    }

    /// Return the non-public value bulletproof generator references
    pub fn hi_base_ref(&self) -> Vec<&RistrettoPoint> {
        let hi_base_ref: Vec<&RistrettoPoint> = self.hi_base_iter().collect();
        hi_base_ref
    }

    /// Return the non-public value bulletproof generator references
    pub fn hi_base_copied(&self) -> Vec<RistrettoPoint> {
        let hi_base_ref: Vec<RistrettoPoint> = self.hi_base_iter().copied().collect();
        hi_base_ref
    }

    /// Return the non-public mask iterator to the bulletproof generators
    pub fn gi_base_iter(&self) -> impl Iterator<Item = &RistrettoPoint> {
        self.bp_gens.g_iter(self.bit_length(), self.aggregation_factor())
    }

    /// Return the non-public mask bulletproof generator references
    pub fn gi_base_ref(&self) -> Vec<&RistrettoPoint> {
        let gi_base_ref: Vec<&RistrettoPoint> = self.gi_base_iter().collect();
        gi_base_ref
    }

    /// Return the non-public mask bulletproof generators
    pub fn gi_base_copied(&self) -> Vec<RistrettoPoint> {
        let gi_base: Vec<RistrettoPoint> = self.gi_base_iter().copied().collect();
        gi_base
    }
}
