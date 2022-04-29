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
    pub fn init(bit_length: usize, batch_size: usize) -> Result<RangeParameters, ProofError> {
        if !batch_size.is_power_of_two() {
            return Err(ProofError::InvalidArgument(
                "Batch size must be a power of two".to_string(),
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
            bp_gens: BulletproofGens::new(bit_length, batch_size),
            pc_gens: PedersenGens::default(),
        })
    }

    /// Return a reference to the protected bulletproof generators
    pub fn bp_gens(&self) -> &BulletproofGens {
        &self.bp_gens
    }

    /// Return a reference to the protected base point generators
    pub fn pc_gens(&self) -> &PedersenGens {
        &self.pc_gens
    }

    /// Returns the
    pub fn batch_size(&self) -> usize {
        self.bp_gens.party_capacity
    }

    /// Returns the
    pub fn bit_length(&self) -> usize {
        self.bp_gens.gens_capacity
    }

    /// Return the protected value base point
    pub fn h_base(&self) -> RistrettoPoint {
        self.pc_gens.h_base
    }

    /// Return the protected mask base point
    pub fn g_base(&self) -> RistrettoPoint {
        self.pc_gens.g_base
    }

    /// Return the protected value compressed base point
    pub fn h_base_compressed(&self) -> CompressedRistretto {
        self.pc_gens.h_base_compressed
    }

    /// Return the protected mask compressed base point
    pub fn g_base_compressed(&self) -> CompressedRistretto {
        self.pc_gens.g_base_compressed
    }

    /// Return the protected value bulletproof generators
    pub fn hi_base(&self) -> Vec<RistrettoPoint> {
        let hi_base: Vec<RistrettoPoint> = self
            .bp_gens
            .h_iter(self.bit_length(), self.batch_size())
            .copied()
            .collect();
        hi_base
    }

    /// Return the protected mask bulletproof generators
    pub fn gi_base(&self) -> Vec<RistrettoPoint> {
        let gi_base: Vec<RistrettoPoint> = self
            .bp_gens
            .g_iter(self.bit_length(), self.batch_size())
            .copied()
            .collect();
        gi_base
    }
}
