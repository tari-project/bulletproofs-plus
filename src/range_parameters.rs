// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::errors::ProofError;
use crate::range_proof::RangeProof;
use crate::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::RistrettoPoint;

/// Contains all the generators and base points needed for a batch of range proofs
#[derive(Clone, Debug)]
pub struct RangeParameters {
    /// Generators needed for aggregating up to `m` range proofs of up to `n` bits each.
    bp_gens: BulletproofGens,
    /// The pair of base points for Pedersen commitments.
    pc_gens: PedersenGens,
}

impl RangeParameters {
    pub fn init(bit_length: usize, batch_size: usize) -> Result<RangeParameters, ProofError> {
        if !batch_size.is_power_of_two() {
            return Err(ProofError::InternalDataInconsistent(
                "Batch size must be a power of two".to_string(),
            ));
        }
        if !bit_length.is_power_of_two() {
            return Err(ProofError::InternalDataInconsistent(
                "Bit length must be a power of two".to_string(),
            ));
        }
        if bit_length > RangeProof::MAX_BIT_LENGTH {
            return Err(ProofError::InternalDataInconsistent(format!(
                "Bit length must be <= {}",
                RangeProof::MAX_BIT_LENGTH
            )));
        }

        Ok(Self {
            bp_gens: BulletproofGens::new(bit_length, batch_size),
            pc_gens: PedersenGens::default(),
        })
    }

    pub fn bp_gens(&self) -> &BulletproofGens {
        &self.bp_gens
    }

    pub fn pc_gens(&self) -> &PedersenGens {
        &self.pc_gens
    }

    pub fn batch_size(&self) -> usize {
        self.bp_gens.party_capacity
    }

    pub fn bit_length(&self) -> usize {
        self.bp_gens.gens_capacity
    }

    pub fn h_base(&self) -> RistrettoPoint {
        self.pc_gens.b_base
    }

    pub fn g_base(&self) -> RistrettoPoint {
        self.pc_gens.b_base_blinding
    }

    pub fn hi_base(&self) -> Vec<RistrettoPoint> {
        let hi_base: Vec<RistrettoPoint> = self
            .bp_gens
            .h_iter(self.bit_length(), self.batch_size())
            .cloned()
            .collect();
        hi_base
    }

    pub fn gi_base(&self) -> Vec<RistrettoPoint> {
        let gi_base: Vec<RistrettoPoint> = self
            .bp_gens
            .g_iter(self.bit_length(), self.batch_size())
            .cloned()
            .collect();
        gi_base
    }
}
