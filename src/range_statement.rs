// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

#![allow(non_snake_case)]

use crate::errors::ProofError;
use crate::range_parameters::RangeParameters;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

#[derive(Clone, Debug)]
pub struct RangeStatement {
    pub generators: RangeParameters,
    pub commitments: Vec<RistrettoPoint>, // range statement
    pub offsets: Vec<u64>,
    pub seed_nonce: Option<Scalar>,
}

impl RangeStatement {
    pub fn init(
        generators: RangeParameters,
        commitments: Vec<RistrettoPoint>,
        offsets: Vec<u64>,
        seed_nonce: Option<Scalar>,
    ) -> Result<RangeStatement, ProofError> {
        if !commitments.len().is_power_of_two() {
            return Err(ProofError::InternalDataInconsistent(
                "Number of commitments must be a power of two".to_string(),
            ));
        }
        if !offsets.len() == commitments.len() {
            return Err(ProofError::InternalDataInconsistent(
                "Incorrect number of offsets".to_string(),
            ));
        }
        if generators.batch_size() < commitments.len() {
            return Err(ProofError::InternalDataInconsistent(
                "Not enough generators for this statement".to_string(),
            ));
        }
        if seed_nonce.is_some() && commitments.len() > 1 {
            return Err(ProofError::InternalDataInconsistent(
                "Mask recovery is not supported with an aggregated statement".to_string(),
            ));
        }
        Ok(Self {
            generators,
            commitments,
            offsets,
            seed_nonce,
        })
    }
}
