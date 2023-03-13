// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ commitment openings for the aggregated case

use core::convert::TryInto;

#[cfg(feature = "zero")]
use zeroize::Zeroize;
use alloc::vec::Vec;
use crate::{commitment_opening::CommitmentOpening, errors::ProofError, generators::pedersen_gens::ExtensionDegree};
use crate::alloc::string::ToString;

/// A convenience struct for holding commitment openings for the aggregated case
#[derive(Clone)]
pub struct RangeWitness {
    /// The vector of commitment openings for the aggregated case
    pub openings: Vec<CommitmentOpening>,
    /// Blinding factor extension degree
    pub extension_degree: ExtensionDegree,
}

impl RangeWitness {
    /// Construct a new 'RangeWitness'
    pub fn init(openings: Vec<CommitmentOpening>) -> Result<RangeWitness, ProofError> {
        if openings.is_empty() {
            return Err(ProofError::InvalidLength {
                reason: "Vector openings cannot be empty".to_string(),
            });
        }
        let extension_degree = openings[0].r_len()?;
        for item in openings.iter().skip(1) {
            if extension_degree != item.r_len()? {
                return Err(ProofError::InvalidLength {
                    reason: "Extended blinding factors must have consistent length".to_string(),
                });
            }
        }
        Ok(Self {
            openings,
            extension_degree: extension_degree.try_into()?,
        })
    }
}

/// Overwrite secrets with null bytes when they go out of scope.
impl Drop for RangeWitness {
    fn drop(&mut self) {
        for item in &mut self.openings {
            #[cfg(feature = "zero")]
            item.zeroize();
        }
    }
}
