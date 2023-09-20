// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ commitment openings for the aggregated case

use std::convert::TryInto;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{commitment_opening::CommitmentOpening, errors::ProofError, generators::pedersen_gens::ExtensionDegree};

/// A convenience struct for holding commitment openings for the aggregated case
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
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
            return Err(ProofError::InvalidLength("Vector openings cannot be empty".to_string()));
        }
        let extension_degree = openings[0].r_len()?;
        for item in openings.iter().skip(1) {
            if extension_degree != item.r_len()? {
                return Err(ProofError::InvalidLength(
                    "Extended blinding factors must have consistent length".to_string(),
                ));
            }
        }
        Ok(Self {
            openings,
            extension_degree: extension_degree.try_into()?,
        })
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::Scalar;

    use super::*;

    #[test]
    fn test_init_errors() {
        let s = Scalar::ZERO;

        // Empty openings
        assert!(RangeWitness::init(Vec::new()).is_err());

        // Mismatched blinding factor lengths
        let openings = vec![
            CommitmentOpening::new(1u64, vec![s]),
            CommitmentOpening::new(1u64, vec![s, s]),
        ];
        assert!(RangeWitness::init(openings).is_err());
    }
}
