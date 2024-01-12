// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ commitment opening struct

use alloc::{string::ToString, vec::Vec};

use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::ProofError;

/// Commitment openings to be used for Pedersen commitments
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CommitmentOpening {
    /// Value
    pub(crate) v: u64,
    /// Extended blinding factors
    pub(crate) r: Vec<Scalar>,
}

impl CommitmentOpening {
    /// Construct a new commitment opening
    pub fn new(v: u64, r: Vec<Scalar>) -> Self {
        Self { v, r }
    }

    /// Size of the blinding factor vector
    pub fn r_len(&self) -> Result<usize, ProofError> {
        if self.r.is_empty() {
            Err(ProofError::InvalidLength(
                "Extended blinding factors cannot be empty".to_string(),
            ))
        } else {
            Ok(self.r.len())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_empty_blinding() {
        let opening = CommitmentOpening::new(0u64, Vec::new());

        assert!(opening.r_len().is_err());
    }
}
