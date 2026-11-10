// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ commitment opening struct

use alloc::{string::ToString, vec::Vec};

use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::ProofError;

/// Commitment openings to be used for Pedersen commitments
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
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

    /// Return the committed value
    pub fn v(&self) -> u64 {
        self.v
    }

    /// Return the blinding factor slice, or an error if empty
    pub fn blindings(&self) -> Result<&[Scalar], ProofError> {
        if self.r.is_empty() {
            Err(ProofError::InvalidLength(
                "Extended blinding factors cannot be empty".to_string(),
            ))
        } else {
            Ok(&self.r)
        }
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
    use alloc::vec;

    use super::*;

    #[test]
    fn test_empty_blinding() {
        let opening = CommitmentOpening::new(0u64, Vec::new());

        assert_eq!(
            opening.r_len(),
            Err(ProofError::InvalidLength(
                "Extended blinding factors cannot be empty".to_string()
            ))
        );
        assert_eq!(
            opening.blindings(),
            Err(ProofError::InvalidLength(
                "Extended blinding factors cannot be empty".to_string()
            ))
        );
    }

    #[test]
    fn test_accessors_and_equality() {
        let blindings = vec![Scalar::ONE, Scalar::ZERO];
        let opening = CommitmentOpening::new(42u64, blindings.clone());
        assert_eq!(opening.v(), 42u64);
        assert_eq!(opening.r_len(), Ok(2));
        assert_eq!(opening.blindings(), Ok(blindings.as_slice()));
        assert_eq!(opening.clone(), opening);
    }
}
