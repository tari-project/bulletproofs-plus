// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ embedded extended mask

use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{errors::ProofError, generators::pedersen_gens::ExtensionDegree};

/// Contains the embedded extended mask for non-aggregated proofs
#[derive(Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedMask {
    blindings: Vec<Scalar>, // Do not allow direct assignment of struct member (i.e. should not be public)
}

impl ExtendedMask {
    /// Construct a new extended mask
    pub fn assign(extension_degree: ExtensionDegree, blindings: Vec<Scalar>) -> Result<ExtendedMask, ProofError> {
        if blindings.is_empty() || blindings.len() != extension_degree as usize {
            Err(ProofError::InvalidLength(
                "Extended mask length must correspond to the extension degree".to_string(),
            ))
        } else {
            Ok(Self { blindings })
        }
    }

    /// Return the extended mask blinding factors
    pub fn blindings(&self) -> Result<Vec<Scalar>, ProofError> {
        if self.blindings.is_empty() {
            Err(ProofError::InvalidLength(
                "Extended mask values not assigned yet".to_string(),
            ))
        } else {
            Ok(self.blindings.clone())
        }
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use super::*;

    #[test]
    fn test_assign() {
        // Valid assignments
        for degree in 1..=6 {
            let blindings = vec![Scalar::ZERO; degree];
            let extension = ExtensionDegree::try_from(degree).unwrap();

            assert!(ExtendedMask::assign(extension, blindings).is_ok());
        }

        // Empty blinding vector
        assert!(ExtendedMask::assign(ExtensionDegree::DefaultPedersen, Vec::new()).is_err());

        // Extension degree mismatch
        let blindings = vec![Scalar::ZERO];
        assert!(ExtendedMask::assign(ExtensionDegree::AddTwoBasePoints, blindings).is_err());
    }

    #[test]
    fn test_blindings() {
        // Empty blinding vector; this shouldn't be possible
        let mask = ExtendedMask { blindings: Vec::new() };
        assert!(mask.blindings().is_err());

        // Valid mask
        let blindings = vec![Scalar::ZERO, Scalar::ONE];
        let mask = ExtendedMask::assign(ExtensionDegree::AddOneBasePoint, blindings.clone()).unwrap();
        assert_eq!(mask.blindings().unwrap(), blindings);
    }
}
