// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ embedded extended mask

use curve25519_dalek::scalar::Scalar;

use crate::{errors::ProofError, generators::pedersen_gens::ExtensionDegree};

/// Contains the embedded extended mask for non-aggregated proofs
#[derive(Debug, PartialEq)]
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
