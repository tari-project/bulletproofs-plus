// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ embedded extended mask

use curve25519_dalek::scalar::Scalar;

use crate::{errors::ProofError, generators::pedersen_gens::ExtensionDegree};

/// Contains the embedded extended mask for non-aggregated proofs
#[derive(Debug, PartialEq)]
pub struct ExtendedMask {
    extended_mask: Vec<Scalar>, // Do not allow direct assignment of struct member (i.e. should not be public)
}

impl ExtendedMask {
    /// Construct a new extended mask
    pub fn assign(extension_degree: ExtensionDegree, extended_mask: Vec<Scalar>) -> Result<ExtendedMask, ProofError> {
        if extended_mask.is_empty() || extended_mask.len() != extension_degree as usize {
            Err(ProofError::InvalidLength(
                "Extended mask length must correspond to the extension degree".to_string(),
            ))
        } else {
            Ok(Self { extended_mask })
        }
    }
}
