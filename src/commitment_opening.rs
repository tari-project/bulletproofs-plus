// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ commitment opening struct

use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

/// Commitment openings to be used for Pedersen commitments
#[derive(Clone, Zeroize)]
pub struct CommitmentOpening {
    pub(crate) v: u64,
    pub(crate) r: Scalar,
}

impl CommitmentOpening {
    /// Construct a new commitment opening
    pub fn new(v: u64, r: Scalar) -> Self {
        Self { v, r }
    }
}

/// Overwrite secrets with null bytes when they go out of scope.
impl Drop for CommitmentOpening {
    fn drop(&mut self) {
        self.v.zeroize();
        self.r.zeroize();
    }
}
