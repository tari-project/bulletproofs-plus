// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ commitment openings for the aggregated case

use zeroize::Zeroize;

use crate::commitment_opening::CommitmentOpening;

/// A convenience struct for holding commitment openings for the aggregated case
#[derive(Clone)]
pub struct RangeWitness {
    /// The vector of commitment openings for the aggregated case
    pub openings: Vec<CommitmentOpening>,
}

impl RangeWitness {
    /// Construct a new 'RangeWitness'
    pub fn new(openings: Vec<CommitmentOpening>) -> Self {
        Self { openings }
    }
}

/// Overwrite secrets with null bytes when they go out of scope.
impl Drop for RangeWitness {
    fn drop(&mut self) {
        for item in &mut self.openings {
            item.zeroize();
        }
    }
}
