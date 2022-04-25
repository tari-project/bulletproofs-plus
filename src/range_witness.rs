// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::commitment_opening::CommitmentOpening;

#[derive(Clone, Debug)]
pub struct RangeWitness {
    pub openings: Vec<CommitmentOpening>,
}

impl RangeWitness {
    pub fn new(openings: Vec<CommitmentOpening>) -> Self {
        Self { openings }
    }
}
