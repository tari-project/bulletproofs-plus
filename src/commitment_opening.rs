// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use curve25519_dalek::scalar::Scalar;

#[derive(Clone, Debug)]
pub struct CommitmentOpening {
    pub(crate) v: u64,
    pub(crate) r: Scalar,
}

impl CommitmentOpening {
    pub fn new(v: u64, r: Scalar) -> Self {
        Self { v, r }
    }
}
