// Copyright (c) 2018 Chain, Inc.
// SPDX-License-Identifier: MIT

// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Defines a `` trait for using a Scalar.

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

pub trait ScalarProtocol {
    /// Returns a non-zero random Scalar.
    fn random_not_zero<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar;
}

impl ScalarProtocol for Scalar {
    fn random_not_zero<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
        loop {
            let value = Scalar::random(rng);
            if value != Scalar::zero() {
                return value;
            }
        }
    }
}
