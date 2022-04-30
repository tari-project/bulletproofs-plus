// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

//! Bulletproofs+ `ScalarProtocol` trait for using a Scalar

use blake2::{Blake2b, Digest};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};

/// Defines a `ScalarProtocol` trait for using a Scalar
pub trait ScalarProtocol {
    /// Returns a non-zero random Scalar
    fn random_not_zero<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar;

    /// Construct a scalar from an existing Blake2b instance (helper function to implement 'Scalar::from_hash<Blake2b>')
    fn from_hasher_blake2b(hasher: Blake2b) -> Scalar;
}

impl ScalarProtocol for Scalar {
    // 'Scalar::random(rng)' in most cases will not return zero due to the intent of the implementation, but this is
    // not guaranteed. This function makes it clear that zero will never be returned
    fn random_not_zero<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
        loop {
            let value = Scalar::random(rng);
            if value != Scalar::zero() {
                return value;
            }
        }
    }

    fn from_hasher_blake2b(hasher: Blake2b) -> Scalar {
        let mut output = [0u8; 64];
        output.copy_from_slice(hasher.finalize().as_slice());
        Scalar::from_bytes_mod_order_wide(&output)
    }
}
