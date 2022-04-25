// Copyright (c) 2018 Chain, Inc.
// SPDX-License-Identifier: MIT

// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::MultiscalarMul,
};
use sha3::Sha3_512;

/// Represents a pair of base points for Pedersen commitments
///
/// The Bulletproofs implementation and API is designed to support pluggable bases for Pedersen commitments, so that
/// the choice of bases is not hard-coded.
///
/// The default generators are:
///
/// * `b_base`: the `ristretto255` basepoint;
/// * `b_base_blinding`: the result of `ristretto255` SHA3-512
/// hash-to-group on input `B_bytes`.
#[derive(Copy, Clone, Debug)]
pub struct PedersenGens {
    /// Base for the committed value
    pub b_base: RistrettoPoint,
    /// Base for the blinding factor
    pub b_base_blinding: RistrettoPoint,
}

impl PedersenGens {
    /// Creates a Pedersen commitment using the value scalar and a blinding factor.
    pub fn commit(&self, value: Scalar, blinding: Scalar) -> RistrettoPoint {
        RistrettoPoint::multiscalar_mul(&[value, blinding], &[self.b_base, self.b_base_blinding])
    }
}

impl Default for PedersenGens {
    fn default() -> Self {
        PedersenGens {
            b_base: RISTRETTO_BASEPOINT_POINT,
            b_base_blinding: RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes()),
        }
    }
}
