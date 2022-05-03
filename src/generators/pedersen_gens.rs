// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};

use crate::protocols::ristretto_point_protocol::RistrettoPointProtocol;

/// Represents a pair of base points for Pedersen commitments
///
/// The Bulletproofs implementation and API is designed to support pluggable bases for Pedersen commitments, so that
/// the choice of bases is not hard-coded.
///
/// The default generators are:
///
/// * `h_base`: the `ristretto255` basepoint;
/// * `g_base`: the result of `ristretto255` SHA3-512
/// hash-to-group on input `B_bytes`.
#[derive(Copy, Clone, Debug)]
pub struct PedersenGens {
    /// Base for the committed value
    pub h_base: RistrettoPoint,
    /// Base for the blinding factor
    pub g_base: RistrettoPoint,
    /// Compressed base for the committed value
    pub h_base_compressed: CompressedRistretto,
    /// Compressed base for the blinding factor
    pub g_base_compressed: CompressedRistretto,
}

lazy_static! {
    static ref RISTRETTO_BASEPOINT_POINT_BLINDING: RistrettoPoint =
        RistrettoPoint::hash_from_bytes_sha3_512(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
}

impl PedersenGens {
    // Pre-calculated '(*RISTRETTO_BASEPOINT_POINT_BLINDING).compress()'
    const RISTRETTO_BASEPOINT_COMPRESSED_BLINDING: CompressedRistretto = CompressedRistretto([
        140, 146, 64, 180, 86, 169, 230, 220, 101, 195, 119, 161, 4, 141, 116, 95, 148, 160, 140, 219, 127, 68, 203,
        205, 123, 70, 243, 64, 72, 135, 17, 52,
    ]);

    /// Creates a Pedersen commitment using the value scalar and a blinding factor.
    pub fn commit(&self, value: Scalar, blinding: Scalar) -> RistrettoPoint {
        RistrettoPoint::multiscalar_mul(&[value, blinding], &[self.h_base, self.g_base])
    }
}

impl Default for PedersenGens {
    fn default() -> Self {
        PedersenGens {
            h_base: RISTRETTO_BASEPOINT_POINT,
            g_base: *RISTRETTO_BASEPOINT_POINT_BLINDING,
            h_base_compressed: RISTRETTO_BASEPOINT_COMPRESSED,
            g_base_compressed: PedersenGens::RISTRETTO_BASEPOINT_COMPRESSED_BLINDING,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{generators::pedersen_gens::RISTRETTO_BASEPOINT_POINT_BLINDING, PedersenGens};

    #[test]
    fn test_const() {
        let pc_gens = PedersenGens::default();
        assert_eq!(pc_gens.g_base.compress(), pc_gens.g_base_compressed);
        assert_eq!(
            (*RISTRETTO_BASEPOINT_POINT_BLINDING).compress(),
            pc_gens.g_base_compressed
        );
    }
}
