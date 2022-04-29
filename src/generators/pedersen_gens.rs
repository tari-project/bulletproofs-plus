// Copyright (c) 2018 Chain, Inc.
// SPDX-License-Identifier: MIT

// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};
use digest::Digest;
use sha3::Sha3_512;

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
        hash_from_bytes_sha3_512(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    static ref RISTRETTO_BASEPOINT_COMPRESSED_BLINDING: CompressedRistretto =
        (*RISTRETTO_BASEPOINT_POINT_BLINDING).compress();
}
impl PedersenGens {
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
            g_base_compressed: *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING,
        }
    }
}

// Helper function to implement 'RistrettoPoint::hash_from_bytes::<Sha3_512>'
fn hash_from_bytes_sha3_512(input: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha3_512::default();
    hasher.update(input);
    from_hash_sha3_512(hasher)
}

// Helper function to implement 'RistrettoPoint::from_hash::<Sha3_512>'
fn from_hash_sha3_512(hasher: Sha3_512) -> RistrettoPoint {
    let output = hasher.finalize();
    let mut output_bytes = [0u8; 64];
    output_bytes.copy_from_slice(output.as_slice());

    RistrettoPoint::from_uniform_bytes(&output_bytes)
}
