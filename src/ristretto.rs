// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! # RistrettoBulletProof
//!
//! Implementation of BulletProofs for the Ristretto group for Curve25519.

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
};

use crate::{
    generators::pedersen_gens::ExtensionDegree,
    protocols::curve_point_protocol::CurvePointProtocol,
    range_proof::RangeProof,
    traits::{Compressable, Decompressable, FixedBytesRepr, FromUniformBytes},
    PedersenGens,
};

/// A Bullet proof implentation using the Ristretto group.
pub type RistrettoRangeProof = RangeProof<RistrettoPoint>;

impl CurvePointProtocol for RistrettoPoint {}

impl FixedBytesRepr for CompressedRistretto {
    fn as_fixed_bytes(&self) -> &[u8; 32] {
        CompressedRistretto::as_bytes(self)
    }

    fn from_fixed_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Decompressable for CompressedRistretto {
    type Decompressed = RistrettoPoint;

    fn decompress(&self) -> Option<Self::Decompressed> {
        CompressedRistretto::decompress(self)
    }
}

impl FromUniformBytes for RistrettoPoint {
    fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        RistrettoPoint::from_uniform_bytes(bytes)
    }
}

impl Compressable for RistrettoPoint {
    type Compressed = CompressedRistretto;

    fn compress(&self) -> Self::Compressed {
        RistrettoPoint::compress(self)
    }
}

/// Create extended Pedersen generators for the required extension degree using pre-calculated compressed constants
pub fn create_pedersen_gens_with_extension_degree(extension_degree: ExtensionDegree) -> PedersenGens<RistrettoPoint> {
    let (g_base_vec, g_base_compressed_vec) = get_g_base(extension_degree);
    PedersenGens {
        h_base: RISTRETTO_BASEPOINT_POINT,
        h_base_compressed: RISTRETTO_BASEPOINT_COMPRESSED,
        g_base_vec: g_base_vec[..].to_owned(),
        g_base_compressed_vec: g_base_compressed_vec[..].to_owned(),
        extension_degree,
    }
}

// Assign vectors only performing the number of lazy static base point calculations that is necessary, using
// on the fly compression for compressed base points otherwise
fn get_g_base(extension_degree: ExtensionDegree) -> (Vec<RistrettoPoint>, Vec<CompressedRistretto>) {
    match extension_degree {
        ExtensionDegree::DefaultPedersen => (vec![*RISTRETTO_BASEPOINT_POINT_BLINDING_1], vec![
            *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1,
        ]),
        ExtensionDegree::AddOneBasePoint => (
            vec![
                *RISTRETTO_BASEPOINT_POINT_BLINDING_1,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_2,
            ],
            vec![
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2,
            ],
        ),
        ExtensionDegree::AddTwoBasePoints => (
            vec![
                *RISTRETTO_BASEPOINT_POINT_BLINDING_1,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_2,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_3,
            ],
            vec![
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_3,
            ],
        ),
        ExtensionDegree::AddThreeBasePoints => (
            vec![
                *RISTRETTO_BASEPOINT_POINT_BLINDING_1,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_2,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_3,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_4,
            ],
            vec![
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_3,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_4,
            ],
        ),
        ExtensionDegree::AddFourBasePoints => (
            vec![
                *RISTRETTO_BASEPOINT_POINT_BLINDING_1,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_2,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_3,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_4,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_5,
            ],
            vec![
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_3,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_4,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_5,
            ],
        ),
        ExtensionDegree::AddFiveBasePoints => (
            vec![
                *RISTRETTO_BASEPOINT_POINT_BLINDING_1,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_2,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_3,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_4,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_5,
                *RISTRETTO_BASEPOINT_POINT_BLINDING_6,
            ],
            vec![
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_3,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_4,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_5,
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_6,
            ],
        ),
    }
}

lazy_static! {
    static ref RISTRETTO_BASEPOINT_POINT_BLINDING_1: RistrettoPoint =
        RistrettoPoint::hash_from_bytes_sha3_512(b"RISTRETTO_BASEPOINT_POINT_BLINDING_1 degree ZERO");
    static ref RISTRETTO_BASEPOINT_POINT_BLINDING_2: RistrettoPoint =
        RistrettoPoint::hash_from_bytes_sha3_512(b"RISTRETTO_BASEPOINT_POINT_BLINDING_2 degree ONE");
    static ref RISTRETTO_BASEPOINT_POINT_BLINDING_3: RistrettoPoint =
        RistrettoPoint::hash_from_bytes_sha3_512(b"RISTRETTO_BASEPOINT_POINT_BLINDING_3 degree TWO");
    static ref RISTRETTO_BASEPOINT_POINT_BLINDING_4: RistrettoPoint =
        RistrettoPoint::hash_from_bytes_sha3_512(b"RISTRETTO_BASEPOINT_POINT_BLINDING_4 degree THREE");
    static ref RISTRETTO_BASEPOINT_POINT_BLINDING_5: RistrettoPoint =
        RistrettoPoint::hash_from_bytes_sha3_512(b"RISTRETTO_BASEPOINT_POINT_BLINDING_5 degree FOUR");
    static ref RISTRETTO_BASEPOINT_POINT_BLINDING_6: RistrettoPoint =
        RistrettoPoint::hash_from_bytes_sha3_512(b"RISTRETTO_BASEPOINT_POINT_BLINDING_6 degree FIVE");
    static ref RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1: CompressedRistretto =
        (*RISTRETTO_BASEPOINT_POINT_BLINDING_1).compress();
    static ref RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2: CompressedRistretto =
        (*RISTRETTO_BASEPOINT_POINT_BLINDING_2).compress();
    static ref RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_3: CompressedRistretto =
        (*RISTRETTO_BASEPOINT_POINT_BLINDING_3).compress();
    static ref RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_4: CompressedRistretto =
        (*RISTRETTO_BASEPOINT_POINT_BLINDING_4).compress();
    static ref RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_5: CompressedRistretto =
        (*RISTRETTO_BASEPOINT_POINT_BLINDING_5).compress();
    static ref RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_6: CompressedRistretto =
        (*RISTRETTO_BASEPOINT_POINT_BLINDING_6).compress();
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;

    use super::*;
    use crate::protocols::scalar_protocol::ScalarProtocol;

    static EXTENSION_DEGREE: [ExtensionDegree; 6] = [
        ExtensionDegree::DefaultPedersen,
        ExtensionDegree::AddOneBasePoint,
        ExtensionDegree::AddTwoBasePoints,
        ExtensionDegree::AddThreeBasePoints,
        ExtensionDegree::AddFourBasePoints,
        ExtensionDegree::AddFiveBasePoints,
    ];

    #[test]
    fn test_constants() {
        // Extended Pedersen generators with extension degree of zero to five
        let lazy_statics = [
            *RISTRETTO_BASEPOINT_POINT_BLINDING_1,
            *RISTRETTO_BASEPOINT_POINT_BLINDING_2,
            *RISTRETTO_BASEPOINT_POINT_BLINDING_3,
            *RISTRETTO_BASEPOINT_POINT_BLINDING_4,
            *RISTRETTO_BASEPOINT_POINT_BLINDING_5,
            *RISTRETTO_BASEPOINT_POINT_BLINDING_6,
        ];
        for extension_degree in EXTENSION_DEGREE {
            let pc_gens = create_pedersen_gens_with_extension_degree(extension_degree);
            for (i, item) in lazy_statics.iter().enumerate().take(pc_gens.extension_degree as usize) {
                assert_eq!(pc_gens.g_base_vec[i].compress(), pc_gens.g_base_compressed_vec[i]);
                assert_eq!(item.compress(), pc_gens.g_base_compressed_vec[i]);
            }
            assert_eq!(pc_gens.g_base_vec.len(), extension_degree as usize);
            assert_eq!(pc_gens.g_base_compressed_vec.len(), extension_degree as usize);
        }
    }

    #[test]
    fn test_commitments() {
        let mut rng = rand::thread_rng();
        let value = Scalar::random_not_zero(&mut rng);
        let blindings = vec![
            Scalar::random_not_zero(&mut rng),
            Scalar::random_not_zero(&mut rng),
            Scalar::random_not_zero(&mut rng),
            Scalar::random_not_zero(&mut rng),
            Scalar::random_not_zero(&mut rng),
            Scalar::random_not_zero(&mut rng),
        ];

        for extension_degree in EXTENSION_DEGREE {
            let pc_gens = create_pedersen_gens_with_extension_degree(extension_degree);
            for i in 0..ExtensionDegree::AddFiveBasePoints as usize {
                // All commitments where enough extended generators are available to enable multi-exponentiation
                // multiplication of the blinding factor vector will be ok
                if i > 0 && i <= extension_degree as usize {
                    assert!(pc_gens.commit(&value, &blindings[..i]).is_ok());
                } else {
                    assert!(pc_gens.commit(&value, &blindings[..i]).is_err());
                }
            }
        }
    }
}
