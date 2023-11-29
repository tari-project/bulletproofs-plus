// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! # RistrettoBulletProof
//!
//! Implementation of BulletProofs for the Ristretto group for Curve25519.

use alloc::vec::Vec;

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint, VartimeRistrettoPrecomputation},
};
use once_cell::sync::OnceCell;

use crate::{
    generators::pedersen_gens::ExtensionDegree,
    protocols::curve_point_protocol::CurvePointProtocol,
    range_proof::RangeProof,
    traits::{Compressable, Decompressable, FixedBytesRepr, FromUniformBytes, Precomputable},
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

impl Precomputable for RistrettoPoint {
    type Precomputation = VartimeRistrettoPrecomputation;
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

// Get masking points and compressed points based on extension degree
fn get_g_base(extension_degree: ExtensionDegree) -> (Vec<RistrettoPoint>, Vec<CompressedRistretto>) {
    (
        ristretto_masking_basepoints()[..extension_degree as usize].to_vec(),
        ristretto_compressed_masking_basepoints()[..extension_degree as usize].to_vec(),
    )
}

/// A static array of pre-generated points
fn ristretto_masking_basepoints() -> &'static [RistrettoPoint; ExtensionDegree::COUNT] {
    static INSTANCE: OnceCell<[RistrettoPoint; ExtensionDegree::COUNT]> = OnceCell::new();
    INSTANCE.get_or_init(|| {
        let mut arr = [RistrettoPoint::default(); ExtensionDegree::COUNT];
        for (i, point) in (ExtensionDegree::MINIMUM..).zip(arr.iter_mut()) {
            let label = "RISTRETTO_MASKING_BASEPOINT_".to_owned() + &i.to_string();
            *point = RistrettoPoint::hash_from_bytes_sha3_512(label.as_bytes());
        }

        arr
    })
}

/// A static array of compressed pre-generated points
fn ristretto_compressed_masking_basepoints() -> &'static [CompressedRistretto; ExtensionDegree::COUNT] {
    static INSTANCE: OnceCell<[CompressedRistretto; ExtensionDegree::COUNT]> = OnceCell::new();
    INSTANCE.get_or_init(|| {
        let mut arr = [CompressedRistretto::default(); ExtensionDegree::COUNT];
        for (i, point) in ristretto_masking_basepoints().iter().enumerate() {
            arr[i] = point.compress();
        }

        arr
    })
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand::thread_rng;

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
        let masking_basepoints = ristretto_masking_basepoints();
        for extension_degree in EXTENSION_DEGREE {
            let pc_gens = create_pedersen_gens_with_extension_degree(extension_degree);
            for (i, item) in masking_basepoints
                .iter()
                .enumerate()
                .take(pc_gens.extension_degree as usize)
            {
                assert_eq!(pc_gens.g_base_vec[i].compress(), pc_gens.g_base_compressed_vec[i]);
                assert_eq!(item.compress(), pc_gens.g_base_compressed_vec[i]);
            }
            assert_eq!(pc_gens.g_base_vec.len(), extension_degree as usize);
            assert_eq!(pc_gens.g_base_compressed_vec.len(), extension_degree as usize);
        }
    }

    #[test]
    fn test_commitments() {
        let mut rng = thread_rng();
        let value = Scalar::random_not_zero(&mut rng);
        let blindings = [
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
