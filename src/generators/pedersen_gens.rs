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

use crate::{errors::ProofError, protocols::ristretto_point_protocol::RistrettoPointProtocol};

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
#[derive(Clone, Debug)]
pub struct PedersenGens {
    /// Base for the committed value
    pub h_base: RistrettoPoint,
    /// Base for the blinding factor vector
    pub g_base_vec: Vec<RistrettoPoint>,
    /// Compressed base for the committed value
    pub h_base_compressed: CompressedRistretto,
    /// Compressed base for the blinding factor vector
    pub g_base_compressed_vec: Vec<CompressedRistretto>,
    /// Blinding factor extension degree
    pub extension_degree: ExtensionDegree,
}

/// The extension degree for extended commitments
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ExtensionDegree {
    /// Default Pedersen commitment
    ZERO = 1,
    /// Pedersen commitment extended with one degree
    ONE = 2,
    /// Pedersen commitment extended with two degrees
    TWO = 3,
}

lazy_static! {
    static ref RISTRETTO_BASEPOINT_POINT_BLINDING_1: RistrettoPoint =
        RistrettoPoint::hash_from_bytes_sha3_512(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    static ref RISTRETTO_BASEPOINT_POINT_BLINDING_2: RistrettoPoint = RistrettoPoint::hash_from_bytes_sha3_512(
        RistrettoPoint::hash_from_bytes_sha3_512(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes())
            .compress()
            .as_bytes()
    );
    static ref RISTRETTO_BASEPOINT_POINT_BLINDING_3: RistrettoPoint = RistrettoPoint::hash_from_bytes_sha3_512(
        RistrettoPoint::hash_from_bytes_sha3_512(
            RistrettoPoint::hash_from_bytes_sha3_512(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes())
                .compress()
                .as_bytes()
        )
        .compress()
        .as_bytes()
    );
    static ref RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2: CompressedRistretto =
        (*RISTRETTO_BASEPOINT_POINT_BLINDING_2).compress();
    static ref RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_3: CompressedRistretto =
        (*RISTRETTO_BASEPOINT_POINT_BLINDING_3).compress();
}

impl PedersenGens {
    // Pre-calculated compressed base points
    const RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1: CompressedRistretto = CompressedRistretto([
        140, 146, 64, 180, 86, 169, 230, 220, 101, 195, 119, 161, 4, 141, 116, 95, 148, 160, 140, 219, 127, 68, 203,
        205, 123, 70, 243, 64, 72, 135, 17, 52,
    ]);
    const RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2: CompressedRistretto = CompressedRistretto([
        22, 71, 181, 26, 192, 136, 81, 194, 135, 98, 165, 113, 214, 100, 253, 85, 86, 117, 211, 33, 9, 68, 70, 67, 168,
        225, 172, 171, 166, 53, 36, 21,
    ]);
    const RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_3: CompressedRistretto = CompressedRistretto([
        52, 193, 44, 14, 233, 178, 175, 56, 80, 198, 174, 186, 11, 191, 138, 91, 163, 168, 10, 85, 147, 242, 17, 126,
        236, 165, 8, 171, 159, 203, 127, 107,
    ]);

    /// Creates a Pedersen commitment using the value scalar and a blinding factor.
    pub fn commit(&self, value: Scalar, blindings: &[Scalar]) -> Result<RistrettoPoint, ProofError> {
        let extension_degree = self.extension_degree as usize;
        if blindings.is_empty() || blindings.len() != extension_degree {
            Err(ProofError::InvalidLength("blinding vector".to_string()))
        } else {
            let mut scalars = Vec::with_capacity(1 + extension_degree);
            scalars.push(value);
            for item in blindings {
                scalars.push(*item);
            }
            let mut points = Vec::with_capacity(1 + extension_degree);
            points.push(self.h_base);
            for item in self.g_base_vec.iter().take(extension_degree) {
                points.push(*item);
            }
            Ok(RistrettoPoint::multiscalar_mul(&scalars, &points))
        }
    }

    /// Create extended Pedersen generators for the required extension degree
    pub fn with_extension_degree(extension_degree: ExtensionDegree) -> Self {
        match extension_degree {
            ExtensionDegree::ZERO => PedersenGens::default(),
            ExtensionDegree::ONE => PedersenGens {
                g_base_vec: vec![
                    *RISTRETTO_BASEPOINT_POINT_BLINDING_1,
                    *RISTRETTO_BASEPOINT_POINT_BLINDING_2,
                ],
                g_base_compressed_vec: vec![
                    PedersenGens::RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1,
                    PedersenGens::RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2,
                ],
                extension_degree,
                ..Default::default()
            },
            ExtensionDegree::TWO => PedersenGens {
                g_base_vec: vec![
                    *RISTRETTO_BASEPOINT_POINT_BLINDING_1,
                    *RISTRETTO_BASEPOINT_POINT_BLINDING_2,
                    *RISTRETTO_BASEPOINT_POINT_BLINDING_3,
                ],
                g_base_compressed_vec: vec![
                    PedersenGens::RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1,
                    PedersenGens::RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2,
                    PedersenGens::RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_3,
                ],
                extension_degree,
                ..Default::default()
            },
        }
    }

    /// Helper function to convert a size into an extension degree
    pub fn extension_degree(size: usize) -> Result<ExtensionDegree, ProofError> {
        match size {
            1 => Ok(ExtensionDegree::ZERO),
            2 => Ok(ExtensionDegree::ONE),
            3 => Ok(ExtensionDegree::TWO),
            _ => Err(ProofError::InvalidArgument("Extension degree not valid".to_string())),
        }
    }
}

impl Default for PedersenGens {
    fn default() -> Self {
        PedersenGens {
            h_base: RISTRETTO_BASEPOINT_POINT,
            g_base_vec: vec![*RISTRETTO_BASEPOINT_POINT_BLINDING_1],
            h_base_compressed: RISTRETTO_BASEPOINT_COMPRESSED,
            g_base_compressed_vec: vec![PedersenGens::RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1],
            extension_degree: ExtensionDegree::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;

    use crate::{
        generators::pedersen_gens::{
            ExtensionDegree,
            RISTRETTO_BASEPOINT_POINT_BLINDING_1,
            RISTRETTO_BASEPOINT_POINT_BLINDING_2,
            RISTRETTO_BASEPOINT_POINT_BLINDING_3,
        },
        protocols::scalar_protocol::ScalarProtocol,
        PedersenGens,
    };

    #[test]
    fn test_const() {
        // Extended Pedersen generators with extension degree of zero
        let pc_gens = PedersenGens::with_extension_degree(ExtensionDegree::ZERO);
        for i in 0..pc_gens.extension_degree as usize {
            assert_eq!(pc_gens.g_base_vec[i].compress(), pc_gens.g_base_compressed_vec[i]);
        }
        assert_eq!(
            (*RISTRETTO_BASEPOINT_POINT_BLINDING_1).compress(),
            pc_gens.g_base_compressed_vec[0]
        );
        assert_eq!(pc_gens.g_base_vec.len(), ExtensionDegree::ZERO as usize);
        assert_eq!(pc_gens.g_base_compressed_vec.len(), ExtensionDegree::ZERO as usize);

        // Extended Pedersen generators with extension degree of one
        let pc_gens = PedersenGens::with_extension_degree(ExtensionDegree::ONE);
        for i in 0..pc_gens.extension_degree as usize {
            assert_eq!(pc_gens.g_base_vec[i].compress(), pc_gens.g_base_compressed_vec[i]);
        }
        assert_eq!(
            (*RISTRETTO_BASEPOINT_POINT_BLINDING_1).compress(),
            pc_gens.g_base_compressed_vec[0]
        );
        assert_eq!(
            (*RISTRETTO_BASEPOINT_POINT_BLINDING_2).compress(),
            pc_gens.g_base_compressed_vec[1]
        );
        assert_eq!(pc_gens.g_base_vec.len(), ExtensionDegree::ONE as usize);
        assert_eq!(pc_gens.g_base_compressed_vec.len(), ExtensionDegree::ONE as usize);

        // Extended Pedersen generators with extension degree of two
        let pc_gens = PedersenGens::with_extension_degree(ExtensionDegree::TWO);
        for i in 0..pc_gens.extension_degree as usize {
            assert_eq!(pc_gens.g_base_vec[i].compress(), pc_gens.g_base_compressed_vec[i]);
        }
        assert_eq!(
            (*RISTRETTO_BASEPOINT_POINT_BLINDING_1).compress(),
            pc_gens.g_base_compressed_vec[0]
        );
        assert_eq!(
            (*RISTRETTO_BASEPOINT_POINT_BLINDING_2).compress(),
            pc_gens.g_base_compressed_vec[1]
        );
        assert_eq!(
            (*RISTRETTO_BASEPOINT_POINT_BLINDING_3).compress(),
            pc_gens.g_base_compressed_vec[2]
        );
        assert_eq!(pc_gens.g_base_vec.len(), ExtensionDegree::TWO as usize);
        assert_eq!(pc_gens.g_base_compressed_vec.len(), ExtensionDegree::TWO as usize);
    }

    #[test]
    fn test_commitment() {
        let mut rng = rand::thread_rng();
        let value = Scalar::random_not_zero(&mut rng);
        let blinding_1 = Scalar::random_not_zero(&mut rng);
        let blinding_2 = Scalar::random_not_zero(&mut rng);
        let blinding_3 = Scalar::random_not_zero(&mut rng);

        let pc_gens = PedersenGens::with_extension_degree(ExtensionDegree::ZERO);
        assert!(pc_gens.commit(value, vec![blinding_1].as_slice()).is_ok());
        assert!(pc_gens.commit(value, vec![blinding_1, blinding_2].as_slice()).is_err());
        assert!(pc_gens
            .commit(value, vec![blinding_1, blinding_2, blinding_3].as_slice())
            .is_err());

        let pc_gens = PedersenGens::with_extension_degree(ExtensionDegree::ONE);
        assert!(pc_gens.commit(value, vec![blinding_1].as_slice()).is_err());
        assert!(pc_gens.commit(value, vec![blinding_1, blinding_2].as_slice()).is_ok());
        assert!(pc_gens
            .commit(value, vec![blinding_1, blinding_2, blinding_3].as_slice())
            .is_err());

        let pc_gens = PedersenGens::with_extension_degree(ExtensionDegree::TWO);
        assert!(pc_gens.commit(value, vec![blinding_1].as_slice()).is_err());
        assert!(pc_gens.commit(value, vec![blinding_1, blinding_2].as_slice()).is_err());
        assert!(pc_gens
            .commit(value, vec![blinding_1, blinding_2, blinding_3].as_slice())
            .is_ok());
    }
}
