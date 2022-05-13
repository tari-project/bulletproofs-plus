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
/// * `g_base_vec`: the result of domain separated `ristretto255` SHA3-512 (hash of unique indexed strings)
/// hash-to-group on input `B_bytes`.
#[derive(Clone, Debug, PartialEq)]
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

/// The extension degree for extended commitments. Currently this is limited to 5 extension degrees, but in theory it
/// could be arbitrarily long, although practically, very few if any test cases will use more than 2 extension degrees.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ExtensionDegree {
    /// Default Pedersen commitment
    ZERO = 1,
    /// Pedersen commitment extended with one degree
    ONE = 2,
    /// Pedersen commitment extended with two degrees
    TWO = 3,
    /// Pedersen commitment extended with three degrees
    THREE = 4,
    /// Pedersen commitment extended with four degrees
    FOUR = 5,
    /// Pedersen commitment extended with five degrees
    FIVE = 6,
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

impl PedersenGens {
    /// Creates a Pedersen commitment using the value scalar and a blinding factor vector
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

    /// Create extended Pedersen generators for the required extension degree using pre-calculated compressed constants
    pub fn with_extension_degree(extension_degree: ExtensionDegree) -> Self {
        let (g_base_vec, g_base_compressed_vec) = PedersenGens::g_base(extension_degree);
        let index = extension_degree as usize;
        match extension_degree {
            ExtensionDegree::ZERO => PedersenGens::default(),
            _ => PedersenGens {
                g_base_vec: g_base_vec[..index].to_owned(),
                g_base_compressed_vec: g_base_compressed_vec[..index].to_owned(),
                extension_degree,
                ..Default::default()
            },
        }
    }

    // Assign vectors only performing the number of lazy static base point calculations that is necessary, using
    // on the fly compression for compressed base points otherwise
    fn g_base(extension_degree: ExtensionDegree) -> (Vec<RistrettoPoint>, Vec<CompressedRistretto>) {
        match extension_degree {
            ExtensionDegree::ZERO => (vec![*RISTRETTO_BASEPOINT_POINT_BLINDING_1], vec![
                *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1,
            ]),
            ExtensionDegree::ONE => (
                vec![
                    *RISTRETTO_BASEPOINT_POINT_BLINDING_1,
                    *RISTRETTO_BASEPOINT_POINT_BLINDING_2,
                ],
                vec![
                    *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_1,
                    *RISTRETTO_BASEPOINT_COMPRESSED_BLINDING_2,
                ],
            ),
            ExtensionDegree::TWO => (
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
            ExtensionDegree::THREE => (
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
            ExtensionDegree::FOUR => (
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
            ExtensionDegree::FIVE => (
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

    /// Helper function to convert a size into an extension degree
    pub fn extension_degree(size: usize) -> Result<ExtensionDegree, ProofError> {
        match size {
            1 => Ok(ExtensionDegree::ZERO),
            2 => Ok(ExtensionDegree::ONE),
            3 => Ok(ExtensionDegree::TWO),
            4 => Ok(ExtensionDegree::THREE),
            5 => Ok(ExtensionDegree::FOUR),
            6 => Ok(ExtensionDegree::FIVE),
            _ => Err(ProofError::InvalidArgument("Extension degree not valid".to_string())),
        }
    }
}

impl Default for PedersenGens {
    fn default() -> Self {
        let (g_base_vec, g_base_compressed_vec) = PedersenGens::g_base(ExtensionDegree::ZERO);
        PedersenGens {
            h_base: RISTRETTO_BASEPOINT_POINT,
            g_base_vec,
            h_base_compressed: RISTRETTO_BASEPOINT_COMPRESSED,
            g_base_compressed_vec,
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
            RISTRETTO_BASEPOINT_POINT_BLINDING_4,
            RISTRETTO_BASEPOINT_POINT_BLINDING_5,
            RISTRETTO_BASEPOINT_POINT_BLINDING_6,
        },
        protocols::scalar_protocol::ScalarProtocol,
        PedersenGens,
    };

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
        for extension_degree in [
            ExtensionDegree::ZERO,
            ExtensionDegree::ONE,
            ExtensionDegree::TWO,
            ExtensionDegree::THREE,
            ExtensionDegree::FOUR,
            ExtensionDegree::FIVE,
        ] {
            let pc_gens = PedersenGens::with_extension_degree(extension_degree);
            for (i, item) in lazy_statics.iter().enumerate().take(pc_gens.extension_degree as usize) {
                assert_eq!(pc_gens.g_base_vec[i].compress(), pc_gens.g_base_compressed_vec[i]);
                assert_eq!(item.compress(), pc_gens.g_base_compressed_vec[i]);
            }
            assert_eq!(pc_gens.g_base_vec.len(), extension_degree as usize);
            assert_eq!(pc_gens.g_base_compressed_vec.len(), extension_degree as usize);
        }
    }

    #[test]
    fn test_default() {
        assert_eq!(
            PedersenGens::with_extension_degree(ExtensionDegree::ZERO),
            PedersenGens::default()
        );
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

        for extension_degree in [
            ExtensionDegree::ZERO,
            ExtensionDegree::ONE,
            ExtensionDegree::TWO,
            ExtensionDegree::THREE,
            ExtensionDegree::FOUR,
            ExtensionDegree::FIVE,
        ] {
            let pc_gens = PedersenGens::with_extension_degree(extension_degree);
            for i in 0..ExtensionDegree::FIVE as usize {
                if i == extension_degree as usize {
                    assert!(pc_gens.commit(value, blindings[..i].to_owned().as_slice()).is_ok());
                } else {
                    assert!(pc_gens.commit(value, blindings[..i].to_owned().as_slice()).is_err());
                }
            }
        }
    }
}
