// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ `RistrettoPointProtocol` trait for using a RistrettoPoint

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use digest::Digest;
use sha3::Sha3_512;

use crate::errors::ProofError;

/// Defines a `RistrettoPointProtocol` trait for using a RistrettoPoint
pub trait RistrettoPointProtocol {
    /// Helper function to implement 'RistrettoPoint::hash_from_bytes::<Sha3_512>'
    fn hash_from_bytes_sha3_512(input: &[u8]) -> RistrettoPoint;

    /// Helper function to implement 'RistrettoPoint::from_hash::<Sha3_512>'
    fn from_hash_sha3_512(hasher: Sha3_512) -> RistrettoPoint;

    /// Helper function to multiply a point vector with a scalar vector
    fn mul_point_vec_with_scalar(
        point_vec: &[RistrettoPoint],
        scalar: &Scalar,
    ) -> Result<Vec<RistrettoPoint>, ProofError>;

    /// Helper function to add two point vectors
    fn add_point_vectors(a: &[RistrettoPoint], b: &[RistrettoPoint]) -> Result<Vec<RistrettoPoint>, ProofError>;
}

impl RistrettoPointProtocol for RistrettoPoint {
    fn hash_from_bytes_sha3_512(input: &[u8]) -> RistrettoPoint {
        let mut hasher = Sha3_512::default();
        hasher.update(input);
        Self::from_hash_sha3_512(hasher)
    }

    fn from_hash_sha3_512(hasher: Sha3_512) -> RistrettoPoint {
        let output = hasher.finalize();
        let mut output_bytes = [0u8; 64];
        output_bytes.copy_from_slice(output.as_slice());

        RistrettoPoint::from_uniform_bytes(&output_bytes)
    }

    fn mul_point_vec_with_scalar(
        point_vec: &[RistrettoPoint],
        scalar: &Scalar,
    ) -> Result<Vec<RistrettoPoint>, ProofError> {
        if point_vec.is_empty() {
            return Err(ProofError::InvalidLength(
                "Cannot multiply empty point vector with scalar".to_string(),
            ));
        }
        let mut out = vec![RistrettoPoint::default(); point_vec.len()];
        for i in 0..point_vec.len() {
            out[i] = point_vec[i] * scalar;
        }
        Ok(out)
    }

    fn add_point_vectors(a: &[RistrettoPoint], b: &[RistrettoPoint]) -> Result<Vec<RistrettoPoint>, ProofError> {
        if a.len() != b.len() || a.is_empty() {
            return Err(ProofError::InvalidLength("Cannot add empty point vectors".to_string()));
        }
        let mut out = vec![RistrettoPoint::default(); a.len()];
        for i in 0..a.len() {
            out[i] = a[i] + b[i];
        }
        Ok(out)
    }
}
