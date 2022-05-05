// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ `ScalarProtocol` trait for using a Scalar

use blake2::Blake2b;
use curve25519_dalek::scalar::Scalar;
use digest::Digest;
use rand::{CryptoRng, RngCore};

use crate::errors::ProofError;

/// Defines a `ScalarProtocol` trait for using a Scalar
pub trait ScalarProtocol {
    /// Returns a non-zero random Scalar
    fn random_not_zero<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar;

    /// Construct a scalar from an existing Blake2b instance (helper function to implement 'Scalar::from_hash<Blake2b>')
    fn from_hasher_blake2b(hasher: Blake2b) -> Scalar;

    /// Helper function to multiply one scalar vector with another scalar vector
    fn mul_scalar_vec_with_scalar(scalar_vec: &[Scalar], scalar: &Scalar) -> Result<Vec<Scalar>, ProofError>;

    /// Helper function to add two scalar vectors
    fn add_scalar_vectors(a: &[Scalar], b: &[Scalar]) -> Result<Vec<Scalar>, ProofError>;
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

    fn mul_scalar_vec_with_scalar(scalar_vec: &[Scalar], scalar: &Scalar) -> Result<Vec<Scalar>, ProofError> {
        if scalar_vec.is_empty() {
            return Err(ProofError::InvalidLength(
                "Cannot multiply empty scalar vector with scalar".to_string(),
            ));
        }
        let mut out = vec![Scalar::default(); scalar_vec.len()];
        for i in 0..scalar_vec.len() {
            out[i] = scalar_vec[i] * scalar;
        }
        Ok(out)
    }

    fn add_scalar_vectors(a: &[Scalar], b: &[Scalar]) -> Result<Vec<Scalar>, ProofError> {
        if a.len() != b.len() || a.is_empty() {
            return Err(ProofError::InvalidLength("Cannot add empty scalar vectors".to_string()));
        }
        let mut out = vec![Scalar::default(); a.len()];
        for i in 0..a.len() {
            out[i] = a[i] + b[i];
        }
        Ok(out)
    }
}
