// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ `CurvePointProtocol` trait provides the required interface for curves using BP+.

use core::{
    borrow::Borrow,
    ops::{Add, AddAssign},
};

use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use digest::Digest;
use sha3::Sha3_512;

use crate::traits::{Compressable, FromUniformBytes};

/// The `CurvePointProtocol` trait. Any implementation of this trait can be used with BP+.
pub trait CurvePointProtocol:
    Sized
    + Identity
    + VartimeMultiscalarMul<Point = Self>
    + FromUniformBytes
    + Borrow<Self::Point>
    + Add<Output = Self>
    + AddAssign
    + PartialEq
    + Compressable
    + Clone
{
    /// Generates an instance from the hash bytes of the input.
    fn hash_from_bytes_sha3_512(input: &[u8]) -> Self {
        let mut hasher = Sha3_512::default();
        hasher.update(input);
        Self::from_uniform_bytes(&hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};

    use super::*;

    #[test]
    fn hash_from_bytes_sha3_512_is_deterministic_and_collision_resistant_on_labels() {
        let p1 = RistrettoPoint::hash_from_bytes_sha3_512(b"RISTRETTO_MASKING_BASEPOINT_1");
        let p1_again = RistrettoPoint::hash_from_bytes_sha3_512(b"RISTRETTO_MASKING_BASEPOINT_1");
        let p2 = RistrettoPoint::hash_from_bytes_sha3_512(b"RISTRETTO_MASKING_BASEPOINT_2");
        let empty = RistrettoPoint::hash_from_bytes_sha3_512(b"");

        assert_eq!(p1, p1_again);
        assert_ne!(p1, p2);
        assert_ne!(p1, empty);
        assert_ne!(p1, RistrettoPoint::identity());
    }
}
