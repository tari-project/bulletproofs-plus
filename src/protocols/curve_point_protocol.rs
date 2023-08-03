// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ `CurvePointProtocol` trait provides the required interface for curves using BP+.

use std::{
    borrow::Borrow,
    cmp::min,
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
        Self::from_hash_sha3_512(hasher)
    }

    /// Generates an instance from the byte result of the SHA3_512 hasher.
    fn from_hash_sha3_512(hasher: Sha3_512) -> Self {
        let output = hasher.finalize();
        // If we use 'curve25519-dalek = { package = "curve25519-dalek", version = "4.0.0-pre.2"', change to
        // 'Self::from_uniform_bytes(&output.into())'
        // instead of below
        let mut buffer = [0u8; 64];
        let size = min(output.len(), 64);
        (buffer[0..size]).copy_from_slice(&output.as_slice()[0..size]);
        Self::from_uniform_bytes(&buffer)
    }
}
