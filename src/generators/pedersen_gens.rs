// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

use std::{borrow::Borrow, convert::TryFrom, iter::once};

use curve25519_dalek::{scalar::Scalar, traits::MultiscalarMul};
use zeroize::Zeroize;

use crate::{errors::ProofError, traits::Compressable};

/// Represents a pair of base points for Pedersen commitments
///
/// The Bulletproofs implementation and API is designed to support pluggable bases for Pedersen commitments, so that
/// the choice of bases is not hard-coded.
///
/// The default generators are:
///
/// * `h_base`: the curve basepoint;
/// * `g_base_vec`: the result of domain separated SHA3-512 (hash of unique indexed strings)
/// hash-to-group on input `B_bytes`.
#[derive(Clone, Debug, PartialEq)]
pub struct PedersenGens<P: Compressable> {
    /// Base for the committed value
    pub h_base: P,
    /// Compressed base for the committed value
    pub h_base_compressed: P::Compressed,
    /// Base for the blinding factor vector
    pub g_base_vec: Vec<P>,
    /// Compressed base for the blinding factor vector
    pub g_base_compressed_vec: Vec<P::Compressed>,
    /// Blinding factor extension degree
    pub extension_degree: ExtensionDegree,
}

/// The extension degree for extended commitments. Currently this is arbitrarily limited to 5 extension degrees.
/// The discriminants MUST increment, or other functions may panic.
#[derive(Copy, Clone, Debug, PartialEq, Zeroize)]
#[repr(u8)]
pub enum ExtensionDegree {
    /// Default Pedersen commitment
    DefaultPedersen = 1,
    /// Pedersen commitment extended with one degree
    AddOneBasePoint,
    /// Pedersen commitment extended with two degrees
    AddTwoBasePoints,
    /// Pedersen commitment extended with three degrees
    AddThreeBasePoints,
    /// Pedersen commitment extended with four degrees
    AddFourBasePoints,
    /// Pedersen commitment extended with five degrees
    AddFiveBasePoints,
}

impl ExtensionDegree {
    /// The total number of valid extension degrees
    pub(crate) const COUNT: usize = ExtensionDegree::MAXIMUM - ExtensionDegree::MINIMUM + 1;
    /// The highest numerical value corresponding to a valid extension degree
    /// This MUST be correct, or other functions may panic
    pub(crate) const MAXIMUM: usize = ExtensionDegree::AddFiveBasePoints as usize;
    /// The lowest numerical value corresponding to a valid extension degree
    /// This MUST be correct, or other functions may panic
    pub(crate) const MINIMUM: usize = ExtensionDegree::DefaultPedersen as usize;
}

impl TryFrom<u8> for ExtensionDegree {
    type Error = ProofError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ExtensionDegree::DefaultPedersen),
            2 => Ok(ExtensionDegree::AddOneBasePoint),
            3 => Ok(ExtensionDegree::AddTwoBasePoints),
            4 => Ok(ExtensionDegree::AddThreeBasePoints),
            5 => Ok(ExtensionDegree::AddFourBasePoints),
            6 => Ok(ExtensionDegree::AddFiveBasePoints),
            _ => Err(ProofError::InvalidArgument("Extension degree not valid".to_string())),
        }
    }
}

impl TryFrom<usize> for ExtensionDegree {
    type Error = ProofError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        ExtensionDegree::try_from(
            u8::try_from(value).map_err(|_| ProofError::InvalidArgument("Extension degree not valid".to_string()))?,
        )
    }
}

impl<P> PedersenGens<P>
where P: Compressable
{
    /// Returns the non-public value base point
    pub fn h_base(&self) -> &P {
        &self.h_base
    }

    /// Returns the non-public value compressed base point
    pub fn h_base_compressed(&self) -> P::Compressed {
        self.h_base_compressed
    }
}

impl<P> PedersenGens<P>
where P: Compressable + MultiscalarMul<Point = P> + Clone
{
    /// Creates a Pedersen commitment using the value scalar and a blinding factor vector
    pub fn commit<T>(&self, value: &T, blindings: &[T]) -> Result<P, ProofError>
    where for<'a> &'a T: Borrow<Scalar> {
        if blindings.is_empty() || blindings.len() > self.extension_degree as usize {
            Err(ProofError::InvalidLength("blinding vector".to_string()))
        } else {
            let scalars = once(value).chain(blindings);
            let g_base_head = self.g_base_vec.iter().take(blindings.len());
            let points = once(&self.h_base).chain(g_base_head);
            Ok(P::multiscalar_mul(scalars, points))
        }
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use super::ExtensionDegree;

    #[test]
    // Test the size range, assuming extension degree values are incremented
    fn test_extension_degree_size() {
        // Value is too low
        assert!(ExtensionDegree::try_from(ExtensionDegree::MINIMUM - 1).is_err());

        // Valid values
        for i in ExtensionDegree::MINIMUM..=ExtensionDegree::MAXIMUM {
            assert!(ExtensionDegree::try_from(i).is_ok());
        }

        // Value is too high
        assert!(ExtensionDegree::try_from(ExtensionDegree::MAXIMUM + 1).is_err());
    }
}
