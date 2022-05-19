// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

use std::marker::PhantomData;

use digest::{ExtendableOutputDirty, Update, XofReader};
use sha3::{Sha3XofReader, Shake256};

use crate::traits::FromUniformBytes;

/// The `GeneratorsChain` creates an arbitrary-long sequence of orthogonal generators.  The sequence can be
/// deterministically produced starting with an arbitrary point.
pub struct GeneratorsChain<P> {
    reader: Sha3XofReader,
    _phantom: PhantomData<P>,
}

impl<P> GeneratorsChain<P> {
    /// Creates a chain of generators, determined by the hash of `label`
    pub(crate) fn new(label: &[u8]) -> Self {
        let mut shake = Shake256::default();
        shake.update(b"GeneratorsChain");
        shake.update(label);

        GeneratorsChain {
            reader: shake.finalize_xof_dirty(),
            _phantom: PhantomData,
        }
    }

    /// Advances the reader n times, squeezing and discarding the result
    pub(crate) fn fast_forward(mut self, n: usize) -> Self {
        let mut buf = [0u8; 64];
        for _ in 0..n {
            self.reader.read(&mut buf);
        }
        self
    }
}

impl<P> Default for GeneratorsChain<P> {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl<P: FromUniformBytes> Iterator for GeneratorsChain<P> {
    type Item = P;

    fn next(&mut self) -> Option<Self::Item> {
        let mut uniform_bytes = [0u8; 64];
        self.reader.read(&mut uniform_bytes);

        Some(P::from_uniform_bytes(&uniform_bytes))
    }
}
