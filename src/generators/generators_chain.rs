// Copyright (c) 2018 Chain, Inc.
// SPDX-License-Identifier: MIT

// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use curve25519_dalek::ristretto::RistrettoPoint;
use digest::{ExtendableOutputDirty, Update, XofReader};
use sha3::{Sha3XofReader, Shake256};

/// The `GeneratorsChain` creates an arbitrary-long sequence of orthogonal generators.  The sequence can be
/// deterministically produced starting with an arbitrary point.
pub struct GeneratorsChain {
    reader: Sha3XofReader,
}

impl GeneratorsChain {
    /// Creates a chain of generators, determined by the hash of `label`
    pub(crate) fn new(label: &[u8]) -> Self {
        let mut shake = Shake256::default();
        shake.update(b"GeneratorsChain");
        shake.update(label);

        GeneratorsChain {
            reader: shake.finalize_xof_dirty(),
        }
    }

    /// Advances the reader n times, squeezing and discarding the result
    pub(crate) fn fast_forward(mut self, n: usize) -> Self {
        for _ in 0..n {
            let mut buf = [0u8; 64];
            self.reader.read(&mut buf);
        }
        self
    }
}

impl Default for GeneratorsChain {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl Iterator for GeneratorsChain {
    type Item = RistrettoPoint;

    fn next(&mut self) -> Option<Self::Item> {
        let mut uniform_bytes = [0u8; 64];
        self.reader.read(&mut uniform_bytes);

        Some(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}
