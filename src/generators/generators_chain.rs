// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

use std::marker::PhantomData;

use digest::{core_api::XofReaderCoreWrapper, ExtendableOutput, Update, XofReader};
use sha3::{Shake256, Shake256ReaderCore};

use crate::traits::FromUniformBytes;

/// The `GeneratorsChain` creates an arbitrary-long sequence of orthogonal generators.  The sequence can be
/// deterministically produced starting with an arbitrary point.
pub struct GeneratorsChain<P> {
    reader: XofReaderCoreWrapper<Shake256ReaderCore>,
    _phantom: PhantomData<P>,
}

impl<P> GeneratorsChain<P> {
    /// Creates a chain of generators, determined by the hash of `label`
    pub(crate) fn new(label: &[u8]) -> Self {
        let mut shake = Shake256::default();
        shake.update(b"GeneratorsChain");
        shake.update(label);

        GeneratorsChain {
            reader: shake.finalize_xof(),
            _phantom: PhantomData,
        }
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
