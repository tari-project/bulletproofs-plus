// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

use core::{
    fmt::{self, Debug, Formatter},
    iter::FusedIterator,
    marker::PhantomData,
};

use digest::{ExtendableOutput, Update, XofReader, core_api::XofReaderCoreWrapper};
use sha3::{Shake256, Shake256ReaderCore};

use crate::traits::FromUniformBytes;

/// The `GeneratorsChain` creates an arbitrary-long sequence of orthogonal generators.  The sequence can be
/// deterministically produced starting with an arbitrary point.
pub struct GeneratorsChain<P> {
    reader: XofReaderCoreWrapper<Shake256ReaderCore>,
    _phantom: PhantomData<P>,
}

impl<P> Clone for GeneratorsChain<P> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<P> Debug for GeneratorsChain<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratorsChain").finish_non_exhaustive()
    }
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

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}

impl<P: FromUniformBytes> FusedIterator for GeneratorsChain<P> {}

#[cfg(test)]
mod tests {
    use alloc::{format, vec::Vec};

    use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};

    use super::*;

    #[test]
    fn generators_chain_is_deterministic_and_domain_separated() {
        let chain_a1: Vec<RistrettoPoint> = GeneratorsChain::new(b"party-0").take(4).collect();
        let chain_a2: Vec<RistrettoPoint> = GeneratorsChain::new(b"party-0").take(4).collect();
        let chain_b: Vec<RistrettoPoint> = GeneratorsChain::new(b"party-1").take(4).collect();

        assert_eq!(chain_a1, chain_a2);
        assert_ne!(chain_a1, chain_b);
        assert!(chain_a1.iter().all(|p| *p != RistrettoPoint::identity()));
    }

    #[test]
    fn generators_chain_clone_and_default_preserve_xof_state() {
        let mut chain = GeneratorsChain::<RistrettoPoint>::default();
        let first_default = chain.next().unwrap();
        let mut direct_empty = GeneratorsChain::<RistrettoPoint>::new(&[]);
        assert_eq!(first_default, direct_empty.next().unwrap());

        let mut forked = chain.clone();
        assert_eq!(chain.next(), forked.next());
        assert_eq!(chain.size_hint(), (usize::MAX, None));
        assert!(format!("{chain:?}").contains("GeneratorsChain"));
    }
}
