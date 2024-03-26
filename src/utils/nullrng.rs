// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! A null random number generator useful for batch verification.

use rand_core::{
    impls::{next_u32_via_fill, next_u64_via_fill},
    CryptoRng,
    RngCore,
};
use zeroize::Zeroize;

/// This is a null random number generator that exists only for deterministic transcript-based weight generation.
/// It only produces zero.
/// This is DANGEROUS in general; don't use this for any other purpose!
pub(crate) struct NullRng;

impl RngCore for NullRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.zeroize();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);

        Ok(())
    }

    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }
}

// This is not actually cryptographically secure!
// We do this so we can use `NullRng` with `TranscriptRng`.
impl CryptoRng for NullRng {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_fill_bytes() {
        let mut rng = NullRng;
        let mut bytes = [1u8; 32];

        // The buffer should always be set to zero
        rng.fill_bytes(&mut bytes);
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn test_try_fill_bytes() {
        let mut rng = NullRng;
        let mut bytes = [1u8; 32];

        // The buffer should always be set to zero
        rng.try_fill_bytes(&mut bytes).unwrap();
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn test_next() {
        let mut rng = NullRng;

        // We should always get zero
        assert_eq!(rng.next_u32(), 0);
        assert_eq!(rng.next_u32(), 0);
        assert_eq!(rng.next_u64(), 0);
        assert_eq!(rng.next_u64(), 0);
    }
}
