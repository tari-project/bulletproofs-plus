// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! A null random number generator useful for batch verification.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use zeroize::Zeroize;

/// This is a null random number generator that exists only for deterministic transcript-based weight generation.
/// It only produces zero.
/// This is DANGEROUS in general; don't use this for any other purpose!
pub(crate) struct NullRng;

impl TryRng for NullRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.zeroize();
        Ok(())
    }
}

// This is not actually cryptographically secure!
// We do this so we can use `NullRng` with `TranscriptRng`.
impl TryCryptoRng for NullRng {}

#[cfg(test)]
mod test {
    use rand_core::Rng;

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
