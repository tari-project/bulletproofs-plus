// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ `ScalarProtocol` trait for using a Scalar

use blake2::Blake2bMac512;
use curve25519_dalek::scalar::Scalar;
use digest::FixedOutput;
use rand_core::CryptoRngCore;

/// Defines a `ScalarProtocol` trait for using a Scalar
pub trait ScalarProtocol {
    /// Returns a non-zero random Scalar
    fn random_not_zero<R: CryptoRngCore>(rng: &mut R) -> Scalar;

    /// Construct a scalar from an existing Blake2b instance (helper function to implement `Scalar::from_hash<Blake2b>`)
    fn from_hasher_blake2b(hasher: Blake2bMac512) -> Scalar;
}

impl ScalarProtocol for Scalar {
    // 'Scalar::random(rng)' in most cases will not return zero due to the intent of the implementation, but this is
    // not guaranteed. This function makes it clear that zero will never be returned
    fn random_not_zero<R: CryptoRngCore>(rng: &mut R) -> Scalar {
        let mut value = Scalar::ZERO;
        while value == Scalar::ZERO {
            value = Scalar::random(rng);
        }

        value
    }

    fn from_hasher_blake2b(hasher: Blake2bMac512) -> Scalar {
        let mut output = [0u8; 64];
        output.copy_from_slice(hasher.finalize_fixed().as_slice());
        Scalar::from_bytes_mod_order_wide(&output)
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::Scalar;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn test_nonzero() {
        let mut rng = ChaCha12Rng::seed_from_u64(8675309); // for testing only!
        assert_ne!(Scalar::random_not_zero(&mut rng), Scalar::ZERO);
    }
}
