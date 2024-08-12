// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

//! Bulletproofs+ utilities

use alloc::{string::ToString, vec::Vec};
use core::convert::TryFrom;

use blake2::Blake2bMac512;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroizing;

use crate::{errors::ProofError, protocols::scalar_protocol::ScalarProtocol};

/// The maximum number of bytes that `Blake2b` can accommodate in its `persona` field
/// This is defined in https://www.blake2.net/blake2.pdf section 2.8
const BLAKE2B_PERSONA_LIMIT: usize = 16;

/// Encode a `usize` as 32 bits, or return an error if this would truncate
fn encode_usize(size: usize) -> Result<Vec<u8>, ProofError> {
    u32::try_from(size)
        .map_err(|_| ProofError::InvalidLength("Bad size encoding".to_string()))
        .map(|s| s.to_le_bytes().to_vec())
}

/// Create a deterministic scalar nonce given a seed, label and two (optional) indexes
pub fn nonce(
    seed_nonce: &Scalar,
    label: &str,
    index_j: Option<usize>,
    index_k: Option<usize>,
) -> Result<Scalar, ProofError> {
    // The label is embedded into the `Blake2b` hash using its `persona` field
    // To avoid scary exceptions, we manually check for a valid length
    let encoded_label = label.as_bytes();
    if encoded_label.len() > BLAKE2B_PERSONA_LIMIT {
        return Err(ProofError::InvalidLength("Bad nonce label encoding".to_string()));
    };

    // We use fixed-length encodings of the seed and (optional) indexes
    // Further, we use domain separation for the indexes to avoid collisions
    let mut key = Zeroizing::new(Vec::with_capacity(43)); // 1 + 32 + optional(1 + 4)  + optional(1 + 4)
    key.push(0u8); // Initialize the vector to enable 'append' (1 byte)
    key.append(&mut seed_nonce.to_bytes().to_vec()); // Fixed length encoding of 'seed_nonce' (32 bytes)
    if let Some(index) = index_j {
        key.append(&mut b"j".to_vec()); // Domain separated index label (1 byte)
        key.append(&mut encode_usize(index)?); // Fixed length encoding of 'index_j' (4 bytes)
    }
    if let Some(index) = index_k {
        key.append(&mut b"k".to_vec()); // Domain separated index label (1 byte)
        key.append(&mut encode_usize(index)?); // Fixed length encoding of 'index_k' (4 bytes)
    }
    let hasher =
        Blake2bMac512::new_with_salt_and_personal(&key, &[], encoded_label).map_err(|_| ProofError::InvalidBlake2b)?;

    Ok(Scalar::from_hasher_blake2b(hasher))
}

/// Compute the padding needed for generator vectors
pub fn compute_generator_padding(
    bit_length: usize,
    aggregation_factor: usize,
    max_aggregation_factor: usize,
) -> Result<usize, ProofError> {
    let padded_capacity = 2usize
        .checked_mul(bit_length)
        .ok_or(ProofError::SizeOverflow)?
        .checked_mul(max_aggregation_factor)
        .ok_or(ProofError::SizeOverflow)?;
    let actual_capacity = 2usize
        .checked_mul(bit_length)
        .ok_or(ProofError::SizeOverflow)?
        .checked_mul(aggregation_factor)
        .ok_or(ProofError::SizeOverflow)?;

    padded_capacity
        .checked_sub(actual_capacity)
        .ok_or(ProofError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use curve25519_dalek::scalar::Scalar;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use crate::{protocols::scalar_protocol::ScalarProtocol, utils::generic::*};

    #[test]
    fn test_padding() {
        // No padding
        assert_eq!(compute_generator_padding(64, 1, 1).unwrap(), 0);

        // Padding
        assert_eq!(compute_generator_padding(64, 1, 2).unwrap(), 128);

        // Invalid
        assert!(compute_generator_padding(64, 2, 1).is_err());
        assert!(compute_generator_padding(64, usize::MAX - 1, usize::MAX).is_err());
    }

    #[test]
    fn test_nonce() {
        let mut rng = ChaCha12Rng::seed_from_u64(8675309); // for testing only!
        let seed_nonce = Scalar::random_not_zero(&mut rng);

        // Create personalized nonces
        let ref_nonce_eta = nonce(&seed_nonce, "eta", None, None).unwrap();
        let ref_nonce_a = nonce(&seed_nonce, "a", None, None).unwrap();
        assert_ne!(ref_nonce_eta, ref_nonce_a);
        let mut ref_nonces_dl = vec![];
        let mut ref_nonces_dr = vec![];
        for i in 0..16 {
            ref_nonces_dl.push(nonce(&seed_nonce, "dL", Some(i), Some(1)).unwrap());
            ref_nonces_dr.push(nonce(&seed_nonce, "dR", Some(i), Some(2)).unwrap());
        }

        // Verify deterministic nonces
        for i in 0..16 {
            assert_ne!(ref_nonces_dl[i], nonce(&seed_nonce, "dR", Some(i), Some(2)).unwrap());
            assert_ne!(ref_nonces_dr[i], nonce(&seed_nonce, "dL", Some(i), Some(1)).unwrap());
            assert_ne!(
                ref_nonces_dl[i],
                nonce(&seed_nonce, "dL", Some(i + 1), Some(1)).unwrap()
            );
            assert_ne!(
                ref_nonces_dr[i],
                nonce(&seed_nonce, "dR", Some(i + 1), Some(2)).unwrap()
            );
            assert_ne!(ref_nonces_dl[i], nonce(&seed_nonce, "dL", Some(i), Some(2)).unwrap());
            assert_ne!(ref_nonces_dr[i], nonce(&seed_nonce, "dR", Some(i), Some(1)).unwrap());
        }
        assert_ne!(ref_nonce_eta, nonce(&seed_nonce, "a", None, None).unwrap());
        assert_ne!(ref_nonce_a, nonce(&seed_nonce, "eta", None, None).unwrap());
        assert_ne!(ref_nonce_a, nonce(&seed_nonce, "a", None, Some(1)).unwrap());
        assert_ne!(ref_nonce_eta, nonce(&seed_nonce, "eta", None, Some(1)).unwrap());

        for i in (0..16).rev() {
            assert_eq!(ref_nonces_dr[i], nonce(&seed_nonce, "dR", Some(i), Some(2)).unwrap());
            assert_eq!(ref_nonces_dl[i], nonce(&seed_nonce, "dL", Some(i), Some(1)).unwrap());
        }
        assert_eq!(ref_nonce_a, nonce(&seed_nonce, "a", None, None).unwrap());
        assert_eq!(ref_nonce_eta, nonce(&seed_nonce, "eta", None, None).unwrap());

        // Verify domain separation for indexes
        assert_ne!(
            nonce(&seed_nonce, "", None, Some(1)).unwrap(),
            nonce(&seed_nonce, "", Some(1), None).unwrap()
        );
        assert_eq!(
            nonce(&seed_nonce, "", Some(1), None).unwrap(),
            nonce(&seed_nonce, "", Some(1), None).unwrap()
        );
        assert_eq!(
            nonce(&seed_nonce, "", None, Some(1)).unwrap(),
            nonce(&seed_nonce, "", None, Some(1)).unwrap()
        );
        assert_ne!(
            nonce(&seed_nonce, "", None, None).unwrap(),
            nonce(&seed_nonce, "", Some(1), None).unwrap()
        );
        assert_ne!(
            nonce(&seed_nonce, "", None, None).unwrap(),
            nonce(&seed_nonce, "", None, Some(1)).unwrap()
        );

        // Verify no unhandled exceptions occur with varying label parameter lengths
        for i in 0..32 {
            let label = "a".repeat(i);
            match nonce(
                &Scalar::random(&mut rng),
                label.as_str(),
                Some(u32::MAX as usize),
                Some(u32::MAX as usize),
            ) {
                Ok(_) => {
                    assert!(i <= BLAKE2B_PERSONA_LIMIT);
                },
                Err(_) => {
                    assert!(i > BLAKE2B_PERSONA_LIMIT);
                },
            }
        }

        // Verify that indexes are valid if within a `u32` limit
        for index in [0, 1, 2, u32::MAX as usize] {
            assert!(nonce(&seed_nonce, "", Some(index), None).is_ok());
            assert!(nonce(&seed_nonce, "", None, Some(index)).is_ok());
        }

        // Verify that indexes are invalid if exceeding a `u32` limit
        assert!(nonce(&seed_nonce, "", Some(u32::MAX as usize + 1), None).is_err());
        assert!(nonce(&seed_nonce, "", None, Some(u32::MAX as usize + 1)).is_err());
    }
}
