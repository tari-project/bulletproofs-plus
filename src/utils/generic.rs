// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

//! Bulletproofs+ utilities

use core::{
    option::{Option, Option::Some},
    result::{
        Result,
        Result::{Err, Ok},
    },
};
use std::convert::TryFrom;

use blake2::Blake2bMac512;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroizing;

use crate::{errors::ProofError, protocols::scalar_protocol::ScalarProtocol, range_proof::MAX_RANGE_PROOF_BIT_LENGTH};

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

/// Decompose a given value into a vector of scalars for the required bit length
pub fn bit_vector_of_scalars(value: u64, bit_length: usize) -> Result<Vec<Scalar>, ProofError> {
    if !bit_length.is_power_of_two() || bit_length > MAX_RANGE_PROOF_BIT_LENGTH {
        return Err(ProofError::InvalidLength(
            "Bit size not valid, must be a power of 2 and <= 64".to_string(),
        ));
    }
    if value >> (bit_length - 1) > 1 {
        return Err(ProofError::InvalidLength(
            "Value too large, bit vector capacity will be exceeded".to_string(),
        ));
    }
    let mut result = Vec::with_capacity(bit_length);
    for i in 0..bit_length {
        if (value >> i) & 1 == 0 {
            result.push(Scalar::ZERO);
        } else {
            result.push(Scalar::ONE);
        }
    }
    Ok(result)
}

/// Split a vector, checking the bound to avoid a panic
pub fn split_at_checked<T>(vec: &[T], n: usize) -> Result<(&[T], &[T]), ProofError> {
    if n <= vec.len() {
        Ok(vec.split_at(n))
    } else {
        Err(ProofError::InvalidLength("Invalid vector split index".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    use crate::{
        errors::ProofError,
        protocols::scalar_protocol::ScalarProtocol,
        range_proof::MAX_RANGE_PROOF_BIT_LENGTH,
        utils::generic::{bit_vector_of_scalars, nonce, split_at_checked, BLAKE2B_PERSONA_LIMIT},
    };

    #[test]
    fn test_split() {
        // Check valid splits
        let v = vec![0u8, 1u8, 2u8];
        let (l, r) = split_at_checked(&v, 0).unwrap();
        assert_eq!(l, vec![]);
        assert_eq!(r, vec![0u8, 1u8, 2u8]);

        let (l, r) = split_at_checked(&v, 1).unwrap();
        assert_eq!(l, vec![0u8]);
        assert_eq!(r, vec![1u8, 2u8]);

        let (l, r) = split_at_checked(&v, 2).unwrap();
        assert_eq!(l, vec![0u8, 1u8]);
        assert_eq!(r, vec![2u8]);

        let (l, r) = split_at_checked(&v, 3).unwrap();
        assert_eq!(l, vec![0u8, 1u8, 2u8]);
        assert_eq!(r, vec![]);

        // Check invalid split
        assert!(split_at_checked(&v, 4).is_err());

        // Split an empty vector
        let v = Vec::<u8>::new();
        let (l, r) = split_at_checked(&v, 0).unwrap();
        assert_eq!(l, Vec::<u8>::new());
        assert_eq!(r, Vec::<u8>::new());
    }

    #[test]
    fn test_nonce() {
        let mut rng = thread_rng();
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
            let label: String = (&mut rng).sample_iter(Alphanumeric).take(i).map(char::from).collect();
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

    fn bit_vector_to_value(bit_vector: &[Scalar]) -> Result<u64, ProofError> {
        if !bit_vector.len().is_power_of_two() || bit_vector.len() > MAX_RANGE_PROOF_BIT_LENGTH {
            return Err(ProofError::InvalidLength(
                "Bit vector must be a power of 2 with length <= 64".to_string(),
            ));
        }
        let mut result = 0u128;
        for i in 0..bit_vector.len() as u128 {
            if bit_vector[i as usize] == Scalar::ONE {
                result += 1 << i;
            }
        }
        #[allow(clippy::cast_possible_truncation)]
        Ok(result as u64)
    }

    #[test]
    fn test_bit_vector() {
        // Valid cases
        assert_eq!(bit_vector_to_value(&bit_vector_of_scalars(11, 4).unwrap()).unwrap(), 11);
        assert_eq!(bit_vector_to_value(&bit_vector_of_scalars(15, 4).unwrap()).unwrap(), 15);
        assert_eq!(
            bit_vector_to_value(&bit_vector_of_scalars(u64::MAX - 12187, MAX_RANGE_PROOF_BIT_LENGTH).unwrap()).unwrap(),
            u64::MAX - 12187
        );
        assert_eq!(
            bit_vector_to_value(&bit_vector_of_scalars(u64::MAX, MAX_RANGE_PROOF_BIT_LENGTH).unwrap()).unwrap(),
            u64::MAX
        );

        // Error cases
        assert!(bit_vector_of_scalars(15, 5).is_err());
        assert!(bit_vector_of_scalars(16, 4).is_err());
        assert!(bit_vector_of_scalars(0, MAX_RANGE_PROOF_BIT_LENGTH * 2).is_err());
    }
}
