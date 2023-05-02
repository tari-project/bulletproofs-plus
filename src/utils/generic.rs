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

use blake2::Blake2b;
use curve25519_dalek::scalar::Scalar;

use crate::{errors::ProofError, protocols::scalar_protocol::ScalarProtocol, range_proof::MAX_RANGE_PROOF_BIT_LENGTH};

/// Encode a `usize` as 32 bits, or return an appropriate error
fn encode_usize(size: usize) -> Result<Vec<u8>, ProofError> {
    u32::try_from(size)
        .map_err(|_| ProofError::InvalidLength("Bad size encoding".to_string()))
        .map(|s| s.to_le_bytes().to_vec())
}

/// Create a Blake2B deterministic nonce given a seed, label and two indexes
pub fn nonce(
    seed_nonce: &[u8],
    label: &str,
    index_j: Option<usize>,
    index_k: Option<usize>,
) -> Result<Scalar, ProofError> {
    // Using `Blake2b::with_params(key: &[u8], salt: &[u8], persona: &[u8])`, if the `persona` or `salt` parameters
    // exceed 16 bytes, unhandled exceptions occur, so we have to do the length check ourselves.
    // See https://www.blake2.net/blake2.pdf section 2.8
    let encoded_label = label.as_bytes();
    if encoded_label.len() > 16 {
        return Err(ProofError::InvalidLength("nonce label".to_string()));
    };

    // Allocate enough memory
    let mut key = Vec::with_capacity(1 + seed_nonce.len() + 1 + 8 + 1 + 8);
    key.push(0u8); // Initialize the vector to enable 'append' (1 byte)

    // Write the seed nonce with prepended length
    key.append(&mut encode_usize(seed_nonce.len())?);
    key.append(&mut seed_nonce.to_vec());

    // If defined, write the j-index with prepended length
    if let Some(index) = index_j {
        key.append(&mut b"j".to_vec());
        key.append(&mut encode_usize(index)?);
    }

    // If defined, write the k-index with prepended length
    if let Some(index) = index_k {
        key.append(&mut b"k".to_vec());
        key.append(&mut encode_usize(index)?);
    }
    let hasher = Blake2b::with_params(&key, &[], encoded_label);

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
            result.push(Scalar::zero());
        } else {
            result.push(Scalar::one());
        }
    }
    Ok(result)
}

/// Given `data` with `len >= 32`, return the first 32 bytes.
pub fn read_32_bytes(data: &[u8]) -> [u8; 32] {
    let mut buf32 = [0u8; 32];
    buf32[..].copy_from_slice(&data[..32]);
    buf32
}

/// Given `data` with `len >= 1`, return the first 1 byte.
pub fn read_1_byte(data: &[u8]) -> [u8; 1] {
    let mut buf8 = [0u8; 1];
    buf8[..].copy_from_slice(&data[..1]);
    buf8
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    use crate::{
        errors::ProofError,
        range_proof::MAX_RANGE_PROOF_BIT_LENGTH,
        utils::generic::{bit_vector_of_scalars, nonce},
    };

    #[test]
    fn test_nonce() {
        let seed_nonce = thread_rng().gen::<[u8; 32]>().to_vec();

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
            let label: String = (&mut thread_rng())
                .sample_iter(Alphanumeric)
                .take(i)
                .map(char::from)
                .collect();
            match nonce(
                &seed_nonce,
                label.as_str(),
                Some(u32::MAX as usize),
                Some(u32::MAX as usize),
            ) {
                Ok(_) => {
                    if i > 16 {
                        panic!("Should err on label size >16")
                    }
                },
                Err(_) => {
                    if i <= 16 {
                        panic!("Should not err on label size <=16")
                    }
                },
            }
        }
    }

    fn bit_vector_to_value(bit_vector: &[Scalar]) -> Result<u64, ProofError> {
        if !bit_vector.len().is_power_of_two() || bit_vector.len() > MAX_RANGE_PROOF_BIT_LENGTH {
            return Err(ProofError::InvalidLength(
                "Bit vector must be a power of 2 with length <= 64".to_string(),
            ));
        }
        let mut result = 0u128;
        for i in 0..bit_vector.len() as u128 {
            if bit_vector[i as usize] == Scalar::one() {
                result += 1 << i;
            }
        }
        #[allow(clippy::cast_possible_truncation)]
        Ok(result as u64)
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn test_bit_vector() {
        match bit_vector_of_scalars(11, 4) {
            Ok(values) => {
                assert_eq!(11, bit_vector_to_value(&values).unwrap());
            },
            Err(_) => {
                panic!("Should not err")
            },
        }
        match bit_vector_of_scalars(15, 4) {
            Ok(values) => {
                assert_eq!(15, bit_vector_to_value(&values).unwrap());
            },
            Err(_) => {
                panic!("Should not err")
            },
        }
        if bit_vector_of_scalars(15, 5).is_ok() {
            panic!("Should panic");
        }
        if bit_vector_of_scalars(16, 4).is_ok() {
            panic!("Should panic");
        }
        if bit_vector_of_scalars(0, MAX_RANGE_PROOF_BIT_LENGTH * 2).is_ok() {
            panic!("Should panic");
        }
        match bit_vector_of_scalars(u64::MAX - 12187, MAX_RANGE_PROOF_BIT_LENGTH) {
            Ok(values) => {
                assert_eq!(u64::MAX - 12187, bit_vector_to_value(&values).unwrap());
            },
            Err(_) => {
                panic!("Should not err")
            },
        }
        match bit_vector_of_scalars(u64::MAX, MAX_RANGE_PROOF_BIT_LENGTH) {
            Ok(values) => {
                assert_eq!(u64::MAX, bit_vector_to_value(&values).unwrap());
            },
            Err(_) => {
                panic!("Should not err")
            },
        }
    }
}
