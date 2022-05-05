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

use blake2::{crypto_mac::Mac, Blake2b};
use curve25519_dalek::scalar::Scalar;

use crate::{errors::ProofError, protocols::scalar_protocol::ScalarProtocol, range_proof::RangeProof};

/// Create a Blake2B deterministic nonce given a seed, label and index
pub fn nonce(
    seed_nonce: &Scalar,
    label: &str,
    index_j: Option<usize>,
    index_k: Option<usize>,
) -> Result<Scalar, ProofError> {
    let encoded_label = label.as_bytes();
    if encoded_label.len() > 16 {
        // See https://www.blake2.net/blake2.pdf section 2.8
        return Err(ProofError::InvalidLength("nonce label".to_string()));
    };
    let mut hasher = if let Some(salt) = index_j {
        let encoded_salt = salt.to_le_bytes();
        if encoded_salt.len() > 16 {
            // See https://www.blake2.net/blake2.pdf section 2.8
            return Err(ProofError::InvalidLength("nonce index_j".to_string()));
        };
        Blake2b::with_params(&seed_nonce.to_bytes(), &encoded_salt, encoded_label)
    } else {
        Blake2b::with_params(&seed_nonce.to_bytes(), &[], encoded_label)
    };
    if let Some(salt) = index_k {
        let encoded_salt = salt.to_le_bytes();
        if encoded_salt.len() > 16 {
            // See https://www.blake2.net/blake2.pdf section 2.8
            return Err(ProofError::InvalidLength("nonce index_k".to_string()));
        };
        hasher.update(&encoded_salt);
    }

    Ok(Scalar::from_hasher_blake2b(hasher))
}

/// Decompose a given value into a vector of scalars for the required bit length
pub fn bit_vector_of_scalars(value: u64, bit_length: usize) -> Result<Vec<Scalar>, ProofError> {
    if !bit_length.is_power_of_two() || bit_length > RangeProof::MAX_BIT_LENGTH {
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
pub fn read32(data: &[u8]) -> [u8; 32] {
    let mut buf32 = [0u8; 32];
    buf32[..].copy_from_slice(&data[..32]);
    buf32
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand::thread_rng;

    use crate::{
        errors::ProofError,
        protocols::scalar_protocol::ScalarProtocol,
        range_proof::RangeProof,
        utils::generic::{bit_vector_of_scalars, nonce},
    };

    #[test]
    fn test_nonce() {
        let rng = &mut thread_rng();
        let seed_nonce = Scalar::random_not_zero(rng);

        // Create personalized nonces
        let ref_nonce_eta = nonce(&seed_nonce, "eta", None, None).unwrap();
        let ref_nonce_a = nonce(&seed_nonce, "a", None, None).unwrap();
        let mut ref_nonces_dl = vec![];
        let mut ref_nonces_dr = vec![];
        for i in 0..16 {
            ref_nonces_dl.push(nonce(&seed_nonce, "dL", Some(i), Some(1)).unwrap());
            ref_nonces_dr.push(nonce(&seed_nonce, "dR", Some(i), Some(2)).unwrap());
        }

        // Verify
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
    }

    fn bit_vector_to_value(bit_vector: &[Scalar]) -> Result<u64, ProofError> {
        if !bit_vector.len().is_power_of_two() || bit_vector.len() > RangeProof::MAX_BIT_LENGTH {
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
        if bit_vector_of_scalars(0, RangeProof::MAX_BIT_LENGTH * 2).is_ok() {
            panic!("Should panic");
        }
        match bit_vector_of_scalars(u64::MAX - 12187, RangeProof::MAX_BIT_LENGTH) {
            Ok(values) => {
                assert_eq!(u64::MAX - 12187, bit_vector_to_value(&values).unwrap());
            },
            Err(_) => {
                panic!("Should not err")
            },
        }
        match bit_vector_of_scalars(u64::MAX, RangeProof::MAX_BIT_LENGTH) {
            Ok(values) => {
                assert_eq!(u64::MAX, bit_vector_to_value(&values).unwrap());
            },
            Err(_) => {
                panic!("Should not err")
            },
        }
    }
}
