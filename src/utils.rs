// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::errors::ProofError;
use crate::range_proof::RangeProof;
use blake2::Blake2b;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

pub fn nonce(seed: &Scalar, label: &str, index: Option<usize>) -> Result<Scalar, ProofError> {
    let encoded_label = label.as_bytes();
    if encoded_label.len() > 16 {
        // See https://www.blake2.net/blake2.pdf section 2.8
        return Err(ProofError::InvalidLength("nonce label".to_string()));
    };
    let hasher = if let Some(salt) = index {
        let encoded_index = salt.to_le_bytes();
        if encoded_index.len() > 16 {
            // See https://www.blake2.net/blake2.pdf section 2.8
            return Err(ProofError::InvalidLength("nonce index".to_string()));
        };
        Blake2b::with_params(&seed.to_bytes(), &encoded_index, encoded_label)
    } else {
        Blake2b::with_params(&seed.to_bytes(), &[], encoded_label)
    };
    Ok(Scalar::from_hash(hasher))
}

pub fn mul_point_vec_with_scalar(
    point_vec: &[RistrettoPoint],
    scalar: &Scalar,
) -> Result<Vec<RistrettoPoint>, ProofError> {
    if point_vec.is_empty() {
        return Err(ProofError::InvalidLength(
            "Cannot multiply empty point vector with scalar".to_string(),
        ));
    }
    let mut out = vec![RistrettoPoint::default(); point_vec.len()];
    for i in 0..point_vec.len() {
        out[i] = point_vec[i] * scalar;
    }
    Ok(out)
}

pub fn add_point_vec(
    a: &[RistrettoPoint],
    b: &[RistrettoPoint],
) -> Result<Vec<RistrettoPoint>, ProofError> {
    if a.len() != b.len() || a.is_empty() {
        return Err(ProofError::InvalidLength(
            "Cannot add empty point vectors".to_string(),
        ));
    }
    let mut out = vec![RistrettoPoint::default(); a.len()];
    for i in 0..a.len() {
        out[i] = a[i] + b[i];
    }
    Ok(out)
}

pub fn mul_scalar_vec_with_scalar(
    scalar_vec: &[Scalar],
    scalar: &Scalar,
) -> Result<Vec<Scalar>, ProofError> {
    if scalar_vec.is_empty() {
        return Err(ProofError::InvalidLength(
            "Cannot multiply empty scalar vector with scalar".to_string(),
        ));
    }
    let mut out = vec![Scalar::default(); scalar_vec.len()];
    for i in 0..scalar_vec.len() {
        out[i] = scalar_vec[i] * scalar;
    }
    Ok(out)
}

pub fn add_scalar_vec(a: &[Scalar], b: &[Scalar]) -> Result<Vec<Scalar>, ProofError> {
    if a.len() != b.len() || a.is_empty() {
        return Err(ProofError::InvalidLength(
            "Cannot add empty scalar vectors".to_string(),
        ));
    }
    let mut out = vec![Scalar::default(); a.len()];
    for i in 0..a.len() {
        out[i] = a[i] + b[i];
    }
    Ok(out)
}

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
    let mut result = vec![];
    for i in 0..bit_length {
        if (value >> i) & 1 != 0 {
            result.push(Scalar::one());
        } else {
            result.push(Scalar::zero());
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::errors::ProofError;
    use crate::range_proof::RangeProof;
    use crate::utils::{bit_vector_of_scalars, nonce};
    use curve25519_dalek::scalar::Scalar;
    use rand::thread_rng;

    #[test]
    fn test_nonce() {
        let rng = &mut thread_rng();
        let seed = Scalar::random(rng);

        // Create personalized nonces
        let ref_nonce_eta = nonce(&seed, "eta", None).unwrap();
        let ref_nonce_a = nonce(&seed, "a", None).unwrap();
        let mut ref_nonces_dl = vec![];
        let mut ref_nonces_dr = vec![];
        for i in 0..16 {
            ref_nonces_dl.push(nonce(&seed, "dL", Some(i)).unwrap());
            ref_nonces_dr.push(nonce(&seed, "dR", Some(i)).unwrap());
        }

        // Verify
        for i in 0..16 {
            assert_ne!(ref_nonces_dl[i], nonce(&seed, "dR", Some(i)).unwrap());
            assert_ne!(ref_nonces_dr[i], nonce(&seed, "dL", Some(i)).unwrap());
            assert_ne!(ref_nonces_dl[i], nonce(&seed, "dL", Some(i + 1)).unwrap());
            assert_ne!(ref_nonces_dr[i], nonce(&seed, "dR", Some(i + 1)).unwrap());
        }
        assert_ne!(ref_nonce_eta, nonce(&seed, "a", None).unwrap());
        assert_ne!(ref_nonce_a, nonce(&seed, "eta", None).unwrap());

        for i in (0..16).rev() {
            assert_eq!(ref_nonces_dr[i], nonce(&seed, "dR", Some(i)).unwrap());
            assert_eq!(ref_nonces_dl[i], nonce(&seed, "dL", Some(i)).unwrap());
        }
        assert_eq!(ref_nonce_a, nonce(&seed, "a", None).unwrap());
        assert_eq!(ref_nonce_eta, nonce(&seed, "eta", None).unwrap());
    }

    fn bit_vector_to_value(bit_vector: Vec<Scalar>) -> Result<u64, ProofError> {
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
        Ok(result as u64)
    }

    #[test]
    fn test_bit_vector() {
        match bit_vector_of_scalars(11, 4) {
            Ok(values) => {
                assert_eq!(11, bit_vector_to_value(values).unwrap());
            }
            Err(_) => {
                panic!("Should not err")
            }
        }
        match bit_vector_of_scalars(15, 4) {
            Ok(values) => {
                assert_eq!(15, bit_vector_to_value(values).unwrap());
            }
            Err(_) => {
                panic!("Should not err")
            }
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
                assert_eq!(u64::MAX - 12187, bit_vector_to_value(values).unwrap());
            }
            Err(_) => {
                panic!("Should not err")
            }
        }
        match bit_vector_of_scalars(u64::MAX, RangeProof::MAX_BIT_LENGTH) {
            Ok(values) => {
                assert_eq!(u64::MAX, bit_vector_to_value(values).unwrap());
            }
            Err(_) => {
                panic!("Should not err")
            }
        }
    }
}
