// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

//! Bulletproofs+ `TranscriptProtocol` trait for using a Transcript

use alloc::string::ToString;

use curve25519_dalek::{scalar::Scalar, traits::IsIdentity};
use merlin::Transcript;

use crate::{errors::ProofError, traits::FixedBytesRepr};

/// Defines a `TranscriptProtocol` trait for using a Merlin transcript.
pub trait TranscriptProtocol {
    /// Append a domain separator for the range proof.
    fn append_domain_separator(&mut self);

    /// Append a `point` with the given `label`.
    fn append_point<P: FixedBytesRepr>(&mut self, label: &'static [u8], point: &P);

    /// Check that a point is not the identity, then append it to the
    /// transcript.  Otherwise, return an error.
    fn validate_and_append_point<P: FixedBytesRepr + IsIdentity>(
        &mut self,
        label: &'static [u8],
        point: &P,
    ) -> Result<(), ProofError>;

    /// Append a `scalar` with a given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Result<Scalar, ProofError>;
}

impl TranscriptProtocol for Transcript {
    fn append_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"Bulletproofs+ Range Proof");
    }

    fn append_point<P: FixedBytesRepr>(&mut self, label: &'static [u8], point: &P) {
        self.append_message(label, point.as_fixed_bytes());
    }

    fn validate_and_append_point<P: FixedBytesRepr + IsIdentity>(
        &mut self,
        label: &'static [u8],
        point: &P,
    ) -> Result<(), ProofError> {
        if point.is_identity() {
            Err(ProofError::VerificationFailed(
                "Identity element cannot be added to the transcript".to_string(),
            ))
        } else {
            self.append_message(label, point.as_fixed_bytes());
            Ok(())
        }
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Result<Scalar, ProofError> {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        let value = Scalar::from_bytes_mod_order_wide(&buf);
        if value == Scalar::ZERO {
            Err(ProofError::VerificationFailed(
                "Transcript challenge cannot be zero".to_string(),
            ))
        } else {
            Ok(value)
        }
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::{traits::Identity, RistrettoPoint};
    use merlin::Transcript;

    use super::*;

    #[test]
    fn test_identity_point() {
        let mut transcript = Transcript::new(b"test");
        assert!(transcript
            .validate_and_append_point(b"identity", &RistrettoPoint::identity().compress())
            .is_err());
    }
}
