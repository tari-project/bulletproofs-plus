// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

//! Bulletproofs+ `TranscriptProtocol` trait for using a Transcript

use curve25519_dalek::{scalar::Scalar, traits::IsIdentity};
use merlin::Transcript;

use crate::{errors::ProofError, traits::FixedBytesRepr};

/// Defines a `TranscriptProtocol` trait for using a Merlin transcript.
pub trait TranscriptProtocol {
    /// Append a domain separator for the range proof with the given `label` and `message`.
    fn domain_separator(&mut self, label: &'static [u8], message: &[u8]);

    /// Append a `scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);

    /// Append a `point` with the given `label`.
    fn append_point<P: FixedBytesRepr>(&mut self, label: &'static [u8], point: &P);

    /// Check that a point is not the identity, then append it to the
    /// transcript.  Otherwise, return an error.
    fn validate_and_append_point<P: FixedBytesRepr + IsIdentity>(
        &mut self,
        label: &'static [u8],
        point: &P,
    ) -> Result<(), ProofError>;

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Result<Scalar, ProofError>;
}

impl TranscriptProtocol for Transcript {
    fn domain_separator(&mut self, label: &'static [u8], message: &[u8]) {
        self.append_message(label, message);
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
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

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Result<Scalar, ProofError> {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        let value = Scalar::from_bytes_mod_order_wide(&buf);
        if value == Scalar::zero() {
            Err(ProofError::VerificationFailed(
                "Transcript challenge cannot be zero".to_string(),
            ))
        } else {
            Ok(value)
        }
    }
}
