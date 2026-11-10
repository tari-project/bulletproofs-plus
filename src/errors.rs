// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ error definitions

use alloc::string::String;

use thiserror_no_std::Error;

/// Represents an error in proof creation, verification, or parsing.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProofError {
    /// A proof component failed to verify
    #[error("A proof component failed to verify: `{0}`")]
    VerificationFailed(String),
    /// Internal data sizes are inconsistent
    #[error("Internal data is invalid: `{0}`")]
    InvalidArgument(String),
    /// Invalid array/vector length error
    #[error("Invalid array/vector length error: `{0}`")]
    InvalidLength(String),
    /// Invalid `Blake2b` hash operation
    #[error("Invalid Blake2b")]
    InvalidBlake2b,
    /// Internal size overflow
    #[error("Internal size overflow")]
    SizeOverflow,
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_proof_error_display_and_equality() {
        let err = ProofError::VerificationFailed("bad point".to_string());
        assert_eq!(err.to_string(), "A proof component failed to verify: `bad point`");
        assert_eq!(err.clone(), err);
        assert_ne!(err, ProofError::SizeOverflow);
    }
}
