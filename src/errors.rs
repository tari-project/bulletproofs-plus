// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

// #![deny(missing_docs)]

use thiserror::Error;

/// Represents an error in proof creation, verification, or parsing.
#[derive(Debug, Error)]
pub enum ProofError {
    #[error("A proof component failed to verify: `{0}")]
    VerificationFailed(String),
    #[error("Internal data sizes are inconsistent: `{0}`")]
    InternalDataInconsistent(String),
    #[error("Invalid array/vector length error: `{0}`")]
    InvalidLength(String),
}
