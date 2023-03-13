// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ error definitions

use snafu::prelude::*;
use alloc::string::String;
/// Represents an error in proof creation, verification, or parsing.
#[derive(Debug, Snafu)]
pub enum ProofError {
    /// A proof component failed to verify
    #[snafu(display("A proof component failed to verify: `{reason}"))]
    VerificationFailed { reason: String },
    /// Internal data sizes are inconsistent
    #[snafu(display("Internal data is invalid: `{reason}`"))]
    InvalidArgument { reason: String },
    /// Invalid array/vector length error
    #[snafu(display("Invalid array/vector length error: `{reason}`"))]
    InvalidLength { reason: String },
    #[snafu(display("Invalid Blake2b"))]
    InvalidBlake2b {},
}
