// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+

#![recursion_limit = "1024"]

#[macro_use]
extern crate lazy_static;

/// Bulletproofs+ commitment opening
pub mod commitment_opening;
/// Bulletproofs+ error definitions
pub mod errors;
/// Bulletproofs+ `generators` module contains API for producing a set of generators for a range proof
pub mod generators;
/// Bulletproofs+ add 'Debug' functionality to other struct members that do not implement 'Debug'
pub mod hidden;
/// Bulletproofs+ inner product calculation for each round
mod inner_product_round;
/// Bulletproofs+ range parameters (generators and base points) needed for a batch of range proofs
pub mod range_parameters;
/// Bulletproofs+ public range proof parameters intended for a verifier
pub mod range_proof;
/// Bulletproofs+ generators, vector of commitments, vector of optional minimum promised
/// values and a vector of optional seed nonces for mask recovery
pub mod range_statement;
/// Bulletproofs+ commitment openings for the aggregated case
pub mod range_witness;
/// Bulletproofs+ `ScalarProtocol` trait for using a Scalar
pub mod scalar_protocol;
/// Bulletproofs+ `TranscriptProtocol` trait for using a Scalar
mod transcript_protocol;
/// Bulletproofs+ utilities
mod utils;

/// Bulletproofs+ generators and base points needed for a batch of range proofs
pub use generators::bulletproof_gens::BulletproofGens;
/// Bulletproofs+ generators and base points needed for a batch of range proofs
pub use generators::pedersen_gens::PedersenGens;
