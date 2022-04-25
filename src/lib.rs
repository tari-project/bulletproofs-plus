// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

#![cfg_attr(not(debug_assertions), deny(unused_variables))]
#![cfg_attr(not(debug_assertions), deny(unused_imports))]
#![cfg_attr(not(debug_assertions), deny(dead_code))]
#![cfg_attr(not(debug_assertions), deny(unused_extern_crates))]
#![deny(unused_must_use)]
#![deny(unreachable_patterns)]
#![deny(unknown_lints)]
#![recursion_limit = "1024"]
// #![deny(missing_docs)]

// Some functions have a large amount of dependencies (e.g. services) and historically this warning has lead to
// bundling of dependencies into a resources struct, which is then overused and is the wrong abstraction
#![allow(clippy::too_many_arguments)]

/// Bulletproof+ commitment opening
pub mod commitment_opening;
/// Bulletproof+ error definitions
pub mod errors;
/// Bulletproof+ `generators` module contains API for producing a set of generators for a range proof
pub mod generators;
/// Bulletproof+ add 'Debug' functionality to other struct members that do not implement 'Debug'
pub mod hidden;
/// Bulletproof+ inner product calculation for each round
mod inner_product_round;
/// Bulletproof+ range parameters (generators and base points) needed for a batch of range proofs
pub mod range_parameters;
/// Bulletproof+ public range proof parameters intended for a verifier
pub mod range_proof;
/// Bulletproof+ generators, vector of commitments, vector of optional minimum promised
/// values and a vector of optional seed nonces for mask recovery
pub mod range_statement;
/// Bulletproof+ commitment openings for the aggregated case
pub mod range_witness;
/// Bulletproof+ `ScalarProtocol` trait for using a Scalar
pub mod scalar_protocol;
/// Bulletproof+ `TranscriptProtocol` trait for using a Scalar
mod transcript_protocol;
/// Bulletproof+ utilities
mod utils;

/// Bulletproof+ generators and base points needed for a batch of range proofs
pub use generators::bulletproof_gens::BulletproofGens;
/// Bulletproof+ generators and base points needed for a batch of range proofs
pub use generators::pedersen_gens::PedersenGens;
