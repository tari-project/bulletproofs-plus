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
// Some functions have a large amount of dependencies (e.g. services) and historically this warning
// has lead to bundling of dependencies into a resources struct, which is then overused and is the
// wrong abstraction
#![allow(clippy::too_many_arguments)]

pub mod commitment_opening;
mod errors;
pub mod generators;
mod inner_product_round;
pub mod range_parameters;
pub mod range_proof;
pub mod range_statement;
pub mod range_witness;
mod transcript;
mod utils;

pub use crate::generators::{BulletproofGens, PedersenGens};
