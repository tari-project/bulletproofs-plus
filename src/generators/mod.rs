// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

//! The `generators` module contains API for producing a set of generators for a range proof

/// A convenience iterator struct for the generators
mod aggregated_gens_iter;
/// All the generators needed for aggregating range proofs for specified bit lengths
pub mod bulletproof_gens;
/// Arbitrary-long sequence of orthogonal generators, deterministically produced starting with an arbitrary point
mod generators_chain;
/// Represents a pair of base points for Pedersen commitments
pub mod pedersen_gens;

#[cfg(test)]
mod tests {
    use curve25519_dalek::ristretto::RistrettoPoint;

    use crate::generators::bulletproof_gens::BulletproofGens;

    #[test]
    fn aggregated_gens_iter_matches_flat_map() {
        let gens = BulletproofGens::new(64, 8);

        let helper = |n: usize, m: usize| {
            let agg_g: Vec<RistrettoPoint> = gens.g_iter(n, m).copied().collect();
            let flat_g: Vec<RistrettoPoint> = gens
                .g_vec
                .iter()
                .take(m)
                .flat_map(move |g_j| g_j.iter().take(n))
                .copied()
                .collect();

            let agg_h: Vec<RistrettoPoint> = gens.h_iter(n, m).copied().collect();
            let flat_h: Vec<RistrettoPoint> = gens
                .h_vec
                .iter()
                .take(m)
                .flat_map(move |h_j| h_j.iter().take(n))
                .copied()
                .collect();

            assert_eq!(agg_g, flat_g);
            assert_eq!(agg_h, flat_h);
        };

        helper(64, 8);
        helper(64, 4);
        helper(64, 2);
        helper(64, 1);
        helper(32, 8);
        helper(32, 4);
        helper(32, 2);
        helper(32, 1);
        helper(16, 8);
        helper(16, 4);
        helper(16, 2);
        helper(16, 1);
    }

    #[test]
    fn resizing_small_gens_matches_creating_bigger_gens() {
        let gens = BulletproofGens::new(64, 8);

        let mut gen_resized = BulletproofGens::new(32, 8);
        gen_resized.increase_capacity(64);

        let helper = |n: usize, m: usize| {
            let gens_g: Vec<RistrettoPoint> = gens.g_iter(n, m).copied().collect();
            let gens_h: Vec<RistrettoPoint> = gens.h_iter(n, m).copied().collect();

            let resized_g: Vec<RistrettoPoint> = gen_resized.g_iter(n, m).copied().collect();
            let resized_h: Vec<RistrettoPoint> = gen_resized.h_iter(n, m).copied().collect();

            assert_eq!(gens_g, resized_g);
            assert_eq!(gens_h, resized_h);
        };

        helper(64, 8);
        helper(32, 8);
        helper(16, 8);
    }
}
