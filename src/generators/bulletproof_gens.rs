// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

use crate::{generators::aggregated_gens_iter::AggregatedGensIter, traits::FromUniformBytes};

/// The `BulletproofGens` struct contains all the generators needed for aggregating up to `m` range proofs of up to `n`
/// bits each.
///
/// # Extensible Generator Generation
///
/// Instead of constructing a single vector of size `m*n`, as described in the Bulletproofs paper, we construct each
/// party's generators separately.
///
/// To construct an arbitrary-length chain of generators, we apply SHAKE256 to a domain separator label, and feed each
/// 64 bytes of XOF output into the curve hash-to-group function. Each of the `m` parties' generators are
/// constructed using a different domain separation label, and proving and verification uses the first `n` elements of
/// the arbitrary-length chain.
///
/// This means that the aggregation size (number of parties) is orthogonal to the rangeproof size (number of bits),
/// and allows using the same `BulletproofGens` object for different proving parameters.
///
/// This construction is also forward-compatible with constraint system proofs, which use a much larger slice of the
/// generator chain, and even forward-compatible to multiparty aggregation of constraint system proofs, since the
/// generators are namespaced by their party index.
#[derive(Clone, Debug)]
pub struct BulletproofGens<P> {
    /// The maximum number of usable generators for each party.
    pub gens_capacity: usize,
    /// Number of values or parties
    pub party_capacity: usize,
    /// Precomputed \\(\mathbf G\\) generators for each party.
    pub(crate) g_vec: Vec<Vec<P>>,
    /// Precomputed \\(\mathbf H\\) generators for each party.
    pub(crate) h_vec: Vec<Vec<P>>,
}

impl<P: FromUniformBytes> BulletproofGens<P> {
    /// Create a new `BulletproofGens` object.
    ///
    /// # Inputs
    ///
    /// * `gens_capacity` is the number of generators to precompute for each party.  For rangeproofs, it is sufficient
    ///   to pass `64`, the maximum bitsize of the rangeproofs.  For circuit proofs, the capacity must be greater than
    ///   the number of multipliers, rounded up to the next power of two.
    ///
    /// * `party_capacity` is the maximum number of parties that can produce an aggregated proof.
    pub fn new(gens_capacity: usize, party_capacity: usize) -> Self {
        let mut gens = BulletproofGens {
            gens_capacity: 0,
            party_capacity,
            g_vec: (0..party_capacity).map(|_| Vec::new()).collect(),
            h_vec: (0..party_capacity).map(|_| Vec::new()).collect(),
        };
        gens.increase_capacity(gens_capacity);
        gens
    }

    /// Increases the generators' capacity to the amount specified. If less than or equal to the current capacity,
    /// does nothing.
    pub fn increase_capacity(&mut self, new_capacity: usize) {
        use byteorder::{ByteOrder, LittleEndian};

        use crate::generators::generators_chain::GeneratorsChain;

        if self.gens_capacity >= new_capacity {
            return;
        }

        for i in 0..self.party_capacity {
            #[allow(clippy::cast_possible_truncation)]
            let party_index = i as u32;
            let mut label = [b'G', 0, 0, 0, 0];
            LittleEndian::write_u32(&mut label[1..5], party_index);
            self.g_vec[i].extend(
                &mut GeneratorsChain::new(&label)
                    .fast_forward(self.gens_capacity)
                    .take(new_capacity - self.gens_capacity),
            );

            label[0] = b'H';
            self.h_vec[i].extend(
                &mut GeneratorsChain::new(&label)
                    .fast_forward(self.gens_capacity)
                    .take(new_capacity - self.gens_capacity),
            );
        }
        self.gens_capacity = new_capacity;
    }

    /// Return an iterator over the aggregation of the parties' G generators with given size `n`.
    pub(crate) fn g_iter(&self, n: usize, m: usize) -> impl Iterator<Item = &P> {
        AggregatedGensIter {
            n,
            m,
            array: &self.g_vec,
            party_idx: 0,
            gen_idx: 0,
        }
    }

    /// Return an iterator over the aggregation of the parties' H generators with given size `n`.
    pub(crate) fn h_iter(&self, n: usize, m: usize) -> impl Iterator<Item = &P> {
        AggregatedGensIter {
            n,
            m,
            array: &self.h_vec,
            party_idx: 0,
            gen_idx: 0,
        }
    }
}
