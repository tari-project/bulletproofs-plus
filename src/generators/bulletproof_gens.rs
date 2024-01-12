// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

use alloc::{sync::Arc, vec::Vec};
use core::{
    convert::TryFrom,
    fmt::{Debug, Formatter},
};

use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::traits::VartimePrecomputedMultiscalarMul;
use itertools::Itertools;

use crate::{
    errors::ProofError,
    generators::{aggregated_gens_iter::AggregatedGensIter, generators_chain::GeneratorsChain},
    traits::{Compressable, FromUniformBytes, Precomputable},
};

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
pub struct BulletproofGens<P: Precomputable> {
    /// The maximum number of usable generators for each party.
    pub gens_capacity: usize,
    /// Number of values or parties
    pub party_capacity: usize,
    /// Precomputed \\(\mathbf G\\) generators for each party.
    pub(crate) g_vec: Vec<Vec<P>>,
    /// Precomputed \\(\mathbf H\\) generators for each party.
    pub(crate) h_vec: Vec<Vec<P>>,
    /// Interleaved precomputed generators
    pub(crate) precomp: Arc<P::Precomputation>,
}

// This manual `Clone` implementation is required since derived cloning requires the curve library precomputation struct
// to support `Clone`
impl<P> Clone for BulletproofGens<P>
where
    P: Precomputable,
    Vec<P>: Clone,
{
    fn clone(&self) -> Self {
        BulletproofGens {
            gens_capacity: self.gens_capacity,
            party_capacity: self.party_capacity,
            g_vec: self.g_vec.clone(),
            h_vec: self.h_vec.clone(),
            precomp: self.precomp.clone(),
        }
    }
}

impl<P: FromUniformBytes + Precomputable> BulletproofGens<P> {
    /// Create a new `BulletproofGens` object.
    ///
    /// # Inputs
    ///
    /// * `gens_capacity` is the number of generators to precompute for each party.  For rangeproofs, it is sufficient
    ///   to pass `64`, the maximum bitsize of the rangeproofs.  For circuit proofs, the capacity must be greater than
    ///   the number of multipliers, rounded up to the next power of two.
    ///
    /// * `party_capacity` is the maximum number of parties that can produce an aggregated proof.
    pub fn new(gens_capacity: usize, party_capacity: usize) -> Result<Self, ProofError> {
        let mut g_vec: Vec<Vec<P>> = (0..party_capacity).map(|_| Vec::new()).collect();
        let mut h_vec: Vec<Vec<P>> = (0..party_capacity).map(|_| Vec::new()).collect();

        // Generate the points
        for (i, (g, h)) in g_vec.iter_mut().zip(h_vec.iter_mut()).enumerate() {
            let party_index = u32::try_from(i).map_err(|_| ProofError::SizeOverflow)?;

            let mut label = [b'G', 0, 0, 0, 0];
            LittleEndian::write_u32(&mut label[1..5], party_index);
            g.extend(&mut GeneratorsChain::<P>::new(&label).take(gens_capacity));

            label[0] = b'H';
            h.extend(&mut GeneratorsChain::<P>::new(&label).take(gens_capacity));
        }

        // Generate a flattened interleaved iterator for the precomputation tables
        let iter_g_vec = g_vec.iter().flat_map(move |g_j| g_j.iter());
        let iter_h_vec = h_vec.iter().flat_map(move |h_j| h_j.iter());
        let iter_interleaved = iter_g_vec.interleave(iter_h_vec);
        let precomp = Arc::new(P::Precomputation::new(iter_interleaved));

        Ok(BulletproofGens {
            gens_capacity,
            party_capacity,
            g_vec,
            h_vec,
            precomp,
        })
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

impl<P> Debug for BulletproofGens<P>
where
    P: Compressable + Debug + Precomputable,
    P::Compressed: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RangeParameters")
            .field("gens_capacity", &self.gens_capacity)
            .field("party_capacity", &self.party_capacity)
            .field("g_vec", &self.g_vec)
            .field("h_vec", &self.h_vec)
            .finish()
    }
}
