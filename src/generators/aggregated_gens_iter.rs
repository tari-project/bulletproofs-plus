// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//   Modified from:
//     Copyright (c) 2018 Chain, Inc.
//     SPDX-License-Identifier: MIT

/// A convenience iterator struct for the generators
pub struct AggregatedGensIter<'a, P> {
    pub(super) array: &'a Vec<Vec<P>>,
    pub(super) n: usize,
    pub(super) m: usize,
    pub(super) party_idx: usize,
    pub(super) gen_idx: usize,
}

impl<'a, P> Iterator for AggregatedGensIter<'a, P> {
    type Item = &'a P;

    fn next(&mut self) -> Option<Self::Item> {
        if self.gen_idx >= self.n {
            self.gen_idx = 0;
            self.party_idx = self.party_idx.checked_add(1)?;
        }

        if self.party_idx >= self.m {
            None
        } else {
            let cur_gen = self.gen_idx;
            self.gen_idx = self.gen_idx.checked_add(1)?;
            self.array.get(self.party_idx)?.get(cur_gen)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self
            .n
            .saturating_mul(self.m.saturating_sub(self.party_idx))
            .saturating_sub(self.gen_idx);
        (size, Some(size))
    }
}
