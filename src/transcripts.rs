//  Copyright 2022 The Tari Project
//  SPDX-License-Identifier: BSD-3-Clause

use core::mem::size_of;
use std::marker::PhantomData;

use curve25519_dalek::{scalar::Scalar, traits::IsIdentity};
use merlin::{Transcript, TranscriptRng};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::{
    errors::ProofError,
    protocols::transcript_protocol::TranscriptProtocol,
    range_statement::RangeStatement,
    range_witness::RangeWitness,
    traits::{Compressable, FixedBytesRepr, Precomputable},
};

/// A wrapper around a Merlin transcript
pub(crate) struct RangeProofTranscript<P>
where
    P: Compressable + Precomputable,
    P::Compressed: FixedBytesRepr + IsIdentity,
{
    transcript: Transcript,
    _phantom: PhantomData<P>,
}

impl<P> RangeProofTranscript<P>
where
    P: Compressable + Precomputable,
    P::Compressed: FixedBytesRepr + IsIdentity,
{
    // Initialize a transcript
    pub(crate) fn new(
        label: &'static str,
        h_base_compressed: &P::Compressed,
        g_base_compressed: &[P::Compressed],
        bit_length: usize,
        extension_degree: usize,
        aggregation_factor: usize,
        statement: &RangeStatement<P>,
    ) -> Result<Self, ProofError> {
        // Initialize the transcript with parameters and statement
        let mut transcript = Transcript::new(label.as_bytes());
        transcript.domain_separator(b"Bulletproofs+", b"Range Proof");
        transcript.validate_and_append_point(b"H", h_base_compressed)?;
        for item in g_base_compressed {
            transcript.validate_and_append_point(b"G", item)?;
        }
        transcript.append_u64(b"N", bit_length as u64);
        transcript.append_u64(b"T", extension_degree as u64);
        transcript.append_u64(b"M", aggregation_factor as u64);
        for item in &statement.commitments_compressed {
            transcript.append_point(b"Ci", item);
        }
        for item in &statement.minimum_value_promises {
            if let Some(minimum_value) = item {
                transcript.append_u64(b"vi - minimum_value", *minimum_value);
            } else {
                transcript.append_u64(b"vi - minimum_value", 0);
            }
        }

        Ok(Self {
            transcript,
            _phantom: PhantomData,
        })
    }

    // Construct the `y` and `z` challenges
    pub(crate) fn challenges_y_z(&mut self, a: &P::Compressed) -> Result<(Scalar, Scalar), ProofError> {
        self.transcript.validate_and_append_point(b"A", a)?;
        Ok((
            self.transcript.challenge_scalar(b"y")?,
            self.transcript.challenge_scalar(b"z")?,
        ))
    }

    /// Construct an inner-product round `e` challenge
    pub(crate) fn challenge_round_e(&mut self, l: &P::Compressed, r: &P::Compressed) -> Result<Scalar, ProofError> {
        self.transcript.validate_and_append_point(b"L", l)?;
        self.transcript.validate_and_append_point(b"R", r)?;
        self.transcript.challenge_scalar(b"e")
    }

    /// Construct the final `e` challenge
    pub(crate) fn challenge_final_e(&mut self, a1: &P::Compressed, b: &P::Compressed) -> Result<Scalar, ProofError> {
        self.transcript.validate_and_append_point(b"A1", a1)?;
        self.transcript.validate_and_append_point(b"B", b)?;
        self.transcript.challenge_scalar(b"e")
    }

    /// Construct a random number generator from the current transcript state
    pub(crate) fn build_rng<R: CryptoRngCore>(&self, witness: &RangeWitness, rng: &mut R) -> TranscriptRng {
        // Produce a (non-canonical) byte representation of the witness
        let size: usize = witness
            .openings
            .iter()
            .map(|o| size_of::<u64>() + o.r.len() * size_of::<Scalar>())
            .sum();
        let mut witness_bytes = Zeroizing::new(Vec::<u8>::with_capacity(size));
        for opening in &witness.openings {
            witness_bytes.extend(opening.v.to_le_bytes());
            for r in &opening.r {
                witness_bytes.extend(r.as_bytes());
            }
        }

        self.transcript
            .build_rng()
            .rekey_with_witness_bytes("witness".as_bytes(), &witness_bytes)
            .finalize(rng)
    }
}
