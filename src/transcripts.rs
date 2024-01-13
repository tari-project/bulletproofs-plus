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

/// A wrapper around a Merlin transcript.
///
/// This does the usual Fiat-Shamir operations: initialize a transcript, add proof messages, and get challenges.
///
/// But it does more!
/// Following the design from [Merlin](https://merlin.cool/transcript/rng.html), it provides a random number generator.
/// It does this using the latest transcript state, (optional) secret data, and an external random number generator.
/// This helps to guard against failure of the external random number generator.
///
/// When the prover initializes the wrapper, it includes the witness as the secret data.
/// The verifier doesn't have any secret data to include, so it passes `None` instead.
/// In either case, you get a `RangeProofTranscript` and a `TranscriptRng`.
///
/// When the transcript is updated using the challenge functions, you must provide the `TranscriptRng`, which is also
/// updated.
///
/// When randomness is needed, just use the `TranscriptRng`.
/// The prover uses this whenever it needs a random nonce.
/// The batch verifier uses this to generate weights.
pub(crate) struct RangeProofTranscript<'a, P, R>
where
    P: Compressable + Precomputable,
    P::Compressed: FixedBytesRepr + IsIdentity,
    R: CryptoRngCore,
{
    transcript: Transcript,
    bytes: Option<Zeroizing<Vec<u8>>>,
    transcript_rng: TranscriptRng,
    external_rng: &'a mut R,
    _phantom: PhantomData<P>,
}

impl<'a, P, R> RangeProofTranscript<'a, P, R>
where
    P: Compressable + Precomputable,
    P::Compressed: FixedBytesRepr + IsIdentity,
    R: CryptoRngCore,
{
    /// Initialize a transcript.
    ///
    /// The prover should include its `witness` here; the verifier should pass `None`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        label: &'static str,
        h_base_compressed: &P::Compressed,
        g_base_compressed: &[P::Compressed],
        bit_length: usize,
        extension_degree: usize,
        aggregation_factor: usize,
        statement: &RangeStatement<P>,
        witness: Option<&RangeWitness>,
        external_rng: &'a mut R,
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

        // Serialize the witness if provided
        let bytes = if let Some(witness) = witness {
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

            Some(witness_bytes)
        } else {
            None
        };

        // Set up the RNG
        let rng = Self::build_rng(&transcript, bytes.as_ref(), external_rng);

        Ok(Self {
            transcript,
            bytes,
            transcript_rng: rng,
            external_rng,
            _phantom: PhantomData,
        })
    }

    // Construct the `y` and `z` challenges and update the RNG
    pub(crate) fn challenges_y_z(&mut self, a: &P::Compressed) -> Result<(Scalar, Scalar), ProofError> {
        // Update the transcript
        self.transcript.validate_and_append_point(b"A", a)?;

        // Update the RNG
        self.transcript_rng = Self::build_rng(&self.transcript, self.bytes.as_ref(), self.external_rng);

        // Return the challenges
        Ok((
            self.transcript.challenge_scalar(b"y")?,
            self.transcript.challenge_scalar(b"z")?,
        ))
    }

    /// Construct an inner-product round `e` challenge and update the RNG
    pub(crate) fn challenge_round_e(&mut self, l: &P::Compressed, r: &P::Compressed) -> Result<Scalar, ProofError> {
        // Update the transcript
        self.transcript.validate_and_append_point(b"L", l)?;
        self.transcript.validate_and_append_point(b"R", r)?;

        // Update the RNG
        self.transcript_rng = Self::build_rng(&self.transcript, self.bytes.as_ref(), self.external_rng);

        // Return the challenge
        self.transcript.challenge_scalar(b"e")
    }

    /// Construct the final `e` challenge and update the RNG
    pub(crate) fn challenge_final_e(&mut self, a1: &P::Compressed, b: &P::Compressed) -> Result<Scalar, ProofError> {
        // Update the transcript
        self.transcript.validate_and_append_point(b"A1", a1)?;
        self.transcript.validate_and_append_point(b"B", b)?;

        // Update the RNG
        self.transcript_rng = Self::build_rng(&self.transcript, self.bytes.as_ref(), self.external_rng);

        // Return the challenge
        self.transcript.challenge_scalar(b"e")
    }

    /// Construct a random number generator from the current transcript state
    ///
    /// Internally, this builds the RNG using a clone of the transcript state, the secret bytes (if provided), and the
    /// external RNG.
    fn build_rng(transcript: &Transcript, bytes: Option<&Zeroizing<Vec<u8>>>, external_rng: &mut R) -> TranscriptRng {
        if let Some(bytes) = bytes {
            transcript
                .build_rng()
                .rekey_with_witness_bytes("witness".as_bytes(), bytes)
                .finalize(external_rng)
        } else {
            transcript.build_rng().finalize(external_rng)
        }
    }

    /// Get a mutable reference to the transcript RNG.
    /// This is suitable for passing into functions that use it to generate random data.
    pub(crate) fn as_mut_rng(&mut self) -> &mut TranscriptRng {
        &mut self.transcript_rng
    }
}
