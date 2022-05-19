//  Copyright 2022 The Tari Project
//  SPDX-License-Identifier: BSD-3-Clause

use curve25519_dalek::{scalar::Scalar, traits::IsIdentity};
use merlin::Transcript;

use crate::{
    errors::ProofError,
    protocols::transcript_protocol::TranscriptProtocol,
    range_statement::RangeStatement,
    traits::{Compressable, FixedBytesRepr},
};

// Helper function to construct the initial transcript
pub(crate) fn transcript_initialize<P>(
    transcript: &mut Transcript,
    h_base_compressed: &P::Compressed,
    g_base_compressed: &[P::Compressed],
    bit_length: usize,
    extension_degree: usize,
    aggregation_factor: usize,
    statement: &RangeStatement<P>,
) -> Result<(), ProofError>
where
    P: Compressable,
    P::Compressed: FixedBytesRepr + IsIdentity,
{
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
    Ok(())
}
// Helper function to construct the y and z challenge scalars after points A
pub(crate) fn transcript_point_a_challenges_y_z<P: FixedBytesRepr + IsIdentity>(
    transcript: &mut Transcript,
    a: &P,
) -> Result<(Scalar, Scalar), ProofError> {
    transcript.validate_and_append_point(b"A", a)?;
    Ok((transcript.challenge_scalar(b"y")?, transcript.challenge_scalar(b"z")?))
}

/// Helper function to construct the e challenge scalar after points L and R
pub(crate) fn transcript_points_l_r_challenge_e<P: FixedBytesRepr + IsIdentity>(
    transcript: &mut Transcript,
    l: &P,
    r: &P,
) -> Result<Scalar, ProofError> {
    transcript.validate_and_append_point(b"L", l)?;
    transcript.validate_and_append_point(b"R", r)?;
    transcript.challenge_scalar(b"e")
}

/// Helper function to construct the e challenge scalar after points A1 and B
pub(crate) fn transcript_points_a1_b_challenge_e<P: FixedBytesRepr + IsIdentity>(
    transcript: &mut Transcript,
    a1: &P,
    b: &P,
) -> Result<Scalar, ProofError> {
    transcript.validate_and_append_point(b"A1", a1)?;
    transcript.validate_and_append_point(b"B", b)?;
    transcript.challenge_scalar(b"e")
}
