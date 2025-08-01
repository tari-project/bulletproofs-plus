// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ public range proof parameters intended for a verifier

#![allow(clippy::too_many_lines)]

use alloc::{string::ToString, vec, vec::Vec};
use core::{
    convert::{TryFrom, TryInto},
    iter::once,
    marker::PhantomData,
    ops::{Add, Mul, Shr},
    slice::ChunksExact,
};

use curve25519_dalek::{
    scalar::Scalar,
    traits::{Identity, IsIdentity, MultiscalarMul, VartimePrecomputedMultiscalarMul},
};
use ff::Field;
use itertools::{izip, Itertools};
use merlin::Transcript;
use rand_core::CryptoRngCore;
#[cfg(feature = "rand")]
use rand_core::OsRng;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::{
    errors::ProofError,
    extended_mask::ExtendedMask,
    generators::pedersen_gens::ExtensionDegree,
    protocols::{curve_point_protocol::CurvePointProtocol, scalar_protocol::ScalarProtocol},
    range_statement::RangeStatement,
    range_witness::RangeWitness,
    traits::{Compressable, Decompressable, FixedBytesRepr, Precomputable},
    transcripts::RangeProofTranscript,
    utils::{generic::nonce, nullrng::NullRng},
};

/// Optionally extract masks when verifying the proofs
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum VerifyAction {
    /// No masks will be recovered (e.g. as a public entity)
    VerifyOnly,
    /// Recover masks and verify the proofs (e.g. as the commitment owner)
    RecoverAndVerify,
    /// Only recover masks but do not verify the proofs (e.g. as the commitment owner)
    RecoverOnly,
}

/// Contains the public range proof parameters intended for a verifier
#[derive(Clone, Debug, PartialEq)]
pub struct RangeProof<P: Compressable> {
    a: P::Compressed,
    a1: P::Compressed,
    b: P::Compressed,
    r1: Scalar,
    s1: Scalar,
    d1: Vec<Scalar>,
    li: Vec<P::Compressed>,
    ri: Vec<P::Compressed>,
    extension_degree: ExtensionDegree,
}

/// The maximum bit length for which proofs can be generated
pub const MAX_RANGE_PROOF_BIT_LENGTH: usize = 64;

/// Maximum number of proofs in a batch
/// This is only for performance reasons, where a very large batch can see diminishing returns
/// There is no theoretical limit imposed by the algorithms!
const MAX_RANGE_PROOF_BATCH_SIZE: usize = 256;

/// The number of bytes in each serialized proof element
const SERIALIZED_ELEMENT_SIZE: usize = 32;

/// The number of proof elements fixed in all proofs: `a, a1, b, r1, s1`
const FIXED_PROOF_ELEMENTS: usize = 5;

/// Assorted serialization constants
const ENCODED_EXTENSION_SIZE: usize = 1;

/// # Example
/// ```
/// use curve25519_dalek::scalar::Scalar;
/// use merlin::Transcript;
/// #[cfg(feature = "rand")]
/// use rand_core::OsRng;
/// # fn main() {
/// #[cfg(feature = "rand")]
/// # {
/// use tari_bulletproofs_plus::{
///     commitment_opening::CommitmentOpening,
///     errors::ProofError,
///     extended_mask::ExtendedMask,
///     generators::pedersen_gens::ExtensionDegree,
///     protocols::scalar_protocol::ScalarProtocol,
///     range_parameters::RangeParameters,
///     range_proof::{RangeProof, VerifyAction},
///     range_statement::RangeStatement,
///     range_witness::RangeWitness,
///     ristretto,
///     ristretto::RistrettoRangeProof,
/// };
/// let mut rng = OsRng;
/// let transcript_label: &'static str = "BatchedRangeProofTest";
/// let bit_length = 64; // Other powers of two are permissible up to 2^6 = 64
///
/// // 0.  Batch data
/// let proof_batch = vec![1, 4]; // a batch with two proofs, one of which is aggregated
/// let mut private_masks: Vec<Option<ExtendedMask>> = vec![];
/// let mut public_masks = vec![];
/// let mut statements_private = vec![];
/// let mut statements_public = vec![];
/// let mut proofs = vec![];
/// let mut transcripts = vec![];
///
/// for aggregation_size in proof_batch {
///     // 1. Generators
///     let extension_degree = ExtensionDegree::DefaultPedersen;
///     let pc_gens = ristretto::create_pedersen_gens_with_extension_degree(extension_degree);
///     let generators = RangeParameters::init(bit_length, aggregation_size, pc_gens).unwrap();
///
///     // 2. Create witness data
///     let mut commitments = vec![];
///     let mut openings = vec![];
///     let mut minimum_values = vec![];
///     for m in 0..aggregation_size {
///         let value = 123000111222333 * m as u64; // Value in uT
///         let blindings = vec![Scalar::random_not_zero(&mut rng); extension_degree as usize];
///         if m == 2 {
///             // Minimum value proofs other than zero are can be built into the proof
///             minimum_values.push(Some(value / 3));
///         } else {
///             minimum_values.push(None);
///         }
///         commitments.push(
///             generators
///                 .pc_gens()
///                 .commit(&Scalar::from(value), blindings.as_slice())
///                 .unwrap(),
///         );
///         openings.push(CommitmentOpening::new(value, blindings.clone()));
///         if m == 0 {
///             if aggregation_size == 1 {
///                 // Masks (any secret scalar) can be embedded for proofs with aggregation size = 1
///                 private_masks.push(Some(ExtendedMask::assign(extension_degree, blindings).unwrap()));
///                 public_masks.push(None);
///             } else {
///                 private_masks.push(None);
///                 public_masks.push(None);
///             }
///         }
///     }
///     let mut witness = RangeWitness::init(openings).unwrap();
///
///     // 3. Generate the statement
///     let seed_nonce = if aggregation_size == 1 {
///         // A secret seed nonce will be needed to recover the secret scalar for proofs with aggregation size = 1
///         Some(Scalar::random_not_zero(&mut rng))
///     } else {
///         None
///     };
///     let private_statement = RangeStatement::init(
///         generators.clone(),
///         commitments.clone(),
///         minimum_values.clone(),
///         // Only the owner will know the secret seed_nonce
///         seed_nonce,
///     )
///     .unwrap();
///     statements_private.push(private_statement.clone());
///     let public_statement =
///         RangeStatement::init(generators.clone(), commitments, minimum_values.clone(), None).unwrap();
///     statements_public.push(public_statement.clone());
///     let mut transcript = Transcript::new(transcript_label.as_bytes());
///     transcripts.push(transcript.clone());
///
///     // 4. Create the proofs
///     let proof = RistrettoRangeProof::prove(&mut transcript, &private_statement.clone(), &witness);
///     proofs.push(proof.unwrap());
/// }
///
/// // 5. Verify the entire batch as the commitment owner, i.e. the prover self
/// let recovered_private_masks = RangeProof::verify_batch(
///     &mut transcripts.clone(),
///     &statements_private,
///     &proofs,
///     VerifyAction::RecoverAndVerify,
/// )
/// .unwrap();
/// assert_eq!(private_masks, recovered_private_masks);
///
/// // 6. Verify the entire batch as public entity
/// let recovered_public_masks =
///     RangeProof::verify_batch(&mut transcripts, &statements_public, &proofs, VerifyAction::VerifyOnly).unwrap();
/// assert_eq!(public_masks, recovered_public_masks);
///
/// # }
/// # }
/// ```

impl<P> RangeProof<P>
where
    for<'p> &'p P: Mul<Scalar, Output = P>,
    for<'p> &'p P: Add<Output = P>,
    P: CurvePointProtocol + Precomputable + MultiscalarMul<Point = P>,
    P::Compressed: FixedBytesRepr + IsIdentity + Identity,
{
    /// Helper function to return the proof's extension degree
    pub fn extension_degree(&self) -> ExtensionDegree {
        self.extension_degree
    }

    /// Create a single or aggregated range proof for a single party that knows all the secrets
    /// The prover must ensure that the commitments and witness opening data are consistent
    #[cfg(feature = "rand")]
    pub fn prove(
        transcript: &mut Transcript,
        statement: &RangeStatement<P>,
        witness: &RangeWitness,
    ) -> Result<Self, ProofError> {
        Self::prove_with_rng(transcript, statement, witness, &mut OsRng)
    }

    /// Create a single or aggregated range proof for a single party that knows all the secrets
    /// The prover must ensure that the commitments and witness opening data are consistent
    pub fn prove_with_rng<R: CryptoRngCore>(
        transcript: &mut Transcript,
        statement: &RangeStatement<P>,
        witness: &RangeWitness,
        rng: &mut R,
    ) -> Result<Self, ProofError> {
        // Useful lengths
        let bit_length = statement.generators.bit_length();
        let aggregation_factor = statement.commitments.len();
        let extension_degree = statement.generators.extension_degree() as usize;
        let full_length = bit_length
            .checked_mul(aggregation_factor)
            .ok_or(ProofError::SizeOverflow)?;

        // The witness openings must correspond to the number of statement commitments
        // This ensures a common aggregation factor
        if witness.openings.len() != statement.commitments.len() {
            return Err(ProofError::InvalidLength(
                "Witness openings and statement commitments do not match!".to_string(),
            ));
        }

        // The witness and statement extension degrees must match
        // This ensures we have the necessary corresponding generators
        if witness.extension_degree != statement.generators.extension_degree() {
            return Err(ProofError::InvalidLength(
                "Witness and statement extension degrees do not match!".to_string(),
            ));
        }

        // Each witness value must not overflow the bit length
        // This ensures bit decompositions are valid
        for opening in &witness.openings {
            // If the bit length is large enough, no `u64` value can overflow
            if bit_length < 64 && opening.v >> bit_length > 0 {
                return Err(ProofError::InvalidLength(
                    "Value exceeds bit vector capacity!".to_string(),
                ));
            }
        }

        // Each witness opening must be valid for the corresponding statement commitment
        // This ensures correctness of the proving relation for this instance
        for (opening, commitment) in witness.openings.iter().zip(statement.commitments.iter()) {
            if &statement
                .generators
                .pc_gens
                .commit(&Scalar::from(opening.v), &opening.r)? !=
                commitment
            {
                return Err(ProofError::InvalidArgument("Witness opening is invalid!".to_string()));
            }
        }

        // Start a new transcript and generate the transcript RNG
        let mut range_proof_transcript = RangeProofTranscript::<P, R>::new(
            transcript,
            &statement.generators.h_base().compress(),
            statement.generators.g_bases_compressed(),
            bit_length,
            extension_degree,
            aggregation_factor,
            statement,
            Some(witness),
            rng,
        )?;

        // Set bit arrays
        let mut a_li = Zeroizing::new(Vec::with_capacity(full_length));
        let mut a_ri = Zeroizing::new(Vec::with_capacity(full_length));
        for (minimum_value, value) in statement
            .minimum_value_promises
            .iter()
            .zip(witness.openings.iter().map(|o| &o.v))
        {
            // Offset by the minimum value if needed
            let offset_value = if let Some(minimum_value) = minimum_value {
                Zeroizing::new(value.checked_sub(*minimum_value).ok_or(ProofError::InvalidArgument(
                    "Minimum value is larger than value".to_string(),
                ))?)
            } else {
                Zeroizing::new(*value)
            };

            // Decompose into bits
            for i in 0..bit_length {
                let i_u32 = u32::try_from(i).map_err(|_| ProofError::SizeOverflow)?;
                a_li.push(Scalar::from(offset_value.shr(i_u32) & 1));
                a_ri.push(Scalar::from(offset_value.shr(i_u32) & 1) - Scalar::ONE);
            }
        }

        // Compute A by multi-scalar multiplication
        let mut alpha = Zeroizing::new(Vec::with_capacity(extension_degree));
        for k in 0..extension_degree {
            alpha.push(if let Some(seed_nonce) = statement.seed_nonce {
                nonce(&seed_nonce, "alpha", None, Some(k))?
            } else {
                // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
                Scalar::random_not_zero(range_proof_transcript.as_mut_rng())
            });
        }
        let a = statement.generators.precomp().vartime_mixed_multiscalar_mul(
            a_li.iter().interleave(a_ri.iter()),
            alpha.iter(),
            statement.generators.g_bases().iter(),
        );

        // Update transcript, get challenges, and update RNG
        let (y, z) = range_proof_transcript.challenges_y_z(&a.compress())?;

        let z_square = z * z;

        // Compute powers of the challenge
        let y_powers_len = full_length.checked_add(2).ok_or(ProofError::SizeOverflow)?;
        let mut y_powers = Vec::with_capacity(y_powers_len);
        let mut y_power = Scalar::ONE;
        for _ in 0..y_powers_len {
            y_powers.push(y_power);
            y_power *= y;
        }

        // Compute d efficiently
        let mut d = Vec::with_capacity(full_length);
        d.push(z_square);
        let two = Scalar::from(2u8);
        for _ in 1..bit_length {
            d.push(two * d.last().ok_or(ProofError::SizeOverflow)?);
        }
        for j in 1..aggregation_factor {
            for i in 0..bit_length {
                #[allow(clippy::arithmetic_side_effects)]
                d.push(d.get((j - 1) * bit_length + i).ok_or(ProofError::SizeOverflow)? * z_square);
            }
        }

        // Prepare for inner product
        for a_li in a_li.iter_mut() {
            *a_li -= z;
        }
        for (a_ri, d, y_power) in izip!(a_ri.iter_mut(), d.iter(), y_powers.iter().rev().skip(1)) {
            *a_ri += d * y_power + z;
        }
        let mut z_even_powers = Scalar::ONE;
        for opening in &witness.openings {
            z_even_powers *= z_square;
            for (r, alpha1_val) in opening.r.iter().zip(alpha.iter_mut()) {
                *alpha1_val += z_even_powers *
                    r *
                    y_powers
                        .get(full_length.checked_add(1).ok_or(ProofError::SizeOverflow)?)
                        .ok_or(ProofError::SizeOverflow)?;
            }
        }

        // Only take as much of the folding vectors as needed for the aggregation factor
        let mut gi_base: Vec<P> = statement.generators.gi_base_iter().take(full_length).cloned().collect();
        let mut hi_base: Vec<P> = statement.generators.hi_base_iter().take(full_length).cloned().collect();

        let g_base = statement.generators.g_bases();
        let h_base = statement.generators.h_base();

        let rounds = usize::try_from(full_length.ilog2()).map_err(|_| ProofError::SizeOverflow)?;
        let mut li = Vec::<P>::with_capacity(rounds);
        let mut ri = Vec::<P>::with_capacity(rounds);

        let mut n = full_length;
        let mut round = 0;

        // Perform the inner-product folding rounds
        while n > 1 {
            n /= 2;

            // Split the vectors for folding
            let (a_lo, a_hi) = a_li
                .split_at_checked(n)
                .ok_or(ProofError::InvalidLength("Invalid vector split index".to_string()))?;
            let (b_lo, b_hi) = a_ri
                .split_at_checked(n)
                .ok_or(ProofError::InvalidLength("Invalid vector split index".to_string()))?;
            let (gi_base_lo, gi_base_hi) = gi_base
                .split_at_checked(n)
                .ok_or(ProofError::InvalidLength("Invalid vector split index".to_string()))?;
            let (hi_base_lo, hi_base_hi) = hi_base
                .split_at_checked(n)
                .ok_or(ProofError::InvalidLength("Invalid vector split index".to_string()))?;

            let y_n_inverse = if y_powers[n] == Scalar::ZERO {
                return Err(ProofError::InvalidArgument(
                    "Cannot invert a zero valued Scalar".to_string(),
                ));
            } else {
                y_powers[n].invert()
            };

            let a_lo_offset = a_lo.iter().map(|s| s * y_n_inverse).collect::<Vec<Scalar>>();
            let a_hi_offset = a_hi.iter().map(|s| s * y_powers[n]).collect::<Vec<Scalar>>();

            let d_l = if let Some(seed_nonce) = statement.seed_nonce {
                Zeroizing::new(
                    (0..extension_degree)
                        .map(|k| nonce(&seed_nonce, "dL", Some(round), Some(k)))
                        .collect::<Result<Vec<_>, ProofError>>()?,
                )
            } else {
                // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
                Zeroizing::new(
                    (0..extension_degree)
                        .map(|_| Scalar::random_not_zero(range_proof_transcript.as_mut_rng()))
                        .collect(),
                )
            };
            let d_r = if let Some(seed_nonce) = statement.seed_nonce {
                Zeroizing::new(
                    (0..extension_degree)
                        .map(|k| nonce(&seed_nonce, "dR", Some(round), Some(k)))
                        .collect::<Result<Vec<_>, ProofError>>()?,
                )
            } else {
                // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
                Zeroizing::new(
                    (0..extension_degree)
                        .map(|_| Scalar::random_not_zero(range_proof_transcript.as_mut_rng()))
                        .collect(),
                )
            };

            round = round.checked_add(1).ok_or(ProofError::SizeOverflow)?;

            let c_l = Zeroizing::new(
                izip!(a_lo, y_powers.iter().skip(1), b_hi)
                    .fold(Scalar::ZERO, |acc, (a, y_power, b)| acc + a * y_power * b),
            );
            let c_r = Zeroizing::new(
                izip!(
                    a_hi,
                    y_powers.iter().skip(n.checked_add(1).ok_or(ProofError::SizeOverflow)?),
                    b_lo
                )
                .fold(Scalar::ZERO, |acc, (a, y_power, b)| acc + a * y_power * b),
            );

            // Compute L and R by multi-scalar multiplication
            li.push(P::vartime_multiscalar_mul(
                once::<&Scalar>(&c_l)
                    .chain(d_l.iter())
                    .chain(a_lo_offset.iter())
                    .chain(b_hi.iter()),
                once(h_base).chain(g_base.iter()).chain(gi_base_hi).chain(hi_base_lo),
            ));
            ri.push(P::vartime_multiscalar_mul(
                once::<&Scalar>(&c_r)
                    .chain(d_r.iter())
                    .chain(a_hi_offset.iter())
                    .chain(b_lo.iter()),
                once(h_base).chain(g_base.iter()).chain(gi_base_lo).chain(hi_base_hi),
            ));

            // Update transcript, get challenge, and update RNG
            let e = range_proof_transcript.challenge_round_e(
                &li.last()
                    .ok_or(ProofError::InvalidLength("Bad inner product vector length".to_string()))?
                    .compress(),
                &ri.last()
                    .ok_or(ProofError::InvalidLength("Bad inner product vector length".to_string()))?
                    .compress(),
            )?;
            let e_square = e * e;
            let e_inverse = e.invert();
            let e_inverse_square = e_inverse * e_inverse;

            // Fold the vectors
            let e_y_n_inverse = e * y_n_inverse;
            gi_base = gi_base_lo
                .iter()
                .zip(gi_base_hi.iter())
                .map(|(lo, hi)| P::vartime_multiscalar_mul([&e_inverse, &e_y_n_inverse], [lo, hi]))
                .collect();
            hi_base = hi_base_lo
                .iter()
                .zip(hi_base_hi.iter())
                .map(|(lo, hi)| P::vartime_multiscalar_mul([&e, &e_inverse], [lo, hi]))
                .collect();
            a_li = Zeroizing::new(
                a_lo.iter()
                    .zip(a_hi_offset.iter())
                    .map(|(lo, hi)| lo * e + hi * e_inverse)
                    .collect(),
            );
            a_ri = Zeroizing::new(
                b_lo.iter()
                    .zip(b_hi.iter())
                    .map(|(lo, hi)| lo * e_inverse + hi * e)
                    .collect(),
            );

            for (alpha, (l, r)) in alpha.iter_mut().zip(d_l.iter().zip(d_r.iter())) {
                *alpha += l * e_square + r * e_inverse_square;
            }
        }

        // Random masks
        // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
        let r = Zeroizing::new(Scalar::random_not_zero(range_proof_transcript.as_mut_rng()));
        let s = Zeroizing::new(Scalar::random_not_zero(range_proof_transcript.as_mut_rng()));
        let d = if let Some(seed_nonce) = statement.seed_nonce {
            Zeroizing::new(
                (0..extension_degree)
                    .map(|k| nonce(&seed_nonce, "d", None, Some(k)))
                    .collect::<Result<Vec<_>, ProofError>>()?,
            )
        } else {
            // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
            Zeroizing::new(
                (0..extension_degree)
                    .map(|_| Scalar::random_not_zero(range_proof_transcript.as_mut_rng()))
                    .collect(),
            )
        };
        let eta = if let Some(seed_nonce) = statement.seed_nonce {
            Zeroizing::new(
                (0..extension_degree)
                    .map(|k| nonce(&seed_nonce, "eta", None, Some(k)))
                    .collect::<Result<Vec<_>, ProofError>>()?,
            )
        } else {
            // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
            Zeroizing::new(
                (0..extension_degree)
                    .map(|_| Scalar::random_not_zero(range_proof_transcript.as_mut_rng()))
                    .collect(),
            )
        };

        #[allow(clippy::arithmetic_side_effects)]
        let mut a1 =
            &gi_base[0] * *r + &hi_base[0] * *s + h_base * (*r * y_powers[1] * a_ri[0] + *s * y_powers[1] * a_li[0]);
        let mut b = h_base * (*r * y_powers[1] * *s);
        #[allow(clippy::arithmetic_side_effects)]
        for (g_base, &d) in g_base.iter().zip(d.iter()) {
            a1 += g_base * d;
        }
        #[allow(clippy::arithmetic_side_effects)]
        for (g_base, &eta) in g_base.iter().zip(eta.iter()) {
            b += g_base * eta;
        }

        // Update transcript, get challenge, and update RNG
        let e = range_proof_transcript.challenge_final_e(&a1.compress(), &b.compress())?;
        let e_square = e * e;

        let r1 = *r + a_li[0] * e;
        let s1 = *s + a_ri[0] * e;
        let d1: Vec<Scalar> = izip!(eta.iter(), d.iter(), alpha.iter())
            .map(|(eta, d, alpha)| eta + d * e + alpha * e_square)
            .collect();

        // Assemble the proof
        Ok(RangeProof {
            a: a.compress(),
            a1: a1.compress(),
            b: b.compress(),
            r1,
            s1,
            d1,
            li: li.iter().map(|p| p.compress()).collect(),
            ri: ri.iter().map(|p| p.compress()).collect(),
            extension_degree: statement.generators.extension_degree(),
        })
    }

    fn verify_statements_and_generators_consistency(
        statements: &[RangeStatement<P>],
        range_proofs: &[RangeProof<P>],
    ) -> Result<(usize, usize), ProofError> {
        let first_statement = statements
            .first()
            .ok_or(ProofError::InvalidArgument("Empty proof statements".to_string()))?;
        let first_proof = range_proofs
            .first()
            .ok_or(ProofError::InvalidArgument("Empty proofs".to_string()))?;
        if statements.len() != range_proofs.len() {
            return Err(ProofError::InvalidArgument(
                "Range statements and proofs length mismatch".to_string(),
            ));
        }

        let g_base_vec = first_statement.generators.g_bases();
        let h_base = first_statement.generators.h_base();
        let bit_length = first_statement.generators.bit_length();
        let mut max_mn = first_statement
            .commitments
            .len()
            .checked_mul(first_statement.generators.bit_length())
            .ok_or(ProofError::SizeOverflow)?;
        let mut max_index = 0;
        let extension_degree = first_statement.generators.extension_degree();

        if extension_degree != ExtensionDegree::try_from(first_proof.d1.len())? {
            return Err(ProofError::InvalidArgument("Inconsistent extension degree".to_string()));
        }
        for (i, (statement, proof)) in statements.iter().zip(range_proofs.iter()).enumerate().skip(1) {
            if g_base_vec != statement.generators.g_bases() {
                return Err(ProofError::InvalidArgument(
                    "Inconsistent G generator point in batch statement".to_string(),
                ));
            }
            if h_base != statement.generators.h_base() {
                return Err(ProofError::InvalidArgument(
                    "Inconsistent H generator point in batch statement".to_string(),
                ));
            }
            if bit_length != statement.generators.bit_length() {
                return Err(ProofError::InvalidArgument(
                    "Inconsistent bit length in batch statement".to_string(),
                ));
            }
            if extension_degree != statement.generators.extension_degree() ||
                extension_degree != ExtensionDegree::try_from(proof.d1.len())?
            {
                return Err(ProofError::InvalidArgument("Inconsistent extension degree".to_string()));
            }
            let full_length = statement
                .commitments
                .len()
                .checked_mul(statement.generators.bit_length())
                .ok_or(ProofError::SizeOverflow)?;
            if full_length > max_mn {
                max_mn = full_length;
                max_index = i;
            }
        }
        let max_statement = statements
            .get(max_index)
            .ok_or(ProofError::InvalidArgument("Out of bounds statement index".to_string()))?;
        for (i, statement) in statements.iter().enumerate() {
            for value in Iterator::flatten(statement.minimum_value_promises.iter()) {
                // If the bit length is 64, no 64-bit value can exceed the capacity
                if bit_length < 64 && value >> bit_length > 0 {
                    return Err(ProofError::InvalidLength(
                        "Minimum value promise exceeds bit vector capacity".to_string(),
                    ));
                }
            }
            if i == max_index {
                continue;
            }
            if statement
                .generators
                .gi_base_iter()
                .zip(max_statement.generators.gi_base_iter())
                .any(|(a, b)| a != b)
            {
                return Err(ProofError::InvalidArgument(
                    "Inconsistent Gi generator point vector in batch statement".to_string(),
                ));
            }
            if statement
                .generators
                .hi_base_iter()
                .zip(max_statement.generators.hi_base_iter())
                .any(|(a, b)| a != b)
            {
                return Err(ProofError::InvalidArgument(
                    "Inconsistent Hi generator point vector in batch statement".to_string(),
                ));
            }
        }

        Ok((max_mn, max_index))
    }

    /// Wrapper function for batch verification in different modes: mask recovery, verification, or both
    pub fn verify_batch(
        transcripts: &mut [Transcript],
        statements: &[RangeStatement<P>],
        proofs: &[RangeProof<P>],
        action: VerifyAction,
    ) -> Result<Vec<Option<ExtendedMask>>, ProofError> {
        // By definition, an empty batch fails
        if statements.is_empty() || proofs.is_empty() || transcripts.is_empty() {
            return Err(ProofError::InvalidArgument(
                "Range statements or proofs length empty".to_string(),
            ));
        }
        // We need to check for size consistency here, even though it's also done later
        if statements.len() != proofs.len() {
            return Err(ProofError::InvalidArgument(
                "Range statements and proofs length mismatch".to_string(),
            ));
        }
        if transcripts.len() != statements.len() {
            return Err(ProofError::InvalidArgument(
                "Range statements and transcripts length mismatch".to_string(),
            ));
        }

        // Store masks from all results
        let mut masks = Vec::<Option<ExtendedMask>>::with_capacity(proofs.len());

        // Get chunks of both the statements and proofs
        let mut chunks = statements
            .chunks(MAX_RANGE_PROOF_BATCH_SIZE)
            .zip(proofs.chunks(MAX_RANGE_PROOF_BATCH_SIZE));

        // If the batch fails, propagate the error; otherwise, store the masks and keep going
        if let Some((batch_statements, batch_proofs)) = chunks.next() {
            let mut result = RangeProof::verify(transcripts, batch_statements, batch_proofs, action)?;

            masks.append(&mut result);
        }

        Ok(masks)
    }

    // Verify a batch of single and/or aggregated range proofs as a public entity, or recover the masks for single
    // range proofs by a party that can supply the optional seed nonces
    fn verify(
        transcripts: &mut [Transcript],
        statements: &[RangeStatement<P>],
        range_proofs: &[RangeProof<P>],
        extract_masks: VerifyAction,
    ) -> Result<Vec<Option<ExtendedMask>>, ProofError> {
        // Verify generators consistency & select largest aggregation factor
        let (max_mn, max_index) = RangeProof::verify_statements_and_generators_consistency(statements, range_proofs)?;
        let first_statement = statements
            .first()
            .ok_or(ProofError::InvalidArgument("Empty proof statements".to_string()))?;
        let max_statement = statements
            .get(max_index)
            .ok_or(ProofError::InvalidArgument("Out of bounds statement index".to_string()))?;

        // Set up useful values
        let g_base_vec = first_statement.generators.g_bases();
        let h_base = first_statement.generators.h_base();
        let bit_length = first_statement.generators.bit_length();
        let extension_degree = first_statement.generators.extension_degree() as usize;
        let g_bases_compressed = first_statement.generators.g_bases_compressed();
        let h_base_compressed = first_statement.generators.h_base_compressed();
        let precomp = max_statement.generators.precomp();

        // Compute 2**n-1 for later use
        let two = Scalar::from(2u8);
        let two_n_minus_one = two.pow_vartime([bit_length as u64]) - Scalar::ONE;

        // Weighted coefficients for common generators
        let mut g_base_scalars = vec![Scalar::ZERO; extension_degree];
        let mut h_base_scalar = Scalar::ZERO;
        let mut gi_base_scalars = vec![Scalar::ZERO; max_mn];
        let mut hi_base_scalars = vec![Scalar::ZERO; max_mn];

        // Final multiscalar multiplication data
        // Because we use precomputation on the generator vectors, we need to separate the static data from the dynamic
        // data. However, we can't combine precomputation data, so the Pedersen generators go with the dynamic
        // data :(
        let mut msm_dynamic_len = extension_degree.checked_add(1).ok_or(ProofError::SizeOverflow)?;
        for (statement, proof) in statements.iter().zip(range_proofs.iter()) {
            msm_dynamic_len = msm_dynamic_len
                .checked_add(statement.commitments.len())
                .ok_or(ProofError::SizeOverflow)?;
            msm_dynamic_len = msm_dynamic_len.checked_add(3).ok_or(ProofError::SizeOverflow)?;
            msm_dynamic_len = msm_dynamic_len
                .checked_add(proof.li.len().checked_mul(2).ok_or(ProofError::SizeOverflow)?)
                .ok_or(ProofError::SizeOverflow)?;
        }
        let mut dynamic_scalars: Vec<Scalar> = Vec::with_capacity(msm_dynamic_len);
        let mut dynamic_points: Vec<P> = Vec::with_capacity(msm_dynamic_len);

        // Recovered masks
        let mut masks = Vec::with_capacity(range_proofs.len());

        // Set up the weight transcript
        let mut weight_transcript = Transcript::new(b"Bulletproofs+ verifier weights");

        // Generate challenges from all proofs in the batch, using the final transcript RNG of each to obtain a new
        // weight
        let mut batch_challenges = Vec::with_capacity(range_proofs.len());
        for (proof, statement, transcript) in izip!(range_proofs, statements, transcripts) {
            let mut null_rng = NullRng;

            // Start the transcript, using `NullRng` since we don't need or want actual randomness there
            let mut transcript = RangeProofTranscript::new(
                transcript,
                &h_base_compressed,
                g_bases_compressed,
                bit_length,
                extension_degree,
                statement.commitments.len(),
                statement,
                None,
                &mut null_rng,
            )?;

            // Get the challenges and include them in the batch vectors
            let (y, z) = transcript.challenges_y_z(&proof.a)?;
            let round_e = proof
                .li
                .iter()
                .zip(proof.ri.iter())
                .map(|(l, r)| transcript.challenge_round_e(l, r))
                .collect::<Result<Vec<Scalar>, ProofError>>()?;
            let e = transcript.challenge_final_e(&proof.a1, &proof.b)?;

            batch_challenges.push((y, z, round_e, e));

            // Use the transcript RNG to bind this proof to the weight transcript
            let mut transcript_rng = transcript.to_verifier_rng(&proof.r1, &proof.s1, &proof.d1);
            let mut bytes = vec![0u8; 32];
            let transcript_rng = transcript_rng.as_rngcore();
            transcript_rng.fill_bytes(&mut bytes);
            weight_transcript.append_message(b"proof", &bytes);
        }

        // Finalize the weight transcript so it can be used for pseudorandom weights
        let mut weight_transcript_rng = weight_transcript.build_rng().finalize(&mut NullRng);

        // Process each proof and add it to the batch
        for (proof, statement, batch_challenge) in izip!(range_proofs, statements, batch_challenges) {
            let commitments = statement.commitments.clone();
            let minimum_value_promises = statement.minimum_value_promises.clone();
            let a = proof.a_decompressed()?;
            let a1 = proof.a1_decompressed()?;
            let b = proof.b_decompressed()?;
            let r1 = proof.r1;
            let s1 = proof.s1;
            let d1 = proof.d1.clone();
            let li = proof.li_decompressed()?;
            let ri = proof.ri_decompressed()?;

            // Useful lengths
            let aggregation_factor = commitments.len();
            let full_length = aggregation_factor
                .checked_mul(bit_length)
                .ok_or(ProofError::SizeOverflow)?;
            let rounds = li.len();

            if li.len() != ri.len() {
                return Err(ProofError::InvalidLength(
                    "Vector L length not equal to vector R length".to_string(),
                ));
            }

            // Check for an overflow from the number of rounds
            let rounds_u32 = u32::try_from(rounds).map_err(|_| ProofError::SizeOverflow)?;
            if rounds_u32.leading_zeros() == 0 {
                return Err(ProofError::SizeOverflow);
            }
            if 1usize.checked_shl(rounds_u32).ok_or(ProofError::SizeOverflow)? != full_length {
                return Err(ProofError::InvalidLength("Vector L/R length not adequate".to_string()));
            }

            // Parse out the challenges
            let (y, z, challenges, e) = batch_challenge;

            // Nonzero batch weight
            let weight = Scalar::random_not_zero(&mut weight_transcript_rng);

            // Compute challenge inverses in a batch
            let mut challenges_inv = challenges.clone();
            challenges_inv.extend_from_slice(&[y, y - Scalar::ONE]);
            let challenges_inv_prod = Scalar::batch_invert(&mut challenges_inv) * y * (y - Scalar::ONE);
            let y_1_inverse = challenges_inv
                .pop()
                .ok_or(ProofError::VerificationFailed("Unexpected vector error".to_string()))?;
            let y_inverse = challenges_inv
                .pop()
                .ok_or(ProofError::VerificationFailed("Unexpected vector error".to_string()))?;

            // Compute useful challenge values
            let z_square = z * z;
            let e_square = e * e;
            let challenges_sq: Vec<Scalar> = challenges.iter().map(|c| c * c).collect();
            let challenges_sq_inv: Vec<Scalar> = challenges_inv.iter().map(|c| c * c).collect();
            let y_nm = y.pow_vartime([full_length as u64]);
            let y_nm_1 = y_nm * y;

            // Compute the sum of powers of the challenge as a partial sum of a geometric series
            let y_sum = y * (y_nm - Scalar::ONE) * y_1_inverse;

            // Compute d efficiently
            let mut d = Vec::with_capacity(full_length);
            d.push(z_square);
            for _ in 1..bit_length {
                d.push(two * d.last().ok_or(ProofError::SizeOverflow)?);
            }
            #[allow(clippy::arithmetic_side_effects)]
            for j in 1..aggregation_factor {
                for i in 0..bit_length {
                    d.push(d.get((j - 1) * bit_length + i).ok_or(ProofError::SizeOverflow)? * z_square);
                }
            }

            // Compute d's sum efficiently
            let mut d_sum = z_square;
            let mut d_sum_temp_z = z_square;
            for _ in 0..aggregation_factor.ilog2() {
                d_sum = d_sum + d_sum * d_sum_temp_z;
                d_sum_temp_z = d_sum_temp_z * d_sum_temp_z;
            }
            d_sum *= two_n_minus_one;

            // Recover the mask if possible (only for non-aggregated proofs)
            match extract_masks {
                VerifyAction::VerifyOnly => masks.push(None),
                _ => {
                    if let Some(seed_nonce) = statement.seed_nonce {
                        let mut temp_masks = Vec::with_capacity(extension_degree);
                        for (k, d1_val) in d1.iter().enumerate().take(extension_degree) {
                            let mut this_mask = (*d1_val -
                                nonce(&seed_nonce, "eta", None, Some(k))? -
                                e * nonce(&seed_nonce, "d", None, Some(k))?) *
                                e_square.invert();
                            this_mask -= nonce(&seed_nonce, "alpha", None, Some(k))?;
                            for (j, (challenge_sq, challenge_sq_inv)) in
                                challenges_sq.iter().zip(challenges_sq_inv.iter()).enumerate()
                            {
                                this_mask -= challenge_sq * nonce(&seed_nonce, "dL", Some(j), Some(k))?;
                                this_mask -= challenge_sq_inv * nonce(&seed_nonce, "dR", Some(j), Some(k))?;
                            }
                            this_mask *= (z_square * y_nm_1).invert();
                            temp_masks.push(this_mask);
                        }
                        masks.push(Some(ExtendedMask::assign(extension_degree.try_into()?, temp_masks)?));
                    } else {
                        masks.push(None);
                    }
                    if extract_masks == VerifyAction::RecoverOnly {
                        continue;
                    }
                },
            }

            // Aggregate the generator scalars
            let mut y_inv_i = Scalar::ONE;
            let mut y_nm_i = y_nm;

            let mut s = Vec::with_capacity(full_length);
            s.push(challenges_inv_prod);
            for i in 1..full_length {
                let log_i = usize::try_from(i.checked_ilog2().ok_or(ProofError::SizeOverflow)?)
                    .map_err(|_| ProofError::SizeOverflow)?;
                let j = 1 << log_i;
                #[allow(clippy::arithmetic_side_effects)]
                s.push(
                    s.get(i - j).ok_or(ProofError::SizeOverflow)? *
                        challenges_sq.get(rounds - log_i - 1).ok_or(ProofError::SizeOverflow)?,
                );
            }
            let r1_e = r1 * e;
            let s1_e = s1 * e;
            let e_square_z = e_square * z;
            for (s, s_rev, gi_base_scalar, hi_base_scalar, d) in izip!(
                s.iter(),
                s.iter().rev(),
                gi_base_scalars.iter_mut(),
                hi_base_scalars.iter_mut(),
                d.iter()
            ) {
                let g = r1_e * y_inv_i * s;
                let h = s1_e * s_rev;
                *gi_base_scalar += weight * (g + e_square_z);
                *hi_base_scalar += weight * (h - e_square * (d * y_nm_i + z));
                y_inv_i *= y_inverse;
                y_nm_i *= y_inverse;
            }

            // Remaining terms
            let mut z_even_powers = Scalar::ONE;
            for minimum_value_promise in minimum_value_promises {
                z_even_powers *= z_square;
                let weighted = weight * (-e_square * z_even_powers * y_nm_1);
                dynamic_scalars.push(weighted);
                if let Some(minimum_value) = minimum_value_promise {
                    h_base_scalar -= weighted * Scalar::from(minimum_value);
                }
            }
            dynamic_points.extend(commitments);

            h_base_scalar += weight * (r1 * y * s1 + e_square * (y_nm_1 * z * d_sum + (z_square - z) * y_sum));
            for (g_base_scalar, d1) in g_base_scalars.iter_mut().zip(d1.iter()) {
                *g_base_scalar += weight * d1;
            }

            dynamic_scalars.push(weight * (-e));
            dynamic_points.push(a1);
            dynamic_scalars.push(-weight);
            dynamic_points.push(b);
            dynamic_scalars.push(weight * (-e_square));
            dynamic_points.push(a);

            dynamic_scalars.extend(challenges_sq.into_iter().map(|c| weight * -e_square * c));
            dynamic_points.extend(li);
            dynamic_scalars.extend(challenges_sq_inv.into_iter().map(|c| weight * -e_square * c));
            dynamic_points.extend(ri);
        }
        if extract_masks == VerifyAction::RecoverOnly {
            return Ok(masks);
        }

        // Pedersen generators
        dynamic_scalars.extend_from_slice(&g_base_scalars);
        dynamic_points.extend_from_slice(g_base_vec);
        dynamic_scalars.push(h_base_scalar);
        dynamic_points.push(h_base.clone());

        // Perform the final check using precomputation
        if precomp.vartime_mixed_multiscalar_mul(
            gi_base_scalars.iter().interleave(hi_base_scalars.iter()),
            dynamic_scalars.iter(),
            dynamic_points.iter(),
        ) != P::identity()
        {
            return Err(ProofError::VerificationFailed(
                "Range proof batch not valid".to_string(),
            ));
        }

        Ok(masks)
    }

    fn a_decompressed(&self) -> Result<P, ProofError> {
        self.a.decompress().ok_or_else(|| {
            ProofError::InvalidArgument("Member 'a' was not the canonical encoding of a point".to_string())
        })
    }

    // Helper function to decompress A1
    fn a1_decompressed(&self) -> Result<P, ProofError> {
        self.a1.decompress().ok_or_else(|| {
            ProofError::InvalidArgument("Member 'a1' was not the canonical encoding of a point".to_string())
        })
    }

    // Helper function to decompress B
    fn b_decompressed(&self) -> Result<P, ProofError> {
        self.b.decompress().ok_or_else(|| {
            ProofError::InvalidArgument("Member 'b' was not the canonical encoding of a point".to_string())
        })
    }

    // Helper function to decompress Li
    fn li_decompressed(&self) -> Result<Vec<P>, ProofError> {
        self.li
            .iter()
            .map(|p| {
                p.decompress().ok_or(ProofError::InvalidArgument(
                    "An item in member 'L' was not the canonical encoding of a point".to_string(),
                ))
            })
            .collect()
    }

    // Helper function to decompress Ri
    fn ri_decompressed(&self) -> Result<Vec<P>, ProofError> {
        self.ri
            .iter()
            .map(|p| {
                p.decompress().ok_or(ProofError::InvalidArgument(
                    "An item in member 'L' was not the canonical encoding of a point".to_string(),
                ))
            })
            .collect()
    }
}

impl<P> RangeProof<P>
where
    P: Compressable,
    P::Compressed: FixedBytesRepr,
{
    /// Serializes the proof into a canonical byte array
    /// The first byte is an encoding of the extension degree, which tells us the length of `d1`
    /// Then we serialize the rest of the proof elements as canonical byte encodings
    pub fn to_bytes(&self) -> Vec<u8> {
        // The total proof size: extension degree encoding, fixed elements, vectors
        #[allow(clippy::arithmetic_side_effects)]
        let mut buf = Vec::with_capacity(
            ENCODED_EXTENSION_SIZE +
                (self.li.len() + self.ri.len() + FIXED_PROOF_ELEMENTS + self.d1.len()) * SERIALIZED_ELEMENT_SIZE,
        );

        // Encode the extension degree as a single byte
        buf.extend_from_slice(&(self.extension_degree as u8).to_le_bytes());

        // Encode `d1`, whose size is set by the extension degree
        for d1 in &self.d1 {
            buf.extend_from_slice(d1.as_bytes());
        }

        // Encode the fixed proof elements
        buf.extend_from_slice(self.a.as_fixed_bytes());
        buf.extend_from_slice(self.a1.as_fixed_bytes());
        buf.extend_from_slice(self.b.as_fixed_bytes());
        buf.extend_from_slice(self.r1.as_bytes());
        buf.extend_from_slice(self.s1.as_bytes());

        // Encode the remaining vectors, interleaved for easier deserialization
        for (l, r) in self.li.iter().zip(self.ri.iter()) {
            buf.extend_from_slice(l.as_fixed_bytes());
            buf.extend_from_slice(r.as_fixed_bytes());
        }

        buf
    }

    /// Deserializes the proof from a canonical byte slice
    /// First we parse the extension degree, validate it, and use it to parse `d1`
    /// Then we parse the remainder of the proof elements, inferring the lengths of `li` and `ri`
    pub fn from_bytes(slice: &[u8]) -> Result<Self, ProofError> {
        // Helper to parse a scalar from a chunk iterator
        let parse_scalar = |chunks: &mut ChunksExact<'_, u8>| -> Result<Scalar, ProofError> {
            chunks
                .next()
                .ok_or(ProofError::InvalidLength("Serialized proof is too short".to_string()))
                .and_then(|slice| {
                    let bytes: [u8; SERIALIZED_ELEMENT_SIZE] = slice
                        .try_into()
                        .map_err(|_| ProofError::InvalidLength("Unexpected deserialization failure".to_string()))?;
                    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
                        .ok_or(ProofError::InvalidArgument("Invalid parsing".to_string()))
                })
        };

        // Helper to parse a compressed point from a chunk iterator
        let parse_point = |chunks: &mut ChunksExact<'_, u8>| -> Result<<P as Compressable>::Compressed, ProofError> {
            chunks
                .next()
                .ok_or(ProofError::InvalidLength("Serialized proof is too short".to_string()))
                .and_then(|slice| {
                    let bytes: [u8; SERIALIZED_ELEMENT_SIZE] = slice
                        .try_into()
                        .map_err(|_| ProofError::InvalidLength("Unexpected deserialization failure".to_string()))?;
                    Ok(<P as Compressable>::Compressed::from_fixed_bytes(bytes))
                })
        };

        // Get the extension degree, which is encoded as a single byte
        let extension_degree = ExtensionDegree::try_from(
            *(slice
                .first()
                .ok_or_else(|| ProofError::InvalidLength("Serialized proof is too short".to_string()))?),
        )?;

        // The rest of the serialization is of encoded proof elements
        let mut chunks = slice
            .get(ENCODED_EXTENSION_SIZE..)
            .ok_or(ProofError::InvalidLength("Serialized proof is too short".to_string()))?
            .chunks_exact(SERIALIZED_ELEMENT_SIZE);

        // Extract `d1`, whose length is determined by the extension degree
        let d1 = (0..extension_degree as usize)
            .map(|_| parse_scalar(&mut chunks))
            .collect::<Result<Vec<Scalar>, ProofError>>()?;

        // Extract the fixed proof elements
        let a = parse_point(&mut chunks)?;
        let a1 = parse_point(&mut chunks)?;
        let b = parse_point(&mut chunks)?;
        let r1 = parse_scalar(&mut chunks)?;
        let s1 = parse_scalar(&mut chunks)?;

        // Extract the inner-product folding vectors `li` and `ri`
        let mut tuples = chunks.by_ref().tuples::<(&[u8], &[u8])>();
        let (li, ri): (
            Vec<<P as Compressable>::Compressed>,
            Vec<<P as Compressable>::Compressed>,
        ) = tuples
            .by_ref()
            .map(|(l, r)| {
                let bytes_l: [u8; SERIALIZED_ELEMENT_SIZE] = l
                    .try_into()
                    .map_err(|_| ProofError::InvalidLength("Unexpected deserialization failure".to_string()))?;
                let bytes_r: [u8; SERIALIZED_ELEMENT_SIZE] = r
                    .try_into()
                    .map_err(|_| ProofError::InvalidLength("Unexpected deserialization failure".to_string()))?;
                Ok((
                    <P as Compressable>::Compressed::from_fixed_bytes(bytes_l),
                    <P as Compressable>::Compressed::from_fixed_bytes(bytes_r),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .unzip();

        // The inner-product folding vectors should not be empty
        if li.is_empty() || ri.is_empty() {
            return Err(ProofError::InvalidLength("Serialized proof is too short".to_string()));
        }

        // We want to ensure that no data remains unused, to ensure serialization is canonical
        // To do so, we check two things:
        // - the tuple iterator has no leftover data, meaning an extra proof element
        // - the chunk iterator has no leftover data, meaning extra bytes that don't yield a full proof element
        if tuples.into_buffer().len() > 0 || !chunks.remainder().is_empty() {
            return Err(ProofError::InvalidLength(
                "Unused data after deserialization".to_string(),
            ));
        }

        Ok(RangeProof {
            a,
            a1,
            b,
            r1,
            s1,
            d1,
            li,
            ri,
            extension_degree,
        })
    }

    /// Helper function to return the serialized proof's extension degree
    pub fn extension_degree_from_proof_bytes(slice: &[u8]) -> Result<ExtensionDegree, ProofError> {
        ExtensionDegree::try_from(
            *(slice
                .first()
                .ok_or_else(|| ProofError::InvalidLength("Serialized proof is too short".to_string()))?)
                as usize,
        )
    }
}

impl<P> Serialize for RangeProof<P>
where
    P: Compressable,
    P::Compressed: FixedBytesRepr,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

impl<'de, P> Deserialize<'de> for RangeProof<P>
where
    P: Compressable,
    P::Compressed: FixedBytesRepr,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct RangeProofVisitor<B>(PhantomData<B>);

        impl<'de, T> Visitor<'de> for RangeProofVisitor<T>
        where
            T: Compressable,
            T::Compressed: FixedBytesRepr,
        {
            type Value = RangeProof<T>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("a valid RangeProof")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<RangeProof<T>, E>
            where E: serde::de::Error {
                RangeProof::from_bytes(v).map_err(|_| serde::de::Error::custom("deserialization error"))
            }
        }

        deserializer.deserialize_bytes(RangeProofVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use core::convert::TryFrom;

    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::{
        commitment_opening::CommitmentOpening,
        generators::pedersen_gens::ExtensionDegree,
        range_parameters::RangeParameters,
        ristretto::{create_pedersen_gens_with_extension_degree, RistrettoRangeProof},
        BulletproofGens,
    };

    #[test]
    fn test_serialized_element_size() {
        // Check that the serialized proof element size constant is correct (at least for Ristretto)
        assert_eq!(
            RistrettoPoint::identity().compress().as_bytes().len(),
            SERIALIZED_ELEMENT_SIZE
        );
        assert_eq!(Scalar::ZERO.as_bytes().len(), SERIALIZED_ELEMENT_SIZE);
    }

    #[test]
    fn test_from_bytes() {
        assert!((RistrettoRangeProof::from_bytes(&[])).is_err());
        assert!((RistrettoRangeProof::from_bytes(Scalar::ZERO.as_bytes().as_slice())).is_err());
        let proof = RistrettoRangeProof {
            a: CompressedRistretto::identity(),
            a1: CompressedRistretto::identity(),
            b: CompressedRistretto::identity(),
            r1: Scalar::ZERO,
            s1: Scalar::ZERO,
            d1: vec![],
            li: vec![],
            ri: vec![],
            extension_degree: ExtensionDegree::DefaultPedersen,
        };
        let proof_bytes = proof.to_bytes();
        assert!(RistrettoRangeProof::from_bytes(&proof_bytes).is_err());

        let proof = RistrettoRangeProof {
            a: CompressedRistretto::identity(),
            a1: CompressedRistretto::identity(),
            b: CompressedRistretto::identity(),
            r1: Scalar::ZERO,
            s1: Scalar::ZERO,
            d1: vec![Scalar::ZERO],
            li: vec![CompressedRistretto::identity()],
            ri: vec![CompressedRistretto::identity()],
            extension_degree: ExtensionDegree::DefaultPedersen,
        };
        let proof_bytes = proof.to_bytes();
        assert!(RistrettoRangeProof::from_bytes(&proof_bytes).is_ok());
        assert_eq!(proof.extension_degree(), proof.extension_degree);
        assert_eq!(
            RistrettoRangeProof::extension_degree_from_proof_bytes(&proof_bytes).unwrap(),
            proof.extension_degree()
        );

        let proof = RistrettoRangeProof {
            a: CompressedRistretto::identity(),
            a1: CompressedRistretto::identity(),
            b: CompressedRistretto::identity(),
            r1: Scalar::ZERO,
            s1: Scalar::ZERO,
            d1: vec![
                Scalar::ZERO,
                Scalar::ZERO,
                Scalar::ZERO,
                Scalar::ZERO,
                Scalar::ZERO,
                Scalar::ZERO,
            ],
            li: vec![CompressedRistretto::identity()],
            ri: vec![CompressedRistretto::identity()],
            extension_degree: ExtensionDegree::AddFiveBasePoints,
        };
        let proof_bytes = proof.to_bytes();
        assert_eq!(proof.extension_degree(), proof.extension_degree);
        assert_eq!(
            RistrettoRangeProof::extension_degree_from_proof_bytes(&proof_bytes).unwrap(),
            proof.extension_degree()
        );
        assert!(RistrettoRangeProof::from_bytes(&proof_bytes).is_ok());
        let mut proof_bytes_meddled = proof_bytes.clone();

        for i in 0..u8::MAX {
            if ExtensionDegree::try_from(i).is_err() {
                proof_bytes_meddled[0] = i;
                assert!(RistrettoRangeProof::from_bytes(&proof_bytes_meddled).is_err());
                break;
            }
        }

        for i in 0..proof_bytes.len() {
            match RistrettoRangeProof::from_bytes(&proof_bytes[..proof_bytes.len() - i]) {
                Ok(proof_from_bytes) => {
                    assert_eq!(proof, proof_from_bytes);
                    assert_eq!(i, 0)
                },
                Err(_) => {
                    assert_ne!(i, 0)
                },
            }
        }

        let mut proof_bytes_meddled = proof_bytes.clone();
        for i in 0..proof_bytes.len() * 10 {
            proof_bytes_meddled.append(&mut 0u8.to_le_bytes().to_vec());
            match RistrettoRangeProof::from_bytes(&proof_bytes_meddled) {
                Ok(_) => {
                    // Adding two zero-valued byte representations of CompressedRistretto would be valid
                    assert_eq!((i + 1) % 64, 0);
                },
                Err(_) => {
                    assert_ne!((i + 1) % 64, 0);
                },
            }
        }
    }

    #[test]
    fn test_consistency_errors() {
        let mut rng = ChaCha12Rng::seed_from_u64(8675309); // for testing only!

        // Generate two proofs
        let params = RangeParameters::init(
            4,
            1,
            create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen),
        )
        .unwrap();
        let mut witnesses = Vec::new();
        let mut statements = Vec::new();
        let mut proofs = Vec::new();
        for _ in 0..2 {
            witnesses.push(RangeWitness::init(vec![CommitmentOpening::new(1u64, vec![Scalar::ONE])]).unwrap());
            statements.push(
                RangeStatement::init(
                    params.clone(),
                    vec![params.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
                    vec![None],
                    None,
                )
                .unwrap(),
            );
            proofs.push(
                RangeProof::prove_with_rng(
                    &mut Transcript::new(b"Test"),
                    statements.last().unwrap(),
                    witnesses.last().unwrap(),
                    &mut rng,
                )
                .unwrap(),
            );
        }

        // Empty vectors
        assert!(RangeProof::verify_statements_and_generators_consistency(&[], &proofs).is_err());
        assert!(RangeProof::verify_statements_and_generators_consistency(&statements, &[]).is_err());

        // Vector length mismatch
        assert!(RangeProof::verify_statements_and_generators_consistency(&statements, &proofs[..1]).is_err());

        // Make the first statement's extension degree mismatch against the corresponding proof
        let params_mismatch = RangeParameters::init(
            4,
            1,
            create_pedersen_gens_with_extension_degree(ExtensionDegree::AddOneBasePoint),
        )
        .unwrap();
        let statement_mismatch = RangeStatement::init(
            params_mismatch.clone(),
            vec![params_mismatch.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        assert!(RangeProof::verify_statements_and_generators_consistency(&[statement_mismatch], &proofs[..1]).is_err());

        // Make the second statement's `g_base_vec` mismatch against the first statement
        let mut gens_mismatch = create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen);
        gens_mismatch.g_base_vec[0] = RistrettoPoint::identity();
        let params_mismatch = RangeParameters::init(4, 1, gens_mismatch).unwrap();
        let statement_mismatch = RangeStatement::init(
            params_mismatch.clone(),
            vec![params_mismatch.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        assert!(RangeProof::verify_statements_and_generators_consistency(
            &[statements[0].clone(), statement_mismatch],
            &proofs
        )
        .is_err());

        // Make the second statement's `h_base` mismatch against the first statement
        let mut gens_mismatch = create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen);
        gens_mismatch.h_base = RistrettoPoint::identity();
        let params_mismatch = RangeParameters::init(4, 1, gens_mismatch).unwrap();
        let statement_mismatch = RangeStatement::init(
            params_mismatch.clone(),
            vec![params_mismatch.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        assert!(RangeProof::verify_statements_and_generators_consistency(
            &[statements[0].clone(), statement_mismatch],
            &proofs
        )
        .is_err());

        // Make the second statement's bit length mismatch against the first statement
        let params_mismatch = RangeParameters::init(
            2,
            1,
            create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen),
        )
        .unwrap();
        let statement_mismatch = RangeStatement::init(
            params_mismatch.clone(),
            vec![params_mismatch.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        assert!(RangeProof::verify_statements_and_generators_consistency(
            &[statements[0].clone(), statement_mismatch],
            &proofs
        )
        .is_err());

        // Make the second statement's extension degree mismatch against the first statement
        let mut gens_mismatch = create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen);
        gens_mismatch.extension_degree = ExtensionDegree::AddOneBasePoint;
        let params_mismatch = RangeParameters::init(4, 1, gens_mismatch).unwrap();
        let statement_mismatch = RangeStatement::init(
            params_mismatch.clone(),
            vec![params_mismatch.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        assert!(RangeProof::verify_statements_and_generators_consistency(
            &[statements[0].clone(), statement_mismatch],
            &proofs
        )
        .is_err());

        // Use a minimum value promise exceeding the bit length
        let statement_invalid = RangeStatement::init(
            params.clone(),
            vec![params.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
            vec![Some(1 << 4)],
            None,
        )
        .unwrap();
        assert!(RangeProof::verify_statements_and_generators_consistency(
            &[statements[0].clone(), statement_invalid],
            &proofs
        )
        .is_err());

        // Make the second statement's `gi_base` mismatch against the first statement
        let mut gens_mismatch = BulletproofGens::new(4, 1).unwrap();
        gens_mismatch.g_vec[0][0] = RistrettoPoint::identity();
        let params_mismatch = RangeParameters {
            bp_gens: gens_mismatch,
            pc_gens: create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen),
        };
        let statement_mismatch = RangeStatement::init(
            params_mismatch.clone(),
            vec![params_mismatch.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        assert!(RangeProof::verify_statements_and_generators_consistency(
            &[statements[0].clone(), statement_mismatch],
            &proofs
        )
        .is_err());

        // Make the second statement's `hi_base` mismatch against the first statement
        let mut gens_mismatch = BulletproofGens::new(4, 1).unwrap();
        gens_mismatch.h_vec[0][0] = RistrettoPoint::identity();
        let params_mismatch = RangeParameters {
            bp_gens: gens_mismatch,
            pc_gens: create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen),
        };
        let statement_mismatch = RangeStatement::init(
            params_mismatch.clone(),
            vec![params_mismatch.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        assert!(RangeProof::verify_statements_and_generators_consistency(
            &[statements[0].clone(), statement_mismatch],
            &proofs
        )
        .is_err());
    }

    #[test]
    fn test_getters() {
        let mut rng = ChaCha12Rng::seed_from_u64(8675309); // for testing only!

        // Generate a valid proof
        let params = RangeParameters::init(
            4,
            1,
            create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen),
        )
        .unwrap();
        let witness = RangeWitness::init(vec![CommitmentOpening::new(1u64, vec![Scalar::ONE])]).unwrap();
        let statement = RangeStatement::init(
            params.clone(),
            vec![params.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        let mut proof =
            RangeProof::prove_with_rng(&mut Transcript::new(b"Test"), &statement, &witness, &mut rng).unwrap();

        // Mutate proof elements
        let mut bytes = [0u8; 32];
        bytes[0] = 1;

        proof.a = CompressedRistretto::from_fixed_bytes(bytes);
        assert!(proof.a_decompressed().is_err());

        proof.a1 = CompressedRistretto::from_fixed_bytes(bytes);
        assert!(proof.a1_decompressed().is_err());

        proof.b = CompressedRistretto::from_fixed_bytes(bytes);
        assert!(proof.b_decompressed().is_err());

        // Mutate proof vectors
        proof.li[0] = CompressedRistretto::from_fixed_bytes(bytes);
        assert!(proof.li_decompressed().is_err());

        proof.ri[0] = CompressedRistretto::from_fixed_bytes(bytes);
        assert!(proof.ri_decompressed().is_err());
    }

    #[test]
    fn test_extension_degree_from_proof_bytes() {
        assert!(RangeProof::<RistrettoPoint>::extension_degree_from_proof_bytes(&[]).is_err());
        assert!(RangeProof::<RistrettoPoint>::extension_degree_from_proof_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_prover_consistency_errors() {
        let mut rng = ChaCha12Rng::seed_from_u64(8675309); // for testing only!

        // Create range parameters to use for all tests
        let params = RangeParameters::init(
            4,
            2,
            create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen),
        )
        .unwrap();

        // Witness openings do not correspond to number of statement commitments
        // The witness opens one commitment, but the statement opens two
        let witness = RangeWitness::init(vec![CommitmentOpening::new(1u64, vec![Scalar::ONE])]).unwrap();
        let statement = RangeStatement::init(
            params.clone(),
            vec![
                params
                    .pc_gens
                    .commit(&Scalar::from(1u64), &witness.openings[0].r)
                    .unwrap();
                2
            ],
            vec![None, None],
            None,
        )
        .unwrap();
        assert!(RangeProof::prove_with_rng(&mut Transcript::new(b"Test"), &statement, &witness, &mut rng).is_err());

        // Witness and statement extension degrees do not match
        let witness = RangeWitness::init(vec![CommitmentOpening::new(1u64, vec![Scalar::ONE, Scalar::ONE])]).unwrap();
        let statement = RangeStatement::init(
            params.clone(),
            vec![params
                .pc_gens
                .commit(&Scalar::from(1u64), &witness.openings[0].r[..1])
                .unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        assert!(RangeProof::prove_with_rng(&mut Transcript::new(b"Test"), &statement, &witness, &mut rng).is_err());

        // Witness value overflows bit length
        let witness = RangeWitness::init(vec![CommitmentOpening::new(16u64, vec![Scalar::ONE])]).unwrap();
        let statement = RangeStatement::init(
            params.clone(),
            vec![params
                .pc_gens
                .commit(&Scalar::from(16u64), &witness.openings[0].r)
                .unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        assert!(RangeProof::prove_with_rng(&mut Transcript::new(b"Test"), &statement, &witness, &mut rng).is_err());

        // Witness opening is invalid for statement commitment
        let witness = RangeWitness::init(vec![CommitmentOpening::new(1u64, vec![Scalar::ONE])]).unwrap();
        let statement = RangeStatement::init(
            params.clone(),
            vec![params
                .pc_gens
                .commit(&Scalar::from(2u64), &(witness.openings[0].r))
                .unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        assert!(RangeProof::prove_with_rng(&mut Transcript::new(b"Test"), &statement, &witness, &mut rng).is_err());

        // Witness value does not meet minimum value promise
        let witness = RangeWitness::init(vec![CommitmentOpening::new(1u64, vec![Scalar::ONE])]).unwrap();
        let statement = RangeStatement::init(
            params.clone(),
            vec![params
                .pc_gens
                .commit(&Scalar::from(1u64), &(witness.openings[0].r))
                .unwrap()],
            vec![Some(2u64)],
            None,
        )
        .unwrap();
        assert!(RangeProof::prove_with_rng(&mut Transcript::new(b"Test"), &statement, &witness, &mut rng).is_err());
    }

    #[test]
    fn test_verify_errors() {
        let mut rng = ChaCha12Rng::seed_from_u64(8675309); // for testing only!

        // Generate a valid proof
        let params = RangeParameters::init(
            4,
            1,
            create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen),
        )
        .unwrap();
        let witness = RangeWitness::init(vec![CommitmentOpening::new(1u64, vec![Scalar::ONE])]).unwrap();
        let statement = RangeStatement::init(
            params.clone(),
            vec![params.pc_gens().commit(&Scalar::ONE, &[Scalar::ONE]).unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        let mut proof =
            RangeProof::prove_with_rng(&mut Transcript::new(b"Test"), &statement, &witness, &mut rng).unwrap();

        // Empty statement and proof vectors
        assert!(RangeProof::verify_batch(&mut [], &[], &[proof.clone()], VerifyAction::VerifyOnly).is_err());
        assert!(RangeProof::verify_batch(
            &mut [Transcript::new(b"Test")],
            &[statement.clone()],
            &[],
            VerifyAction::VerifyOnly,
        )
        .is_err());

        // Proof vector mismatches
        proof.li.pop();
        assert!(RangeProof::verify_batch(
            &mut [Transcript::new(b"Test")],
            &[statement.clone()],
            &[proof.clone()],
            VerifyAction::VerifyOnly,
        )
        .is_err());

        proof.ri.pop();
        assert!(RangeProof::verify_batch(
            &mut [Transcript::new(b"Test")],
            &[statement],
            &[proof],
            VerifyAction::VerifyOnly,
        )
        .is_err());
    }

    #[test]
    fn test_aggregation_lower_than_generators() {
        let mut rng = ChaCha12Rng::seed_from_u64(8675309); // for testing only!

        // Create range parameters
        let params = RangeParameters::init(
            4,
            2,
            create_pedersen_gens_with_extension_degree(ExtensionDegree::DefaultPedersen),
        )
        .unwrap();

        // Witness and statement correspond to fewer commitments than the aggregation factor
        let witness = RangeWitness::init(vec![CommitmentOpening::new(1u64, vec![Scalar::ONE])]).unwrap();
        let statement = RangeStatement::init(
            params.clone(),
            vec![params
                .pc_gens
                .commit(&Scalar::from(1u64), &witness.openings[0].r)
                .unwrap()],
            vec![None],
            None,
        )
        .unwrap();
        let proof = RangeProof::prove_with_rng(&mut Transcript::new(b"Test"), &statement, &witness, &mut rng).unwrap();

        // The proof should verify
        RangeProof::verify_batch(
            &mut [Transcript::new(b"Test")],
            &[statement],
            &[proof],
            VerifyAction::VerifyOnly,
        )
        .unwrap();
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_s_logarithm() {
        for i in 1usize..64 {
            assert_eq!(
                (32 - 1 - (i as u32).leading_zeros()) as usize,
                usize::try_from(i.ilog2()).unwrap()
            );
        }
    }
}
