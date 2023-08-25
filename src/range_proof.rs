// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ public range proof parameters intended for a verifier

#![allow(clippy::too_many_lines)]

use std::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
    ops::{Add, Mul},
};

use curve25519_dalek::{
    scalar::Scalar,
    traits::{Identity, IsIdentity, VartimePrecomputedMultiscalarMul},
};
use itertools::{izip, Itertools};
use merlin::Transcript;
use rand::thread_rng;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    errors::ProofError,
    extended_mask::ExtendedMask,
    generators::pedersen_gens::ExtensionDegree,
    protocols::{
        curve_point_protocol::CurvePointProtocol,
        scalar_protocol::ScalarProtocol,
        transcript_protocol::TranscriptProtocol,
    },
    range_statement::RangeStatement,
    range_witness::RangeWitness,
    traits::{Compressable, Decompressable, FixedBytesRepr, Precomputable},
    transcripts,
    utils::generic::{bit_vector_of_scalars, nonce, read_1_byte, read_32_bytes, split_at_checked},
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

/// # Example
/// ```
/// use curve25519_dalek::scalar::Scalar;
/// use merlin::Transcript;
/// use rand::Rng;
/// # fn main() {
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
/// let mut rng = rand::thread_rng();
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
///
///     // 4. Create the proofs
///     let proof = RistrettoRangeProof::prove(transcript_label, &private_statement.clone(), &witness);
///     proofs.push(proof.unwrap());
/// }
///
/// // 5. Verify the entire batch as the commitment owner, i.e. the prover self
/// let recovered_private_masks = RangeProof::verify_batch(
///     transcript_label,
///     &statements_private,
///     &proofs,
///     VerifyAction::RecoverAndVerify,
/// )
/// .unwrap();
/// assert_eq!(private_masks, recovered_private_masks);
///
/// // 6. Verify the entire batch as public entity
/// let recovered_public_masks =
///     RangeProof::verify_batch(transcript_label, &statements_public, &proofs, VerifyAction::VerifyOnly).unwrap();
/// assert_eq!(public_masks, recovered_public_masks);
///
/// # }
/// ```

impl<P> RangeProof<P>
where
    for<'p> &'p P: Mul<Scalar, Output = P>,
    for<'p> &'p P: Add<Output = P>,
    P: CurvePointProtocol + Precomputable,
    P::Compressed: FixedBytesRepr + IsIdentity + Identity,
{
    /// Helper function to return the proof's extension degree
    pub fn extension_degree(&self) -> ExtensionDegree {
        self.extension_degree
    }

    /// Create a single or aggregated range proof for a single party that knows all the secrets
    /// The prover must ensure that the commitments and witness opening data are consistent
    pub fn prove(
        transcript_label: &'static str,
        statement: &RangeStatement<P>,
        witness: &RangeWitness,
    ) -> Result<Self, ProofError> {
        // Useful lengths
        let bit_length = statement.generators.bit_length();
        let aggregation_factor = statement.commitments.len();
        let extension_degree = statement.generators.extension_degree() as usize;
        let full_length = bit_length
            .checked_mul(aggregation_factor)
            .ok_or(ProofError::SizeOverflow)?;

        // Consistency checks (can we nix these?)
        if witness.openings.len() != aggregation_factor {
            return Err(ProofError::InvalidLength(
                "Witness openings statement commitments do not match!".to_string(),
            ));
        }
        if witness.extension_degree != statement.generators.extension_degree() {
            return Err(ProofError::InvalidLength(
                "Witness and statement extension degrees do not match!".to_string(),
            ));
        }

        // Start the transcript
        let mut transcript = Transcript::new(transcript_label.as_bytes());
        transcript.domain_separator(b"Bulletproofs+", b"Range Proof");
        transcripts::transcript_initialize::<P>(
            &mut transcript,
            &statement.generators.h_base().compress(),
            statement.generators.g_bases_compressed(),
            bit_length,
            extension_degree,
            aggregation_factor,
            statement,
        )?;

        // Set bit arrays
        let mut a_li = Vec::with_capacity(full_length);
        let mut a_ri = Vec::with_capacity(full_length);
        for (j, value) in witness.openings.iter().map(|o| o.v).enumerate() {
            let bit_vector = if let Some(minimum_value) = statement.minimum_value_promises[j] {
                let offset_value = value.checked_sub(minimum_value).ok_or(ProofError::InvalidArgument(
                    "Minimum value is larger than value".to_string(),
                ))?;
                bit_vector_of_scalars(offset_value, bit_length)?
            } else {
                bit_vector_of_scalars(value, bit_length)?
            };
            for bit_field in bit_vector.clone() {
                a_li.push(bit_field);
                a_ri.push(bit_field - Scalar::ONE);
            }
        }

        // Compute A by multi-scalar multiplication
        let rng = &mut thread_rng();
        let mut alpha = Vec::with_capacity(extension_degree);
        for k in 0..extension_degree {
            alpha.push(if let Some(seed_nonce) = statement.seed_nonce {
                nonce(&seed_nonce, "alpha", None, Some(k))?
            } else {
                // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
                Scalar::random_not_zero(rng)
            });
        }
        let a = statement.generators.precomp().vartime_mixed_multiscalar_mul(
            a_li.iter().interleave(a_ri.iter()),
            alpha.iter(),
            statement.generators.g_bases().iter(),
        );

        // Get challenges
        let (y, z) = transcripts::transcript_point_a_challenges_y_z(&mut transcript, &a.compress())?;
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
        for i in 1..bit_length {
            d.push(two * d[i - 1]);
        }
        for j in 1..aggregation_factor {
            for i in 0..bit_length {
                d.push(d[(j - 1) * bit_length + i] * z_square);
            }
        }

        // Prepare for inner product
        for item in &mut a_li {
            *item -= z;
        }
        for (i, item) in a_ri.iter_mut().enumerate() {
            *item += d[i] * y_powers[bit_length * aggregation_factor - i] + z;
        }
        let mut z_even_powers = Scalar::ONE;
        for j in 0..aggregation_factor {
            z_even_powers *= z_square;
            for (k, alpha1_val) in alpha.iter_mut().enumerate().take(extension_degree) {
                *alpha1_val += z_even_powers * witness.openings[j].r[k] * y_powers[bit_length * aggregation_factor + 1];
            }
        }

        let mut gi_base: Vec<P> = statement.generators.gi_base_iter().cloned().collect();
        let mut hi_base: Vec<P> = statement.generators.hi_base_iter().cloned().collect();
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
            let (a_lo, a_hi) = split_at_checked(&a_li, n)?;
            let (b_lo, b_hi) = split_at_checked(&a_ri, n)?;
            let (gi_base_lo, gi_base_hi) = split_at_checked(&gi_base, n)?;
            let (hi_base_lo, hi_base_hi) = split_at_checked(&hi_base, n)?;

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
                (0..extension_degree)
                    .map(|k| nonce(&seed_nonce, "dL", Some(round), Some(k)))
                    .collect::<Result<Vec<_>, ProofError>>()?
            } else {
                // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
                (0..extension_degree).map(|_| Scalar::random_not_zero(rng)).collect()
            };
            let d_r = if let Some(seed_nonce) = statement.seed_nonce {
                (0..extension_degree)
                    .map(|k| nonce(&seed_nonce, "dR", Some(round), Some(k)))
                    .collect::<Result<Vec<_>, ProofError>>()?
            } else {
                // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
                (0..extension_degree).map(|_| Scalar::random_not_zero(rng)).collect()
            };

            round += 1;

            let c_l = izip!(a_lo, y_powers.iter().skip(1), b_hi)
                .fold(Scalar::ZERO, |acc, (a, y_power, b)| acc + a * y_power * b);
            let c_r = izip!(a_hi, y_powers.iter().skip(n + 1), b_lo)
                .fold(Scalar::ZERO, |acc, (a, y_power, b)| acc + a * y_power * b);

            // Compute L and R by multi-scalar multiplication
            li.push(P::vartime_multiscalar_mul(
                std::iter::once(&c_l)
                    .chain(d_l.iter())
                    .chain(a_lo_offset.iter())
                    .chain(b_hi.iter()),
                std::iter::once(h_base)
                    .chain(g_base.iter())
                    .chain(gi_base_hi)
                    .chain(hi_base_lo),
            ));
            ri.push(P::vartime_multiscalar_mul(
                std::iter::once(&c_r)
                    .chain(d_r.iter())
                    .chain(a_hi_offset.iter())
                    .chain(b_lo.iter()),
                std::iter::once(h_base)
                    .chain(g_base.iter())
                    .chain(gi_base_lo)
                    .chain(hi_base_hi),
            ));

            // Get the round challenge and associated values
            let e = transcripts::transcript_points_l_r_challenge_e(
                &mut transcript,
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
            a_li = a_lo
                .iter()
                .zip(a_hi_offset.iter())
                .map(|(lo, hi)| lo * e + hi * e_inverse)
                .collect();
            a_ri = b_lo
                .iter()
                .zip(b_hi.iter())
                .map(|(lo, hi)| lo * e_inverse + hi * e)
                .collect();

            for (alpha, (l, r)) in alpha.iter_mut().zip(d_l.iter().zip(d_r.iter())) {
                *alpha += l * e_square + r * e_inverse_square;
            }
        }

        // Random masks
        // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
        let (r, s) = (Scalar::random_not_zero(rng), Scalar::random_not_zero(rng));
        let d = if let Some(seed_nonce) = statement.seed_nonce {
            (0..extension_degree)
                .map(|k| nonce(&seed_nonce, "d", None, Some(k)))
                .collect::<Result<Vec<_>, ProofError>>()?
        } else {
            // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
            (0..extension_degree).map(|_| Scalar::random_not_zero(rng)).collect()
        };
        let eta = if let Some(seed_nonce) = statement.seed_nonce {
            (0..extension_degree)
                .map(|k| nonce(&seed_nonce, "eta", None, Some(k)))
                .collect::<Result<Vec<_>, ProofError>>()?
        } else {
            // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
            (0..extension_degree).map(|_| Scalar::random_not_zero(rng)).collect()
        };

        let mut a1 =
            &gi_base[0] * r + &hi_base[0] * s + h_base * (r * y_powers[1] * a_ri[0] + s * y_powers[1] * a_li[0]);
        let mut b = h_base * (r * y_powers[1] * s);
        for k in 0..extension_degree {
            a1 += &g_base[k] * d[k];
            b += &g_base[k] * eta[k]
        }

        let e = transcripts::transcript_points_a1_b_challenge_e(&mut transcript, &a1.compress(), &b.compress())?;
        let e_square = e * e;

        let r1 = r + a_li[0] * e;
        let s1 = s + a_ri[0] * e;
        let d1: Vec<Scalar> = izip!(eta, d, alpha.iter())
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
        if statements.is_empty() || range_proofs.is_empty() {
            return Err(ProofError::InvalidArgument(
                "Range statements or proofs length empty".to_string(),
            ));
        }
        if statements.len() != range_proofs.len() {
            return Err(ProofError::InvalidArgument(
                "Range statements and proofs length mismatch".to_string(),
            ));
        }

        let (g_base_vec, h_base) = (statements[0].generators.g_bases(), statements[0].generators.h_base());
        let bit_length = statements[0].generators.bit_length();
        let mut max_mn = statements[0].commitments.len() * statements[0].generators.bit_length();
        let mut max_index = 0;
        let extension_degree = statements[0].generators.extension_degree();

        if extension_degree != ExtensionDegree::try_from_size(range_proofs[0].d1.len())? {
            return Err(ProofError::InvalidArgument("Inconsistent extension degree".to_string()));
        }
        for (i, statement) in statements.iter().enumerate().skip(1) {
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
                extension_degree != ExtensionDegree::try_from_size(range_proofs[i].d1.len())?
            {
                return Err(ProofError::InvalidArgument("Inconsistent extension degree".to_string()));
            }
            if statement.commitments.len() * statement.generators.bit_length() > max_mn {
                max_mn = statement.commitments.len() * statement.generators.bit_length();
                max_index = i;
            }
        }
        let (gi_base_ref, hi_base_ref) = (
            statements[max_index].generators.gi_base_ref(),
            statements[max_index].generators.hi_base_ref(),
        );
        for (i, statement) in statements.iter().enumerate() {
            for value in Iterator::flatten(statement.minimum_value_promises.iter()) {
                if value >> (bit_length - 1) > 1 {
                    return Err(ProofError::InvalidLength(
                        "Minimum value promise exceeds bit vector capacity".to_string(),
                    ));
                }
            }
            if i == max_index {
                continue;
            }
            let statement_gi_base_ref = statement.generators.gi_base_ref();
            for (j, gi_base_ref_item) in gi_base_ref.iter().enumerate().take(statement_gi_base_ref.len()) {
                if &statement_gi_base_ref[j] != gi_base_ref_item {
                    return Err(ProofError::InvalidArgument(
                        "Inconsistent Gi generator point vector in batch statement".to_string(),
                    ));
                }
            }
            let statement_hi_base_ref = statement.generators.hi_base_ref();
            for (j, hi_base_ref_item) in hi_base_ref.iter().enumerate().take(statement_hi_base_ref.len()) {
                if &statement_hi_base_ref[j] != hi_base_ref_item {
                    return Err(ProofError::InvalidArgument(
                        "Inconsistent Hi generator point vector in batch statement".to_string(),
                    ));
                }
            }
        }

        Ok((max_mn, max_index))
    }

    /// Wrapper function for batch verification in different modes: mask recovery, verification, or both
    pub fn verify_batch(
        transcript_label: &'static str,
        statements: &[RangeStatement<P>],
        proofs: &[RangeProof<P>],
        action: VerifyAction,
    ) -> Result<Vec<Option<ExtendedMask>>, ProofError> {
        // By definition, an empty batch fails
        if statements.is_empty() || proofs.is_empty() {
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

        // Store masks from all results
        let mut masks = Vec::<Option<ExtendedMask>>::with_capacity(proofs.len());

        // Get chunks of both the statements and proofs
        let mut chunks = statements
            .chunks(MAX_RANGE_PROOF_BATCH_SIZE)
            .zip(proofs.chunks(MAX_RANGE_PROOF_BATCH_SIZE));

        // If the batch fails, propagate the error; otherwise, store the masks and keep going
        if let Some((batch_statements, batch_proofs)) = chunks.next() {
            let mut result = RangeProof::verify(transcript_label, batch_statements, batch_proofs, action)?;

            masks.append(&mut result);
        }

        Ok(masks)
    }

    // Verify a batch of single and/or aggregated range proofs as a public entity, or recover the masks for single
    // range proofs by a party that can supply the optional seed nonces
    fn verify(
        transcript_label: &'static str,
        statements: &[RangeStatement<P>],
        range_proofs: &[RangeProof<P>],
        extract_masks: VerifyAction,
    ) -> Result<Vec<Option<ExtendedMask>>, ProofError> {
        // Verify generators consistency & select largest aggregation factor
        let (max_mn, max_index) = RangeProof::verify_statements_and_generators_consistency(statements, range_proofs)?;
        let (g_base_vec, h_base) = (statements[0].generators.g_bases(), statements[0].generators.h_base());
        let bit_length = statements[0].generators.bit_length();
        let extension_degree = statements[0].generators.extension_degree() as usize;
        let g_bases_compressed = statements[0].generators.g_bases_compressed();
        let h_base_compressed = statements[0].generators.h_base_compressed();
        let precomp = statements[max_index].generators.precomp();

        // Compute log2(N)
        let mut log_n = 0u32;
        let mut temp_n = bit_length >> 1;
        while temp_n != 0 {
            log_n += 1;
            temp_n >>= 1;
        }

        // Compute 2**N-1 for later use
        let mut two_n_minus_one = Scalar::from(2u8);
        for _ in 0..log_n {
            two_n_minus_one = two_n_minus_one * two_n_minus_one;
        }
        two_n_minus_one -= Scalar::ONE;

        // Weighted coefficients for common generators
        let mut g_base_scalars = vec![Scalar::ZERO; extension_degree];
        let mut h_base_scalar = Scalar::ZERO;
        let mut gi_base_scalars = vec![Scalar::ZERO; max_mn];
        let mut hi_base_scalars = vec![Scalar::ZERO; max_mn];

        // Final multiscalar multiplication data
        // Because we use precomputation on the generator vectors, we need to separate the static data from the dynamic
        // data. However, we can't combine precomputation data, so the Pedersen generators go with the dynamic
        // data :(
        let mut msm_dynamic_len = extension_degree + 1;
        for (index, item) in statements.iter().enumerate() {
            msm_dynamic_len += item.generators.aggregation_factor() + 3 + range_proofs[index].li.len() * 2;
        }
        let mut dynamic_scalars: Vec<Scalar> = Vec::with_capacity(msm_dynamic_len);
        let mut dynamic_points: Vec<P> = Vec::with_capacity(msm_dynamic_len);

        // Recovered masks
        let mut masks = Vec::with_capacity(range_proofs.len());

        let two = Scalar::from(2u8);

        // Process each proof and add it to the batch
        let rng = &mut thread_rng();
        for (proof, statement) in range_proofs.iter().zip(statements) {
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

            if li.len() != ri.len() {
                return Err(ProofError::InvalidLength(
                    "Vector L length not equal to vector R length".to_string(),
                ));
            }
            if 1 << li.len() != commitments.len() * bit_length {
                return Err(ProofError::InvalidLength("Vector L length not adequate".to_string()));
            }

            // Helper values
            let aggregation_factor = commitments.len();
            let gen_length = aggregation_factor * bit_length;
            let rounds = li.len();

            // Batch weight (may not be equal to a zero valued scalar) - this may not be zero ever
            let weight = Scalar::random_not_zero(rng);

            // Start the transcript
            let mut transcript = Transcript::new(transcript_label.as_bytes());
            transcript.domain_separator(b"Bulletproofs+", b"Range Proof");
            transcripts::transcript_initialize(
                &mut transcript,
                &h_base_compressed,
                g_bases_compressed,
                bit_length,
                extension_degree,
                aggregation_factor,
                statement,
            )?;

            // Reconstruct challenges
            let (y, z) = transcripts::transcript_point_a_challenges_y_z(&mut transcript, &proof.a)?;
            let mut challenges = Vec::with_capacity(rounds);
            for j in 0..rounds {
                let e = transcripts::transcript_points_l_r_challenge_e(&mut transcript, &proof.li[j], &proof.ri[j])?;
                challenges.push(e);
            }
            let e = transcripts::transcript_points_a1_b_challenge_e(&mut transcript, &proof.a1, &proof.b)?;

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
            let mut y_nm = y;
            let mut challenges_sq = Vec::with_capacity(challenges.len());
            let mut challenges_sq_inv = Vec::with_capacity(challenges_inv.len());
            for i in 0..rounds {
                y_nm = y_nm * y_nm;
                challenges_sq.push(challenges[i] * challenges[i]);
                challenges_sq_inv.push(challenges_inv[i] * challenges_inv[i]);
            }
            let y_nm_1 = y_nm * y;

            // Compute the sum of powers of the challenge as a partial sum of a geometric series
            let y_sum = y * (y_nm - Scalar::ONE) * y_1_inverse;

            // Compute d efficiently
            let mut d = Vec::with_capacity(bit_length * aggregation_factor);
            d.push(z_square);
            for i in 1..bit_length {
                d.push(two * d[i - 1]);
            }
            for j in 1..aggregation_factor {
                for i in 0..bit_length {
                    d.push(d[(j - 1) * bit_length + i] * z_square);
                }
            }

            // Compute d's sum efficiently
            let mut d_sum = z_square;
            let mut d_sum_temp_z = z_square;
            let mut d_sum_temp_2m = 2 * aggregation_factor;
            while d_sum_temp_2m > 2 {
                d_sum = d_sum + d_sum * d_sum_temp_z;
                d_sum_temp_z = d_sum_temp_z * d_sum_temp_z;
                d_sum_temp_2m /= 2; // Rounds towards zero, truncating any fractional part
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
                            for j in 0..rounds {
                                this_mask -= challenges_sq[j] * nonce(&seed_nonce, "dL", Some(j), Some(k))?;
                                this_mask -= challenges_sq_inv[j] * nonce(&seed_nonce, "dR", Some(j), Some(k))?;
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

            let mut s = Vec::with_capacity(gen_length);
            s.push(challenges_inv_prod);
            for i in 1..gen_length {
                #[allow(clippy::cast_possible_truncation)]
                // Note: 'i' must be cast to u32 in this case (usize is 64bit on 64bit platforms)
                let log_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
                let j = 1 << log_i;
                s.push(s[i - j] * challenges_sq[rounds - log_i - 1]);
            }
            let r1_e = r1 * e;
            let s1_e = s1 * e;
            let e_square_z = e_square * z;
            for i in 0..gen_length {
                let g = r1_e * y_inv_i * s[i];
                let h = s1_e * s[gen_length - i - 1];
                gi_base_scalars[i] += weight * (g + e_square_z);
                hi_base_scalars[i] += weight * (h - e_square * (d[i] * y_nm_i + z));
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
            for k in 0..extension_degree {
                g_base_scalars[k] += weight * d1[k];
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
        for k in 0..extension_degree {
            dynamic_scalars.push(g_base_scalars[k]);
            dynamic_points.push(g_base_vec[k].clone());
        }
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
    /// Serializes the proof into a byte array of 32-byte elements
    pub fn to_bytes(&self) -> Vec<u8> {
        // 6 elements, 2 vectors
        let mut buf = Vec::with_capacity(1 + (self.li.len() + self.ri.len() + 5 + self.d1.len()) * 32);
        buf.extend_from_slice(&(self.extension_degree as u8).to_le_bytes());
        for l in &self.li {
            buf.extend_from_slice(l.as_fixed_bytes());
        }
        for r in &self.ri {
            buf.extend_from_slice(r.as_fixed_bytes());
        }
        buf.extend_from_slice(self.a.as_fixed_bytes());
        buf.extend_from_slice(self.a1.as_fixed_bytes());
        buf.extend_from_slice(self.b.as_fixed_bytes());
        buf.extend_from_slice(self.r1.as_bytes());
        buf.extend_from_slice(self.s1.as_bytes());
        for d1 in &self.d1 {
            buf.extend_from_slice(d1.as_bytes());
        }
        buf
    }

    /// Deserializes the proof from a byte slice
    pub fn from_bytes(slice: &[u8]) -> Result<Self, ProofError> {
        if slice.is_empty() || (slice.len() - 1) % 32 != 0 {
            return Err(ProofError::InvalidLength(
                "Invalid serialized proof bytes length".to_string(),
            ));
        }
        let extension_degree = ExtensionDegree::try_from(read_1_byte(&slice[0..])[0] as usize)?;
        let num_elements = (slice.len() - 1) / 32;
        if num_elements < 2 + 5 + extension_degree as usize {
            return Err(ProofError::InvalidLength(
                "Serialized proof has incorrect number of elements".to_string(),
            ));
        };
        let num_inner_prod_vec_elements = num_elements - 5 - extension_degree as usize;
        if num_inner_prod_vec_elements % 2 != 0 {
            return Err(ProofError::InvalidLength(
                "Serialized proof has incorrect number of elements".to_string(),
            ));
        }
        let n = num_inner_prod_vec_elements / 2;

        let mut li = Vec::with_capacity(n);
        let mut ri = Vec::with_capacity(n);
        for i in 0..n {
            li.push(P::Compressed::from_fixed_bytes(read_32_bytes(&slice[1 + i * 32..])));
        }
        for i in n..2 * n {
            ri.push(P::Compressed::from_fixed_bytes(read_32_bytes(&slice[1 + i * 32..])));
        }

        let pos = 1 + 2 * n * 32;
        let a = P::Compressed::from_fixed_bytes(read_32_bytes(&slice[pos..]));
        let a1 = P::Compressed::from_fixed_bytes(read_32_bytes(&slice[pos + 32..]));
        let b = P::Compressed::from_fixed_bytes(read_32_bytes(&slice[pos + 64..]));
        let r1 = Option::from(Scalar::from_canonical_bytes(read_32_bytes(&slice[pos + 96..])))
            .ok_or_else(|| ProofError::InvalidArgument("r1 bytes not a canonical byte representation".to_string()))?;
        let s1 = Option::from(Scalar::from_canonical_bytes(read_32_bytes(&slice[pos + 128..])))
            .ok_or_else(|| ProofError::InvalidArgument("s1 bytes not a canonical byte representation".to_string()))?;
        let mut d1 = Vec::with_capacity(extension_degree as usize);
        for i in 0..extension_degree as usize {
            d1.push(
                Option::from(Scalar::from_canonical_bytes(read_32_bytes(
                    &slice[pos + 160 + i * 32..],
                )))
                .ok_or_else(|| {
                    ProofError::InvalidArgument("d1 bytes not a canonical byte representation".to_string())
                })?,
            );
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
        if slice.is_empty() || (slice.len() - 1) % 32 != 0 {
            return Err(ProofError::InvalidLength(
                "Invalid serialized proof bytes length".to_string(),
            ));
        }
        ExtensionDegree::try_from(read_1_byte(&slice[0..])[0] as usize)
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
    use std::convert::TryFrom;

    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

    use super::*;
    use crate::{
        commitment_opening::CommitmentOpening,
        generators::pedersen_gens::ExtensionDegree,
        range_parameters::RangeParameters,
        ristretto::{create_pedersen_gens_with_extension_degree, RistrettoRangeProof},
        BulletproofGens,
    };

    #[test]
    fn test_from_bytes() {
        assert!((RistrettoRangeProof::from_bytes(&[])).is_err());
        assert!((RistrettoRangeProof::from_bytes(Scalar::ZERO.as_bytes().as_slice())).is_err());
        let proof = RistrettoRangeProof {
            a: Default::default(),
            a1: Default::default(),
            b: Default::default(),
            r1: Default::default(),
            s1: Default::default(),
            d1: vec![],
            li: vec![],
            ri: vec![],
            extension_degree: ExtensionDegree::DefaultPedersen,
        };
        let proof_bytes = proof.to_bytes();
        assert!(RistrettoRangeProof::from_bytes(&proof_bytes).is_err());

        let proof = RistrettoRangeProof {
            a: Default::default(),
            a1: Default::default(),
            b: Default::default(),
            r1: Default::default(),
            s1: Default::default(),
            d1: vec![Scalar::default()],
            li: vec![CompressedRistretto::default()],
            ri: vec![CompressedRistretto::default()],
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
            a: Default::default(),
            a1: Default::default(),
            b: Default::default(),
            r1: Default::default(),
            s1: Default::default(),
            d1: vec![
                Scalar::default(),
                Scalar::default(),
                Scalar::default(),
                Scalar::default(),
                Scalar::default(),
                Scalar::default(),
            ],
            li: vec![CompressedRistretto::default()],
            ri: vec![CompressedRistretto::default()],
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
            if ExtensionDegree::try_from(i as usize).is_err() {
                proof_bytes_meddled[0] = i;
                if RistrettoRangeProof::from_bytes(&proof_bytes_meddled).is_ok() {
                    panic!("Should err");
                }
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

        let mut proof_bytes_meddled = proof_bytes.clone();
        for _i in 0..proof_bytes.len() * 10 {
            proof_bytes_meddled.append(&mut u8::MAX.to_le_bytes().to_vec());
            if RistrettoRangeProof::from_bytes(&proof_bytes_meddled).is_ok() {
                panic!("Should err");
            }
        }
    }

    #[test]
    fn test_consistency_errors() {
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
            proofs.push(RangeProof::prove("test", statements.last().unwrap(), witnesses.last().unwrap()).unwrap());
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
        gens_mismatch.g_base_vec[0] = RistrettoPoint::default();
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
        gens_mismatch.h_base = RistrettoPoint::default();
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
        let mut gens_mismatch = BulletproofGens::new(4, 1);
        gens_mismatch.g_vec[0][0] = RistrettoPoint::default();
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
        let mut gens_mismatch = BulletproofGens::new(4, 1);
        gens_mismatch.h_vec[0][0] = RistrettoPoint::default();
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
        let mut proof = RangeProof::prove("test", &statement, &witness).unwrap();

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
    fn test_verify_errors() {
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
        let mut proof = RangeProof::prove("test", &statement, &witness).unwrap();

        // Empty statement and proof vectors
        assert!(RangeProof::verify_batch("test", &[], &[proof.clone()], VerifyAction::VerifyOnly).is_err());
        assert!(RangeProof::verify_batch("test", &[statement.clone()], &[], VerifyAction::VerifyOnly).is_err());

        // Proof vector mismatches
        proof.li.pop();
        assert!(RangeProof::verify("test", &[statement.clone()], &[proof.clone()], VerifyAction::VerifyOnly).is_err());

        proof.ri.pop();
        assert!(RangeProof::verify("test", &[statement], &[proof], VerifyAction::VerifyOnly).is_err());
    }
}
