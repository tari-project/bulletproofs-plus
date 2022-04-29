// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ public range proof parameters intended for a verifier

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul},
};
use merlin::Transcript;
use rand::thread_rng;

use crate::{
    errors::ProofError,
    inner_product_round::InnerProductRound,
    range_statement::RangeStatement,
    range_witness::RangeWitness,
    scalar_protocol::ScalarProtocol,
    transcript_protocol::TranscriptProtocol,
    utils::{bit_vector_of_scalars, nonce},
};

/// Contains the public range proof parameters intended for a verifier
#[derive(Clone, Debug)]
pub struct RangeProof {
    a: CompressedRistretto,
    a1: CompressedRistretto,
    b: CompressedRistretto,
    r1: Scalar,
    s1: Scalar,
    d1: Scalar,
    li: Vec<CompressedRistretto>,
    ri: Vec<CompressedRistretto>,
}

impl RangeProof {
    /// The maximum bit length that proofs can be generated for
    pub const MAX_BIT_LENGTH: usize = 64;

    fn a_decompressed(&self) -> Result<RistrettoPoint, ProofError> {
        self.a.decompress().ok_or_else(|| {
            ProofError::InvalidArgument("Member 'a' was not the canonical encoding of a point".to_string())
        })
    }

    fn a1_decompressed(&self) -> Result<RistrettoPoint, ProofError> {
        self.a1.decompress().ok_or_else(|| {
            ProofError::InvalidArgument("Member 'a1' was not the canonical encoding of a point".to_string())
        })
    }

    fn b_decompressed(&self) -> Result<RistrettoPoint, ProofError> {
        self.b.decompress().ok_or_else(|| {
            ProofError::InvalidArgument("Member 'b' was not the canonical encoding of a point".to_string())
        })
    }

    fn li_decompressed(&self) -> Result<Vec<RistrettoPoint>, ProofError> {
        if self.li.is_empty() {
            Err(ProofError::InvalidArgument("Vector 'L' not assigned yet".to_string()))
        } else {
            let mut li = Vec::with_capacity(self.li.len());
            for item in self.li.clone() {
                li.push(item.decompress().ok_or_else(|| {
                    ProofError::InvalidArgument(
                        "An item in member 'L' was not the canonical encoding of a point".to_string(),
                    )
                })?)
            }
            Ok(li)
        }
    }

    fn li(&self) -> Result<Vec<CompressedRistretto>, ProofError> {
        if self.li.is_empty() {
            Err(ProofError::InvalidArgument("Vector 'L' not assigned yet".to_string()))
        } else {
            Ok(self.li.clone())
        }
    }

    fn ri_decompressed(&self) -> Result<Vec<RistrettoPoint>, ProofError> {
        if self.ri.is_empty() {
            Err(ProofError::InvalidArgument("Vector 'R' not assigned yet".to_string()))
        } else {
            let mut ri = Vec::with_capacity(self.ri.len());
            for item in self.ri.clone() {
                ri.push(item.decompress().ok_or_else(|| {
                    ProofError::InvalidArgument(
                        "An item in member 'R' was not the canonical encoding of a point".to_string(),
                    )
                })?)
            }
            Ok(ri)
        }
    }

    fn ri(&self) -> Result<Vec<CompressedRistretto>, ProofError> {
        if self.ri.is_empty() {
            Err(ProofError::InvalidArgument("Vector 'R' not assigned yet".to_string()))
        } else {
            Ok(self.ri.clone())
        }
    }

    /// Create a single or aggregated range proof for a single party that knows all the secrets
    /// The prover must ensure that the commitments and witness opening data are consistent
    pub fn prove(
        transcript: &mut Transcript,
        statement: &RangeStatement,
        witness: &RangeWitness,
    ) -> Result<RangeProof, ProofError> {
        let batch_size = statement.commitments.len();
        if witness.openings.len() != batch_size {
            return Err(ProofError::InvalidLength(
                "Invalid range statement - commitments and openings do not match!".to_string(),
            ));
        }

        let bit_length = statement.generators.bit_length();

        // Global generators
        let (h_base, g_base) = (statement.generators.h_base(), statement.generators.g_base());
        let h_base_compressed = statement.generators.h_base_compressed();
        let g_base_compressed = statement.generators.g_base_compressed();
        let (hi_base, gi_base) = (statement.generators.hi_base(), statement.generators.gi_base());

        transcript.domain_separator(b"Bulletproofs+", b"Range Proof");
        transcript.validate_and_append_point(b"H", &h_base_compressed)?;
        transcript.validate_and_append_point(b"G", &g_base_compressed)?;
        transcript.append_u64(b"N", bit_length as u64);
        transcript.append_u64(b"M", batch_size as u64);
        for item in statement.commitments_compressed.clone() {
            transcript.append_point(b"Ci", &item);
        }
        for item in statement.minimum_value_promises.clone() {
            if let Some(minimum_value) = item {
                transcript.append_u64(b"vi - minimum_value", minimum_value);
            } else {
                transcript.append_u64(b"vi - minimum_value", 0);
            }
        }

        // Set bit arrays
        let mut a_li = Vec::with_capacity(bit_length * batch_size);
        let mut a_ri = Vec::with_capacity(bit_length * batch_size);
        for j in 0..batch_size {
            let bit_vector = if let Some(minimum_value) = statement.minimum_value_promises[j] {
                if minimum_value > witness.openings[j].v {
                    return Err(ProofError::InvalidArgument(
                        "Minimum value cannot be larger than value!".to_string(),
                    ));
                } else {
                    bit_vector_of_scalars(witness.openings[j].v - minimum_value, bit_length)?
                }
            } else {
                bit_vector_of_scalars(witness.openings[j].v, bit_length)?
            };
            for bit_field in bit_vector.clone() {
                a_li.push(bit_field);
                a_ri.push(bit_field - Scalar::one());
            }
        }

        // Compute A by multi-scalar multiplication
        let rng = &mut thread_rng();
        let alpha = if let Some(seed_nonce) = statement.seed_nonce {
            nonce(&seed_nonce, "alpha", None)?
        } else {
            // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
            Scalar::random_not_zero(rng)
        };
        let mut ai_scalars = Vec::with_capacity(bit_length * batch_size + 1);
        ai_scalars.push(alpha);
        let mut ai_points = Vec::with_capacity(bit_length * batch_size + 1);
        ai_points.push(g_base);
        for i in 0..(bit_length * batch_size) {
            ai_scalars.push(a_li[i]);
            ai_points.push(gi_base[i]);
            ai_scalars.push(a_ri[i]);
            ai_points.push(hi_base[i]);
        }
        let a = RistrettoPoint::vartime_multiscalar_mul(ai_scalars, ai_points);
        transcript.validate_and_append_point(b"A", &a.compress())?;

        // Get challenges
        let (y, z) = (transcript.challenge_scalar(b"y")?, transcript.challenge_scalar(b"z")?);
        let z_square = z * z;

        // Compute powers of the challenge
        let mut y_powers = Vec::with_capacity(batch_size * bit_length + 2);
        y_powers.push(Scalar::one());
        for _ in 1..(batch_size * bit_length + 2) {
            y_powers.push(y_powers[y_powers.len() - 1] * y);
        }

        // Compute d efficiently
        let mut d = Vec::with_capacity(bit_length + bit_length * batch_size);
        d.push(z_square);
        let two = Scalar::from(2u8);
        for i in 1..bit_length {
            d.push(two * d[i - 1]);
        }
        for j in 1..batch_size {
            for i in 0..bit_length {
                d.push(d[(j - 1) * bit_length + i] * z_square);
            }
        }

        // Prepare for inner product
        let mut a_li_1 = Vec::with_capacity(a_li.len());
        for item in a_li {
            a_li_1.push(item - z);
        }
        let mut a_ri_1 = Vec::with_capacity(a_ri.len());
        for i in 0..a_ri.len() {
            a_ri_1.push(a_ri[i] + d[i] * y_powers[bit_length * batch_size - i] + z);
        }
        let mut alpha1 = alpha;
        let mut z_even_powers = Scalar::one();
        for j in 0..batch_size {
            z_even_powers *= z_square;
            alpha1 += z_even_powers * witness.openings[j].r * y_powers[bit_length * batch_size + 1];
        }

        // Calculate the inner product
        transcript.domain_separator(b"Bulletproofs+", b"Inner Product Proof");
        let mut ip_data = InnerProductRound::init(
            gi_base,
            hi_base,
            g_base,
            h_base,
            a_li_1,
            a_ri_1,
            alpha1,
            y_powers,
            transcript,
            statement.seed_nonce,
            batch_size,
        )?;
        loop {
            let _result = ip_data.inner_product(rng);
            if ip_data.is_done() {
                return Ok(RangeProof {
                    a: a.compress(),
                    a1: ip_data.get_a1()?,
                    b: ip_data.get_b()?,
                    r1: ip_data.get_r1()?,
                    s1: ip_data.get_s1()?,
                    d1: ip_data.get_d1()?,
                    li: ip_data.get_li()?,
                    ri: ip_data.get_ri()?,
                });
            }
        }
    }

    /// Verify a batch of single and/or aggregated range proofs as a public entity, or recover the masks for single
    /// range proofs by a party that can supply the optional seed nonces
    pub fn verify(
        transcript_label: &'static str,
        statements: &[RangeStatement],
        range_proofs: &[RangeProof],
    ) -> Result<Vec<Option<Scalar>>, ProofError> {
        // Consistency checks
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

        // Verify generators consistency & select largest batch
        let (g_base, h_base) = (statements[0].generators.g_base(), statements[0].generators.h_base());
        let (g_base_compressed, h_base_compressed) = (
            statements[0].generators.g_base_compressed(),
            statements[0].generators.h_base_compressed(),
        );
        let bit_length = statements[0].generators.bit_length();
        let mut max_mn = statements[0].commitments.len() * statements[0].generators.bit_length();
        let (mut gi_base, mut hi_base) = (statements[0].generators.gi_base(), statements[0].generators.hi_base());
        let mut max_index = 0;
        for (i, statement) in statements.iter().enumerate().skip(1) {
            if g_base != statement.generators.g_base() {
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
            if statement.commitments.len() * statement.generators.bit_length() > max_mn {
                max_mn = statement.commitments.len() * statement.generators.bit_length();
                max_index = i;
                gi_base = statement.generators.gi_base();
                hi_base = statement.generators.hi_base();
            }
        }
        for (i, statement) in statements.iter().enumerate() {
            if i == max_index {
                continue;
            }
            for (j, this_gi_base) in gi_base.iter().enumerate().take(statement.generators.gi_base().len()) {
                if gi_base[j] != *this_gi_base {
                    return Err(ProofError::InvalidArgument(
                        "Inconsistent Gi generator point vector in batch statement".to_string(),
                    ));
                }
            }
            for (j, this_hi_base) in hi_base.iter().enumerate().take(statement.generators.hi_base().len()) {
                if hi_base[j] != *this_hi_base {
                    return Err(ProofError::InvalidArgument(
                        "Inconsistent Hi generator point vector in batch statement".to_string(),
                    ));
                }
            }
        }

        // Compute log2(N)
        let mut log_n = 0;
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
        two_n_minus_one -= Scalar::one();

        // Weighted coefficients for common generators
        let mut g_base_scalar = Scalar::zero();
        let mut h_base_scalar = Scalar::zero();
        let mut gi_base_scalars = vec![Scalar::zero(); max_mn];
        let mut hi_base_scalars = vec![Scalar::zero(); max_mn];

        // Final multiscalar multiplication data
        let mut msm_len = 0;
        for (index, item) in statements.iter().enumerate() {
            msm_len += item.generators.batch_size() + 3 + range_proofs[index].li.len() * 2;
        }
        msm_len += 2 + max_mn * 2;
        let mut scalars: Vec<Scalar> = Vec::with_capacity(msm_len);
        let mut points: Vec<RistrettoPoint> = Vec::with_capacity(msm_len);

        // Recovered masks
        let mut masks = Vec::with_capacity(range_proofs.len());

        let two = Scalar::from(2u8);

        // Process each proof and add it to the batch
        let rng = &mut thread_rng();
        for (index, proof) in range_proofs.iter().enumerate() {
            let commitments = statements[index].commitments.clone();
            let minimum_value_promises = statements[index].minimum_value_promises.clone();
            let a = proof.a_decompressed()?;
            let a1 = proof.a1_decompressed()?;
            let b = proof.b_decompressed()?;
            let r1 = proof.r1;
            let s1 = proof.s1;
            let d1 = proof.d1;
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
            let batch_size = commitments.len();
            let rounds = li.len();

            // Batch weight (may not be equal to a zero valued scalar) - this may not be zero ever
            let weight = Scalar::random_not_zero(rng);

            // Start the transcript
            let mut transcript = Transcript::new(transcript_label.as_bytes());
            transcript.domain_separator(b"Bulletproofs+", b"Range Proof");
            transcript.validate_and_append_point(b"H", &h_base_compressed)?;
            transcript.validate_and_append_point(b"G", &g_base_compressed)?;
            transcript.append_u64(b"N", bit_length as u64);
            transcript.append_u64(b"M", batch_size as u64);
            for i in 0..(statements[index].commitments_compressed.len()) {
                transcript.append_point(b"Ci", &statements[index].commitments_compressed[i]);
            }
            for item in statements[index].minimum_value_promises.clone() {
                if let Some(minimum_value) = item {
                    transcript.append_u64(b"vi - minimum_value", minimum_value);
                } else {
                    transcript.append_u64(b"vi - minimum_value", 0);
                }
            }

            // Reconstruct challenges
            transcript.validate_and_append_point(b"A", &proof.a)?;
            let y = transcript.challenge_scalar(b"y")?;
            let z = transcript.challenge_scalar(b"z")?;
            transcript.domain_separator(b"Bulletproofs+", b"Inner Product Proof");
            let mut challenges = Vec::with_capacity(rounds);
            for j in 0..rounds {
                transcript.validate_and_append_point(b"L", &proof.li()?[j])?;
                transcript.validate_and_append_point(b"R", &proof.ri()?[j])?;
                let e = transcript.challenge_scalar(b"e")?;
                challenges.push(e);
            }
            let mut challenges_inv = challenges.clone();
            let _ = Scalar::batch_invert(&mut challenges_inv);
            transcript.validate_and_append_point(b"A1", &proof.a1)?;
            transcript.validate_and_append_point(b"B", &proof.b)?;
            let e = transcript.challenge_scalar(b"e")?;

            // Compute useful challenge values
            let z_square = z * z;
            let e_square = e * e;
            let y_inverse = y.invert();
            let mut y_nm = y;
            for _ in 0..rounds {
                y_nm = y_nm * y_nm;
            }
            let y_nm_1 = y_nm * y;
            let mut y_sum = Scalar::zero();
            let mut y_sum_temp = y;
            for _ in 0..bit_length * batch_size {
                y_sum += y_sum_temp;
                y_sum_temp *= y;
            }

            // Compute d efficiently
            let mut d = Vec::with_capacity(bit_length + bit_length * batch_size);
            d.push(z_square);
            for i in 1..bit_length {
                d.push(two * d[i - 1]);
            }
            for j in 1..batch_size {
                for i in 0..bit_length {
                    d.push(d[(j - 1) * bit_length + i] * z_square);
                }
            }

            // Compute its sum efficiently
            let mut d_sum = z_square;
            let mut d_sum_temp_z = z_square;
            let mut d_sum_temp_2m = 2 * batch_size;
            while d_sum_temp_2m > 2 {
                d_sum = d_sum + d_sum * d_sum_temp_z;
                d_sum_temp_z = d_sum_temp_z * d_sum_temp_z;
                d_sum_temp_2m /= 2; // Rounds towards zero, truncating any fractional part
            }
            d_sum *= two_n_minus_one;

            // Recover the mask if possible (only for non-aggregated proofs)
            if let Some(seed_nonce) = statements[index].seed_nonce {
                let mut mask = (d1 - nonce(&seed_nonce, "eta", None)? - e * nonce(&seed_nonce, "d", None)?) *
                    e.invert() *
                    e.invert();
                mask -= nonce(&seed_nonce, "alpha", None)?;
                for j in 0..rounds {
                    mask -= challenges[j] * challenges[j] * nonce(&seed_nonce, "dL", Some(j))?;
                    mask -= challenges_inv[j] * challenges_inv[j] * nonce(&seed_nonce, "dR", Some(j))?;
                }
                mask *= (z_square * y_nm_1).invert();
                masks.push(Some(mask));
            } else {
                masks.push(None);
            }

            // Aggregate the generator scalars
            let mut y_inv_i = Scalar::one();
            let mut y_nm_i = y_nm;
            for i in 0..batch_size * bit_length {
                let mut g = r1 * e * y_inv_i;
                let mut h = s1 * e;
                for j in 0..rounds {
                    let k = rounds - j - 1;
                    if (i >> j) & 1 > 0 {
                        g *= challenges[k];
                        h *= challenges_inv[k];
                    } else {
                        g *= challenges_inv[k];
                        h *= challenges[k];
                    }
                }
                gi_base_scalars[i] += weight * (g + e_square * z);
                hi_base_scalars[i] += weight * (h - e_square * (d[i] * y_nm_i + z));
                y_inv_i *= y_inverse;
                y_nm_i *= y_inverse;
            }

            // Remaining terms
            let mut z_even_powers = Scalar::one();
            for k in 0..batch_size {
                z_even_powers *= z_square;
                let weighted = weight * (-e_square * z_even_powers * y_nm_1);
                scalars.push(weighted);
                points.push(commitments[k]);
                if let Some(minimum_value) = minimum_value_promises[k] {
                    h_base_scalar -= weighted * Scalar::from(minimum_value);
                }
            }

            h_base_scalar += weight * (r1 * y * s1 + e_square * (y_nm_1 * z * d_sum + (z_square - z) * y_sum));
            g_base_scalar += weight * d1;

            scalars.push(weight * (-e));
            points.push(a1);
            scalars.push(-weight);
            points.push(b);
            scalars.push(weight * (-e_square));
            points.push(a);

            for j in 0..rounds {
                scalars.push(weight * (-e_square * challenges[j] * challenges[j]));
                points.push(li[j]);
                scalars.push(weight * (-e_square * challenges_inv[j] * challenges_inv[j]));
                points.push(ri[j]);
            }
        }

        // Common generators
        scalars.push(g_base_scalar);
        points.push(g_base);
        scalars.push(h_base_scalar);
        points.push(h_base);
        for i in 0..max_mn {
            scalars.push(gi_base_scalars[i]);
            points.push(gi_base[i]);
            scalars.push(hi_base_scalars[i]);
            points.push(hi_base[i]);
        }

        println!("my calc: {}, actual: {}", msm_len, scalars.len());
        if RistrettoPoint::vartime_multiscalar_mul(scalars, points) != RistrettoPoint::identity() {
            return Err(ProofError::VerificationFailed(
                "Range proof batch not valid".to_string(),
            ));
        }

        Ok(masks)
    }
}
