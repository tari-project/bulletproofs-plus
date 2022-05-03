// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ inner product calculation for each round

#![allow(clippy::too_many_lines)]

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::VartimeMultiscalarMul,
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{
    errors::ProofError,
    protocols::{
        ristretto_point_protocol::RistrettoPointProtocol,
        scalar_protocol::ScalarProtocol,
        transcript_protocol::TranscriptProtocol,
    },
    utils::{generic::nonce, non_debug::NonDebug},
};

/// The struct that will hold the inner product calculation for each round, called consecutively
#[derive(Debug)]
pub struct InnerProductRound<'a> {
    // Common data
    gi_base: Vec<RistrettoPoint>,
    hi_base: Vec<RistrettoPoint>,
    g_base: RistrettoPoint,
    h_base: RistrettoPoint,
    y_powers: Vec<Scalar>,
    done: bool,

    // Prover data
    ai: Vec<Scalar>,
    bi: Vec<Scalar>,
    alpha: Scalar,

    // Verifier data
    a1: Option<RistrettoPoint>,
    b: Option<RistrettoPoint>,
    r1: Option<Scalar>,
    s1: Option<Scalar>,
    d1: Option<Scalar>,
    li: Vec<RistrettoPoint>,
    ri: Vec<RistrettoPoint>,

    // Transcript
    transcript: NonDebug<&'a mut Transcript>,

    // Seed for mask recovery
    round: usize,
    seed_nonce: Option<Scalar>,
}

impl<'a> InnerProductRound<'a> {
    #![allow(clippy::too_many_arguments)]
    /// Initialize a new 'InnerProductRound' with sanity checks
    pub fn init(
        gi_base: Vec<RistrettoPoint>,
        hi_base: Vec<RistrettoPoint>,
        g_base: RistrettoPoint,
        h_base: RistrettoPoint,
        ai: Vec<Scalar>,
        bi: Vec<Scalar>,
        alpha: Scalar,
        y_powers: Vec<Scalar>,
        transcript: &'a mut Transcript,
        seed_nonce: Option<Scalar>,
        aggregation_factor: usize,
    ) -> Result<Self, ProofError> {
        let n = gi_base.len();
        if gi_base.is_empty() || hi_base.is_empty() || ai.is_empty() || bi.is_empty() || y_powers.is_empty() {
            Err(ProofError::InvalidLength(
                "Vectors gi_base, hi_base, ai, bi and y_powers cannot be empty".to_string(),
            ))
        } else if !(hi_base.len() == n && ai.len() == n && bi.len() == n) || (y_powers.len() != (n + 2)) {
            Err(ProofError::InvalidArgument(
                "Vector length for inner product round".to_string(),
            ))
        } else {
            Ok(Self {
                gi_base,
                hi_base,
                g_base,
                h_base,
                y_powers,
                done: false,
                ai,
                bi,
                alpha,
                a1: None,
                b: None,
                r1: None,
                s1: None,
                d1: None,
                li: Vec::with_capacity(n * aggregation_factor + 2),
                ri: Vec::with_capacity(n * aggregation_factor + 2),
                transcript: transcript.into(),
                round: 0,
                seed_nonce,
            })
        }
    }

    /// Calculate the inner product, updating 'self' for each round
    pub fn inner_product<T: RngCore + CryptoRng>(&mut self, rng: &mut T) -> Result<(), ProofError> {
        let mut n = self.gi_base.len();
        if n == 1 {
            self.done = true;

            // Random masks
            // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
            let (r, s) = (Scalar::random_not_zero(rng), Scalar::random_not_zero(rng));
            let (d, eta) = if let Some(seed_nonce) = self.seed_nonce {
                (nonce(&seed_nonce, "d", None)?, nonce(&seed_nonce, "eta", None)?)
            } else {
                // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
                (Scalar::random_not_zero(rng), Scalar::random_not_zero(rng))
            };

            let a1 = self.gi_base[0] * r +
                self.hi_base[0] * s +
                self.h_base * (r * self.y_powers[1] * self.bi[0] + s * self.y_powers[1] * self.ai[0]) +
                self.g_base * d;
            self.a1 = Some(a1);
            let b = self.h_base * (r * self.y_powers[1] * s) + self.g_base * eta;
            self.b = Some(b);

            self.transcript.validate_and_append_point(b"A1", &a1.compress())?;
            self.transcript.validate_and_append_point(b"B", &b.compress())?;
            let e = self.transcript.challenge_scalar(b"e")?;

            self.r1 = Some(r + self.ai[0] * e);
            self.s1 = Some(s + self.bi[0] * e);
            self.d1 = Some(eta + d * e + self.alpha * e * e);

            return Ok(());
        };

        n /= 2; // Rounds towards zero, truncating any fractional part
        let a1 = &self.ai[..n];
        let a2 = &self.ai[n..];
        let b1 = &self.bi[..n];
        let b2 = &self.bi[n..];
        let gi_base_lo = &self.gi_base[..n];
        let gi_base_hi = &self.gi_base[n..];
        let hi_base_lo = &self.hi_base[..n];
        let hi_base_hi = &self.hi_base[n..];
        let y_n_inverse = if self.y_powers[n] == Scalar::zero() {
            return Err(ProofError::InvalidArgument(
                "Cannot invert a zero valued Scalar".to_string(),
            ));
        } else {
            self.y_powers[n].invert()
        };

        let (d_l, d_r) = if let Some(seed_nonce) = self.seed_nonce {
            (
                nonce(&seed_nonce, "dL", Some(self.round))?,
                nonce(&seed_nonce, "dR", Some(self.round))?,
            )
        } else {
            // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
            (Scalar::random_not_zero(rng), Scalar::random_not_zero(rng))
        };
        self.round += 1;

        let mut c_l = Scalar::zero();
        let mut c_r = Scalar::zero();
        for i in 0..n {
            c_l += a1[i] * self.y_powers[i + 1] * b2[i];
            c_r += a2[i] * self.y_powers[n + i + 1] * b1[i];
        }

        // Compute L and R by multi-scalar multiplication
        let mut li_scalars = Vec::with_capacity(2 * n + 2);
        li_scalars.push(c_l);
        li_scalars.push(d_l);
        let mut li_points = Vec::with_capacity(2 * n + 2);
        li_points.push(self.h_base);
        li_points.push(self.g_base);
        let mut ri_scalars = Vec::with_capacity(2 * n + 2);
        ri_scalars.push(c_r);
        ri_scalars.push(d_r);
        let mut ri_points = Vec::with_capacity(2 * n + 2);
        ri_points.push(self.h_base);
        ri_points.push(self.g_base);
        for i in 0..n {
            li_scalars.push(a1[i] * y_n_inverse);
            li_points.push(gi_base_hi[i]);
            li_scalars.push(b2[i]);
            li_points.push(hi_base_lo[i]);
            ri_scalars.push(a2[i] * self.y_powers[n]);
            ri_points.push(gi_base_lo[i]);
            ri_scalars.push(b1[i]);
            ri_points.push(hi_base_hi[i]);
        }
        self.li
            .push(RistrettoPoint::vartime_multiscalar_mul(li_scalars, li_points));
        self.ri
            .push(RistrettoPoint::vartime_multiscalar_mul(ri_scalars, ri_points));

        self.transcript
            .validate_and_append_point(b"L", &self.li[self.li.len() - 1].compress())?;
        self.transcript
            .validate_and_append_point(b"R", &self.ri[self.ri.len() - 1].compress())?;
        let e = self.transcript.challenge_scalar(b"e")?;
        let e_inverse = e.invert();

        self.gi_base = RistrettoPoint::add_point_vectors(
            RistrettoPoint::mul_point_vec_with_scalar(gi_base_lo, &e_inverse)?.as_slice(),
            RistrettoPoint::mul_point_vec_with_scalar(gi_base_hi, &(e * y_n_inverse))?.as_slice(),
        )?;
        self.hi_base = RistrettoPoint::add_point_vectors(
            RistrettoPoint::mul_point_vec_with_scalar(hi_base_lo, &e)?.as_slice(),
            RistrettoPoint::mul_point_vec_with_scalar(hi_base_hi, &e_inverse)?.as_slice(),
        )?;

        self.ai = Scalar::add_scalar_vectors(
            Scalar::mul_with_scalar_vec_with_scalar(a1, &e)?.as_slice(),
            Scalar::mul_with_scalar_vec_with_scalar(a2, &(self.y_powers[n] * e_inverse))?.as_slice(),
        )?;
        self.bi = Scalar::add_scalar_vectors(
            Scalar::mul_with_scalar_vec_with_scalar(b1, &e_inverse)?.as_slice(),
            Scalar::mul_with_scalar_vec_with_scalar(b2, &e)?.as_slice(),
        )?;
        self.alpha += d_l * e * e + d_r * e_inverse * e_inverse;

        Ok(())
    }

    /// Indicating when the inner product rounds are complete
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Compresses and returns the non-public point 'a1' using the Ristretto encoding
    pub fn a1_compressed(&self) -> Result<CompressedRistretto, ProofError> {
        if let Some(a1) = self.a1 {
            Ok(a1.compress())
        } else {
            Err(ProofError::InvalidArgument("Value 'A' not assigned yet".to_string()))
        }
    }

    /// Compresses and returns the non-public point 'b' using the Ristretto encoding
    pub fn b_compressed(&self) -> Result<CompressedRistretto, ProofError> {
        if let Some(b) = self.b {
            Ok(b.compress())
        } else {
            Err(ProofError::InvalidArgument("Value 'B' not assigned yet".to_string()))
        }
    }

    /// Returns the non-public scalar 'r1'
    pub fn r1(&self) -> Result<Scalar, ProofError> {
        if let Some(r1) = self.r1 {
            Ok(r1)
        } else {
            Err(ProofError::InvalidArgument("Value 'r1' not assigned yet".to_string()))
        }
    }

    /// Returns the non-public scalar 's1'
    pub fn s1(&self) -> Result<Scalar, ProofError> {
        if let Some(s1) = self.s1 {
            Ok(s1)
        } else {
            Err(ProofError::InvalidArgument("Value 's1' not assigned yet".to_string()))
        }
    }

    /// Returns the non-public scalar 'd1'
    pub fn d1(&self) -> Result<Scalar, ProofError> {
        if let Some(d1) = self.d1 {
            Ok(d1)
        } else {
            Err(ProofError::InvalidArgument("Value 'd1' not assigned yet".to_string()))
        }
    }

    /// Compresses and returns the non-public vector of points 'li' using the Ristretto encoding
    pub fn li_compressed(&self) -> Result<Vec<CompressedRistretto>, ProofError> {
        if self.li.is_empty() {
            Err(ProofError::InvalidArgument("Vector 'L' not assigned yet".to_string()))
        } else {
            let mut li = Vec::with_capacity(self.li.len());
            for item in self.li.clone() {
                li.push(item.compress())
            }
            Ok(li)
        }
    }

    /// Compresses and returns the non-public vector of points 'ri' using the Ristretto encoding
    pub fn ri_compressed(&self) -> Result<Vec<CompressedRistretto>, ProofError> {
        if self.ri.is_empty() {
            Err(ProofError::InvalidArgument("Vector 'R' not assigned yet".to_string()))
        } else {
            let mut ri = Vec::with_capacity(self.ri.len());
            for item in self.ri.clone() {
                ri.push(item.compress())
            }
            Ok(ri)
        }
    }
}

/// Overwrite secrets with null bytes when they go out of scope.
impl<'a> Drop for InnerProductRound<'a> {
    fn drop(&mut self) {
        for mut item in self.ai.clone() {
            item.zeroize();
        }
        for mut item in self.bi.clone() {
            item.zeroize();
        }
        self.alpha.zeroize();
        self.seed_nonce.zeroize();
    }
}
