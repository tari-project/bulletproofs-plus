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
    generators::pedersen_gens::ExtensionDegree,
    protocols::{ristretto_point_protocol::RistrettoPointProtocol, scalar_protocol::ScalarProtocol},
    range_proof::RangeProof,
    utils::generic::nonce,
    PedersenGens,
};

/// The struct that will hold the inner product calculation for each round, called consecutively
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct InnerProductRound<'a> {
    // Common data
    gi_base: Vec<RistrettoPoint>,
    hi_base: Vec<RistrettoPoint>,
    g_base: Vec<RistrettoPoint>,
    h_base: RistrettoPoint,
    y_powers: Vec<Scalar>,
    done: bool,
    extension_degree: ExtensionDegree,

    // Prover data
    ai: Vec<Scalar>,
    bi: Vec<Scalar>,
    alpha: Vec<Scalar>,

    // Verifier data
    a1: Option<RistrettoPoint>,
    b: Option<RistrettoPoint>,
    r1: Option<Scalar>,
    s1: Option<Scalar>,
    d1: Vec<Scalar>,
    li: Vec<RistrettoPoint>,
    ri: Vec<RistrettoPoint>,

    // Transcript
    #[derivative(Debug = "ignore")]
    transcript: &'a mut Transcript,

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
        g_base: Vec<RistrettoPoint>,
        h_base: RistrettoPoint,
        ai: Vec<Scalar>,
        bi: Vec<Scalar>,
        alpha: Vec<Scalar>,
        y_powers: Vec<Scalar>,
        transcript: &'a mut Transcript,
        seed_nonce: Option<Scalar>,
        aggregation_factor: usize,
    ) -> Result<Self, ProofError> {
        let n = gi_base.len();
        if gi_base.is_empty() || hi_base.is_empty() || ai.is_empty() || bi.is_empty() || y_powers.is_empty() {
            return Err(ProofError::InvalidLength(
                "Vectors gi_base, hi_base, ai, bi and y_powers cannot be empty".to_string(),
            ));
        }
        if !(hi_base.len() == n && ai.len() == n && bi.len() == n) || (y_powers.len() != (n + 2)) {
            return Err(ProofError::InvalidArgument(
                "Vector length for inner product round".to_string(),
            ));
        }
        let extension_degree = PedersenGens::extension_degree(g_base.len())?;
        if extension_degree as usize != alpha.len() {
            return Err(ProofError::InvalidLength("Inconsistent extension degree".to_string()));
        }
        Ok(Self {
            gi_base,
            hi_base,
            g_base,
            h_base,
            y_powers,
            done: false,
            extension_degree,
            ai,
            bi,
            alpha,
            a1: None,
            b: None,
            r1: None,
            s1: None,
            d1: Vec::with_capacity(extension_degree as usize),
            li: Vec::with_capacity(n * aggregation_factor + 2),
            ri: Vec::with_capacity(n * aggregation_factor + 2),
            transcript,
            round: 0,
            seed_nonce,
        })
    }

    /// Calculate the inner product, updating 'self' for each round
    pub fn inner_product<T: RngCore + CryptoRng>(&mut self, rng: &mut T) -> Result<(), ProofError> {
        let mut n = self.gi_base.len();
        let extension_degree = self.extension_degree as usize;
        if n == 1 {
            self.done = true;

            // Random masks
            // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
            let (r, s) = (Scalar::random_not_zero(rng), Scalar::random_not_zero(rng));
            let (mut d, mut eta) = (
                Vec::with_capacity(extension_degree),
                Vec::with_capacity(extension_degree),
            );
            if let Some(seed_nonce) = self.seed_nonce {
                for k in 0..extension_degree {
                    d.push((nonce(&seed_nonce, "d", None, Some(k)))?);
                    eta.push((nonce(&seed_nonce, "eta", None, Some(k)))?);
                }
            } else {
                for _k in 0..extension_degree {
                    // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
                    d.push(Scalar::random_not_zero(rng));
                    eta.push(Scalar::random_not_zero(rng));
                }
            };

            let mut a1 = self.gi_base[0] * r +
                self.hi_base[0] * s +
                self.h_base * (r * self.y_powers[1] * self.bi[0] + s * self.y_powers[1] * self.ai[0]);
            let mut b = self.h_base * (r * self.y_powers[1] * s);
            for k in 0..extension_degree {
                a1 += self.g_base[k] * d[k];
                b += self.g_base[k] * eta[k]
            }
            self.a1 = Some(a1);
            self.b = Some(b);

            let e = RangeProof::transcript_points_a1_b_challenge_e(self.transcript, &a1.compress(), &b.compress())?;

            self.r1 = Some(r + self.ai[0] * e);
            self.s1 = Some(s + self.bi[0] * e);
            let e_square = e * e;
            for k in 0..extension_degree {
                self.d1.push(eta[k] + d[k] * e + self.alpha[k] * e_square)
            }

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

        let (mut d_l, mut d_r) = (
            Vec::with_capacity(extension_degree),
            Vec::with_capacity(extension_degree),
        );
        if let Some(seed_nonce) = self.seed_nonce {
            for k in 0..extension_degree {
                d_l.push((nonce(&seed_nonce, "dL", Some(self.round), Some(k)))?);
                d_r.push((nonce(&seed_nonce, "dR", Some(self.round), Some(k)))?);
            }
        } else {
            for _k in 0..extension_degree {
                // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
                d_l.push(Scalar::random_not_zero(rng));
                d_r.push(Scalar::random_not_zero(rng));
            }
        };
        self.round += 1;

        let mut c_l = Scalar::zero();
        let mut c_r = Scalar::zero();
        for i in 0..n {
            c_l += a1[i] * self.y_powers[i + 1] * b2[i];
            c_r += a2[i] * self.y_powers[n + i + 1] * b1[i];
        }

        // Compute L and R by multi-scalar multiplication
        let mut li_scalars = Vec::with_capacity(2 * n + 1 + extension_degree);
        li_scalars.push(c_l);
        let mut li_points = Vec::with_capacity(2 * n + 1 + extension_degree);
        li_points.push(self.h_base);
        let mut ri_scalars = Vec::with_capacity(2 * n + 1 + extension_degree);
        ri_scalars.push(c_r);
        let mut ri_points = Vec::with_capacity(2 * n + 1 + extension_degree);
        ri_points.push(self.h_base);
        for k in 0..extension_degree {
            li_scalars.push(d_l[k]);
            li_points.push(self.g_base[k]);
            ri_scalars.push(d_r[k]);
            ri_points.push(self.g_base[k]);
        }
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

        let e = RangeProof::transcript_points_l_r_challenge_e(
            self.transcript,
            &self.li[self.li.len() - 1].compress(),
            &self.ri[self.ri.len() - 1].compress(),
        )?;
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
            Scalar::mul_scalar_vec_with_scalar(a1, &e)?.as_slice(),
            Scalar::mul_scalar_vec_with_scalar(a2, &(self.y_powers[n] * e_inverse))?.as_slice(),
        )?;
        self.bi = Scalar::add_scalar_vectors(
            Scalar::mul_scalar_vec_with_scalar(b1, &e_inverse)?.as_slice(),
            Scalar::mul_scalar_vec_with_scalar(b2, &e)?.as_slice(),
        )?;
        let e_square = e * e;
        let e_inverse_square = e_inverse * e_inverse;
        for k in 0..extension_degree {
            self.alpha[k] += d_l[k] * e_square + d_r[k] * e_inverse_square;
        }

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
    pub fn d1(&self) -> Result<Vec<Scalar>, ProofError> {
        if self.d1.is_empty() {
            Err(ProofError::InvalidArgument("Value 'd1' not assigned yet".to_string()))
        } else {
            Ok(self.d1.clone())
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
