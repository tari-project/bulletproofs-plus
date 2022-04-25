// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::errors::ProofError;
use crate::hidden::Hidden;
use crate::scalar_protocol::ScalarProtocol;
use crate::transcript_protocol::TranscriptProtocol;
use crate::utils::{
    add_point_vec, add_scalar_vec, div_floor_usize, mul_point_vec_with_scalar,
    mul_scalar_vec_with_scalar, nonce,
};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use merlin::Transcript;
use non_empty_vec::NonEmpty;
use rand_core::{CryptoRng, RngCore};
use std::convert::TryFrom;

#[derive(Debug)]
pub struct InnerProductRound<'a> {
    // Common data
    gi_base: NonEmpty<RistrettoPoint>,
    hi_base: NonEmpty<RistrettoPoint>,
    g_base: RistrettoPoint,
    h_base: RistrettoPoint,
    y_powers: NonEmpty<Scalar>,
    done: bool,

    // Prover data
    ai: NonEmpty<Scalar>,
    bi: NonEmpty<Scalar>,
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
    transcript: Hidden<&'a mut Transcript>,

    //Seed for mask recovery
    round: usize,
    seed_nonce: Option<Scalar>,
}

impl<'a> InnerProductRound<'a> {
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
    ) -> Result<Self, ProofError> {
        let gi_base = NonEmpty::try_from(gi_base)
            .map_err(|e| ProofError::InvalidLength(format!("Gi - {:?}", e)))?;
        let hi_base = NonEmpty::try_from(hi_base)
            .map_err(|e| ProofError::InvalidLength(format!("Hi - {:?}", e)))?;
        let a = NonEmpty::try_from(ai)
            .map_err(|e| ProofError::InvalidLength(format!("a - {:?}", e)))?;
        let b = NonEmpty::try_from(bi)
            .map_err(|e| ProofError::InvalidLength(format!("b - {:?}", e)))?;
        let y_powers = NonEmpty::try_from(y_powers)
            .map_err(|e| ProofError::InvalidLength(format!("{:?}", e)))?;
        let n = gi_base.len().get();
        if !(hi_base.len().get() == n && a.len().get() == n && b.len().get() == n)
            || (y_powers.len().get() != (n + 2))
        {
            return Err(ProofError::InternalDataInconsistent(
                "Vector length for inner product round".to_string(),
            ));
        };
        Ok(Self {
            gi_base,
            hi_base,
            g_base,
            h_base,
            y_powers,
            done: false,
            ai: a,
            bi: b,
            alpha,
            a1: None,
            b: None,
            r1: None,
            s1: None,
            d1: None,
            li: Vec::new(),
            ri: Vec::new(),
            transcript: transcript.into(),
            round: 0,
            seed_nonce,
        })
    }

    pub fn inner_product<T: RngCore + CryptoRng>(&mut self, rng: &mut T) -> Result<(), ProofError> {
        let mut n = self.gi_base.len().get();
        if n == 1 {
            self.done = true;

            // Random masks
            // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
            let r = Scalar::random_not_zero(rng);
            // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
            let s = Scalar::random_not_zero(rng);
            let (d, eta) = if let Some(seed_nonce) = self.seed_nonce {
                (
                    nonce(&seed_nonce, "d", None)?,
                    nonce(&seed_nonce, "eta", None)?,
                )
            } else {
                // Zero is allowed by the protocol, but excluded by the implementation to be unambiguous
                (Scalar::random_not_zero(rng), Scalar::random_not_zero(rng))
            };

            let a1 = self.gi_base[0] * r
                + self.hi_base[0] * s
                + self.h_base
                    * (r * self.y_powers[1] * self.bi[0] + s * self.y_powers[1] * self.ai[0])
                + self.g_base * d;
            self.a1 = Some(a1);
            let b = self.h_base * (r * self.y_powers[1] * s) + self.g_base * eta;
            self.b = Some(b);

            self.transcript
                .validate_and_append_point(b"A1", &a1.compress())?;
            self.transcript
                .validate_and_append_point(b"B", &b.compress())?;
            let e = self.transcript.challenge_scalar(b"e")?;

            self.r1 = Some(r + self.ai[0] * e);
            self.s1 = Some(s + self.bi[0] * e);
            self.d1 = Some(eta + d * e + self.alpha * e * e);

            return Ok(());
        };

        n = div_floor_usize(n as f32, 2f32);
        let a1 = self
            .ai
            .get(..n)
            .ok_or_else(|| ProofError::InternalDataInconsistent("Zero length (a)".to_string()))?;
        let a2 = self
            .ai
            .get(n..)
            .ok_or_else(|| ProofError::InternalDataInconsistent("Zero length (a)".to_string()))?;
        let b1 = self
            .bi
            .get(..n)
            .ok_or_else(|| ProofError::InternalDataInconsistent("Zero length (b)".to_string()))?;
        let b2 = self
            .bi
            .get(n..)
            .ok_or_else(|| ProofError::InternalDataInconsistent("Zero length (b)".to_string()))?;
        let gi_base_lo = self
            .gi_base
            .get(..n)
            .ok_or_else(|| ProofError::InternalDataInconsistent("Zero length (Gi)".to_string()))?;
        let gi_base_hi = self
            .gi_base
            .get(n..)
            .ok_or_else(|| ProofError::InternalDataInconsistent("Zero length (Gi)".to_string()))?;
        let hi_base_lo = self
            .hi_base
            .get(..n)
            .ok_or_else(|| ProofError::InternalDataInconsistent("Zero length (Hi)".to_string()))?;
        let hi_base_hi = self
            .hi_base
            .get(n..)
            .ok_or_else(|| ProofError::InternalDataInconsistent("Zero length (Hi)".to_string()))?;
        let y_n_inverse = if self.y_powers[n] != Scalar::zero() {
            self.y_powers[n].invert()
        } else {
            return Err(ProofError::InternalDataInconsistent(
                "Cannot invert a zero valued Scalar".to_string(),
            ));
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
        let mut li_scalars = vec![c_l, d_l];
        let mut li_points = vec![self.h_base, self.g_base];
        let mut ri_scalars = vec![c_r, d_r];
        let mut ri_points = vec![self.h_base, self.g_base];
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
            .push(RistrettoPoint::multiscalar_mul(li_scalars, li_points));
        self.ri
            .push(RistrettoPoint::multiscalar_mul(ri_scalars, ri_points));

        self.transcript
            .validate_and_append_point(b"L", &self.li[self.li.len() - 1].compress())?;
        self.transcript
            .validate_and_append_point(b"R", &self.ri[self.ri.len() - 1].compress())?;
        let e = self.transcript.challenge_scalar(b"e")?;
        let e_inverse = e.invert();

        self.gi_base = NonEmpty::try_from(add_point_vec(
            mul_point_vec_with_scalar(gi_base_lo, &e_inverse)?.as_slice(),
            mul_point_vec_with_scalar(gi_base_hi, &(e * y_n_inverse))?.as_slice(),
        )?)
        .map_err(|e| ProofError::InvalidLength(format!("With Gi - {:?}", e)))?;
        self.hi_base = NonEmpty::try_from(add_point_vec(
            mul_point_vec_with_scalar(hi_base_lo, &e)?.as_slice(),
            mul_point_vec_with_scalar(hi_base_hi, &e_inverse)?.as_slice(),
        )?)
        .map_err(|e| ProofError::InvalidLength(format!("With Hi - {:?}", e)))?;

        self.ai = NonEmpty::try_from(add_scalar_vec(
            mul_scalar_vec_with_scalar(a1, &e)?.as_slice(),
            mul_scalar_vec_with_scalar(a2, &(self.y_powers[n] * e_inverse))?.as_slice(),
        )?)
        .map_err(|e| ProofError::InvalidLength(format!("With a - {:?}", e)))?;
        self.bi = NonEmpty::try_from(add_scalar_vec(
            mul_scalar_vec_with_scalar(b1, &e_inverse)?.as_slice(),
            mul_scalar_vec_with_scalar(b2, &e)?.as_slice(),
        )?)
        .map_err(|e| ProofError::InvalidLength(format!("With b - {:?}", e)))?;
        self.alpha = d_l * e * e + self.alpha + d_r * e_inverse * e_inverse;

        Ok(())
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn get_a1(&self) -> Result<CompressedRistretto, ProofError> {
        if let Some(a1) = self.a1 {
            Ok(a1.compress())
        } else {
            Err(ProofError::InternalDataInconsistent(
                "Value 'A' not assigned yet".to_string(),
            ))
        }
    }

    pub fn get_b(&self) -> Result<CompressedRistretto, ProofError> {
        if let Some(b) = self.b {
            Ok(b.compress())
        } else {
            Err(ProofError::InternalDataInconsistent(
                "Value 'B' not assigned yet".to_string(),
            ))
        }
    }

    pub fn get_r1(&self) -> Result<Scalar, ProofError> {
        if let Some(r1) = self.r1 {
            Ok(r1)
        } else {
            Err(ProofError::InternalDataInconsistent(
                "Value 'r1' not assigned yet".to_string(),
            ))
        }
    }

    pub fn get_s1(&self) -> Result<Scalar, ProofError> {
        if let Some(s1) = self.s1 {
            Ok(s1)
        } else {
            Err(ProofError::InternalDataInconsistent(
                "Value 's1' not assigned yet".to_string(),
            ))
        }
    }

    pub fn get_d1(&self) -> Result<Scalar, ProofError> {
        if let Some(d1) = self.d1 {
            Ok(d1)
        } else {
            Err(ProofError::InternalDataInconsistent(
                "Value 'd1' not assigned yet".to_string(),
            ))
        }
    }

    pub fn get_li(&self) -> Result<Vec<CompressedRistretto>, ProofError> {
        if !self.li.is_empty() {
            let mut li = Vec::with_capacity(self.li.len());
            for item in self.li.clone() {
                li.push(item.compress())
            }
            Ok(li)
        } else {
            Err(ProofError::InternalDataInconsistent(
                "Vector 'L' not assigned yet".to_string(),
            ))
        }
    }

    pub fn get_ri(&self) -> Result<Vec<CompressedRistretto>, ProofError> {
        if !self.ri.is_empty() {
            let mut ri = Vec::with_capacity(self.ri.len());
            for item in self.ri.clone() {
                ri.push(item.compress())
            }
            Ok(ri)
        } else {
            Err(ProofError::InternalDataInconsistent(
                "Vector 'R' not assigned yet".to_string(),
            ))
        }
    }
}
