// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ inner product calculation for each round

#![allow(clippy::too_many_lines)]

use std::ops::{Add, Mul};

use curve25519_dalek::{scalar::Scalar, traits::IsIdentity};
use itertools::izip;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{
    errors::ProofError,
    generators::pedersen_gens::ExtensionDegree,
    protocols::{curve_point_protocol::CurvePointProtocol, scalar_protocol::ScalarProtocol},
    traits::FixedBytesRepr,
    transcripts,
    utils::{generic::nonce, non_debug::NonDebug},
};

/// The struct that will hold the inner product calculation for each round, called consecutively
#[derive(Debug)]
pub struct InnerProductRound<'a, P> {
    // Common data
    gi_base: Vec<P>,
    hi_base: Vec<P>,
    g_base: Vec<P>,
    h_base: P,
    y_powers: Vec<Scalar>,
    done: bool,
    extension_degree: ExtensionDegree,

    // Prover data
    ai: Vec<Scalar>,
    bi: Vec<Scalar>,
    alpha: Vec<Scalar>,

    // Verifier data
    a1: Option<P>,
    b: Option<P>,
    r1: Option<Scalar>,
    s1: Option<Scalar>,
    d1: Vec<Scalar>,
    li: Vec<P>,
    ri: Vec<P>,

    // Transcript
    transcript: NonDebug<&'a mut Transcript>,

    // Seed for mask recovery
    round: usize,
    seed_nonce: Option<Scalar>,
}

impl<'a, P: 'a> InnerProductRound<'a, P>
where
    for<'p> &'p P: Mul<Scalar, Output = P>,
    for<'p> &'p P: Add<Output = P>,
    P: CurvePointProtocol + Clone,
    P::Compressed: FixedBytesRepr + IsIdentity,
{
    #![allow(clippy::too_many_arguments)]
    /// Initialize a new 'InnerProductRound' with sanity checks
    pub fn init(
        gi_base: Vec<P>,
        hi_base: Vec<P>,
        g_base: Vec<P>,
        h_base: P,
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
        let extension_degree = ExtensionDegree::try_from_size(g_base.len())?;
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
            transcript: transcript.into(),
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

            let mut a1 = &self.gi_base[0] * r +
                &self.hi_base[0] * s +
                &self.h_base * (r * self.y_powers[1] * self.bi[0] + s * self.y_powers[1] * self.ai[0]);
            let mut b = &self.h_base * (r * self.y_powers[1] * s);
            for k in 0..extension_degree {
                a1 += &self.g_base[k] * d[k];
                b += &self.g_base[k] * eta[k]
            }
            self.a1 = Some(a1.clone());
            self.b = Some(b.clone());

            let e =
                transcripts::transcript_points_a1_b_challenge_e(&mut self.transcript, &a1.compress(), &b.compress())?;
            let e_square = e * e;

            self.r1 = Some(r + self.ai[0] * e);
            self.s1 = Some(s + self.bi[0] * e);
            self.d1 = izip!(eta, d, self.alpha.iter())
                .map(|(eta, d, alpha)| eta + d * e + alpha * e_square)
                .collect();

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
        let y_n_inverse = if self.y_powers[n] == Scalar::ZERO {
            return Err(ProofError::InvalidArgument(
                "Cannot invert a zero valued Scalar".to_string(),
            ));
        } else {
            self.y_powers[n].invert()
        };
        let a1_offset = a1.iter().map(|s| s * y_n_inverse).collect::<Vec<Scalar>>();
        let a2_offset = a2.iter().map(|s| s * self.y_powers[n]).collect::<Vec<Scalar>>();

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

        let c_l = izip!(a1, self.y_powers.iter().skip(1), b2)
            .fold(Scalar::ZERO, |acc, (a, y_power, b)| acc + a * y_power * b);
        let c_r = izip!(a2, self.y_powers.iter().skip(n + 1), b1)
            .fold(Scalar::ZERO, |acc, (a, y_power, b)| acc + a * y_power * b);

        // Compute L and R by multi-scalar multiplication
        self.li.push(P::vartime_multiscalar_mul(
            std::iter::once(&c_l)
                .chain(d_l.iter())
                .chain(a1_offset.iter())
                .chain(b2.iter()),
            std::iter::once(&self.h_base)
                .chain(self.g_base.iter())
                .chain(gi_base_hi)
                .chain(hi_base_lo),
        ));
        self.ri.push(P::vartime_multiscalar_mul(
            std::iter::once(&c_r)
                .chain(d_r.iter())
                .chain(a2_offset.iter())
                .chain(b1.iter()),
            std::iter::once(&self.h_base)
                .chain(self.g_base.iter())
                .chain(gi_base_lo)
                .chain(hi_base_hi),
        ));

        // Get the round challenge and associated values
        let e = transcripts::transcript_points_l_r_challenge_e(
            &mut self.transcript,
            &self
                .li
                .last()
                .ok_or(ProofError::InvalidLength("Bad inner product vector length".to_string()))?
                .compress(),
            &self
                .ri
                .last()
                .ok_or(ProofError::InvalidLength("Bad inner product vector length".to_string()))?
                .compress(),
        )?;
        let e_square = e * e;
        let e_inverse = e.invert();
        let e_inverse_square = e_inverse * e_inverse;

        // Fold the vectors
        let e_y_n_inverse = e * y_n_inverse;
        self.gi_base = gi_base_lo
            .iter()
            .zip(gi_base_hi.iter())
            .map(|(lo, hi)| P::vartime_multiscalar_mul([&e_inverse, &e_y_n_inverse], [lo, hi]))
            .collect();
        self.hi_base = hi_base_lo
            .iter()
            .zip(hi_base_hi.iter())
            .map(|(lo, hi)| P::vartime_multiscalar_mul([&e, &e_inverse], [lo, hi]))
            .collect();
        self.ai = a1
            .iter()
            .zip(a2_offset.iter())
            .map(|(a1, a2)| a1 * e + a2 * e_inverse)
            .collect();
        self.bi = b1
            .iter()
            .zip(b2.iter())
            .map(|(b1, b2)| b1 * e_inverse + b2 * e)
            .collect();

        for (alpha, (l, r)) in self.alpha.iter_mut().zip(d_l.iter().zip(d_r.iter())) {
            *alpha += l * e_square + r * e_inverse_square;
        }

        Ok(())
    }

    /// Indicating when the inner product rounds are complete
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Compresses and returns the non-public point 'a1'
    pub fn a1_compressed(&self) -> Result<P::Compressed, ProofError> {
        if let Some(ref a1) = self.a1 {
            Ok(a1.compress())
        } else {
            Err(ProofError::InvalidArgument("Value 'A' not assigned yet".to_string()))
        }
    }

    /// Compresses and returns the non-public point 'b'
    pub fn b_compressed(&self) -> Result<P::Compressed, ProofError> {
        if let Some(ref b) = self.b {
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

    /// Compresses and returns the non-public vector of points 'li'
    pub fn li_compressed(&self) -> Result<Vec<P::Compressed>, ProofError> {
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

    /// Compresses and returns the non-public vector of points 'ri'
    pub fn ri_compressed(&self) -> Result<Vec<P::Compressed>, ProofError> {
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
impl<'a, P> Drop for InnerProductRound<'a, P> {
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

#[cfg(test)]
mod test {
    use curve25519_dalek::RistrettoPoint;
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn test_init_errors() {
        let mut transcript = Transcript::new(b"test");
        let p = RistrettoPoint::default();
        let s = Scalar::default();

        // Empty vectors
        let round = InnerProductRound::init(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            RistrettoPoint::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &mut transcript,
            None,
            1,
        );
        round.unwrap_err();

        // Mismatched lengths
        let round = InnerProductRound::init(
            vec![p, p],
            vec![p],
            Vec::new(),
            RistrettoPoint::default(),
            vec![s],
            vec![s],
            Vec::new(),
            vec![s],
            &mut transcript,
            None,
            1,
        );
        round.unwrap_err();

        let round = InnerProductRound::init(
            vec![p],
            vec![p],
            Vec::new(),
            RistrettoPoint::default(),
            vec![s],
            vec![s],
            Vec::new(),
            vec![s],
            &mut transcript,
            None,
            1,
        );
        round.unwrap_err();

        // Extension degree
        let round = InnerProductRound::init(
            vec![p],
            vec![p],
            vec![p],
            RistrettoPoint::default(),
            vec![s],
            vec![s],
            vec![s, s],
            vec![s, s, s],
            &mut transcript,
            None,
            1,
        );
        round.unwrap_err();
    }

    #[test]
    fn test_inversion() {
        let mut transcript = Transcript::new(b"test");
        let p = RistrettoPoint::default();
        let s = Scalar::default();
        let mut rng = OsRng;

        // Fail an inversion
        let mut round = InnerProductRound::init(
            vec![p, p],
            vec![p, p],
            vec![p],
            RistrettoPoint::default(),
            vec![s, s],
            vec![s, s],
            vec![s],
            vec![s, s, s, s],
            &mut transcript,
            None,
            1,
        )
        .unwrap();
        round.inner_product(&mut rng).unwrap_err();
    }

    #[test]
    fn test_getters() {
        let mut transcript = Transcript::new(b"test");
        let p = RistrettoPoint::default();
        let s = Scalar::default();

        // Set up a valid round initialization
        let round = InnerProductRound::init(
            vec![p, p],
            vec![p, p],
            vec![p],
            RistrettoPoint::default(),
            vec![s, s],
            vec![s, s],
            vec![s],
            vec![s, s, s, s],
            &mut transcript,
            None,
            1,
        )
        .unwrap();

        // Each getter should fail, since we haven't actually done a round yet
        round.a1_compressed().unwrap_err();
        round.b_compressed().unwrap_err();
        round.r1().unwrap_err();
        round.s1().unwrap_err();
        round.d1().unwrap_err();
        round.li_compressed().unwrap_err();
        round.ri_compressed().unwrap_err();
    }
}
