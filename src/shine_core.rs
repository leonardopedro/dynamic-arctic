// Copyright 2024 Ian Goldberg
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the “Software”), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::lagrange::*;
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::VartimeRistrettoPrecomputation;
use curve25519_dalek::scalar::Scalar;
   
use curve25519_dalek::traits::Identity;
use curve25519_dalek::traits::VartimePrecomputedMultiscalarMul;
use itertools::Itertools;
use rand::RngCore;
use sha2::digest::FixedOutput;
use sha2::Digest;
use sha2::Sha256;

// Compute (m choose k) when m^k < 2^64
fn binom(m: u32, k: u32) -> u64 {
    let mut numer = 1u64;
    let mut denom = 1u64;
    for i in 0u64..(k as u64) {
        numer *= (m as u64) - i;
        denom *= i + 1;
    }
    numer / denom
}

// The hash function used to create the coefficients for the
// pseudorandom secret sharing.
fn hash1(phi: &[u8; 32], w: &[u8]) -> Scalar {
    let mut hash = Sha256::new();
    hash.update(phi);
    hash.update(w);
    let mut hashval = [0u8; 32];
    hashval.copy_from_slice(&hash.finalize());
    Scalar::from_bytes_mod_order(hashval)
}

// The key for player k will consist of a vector of (v, phi) tuples,
// where the v values enumerate all lists of t-1 player numbers (from
// 1 to n) that do _not_ include k
#[derive(Debug)]
pub struct Key {
    pub n: u32,
    pub t: u32,
    pub k: u32,
    pub secrets: Vec<(Vec<u32>, [u8; 32])>,
}

impl Key {
    pub fn keygen(n: u32, t: u32) -> Vec<Self> {
        let delta = binom(n - 1, t - 1);
        let mut rng = rand::thread_rng();
        let mut res: Vec<Self> = Vec::with_capacity(n as usize);
        for k in 1..=n {
            res.push(Self {
                n,
                t,
                k,
                secrets: Vec::with_capacity(delta as usize),
            });
        }
        let si = (1..=n).combinations((t - 1) as usize);

        for v in si {
            // For each subset of size t-1, pick a random secret, and
            // give it to all players _not_ in that subset
            let mut phi: [u8; 32] = [0; 32];
            rng.fill_bytes(&mut phi);
            let mut vnextind = 0usize;
            let mut vnext = v[0];
            for i in 1..=n {
                if i < vnext {
                    res[(i - 1) as usize].secrets.push((v.clone(), phi));
                } else {
                    vnextind += 1;
                    vnext = if vnextind < ((t - 1) as usize) {
                        v[vnextind]
                    } else {
                        n + 1
                    };
                }
            }
        }
        res
    }
}

#[test]
pub fn test_keygen() {
    let keys = Key::keygen(7, 4);

    println!("key for player 3: {:?}", keys[2]);
    println!("key for player 7: {:?}", keys[6]);
}

#[derive(Debug)]
pub struct PreprocKey {
    pub n: u32,
    pub t: u32,
    pub k: u32,
    pub secrets: Vec<([u8; 32], Scalar)>,
}

impl PreprocKey {
    pub fn preproc(key: &Key) -> Self {
        Self {
            n: key.n,
            t: key.t,
            k: key.k,
            secrets: key
                .secrets
                .iter()
                .map(|(v, phi)| (*phi, lagrange(v, 0, key.k)))
                .collect(),
        }
    }

    pub fn rand(n: u32, t: u32) -> Self {
        let delta = binom(n - 1, t - 1);
        let mut secrets: Vec<([u8; 32], Scalar)> = Vec::new();
        let mut rng = rand::thread_rng();
        for _ in 0u64..delta {
            let mut phi = [0u8; 32];
            rng.fill_bytes(&mut phi);
            let lagrange: Scalar = Scalar::random(&mut rng);
            secrets.push((phi, lagrange));
        }
        Self {
            n,
            t,
            k: 1,
            secrets,
        }
    }

    pub fn gen(&self, w: &[u8]) -> (Scalar, RistrettoPoint) {
        let d = self
            .secrets
            .iter()
            .map(|(phi, lagrange)| hash1(phi, w) * lagrange)
            .sum();
        (d, &d * dalek_constants::RISTRETTO_BASEPOINT_TABLE)
    }

    pub fn delta(&self) -> usize {
        self.secrets.len()
    }
}

pub fn commit(evaluation: &Scalar) -> RistrettoPoint {
    evaluation * dalek_constants::RISTRETTO_BASEPOINT_TABLE
}

// Verify that a set of commitments are consistent with a given t, using
// precomputed Lagrange polynomials.  Return false if the commitments
// are not consistent with the given t, or true if they are. You must
// pass at least 2t-1 commitments, and the same number of lag_polys.
pub fn verify_polys(t: u32, lag_polys: &[ScalarPoly], commitments: &[RistrettoPoint]) -> bool {
    // Check if the commitments are consistent: when interpolating the
    // polys in the exponent, the low t coefficients can be non-0 but
    // the ones above that must be 0

    let coalition_size = commitments.len();
    assert!(t >= 1);
    assert!(coalition_size >= 2 * (t as usize) - 1);
    assert!(coalition_size == lag_polys.len());
    assert!(coalition_size == lag_polys[0].coeffs.len());

    // Use this to compute the multiscalar multiplications
    let multiscalar = VartimeRistrettoPrecomputation::new(std::iter::empty::<RistrettoPoint>());

    // Compute the B_i for i from t to coalition_size-1.  All of them
    // should be the identity; otherwise, the commitments are
    // inconsistent.
    ((t as usize)..coalition_size)
        .map(|i| {
            // B_i = \sum_j lag_polys[j].coeffs[i] * commitments[j]
            multiscalar.vartime_mixed_multiscalar_mul(
                std::iter::empty::<Scalar>(),
                (0..coalition_size).map(|j| lag_polys[j].coeffs[i]),
                commitments,
            )
        })
        .all(|bi: RistrettoPoint| bi == RistrettoPoint::identity())
}

// Verify that a set of commitments are consistent with a given t.
// Return false if the commitments are not consistent with the given t,
// or true if they are. You must pass at least 2t-1 commitments, and the
// same number of lag_polys.
pub fn verify(t: u32, coalition: &[u32], commitments: &[RistrettoPoint]) -> bool {
    let polys = lagrange_polys(coalition);
    verify_polys(t, &polys, commitments)
}

// Combine already-verified commitments using precomputed Lagrange
// polynomials.  You must pass at least 2t-1 commitments, and the same
// number of lag_polys.
pub fn agg_polys(
    t: u32,
    lag_polys: &[ScalarPoly],
    commitments: &[RistrettoPoint],
) -> RistrettoPoint {
    agg_polys_at(t, lag_polys, commitments, &Scalar::ZERO)
}

// Combine already-verified commitments using precomputed Lagrange
// polynomials, and evaluate the result at the given point target_x.
// You must pass at least t commitments, and the same number of lag_polys.
pub fn agg_polys_at(
    _t: u32,
    lag_polys: &[ScalarPoly],
    commitments: &[RistrettoPoint],
    target_x: &Scalar,
) -> RistrettoPoint {
    let coalition_size = commitments.len();
    assert!(coalition_size == lag_polys.len());

    // Use this to compute the multiscalar multiplications
    let multiscalar = VartimeRistrettoPrecomputation::new(std::iter::empty::<RistrettoPoint>());

    // Compute B(target_x) (which is the combined commitment evaluated at target_x)
    multiscalar.vartime_mixed_multiscalar_mul(
        std::iter::empty::<Scalar>(),
        (0..coalition_size).map(|j| lag_polys[j].eval(target_x)),
        commitments,
    )
}

// Combine already-verified commitments. You must pass at least 2t-1
// commitments, and the same number of lag_polys.
pub fn agg(t: u32, coalition: &[u32], commitments: &[RistrettoPoint]) -> RistrettoPoint {
    let polys = lagrange_polys(coalition);
    agg_polys(t, &polys, commitments)
}

// Combine commitments using precomputed Lagrange polynomials.  Return
// None if the commitments are not consistent with the given t.  You
// must pass at least 2t-1 commitments, and the same number of
// lag_polys.  This function combines verify_polys and agg_polys into a
// single call that returns Option<RistrettoPoint>.
pub fn combinecomm_polys(
    t: u32,
    lag_polys: &[ScalarPoly],
    commitments: &[RistrettoPoint],
) -> Option<RistrettoPoint> {
    let coalition_size = commitments.len();
    assert!(t >= 1);
    assert!(coalition_size >= 2 * (t as usize) - 1);
    assert!(coalition_size == lag_polys.len());
    assert!(coalition_size == lag_polys[0].coeffs.len());

    // Check if the commitments are consistent: when interpolating the
    // polys in the exponent, the low t coefficients can be non-0 but
    // the ones above that must be 0

    if !verify_polys(t, lag_polys, commitments) {
        return None;
    }

    Some(agg_polys(t, lag_polys, commitments))
}

// Combine commitments. Return None if the commitments are not
// consistent with the given t.  You must pass at least 2t-1
// commitments, and the same size of coalition.  This function combines
// verify and agg into a single call that returns
// Option<RistrettoPoint>.
pub fn combinecomm(
    t: u32,
    coalition: &[u32],
    commitments: &[RistrettoPoint],
) -> Option<RistrettoPoint> {
    let polys = lagrange_polys(coalition);
    combinecomm_polys(t, &polys, commitments)
}

#[test]
pub fn test_preproc() {
    let keys = Key::keygen(7, 4);

    let ppkey3 = PreprocKey::preproc(&keys[2]);
    let ppkey7 = PreprocKey::preproc(&keys[6]);

    println!("preproc key for player 3: {:?}", ppkey3);
    println!("preproc key for player 7: {:?}", ppkey7);
}

// APPENDIX C ERROR CORRECTION: "Brute Force" Subset Checking
// If the standard VPSS check fails, we iterate through all t-sized subsets of C.
// For each subset S, we reconstruct the polynomial in the exponent.
pub fn robust_vpss_verify(
    t: u32,
    coalition: &[u32],
    commitments: &[RistrettoPoint],
) -> Result<Vec<(u32, RistrettoPoint)>, &'static str> {
    if commitments.len() < (2 * t as usize - 1) {
        return Err("Not enough commitments for robust verification.");
    }

    if verify(t, coalition, commitments) {
        return Ok(coalition.iter().zip(commitments.iter()).map(|(&id, &c)| (id, c)).collect());
    }

    let n = commitments.len();
    let t_usize = t as usize;

    // Try all t-sized subsets
    for subset_indices in (0..n).combinations(t_usize) {
        let subset_ids: Vec<u32> = subset_indices.iter().map(|&i| coalition[i]).collect();
        let subset_points: Vec<RistrettoPoint> = subset_indices.iter().map(|&i| commitments[i]).collect();
        let subset_polys = lagrange_polys(&subset_ids);

        let mut valid_nodes = vec![];
        for i in 0..n {
            let id = coalition[i];
            let id_scalar = Scalar::from(id);
            let expected_commitment = agg_polys_at(t, &subset_polys, &subset_points, &id_scalar);
            if expected_commitment == commitments[i] {
                valid_nodes.push((id, commitments[i]));
            }
        }

        if valid_nodes.len() >= (2 * t_usize - 1) {
            return Ok(valid_nodes);
        }
    }

    Err("Failed to find a valid honest supermajority polynomial.")
}

#[test]
pub fn test_robust_vpss() {
    let t = 3u32;
    let n = 7u32;
    let keys = Key::keygen(n, t);
    let ppkeys: Vec<PreprocKey> = keys.iter().map(|x| PreprocKey::preproc(x)).collect();
    let w = [0u8; 32];
    let mut commitments: Vec<RistrettoPoint> = ppkeys.iter().map(|k| k.gen(&w).1).collect();
    let coalition: Vec<u32> = (1..=n).collect();

    // Verify it works normally
    let res = robust_vpss_verify(t, &coalition, &commitments).unwrap();
    assert_eq!(res.len(), n as usize);

    // Corrupt one commitment (index 0)
    let _original_c0 = commitments[0];
    let v1 = commitments[1];
    commitments[0] += v1;
    
    // Now verify(t, ...) should fail, but robust_vpss_verify should succeed and exclude index 0
    assert!(!verify(t, &coalition, &commitments));
    let res2 = robust_vpss_verify(t, &coalition, &commitments).unwrap();
    assert_eq!(res2.len(), (n - 1) as usize);
    assert!(!res2.iter().any(|(id, _)| *id == 1));

    // Corrupt two commitments (indices 0 and 1)
    // For t=3, 2t-1 = 5. if n=7, we can tolerate 2 bad nodes.
    let v2 = commitments[2];
    commitments[1] += v2;
    let res3 = robust_vpss_verify(t, &coalition, &commitments).unwrap();
    assert_eq!(res3.len(), (n - 2) as usize);
    assert!(!res3.iter().any(|(id, _)| *id == 1 || *id == 2));
    
    // Corrupt three commitments. Should fail since we only have 4 honest nodes left (need 5).
    let v3 = commitments[3];
    commitments[2] += v3;
    assert!(robust_vpss_verify(t, &coalition, &commitments).is_err());
}

#[test]
pub fn test_gen() {
    let keys = Key::keygen(7, 3);
    let ppkeys: Vec<PreprocKey> = keys.iter().map(|x| PreprocKey::preproc(x)).collect();
    let mut rng = rand::thread_rng();
    let mut w = [0u8; 32];
    rng.fill_bytes(&mut w);
    let evals: Vec<Scalar> = ppkeys.iter().map(|k| k.gen(&w).0).collect();

    // Try interpolating different subsets and check that the answer is
    // the same
    let interp1 = interpolate(&vec![1, 2, 3, 4, 5], &evals[0..=4], 0);
    let interp2 = interpolate(&vec![3, 4, 5, 6, 7], &evals[2..=6], 0);
    println!("interp1 = {:?}", interp1);
    println!("interp2 = {:?}", interp2);
    assert!(interp1 == interp2);
}

#[test]
pub fn test_combinecomm() {
    let keys = Key::keygen(7, 3);
    let ppkeys: Vec<PreprocKey> = keys.iter().map(|x| PreprocKey::preproc(x)).collect();
    let mut rng = rand::thread_rng();
    let mut w = [0u8; 32];
    rng.fill_bytes(&mut w);
    let commitments: Vec<RistrettoPoint> = ppkeys.iter().map(|k| k.gen(&w).1).collect();

    let comm1 = combinecomm(3, &vec![1, 2, 3, 4, 5], &commitments[0..=4]);
    let comm2 = combinecomm(3, &vec![3, 4, 5, 6, 7], &commitments[2..=6]);
    assert_ne!(comm1, None);
    assert_ne!(comm2, None);

    // Test a failure case
    let comm3 = combinecomm(3, &vec![1, 2, 3, 4, 6], &commitments[0..=4]);
    assert_eq!(comm3, None);
}
