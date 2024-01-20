use crate::lagrange::*;
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::VartimeRistrettoPrecomputation;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::traits::VartimePrecomputedMultiscalarMul;
use itertools::Itertools;
use rand::RngCore;
use rayon::prelude::*;
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
    hash.finalize_into((&mut hashval).into());
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
            .par_iter()
            .map(|(phi, lagrange)| hash1(phi, w) * lagrange)
            .sum();
        (d, &d * &dalek_constants::RISTRETTO_BASEPOINT_TABLE)
    }

    pub fn delta(&self) -> usize {
        self.secrets.len()
    }
}

pub fn commit(evaluation: &Scalar) -> RistrettoPoint {
    evaluation * &dalek_constants::RISTRETTO_BASEPOINT_TABLE
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
    let multiscalar = VartimeRistrettoPrecomputation::new(Vec::<RistrettoPoint>::new());

    // Compute the B_i for i from t to coalition_size-1.  All of them
    // should be the identity; otherwise, the commitments are
    // inconsistent.
    ((t as usize)..coalition_size)
        .map(|i| {
            // B_i = \sum_j lag_polys[j].coeffs[i] * commitments[j]
            multiscalar.vartime_mixed_multiscalar_mul(
                &Vec::<Scalar>::new(),
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
    let coalition_size = commitments.len();
    assert!(t >= 1);
    assert!(coalition_size >= 2 * (t as usize) - 1);
    assert!(coalition_size == lag_polys.len());
    assert!(coalition_size == lag_polys[0].coeffs.len());

    // Use this to compute the multiscalar multiplications
    let multiscalar = VartimeRistrettoPrecomputation::new(Vec::<RistrettoPoint>::new());

    // Compute B_0 (which is the combined commitment) and return it
    multiscalar.vartime_mixed_multiscalar_mul(
        &Vec::<Scalar>::new(),
        (0..coalition_size).map(|j| lag_polys[j].coeffs[0]),
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
