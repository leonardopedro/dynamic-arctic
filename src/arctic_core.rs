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
use crate::shine_core as shine;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::Digest;
use sha2::Sha256;

pub use crate::lagrange::lagrange_polys;

pub type PubKey = RistrettoPoint;

pub struct SecKey {
    pub t: u32,
    pub k: u32,
    // This player's signature key share
    pub sk: Scalar,
    // This player's Shine key share
    pub shine_key: shine::PreprocKey,
    // The group public key
    pub pk: PubKey,
}

impl SecKey {
    pub fn new(t: u32, k: u32, sk: Scalar, shine_key: shine::PreprocKey, pk: PubKey) -> Self {
        Self { t, k, sk, shine_key, pk }
    }

    pub fn delta(&self) -> usize {
        self.shine_key.delta()
    }

    /// PART 1 of Resharing Ceremony: Generate shares of a 'zero' polynomial.
    /// The polynomial p(x) will satisfy p(0) = 0.
    pub fn generate_reshare_packet(&self, n: u32) -> Vec<Scalar> {
        let mut rng = rand::thread_rng();
        // Degree is t-1, but we fix the constant term to 0.
        let mut coeffs = vec![Scalar::ZERO];
        for _ in 1..self.t {
            coeffs.push(Scalar::random(&mut rng));
        }
        let poly = ScalarPoly { coeffs };
        
        (1..=n).map(|i| poly.eval(&Scalar::from(i))).collect()
    }

    /// PART 2 of Resharing Ceremony: Apply received shares from peers.
    /// Each peer sends us their share of their 'zero' polynomial.
    /// Our new secret share sk' = sk + sum(received_shares).
    pub fn apply_reshare_packets(&mut self, incoming_shares: &[Scalar]) {
        let sum: Scalar = incoming_shares.iter().sum();
        self.sk += sum;
    }
}

pub type R1Output = ([u8; 32], RistrettoPoint);
pub type Signature = (RistrettoPoint, Scalar);

// Generate Arctic keys using a trusted dealer.  The output is the group
// public key, a vector of each individual player's public key (unused
// except in the robust Arctic case), and a vector of each individual
// player's Arctic secret key.
pub fn keygen(n: u32, t: u32) -> (PubKey, Vec<PubKey>, Vec<SecKey>) {
    assert!(t >= 1);
    assert!(n >= 2 * t - 1);

    let mut seckeys: Vec<SecKey> = Vec::new();

    // The Shine key shares
    let shinekeys = shine::Key::keygen(n, t);

    // The signature key shares
    let shamirpoly = ScalarPoly::rand((t as usize) - 1);
    let group_pubkey = shine::commit(&shamirpoly.coeffs[0]);
    let signkeys: Vec<Scalar> = (1..=n).map(|k| shamirpoly.eval(&Scalar::from(k))).collect();
    let player_pubkeys: Vec<PubKey> = signkeys.iter().map(shine::commit).collect();
    for k in 1..=n {
        seckeys.push(SecKey {
            t,
            k,
            sk: signkeys[(k - 1) as usize],
            shine_key: shine::PreprocKey::preproc(&shinekeys[(k as usize) - 1]),
            pk: group_pubkey,
        });
    }

    (group_pubkey, player_pubkeys, seckeys)
}

// The hash function used to generate the value y that's the input to
// shine::gen.
fn hash2(pk: &PubKey, msg: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(pk.compress().as_bytes());
    hash.update(msg);
    let mut hashval = [0u8; 32];
    hashval.copy_from_slice(&hash.finalize());
    hashval
}

// The hash function that's used to generate the challenge c for the
// Schnorr signature.  This function has to match the one for the
// Schnorr verification implementation you're interoperating with, and
// will depend on what group you're operating over.
fn hash3(combcomm: &RistrettoPoint, pk: &PubKey, msg: &[u8]) -> Scalar {
    let mut hash = Sha256::new();
    hash.update(combcomm.compress().as_bytes());
    hash.update(pk.compress().as_bytes());
    hash.update(msg);
    let mut hashval = [0u8; 32];
    hashval.copy_from_slice(&hash.finalize());
    Scalar::from_bytes_mod_order(hashval)
}

// The first round of the signature protocol.
pub fn sign1(sk: &SecKey, coalition: &[u32], msg: &[u8]) -> R1Output {
    assert!(coalition.len() >= 2 * (sk.t as usize) - 1);
    let y = hash2(&sk.pk, msg);
    (y, sk.shine_key.gen(&y).1)
}

// The second round of the signature protocol.  Note: it is vital that
// the R1Output values received from all the parties' first round were
// received over authenticated channels.  If an adversary can forge
// honest parties' round one messages, Arctic is _not_ secure.
pub fn sign2_polys(
    pk: &PubKey,
    sk: &SecKey,
    coalition: &[u32],
    lag_polys: &[ScalarPoly],
    msg: &[u8],
    r1_outputs: &[R1Output],
) -> Option<Scalar> {
    // If the inputs are _malformed_, abort

    assert!(coalition.len() == lag_polys.len());
    assert!(coalition.len() == r1_outputs.len());
    assert!(coalition.len() >= 2 * (sk.t as usize) - 1);

    // Find my own entry in the coalition; abort if it's not there
    let kindex = coalition.iter().position(|&k| k == sk.k).unwrap();

    // If the inputs are just corrupt values from malicious other
    // parties, return None but don't crash

    let y = hash2(pk, msg);

    // Make sure all the parties are submitting commitments for the same
    // y (the same pk and msg).
    if r1_outputs.iter().any(|(yj, _)| yj != &y) {
        return None;
    }

    let (my_eval, my_commit) = sk.shine_key.gen(&y);
    assert!(r1_outputs[kindex].1 == my_commit);

    let commitments: Vec<RistrettoPoint> = r1_outputs
        .iter()
        .map(|(_, commitment)| *commitment)
        .collect();
    if !shine::verify_polys(sk.t, lag_polys, &commitments) {
        return None;
    }
    let combcomm = shine::agg_polys(sk.t, lag_polys, &commitments);
    let c = hash3(&combcomm, pk, msg);

    Some(my_eval + c * sk.sk)
}

pub fn sign2(
    pk: &PubKey,
    sk: &SecKey,
    coalition: &[u32],
    msg: &[u8],
    r1_outputs: &[R1Output],
) -> Option<Scalar> {
    let polys = lagrange_polys(coalition);
    sign2_polys(pk, sk, coalition, &polys, msg, r1_outputs)
}

pub fn combine_polys(
    pk: &PubKey,
    t: u32,
    coalition: &[u32],
    lag_polys: &[ScalarPoly],
    msg: &[u8],
    r1_outputs: &[R1Output],
    sigshares: &[Scalar],
) -> Option<Signature> {
    assert!(coalition.len() == lag_polys.len());
    assert!(coalition.len() == r1_outputs.len());
    assert!(coalition.len() == sigshares.len());
    assert!(coalition.len() >= 2 * (t as usize) - 1);

    let commitments: Vec<RistrettoPoint> = r1_outputs
        .iter()
        .map(|(_, commitment)| *commitment)
        .collect();
    let combcomm = shine::agg_polys(t, lag_polys, &commitments);
    let c = hash3(&combcomm, pk, msg);

    let z = interpolate_polys_0(lag_polys, sigshares);

    // Check the answer

    if shine::commit(&z) == combcomm + c * pk {
        return Some((combcomm, z));
    }
    None
}

pub fn combine(
    pk: &PubKey,
    t: u32,
    coalition: &[u32],
    msg: &[u8],
    r1_outputs: &[R1Output],
    sigshares: &[Scalar],
) -> Option<Signature> {
    let polys = lagrange_polys(coalition);
    combine_polys(pk, t, coalition, &polys, msg, r1_outputs, sigshares)
}

pub fn robust_combine(
    pk: &PubKey,
    t: u32,
    coalition: &[u32],
    msg: &[u8],
    r1_outputs: &[R1Output],
    sigshares: &[Scalar],
    player_pubkeys: &[PubKey],
) -> Option<Signature> {
    let commitments: Vec<RistrettoPoint> = r1_outputs.iter().map(|(_, commitment)| *commitment).collect();
    
    // 1. Identify valid commitments using Robust VPSS
    let valid_nodes = shine::robust_vpss_verify(t, coalition, &commitments).ok()?;
    let valid_ids: std::collections::HashSet<u32> = valid_nodes.iter().map(|(id, _)| *id).collect();

    // Filter coalition to only those with valid commitments
    let mut filtered_indices = vec![];
    for (i, &id) in coalition.iter().enumerate() {
        if valid_ids.contains(&id) {
            filtered_indices.push(i);
        }
    }
    
    let filtered_coalition: Vec<u32> = filtered_indices.iter().map(|&i| coalition[i]).collect();
    let filtered_commitments: Vec<RistrettoPoint> = filtered_indices.iter().map(|&i| commitments[i]).collect();
    
    // 2. Compute the challenge c based on the valid supermajority
    // Appendix C: $|C| \ge 2t-1$ for unique polynomial reconstruction.
    let filtered_polys = lagrange_polys(&filtered_coalition);
    let combcomm = shine::agg_polys(t, &filtered_polys, &filtered_commitments);
    let c = hash3(&combcomm, pk, msg);

    // 3. Verify individual signature shares (Identifiable Abort).
    //
    // Arctic convention (a): sign shares are z_i = my_eval_i + c·sk_i (see
    // `sign2`), so the per-share check is g^z_i == R_i + c·PK_i — WITHOUT the
    // Lagrange factor L_i(0) (L_i(0) only enters at interpolation: the
    // aggregate z = Σ L_i(0)·z_i, checked in step 4). Multiplying c by L_i(0)
    // here would reject every honest share (regression caught by
    // `test_robust_combine_identifiable_abort_single_malicious`).
    let mut honest_indices = vec![];
    for (idx, &orig_idx) in filtered_indices.iter().enumerate() {
        let node_id = coalition[orig_idx];
        let z_i = sigshares[orig_idx];
        let r_i = commitments[orig_idx];
        let pk_i = player_pubkeys[(node_id - 1) as usize];

        // verification: g^z_i == R_i + c * PK_i
        if shine::commit(&z_i) == r_i + c * pk_i {
            honest_indices.push(idx);
        } else {
            println!("🚨 IDENTIFIABLE ABORT: Node {} sent a mathematically invalid share! Excluding.", node_id);
        }
    }

    if honest_indices.len() < (t as usize) {
        return None;
    }

    // 4. Combine using only honest shares
    let honest_coalition: Vec<u32> = honest_indices.iter().map(|&i| filtered_coalition[i]).collect();
    let honest_shares: Vec<Scalar> = honest_indices.iter().map(|&i| sigshares[filtered_indices[i]]).collect();
    let honest_polys = lagrange_polys(&honest_coalition);
    
    let z = interpolate_polys_0(&honest_polys, &honest_shares);

    if shine::commit(&z) == combcomm + c * pk {
        return Some((combcomm, z));
    }
    None
}

pub fn verify(pk: &PubKey, msg: &[u8], sig: &Signature) -> bool {
    let c = hash3(&sig.0, pk, msg);
    shine::commit(&sig.1) == sig.0 + c * pk
}

#[test]
pub fn test_arctic_good() {
    let n = 7u32;
    let t = 4u32;

    let (pubkey, _, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let r1_outputs: Vec<R1Output> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    let sigshares: Vec<Scalar> = seckeys
        .iter()
        .map(|key| sign2(&pubkey, key, &coalition, msg, &r1_outputs).unwrap())
        .collect();

    let sig = combine(&pubkey, t, &coalition, msg, &r1_outputs, &sigshares).unwrap();

    assert!(verify(&pubkey, msg, &sig));
}

#[test]
#[should_panic]
pub fn test_arctic_bad1() {
    let n = 7u32;
    let t = 4u32;

    let (pubkey, _, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let mut r1_outputs: Vec<R1Output> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    // Modify player 1's commitment
    let v = r1_outputs[1].1;
    r1_outputs[0].1 += v;

    // Player 1 should abort because its own commit is no longer in the
    // list
    sign2(&pubkey, &seckeys[0], &coalition, msg, &r1_outputs);
}

#[test]
pub fn test_arctic_bad2() {
    let n = 7u32;
    let t = 4u32;

    let (pubkey, _, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let mut r1_outputs: Vec<R1Output> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    // Modify player 1's commitment
    let v = r1_outputs[1].1;
    r1_outputs[0].1 += v;

    // Player 2 should return None because the commitments are
    // inconsistent
    assert_eq!(
        sign2(&pubkey, &seckeys[1], &coalition, msg, &r1_outputs),
        None
    );
}

#[test]
pub fn test_arctic_bad3() {
    let n = 7u32;
    let t = 4u32;

    let (pubkey, _, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let mut r1_outputs: Vec<R1Output> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    // Modify player 1's y value
    r1_outputs[0].0[0] += 1;

    // Player 2 should return None because the y values are
    // inconsistent
    assert_eq!(
        sign2(&pubkey, &seckeys[1], &coalition, msg, &r1_outputs),
        None
    );
}

#[test]
pub fn test_arctic_bad4() {
    let n = 7u32;
    let t = 4u32;

    let (pubkey, _, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let r1_outputs: Vec<R1Output> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    // Use a different message in round 2
    let msg2 = b"A message to be signef";

    // Player 2 should return None because the y values are
    // inconsistent
    assert_eq!(
        sign2(&pubkey, &seckeys[1], &coalition, msg2, &r1_outputs),
        None
    );
}

#[test]
pub fn test_arctic_bad5() {
    let n = 7u32;
    let t = 4u32;

    let (pubkey, _, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let r1_outputs: Vec<R1Output> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    let mut sigshares: Vec<Scalar> = seckeys
        .iter()
        .map(|key| sign2(&pubkey, key, &coalition, msg, &r1_outputs).unwrap())
        .collect();

    // Modify player 0's signature share
    sigshares[0] += Scalar::ONE;

    // Combine should return None because the shares don't combine to a
    // valid signature
    assert_eq!(
        combine(&pubkey, t, &coalition, msg, &r1_outputs, &sigshares),
        None
    );
}

#[test]
pub fn test_arctic_bad6() {
    let n = 7u32;
    let t = 4u32;

    let (pubkey, _, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let r1_outputs: Vec<R1Output> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    let sigshares: Vec<Scalar> = seckeys
        .iter()
        .map(|key| sign2(&pubkey, key, &coalition, msg, &r1_outputs).unwrap())
        .collect();

    // Modify the message
    let msg2 = b"A message to be signef";

    assert_eq!(
        combine(&pubkey, t, &coalition, msg2, &r1_outputs, &sigshares),
        None
    );
}

/// Serialize an Arctic aggregate signature to its 64-byte wire form:
/// `(compressed RistrettoPoint, Scalar)` — the exact layout that
/// `unfer_consensus::signing::verify_arctic_threshold` consumes (and the
/// size of every `ConsensusTransaction` op's `signature` field).
pub fn signature_to_bytes(sig: &Signature) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(sig.0.compress().as_bytes());
    out[32..].copy_from_slice(&sig.1.to_bytes());
    out
}

#[test]
pub fn test_robust_combine_identifiable_abort_single_malicious() {
    // Appendix C.1 end-to-end: one malicious node sends a mathematically
    // invalid signature share (but a valid round-1 commitment, so Robust VPSS
    // keeps it in the coalition). `robust_combine` must *identify* the bad
    // share, exclude exactly that node, and still produce a valid signature
    // from the honest majority.
    let n = 7u32;
    let t = 4u32;

    let (pubkey, player_pubkeys, seckeys) = keygen(n, t);
    let coalition = (1..=n).collect::<Vec<u32>>();
    let msg = b"A message to be signed";

    let r1_outputs: Vec<R1Output> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();
    let mut sigshares: Vec<Scalar> = seckeys
        .iter()
        .map(|key| sign2(&pubkey, key, &coalition, msg, &r1_outputs).unwrap())
        .collect();

    // Node 0 sends a corrupt signature share (commitment stays valid).
    sigshares[0] += Scalar::ONE;

    // The plain combine must reject the corrupted aggregate…
    assert_eq!(
        combine(&pubkey, t, &coalition, msg, &r1_outputs, &sigshares),
        None
    );
    // …but the robust combine isolates the bad node and still signs.
    let sig = robust_combine(
        &pubkey,
        t,
        &coalition,
        msg,
        &r1_outputs,
        &sigshares,
        &player_pubkeys,
    )
    .expect("robust combine must succeed with one malicious share");
    assert!(verify(&pubkey, msg, &sig));
}

#[test]
pub fn test_robust_combine_too_many_malicious_returns_none() {
    // When the corrupted shares outnumber the honest remainder (fewer than t
    // honest shares survive), robust combine must refuse rather than emit a
    // bogus signature.
    let n = 7u32;
    let t = 4u32;

    let (pubkey, player_pubkeys, seckeys) = keygen(n, t);
    let coalition = (1..=n).collect::<Vec<u32>>();
    let msg = b"A message to be signed";

    let r1_outputs: Vec<R1Output> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();
    let mut sigshares: Vec<Scalar> = seckeys
        .iter()
        .map(|key| sign2(&pubkey, key, &coalition, msg, &r1_outputs).unwrap())
        .collect();

    // Corrupt 4 of 7 shares: only 3 honest shares remain < t = 4.
    for i in 0..4 {
        sigshares[i] += Scalar::ONE;
    }
    assert_eq!(
        robust_combine(
            &pubkey,
            t,
            &coalition,
            msg,
            &r1_outputs,
            &sigshares,
            &player_pubkeys,
        ),
        None
    );
}

#[test]
pub fn test_arctic_signature_64_byte_roundtrip() {
    // The aggregate signature must round-trip through the 64-byte wire form
    // (the `signature` field layout) and verify after deserialization.
    let n = 7u32;
    let t = 4u32;
    let (pubkey, _, seckeys) = keygen(n, t);
    let coalition = (1..=n).collect::<Vec<u32>>();
    let msg = b"A message to be signed";

    let r1_outputs: Vec<R1Output> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();
    let sigshares: Vec<Scalar> = seckeys
        .iter()
        .map(|key| sign2(&pubkey, key, &coalition, msg, &r1_outputs).unwrap())
        .collect();
    let sig = combine(&pubkey, t, &coalition, msg, &r1_outputs, &sigshares).unwrap();

    let bytes = signature_to_bytes(&sig);
    assert_eq!(bytes.len(), 64);

    // Deserialize exactly the way verify_arctic_threshold does.
    let r_point = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&bytes[..32])
        .expect("R must deserialize")
        .decompress()
        .expect("R must decompress");
    let z = Scalar::from_canonical_bytes(bytes[32..].try_into().unwrap())
        .into_option()
        .expect("z must be canonical");
    let roundtripped: Signature = (r_point, z);
    assert_eq!(roundtripped.0, sig.0);
    assert_eq!(roundtripped.1, sig.1);
    assert!(verify(&pubkey, msg, &roundtripped));
}

#[test]
pub fn test_pss_resharing() {
    let n = 10u32;
    let t = 3u32;
    let (pubkey, _, mut seckeys) = keygen(n, t);
    let coalition = (1..=5).collect::<Vec<u32>>(); // Nodes 1, 2, 3, 4, 5. (Need 2t-1 = 5)
    let msg = b"Test resharing";

    // 1. Verify we can sign BEFORE resharing
    let r1_old: Vec<R1Output> = seckeys[0..5].iter().map(|sk| sign1(sk, &coalition, msg)).collect();
    let sigshares_old: Vec<Scalar> = seckeys[0..5]
        .iter()
        .map(|sk| sign2(&pubkey, sk, &coalition, msg, &r1_old).unwrap())
        .collect();
    let sig_old = combine(&pubkey, t, &coalition, msg, &r1_old, &sigshares_old).unwrap();
    assert!(verify(&pubkey, msg, &sig_old));

    // 2. Perform Resharing Ceremony
    // Each node generates its reshare packets.
    let mut shares_matrix: Vec<Vec<Scalar>> = Vec::new();
    for i in 0..n as usize {
        shares_matrix.push(seckeys[i].generate_reshare_packet(n));
    }

    // Nodes receive shares from everyone.
    for i in 0..n as usize {
        let mut my_received: Vec<Scalar> = Vec::new();
        for j in 0..n as usize {
            my_received.push(shares_matrix[j][i]);
        }
        seckeys[i].apply_reshare_packets(&my_received);
    }

    // 3. Signature after resharing (Same coalition, same message)
    let r1_outputs: Vec<R1Output> = seckeys[0..5].iter().map(|sk| sign1(sk, &coalition, msg)).collect();
    let sigshares_new: Vec<Scalar> = seckeys[0..5]
        .iter()
        .map(|sk| sign2(&pubkey, sk, &coalition, msg, &r1_outputs).unwrap())
        .collect();

    let sig = combine(&pubkey, t, &coalition, msg, &r1_outputs, &sigshares_new).unwrap();
    assert!(verify(&pubkey, msg, &sig));
}
