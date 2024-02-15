use crate::lagrange::*;
use crate::shine;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::Digest;
use sha2::Sha256;

pub use crate::lagrange::lagrange_polys;

type PubKey = RistrettoPoint;

pub struct SecKey {
    t: u32,
    k: u32,
    // This player's signature key share
    sk: Scalar,
    // This player's Shine key share
    shine_key: shine::PreprocKey,
    // The group public key
    pk: PubKey,
}

impl SecKey {
    pub fn delta(&self) -> usize {
        self.shine_key.delta()
    }
}

type Signature = (RistrettoPoint, Scalar);

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
    let signkeys : Vec<Scalar> = (1..=n)
        .map(|k| shamirpoly.eval(&Scalar::from(k)))
        .collect();
    let player_pubkeys : Vec<PubKey> = signkeys
        .iter().map(shine::commit).collect();
    for k in 1..=n {
        seckeys.push(SecKey {
            t,
            k,
            sk: signkeys[(k-1) as usize],
            shine_key: shine::PreprocKey::preproc(&shinekeys[(k as usize) - 1]),
            pk: group_pubkey,
        });
    }

    (group_pubkey, player_pubkeys, seckeys)
}

fn hash2(pk: &PubKey, msg: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(pk.compress().as_bytes());
    hash.update(msg);
    hash.finalize().into()
}

fn hash3(combcomm: &RistrettoPoint, pk: &PubKey, msg: &[u8]) -> Scalar {
    let mut hash = Sha256::new();
    hash.update(combcomm.compress().as_bytes());
    hash.update(pk.compress().as_bytes());
    hash.update(msg);
    let mut hashval = [0u8; 32];
    hashval[0..32].copy_from_slice(&hash.finalize());
    Scalar::from_bytes_mod_order(hashval)
}

pub fn sign1(sk: &SecKey, coalition: &[u32], msg: &[u8]) -> RistrettoPoint {
    assert!(coalition.len() >= 2 * (sk.t as usize) - 1);
    let w = hash2(&sk.pk, msg);
    sk.shine_key.gen(&w).1
}

pub fn sign2_polys(
    pk: &PubKey,
    sk: &SecKey,
    coalition: &[u32],
    lag_polys: &[ScalarPoly],
    msg: &[u8],
    commitments: &[RistrettoPoint],
) -> Option<Scalar> {
    // If the inputs are _malformed_, abort

    assert!(coalition.len() == lag_polys.len());
    assert!(coalition.len() == commitments.len());
    assert!(coalition.len() >= 2 * (sk.t as usize) - 1);

    // Find my own entry in the coalition; abort if it's not there
    let kindex = coalition.iter().position(|&k| k == sk.k).unwrap();

    let w = hash2(pk, msg);
    let (my_eval, my_commit) = sk.shine_key.gen(&w);

    assert!(commitments[kindex] == my_commit);

    // If the inputs are just corrupt values from malicious other
    // parties, return None but don't crash

    let combcomm = shine::combinecomm_polys(sk.t, lag_polys, commitments)?;
    let c = hash3(&combcomm, pk, msg);

    Some(my_eval + c * sk.sk)
}

pub fn sign2(
    pk: &PubKey,
    sk: &SecKey,
    coalition: &[u32],
    msg: &[u8],
    commitments: &[RistrettoPoint],
) -> Option<Scalar> {
    let polys = lagrange_polys(coalition);
    sign2_polys(pk, sk, coalition, &polys, msg, commitments)
}

pub fn combine_polys(
    pk: &PubKey,
    t: u32,
    coalition: &[u32],
    lag_polys: &[ScalarPoly],
    msg: &[u8],
    commitments: &[RistrettoPoint],
    sigshares: &[Scalar],
) -> Option<Signature> {
    assert!(coalition.len() == lag_polys.len());
    assert!(coalition.len() == commitments.len());
    assert!(coalition.len() == sigshares.len());
    assert!(coalition.len() >= 2 * (t as usize) - 1);

    let z = interpolate_polys_0(lag_polys, sigshares);

    // Check the answer

    let combcomm = shine::agg_polys(t, lag_polys, commitments);
    let c = hash3(&combcomm, pk, msg);

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
    commitments: &[RistrettoPoint],
    sigshares: &[Scalar],
) -> Option<Signature> {
    let polys = lagrange_polys(coalition);
    combine_polys(pk, t, coalition, &polys, msg, commitments, sigshares)
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

    let commits: Vec<RistrettoPoint> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    let sigshares: Vec<Scalar> = seckeys
        .iter()
        .map(|key| sign2(&pubkey, key, &coalition, msg, &commits).unwrap())
        .collect();

    let sig = combine(&pubkey, t, &coalition, msg, &commits, &sigshares).unwrap();

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

    let mut commits: Vec<RistrettoPoint> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    // Modify player 1's commitment
    let v = commits[1];
    commits[0] += v;

    // Player 1 should abort because its own commit is no longer in the
    // list
    sign2(&pubkey, &seckeys[0], &coalition, msg, &commits);
}

#[test]
pub fn test_arctic_bad2() {
    let n = 7u32;
    let t = 4u32;

    let (pubkey, _, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let mut commits: Vec<RistrettoPoint> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    // Modify player 1's commitment
    let v = commits[1];
    commits[0] += v;

    // Player 2 should return None because the commitments are
    // inconsistent
    assert_eq!(sign2(&pubkey, &seckeys[1], &coalition, msg, &commits), None);
}

#[test]
pub fn test_arctic_bad3() {
    let n = 7u32;
    let t = 4u32;

    let (pubkey, _, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let commits: Vec<RistrettoPoint> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    let mut sigshares: Vec<Scalar> = seckeys
        .iter()
        .map(|key| sign2(&pubkey, key, &coalition, msg, &commits).unwrap())
        .collect();

    // Modify player 0's signature share
    sigshares[0] += Scalar::one();

    // Combine should return None because the shares don't combine to a
    // valid signature
    assert_eq!(
        combine(&pubkey, t, &coalition, msg, &commits, &sigshares),
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

    let commits: Vec<RistrettoPoint> = seckeys
        .iter()
        .map(|key| sign1(key, &coalition, msg))
        .collect();

    let sigshares: Vec<Scalar> = seckeys
        .iter()
        .map(|key| sign2(&pubkey, key, &coalition, msg, &commits).unwrap())
        .collect();

    // Modify the message
    let msg2 = b"A message to be signef";

    assert_eq!(
        combine(&pubkey, t, &coalition, msg2, &commits, &sigshares),
        None
    );
}
