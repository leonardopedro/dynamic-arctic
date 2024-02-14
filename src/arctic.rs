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
    sk: Scalar,
    rk: shine::PreprocKey,
}

impl SecKey {
    pub fn delta(&self) -> usize {
        self.rk.delta()
    }
}

type Signature = (RistrettoPoint, Scalar);

pub fn keygen(n: u32, t: u32) -> (PubKey, Vec<SecKey>) {
    assert!(t >= 1);
    assert!(n >= 2 * t - 1);

    let mut seckeys: Vec<SecKey> = Vec::new();

    // The Shine key shares
    let shinekeys = shine::Key::keygen(n, t);

    // The signature key shares
    let shamirpoly = ScalarPoly::rand((t as usize) - 1);
    let pubkey = shine::commit(&shamirpoly.coeffs[0]);
    for k in 1..=n {
        seckeys.push(SecKey {
            t,
            k,
            sk: shamirpoly.eval(&Scalar::from(k)),
            rk: shine::PreprocKey::preproc(&shinekeys[(k as usize) - 1]),
        });
    }

    (pubkey, seckeys)
}

fn hash2(combcomm: &RistrettoPoint, pk: &PubKey, msg: &[u8]) -> Scalar {
    let mut hash = Sha256::new();
    hash.update(combcomm.compress().as_bytes());
    hash.update(pk.compress().as_bytes());
    hash.update(msg);
    let mut hashval = [0u8; 32];
    hashval[0..32].copy_from_slice(&hash.finalize());
    Scalar::from_bytes_mod_order(hashval)
}

fn hash3(pk: &PubKey, coalition: &[u32], msg: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(pk.compress().as_bytes());
    hash.update(coalition.len().to_le_bytes());
    for c in coalition {
        hash.update(c.to_le_bytes());
    }
    hash.update(msg);
    hash.finalize().into()
}

pub fn sign1(pk: &PubKey, sk: &SecKey, coalition: &[u32], msg: &[u8]) -> RistrettoPoint {
    assert!(coalition.len() >= 2 * (sk.t as usize) - 1);
    let w = hash3(pk, coalition, msg);
    shine::commit(&sk.rk.gen(&w))
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

    let w = hash3(pk, coalition, msg);
    let my_eval = sk.rk.gen(&w);
    let my_commit = shine::commit(&my_eval);

    assert!(commitments[kindex] == my_commit);

    // If the inputs are just corrupt values from malicious other
    // parties, return None but don't crash

    let combcomm = shine::combinecomm_polys(sk.t, lag_polys, commitments)?;
    let c = hash2(&combcomm, pk, msg);

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

    let combcomm = shine::combinecomm_polys_noverify(t, lag_polys, commitments);
    let c = hash2(&combcomm, pk, msg);

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
    let c = hash2(&sig.0, pk, msg);
    shine::commit(&sig.1) == sig.0 + c * pk
}

#[test]
pub fn test_arctic_good() {
    let n = 7u32;
    let t = 4u32;

    let (pubkey, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let commits: Vec<RistrettoPoint> = seckeys
        .iter()
        .map(|key| sign1(&pubkey, key, &coalition, msg))
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

    let (pubkey, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let mut commits: Vec<RistrettoPoint> = seckeys
        .iter()
        .map(|key| sign1(&pubkey, key, &coalition, msg))
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

    let (pubkey, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let mut commits: Vec<RistrettoPoint> = seckeys
        .iter()
        .map(|key| sign1(&pubkey, key, &coalition, msg))
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

    let (pubkey, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let commits: Vec<RistrettoPoint> = seckeys
        .iter()
        .map(|key| sign1(&pubkey, key, &coalition, msg))
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

    let (pubkey, seckeys) = keygen(n, t);

    let coalition = (1..=n).collect::<Vec<u32>>();

    let msg = b"A message to be signed";

    let commits: Vec<RistrettoPoint> = seckeys
        .iter()
        .map(|key| sign1(&pubkey, key, &coalition, msg))
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
