use arctic::shine;
use curve25519_dalek::constants as dalek_constants;
use rand::RngCore;
use std::env;
use std::time::Instant;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 || args.len() > 5 {
        println!("Usage: {} n t wlen [reps]", args[0]);
        return;
    }
    let n: u32 = args[1].parse().unwrap();
    let t: u32 = args[2].parse().unwrap();
    let wlen: usize = args[3].parse().unwrap();
    let mut reps = 1usize;
    if args.len() > 4 {
        reps = args[4].parse().unwrap();
    }
    let mut wvec: Vec<u8> = Vec::new();
    let mut rng = rand::thread_rng();
    wvec.resize(wlen, 0);
    let generator = dalek_constants::RISTRETTO_BASEPOINT_TABLE;

    let rk = shine::PreprocKey::rand(n, t);
    let delta = rk.delta();

    let mut evaltotdur = 0u128;
    let mut commtotdur = 0u128;

    for _ in 0..reps {
        rng.fill_bytes(&mut wvec);
        let evalstart = Instant::now();
        let evaluation = rk.partialeval(&wvec);
        let evaldur = evalstart.elapsed().as_micros();
        evaltotdur += evaldur;

        let commstart = Instant::now();
        let _commitment = &evaluation * &generator;
        let commdur = commstart.elapsed().as_micros();
        commtotdur += commdur;
    }

    println!(
        "{} {} {} {} {} {} {} {}",
        n,
        t,
        wlen,
        reps,
        delta,
        (evaltotdur as usize) / reps,
        (commtotdur as usize) / reps,
        (evaltotdur as f64) / ((reps as f64) * (delta as f64))
    );
}
