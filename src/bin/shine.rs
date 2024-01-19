use arctic::shine;
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use std::env;
use std::time::Instant;

fn mean(vals: &[f64]) -> f64 {
    let num = vals.len();
    if num > 0 {
        vals.iter().sum::<f64>() / (num as f64)
    } else {
        0f64
    }
}

fn stddev(vals: &[f64]) -> f64 {
    let num = vals.len();
    if num < 2 {
        return 0f64;
    }
    let avg = mean(vals);
    (vals
        .iter()
        .map(|v| v - avg)
        .map(|dev| dev * dev)
        .sum::<f64>()
        / ((num - 1) as f64))
        .sqrt()
}

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

    let keys: Vec<shine::PreprocKey> = shine::Key::keygen(n, t)
        .iter()
        .map(|k| shine::PreprocKey::preproc(k))
        .collect();
    let delta = keys[0].delta();

    let mut eval_timings: Vec<f64> = Vec::new();
    let mut commit_timings: Vec<f64> = Vec::new();
    let mut combinecomm_timings: Vec<f64> = Vec::new();

    let coalition = (1..=n).collect::<Vec<u32>>();

    for _ in 0..reps {
        rng.fill_bytes(&mut wvec);
        let (evaluations, eval_iter_timings): (Vec<Scalar>, Vec<f64>) = keys
            .iter()
            .map(|rk| {
                let evalstart = Instant::now();
                let evaluation = rk.partialeval(&wvec);
                let evaldur = evalstart.elapsed().as_micros() as f64;
                (evaluation, evaldur)
            })
            .unzip();
        eval_timings.extend(eval_iter_timings);

        let (commitments, commit_iter_timings): (Vec<RistrettoPoint>, Vec<f64>) = evaluations
            .iter()
            .map(|ev| {
                let commstart = Instant::now();
                let commitment = ev * &generator;
                let commdur = commstart.elapsed().as_micros() as f64;
                (commitment, commdur)
            })
            .unzip();
        commit_timings.extend(commit_iter_timings);

        let combinecommstart = Instant::now();
        let _comb = shine::combinecomm(t, &coalition, &commitments);
        let combinecommdur = combinecommstart.elapsed().as_micros() as f64;
        combinecomm_timings.push(combinecommdur);
    }

    let eval_mean = mean(&eval_timings);
    let eval_stddev = stddev(&eval_timings);
    let commit_mean = mean(&commit_timings);
    let commit_stddev = stddev(&commit_timings);
    let combinecomm_mean = mean(&combinecomm_timings);
    let combinecomm_stddev = stddev(&combinecomm_timings);
    println!(
        "{} {} {} {} {} {:.1} ± {:.1} {:.1} ± {:.1} {:.1} ± {:.1} {:.2} ± {:.2}",
        n,
        t,
        wlen,
        reps,
        delta,
        eval_mean,
        eval_stddev,
        commit_mean,
        commit_stddev,
        combinecomm_mean,
        combinecomm_stddev,
        eval_mean / (delta as f64),
        eval_stddev / (delta as f64)
    );
}
