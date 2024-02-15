use arctic::arctic;
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
        println!("Usage: {} n t Csize [reps]", args[0]);
        return;
    }
    let n: u32 = args[1].parse().unwrap();
    let t: u32 = args[2].parse().unwrap();
    let msglen: usize = 100;
    let coalitionsize: u32 = args[3].parse().unwrap();
    let mut reps = 1usize;
    if args.len() > 4 {
        reps = args[4].parse().unwrap();
    }
    let mut msg: Vec<u8> = Vec::new();
    let mut rng = rand::thread_rng();
    msg.resize(msglen, 0);
    assert!(t >= 1);
    assert!(coalitionsize >= 2 * t - 1);
    assert!(n >= coalitionsize);

    let (pubkey, mut seckeys) = arctic::keygen(n, t);
    let delta = seckeys[0].delta();

    let mut sign1_timings: Vec<f64> = Vec::new();
    let mut sign2_timings: Vec<f64> = Vec::new();
    let mut combine_timings: Vec<f64> = Vec::new();

    let coalition = (1..=coalitionsize).collect::<Vec<u32>>();
    seckeys.truncate(coalitionsize as usize);
    let polys = arctic::lagrange_polys(&coalition);

    for _ in 0..reps {
        rng.fill_bytes(&mut msg);
        let (commits, sign1_iter_timings): (Vec<RistrettoPoint>, Vec<f64>) = seckeys
            .iter()
            .map(|key| {
                let sign1start = Instant::now();
                let commitment = arctic::sign1(key, &coalition, &msg);
                let sign1dur = sign1start.elapsed().as_micros() as f64;
                (commitment, sign1dur)
            })
            .unzip();
        sign1_timings.extend(sign1_iter_timings);

        let (sigshares, sign2_iter_timings): (Vec<Scalar>, Vec<f64>) = seckeys
            .iter()
            .map(|key| {
                let sign2start = Instant::now();
                let sigshare =
                    arctic::sign2_polys(&pubkey, key, &coalition, &polys, &msg, &commits).unwrap();
                let sign2dur = sign2start.elapsed().as_micros() as f64;
                (sigshare, sign2dur)
            })
            .unzip();
        sign2_timings.extend(sign2_iter_timings);

        let combinestart = Instant::now();
        let sig = arctic::combine_polys(&pubkey, t, &coalition, &polys, &msg, &commits, &sigshares)
            .unwrap();
        let combinedur = combinestart.elapsed().as_micros() as f64;
        combine_timings.push(combinedur);

        assert!(arctic::verify(&pubkey, &msg, &sig));
    }

    let sign1_mean = mean(&sign1_timings);
    let sign1_stddev = stddev(&sign1_timings);
    let sign2_mean = mean(&sign2_timings);
    let sign2_stddev = stddev(&sign2_timings);
    let combine_mean = mean(&combine_timings);
    let combine_stddev = stddev(&combine_timings);
    println!(
        "{} {} {} {} {} {:.1} ± {:.1} {:.1} ± {:.1} {:.1} ± {:.1}",
        n,
        t,
        coalitionsize,
        reps,
        delta,
        sign1_mean,
        sign1_stddev,
        sign2_mean,
        sign2_stddev,
        combine_mean,
        combine_stddev,
    );
}
