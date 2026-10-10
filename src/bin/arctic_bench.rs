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

use arctic::arctic_core;
use arctic_core::R1Output;
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

/// A usage error: message + the precondition line on stderr, exit 2 — the
/// contract the sibling runner CLIs already follow (an out-of-range
/// datapoint prints the failing bound instead of a panic backtrace).
fn usage_error(msg: &str) -> ! {
    eprintln!("arctic_bench: {msg}");
    eprintln!(
        "usage: arctic_bench n t Csize [reps]  (t >= 1, Csize >= 2t-1, n >= Csize, reps >= 1)"
    );
    std::process::exit(2);
}

fn arg(raw: &str, name: &str) -> u32 {
    raw.parse()
        .unwrap_or_else(|_| usage_error(&format!("{name} must be a whole number, got {raw:?}")))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 || args.len() > 5 {
        usage_error("expected 3 or 4 arguments");
    }
    let n: u32 = arg(&args[1], "n");
    let t: u32 = arg(&args[2], "t");
    let msglen: usize = 100;
    let coalitionsize: u32 = arg(&args[3], "Csize");
    let mut reps = 1usize;
    if args.len() > 4 {
        reps = args[4].parse().unwrap_or_else(|_| {
            usage_error(&format!("reps must be a whole number, got {:?}", args[4]))
        });
        if reps < 1 {
            usage_error("reps must be >= 1");
        }
    }
    let mut msg: Vec<u8> = Vec::new();
    let mut rng = rand::thread_rng();
    msg.resize(msglen, 0);
    if t < 1 {
        usage_error("t must be >= 1");
    }
    if coalitionsize < 2 * t - 1 {
        usage_error(&format!("Csize must be >= 2t-1 ({})", 2 * t - 1));
    }
    if n < coalitionsize {
        usage_error("n must be >= Csize");
    }

    let (pubkey, _, mut seckeys) = arctic_core::keygen(n, t);
    let delta = seckeys[0].delta();

    let mut sign1_timings: Vec<f64> = Vec::new();
    let mut sign2_timings: Vec<f64> = Vec::new();
    let mut combine_timings: Vec<f64> = Vec::new();

    let coalition = (1..=coalitionsize).collect::<Vec<u32>>();
    seckeys.truncate(coalitionsize as usize);
    let polys = arctic_core::lagrange_polys(&coalition);

    for _ in 0..reps {
        rng.fill_bytes(&mut msg);
        let (r1_outputs, sign1_iter_timings): (Vec<R1Output>, Vec<f64>) = seckeys
            .iter()
            .map(|key| {
                let sign1start = Instant::now();
                let r1_output = arctic_core::sign1(key, &coalition, &msg);
                let sign1dur = sign1start.elapsed().as_micros() as f64;
                (r1_output, sign1dur)
            })
            .unzip();
        sign1_timings.extend(sign1_iter_timings);

        let (sigshares, sign2_iter_timings): (Vec<Scalar>, Vec<f64>) = seckeys
            .iter()
            .map(|key| {
                let sign2start = Instant::now();
                let sigshare =
                    arctic_core::sign2_polys(&pubkey, key, &coalition, &polys, &msg, &r1_outputs)
                        .unwrap();
                let sign2dur = sign2start.elapsed().as_micros() as f64;
                (sigshare, sign2dur)
            })
            .unzip();
        sign2_timings.extend(sign2_iter_timings);

        let combinestart = Instant::now();
        let sig = arctic_core::combine_polys(
            &pubkey,
            t,
            &coalition,
            &polys,
            &msg,
            &r1_outputs,
            &sigshares,
        )
        .unwrap();
        let combinedur = combinestart.elapsed().as_micros() as f64;
        combine_timings.push(combinedur);

        assert!(arctic_core::verify(&pubkey, &msg, &sig));
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
