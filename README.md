# Arctic: Lightweight, Stateless, and Deterministic Two-Round Threshold Schnorr Signatures

Code by Ian Goldberg, iang@uwaterloo.ca

This repository contains the library code, benchmark harness, and reproduction scripts for our paper:

Chelsea Komlo and Ian Goldberg. "[Arctic: Lightweight, Stateless, and Deterministic Two-Round Threshold Schnorr Signatures](https://eprint.iacr.org/2024/466)", PKC 2025.

This code implements both Arctic (the deterministic two-round threshold Schnorr signature scheme) and Shine (the underlying verifiable pseudorandom secret sharing scheme, called VPSS<sub>1</sub> in the paper).

We used Rust 1.73.0 to build and benchmark this code.

## Running the benchmarks

There are two branches in this repository: the `main` branch is the single-threaded version, and the `rayon` branch is the multi-threaded version.

### Single-threaded benchmarks (Figure 7a in the paper)

Build the code with:
```bash
  git checkout main
  cargo build --release
```

Then you can run individual benchmarks with:

  - <code>./target/release/arctic _n_ _t_ _Cs_ _nsigs_</code>

Where:

  - <code>_n_</code> is the total number of parties
  - <code>_t_</code> is the corruption threshold (if the adversary controls this many parties, they can recover the secret key and all security is lost)
  - <code>_Cs_</code> is the size of the signing coalition (the number of parties that participate to produce a signature).
  - <code>_nsigs_</code> is the number of signatures to generate.

It must be the case that <code>_n_</code> ≥ <code>_Cs_</code> ≥ 2<code>_t_</code>-1, and <code>_t_</code> ≥ 2.

Sample command line:

`./target/release/arctic 21 11 21 10`

Sample output:

`21 11 21 10 184756 43984.1 ± 49.2 45616.8 ± 47.2 134.8 ± 5.4`

The output fields are:
 
  - `21 11 21 10`: the four command-line arguments as above
  - `184756`: the value δ = (<code>_n_</code>-1 choose <code>_t_</code>-1), which is the number of elements in the Shine private key.
  - `43984.1 ± 49.2`: the time in microseconds for each of the <code>_Cs_</code> parties to compute Arctic's Sign1 (signing round 1) operation.  The reported values are the mean and stddev over the <code>_Cs_</code> parties and the <code>_nsigs_</code> signatures.
  - `45616.8 ± 47.2`: the time in microseconds for each of the <code>_Cs_</code> parties to compute Arctic's Sign2 (signing round 2) operation.  The reported values are the mean and stddev over the <code>_Cs_</code> parties and the <code>_nsigs_</code> signatures.
  - `134.8 ± 5.4`: the time in microseconds for a single party to compute Arctic's Combine (combining the parties' outputs into the final signature) operation.  The reported values are the mean and stddev over the <code>_nsigs_</code> signatures.

To collect all the datapoints needed to reproduce the Arctic data in Figure 7a in our paper:

```bash
   cd repro
   ./repro-fig7a
```

This should take about 30–40 minutes, depending on your hardware.  The values plotted in the figure are the sums of the means of Sign1, Sign2, and Combine, divided by 1000 to convert from microseconds to milliseconds.  The stddevs plotted are the square roots of the sums of the squares of the stddevs of Sign1, Sign2, and Combine (and again converted to milliseconds), but they are mostly too small to see in the figure.

### Multi-threaded benchmarks (Figure 7b in the paper)

Build the code with:
```bash
  git checkout rayon
  cargo build --release
```

You will also need to have `numactl` installed (even if you aren't running on a NUMA machine).

You will not get a significant performance boost from hyperthreading.  If you have <code>_P_</code> physical cores on your CPU, this code assumes that in `/proc/cpuinfo`, the first <code>_P_</code> listed processors are all the "A sides" of your <code>_P_</code> physical cores.  The code also assumes that these first <code>_P_</code> physical cores are all on NUMA node 0, if you have a NUMA machine.  (These assumptions are quite likely to be true.)

Then you can run individual benchmarks with:

  - <code>numactl -C _cores_ -m0 ./target/release/arctic _n_ _t_ _Cs_ _nsigs_</code>

Where <code>_cores_</code> is a range of core numbers to use.  If you want to use, for example, 18 physical cores on your first (or only) CPU, you would use `numactl -C 0-17 -m0`.  The other arguments, and the output, are as in the single-threaded benchmarks above.

To collect all the datapoints needed to reproduce Figure 7b in our paper, decide how many cores you want to use for each of the datapoints.  For example, if you have a four-core CPU, you might use `1 2 3 4`, while if  you have a 16-core CPU, you might use `1 2 3 4 6 8 10 12 14 16`.  Then, for example:

```bash
   cd repro
   ./repro-fig7b 1 2 3 4 6 8 10 12 14 16
```

Note that only Shine.Gen is parallelized, which is used in Arctic's Sign1 and Sign2, and is in fact the dominant cost of signing when δ is large.  Key generation is not currently parallelized.
