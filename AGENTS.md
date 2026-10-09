# AGENTS.md — dynamic-arctic

Agent guide for the Arctic threshold-signature crate. Small, self-contained
Rust repo; keep changes inside it.

## What this is

`dynamic-arctic` implements the **Arctic** threshold signature scheme with
Native Robustness (Appendix C/C.1): stateless session-PRF round-1 nonces,
identifiable aborts, proactive secret sharing, `did:web` identities for the
AT Protocol. Status: prototype, mostly AI-generated (banner in `README.md` —
keep it honest; don't claim more than the tests show).

## Toolchain

- Rust **1.99.0**, pinned in `rust-toolchain.toml` — rustup installs it
  automatically; CI reads the same file (deliberate bumps only, in lockstep
  with unfer/australVM/velysterm).

## Commands

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test  --all-features --locked            # server/authority path on
cargo test  --no-default-features --lib --locked  # library-only path
cargo run                                    # synthetic local authority demo
nix-shell -p python3 --run "python3 scripts/check-links"   # relative markdown links (CI: linkcheck.yml)
```

Benchmarks and the paper reproduction (upstream's harness, renamed here —
`arctic` is the authority server and rejects positional arguments):

```bash
cargo build --release
./target/release/arctic_bench n t Cs nsigs      # n ≥ Cs ≥ 2t-1, t ≥ 2
./target/release/shine_bench n t wlen [reps]
cd repro && ./repro_fig7a                       # Figure 7a datapoints (30–40 min)
```

The `n ≥ Cs ≥ 2t-1` precondition is an `assert!`, not a validation error, so an
out-of-range datapoint panics rather than printing usage. `repro/repro_fig7a`
sets `Cs = n` and starts at `n = 2t-1`, which satisfies it. Figure 7b and the
`rayon` branch are upstream-only and are not carried here.

CI (`.github/workflows/ci.yml`) runs exactly the above two test profiles plus
fmt/clippy, with SHA-pinned actions — mirror that when adding jobs.

## Rules

1. Ownership: modify only files inside this repo.
2. The MIT LICENSE (Copyright 2024 Ian Goldberg) is upstream's — do not
   relicense; additions here stay under the same terms.
3. `arctic_authority` inside `../australVM` path-depends on this crate:
   public-API changes must stay additive (see `../australVM/arctic.md`).
4. Commit in meaningful stages; push only when the owner asks.
