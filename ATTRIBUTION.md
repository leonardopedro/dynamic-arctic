# Attribution

Borrowed patterns and components that concern *this* repo. The authoritative,
cross-repo table — including what was deliberately **not** adopted — is
[`../ATTRIBUTION.md`](../ATTRIBUTION.md).

| source | licence | what was adapted | where it landed |
|---|---|---|---|
| Arctic (Komlo & Goldberg, PKC 2025) | MIT (this repo) | the threshold-Schnorr scheme is implemented *from the paper*, which is credited in `README_UPSTREAM.md` | `src/arctic_core.rs`, `src/shine_core.rs` |
| `celld` (sibling repo, same author; tree not currently checked out) | Apache-2.0 — as recorded in the reviewed workspace-ledger table (preserved at `../emthin/workspace-backup/ATTRIBUTION.md`); row restored here 2026-10-28 | the `lab` fast-iteration bench profile: release speed with thin LTO, incremental builds, symbols kept so `perf` attributes CPU by function; numbers of record stay on `--release` | `Cargo.toml` (bench profile `lab`) |

## Notes

This repo **is** the implementation of the cited paper, so the attribution
runs the other way: the paper is credited here rather than adapted from.

It is also consumed as a path dependency by `unfer_consensus`, which is why
`cargo build --no-default-features` is part of the verification set.
