# Attribution

Borrowed patterns and components that concern *this* repo. The authoritative,
cross-repo table — including what was deliberately **not** adopted — is
[`../ATTRIBUTION.md`](../ATTRIBUTION.md).

| source | licence | what was adapted | where it landed |
|---|---|---|---|
| Arctic (Komlo & Goldberg, PKC 2025) | MIT (this repo) | the threshold-Schnorr scheme is implemented *from the paper*, which is credited in `README_arctic.md` | `src/arctic_core.rs`, `src/shine_core.rs` |

## Notes

This repo **is** the implementation of the cited paper, so the attribution
runs the other way: the paper is credited here rather than adapted from.

It is also consumed as a path dependency by `unfer_consensus`, which is why
`cargo build --no-default-features` is part of the verification set.
