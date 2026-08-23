# 🧊 Arctic Authority: Distributed Collective Authority for AT Protocol

> **Status**: [PROTOTYPE] This project implements the **Arctic** threshold signature scheme with **Native Robustness (Appendix C/C.1)**. By moving beyond the ROAST coordinator layer, we achieve robustness purely through mathematics, eliminating network retry-loops while preserving absolute statelessness.

---

## 🚀 Overview

Arctic Authority provides a **Lightweight, Stateless, and Robust** threshold signing service. It is designed to act as a "Cold/Warm" Collective Authority that manages `did:web` identities and issues delegation certificates to "Hot" operational keys for the AT Protocol.

### Key Features
- **Deterministic Signing**: Round-1 nonces are derived from session-bound PRFs, eliminating the need for state synchronization between nodes.
- **Native Robustness (Appendix C)**: Mathematical error correction in Round 1 (Robust VPSS) ensures successful signing even if up to $(n - (2t-1))$ nodes send bad data or are offline.
- **Identifiable Aborts (Appendix C.1)**: Individual signature shares are verified against node public keys, allowing the authority to instantly isolate and exclude malicious contributors in a single pass.
- **Stateless Replay Protection**: Secure Session IDs are derived from the certificate and a time-window, ensuring that replayed requests yield identical, harmless shares without needing a database.
- **Proactive Secret Sharing (PSS)**: Built-in support for "epoch-based" secret rotation, allowing nodes to randomize their shares without changing the master public key.
- **AT Protocol Ready**: Serves standard DID documents and implements the delegation certificate ceremony.

---

## 🛠️ Installation

Ensure you have Rust (v1.75+) installed.

```bash
git clone <repository_url>
cd dynamic-arctic
cargo build --release
```

---

## 📖 Tutorial: Running a Synthetic Authority

### 1. Launch the Authority API
For demonstration, you can boot the entire authority (running a 7-node committee with threshold 3) on a single machine:

```bash
cargo run
```
*Output:* `Stateless Arctic Authority (Native Robustness) live on port 3000...`

### 2. Retrieve the DID Document
The authority serves its identity at the standard `.well-known` path:

```bash
curl http://localhost:3000/.well-known/did.json
```

### 3. Request a Delegation Certificate
As a PDS or a user with a "Hot Key," you can request a 30-day delegation certificate. This initiates a **Robust Threshold Ceremony** ($n=7, t=3$):

```bash
curl -X POST http://localhost:3000/api/v1/delegate \
  -H "Content-Type: application/json" \
  -d '{"hot_key_pk_multibase": "z6MkhaXgBZD..."}'
```

### 4. Performing a PSS Resharing (Manual)
To rotate the secret shares for improved proactive security:

```rust
// Individual nodes generate and apply reshare packets:
node.core_key.generate_reshare_packet(n);
node.core_key.apply_reshare_packets(&incoming);
```
*(See `src/arctic_core.rs` tests for a full ritual simulation)*

---

## 🏗️ Architecture

- **`src/arctic_core.rs`**: The core Arctic signing primitives, now featuring **Robust Combine** and Identifiable Abort logic.
- **`src/shine_core.rs`**: The SHINE (VPSS) implementation with **Robust VPSS verification** (error-correcting subset checking).
- **`src/arctic.rs`**: The high-level node implementation, handling deterministic Session IDs and Secure Payloads.
- **`src/main.rs`**: The AT Protocol API entry point and bootstrap logic (gated behind the `server` feature).

---

## 🔗 Reuse in the unfer project

The library (`arctic_core`/`shine_core`) is reused as a **path dependency** by
`unfer/unfer_consensus` with `default-features = false` (no server deps):

- `unfer_consensus::signing::verify_arctic_threshold` verifies a 64-byte Arctic
  aggregate signature `(RistrettoPoint, Scalar)` against a group public key
  over a transaction's canonical bytes.
- `unfer_consensus::certs::MintAuthority::Threshold { threshold, total, pubkey }`
  makes the certificate ledger's mint authority a t-of-n threshold authority:
  `ConsensusNode::submit` and log replay route mint ops through
  `CertificateLedger::verify_threshold_mint` instead of the single-key Ed25519
  check. The 64-byte signature fits the existing `op.signature` field exactly.

See `unfer/PROJECT_PLAN.md` for the five-repo integration map.

---

## 📜 License

This work is based on research by **Ian Goldberg** (iang@uwaterloo.ca) and **Chelsea Komlo**. 
The repository is licensed under the **MIT License**.

---
*Disclaimer: This project implements Native Robustness as described in ePrint 2024/466 Appendix C. The server is prototype status; the library is exercised by 32 passing unit tests and the unfer threshold-mint integration tests.*
