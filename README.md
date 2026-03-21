# 🧊 Arctic Authority: Distributed Collective Authority for AT Protocol

> **Status**: [PROTOTYPE] This project adapts the research-grade **Arctic** threshold signature scheme for use as a high-security, distributed authority in the AT Protocol. It now includes **ROAST** for liveness and **Proactive Secret Sharing (PSS)** for dynamic share rotation.

---

## 🚀 Overview

Arctic Authority provides a **Lightweight, Stateless, and Deterministic** threshold signing service. It is designed to act as a "Cold/Warm" Collective Authority that manages `did:web` identities and issues delegation certificates to "Hot" operational keys.

### Key Features
- **Deterministic Signing**: Round-1 nonces are derived from the message and secret sharing seeds, eliminating the need for state synchronization between nodes.
- **ROAST Liveness**: A robust coordinator that ensures signing success even if up to $(n-t)$ nodes are offline or malicious.
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
For demonstration, you can boot the entire authority (simulating 5 nodes) on a single machine:

```bash
cargo run
```
*Output:* `Authority live on port 3000...`

### 2. Retrieve the DID Document
The authority serves its identity at the standard `.well-known` path:

```bash
curl http://localhost:3000/.well-known/did.json
```

### 3. Request a Delegation Certificate
As a PDS or a user with a "Hot Key," you can request a 30-day delegation certificate. This initiates a **Threshold Signing Ceremony** across the internal nodes:

```bash
curl -X POST http://localhost:3000/api/v1/delegate \
  -H "Content-Type: application/json" \
  -d '{"hot_key_pk_multibase": "z6MkhaXgBZD..."}'
```

### 4. Performing a PSS Resharing (Manual)
To rotate the secret shares for improved proactive security:

```bash
# In the code, this is executed via:
node.core_key.generate_reshare_packet(n);
node.core_key.apply_reshare_packets(&incoming);
```
*(See `src/arctic_core.rs` tests for a full ritual simulation)*

---

## 📊 Benchmarks

Reproduction scripts for the original PKC 2025 paper are preserved in the `repro/` directory.

To run the modernized Arctic benchmarks:
```bash
# Usage: ./target/release/arctic_bench <total_n> <threshold_t> <coalition_size> <reps>
./target/release/arctic_bench 21 11 21 10
```

---

## 🏗️ Architecture

- **`src/arctic_core.rs`**: The core Arctic signing primitives (Round 1 & 2).
- **`src/shine_core.rs`**: The SHINE (VPSS) implementation for verifiable commitments.
- **`src/coordinator.rs`**: The ROAST implementation for robust aggregation.
- **`src/main.rs`**: The AT Protocol API entry point.

---

## 📜 License

This work is based on research by **Ian Goldberg** (iang@uwaterloo.ca) and **Chelsea Komlo**. 
The repository is licensed under the **MIT License**.

---
*Disclaimer: All in this repository is currently Work In Progress. AI-assisted implementation was used to adapt the research primitives into this operational framework.*
