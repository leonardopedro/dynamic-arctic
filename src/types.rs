use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// The secure envelope for all Node-to-Node communication
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurePayload<T> {
    #[serde(with = "serde_bytes")]
    pub session_id: [u8; 32], // Deterministically derived from the AT Protocol request
    pub sender_node_id: u32,
    pub data: T, // The Round 1 Commitment or Round 2 Share
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64], // The sender's mTLS/Ed25519 signature of this payload
}

// Data structures for Round 1 and Round 2
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Commitment {
    #[serde(with = "serde_bytes")]
    pub r_point: [u8; 32], // The deterministic nonce commitment
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Share {
    #[serde(with = "serde_bytes")]
    pub z_share: [u8; 32], // The scalar response
}

/// A single party's partial signature share, as sent to the combiner.
/// Constructed by the collector from Round-2 shares; part of the wire API
/// (external callers build these — nothing in this crate constructs them).
#[derive(Clone, Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct PartialSignature {
    pub node_id: u32,
    pub r_share: [u8; 32],
    pub z_share: [u8; 32],
}

/// The group's aggregate verification key (threshold, total, master pk).
/// Produced at keygen; part of the wire API handed to verifiers (external
/// consumers construct it from keygen output).
#[derive(Clone)]
#[allow(dead_code)]
pub struct AggregateKey {
    pub master_public_key: VerifyingKey,
    pub threshold: usize,
    pub total_nodes: usize,
}

#[derive(Deserialize)]
pub struct DelegationRequest {
    pub hot_key_pk_multibase: String, // e.g., z6MkhaXgBZD...
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DelegationCertificate {
    pub issuer_did: String,
    pub delegatee_pk: String,
    pub expires_at: u64,
    pub capabilities: Vec<String>,
}
