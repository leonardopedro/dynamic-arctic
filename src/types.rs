use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PartialSignature {
    pub node_id: u32,
    pub r_share: [u8; 32],
    pub z_share: [u8; 32],
}

#[derive(Clone)]
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
