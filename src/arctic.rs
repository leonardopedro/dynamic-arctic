use crate::types::{SecurePayload, Round1Commitment, Round2Share};
use crate::arctic_core;
use crate::shine_core as shine;
use sha2::{Sha512, Digest};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;

pub struct ArcticNode {
    pub node_id: u32,
    pub core_key: arctic_core::SecKey,
    // For robustness, we store the full list of player pubkeys (computed during keygen)
    pub player_pubkeys: Vec<arctic_core::PubKey>,
}

impl ArcticNode {
    pub fn new(node_id: u32, secret_bytes: [u8; 32], t: u32, n: u32) -> Self {
        let sk_scalar = Scalar::from_bytes_mod_order(secret_bytes);
        
        // In this project, we simulate the output of a DKG or setup ceremony.
        // Arctic's native robustness requires n >= 3t-2 to tolerate t-1 failures.
        let (group_pk, player_pks, _) = arctic_core::keygen(n, t);
        
        let shine_keys = shine::Key::keygen(n, t);
        let shine_preproc = shine::PreprocKey::preproc(&shine_keys[(node_id as usize) - 1]);
        
        let core_key = arctic_core::SecKey::new(t, node_id, sk_scalar, shine_preproc, group_pk);

        Self {
            node_id,
            core_key,
            player_pubkeys: player_pks,
        }
    }

    /// Process Round 1 Request deterministically using the Session ID (Appendix C.1)
    pub fn process_round_1(&self, session_id: [u8; 32]) -> SecurePayload<Round1Commitment> {
        // Deterministic nonce generation based on session_id ensures stateless robustness.
        // We use the session_id as the input 'w' to the Shine VPSS generator.
        let (_, r_point) = self.core_key.shine_key.gen(&session_id);

        SecurePayload {
            session_id,
            sender_node_id: self.node_id,
            data: Round1Commitment { r_point: r_point.compress().to_bytes() },
            signature: [0u8; 64], // In a real system, this is an mTLS/Ed25519 signature
        }
    }

    /// Process Round 2 Request (Appendix C.1)
    pub fn process_round_2(
        &self, 
        session_id: [u8; 32], 
        coalition: &[u32], 
        r1_commitments: &[(u32, [u8; 32])],
        message: &[u8]
    ) -> Result<SecurePayload<Round2Share>, String> {
        // Prepare Round 1 outputs for arctic_core verification
        let mut r1_outputs = vec![];
        for (id, r_bytes) in r1_commitments {
            let r_point = CompressedRistretto::from_slice(r_bytes)
                .map_err(|e| e.to_string())?
                .decompress()
                .ok_or_else(|| format!("Invalid commitment from node {}", id))?;
            r1_outputs.push((session_id, r_point));
        }

        // Generate the response scalar share
        let z_share = arctic_core::sign2(&self.core_key.pk, &self.core_key, coalition, message, &r1_outputs)
            .ok_or_else(|| "Failed to generate Arctic share (VPSS inconsistent)".to_string())?;

        Ok(SecurePayload {
            session_id,
            sender_node_id: self.node_id,
            data: Round2Share { z_share: z_share.to_bytes() },
            signature: [0u8; 64],
        })
    }
}

/// Derive a deterministic Session ID from the message and current time window
pub fn derive_session_id(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(message);
    // Bind to a 1-hour window for stateless replay protection as per Appendix C.1
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let hour_window = now / 3600;
    hasher.update(hour_window.to_be_bytes());
    
    let result = hasher.finalize();
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&result[..32]);
    session_id
}

/// Aggregate Round 1 and Round 2 payloads into a final signature using robust math
pub fn aggregate_signatures(
    msg: &[u8], 
    session_id: [u8; 32],
    r1_payloads: &[SecurePayload<Round1Commitment>],
    r2_payloads: &[SecurePayload<Round2Share>],
    group_pk: &arctic_core::PubKey,
    player_pks: &[arctic_core::PubKey],
    t: u32
) -> Result<ed25519_dalek::Signature, String> {
    
    let coalition: Vec<u32> = r1_payloads.iter().map(|p| p.sender_node_id).collect();
    let mut r1_outputs = vec![];
    for p in r1_payloads {
        let r_point = CompressedRistretto::from_slice(&p.data.r_point)
            .map_err(|e| e.to_string())?
            .decompress()
            .ok_or("Invalid R point received in Round 1")?;
        r1_outputs.push((session_id, r_point));
    }
    
    // Ensure z_shares match the coalition order for combined interpolation
    let mut sigshares = vec![];
    for &id in &coalition {
        let p = r2_payloads.iter().find(|p| p.sender_node_id == id)
            .ok_or_else(|| format!("Missing share from node {}", id))?;
        sigshares.push(Scalar::from_bytes_mod_order(p.data.z_share));
    }

    // Perform Robust Combine with Identifiable Abort (Appendix C)
    let sig = arctic_core::robust_combine(
        group_pk, 
        t, 
        &coalition, 
        msg, 
        &r1_outputs, 
        &sigshares, 
        player_pks
    ).ok_or("Failed to robustly combine signature shares: too many malicious/bad nodes")?;

    // Format the result as a 64-byte Ed25519-compatible signature (R || z)
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0..32].copy_from_slice(sig.0.compress().as_bytes());
    sig_bytes[32..64].copy_from_slice(sig.1.as_bytes());
    
    Ok(ed25519_dalek::Signature::from_bytes(&sig_bytes))
}
