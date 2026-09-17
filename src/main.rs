mod arctic;
pub mod arctic_core;
mod lagrange;
pub mod shine_core;
mod types;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

use crate::arctic::{aggregate_signatures, derive_session_id, ArcticNode};
use crate::types::{DelegationCertificate, DelegationRequest};

struct AppState {
    nodes: Vec<ArcticNode>,
    threshold: u32,
    #[allow(dead_code)]
    total_nodes: u32,
    master_pubkey_multibase: String,
    domain: String,
}

#[tokio::main]
async fn main() {
    // 1. Bootstrap Authority with Robust Parameters (Appendix C)
    // t=3, n=7 allows native robustness against up to 2 malicious nodes
    let t = 3;
    let n = 7;

    // Simulate DKG output
    // In this project, we create a fresh key set for the 7 nodes.
    let (group_pk, _, _) = arctic_core::keygen(n, t);

    // Map Ristretto group_pk to multibase for DID document representation
    let pk_bytes = group_pk.compress().to_bytes();
    let mut codec_bytes = vec![0xed, 0x01]; // ed25519-pub multicodec
    codec_bytes.extend_from_slice(&pk_bytes);
    let multibase = format!("z{}", bs58::encode(codec_bytes).into_string());

    let nodes: Vec<ArcticNode> = (1..=n)
        .map(|i| ArcticNode::new(i, [i as u8; 32], t, n))
        .collect();

    let state = Arc::new(AppState {
        nodes,
        threshold: t,
        total_nodes: n,
        master_pubkey_multibase: multibase,
        domain: "authority.yourdomain.com".to_string(),
    });

    // 2. HTTP Server
    let app = Router::new()
        .route("/.well-known/did.json", get(serve_did_document))
        .route("/api/v1/delegate", post(handle_delegate))
        .with_state(state);

    let addr = "0.0.0.0:3000";
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Stateless Arctic Authority (Native Robustness) live on port 3000...");
    axum::serve(listener, app).await.unwrap();
}

async fn serve_did_document(State(state): State<Arc<AppState>>) -> Json<Value> {
    let did = format!("did:web:{}", state.domain);
    Json(json!({
        "@context":["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
        "id": did,
        "verificationMethod":[{
            "id": format!("{}#atproto", did),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": state.master_pubkey_multibase
        }],
        "service":[{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": "https://pds.yourdomain.com"
        }]
    }))
}

async fn handle_delegate(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DelegationRequest>,
) -> Json<Value> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create the Delegation Certificate
    let cert = DelegationCertificate {
        issuer_did: format!("did:web:{}", state.domain),
        delegatee_pk: payload.hot_key_pk_multibase,
        expires_at: now + (30 * 24 * 60 * 60),
        capabilities: vec!["atproto-signing".to_string()],
    };

    let cert_bytes = serde_json::to_vec(&cert).unwrap();

    // --- APPENDIX C: NATIVE ROBUSTNESS (NO COORDINATOR RETRY LOOP) ---

    // 1. ROUND 1: Deterministic broadcast to collect commitments
    let session_id = derive_session_id(&cert_bytes);
    let mut r1_payloads = vec![];
    for node in &state.nodes {
        r1_payloads.push(node.process_round_1(session_id));
    }

    // 2. ROUND 2: Broadcast R1 set and collect shares
    let coalition: Vec<u32> = r1_payloads.iter().map(|p| p.sender_node_id).collect();
    let r1_commitments: Vec<(u32, [u8; 32])> = r1_payloads
        .iter()
        .map(|p| (p.sender_node_id, p.data.r_point))
        .collect();

    let mut r2_payloads = vec![];
    for node in &state.nodes {
        // In robust mode, nodes follow a linear path. We simulate broad receiving here.
        if let Ok(share) =
            node.process_round_2(session_id, &coalition, &r1_commitments, &cert_bytes)
        {
            r2_payloads.push(share);
        }
    }

    // 3. COMBINE: Use identifiable abort to isolate honest shares
    // We use the common group key and player pubkeys stored in the first node for this demo state.
    let group_pk = &state.nodes[0].core_key.pk;
    let player_pks = &state.nodes[0].player_pubkeys;

    match aggregate_signatures(
        &cert_bytes,
        session_id,
        &r1_payloads,
        &r2_payloads,
        group_pk,
        player_pks,
        state.threshold,
    ) {
        Ok(sig) => Json(json!({
            "status": "success",
            "certificate": cert,
            "authority_signature": hex::encode(sig.to_bytes())
        })),
        Err(e) => Json(json!({ "status": "error", "message": e })),
    }
}
