mod types;
mod arctic;
mod coordinator;
pub mod arctic_core;
pub mod shine_core;
mod lagrange;

use axum::{routing::{get, post}, Router, Json, extract::State};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::net::TcpListener;
use bs58;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{AggregateKey, DelegationRequest, DelegationCertificate};
use crate::arctic::ArcticNode;
use crate::coordinator::RoastCoordinator;

struct AppState {
    coordinator: RoastCoordinator,
    master_pubkey_multibase: String,
    domain: String,
}

#[tokio::main]
async fn main() {
    // 1. Bootstrap Authority (Simulating DKG Output)
    // We use a fixed seed for demonstration
    let secret = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let master_pubkey = ed25519_dalek::VerifyingKey::from(&secret);
    
    let mut codec_bytes = vec![0xed, 0x01];
    codec_bytes.extend_from_slice(master_pubkey.as_bytes());
    let multibase = format!("z{}", bs58::encode(codec_bytes).into_string());

    let nodes: Vec<ArcticNode> = (1..=5)
        .map(|i| ArcticNode::new(i, [i as u8; 32], master_pubkey.clone()))
        .collect();
    
    let agg_key = AggregateKey { 
        master_public_key: master_pubkey, 
        threshold: 3, 
        total_nodes: 5 
    };
    
    let state = Arc::new(AppState {
        coordinator: RoastCoordinator::new(agg_key, nodes),
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
    println!("Authority live on port 3000...");
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
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    // Create a 30-day certificate
    let cert = DelegationCertificate {
        issuer_did: format!("did:web:{}", state.domain),
        delegatee_pk: payload.hot_key_pk_multibase,
        expires_at: now + (30 * 24 * 60 * 60), 
        capabilities: vec!["atproto-signing".to_string()],
    };

    let cert_bytes = serde_json::to_vec(&cert).unwrap();

    // The ROAST Coordinator handles the threshold ceremony
    match state.coordinator.sign_robustly(&cert_bytes).await {
        Ok(sig) => Json(json!({
            "status": "success",
            "certificate": cert,
            "authority_signature": hex::encode(sig.to_bytes())
        })),
        Err(e) => Json(json!({ "status": "error", "message": e }))
    }
}
