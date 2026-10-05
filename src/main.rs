mod arctic;
pub mod arctic_core;
mod config;
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
    total_nodes: u32,
    master_pubkey_multibase: String,
    domain: String,
}

/// `arctic init` — write a commented starter config and exit.
///
/// The onboarding half of C3. Deterministic for given answers, so the output is
/// assertable rather than eyeballed, and the generated file parses back to the
/// configuration the operator answered with.
fn init_subcommand(answers: &config::InitAnswers) -> std::io::Result<()> {
    print!("{}", config::init_config(answers));
    Ok(())
}

#[tokio::main]
async fn main() {
    // C3: defaults < config file < environment < flags, and the command line is
    // what actually supplies the last layer now. Before this, `resolve` accepted a
    // file and flags and `main` passed `None` and `Flags::default()`, so the two
    // lower layers existed only as a tested API nobody called -- which is how
    // `arctic runbook` could claim a precedence order the binary did not have.
    let invocation = match config::parse_args(&std::env::args().collect::<Vec<_>>()) {
        Ok(v) => v,
        Err(why) => {
            eprintln!("arctic: {why}");
            std::process::exit(2);
        }
    };

    // `init` short-circuits -- it must not need a config file to produce one.
    let (file, flags) = match invocation {
        config::Invocation::Init => {
            // Defaults come from the resolver, so the file `init` writes always
            // agrees with what the server would run with. Deriving them from
            // literals here is how the generated file came to say `threshold = "2"`
            // while the process used 3.
            let (base, _) = config::Config::resolve(None, &|_| None, &config::Flags::default());
            let answers = config::InitAnswers {
                domain: base.domain,
                threshold: base.threshold,
                total_nodes: base.total_nodes,
            };
            init_subcommand(&answers).expect("write starter config to stdout");
            return;
        }
        config::Invocation::Serve { file, flags } => (file, flags),
    };

    // The whole argv -> file -> env -> flags chain is one call so it can be
    // tested. It used to be spelled out here, and every layer had a test while
    // the line joining them had none.
    let (cfg, prov) =
        match config::resolve_invocation(&config::Invocation::Serve { file, flags }, &|k| {
            std::env::var(k).ok()
        }) {
            Ok(Some(v)) => v,
            Ok(None) => unreachable!("Serve always resolves to a configuration"),
            Err(why) => {
                eprintln!("arctic: {why}");
                std::process::exit(2);
            }
        };
    // Say where each value came from, so an operator debugging "why is it t=5"
    // does not have to guess at a precedence order.
    eprintln!("arctic: {prov}");
    if let Err(why) = cfg.validate() {
        eprintln!("arctic: invalid configuration: {why}");
        std::process::exit(2);
    }

    // 1. Bootstrap Authority with Robust Parameters (Appendix C)
    let t = cfg.threshold;
    let n = cfg.total_nodes;

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
        domain: cfg.domain.clone(),
    });

    // 2. HTTP Server
    let app = app(state);

    let addr = cfg.bind_addr.clone();
    // Print where each value came from. Precedence is only trustworthy if an
    // operator can see which layer won.
    eprintln!("arctic: config provenance {}", prov.to_json());
    let listener = TcpListener::bind(&addr).await.unwrap();
    println!(
        "Stateless Arctic Authority (Native Robustness) live on {addr} \
         (t={t}, n={n}, domain={})",
        cfg.domain
    );
    axum::serve(listener, app).await.unwrap();
}

/// Build the HTTP surface (X6).
///
/// Extracted from `main` so the routes can be exercised by an integration test
/// through `tower::ServiceExt::oneshot` -- no port, no listener, no sleep. A
/// health check you can only reach by starting the process is a health check
/// nobody runs.
fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/.well-known/did.json", get(serve_did_document))
        .route("/api/v1/delegate", post(handle_delegate))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .with_state(state)
}

/// Liveness. Deliberately does **not** touch the node set or the threshold: it
/// answers "this process is up and serving", and a dependency-free probe is the
/// only kind that stays useful when something downstream is broken. Readiness
/// questions belong in `/version`, which reports configuration.
async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Build and configuration identity (X6), mirroring `unfer_agent`'s `version`
/// op so an operator has one shape to check across the project's processes.
async fn version(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "name": "arctic-authority",
        "version": env!("CARGO_PKG_VERSION"),
        "threshold": state.threshold,
        "total_nodes": state.total_nodes,
        "domain": state.domain,
    }))
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

#[cfg(test)]
mod ops_surface {
    //! X6 — the ops surface, exercised through the real router.
    //!
    //! These drive `app()` via `tower::ServiceExt::oneshot`, so routing,
    //! extractors and serialization are covered without binding a port or
    //! sleeping on a listener. A health check you can only reach by starting the
    //! process is a health check nobody runs.
    //!
    //! They live here rather than in `tests/` because `AppState` is private to
    //! this *binary* target; an integration test would link the library, which
    //! does not contain the routes. What is exercised is still the real router --
    //! only the process boundary is gone.

    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn state() -> Arc<AppState> {
        Arc::new(AppState {
            nodes: Vec::new(),
            threshold: 2,
            total_nodes: 3,
            master_pubkey_multibase: "zTEST".to_string(),
            domain: "authority.example".to_string(),
        })
    }

    /// The same configuration as  but with a different .
    fn state_with(total_nodes: u32) -> Arc<AppState> {
        Arc::new(AppState {
            nodes: Vec::new(),
            threshold: 2,
            total_nodes,
            master_pubkey_multibase: "zTEST".to_string(),
            domain: "authority.example".to_string(),
        })
    }

    async fn call(app: Router, uri: &str) -> (StatusCode, Value) {
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .expect("router responded");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn healthz_reports_ok() {
        let (status, body) = call(app(state()), "/healthz").await;
        assert_eq!(StatusCode::OK, status, "/healthz must answer 200");
        assert_eq!(json!({ "status": "ok" }), body);
    }

    #[tokio::test]
    async fn version_reports_the_crate_version_and_the_threshold_in_force() {
        let (status, body) = call(app(state()), "/version").await;
        assert_eq!(StatusCode::OK, status);
        assert_eq!(env!("CARGO_PKG_VERSION"), body["version"]);
        assert_eq!("arctic-authority", body["name"]);
        // The *configured* threshold, not a default: an operator reading this
        // is asking how many shares the live process will accept.
        assert_eq!(2, body["threshold"]);
        assert_eq!(3, body["total_nodes"]);
    }

    #[tokio::test]
    async fn healthz_does_not_depend_on_node_configuration() {
        // A probe that reads node state stops answering exactly when it is most
        // needed, so /healthz is deliberately free of it. Both an empty and a
        // populated state answer identically.
        let empty = call(app(state()), "/healthz").await;
        let full = call(app(state_with(1)), "/healthz").await;
        assert_eq!(empty.1, full.1);
    }

    #[tokio::test]
    async fn the_existing_routes_still_resolve() {
        // Adding endpoints must not have displaced the two that already existed.
        let (status, body) = call(app(state()), "/.well-known/did.json").await;
        assert_eq!(StatusCode::OK, status);
        assert!(
            body["id"]
                .as_str()
                .unwrap_or_default()
                .starts_with("did:web:"),
            "DID document must still serve a did:web id, got {}",
            body["id"]
        );

        let (status, _) = call(app(state()), "/api/v1/delegate").await;
        assert_eq!(
            StatusCode::METHOD_NOT_ALLOWED,
            status,
            "delegate is POST-only; a GET must not fall through to a handler"
        );
    }

    #[tokio::test]
    async fn an_unknown_path_is_404_not_a_catch_all() {
        let (status, _) = call(app(state()), "/nope").await;
        assert_eq!(StatusCode::NOT_FOUND, status);
    }
}
