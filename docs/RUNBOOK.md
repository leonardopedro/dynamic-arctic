# Arctic Authority — runbook

Operational surface for the AT-Protocol threshold signing authority. Covers
start, verify, and what each endpoint is for.

## Start

```sh
cargo run --features server            # 0.0.0.0:3000
```

`server` is a default feature; `--no-default-features` builds the library alone,
which is how `unfer/unfer_consensus` consumes it for `MintAuthority::Threshold`.
Keep that split intact: the library must stay free of axum/tokio so the path
dependency stays cheap.

## Endpoints

| endpoint | method | purpose |
|---|---|---|
| `/healthz` | GET | Liveness. Answers `{"status":"ok"}`. |
| `/version` | GET | Build identity and the threshold in force. |
| `/.well-known/did.json` | GET | DID document for the configured domain. |
| `/api/v1/delegate` | POST | Delegation certificate ceremony. |

### `/healthz`

```sh
curl -sf http://localhost:3000/healthz     # {"status":"ok"}
```

Intentionally reads no node state and no threshold. A probe that depends on the
thing it is probing stops answering exactly when it is most needed; this one stays
useful while the node set is misconfigured. Use `/version` for readiness.

### `/version`

```sh
curl -s http://localhost:3000/version
```

```json
{"name":"arctic-authority","version":"0.1.0","threshold":2,"total_nodes":3,"domain":"..."}
```

`threshold` and `total_nodes` are the **configured** values, not defaults — the
question an operator is asking is how many shares this process will accept. The
shape deliberately mirrors `unfer_agent`'s `version` op so one check covers every
process in the project.

## Configuration

Precedence, lowest to highest:

1. built-in defaults
2. configuration file
3. environment
4. command-line flags

Values are read once at startup; there is no hot reload. `threshold`,
`total_nodes` and `domain` come from the process configuration.

## Rotate and revoke

The master key is in memory for the process lifetime and derived at startup from
the node set. Rotation is therefore a **restart**, not an operation:

1. bring up the new node set with the new threshold,
2. restart the authority against it,
3. the DID document changes with `master_pubkey_multibase` — clients must refetch
   `/.well-known/did.json`, so expect a propagation delay equal to the AT
   Protocol's own.

Session IDs are derived from the certificate and a time window, so replaying a
request inside the window yields an identical share rather than a new one. There
is no database to reset, which is the point of the stateless design.

## Backup

There is nothing to back up. No database, no session store, no key material on
disk — the authority is stateless by construction, and a backup procedure here
would be a sign that something had acquired state it should not have.

The one artefact worth keeping is the **configuration**: the node set, threshold
and domain. That is deployment configuration, not runtime state.

## Verify

```sh
cargo test                              # 24 tests (19 library + 5 ops surface)
cargo clippy --all-targets -- -D warnings
```

The `ops_surface` tests drive the real router in-process through
`tower::ServiceExt::oneshot`, so `/healthz` and `/version` are covered without
binding a port. See `ATTRIBUTION.md` for the paper this implements.