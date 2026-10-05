# Arctic Authority — runbook

Operational surface for the AT-Protocol threshold signing authority. Covers
start, verify, and what each endpoint is for.

## Start

```sh
cargo run --features server            # 0.0.0.0:3000, t=3 n=7

cargo run --bin arctic --features server -- init > arctic.toml
```

`init` prints a commented starter config to stdout. Redirect it, or read it and
paste -- it is deterministic, so the same answers always give the same file.

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

Values are read once at startup; there is no hot reload.

| key | env | default |
|---|---|---|
| `bind_addr` | `ARCTIC_BIND_ADDR` | `0.0.0.0:3000` |
| `domain` | `ARCTIC_DOMAIN` | `authority.yourdomain.com` |
| `threshold` | `ARCTIC_THRESHOLD` | `3` |
| `total_nodes` | `ARCTIC_TOTAL_NODES` | `7` |

`threshold` and `total_nodes` are the ceremony's robustness parameters. The
defaults are the values this binary has always used (`t=3, n=7` tolerates up to
2 malicious nodes); a threshold above `total_nodes` is refused at startup rather
than at signing time, where it would look like a network partition.

A malformed or zero value falls through to the layer below instead of aborting
startup -- a typo in an env var should not take the authority down. Startup
prints where each value came from:

    arctic: threshold (flag), domain (env), total_nodes (file), bind_addr (default)

so precedence is something you can read rather than something you trust.

Supply the file layer with `--config`, and override anything with flags. Both
`--flag value` and `--flag=value` work:

    arctic --config /etc/arctic/config.json
    arctic --config ./c.json --threshold 5
    arctic --threshold=5

    arctic init          # write a starter config to stdout
    arctic --help         # usage

Keys in the config file may be written as JSON numbers (`"threshold": 3`) or as
strings (`"threshold": "3"`); both are read. A fractional value like `2.5` is
rejected rather than rounded.

A `--config` path that does not exist, or that is not valid JSON, aborts startup
with a message naming the file. It does not quietly fall back to defaults: a
config layer that is silently ignored is worse than one that is absent.

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
cargo test                              # 35 (19 library + 5 ops surface + 11 config)
cargo clippy --all-targets -- -D warnings
```

The `ops_surface` tests drive the real router in-process through
`tower::ServiceExt::oneshot`, so `/healthz`, `/version`, `/api/v1/delegate` and
`/api/v1/messages` are covered without binding a port. See `ATTRIBUTION.md` for
the paper this implements.

## Deploying

[`../../unfer/deploy/DEPLOY.md`](../../unfer/deploy/DEPLOY.md) covers booting
`arctic` together with `unfer_edge` on a fresh machine: the systemd unit, the
threshold/quorum ordering that this file's config section cannot express, the
env-var reference with defaults, and secret handling. The unit lives in
`unfer/deploy/systemd/arctic.service` rather than here, because C8's acceptance is
that one document boots *both* servers, and two runbooks in two repositories is
how an operator ends up with two half-correct setups.

One thing worth repeating from there: **`arctic` without its quorum answers
"insufficient shares" to every legitimate request.** That looks like a key
problem and is not one, which is why the unit orders itself
`After=unfer-nodes.target`.