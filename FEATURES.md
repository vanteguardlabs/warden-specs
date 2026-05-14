# Agent Warden — Implemented Features

A complete inventory of what's shipped today, with each feature explained on three axes:

1. **Concept** — what it does and why it matters.
2. **Implementation** — where the code lives and the load-bearing structs / wire shapes.
3. **Verify** — concrete steps to observe the feature working.

This is a companion to `TECH_SPEC.md`. Where the spec is design-first, this file is implementation-first: every feature listed here corresponds to working code on `main` in one or more of the 17 repos. Re-verify with `git log --oneline -10` per repo before relying on any specific file reference — code moves faster than docs.

Boot environment assumed for all "Verify" recipes:

```bash
# One-time prereqs
docker run -d --name warden-nats  -p 4222:4222 nats:2
docker run -d --name warden-vault -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault:1.18
./repos/warden-proxy/scripts/gen_certs.sh

# Two boot paths (pick by what you're testing):
./repos/warden-e2e/dev/run.sh                                               # host-cargo, full assertions (dev env)
docker compose -f repos/warden-e2e/prod/docker-compose.yml --profile stack up -d # console-with-data demo
```

The host-cargo runner (`run.sh`) builds in **debug profile on purpose** — Apple clang has been observed to segfault when building `ring`'s release-profile C code on some macOS versions.

---

## Table of contents

1. [Security pipeline (Layers 1–4)](#1-security-pipeline-layers-14)
2. [HIL — human-in-the-loop](#2-hil--human-in-the-loop)
3. [Identity & agent onboarding (WAO)](#3-identity--agent-onboarding-wao)
4. [Operator surface — console](#4-operator-surface--console)
5. [Operator authentication](#5-operator-authentication)
6. [`wardenctl` CLI](#6-wardenctl-cli)
7. [Regulatory export](#7-regulatory-export)
8. [Forensic / audit pipeline](#8-forensic--audit-pipeline)
9. [Cold-tier analytics exports](#9-cold-tier-analytics-exports)
10. [GTM tooling](#10-gtm-tooling)
11. [Test infrastructure](#11-test-infrastructure)
12. [Supply chain & threat model](#12-supply-chain--threat-model)
13. [Wire contracts](#13-wire-contracts)
14. [Known gaps](#14-known-gaps)
15. [Forensic-tier deep review](#15-forensic-tier-deep-review)

---

## 1. Security pipeline (Layers 1–4)

### 1.1 mTLS ingress (Layer 1)

**Concept.** The proxy is the single ingress point for agent traffic. Mutual TLS terminates here — every agent presents a client certificate that the proxy validates against its CA root before any handler runs. There is no "auth-less" entry path; an agent without a valid cert never reaches the security pipeline at all. The proxy parses the SPIFFE SAN URI from the cert (modern path) and falls back to the CN (`MtlsIdentity.cn`) for legacy callers during a deprecation window.

**Implementation.** `warden-proxy:8443`. Cert chain validation happens in `WebPkiClientVerifier` configured at TLS startup. The SPIFFE SAN parser runs in the connection setup layer; the parsed identity flows through every handler as `MtlsIdentity { cn, spiffe_id }`. Vault credential injection happens in `forward_upstream` — the proxy fetches per-agent upstream credentials from Vault Transit and injects them into the upstream HTTP request headers, never logging the credential value.

**Verify.**

```bash
# Without a cert — connection rejected at TLS layer, no handler invocation
curl -v https://localhost:8443/mcp     # ssl handshake failure

# With the e2e suite's bundled cert, the request reaches handle_mcp
./repos/warden-e2e/dev/run.sh              # tail logs for "mtls accept"
```

Console `/audit` shows the resolved agent identity on every row, under the column labeled **`agent`** — that's the CN/SPIFFE identity threaded through (for SPIFFE-bearing certs the column renders just the `<name>` segment of `spiffe://.../agent/<name>/...`, not the full URI).

### 1.2 Security-first serial pipeline

**Concept.** When a request arrives, the proxy resolves the security verdict (Brain → Policy, then HIL if Yellow-tier) **before** any upstream call. Earlier commits raced security against upstream via `tokio::select!` to optimize latency, but that race re-opened a side-effect window for Yellow-tier tools — a wire transfer would have fired before HIL approval. The race has been dropped. Today the proxy fails closed: upstream is only contacted on `Authorized` or HIL-Approved verdicts.

**Implementation.** `handle_mcp` in `warden-proxy/src/lib.rs` awaits the `fork` module's verdict before forking upstream. `update_history` (which records the agent's recent-call counter for velocity tracking) only runs on successful upstream calls — i.e. inside `forward_upstream`, after the verdict resolves.

**Verify.** With a Yellow-tier scenario, observe that the upstream stub never receives the request when HIL denies. Run the chaos-monkey HIL-denial scenario:

```bash
./repos/warden-chaos-monkey/target/release/warden-chaos-monkey --proxy https://localhost:8443 --scenario hil_yellow_denied
```

The proxy returns 403, and the upstream stub log shows zero invocations for that `correlation_id`.

### 1.3 Layer 2 — Brain (semantic inspection)

**Concept.** Brain is the semantic-evaluation layer. It runs three signals against every request: an **intent classifier** (Claude 4.5 Haiku) that maps the JSON-RPC body to a category, a **persona-drift** detector (Haiku) that flags when an agent's behaviour diverges from its baseline, and an **indirect-injection scanner** (Haiku + heuristic) that catches prompt-injection payloads embedded in tool inputs. The deliberate choice is that Brain's model is **separate from any agent's primary LLM** — the "Zero-Knowledge Bonus" — so a compromised agent model can't influence its own inspector.

**Implementation.** `warden-brain:8081`. Wire surface: `POST /inspect`, body `BrainRequest { agent_id, correlation_id, jsonrpc fields... }`, response `{ authorized, intent_category, reason }`. Mock mode triggered by `ANTHROPIC_API_KEY=mock-key` — used by e2e to avoid burning Anthropic tokens; falls back to regex injection detection + bigram embedding similarity. Per-call Anthropic timeout + Voyage embedding fallback prevent latency cascades.

**Verify.**

```bash
# Direct probe (with the runner's bundled e2e setup)
curl -X POST http://localhost:8081/inspect \
  -H 'content-type: application/json' \
  -d '{"agent_id":"test","correlation_id":"...","method":"tools/call","params":{...}}'

# Indirect-injection assertion
./repos/warden-chaos-monkey/... --scenario injection
```

Console `/audit` shows `intent_category` and `reasoning` columns.

### 1.4 Layer 3 — Policy (Rego over `regorus`)

**Concept.** Policy is the rules layer. It evaluates pure-Rust Rego (`regorus` crate) over a set of `.rego` files describing tool denylists, business-hours windows, attestation requirements, and velocity thresholds. The proxy maps Brain's `authorized` boolean to an `intent_score` (`0.1` if true, `0.5` if false); Policy's `intent_score >= 0.2` rule means a Brain rejection alone fails policy — Brain and Policy compose as defense-in-depth, not as alternatives.

**Implementation.** `warden-policy-engine:8082`. Wire surface: `POST /evaluate`, body `PolicyInput { tool_type, agent_history, intent_score, agent_id, method, current_time, correlation_id, recent_request_count, attestation, agent_spiffe }`. The proxy stamps `current_time` (RFC 3339) explicitly; the rego fallback `time.now_ns()` only fires for non-proxy callers. Rego files live at `warden-policy-engine/policies/*.rego` (denylist, business_hours, velocity, attestation).

**Verify.**

```bash
curl -X POST http://localhost:8082/evaluate \
  -H 'content-type: application/json' \
  -d '{"tool_type":"wire_transfer","agent_id":"test","method":"tools/call","intent_score":0.1,"current_time":"<RFC 3339 UTC>","recent_request_count":0}'
```

Returns `{ "allow": false, "reason": "..." }` — wire_transfer requires HIL or attestation.

### 1.5 Velocity tracker — two backends

**Concept.** A circuit breaker against runaway agents. Tracks per-agent request rate over a sliding window and breaks the circuit when the rate exceeds threshold. Two backends: `InProcessTracker` for single-process deployments, `NatsKvTracker` for clustered ones. The two-backend split exists because you want production deploys to share state across replicas (so an agent burst can't be amplified by load-balancing across pods) but local development shouldn't need a NATS dependency.

**Implementation.** `warden-policy-engine` selects via `WARDEN_VELOCITY_BACKEND={in-process|nats-kv}`. Falls back to in-process if `nats-kv` is requested but NATS is unreachable. `InProcessTracker` is `HashMap<String, VecDeque<Instant>>`. `NatsKvTracker` uses a JetStream KV bucket with JSON-encoded ms timestamps and a CAS update loop with per-agent local mutex.

**Verify.**

```bash
./repos/warden-chaos-monkey/... --scenario velocity_breaker     # MUST run last
```

The chaos-monkey ordering rule: `velocity_breaker` runs last because the policy tracker records every `/evaluate`, so a mid-run burst would rate-limit subsequent attacks. The e2e runner (`run.sh`) exercises the nats-kv backend with a per-run unique bucket so test runs don't interfere.

### 1.6 Layer 4 — Ledger (hash-chained forensic store)

**Concept.** Append-only forensic store. Every security verdict, every HIL transition, every agent lifecycle event becomes a row in a SHA-256 hash-chained SQLite database. The chain is the regulator-grade evidence: tamper with any historical row and every later row's hash mismatches.

**Implementation.** `warden-ledger:8083`. Hash formula:

```
genesis        = 64 × "0"
entry_hash[n]  = sha256( prev_hash[n] || "|" || canonical_json(hashable[n]) )
```

`canonical_json` is sorted-keys, no-whitespace, UTF-8 NFC. Wire surface: `POST /log` (HTTP fallback for non-NATS callers), `GET /verify` (whole-chain integrity check), `GET /audit/correlation/{id}` (per-request reconstruction), `POST /export/regulatory` (see §7), `POST /export` (cold-tier Iceberg+Parquet, see §9). NATS subscriber on `warden.forensic` is the primary ingestion path.

**Verify.**

```bash
curl http://localhost:8083/verify
# {"valid":true,"row_count":1234,"head_hash":"..."}
```

Console `/audit` is the human-readable view; `wardenctl regulatory export` produces the auditor-grade artifact.

### 1.7 Three coexisting chain versions

**Concept.** The hash chain has evolved three times. v1 was the original verdict-only shape. v2 added per-action cryptographic signatures (`agent_spiffe`, `signature`, `key_id`). v3 added lifecycle-event row anchoring (a different hashable shape entirely, keyed on `event_kind` + `payload_sha256`). All three coexist in the same SQLite table; the verifier dispatches per-row based on a version marker. This avoids retroactive re-signing — a row written under v1 verifies under v1 forever.

**Implementation.** `CURRENT_CHAIN_VERSION = 3` constant in `warden-ledger`. `recompute_for_version` is the dispatch function; each version has its own `HashableEntryV<N>` struct. The field order **is** the chain version — reordering silently invalidates every existing entry, which is why CLAUDE.md flags the order as locked. Adding a new shape means adding `HashableEntryV<N>` + a new `recompute_for_version` arm, never editing older variants. An unknown version surfaces as the `unsupported_chain_version` signal.

**Verify.** Mixed v1/v2/v3 export verification:

```bash
./repos/warden-e2e/dev/run.sh        # produces a chain with all three versions
curl -s http://localhost:8083/verify | jq .valid    # true
```

The e2e runner specifically covers mixed-version export to assert the dispatch is wired correctly across boundaries.

### 1.8 Append-only `chain_vacuum_cursor`

**Concept.** Long-running deployments accumulate ledger rows; SQLite size grows. Operators want to vacuum old rows after they've been exported to cold storage. But naive deletion would break chain verification — the verifier needs the genesis row to seed `expected_prev`. The append-only `chain_vacuum_cursor` table records "the chain has been vacuumed up to seq N, and the prev_hash at seq N was X" so the verifier can pick up from a cursor instead of genesis.

**Implementation.** `warden-ledger` `chain_vacuum_cursor` SQLite table. Vacuum is **opt-in** post-export — it never runs automatically. The verifier checks the cursor table first; if a cursor exists, `expected_prev` starts from the cursor's recorded hash, not from genesis. Cursor rows are themselves append-only so the audit trail of vacuums is preserved.

**Verify.** Run an export, then trigger vacuum (via the operator-side endpoint or CLI), then re-verify the chain:

```bash
curl http://localhost:8083/verify    # still valid after vacuum
```

This is mostly a disk-pressure relief feature; day-1 deployments don't need it (~3.5 GB/year at 10k rows/day).

### 1.9 Policy mutability — SQLite store + write API + outbox

**Concept.** Policy used to be configured by editing `policies/*.rego` and `policies/*.json` on disk and redeploying the policy engine. Two operational gaps fell out: the only audit trail was `git log` (no anchor in the chain), and tuning the attestation allowlist for a single new measurement still meant a code push. The mutability surface closes both — every policy now lives in SQLite alongside an append-only version table; mutations land via a typed API; the engine atomically rebuilds without dropping in-flight `/evaluate` calls; every change anchors as a `policy.*` chain v3 row through a durable outbox. The console UI is *not* a no-code editor — operators still write rego — but the change loop collapses from "PR + redeploy" to "edit + Save" with a stronger audit trail. Rollback is one-click against the version-history table.

**Implementation.** `warden-policy-engine` modules: `storage.rs` (SQLite-backed `policies` + `policy_versions` + `policy_outbox` tables), `validation.rs` (regorus compile gate for `rego` content type, JSON Schema gate for `json`), `write_api.rs` (the create/update/state/rollback/delete handlers), `outbox_worker.rs` (drains `policy_outbox` to NATS `warden.forensic`). Wire surface (Viewer reads, Admin writes):

```
GET    /policies                              list (Viewer)
GET    /policies/{name}                       current + metadata (Viewer)
GET    /policies/{name}/versions              version timeline (Viewer)
GET    /policies/{name}/versions/{n}          historical body (Viewer)
GET    /policies/{name}/diff?from=N&to=M      unified diff (Viewer)
POST   /policies                              create (Admin)
PUT    /policies/{name}                       update (Admin)
POST   /policies/{name}/activate              (Admin)
POST   /policies/{name}/deactivate            (Admin)
DELETE /policies/{name}                       soft delete (Admin)
POST   /policies/{name}/rollback/{version}    (Admin)
```

Write requests carry `{reason: string, expected_current_version: int}` (required `reason` is the human-readable change rationale; `expected_current_version` enables 409-on-conflict optimistic concurrency so two operators editing the same policy can't silently clobber each other). Failure shapes: `400` for parse/validation errors (regorus error returned verbatim), `409` `policy_version_conflict` with the new metadata so the UI can prompt "policy was changed since you opened the editor; reload?", `403` for `Admin`-gated routes called by lower roles. Boot ingestion: if the `policies` table is empty, `build_engine_from_dir` reads `policies/*` from disk into SQLite once; subsequent boots load directly from SQLite. The chain side is event-kind-polymorphic — no v4 bump needed; new event kinds are `policy.created`, `policy.updated`, `policy.activated`, `policy.deactivated`, `policy.deleted`, `policy.rollback`.

**Verify.**

```bash
./repos/warden-e2e/dev/run-policies.sh
# Boots policy-engine + ledger + NATS, drives the full mutation surface
# end-to-end, asserts every mutation lands as a policy.* chain v3 row
# and the chain still verifies after each.
```

For the console UI counterpart, see §4.10.

### 1.10 Audit-agent fan-out (`GET /agents`)

**Concept.** The console's `/audit` page wants to default to "show me every agent that's ever logged a row" when no search criteria are typed. Computing that list from chain rows on every page load is wasteful; a small endpoint that returns the distinct CN/SPIFFE-name set is cheap and cacheable. Used in tandem with the simulator's roster so transient demo agents and real agents both appear in the default fan-out.

**Implementation.** `GET /agents` on `warden-ledger`. Reads via `list_distinct_audit_agent_ids` against the `audit` table, returns `{ agents: [...] }`. SDK side: `LedgerClient::list_agents() -> Vec<String>`. Console fan-out: `(sim_roster_from_admin) ∪ (ledger /agents response)`.

**Verify.**

```bash
curl http://localhost:8083/agents | jq .agents
```

### 1.11 Pluggable storage backend (SQLite + Postgres)

**Concept.** Until v0.5.0 the ledger was SQLite-only, which capped deployment to a single replica — concurrent writers on a shared PVC corrupt SQLite even with WAL, and SQLite's locking doesn't reach across hosts. The pluggable backend lifts that pin: Postgres mode lets N ledger replicas share one managed Postgres instance, with the `entries.seq UNIQUE` constraint serializing the chain append across pods. SQLite stays the default for single-node deployments and dev. **The chain hash is backend-agnostic** — byte-identical `entry_hash` values across SQLite and Postgres for the same `AppendRequest` sequence, enforced by a cross-backend equivalence test. A chain produced under one backend verifies under the other.

**Implementation.** `LedgerStore` trait in `warden-ledger/src/storage.rs` covers every chain primitive — `append`, `latest_seed`, `read_for_agent` / `_paged` / `count`, `read_for_correlation`, `read_all`, `read_after_seq`, `list_audit_agent_ids`, `read_lifecycle_for_agent`, `read_payload`, `ping`. Two impls: `SqliteLedgerStore` (default, file-backed) and `PostgresLedgerStore` behind the `postgres` cargo feature (`tokio-postgres` + `deadpool-postgres`). `AppState.store: Arc<dyn LedgerStore>` is always set; `AppState.conn: Option<Arc<Mutex<Connection>>>` is populated only in SQLite mode so SQLite-shaped reporting queries (cold-tier export, regulatory bundle, Iceberg metadata, egress sweeper) keep their direct connection. Verify also flows through the trait — `verify_chain_via_store` mirrors per-row version dispatch + JWKS signature check + v3 payload integrity. Equivalence test at `tests/storage_equivalence.rs` feeds 16 deterministic fixtures (v1/v2/v3) through both backends and asserts byte-identical hashes.

Backend select at boot:

```
WARDEN_LEDGER_BACKEND={sqlite|postgres}   # default: sqlite
WARDEN_LEDGER_PG_URL=postgres://...       # required when backend=postgres
WARDEN_LEDGER_DB=/var/lib/warden/...      # sqlite-mode only
```

Postgres mode disables the SQLite-only routes (`POST /export`, `GET /exports`, `POST /export/regulatory`, the egress sweeper) — they return `503 Service Unavailable` with a diagnostic. SIEM ingest in Postgres mode wires directly against the chain table; cold-tier export is the only feature that requires SQLite for now.

Helm wiring lives in `warden-e2e/charts/warden/values.yaml` — SQLite mode pinned to `replicas: 1`, Postgres mode lifts the pin. The "Postgres ledger mode" section of `warden-e2e/HA_RUNBOOK.md` documents the multi-replica deploy + the disabled-feature list.

**Verify.**

```bash
# SQLite (default)
cargo run --bin warden-ledger

# Postgres
docker run -d --rm --name pg -p 5432:5432 -e POSTGRES_PASSWORD=test postgres:16-alpine
WARDEN_LEDGER_BACKEND=postgres \
  WARDEN_LEDGER_PG_URL="postgres://postgres:test@127.0.0.1:5432/postgres" \
  cargo run --features postgres --bin warden-ledger

# Cross-backend equivalence
WARDEN_TEST_POSTGRES_URL="postgres://postgres:test@127.0.0.1:5432/postgres" \
  cargo test --features postgres --test storage_equivalence
# test sqlite_and_postgres_produce_identical_chain ... ok
```

### 1.12 Observe-only mode (`WARDEN_MODE=observe`)

**Concept.** New deployments don't want enforcement to bite on day one — false positives during the tuning window stall agents and burn operator trust. Observe mode flips every deny / review verdict to allow at the proxy boundary while still emitting the forensic event, including a `would_deny` / `would_park` annotation. Operators tune policy against real traffic for a week, then promote to `enforce`. The default is `enforce` so a misconfigured environment fails closed.

**Implementation.** `warden-proxy` reads `WARDEN_MODE={enforce|observe}` (default `enforce`); `warden-lite` exposes the same toggle under `WARDEN_LITE_MODE`. In observe mode the verdict-to-status mapping in `forward_or_block` short-circuits to `Authorized`, but the forensic event carries the original `verdict` and an `observe_mode` flag so downstream audit and webhooks can distinguish "would-have-blocked" from "allowed". The `warden_proxy_would_deny_total` / `warden_proxy_would_park_total` Prometheus counters surface the gap between current policy posture and an enforcement-on world.

**Verify.**

```bash
WARDEN_MODE=observe ./repos/warden-e2e/dev/run.sh
# trigger any scenario that would normally deny
curl http://localhost:9001/metrics | grep warden_proxy_would_deny_total
# counter increments; agent received 200
```

### 1.13 Rate limiting + quotas (proxy ingress)

**Concept.** Before Brain / Policy run, the proxy enforces a token bucket per `agent_id` and per `tenant` (SVID URI `tenant/<t>`). Burst spikes from a runaway agent get bounced with `429 Too Many Requests` before they touch the security pipeline; tenant-wide quotas put a ceiling on shared-noisy-neighbor cost. Forensic events tag the throttle (`signal=rate_limited_{agent,tenant}`) so audit lists exactly which scope tripped. Opt-in: default 0 leaves the limiter `None` and the fast path skips the gate entirely.

**Implementation.** Token-bucket gate in `warden-proxy::handle_mcp`, runs before `handle_mcp_inner`'s Brain/Policy pipeline. Per-agent and per-tenant buckets keyed on the parsed `MtlsIdentity`. Knobs: `WARDEN_PROXY_RATE_LIMIT_PER_AGENT_QPS` / `WARDEN_PROXY_RATE_LIMIT_PER_TENANT_QPS`. 429 body is a structured JSON `{error, scope, key, retry_after_secs, correlation_id}`. New counter `warden_proxy_rate_limit_denied_total{scope}`. `warden-lite` ships the per-agent half (no SVID tenant to derive from); 429 body shape identical minus `scope`.

**Verify.**

```bash
WARDEN_PROXY_RATE_LIMIT_PER_AGENT_QPS=2 ./repos/warden-e2e/dev/run.sh
# burst more than 2 RPS from a single client cert
for _ in $(seq 1 10); do curl -sk --cert client.crt --key client.key https://localhost:8443/mcp -d '{}' & done
# Some return 200, some 429 with retry_after_secs body
```

### 1.14 Policy starter pack (7 Rego templates)

**Concept.** A fresh policy engine without rules denies nothing — but writing seven Rego files cold is a non-trivial first day. The starter pack ships ready-made templates for the common ground-truth bad cases: PII egress, prod-DB writes, money moves, agent impersonation, prompt-injection indicators, off-hours actions, rate-limit review. Each adds rules to `warden.authz`'s deny / review sets; `governance.rego` keeps the `allow if` gate. Operators copy what they want, drop them in `policies/templates/`, and either tune in-place or use the `wardenctl generate-policy` command (§6.6) to scaffold against the sibling repo.

**Implementation.** `repos/warden-policy-engine/policies/templates/`. Seven files: `pii_egress.rego`, `prod_db_writes.rego`, `money_moves.rego`, `agent_impersonation.rego`, `prompt_injection.rego`, `off_hours_actions.rego`, `rate_limit_review.rego`. Each declares packages under `warden.authz.{templates,deny,review}` so they compose with `governance.rego`'s entry point without conflict. Test coverage at `tests/policy_templates.rs` — 17 integration tests probing each template against trigger inputs and safe-baseline inputs.

**Verify.**

```bash
ls repos/warden-policy-engine/policies/templates/
# pii_egress.rego  prod_db_writes.rego  money_moves.rego ...
cargo test --manifest-path repos/warden-policy-engine/Cargo.toml policy_templates
# 17 passed
```

---

## 2. HIL — human-in-the-loop

### 2.1 Yellow-tier state machine

**Concept.** Some tool calls are too expensive (or too irreversible) to auto-approve even when Brain and Policy bless them. Wire transfers, account deletions, large refunds — the "Yellow tier." For these, the proxy parks the request at `warden-hil`, which surfaces it to a human approver and resolves the verdict on their click. The state machine is `Pending → Approved | Denied | Expired`. Approved → upstream fires (proxy treats it like Authorized). Denied/Expired/poll-timeout → 403 to the agent.

**Implementation.** `warden-hil:8084`. Wire surface: `POST /pending` (proxy creates) with body `CreatePending { agent_id, correlation_id, method, request_payload, risk_summary, ttl_seconds, sandbox_report }`; `GET /pending/{id}` long-polled by the proxy until status leaves `pending`; `POST /pending/{id}/decide` for approver clicks; `POST /pending/{id}/modify` for modify-and-resume. Each state transition emits a NATS forensic event that lands in the chain.

**Verify.** Drive the centerpiece scenario through the simulator and watch a row land in `/audit` with `tool_type=wire_transfer` in `Pending` state, then approve via console `/hil`, watch upstream fire.

```bash
# Boot stack
docker compose -f repos/warden-e2e/prod/docker-compose.yml --profile stack up -d
# Open the simulator's run flag
curl -X POST http://localhost:9100/running -d '{"running":true}'
# Approve the queued wire_transfer in the console
open http://localhost:8085/hil
```

### 2.2 Sandbox preview (`sandbox_report`)

**Concept.** When an approver sees a Yellow-tier request, they need to know what the action would actually do — not just "this is a wire_transfer to account X." The `warden-sandbox` static analyzer parses the MCP tool call and produces a structured preview: classification (`Read`/`Write`/`Exec`/`Network`/`Delete`), severity, target list, summary. The HIL approver UI renders this verbatim so the operator can see "this would `rm -rf /etc/letsencrypt`" alongside the raw `risk_summary`.

**Implementation.** `warden-sandbox` is a pure-Rust static analyzer crate. Proxy calls it in `sandbox_handoff.rs` before posting to HIL; the report is serialized as opaque JSON in `CreatePending.sandbox_report`. HIL persists it verbatim, returns it on `GET /pending/{id}` so the console can render the annotated preview.

**Verify.**

```bash
curl http://localhost:8084/pending/<id> | jq .sandbox_report
# { "classification": "Network", "severity": "high", "targets": [...], "summary": "..." }
```

In the console `/hil/{id}` page, the sandbox report renders above the raw payload.

### 2.3 Modify-and-resume

**Concept.** Sometimes an approver looks at a pending request and thinks "this would be fine if it were $100 instead of $5000." Rather than denying and forcing the agent to retry, the approver edits the payload in the UI and approves the modified version. The chain records both the original and the modified payloads.

**Implementation.** `POST /pending/{id}/modify` on `warden-hil`. Console exposes a textarea-edit form; htmx submits the modified payload; the proxy's long-poll resolves with the modified payload, which is what gets forwarded upstream. Two chain rows: the `pending.created` (with original) and the `pending.approved` (with modified payload + a flag that modification occurred).

**Verify.** In the console `/hil/{id}` page, click "Modify" — the payload becomes editable. Save → approve. Check the chain for both rows:

```bash
curl "http://localhost:8083/audit/correlation/<correlation_id>" | jq
```

### 2.4 Async callback flow (`X-Warden-Callback-URL`)

**Concept.** The default Yellow-tier flow is synchronous — the proxy long-polls HIL and the agent's request hangs until decide / expiry. Async callback inverts the dependency: the agent supplies a callback URL on `/mcp`, the proxy returns `202 Accepted` immediately with the correlation ID, and on operator decide HIL POSTs the resolution to the agent's callback. Frees the agent to do other work while the human decides — important for long-tail review windows that exceed sensible HTTP timeouts. Callback targets are gated against an explicit allowlist so a compromised agent can't redirect resolutions to an attacker.

**Implementation.** `warden-lite` ships the OSS surface today; full-stack `warden-proxy + warden-hil` push variant is the next layer. Agent supplies `X-Warden-Callback-URL: <url>` on `/mcp`; on operator decide warden-lite POSTs `{correlation_id, decision, decider_note, decided_at}` fire-and-forget. URLs must match a prefix in `WARDEN_LITE_CALLBACK_ALLOWLIST`; unset rejects callbacks entirely (partners fall back to polling). Failures log at `warn` and never delay the operator response.

**Verify.**

```bash
WARDEN_LITE_CALLBACK_ALLOWLIST=https://my-agent.example.com/ \
  warden-lite serve &
# Agent makes a request and supplies the callback URL
curl ... -H "X-Warden-Callback-URL: https://my-agent.example.com/decide" ...
# Returns 202 Accepted with correlation_id. After approve via /pending/{id}/decide,
# warden-lite POSTs to the agent's callback.
```

### 2.5 Mobile-responsive approver flow

**Concept.** Approvers are not at their desk when production wakes them. The console's HIL queue needs to be operable on a phone: 44pt tap targets, swipeable nav, no horizontal scroll on 375px viewports. Slack notifications carry an "Open in console" deep-link so the approver lands directly on the right pending without hunting through the queue.

**Implementation.** `warden-console/templates/hil*.html` + `static/styles.css` enforce mobile-first widths; the Approve / Deny / Modify buttons are sized for thumb input and the queue uses a swipeable carousel pattern (CSS scroll-snap, no JS library). `warden-hil` reads `WARDEN_CONSOLE_URL`; when set, the Slack pending card embeds an "Open in console" button targeting `${WARDEN_CONSOLE_URL}/hil/${pending_id}` so a Slack-on-phone approval flow lands one tap from the queue.

**Verify.** Open `http://localhost:8085/hil` on a phone-shaped viewport (Chrome devtools → Pixel 7). Buttons hit-test cleanly with no zoom required. With `WARDEN_CONSOLE_URL` set, post a Yellow-tier from the simulator and check the Slack message — the deep-link button is present.

---

## 3. Identity & agent onboarding (WAO)

### 3.1 SVID issuance (`POST /svid`)

**Concept.** Every agent has a verifiable workload identity — a SPIFFE SVID. The format is `spiffe://<trust-domain>/tenant/<tid>/agent/<agent-name>/instance/<uuidv7>`. Three layers:`tenant` is the billing/isolation boundary, `agent` is the stable logical identity (what policy keys off of), `instance` is the per-process replica (rotates on restart so we can revoke a single misbehaving replica without grounding the fleet). The SVID is short-TTL (≤1h) so a stolen cert has a tiny replay window.

**Implementation.** `warden-identity:8086`, `POST /svid`. Caller presents attestation evidence (TPM quote, SEV-SNP report, SGX-DCAP, Nitro, GCP-Shielded, or k8s-projected token); the identity service verifies it against the per-tenant config; on success, mints the cert. SVID metadata persists in the `svids` SQLite table (`id, spiffe_id, attestation_id, not_before, not_after, revoked_at`). In `enforce` registration mode, `/svid` consults the agent registry first — unregistered names get `403 unregistered_agent`.

**Verify.**

```bash
# The e2e runner's onboarding flow exercises this end-to-end
./repos/warden-e2e/dev/run-onboarding.sh
```

Console `/agents/{id}` lifecycle timeline shows the registration row that gates issuance.

### 3.2 OIDC delegation grants (`POST /grant`)

**Concept.** A grant says "this human authorized this agent to do these things." The shape follows RFC 8693 actor-token semantics — the `act` claim makes "Alice's support-bot is acting on behalf of Alice" cryptographically explicit. This is what makes the audit story land: HIL approvers see "Alice's support-bot-3 wants to refund $42," not just "bot-7f3a wants to refund $42." Grants are short-TTL JWTs; they carry both `scope` and `yellow_scope` arrays, intersected against the agent's registered envelope at grant time.

**Implementation.** `warden-identity` `POST /grant`, body includes `id_token` (verified against per-tenant JWKS) + agent SVID mTLS. Returns a grant JWT with claims `{ iss, sub, act { sub, idp, amr }, scope, yellow_scope, exp, jti }`. Persisted in `grants` table. Envelope intersection: requested scopes ⊄ envelope → `403 scope_outside_envelope`; same for yellow.

**Verify.**

```bash
# Already-running identity + dex mock from run-onboarding.sh
TOKEN=$(curl -s http://localhost:9999/dex/token | jq -r .id_token)
curl -X POST http://localhost:8086/grant \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_spiffe":"...","scope":["mcp:read:tickets"],"yellow_scope":[]}'
```

Out-of-envelope scope returns 403 with `{"error":"scope_outside_envelope","offenders":["wire_transfer"]}`.

### 3.3 Per-action signing (`POST /sign`)

**Concept.** After the security verdict resolves, the proxy asks `warden-identity` to sign it. The signature is the legal proof that "Warden, at this timestamp, with this verdict, processed this request from this agent." The chain row carries `signature + key_id` alongside the verdict; a regulator with `manifest.sig` + the issuer JWKS can independently verify every row.

**Implementation.** `POST /sign` on identity, body `{ correlation_id, method, prev_hash, payload_canonical_json }`, header `X-Caller-Spiffe` matched against `WARDEN_IDENTITY_SIGN_ALLOWED_CALLERS`. Returns `{ signature, key_id, signed_at }`. Two backends behind the same `Sign` trait: **Vault Transit** (default — private key stays in Vault, `vaultrs` client makes the `transit/sign` call) and **`Ed25519FileSigner`** (OSS / warden-lite — loads PKCS#8 PEM from `WARDEN_IDENTITY_SIGNING_KEY_PATH`, signs with `ed25519-dalek` directly). JWKS at `/jwks.json` exposes only public material either way. Signing budget: p95 < 5ms.

**Verify.**

```bash
curl http://localhost:8086/jwks.json | jq      # public verification material
```

Then export the chain and verify a row's signature with `openssl` + `sha256sum` per the bundle's `README.txt` recipe (§7).

### 3.4 Detached blob signing (`POST /sign/blob`)

**Concept.** Sibling to `/sign`, used by `warden-ledger` for regulatory-export manifests. Signs a digest (not a structured payload), audience-tagged so a sig minted for one auditor can't be repurposed.

**Implementation.** `POST /sign/blob` on identity, body `{ digest_hex, audience }`, response `{ signature, key_id, algorithm: "ed25519", digest_alg: "sha256", signed_at }`. Same `WARDEN_IDENTITY_SIGN_ALLOWED_CALLERS` allowlist as `/sign`. Wired into ledger via `warden-ledger::identity_client::{ManifestSigner, HttpManifestSigner}`.

**Verify.**

```bash
wardenctl regulatory export --from <FROM_RFC3339> --to <TO_RFC3339> --output bundle.tar.gz
tar -xzf bundle.tar.gz
cat manifest.sig    # 128 hex chars + LF
```

### 3.5 SPIFFE federation

**Concept.** Two Warden tenants need to A2A without sharing a CA. Tenant A publishes its trust bundle at a well-known URL; Tenant B's identity service polls that URL on a schedule. Cross-tenant actor tokens redeem against a freshness-gated peer-bundle store — if Tenant B's last-seen bundle for Tenant A is stale, A2A fails with `peer_bundle_stale:<td>` rather than silently accepting potentially-revoked keys.

**Implementation.** `GET /.well-known/spiffe-bundle` (public). Federation poller in `warden-identity` configured via `WARDEN_FEDERATION_PEERS`. `POST /actor-token` mints; `POST /actor-token/redeem` consults the peer-bundle freshness gate, returning `peer_bundle_unknown:<td>`, `peer_bundle_stale:<td>`, or `jti_already_used` (single-use enforcement).

**Verify.**

```bash
./repos/warden-e2e/dev/run-federation.sh
# Boots two warden-identity instances with different trust domains and asserts:
# 1. Fresh peer bundle → A2A succeeds
# 2. Bundle staled out → peer_bundle_stale rejection
```

### 3.6 A2A actor tokens

**Concept.** When agent A calls agent B (cross-Warden, possibly cross-tenant), B's proxy needs to know that A is authorized for this specific call. A delegation grant says "A can call X" but doesn't bind to a specific outbound call. The actor token is the missing piece: A's outbound request triggers the proxy to mint a single-use, audience-bound token; B's proxy verifies the token via the federation bundle before accepting.

**Implementation.** Proxy outbound: agent sets `x-warden-audience: <target>` header; proxy calls identity `/actor-token` with `{ agent_spiffe, audience, scope, ttl_seconds }`, attaches result as `x-warden-actor-token` on the upstream call. Inbound: peer proxy sees `x-warden-actor-token`, calls identity `/actor-token/redeem`, accepts on success. JTIs are single-use — replay returns `409 jti_already_used`.

**Verify.**

```bash
./repos/warden-chaos-monkey/... --scenario cross_tenant_unfederated
# Asserts unfederated cross-tenant A2A is denied
```

### 3.7 Capability attestation enforcement

**Concept.** SVID + grant prove identity and authorization, but they don't prove the agent's *binary* is the one we approved. A compromised supply chain could swap the binary post-deploy and the SVID would still be valid. Capability attestation closes that gap: for sensitive tools (Yellow tier + a configurable allowlist), the agent's runtime presents a fresh hardware-attested measurement (TPM PCR, SEV-SNP report, etc.); Policy denies if the measurement isn't in the per-tool allowlist.

**Implementation.** `policies/attestation.rego` denies when `tool_type == wire_transfer` (or `delete_*`) and attestation is absent/stale or measurement isn't in `attestation_allowlist.json`. `PolicyInput.attestation: Option<AttestationClaims>` carries the kind, measurement, issued_at, expires_at, nonce_echo. Proxy harvests attestation from a SAN-bound cache (verified once, reused for `min(expires_at, 5min)`) or per-request `X-Warden-Attestation` header override. Six attestation kinds wired: `tpm`, `sev-snp`, `sgx-dcap`, `nitro`, `gcp-shielded`, `k8s-projected`. Rule short-circuits for non-SVID legacy CN-only callers (gates only fire when `agent_spiffe` is set).

**Verify.**

```bash
./repos/warden-chaos-monkey/... --scenario unattested_binary
# Asserts wire_transfer with measurement not in allowlist → policy deny
```

Inspect the allowlist at `repos/warden-policy-engine/policies/attestation_allowlist.json`.

### 3.8 Agent registry + lifecycle (WAO)

**Concept.** Without a registry, `POST /svid` issues for any `(tenant, agent_name)` on a first-call-wins basis — namespace-squat is wide open. The Warden Agent Onboarding (WAO) layer adds a pre-step: every agent must be **declared** before it can hold an SVID. Declaration records the human who authorized the agent, the team that owns it, and the capability envelope it's allowed to operate within. Lifecycle states (Active → Suspended → Decommissioned) give operators an incident lever; the chain records every transition.

**Implementation.** `agents` SQLite table in `warden-identity` with 14 columns including `tenant`, `agent_name`, `state`, `scope_envelope`, `yellow_envelope`, `attestation_kinds_accepted`, `created_by_sub`, `created_by_idp` (immutable — non-repudiation anchor), `owner_team` (mutable via transfer), `state_changed_*`. `UNIQUE (tenant, agent_name)` includes Decommissioned (no name reuse). Indexes on `(tenant, state)` and `(tenant, owner_team)`.

**Verify.**

```bash
wardenctl agents create --tenant acme --name support-bot-3 \
  --owner-team payments \
  --scope mcp:read:tickets --scope mcp:write:tickets \
  --yellow-scope refund:'<=50usd'

wardenctl agents list --tenant acme --state Active
wardenctl agents get <id>
```

Console `/agents` shows the registry; `/agents/{id}` shows the lifecycle timeline (chain v3 rows).

### 3.9 Lifecycle endpoints

**Concept.** Ten endpoints implementing the state machine and the per-attribute mutators. Asymmetric authority is the principle: narrowing the envelope (less capability) is owner-team self-service; widening (more capability) requires a different human with `agents:admin`. The original registering admin's signature covered the original envelope; widening is a *new* authorization event and must be a *new* authorization signature.

**Implementation.** `POST /agents/{id}/{suspend,unsuspend,decommission,envelope/narrow,envelope/widen,attestation-kinds,owner-team,description}` on `warden-identity`. All take `Authorization: Bearer <oidc_id_token>`; capabilities resolved via per-tenant group mapping in `identity.toml`. Each emits a chain v3 row (see §3.11) via the durable outbox.

**Verify.**

```bash
wardenctl agents suspend <id> --reason "investigating anomaly"
wardenctl agents unsuspend <id>                             # requires agents:admin
wardenctl agents envelope narrow <id> --scope mcp:read:tickets
wardenctl agents envelope widen <id> --scope mcp:write:knowledge-base    # requires agents:admin
wardenctl agents transfer <id> --to-team newteam            # requires agents:admin
wardenctl agents decommission <id> --reason "team disbanded"
```

### 3.10 Capability envelope (opaque scope strings)

**Concept.** A scope is a string. It's either in the envelope set or it isn't. No DSL, no parser, no semantic comparison — `refund:<=50usd` and `refund:<=100usd` are distinct strings; if the envelope contains the first, the second is rejected. Teams that want graduated tiers declare each tier as a separate envelope entry. Forward compatibility: any future structured grammar is a strict superset of opaque-string equality, so envelopes verify under every future grammar without invalidating chain v3 rows.

**Implementation.** Strings are NFC-normalized lowercase, ≤128 bytes, no whitespace. Validated by `validate_label` in `grant.rs`, reused for envelope columns. Empty envelope (`[]`) is legal and means "this agent can hold an SVID but cannot be granted any capability" — useful as a Suspended → Active rehearsal state.

**Verify.**

```bash
# Out-of-envelope scope rejected
wardenctl agents create --tenant acme --name test --scope mcp:read:tickets ...
# Then attempt grant with mcp:write — 403 scope_outside_envelope
```

### 3.11 Chain v3 lifecycle anchoring

**Concept.** Every lifecycle transition lands in the chain as a v3 row, signed by the identity issuer key. Tampering with any historical lifecycle row breaks the signature on every later row. Per-event-kind variation lives in a separate payload, content-hashed into `payload_sha256` — the outer hashable is locked at v3 launch and never altered without a v4 bump.

**Implementation.** `HashableEntryV3` order: `{ id, timestamp, event_kind, agent_id, tenant, agent_name, actor_sub, actor_idp, payload_sha256, signature, key_id, seq, prev_hash }`. Nine event kinds: `agent.registered`, `suspended`, `unsuspended`, `decommissioned`, `envelope_narrowed`, `envelope_widened`, `attestation_kinds_changed`, `owner_team_transferred`, `description_changed`. Per-kind payload schemas (e.g., `agent.registered` carries `{ scope_envelope, yellow_envelope, attestation_kinds_accepted, owner_team, description }`). Identity-side durable outbox (`agents_ledger.rs`) handles retry; ledger dispatches via `recompute_for_version`.

**Verify.**

```bash
wardenctl agents create ...        # emits agent.registered v3 row
curl http://localhost:8083/verify  # whole chain still valid

# Inspect the row
curl "http://localhost:8083/audit/correlation/<id>" | jq
```

### 3.12 Registration mode (`off|warn|enforce`)

**Concept.** A migration switch. `off` ignores the registry entirely. `warn` keeps `/svid` and `/grant` succeeding for unregistered agents but stamps an `unregistered_agent` signal on the forensic event so operators see what would have been blocked. `enforce` rejects unregistered agents with 403. The principle: registration is opt-in to enforcement — once a record exists, its envelope is enforced regardless of mode, otherwise registration in `warn` would be decorative.

**Implementation.** `WARDEN_IDENTITY_REGISTRATION_MODE` env var, parsed into `Mode::{Off, Warn, Enforce}`. **Today the default is `Enforce`** (the rollout flip has already happened). Operators bulk-enroll legacy fleets via `wardenctl agents migrate` before the flip.

**Verify.**

```bash
# Observe the enforce default
WARDEN_IDENTITY_REGISTRATION_MODE=enforce
# /svid for a never-registered (tenant, agent_name) → 403 unregistered_agent

./repos/warden-chaos-monkey/... --scenario unregistered_agent_enforce
```

---

## 4. Operator surface — console

### 4.1 Audit page (`/audit`)

**Concept.** The primary investigation surface. Every forensic row from every layer rendered in chronological order, joinable by `correlation_id`. An operator investigating an incident lands here, filters to a time window or a `correlation_id`, and sees the full bundle: proxy verdict, policy decision, HIL state transitions (if any), identity signature.

**Implementation.** `warden-console/src/handlers.rs::audit`. Reads from `warden-ledger` via `warden-sdk::LedgerClient`. Joins related rows by `correlation_id`. Filter chips for signal column (`unregistered_agent`, `peer_bundle_stale:*`, `grant_expired`, etc.). The "Hide simulated traffic" filter joins by `correlation_id` so all sim-driven rows (proxy + policy + HIL) hide together — the `source` column on the forensic event is metadata; only the proxy's first event sets it, but the join means downstream rows hide too. Default agent fan-out when no search criteria are typed = `(simulator roster) ∪ (LedgerClient::list_agents())`. Timestamps render in the browser's local timezone (rather than ledger UTC) so an operator in Berlin doesn't have to do mental arithmetic during an incident.

**Verify.**

```bash
open http://localhost:8085/audit
# Toggle "Hide simulated traffic" — sim rows disappear in groups
```

### 4.2 SSE live tail (`/stream/audit`)

**Concept.** The audit page's incident-mode counterpart. Instead of refreshing to see new rows, operators watch them stream in real time. Useful during a rollout or a chaos exercise.

**Implementation.** `/stream/audit` SSE endpoint backed by a broadcast `Sender` in `warden-ledger`. New rows fanout to every subscribed console. Authenticated — viewer-or-better via `require_viewer_api`.

**Verify.**

```bash
open http://localhost:8085/audit
# In another terminal:
./repos/warden-chaos-monkey/...      # rows appear live in the browser
```

### 4.3 HIL queue (`/hil`)

**Concept.** The approver dashboard. Lists every Pending row with `risk_summary`, `sandbox_report` preview, agent identity, and `correlation_id`. Approve / Deny / Modify buttons inline. OIDC viewers see the queue but no buttons (RBAC).

**Implementation.** `warden-console` `/hil` (list) + `/hil/{id}` (detail). htmx-driven action buttons. Backend calls `warden-hil` via `warden-sdk::HilClient`. Template carries `can_approve` flag based on session role — viewers get read-only.

**Verify.**

```bash
open http://localhost:8085/hil
# As an OIDC viewer (no approver group), buttons hidden
# As an approver, buttons render and decisions land in the chain
```

### 4.4 Agent registry UI (`/agents`)

**Concept.** Browse and manage the agent registry without dropping to the CLI. Shows the lifecycle state badge, owner team, scope counts, last activity (joined from the latest ledger row). Click into `/agents/{id}` for the full record + lifecycle timeline (every chain v3 row for this agent, newest first).

**Implementation.** `warden-console` `/agents`, `/agents/new`, `/agents/{id}`. Reads from `warden-identity` via `warden-sdk::AgentsClient`. htmx action buttons gated on caller capability (`agents:admin` for widen, owner-team-or-admin for narrow, etc.). The form on `/agents/new` dropdowns the caller's `groups` claim for `owner-team` so users can't pick teams they don't belong to.

**Verify.**

```bash
open http://localhost:8085/agents
open http://localhost:8085/agents/new
```

The audit page (`/audit`) gains an "Agent" column linkable to `/agents/{id}` if registered.

### 4.5 `/config` diagnostic page

**Concept.** Answers the "what is this binary, what is it talking to, and is everything reachable?" question without SSH access. Four cards: Console (bind, port, version, git SHA), Backends (required) — ledger + HIL with health probes, Backends (optional) — identity + simulator, Auth (session TTL, cookie_secure, currently logged in). The page is a diagnostic, not a control plane — no mutation. Open by design (matches the rest of the read-only console surface) so it works during auth incidents.

**Implementation.** `warden-console/src/handlers.rs::config` + `templates/config.html`. Probes via `warden-console/src/probe.rs` — dedicated short-timeout `reqwest::Client`, all four probes under one `tokio::join!`. Probe result classification: 2xx + <500ms = green, 2xx + 500–1500ms = amber, otherwise red with truncated reason. Operator token redacted by architecture: handler only ever has access to `bearer_fingerprint() -> Option<String>` (sha256[..8] hex prefix), never the raw token.

**Verify.**

```bash
open http://localhost:8085/config
```

You'll see the four cards; the bearer fingerprint is the redaction guard. Try killing the ledger and refreshing — the ledger card goes red with `connect refused`, the rest of the page still renders.

### 4.6 `/sim` panel

**Concept.** Live control of `warden-simulator` without dropping to curl. Pause/resume, multiplier, transient-agent control. Useful for demos and for stopping the sim mid-investigation.

**Implementation.** `warden-console` `/sim` is a thin proxy to `warden-simulator`'s admin server (`SIM_ADMIN_PORT=9100`, default loopback-only). Endpoints: `/status`, `/multiplier`, `/running`, `/auto-decide`, `/agents`. Rendered when `WARDEN_SIMULATOR_URL` is set; absent otherwise.

**Verify.**

```bash
open http://localhost:8085/sim
# Click "Start" to flip the sim on
```

The simulator boots paused (`SIM_START_RUNNING=true` overrides this); `run-stack-smoke.sh` flips the run flag via the admin server before asserting rows.

### 4.7 `/me/identities` (Slack/Teams self-link)

**Concept.** Approvers click approve buttons in three places: the console UI (OIDC session), Slack DMs (Slack OAuth), Teams DMs (Teams OAuth). All three should produce the same `decided_by` value on the chain — `oidc:<sub>` — regardless of channel. The `/me/identities` page is the operator-side flow: log in via OIDC, then link your Slack and Teams identities. After linking, channel clicks resolve to the same `oidc_sub`.

**Implementation.** `warden-console` `/me/identities` page. Slack OAuth flow (`/auth/slack/start` → callback) and Teams OAuth (symmetric). Mappings persist in `warden-hil`'s `user_identities` table — nullable per-mode columns (`oidc_sub`, `webauthn_name`, `basic_username`, `slack_user_id`, `teams_user_id`) with a CHECK constraint that exactly one identity column is set. Slack/Teams approve clicks look up `slack_user_id → oidc_sub`; if absent, return 404 "your Slack identity is not linked — link via the console first."

**Verify.**

```bash
open http://localhost:8085/me/identities
# Click "Link Slack" — Slack OAuth flow runs, link persists
```

Manifests for buyer-side Slack/Teams app registration: `warden-console/docs/slack-app-manifest.json`, `warden-console/docs/teams-app-manifest.md`.

### 4.8 Other read views

**Concept.** `/exports`, `/velocity`, `/stats/*` give operators the supporting context for an audit investigation. Exports lists past `/export` and `/export/regulatory` runs. Velocity surfaces the per-agent rate-limit state. Stats counts requests by tier, verdict, agent.

**Implementation.** All three are read-only Axum-rendered Askama templates backed by `warden-sdk` clients. Viewer-or-better gated.

**Verify.**

```bash
open http://localhost:8085/exports
open http://localhost:8085/velocity
open http://localhost:8085/stats/by-tier
```

### 4.9 Viewer-route gates

**Concept.** Without a gate, a misconfigured deploy could leak audit data to anyone who hit the URL. Every read route runs through `require_viewer` (HTML pages) or `require_viewer_api` (SSE + JSON) middleware. No-session HTML requests redirect to `/login` (303); no-session SSE/JSON requests get 401 (so the browser doesn't follow the redirect into a non-HTML stream).

**Implementation.** `warden-console/src/handlers.rs::require_viewer` + `require_viewer_api`. Disabled mode short-circuits both gates with a synthetic Approver session for dev/CI. HIL queue template carries `can_approve` flag so OIDC viewers see the queue contents but no Approve/Deny/Modify buttons.

**Verify.**

```bash
# Without a session
curl -i http://localhost:8085/audit
# HTTP/1.1 303 See Other
# Location: /login

curl -i http://localhost:8085/stream/audit
# HTTP/1.1 401 Unauthorized
```

### 4.10 Policy management (`/policies`)

**Concept.** Browser-side counterpart to §1.9. Lists every loaded policy with its state (active/inactive, current version, last editor, last reason). Click into a policy for the textarea editor, the diff modal against any historical version, and one-click activate / deactivate / rollback / delete. Required free-text reason on every mutation — the chain row gets it verbatim. Read views are Viewer-or-better; every mutation is `Role::Admin`-gated server-side, with the buttons hidden client-side for lower roles.

**Implementation.** `warden-console` `/policies` (index), `/policies/new` (create form), `/policies/{name}` (detail + history), `/policies/{name}/edit` (textarea editor), `/policies/{name}/diff?from=N&to=M` (unified diff), plus `POST` handlers for activate / deactivate / rollback and `DELETE` for soft-delete. All call `warden-sdk::PoliciesClient`. Optimistic concurrency: the edit form carries a hidden `expected_current_version`; the conflict response (`409 policy_version_conflict`) renders an htmx flash with "policy was changed since you opened the editor; reload?". Validation errors (regorus compile failure, JSON Schema mismatch) render below the textarea verbatim, including line/column markers from the parser.

**Verify.**

```bash
open http://localhost:8085/policies
# Edit a rego file, save with reason — chain v3 row lands in /audit
```

End-to-end coverage in `./repos/warden-e2e/dev/run-policies.sh` (see §11.7).

### 4.11 Cost + latency dashboard (`/stats/cost-latency`)

**Concept.** Operators need one page that answers "is the security pipeline meeting its latency SLA, and what is it costing us per agent?" The dashboard scrapes `/metrics` from every warden service, parses Prometheus text format with a lenient hand-rolled scraper (no Pushgateway dependency), and surfaces per-service / per-endpoint p50 / p99 / request counts / error rates in one table. Cost is operator-driven: set per-tool prices and the dashboard multiplies ledger row counts over a rolling 24h window. Empty cost table renders an in-page "ingest not configured" explainer rather than blank.

**Implementation.** `warden-console` `/stats/cost-latency` route. Env vars: `WARDEN_CONSOLE_METRICS_URLS` (comma list of `{name}={url}` pairs; sensible localhost defaults), `WARDEN_CONSOLE_TOOL_COSTS=tool:$/call,…`. Pure-Rust Prometheus scraper at `warden-console/src/metrics_scrape.rs` — no `prometheus-parse` dependency (its strictness rejects our `# HELP` formatting in places). Cost rollup queries `warden-ledger`'s `/audit` for the 24h window per configured tool.

**Verify.**

```bash
WARDEN_CONSOLE_TOOL_COSTS="stripe.refund:0.02,search.web:0.001" \
  cargo run --bin warden-console
open http://localhost:8085/stats/cost-latency
```

### 4.12 Audit narrative view (`/audit/agents/{id}/narrative`)

**Concept.** The `/audit` page renders rows. Sometimes you want the story instead — "Everything `support-bot-3` did this week" as a paragraph plus a sparkline plus a top-intent breakdown. The narrative view aggregates the agent's recent ledger window into a `Narrative` shape: headline sentence, hourly/daily sparkline, top intent categories with percentages, top tools by call count, distinct deny reasons with sample reasoning, HIL summary (pending/approved/denied/expired/unreachable), signal annotations, and a notable-events timeline that filters routine traffic out. Same demo-prefix gating as `/audit` and HIL `/decide` so a visitor only narrates their own synthetic agent.

**Implementation.** `warden-console` `/audit/agents/{agent_id}/narrative` route + `narrative.rs` module. Window selector: 1d / 7d (default) / 30d / 90d (hard cap). Bucket granularity auto-picks hourly for 1d, daily for longer. `/audit` page gains a "Story view →" header link surfaced only when exactly one literal agent is in the filter — hidden for wildcards and the all-agents view so the link never misleads about scope. 14 lib tests covering window parsing, empty-state, outside-window drops, headline pluralisation, top-N sort, HIL category mapping, deny-vs-review separation, signal aggregation, notable-events ordering, and bucket-granularity selection.

**Verify.**

```bash
open http://localhost:8085/audit/agents/support-bot-3/narrative?window=7d
```

---

## 5. Operator authentication

### 5.1 Four auth modes

**Concept.** Buyers come in four flavors. Solo evaluators want a single password. Self-hosted small teams want WebAuthn passkeys without an SSO dependency. Production deployments want OIDC against their existing IdP. Dev and CI want auth bypassed entirely. Mode selection is a runtime knob (`WARDEN_CONSOLE_AUTH={disabled|basic-admin|webauthn|oidc}`), not a build-time choice — operators flip modes without rebuilding.

**Implementation.** `warden-console/src/auth_session.rs::AuthMode` enum. Each mode has its own session-establishment path: `disabled` short-circuits to a synthetic Approver session; `basic-admin` validates against `WARDEN_CONSOLE_ADMIN_USER` + `WARDEN_CONSOLE_ADMIN_PASS_BCRYPT` (bcrypt verify); `webauthn` proxies the ceremony to HIL; `oidc` runs the auth-code flow against any compliant IdP.

**Verify.**

```bash
# basic-admin mode
WARDEN_CONSOLE_AUTH=basic-admin \
  WARDEN_CONSOLE_ADMIN_USER=admin \
  WARDEN_CONSOLE_ADMIN_PASS_BCRYPT='$2b$12$...' \
  cargo run -p warden-console
```

The `/login` page renders different forms per mode.

### 5.2 Loopback bind enforcement

**Concept.** `disabled` and `basic-admin` modes are dangerous outside a developer laptop. Boot guards refuse to come up if those modes are paired with a non-loopback bind. `basic-admin` has a documented escape hatch (`WARDEN_CONSOLE_ALLOW_BASIC_ADMIN_NETWORK=true`) for evaluators who want to expose a basic-auth-protected console behind a reverse proxy; `disabled` has no escape — production deploys that need auth-off must also be loopback-bound.

**Implementation.** `guard_loopback(bind, mode_name, allow_override)?` in `warden-console/src/auth_session.rs`. Called during AppState construction; returns Err on mismatch; main panics out with a clear message.

**Verify.**

```bash
WARDEN_CONSOLE_AUTH=disabled cargo run -p warden-console -- --bind 0.0.0.0
# refuses to boot:
# error: auth mode 'disabled' requires loopback bind, got 0.0.0.0
```

### 5.3 WebAuthn approver auth

**Concept.** Passkey auth, with HIL as the credential authority. The console proxies the registration and authentication ceremonies but doesn't hold the credentials. The verified principal flows back to HIL on `/decide` so the chain row's `decided_by` matches the credential that actually clicked.

**Implementation.** Console: `/auth/login/begin` and `/auth/login/finish` proxy the ceremonies to HIL. HIL: stores `webauthn_credentials` table; verified principal stamps `decided_by = "webauthn:{name}"` server-side. Session cookie shuttles back to the browser.

**Verify.** Console `/login` in WebAuthn mode prompts a passkey ceremony. After auth, approving a HIL pending stamps `webauthn:<name>` on the chain row.

### 5.4 OIDC code flow + JWKS

**Concept.** Generic OIDC against any compliant IdP. Tested in CI against Keycloak (the only IdP with reliable Dockerized fixtures); quickstart docs cover Google / Okta / Azure AD / Auth0 without CI fixtures (their public test infra is unreliable). JWKS is cached for an hour, refreshed reactively on signature failure.

**Implementation.** `warden-console/src/auth_handlers.rs` runs the auth-code flow, validates the `id_token` against the per-tenant JWKS, extracts `sub` + `groups`, builds the session. Session cookie via `tower-sessions`.

**Verify.**

```bash
# Boot stack with Keycloak fixture (warden-e2e ships one)
docker compose -f repos/warden-e2e/prod/docker-compose.yml --profile stack-oidc up -d
open http://localhost:8085/login
# Redirects to Keycloak, returns with session
```

### 5.5 RBAC (viewer / approver / admin)

**Concept.** Three static roles, monotonically increasing capability. `viewer` = read-only across the console. `approver` = viewer + ability to decide HIL pending items. `admin` = approver + the policy-management write surface (§4.10). No runtime role exceptions — the IdP's `groups` claim is the source of truth, mapped via config-as-code. Out-of-band admin operations on the agent registry still go through `wardenctl` + direct identity API.

**Implementation.** `OidcGroupMap { admin_groups, approver_groups, viewer_groups: Vec<String> }` in `warden-console/src/auth_session.rs`. Configured via env CSV. Session carries the resolved `Role::{Admin, Approver, Viewer}`; ordering is encoded in `Role::at_least(other)`. Middleware: `require_viewer` (read), `require_approver` (HIL decide), policy mutations check `Role::Admin` inline.

**Verify.**

```bash
# In Keycloak, put the test user in only `viewer_groups`
# Login → /audit works → /hil works (read-only) → buttons hidden
```

### 5.6 Server-stamped `decided_by`

**Concept.** Originally the chain stamped `decided_by = "warden-console"` regardless of which human clicked. After the fix, HIL stamps `decided_by` server-side from the verified principal — the request body can't override it. Three formats: `webauthn:{name}`, `oidc:<sub>`, `basic:<username>`.

**Implementation.** `warden-hil/src/decide.rs` resolves the verified principal from session/cookie/bearer and writes it to the chain row. Slack and Teams clicks stamp `oidc:<sub>` via the linked `oidc_sub` lookup — the underlying channel ID never appears on the chain.

**Verify.**

```bash
# Approve a pending via console as `alice@acme.com` → chain row carries decided_by="oidc:alice@acme.com"
curl http://localhost:8083/audit/correlation/<id> | jq '.[] | .decided_by'
```

### 5.7 `approver_assertion` JSON blob

**Concept.** Hook for stronger per-decision claims later. Today: just records `{ method, credential_id|sub|username, iat }` per format. Hooks for future per-decision WebAuthn step-up over OIDC sessions.

**Implementation.** Field on the HIL state-transition forensic event. WebAuthn shape: `{ method: "webauthn", credential_id: "...", iat: ... }`. OIDC: `{ method: "oidc-session", sub: "...", iat: ... }`. Basic-admin: `{ method: "basic-admin", username: "..." }` (intentionally cheap — no chain-of-trust to assert).

**Verify.**

```bash
curl http://localhost:8083/audit/correlation/<id> | jq '.[] | .approver_assertion'
```

### 5.8 Console → HIL trust (mode-dependent)

**Concept.** Two trust paths, depending on the console's auth mode. WebAuthn mode keeps HIL as the credential authority — it's already a stronger primitive and we don't tear it out. OIDC / basic-admin / disabled modes use a shared bearer token (`WARDEN_HIL_DECIDE_TOKEN`); the console verifies the operator, stamps `decided_by`, and presents the bearer to HIL on `/decide`. HIL accepts the request-body `decided_by` only when the bearer validates. The bearer is the interim posture; internal s2s mTLS via warden-identity SVIDs is the planned uniform replacement.

**Implementation.** Console: `auth_handlers.rs` calls HIL with `Authorization: Bearer <DECIDE_TOKEN>` + `X-Warden-Decided-By: <principal>`. HIL: middleware verifies the bearer (constant-time compare); without it, falls back to `Authn::Disabled` legacy path. Console refuses to boot if the configured mode requires the token and it's missing.

**Verify.**

```bash
# Tamper with the X-Warden-Decided-By header without a bearer
curl -X POST http://localhost:8084/pending/<id>/decide \
  -H "X-Warden-Decided-By: admin@evil.com" \
  -d '{"approve":true}'
# 401 missing bearer
```

### 5.9 Sessions, CSRF, JWKS cache

**Concept.** Mechanical defaults that don't warrant their own sections.

**Implementation.**

- `tower-sessions`, server-side encrypted cookie, 8-hour rolling lifetime (`DEFAULT_SESSION_TTL_SECS = 28800`).
- CSRF: htmx + origin-check + per-session token (no separate state cookie).
- OIDC JWKS: 1-hour cache TTL, reactive refresh on signature failure.
- Logout: clears server session, optionally calls IdP `end_session_endpoint`.

**Verify.** Inspect cookie attributes after login; reload after 8 hours and observe re-prompt.

### 5.10 SAML SP (feature-gated)

**Concept.** OIDC covers the bulk of modern enterprise SSO (Okta, Azure AD, Google Workspace, OneLogin all speak it), but SAML-only IdPs — older Shibboleth, ADFS, some Ping Federate installs — still exist in regulated industries. The console ships a SAML SP behind the `saml` cargo feature so deployments needing it can build with SAML wired in, while default builds keep the static-cargo posture (samael pulls libxml2 + libxmlsec1 via FFI). The role-resolution layer reuses the same OIDC group-map (§5.5) — the SAML half is purely about the bind protocol.

**Implementation.** `warden-console` `AuthMode::Saml(SamlConfig)` arm. Consumes IdP metadata at boot (URL or inline XML); verifies XML-DSig assertions via `samael`'s xmlsec backend; extracts NameID + group attribute with Okta / Azure AD / Google Workspace / OneLogin attribute names recognized. Browser flow: `GET /auth/saml/login` (HTTP-Redirect AuthnRequest) → `POST /auth/saml/acs` (HTTP-POST signed SAMLResponse). Audit chain stamps `decided_by = saml:<NameID>`. RBAC hardening alongside: every gate deny bumps `warden_console_role_denials_total{required,actual}` so SREs can alarm on suspicious access attempts. Builds via `--build-arg WARDEN_CARGO_FEATURES=saml` against the Dockerfile, which conditionally installs the matching system libs. 110 lib tests pass on both feature configs; clippy `-D warnings` clean both ways.

**Verify.**

```bash
WARDEN_CARGO_FEATURES=saml cargo build --features saml --bin warden-console
WARDEN_AUTH_MODE=saml \
  WARDEN_SAML_METADATA_URL=https://idp.example.com/metadata \
  cargo run --features saml --bin warden-console
open http://localhost:8085/auth/saml/login
```

---

## 6. `wardenctl` CLI

### 6.1 Device-flow auth

**Concept.** Same pattern as `gcloud auth login`, `aws sso login`, `gh auth login`. The CLI displays a verification URL + code, the operator opens the URL in a browser, completes auth there, and the CLI polls until the IdP completes the device flow (RFC 8628). No long-lived API tokens. No operator SVID requirement (would be a circular bootstrap).

**Implementation.** `wardenctl auth login --tenant <tid>`. Caches `id_token` + `refresh_token` in `~/.warden/credentials.json`. Re-uses the cached refresh token transparently; expired refresh sends the operator back through device flow. `auth logout` clears the cache; `auth whoami` echoes `sub`, `idp`, `groups`, capabilities.

**Verify.**

```bash
wardenctl auth login --tenant acme
# Visit https://idp.acme.com/device with code ABC-DEF
wardenctl auth whoami
# sub: alice@acme.com, idp: okta, groups: [...], capabilities: [agents:create]
```

Token-file (`--token-file`) and token-stdin (`--token-stdin`) alternatives exist for CI contexts where device flow is impossible.

### 6.2 `agents` subcommands

**Concept.** Full lifecycle CRUD on the agent registry. Mirrors the console UI but scriptable. The `--if-absent` flag on `create` makes it idempotent (200 if existing matches, 409 if differs) — covers IaC-without-Terraform patterns: a CI job loops a YAML file and runs `wardenctl agents create --if-absent` per entry.

**Implementation.** `warden-ctl/src/cmd/agents.rs`. Subcommands: `create`, `list`, `get`, `suspend`, `unsuspend`, `decommission`, `envelope narrow`, `envelope widen`, `transfer`, `description`, `migrate`. Built on `warden-sdk::AgentsClient`. `--json` flag on read commands for machine-readable output.

**Verify.** See §3.8, §3.9.

### 6.3 `agents migrate` (bulk enrollment)

**Concept.** The `enforce` mode flip would have grounded every legacy agent that hadn't been registered. The `migrate` command reads the existing `svids` table and creates `agents` records for every distinct `(tenant, agent_name)` it finds, with operator-supplied defaults. This is the official adoption tool — operators run it once before flipping.

**Implementation.** `wardenctl agents migrate --identity-db <path> [--dry-run] [--default-owner-team unassigned] [--default-envelope '*'] [--default-attestation-kinds '*']`. Idempotent — rerun completes from where it stopped; chain rows for already-migrated agents are no-ops. Each migrated agent gets `actor_sub = "system:migration:<operator_oidc_sub>"` so the human who ran the migration is recorded; never anonymous.

**Verify.**

```bash
wardenctl agents migrate --identity-db /var/lib/warden-identity/identity.sqlite --dry-run
# Reports what would be created
wardenctl agents migrate --identity-db ... --default-envelope '*'
./repos/warden-chaos-monkey/... --scenario migration_replay
# Asserts second run is no-op, no duplicate ledger rows
```

### 6.4 `regulatory export`

**Concept.** Auditor-facing bundle export from the operator's own machine. Distinct from `agents` CRUD because it talks directly to the ledger (no identity gate today). Returns a `.tar.gz` per the format in §7.

**Implementation.** `wardenctl regulatory export --from <RFC3339> --to <RFC3339> [--readme PATH] [--include-exports] [--ledger-url URL] --output bundle.tar.gz`. Thin pass-through to `warden-sdk::LedgerClient::regulatory_export(window, RegulatoryExportOptions { readme, include_exports })`.

**Verify.**

```bash
wardenctl regulatory export \
  --from <FROM_RFC3339> --to <TO_RFC3339> \
  --readme ./tech-docs.md \
  --include-exports \
  --output bundle.tar.gz

tar -tzf bundle.tar.gz
# manifest.json
# manifest.sig
# entries.ndjson
# technical_documentation.md
# README.txt
```

### 6.5 Deterministic exit codes

**Concept.** CI-friendly. Exit codes documented and stable: `0` success, `2` validation, `3` auth/capability, `4` conflict, `5` server.

**Implementation.** Each command's error path maps to one of the five. `--if-absent` returns 0 on idempotent match, 4 on diff.

**Verify.**

```bash
wardenctl agents get nonexistent || echo "exit: $?"      # 4
wardenctl agents get <id> --bad-flag || echo "exit: $?"  # 2
```

### 6.6 First-run ergonomics (`init` / `doctor` / `generate-policy`)

**Concept.** Make `wardenctl` the front door for new operators, not a thin client over `warden-sdk`. Three verbs collapse the typical first-day questions: `init` scaffolds `~/.config/warden/config.toml` (and optionally a `policies/templates/` starter dir); `doctor` probes `/health` on every configured service URL and reports up/down/latency in one go (skips proxy by default — the mTLS gate would register as a false-negative); `generate-policy` lists or emits the 7 starter templates from §1.14 to disk, embedded via `include_str!` against the sibling repo so the CLI is self-contained.

**Implementation.** `warden-ctl` Cargo workspace. `init` writes `config.toml` with `--with-policies` opt-in for the starter dir. `doctor` accepts a comma-list override via `--services`; defaults to console / hil / identity / policy-engine / ledger. `generate-policy {list|<name>}` ships the seven templates from §1.14 baked into the binary so the CLI works without a checked-out sibling repo. 35 unit + integration tests pass; clippy `-D warnings` clean.

**Verify.**

```bash
wardenctl init --with-policies                  # config + starter templates land
wardenctl doctor                                # latency table
wardenctl generate-policy list                  # 7 names
wardenctl generate-policy pii_egress > pii.rego # template to stdout
```

---

## 7. Regulatory export

### 7.1 EU AI Act Article 11/12 bundle

**Concept.** The audit artifact regulators actually want. Article 11 = technical documentation, Article 12 = automatic logging records. The bundle is a `.tar.gz` containing NDJSON (one chain row per line) + a manifest (window metadata, hashes, schema version) + a detached Ed25519 signature + an optional operator-supplied prose document + a 7-step verification recipe in plaintext. The auditor unstars it with `tar`, verifies it with `openssl` and `sha256sum`. **No Warden binary required for verification.**

**Implementation.** `POST /export/regulatory` on `warden-ledger`. Bundle assembled in `warden-ledger/src/regulatory.rs`. Half-open window `[from, to)`. Empty window returns a valid bundle with `row_count: 0` (auditors expect a verifiable artifact even for "we logged nothing"). Operator stores; Warden does not retain bundles server-side.

**Verify.**

```bash
wardenctl regulatory export --from ... --to ... --output bundle.tar.gz
tar -xzf bundle.tar.gz && cat README.txt    # 7-step recipe
```

### 7.2 Manifest schema v3

**Concept.** Self-describing. The manifest tells the auditor what's in the bundle and how to verify it. `chain_state` carries `prev_hash_at_window_start` and `entry_hash_at_window_end` so the auditor can verify chain continuity without fetching anything outside the bundle. `signature` is an envelope referencing the detached `manifest.sig` sidecar. Optional `technical_documentation` and `parquet_pointers` blocks are signed transitively (the signature commits to the canonical manifest).

**Implementation.** `Manifest` struct in `warden-ledger/src/regulatory.rs`. Fields:

```jsonc
{
  "schema_version": "3",
  "generated_at": "...",
  "window": { "from": "...", "to": "..." },
  "row_count": 1234,
  "seq_lo": 5000, "seq_hi": 6233,
  "chain_state": { "prev_hash_at_window_start": "...", "entry_hash_at_window_end": "..." },
  "ndjson_sha256": "...",
  "article_scope": ["EU-AI-Act-Article-11", "EU-AI-Act-Article-12"],
  "signature": { "sidecar": "manifest.sig", "algorithm": "ed25519", "digest_alg": "sha256", "key_id": "...", "signed_at": "..." },
  "technical_documentation": { "filename": "...", "sha256": "...", "byte_size": 2048 },
  "parquet_pointers": [{ "snapshot_id": "...", "data_uri": "...", "data_sha256": "...", ... }]
}
```

**Verify.**

```bash
tar -xzf bundle.tar.gz
jq . manifest.json
```

### 7.3 Detached Ed25519 signature

**Concept.** Embedded signatures are byte-fragile — any whitespace difference between writer and verifier breaks them. Detached signatures keep the manifest byte-stable across implementations. The signature commits to `sha256(canonical_manifest_with_signature_blanked_to_null)` so the auditor blanks the `signature` field, re-serializes pretty-printed, sha256s, and runs `ed25519_verify`. Tampering with `technical_documentation` or `parquet_pointers` (which the manifest carries hashes of) breaks both the signature verification and a cheap recompute.

**Implementation.** `warden-ledger::identity_client::HttpManifestSigner` calls `warden-identity` `POST /sign/blob` with the canonical-manifest digest. Response signature appended as `manifest.sig` (128 hex chars + LF). Wired via `WARDEN_IDENTITY_URL` + `WARDEN_LEDGER_SPIFFE`. Fail-closed: signing errors → 503 `signing_unavailable` (the ledger never emits an unsigned bundle).

**Verify.**

```bash
tar -xzf bundle.tar.gz

# Step 5–6 of the auditor recipe:
jq '.signature = null' manifest.json | jq -S . > unsigned.json
openssl dgst -sha256 -binary unsigned.json | xxd -p -c 256
# Compare digest with what manifest.sig signs (use ed25519 verify against JWKS)
```

### 7.4 Operator-supplied prose

**Concept.** Article 11 wants prose. Operators want to attach a `technical_documentation.md` describing the deployment, its risk classification, intended use cases. The endpoint accepts an optional `text/markdown` request body up to 1 MiB; the bundle embeds it verbatim and commits its sha256 in the manifest.

**Implementation.** `POST /export/regulatory` accepts a `text/markdown` (or any `text/*`) body. 1 MiB cap (`413 payload_too_large` on overrun). Manifest's `technical_documentation` sub-object commits to `{ filename, sha256, byte_size }`.

**Verify.**

```bash
wardenctl regulatory export --from ... --to ... --readme ./tech-docs.md --output bundle.tar.gz
tar -xzf bundle.tar.gz technical_documentation.md
diff tech-docs.md technical_documentation.md
```

### 7.5 Parquet pointers

**Concept.** Cold-tier `/export` snapshots (Iceberg + Parquet, see §9) and the regulatory bundle cover overlapping windows. Operators may want auditors to cross-check analytical aggregates against the chain rows. `?include_exports=true` runs a seq-overlap scan against the `exports` table and embeds Parquet pointers in the manifest. The auditor independently fetches the snapshots, verifies their sha256s against the manifest, and runs whatever Parquet tooling they prefer.

**Implementation.** `BundleOptions { include_exports: bool, .. }` in `warden-ledger`. When true, `regulatory.rs` queries the `exports` table for snapshots with `seq_lo <= window.seq_hi AND seq_hi >= window.seq_lo` and emits one `parquet_pointers[]` entry per match.

**Verify.**

```bash
wardenctl regulatory export --include-exports --from ... --to ... --output bundle.tar.gz
jq '.parquet_pointers' manifest.json
```

### 7.6 Auditor verification recipe (`README.txt`)

**Concept.** The bundle teaches the auditor how to verify it. `README.txt` is plain ASCII, no Markdown rendering required, opens in any text editor.

**Implementation.** Embedded as a constant in `warden-ledger/src/regulatory.rs`. Seven steps:

1. Untar the bundle.
2. Verify `entries.ndjson` byte-hash matches `manifest.json`'s `ndjson_sha256`.
3. Verify chain continuity from `chain_state.prev_hash_at_window_start` through every NDJSON row to `chain_state.entry_hash_at_window_end`.
4. (Optional) Verify `technical_documentation.md` byte-hash matches `manifest.technical_documentation.sha256`.
5. Blank `manifest.signature` → `null`, re-serialize pretty-printed JSON, sha256.
6. `ed25519_verify` the digest from step 5 against `manifest.sig` using the operator-published public key (`key_id` in `manifest.signature`).
7. (Optional) For each entry in `manifest.parquet_pointers`, fetch `data_uri`, sha256, compare to `data_sha256`.

**Verify.**

```bash
tar -xzf bundle.tar.gz
cat README.txt
```

---

## 8. Forensic / audit pipeline

### 8.1 NATS forensic bus (`warden.forensic`)

**Concept.** Every layer publishes its forensic event to a single NATS subject; `warden-ledger` is the sole subscriber. This decouples ingestion: a temporarily-down ledger doesn't block the security pipeline (NATS buffers); a temporarily-down policy engine doesn't lose events that already happened (NATS at-least-once).

**Implementation.** Subject: `warden.forensic`. Publishers: `warden-proxy` (post-verdict), `warden-policy-engine` (per-evaluation), `warden-hil` (per state transition), `warden-identity` (per lifecycle event). All emit `LogRequest`-shaped JSON. Ledger subscriber appends each well-formed message to the chain.

**Verify.**

```bash
nats sub 'warden.forensic'    # in a separate terminal
./repos/warden-chaos-monkey/...    # scenarios fire, events stream by
```

### 8.2 UUIDv4 `correlation_id`

**Concept.** Every request gets a single `correlation_id`, stamped by the proxy in `handle_mcp` at request entry. The ID threads through every downstream call (brain `/inspect`, policy `/evaluate`, HIL `/pending`) and every emitted forensic event. Per-request reconstruction is `GET /audit/correlation/{id}` — the join key is on every row, deterministic, no timestamp-heuristic needed.

**Implementation.** UUIDv4 generated by the proxy. Threaded into `BrainRequest`, `PolicyInput`, `CreatePending`. Console's `/audit` filter can pin to a single ID.

**Verify.**

```bash
# Boot the stack, drive a request, copy any correlation_id from /audit
curl http://localhost:8083/audit/correlation/<id> | jq
# Every event from every layer for that request appears in one response
```

### 8.3 Origin tag (`source` column)

**Concept.** The simulator stamps `x-warden-source: simulator` on every request so the console's "Hide simulated traffic" filter can strip its noise. **`source` is metadata, not in the hashable** — an attacker that controls a client could stamp any value. Never used for authz, tamper detection, or chain integrity.

**Implementation.** Proxy reads `x-warden-source`, stamps it on the forensic event under `source`. Ledger persists in nullable column. Console filter joins by `correlation_id` so policy / HIL rows for sim-driven traffic hide too (those events don't propagate the header).

**Verify.**

```bash
curl http://localhost:8083/audit?source=simulator | jq '.[].correlation_id' | sort -u
# Sim correlation IDs only
```

### 8.4 Annotation signal column

**Concept.** Identity- and proxy-side rejection annotations ride on `LogRequest.signal`: `unregistered_agent`, `agent_suspended`, `agent_decommissioned`, `attestation_kind_not_accepted`, `peer_bundle_stale:<td>`, `grant_expired`, `signing_unavailable`, etc. Persisted as a nullable column, **not in the hashable**, queryable via `/audit`. The console's filter chips key off it.

**Implementation.** Field on `LogRequest`. Ledger persists nullable. Audit query supports `?signal=<name>` filter. SSE `/stream/audit` carries it on every row so the console can render new rows in place.

**Verify.**

```bash
# Filter to a specific signal
open 'http://localhost:8085/audit?signal=peer_bundle_stale:other-tenant'
```

### 8.5 Outbound verdict webhooks (warden-lite)

**Concept.** Operators want every terminal pipeline outcome (allow / deny / park, plus `would_deny` / `would_park` in observe mode) and every HIL decision (`decide_allow` / `decide_deny`) pushed to their SIEM in real time — no scrape lag, no polling. The webhook ships one stable-shape JSON event per outcome to a configured URL. Distinct from the human-facing Slack webhook (which posts Markdown); this one is for ingest pipelines (Datadog HTTP source, Splunk HEC, Loki, Vector, in-house).

**Implementation.** `warden-lite` reads `WARDEN_LITE_WEBHOOK_URL`. Payload: `{event, correlation_id, agent_id, tool_type, method, intent_category, reasoning, review_reasons, mode, ts}` with RFC 3339 ms-precision UTC. 5s per-request timeout; failures log at `warn` and never delay the agent or operator response. 4 integration tests cover allow / deny / park-then-decide / observe-mode `would_deny` emission against a stub sink. Full-stack `warden-proxy` mirror is a follow-up.

**Verify.**

```bash
# Stub sink
nc -lk 4444 &
WARDEN_LITE_WEBHOOK_URL=http://localhost:4444/ warden-lite serve &
# Drive any agent → see one JSON event per outcome on the sink
```

### 8.6 Streaming audit egress (ledger → SIEM)

**Concept.** The full-stack ledger's counterpart to §8.5. Where the cold-tier export (§9) writes one Parquet snapshot per day for archive, the egress sweeper streams every chain row to a SIEM within seconds. Per-sink cursors keep the streams independent of cold export and of each other: mid-batch crashes advance only past entries the sink confirmed, and the next sweep retries from the first failed row. Stable wire envelope across all three sinks carries the chain row's UUID so downstream dedup is straightforward.

**Implementation.** `warden-ledger/src/egress.rs`. `StreamSink` trait + three impls: `SplunkHecSink` (`POST /services/collector` with `Authorization: Splunk <token>`), `DatadogLogsSink` (`POST http-intake.logs.<site>/api/v2/logs` with `DD-API-KEY`), `GenericHttpSink` (JSON POST + optional bearer; covers Loki / Vector / Logstash / in-house). Per-sink cursors in `egress_cursors` SQLite table. Env vars: `WARDEN_LEDGER_EGRESS_INTERVAL_SECS` (default 30; 0 disables), `WARDEN_LEDGER_EGRESS_BATCH_SIZE` (default 100), plus per-sink URL/token. SQLite-only — Postgres mode (§1.11) ingests directly against the chain table.

**Verify.**

```bash
WARDEN_LEDGER_EGRESS_SPLUNK_URL=https://splunk.example.com:8088 \
  WARDEN_LEDGER_EGRESS_SPLUNK_TOKEN=$TOKEN \
  cargo run --bin warden-ledger
# Drive some traffic, then check Splunk for warden events
```

---

## 9. Cold-tier analytics exports

### 9.1 Iceberg v2 metadata

**Concept.** Distinct from regulatory export — this is the analytics-grade snapshot. Apache Iceberg v2 is the open table format that data warehouses (Snowflake, Databricks, BigQuery) consume. Every `/export` produces a real Iceberg snapshot: `metadata/{uuid}-m0.avro` (manifest), `metadata/snap-…avro` (snapshot), `metadata/v{N}.metadata.json` (table metadata). The snapshot summary carries `warden.parquet-sha256` so the integrity property of the legacy JSON sidecar is preserved.

**Implementation.** `iceberg = "0.9"` crate, in-memory `FileIO`, pushed through the existing `Sink` trait (`S3Sink`, `LocalSink`, `MemorySink`). Per-version `iceberg_state` cache upserts atomically with the `exports` insert. Code lives in `warden-ledger/src/export.rs`.

**Verify.**

```bash
curl -X POST 'http://localhost:8083/export?from=...&to=...&format=iceberg-parquet'
# Inspect the resulting metadata directory
```

### 9.2 Native S3 sink (`aws-sdk-s3`)

**Concept.** Production-grade S3 upload. Uses the official `aws-sdk-s3` crate (not a third-party wrapper) so credentials, retries, and multipart uploads behave the same as every other AWS-aware tool in the operator's environment.

**Implementation.** `S3Sink` in `warden-ledger/src/export.rs`. Configured via standard AWS env vars (`AWS_ACCESS_KEY_ID`, etc.) or instance metadata. Multipart uploads for large snapshots.

**Verify.** Configure S3 credentials and run an export with `?sink=s3://bucket/prefix/`; objects appear in the bucket.

---

## 10. GTM tooling

### 10.1 `warden-shadow-scanner`

**Concept.** Top-of-funnel: helps prospects discover their unauthorized agent footprint. Scans GitHub orgs, Slack workspaces, and local filesystem trees for credentials likely belonging to autonomous agents (long-lived API tokens, `.env` patterns, hardcoded keys in code). Output is a CSV the prospect's security team can triage. The cold-outbound motion uses this output as a conversation opener: "we scanned your org and found 47 unmanaged agent credentials."

**Implementation.** Standalone Rust CLI in `repos/warden-shadow-scanner/`. Reads from GitHub API, Slack API, local FS. Pattern matching + heuristic classification.

**Verify.**

```bash
warden-shadow-scanner --github-org <name> --output findings.csv
warden-shadow-scanner --local-fs ~/code --output findings.csv
```

### 10.2 `warden-lite`

**Concept.** OSS single-binary edition for evaluators who want to try Warden without standing up the full six-service stack. Heuristic Brain (no Anthropic dep) + rego policy + hash-chain ledger + proxy in one binary. The chain format and policy input shape are wire-compatible with the full edition, so a customer can graduate from lite to full without re-instrumenting their agents.

**Implementation.** `repos/warden-lite/`. Single-binary crate; subset of the full feature set. No HIL, no identity, no NATS — all in-process. Operator-facing surface:

- **Multi-agent registry.** `WARDEN_LITE_AGENTS=agent-a:tok-a,agent-b:tok-b` registers N agents behind one binary; the matched token determines `agent_id` on the ledger and as `input.agent_id` in Rego, so policies can scope tool access per agent. Mutually exclusive with the legacy single-token `WARDEN_LITE_TOKEN`.
- **Online backup + restore.** `warden-lite backup --output FILE` takes an online snapshot via SQLite's `sqlite3_backup_*` API (safe against a running proxy); `warden-lite restore --input FILE [--force]` verifies the snapshot's chain BEFORE touching the target, then atomic-renames the sibling tmp into place so a partial write can't corrupt. Schema migrations on `Ledger::open` run idempotently, making the version-to-version upgrade path implicit.
- **Outbound webhook.** `WARDEN_LITE_WEBHOOK_URL` — see §8.5.
- **Async callback URL.** `X-Warden-Callback-URL` on `/mcp` + `WARDEN_LITE_CALLBACK_ALLOWLIST` — see §2.4.
- **Observe-only mode.** `WARDEN_LITE_MODE=observe` — see §1.12.

**Verify.**

```bash
WARDEN_LITE_AGENTS=alice:tok-a,bob:tok-b warden-lite serve &
# Per-agent ledger rows
warden-lite backup --output /tmp/lite-backup.db
warden-lite restore --input /tmp/lite-backup.db --force
```

### 10.3 `warden-sdk`

**Concept.** The typed Rust client. Two artifacts share one source of truth: `warden-console` consumes it, `wardenctl` consumes it, external integrators consume it. SDK is the contract.

**Implementation.** `repos/warden-sdk/`. Clients: `LedgerClient`, `HilClient`, `SimClient`, `AgentsClient`, `PoliciesClient`. Each exposes `base_url() -> &Url` for the `/config` page redaction-safe readout. `AgentsClient::bearer_fingerprint() -> Option<String>` returns sha256[..8] hex of the configured token (never the raw token). `LedgerClient::list_agents()` powers the audit page's default fan-out (§4.1). `PoliciesClient` is `Clone`-able and exposes the full Viewer/Admin surface described in §1.9; conflict responses parse via `PoliciesClient::parse_conflict()` so callers can surface the new metadata to operators.

**Verify.** Cargo dep:

```toml
[dependencies]
warden-sdk = "0.x.y"
```

### 10.4 `warden-sandbox`

**Concept.** Pure-Rust static analyzer for MCP tool calls. Classifies a call by `Read`/`Write`/`Exec`/`Network`/`Delete`, severity (`low`/`medium`/`high`), targets (file paths, URLs, IDs), summary (one-line human-readable). Consumed by the proxy for HIL `sandbox_report` (so approvers see a preview, see §2.2).

**Implementation.** `repos/warden-sandbox/` exports a single function `analyze(method: &str, params: &Value) -> SandboxReport`. No external state, no network — pure static analysis.

**Verify.**

```bash
cargo run -p warden-sandbox-cli -- --method tools/call --params '{"name":"shell","args":{"command":"rm -rf /etc"}}'
# Output: classification=Delete, severity=high, summary="rm -rf /etc/..."
```

### 10.5 TypeScript SDK (`warden-ai-sdk`)

**Concept.** Wrap-the-client adapter for `@anthropic-ai/sdk` and `openai` so dropping warden into a Node agent is a two-line change. Streaming + parallel `tool_use` + retries with jittered exponential backoff + observe-mode safety (warden being down can't break the agent — observe falls through to allow + logs). `onPolicyError` callback hooks let the app distinguish "warden was unreachable" from "warden actively denied" without re-implementing the verdict shape.

**Implementation.** `repos/warden-ai-sdk/` — TypeScript, published as `warden-ai-sdk` on npm. `wardenWrap(client, opts)` returns a wrapped client; the wrapper intercepts `messages.create` (Anthropic) and `chat.completions.create` (OpenAI), inspects each `tool_use` block via warden, and either allows / denies / parks. `WardenDenied`, `WardenPending`, `WardenTransportError` exception classes mirror the wire verdicts. `bearer-token` auth at the `warden-lite` ingress (mTLS still available for the full stack). Tests: TypeScript strict mode + tsc clean.

**Verify.**

```bash
cd repos/warden-ai-sdk && npm test
```

### 10.6 Python SDK (`warden-ai`)

**Concept.** Mirror of §10.5 for the Python ecosystem — wraps `AsyncAnthropic` / `AsyncOpenAI` plus the sync `Anthropic` / `OpenAI` clients. 1:1 parity with the TS SDK plus a synchronous flavour because not every Python agent codebase is asyncio.

**Implementation.** `repos/warden-ai-py/`, published as `warden-ai` on PyPI. Streaming (both providers, async + sync); retries with jittered exponential backoff; parallel `tool_use` observability via `asyncio.gather`; `WardenPending.resolve()` end-to-end. `WardenDenied` / `WardenPending` / `WardenTransportError` exception hierarchy matches TS. 43 unit tests; `ruff` + `mypy --strict` clean.

**Verify.**

```bash
cd repos/warden-ai-py && pip install -e . && pytest
```

### 10.7 Framework recipes + Computer Use + Realtime adapters

**Concept.** Working repos under `examples/` for the integrations evaluators actually ask about: native Anthropic, native OpenAI, LangChain (TS + Python), Vercel AI SDK, Mastra, LlamaIndex. Plus two adapter recipes for newer surfaces — Anthropic Computer Use (the agent that drives a GUI) and OpenAI Realtime (the WS pump pattern). Each recipe is one `run.{ts,py}` + a README pointing at the load-bearing line. The top-level `examples/README.md` indexes them and lays out the wrap-the-client vs wrap-the-dispatcher integration spectrum.

**Implementation.** Spread across both SDK repos:

- `warden-ai-sdk/examples/` — `native-anthropic/`, `native-openai/`, `vercel-ai/`, `mastra/`, `langchain-js/`, `openai-realtime/`, `anthropic-computer-use/`. Realtime ships `inspectRealtimeFunctionCall` / `isRealtimeFunctionCallDone` / `normalizeRealtimeFunctionCall` helpers for the WS pump pattern; Computer Use tool_use blocks already flow through `wardenWrap` unchanged, so its recipe is wiring + a starter Rego snippet.
- `warden-ai-py/examples/` — `langchain_recipe.py`, `llamaindex_recipe.py`, `computer_use_recipe.py`, `openai_realtime_recipe.py`. Python helpers under `warden_ai.realtime`. Uses the canonical `inspect_tool_use(NormalizedToolCall, opts)` signature end-to-end including the `WardenPending.resolve()` raise-on-deny contract.

All recipes pass their respective type checkers (TS strict mode, mypy strict). 98 + 61 tests respectively across the two SDKs.

**Verify.**

```bash
cd repos/warden-ai-sdk/examples/native-anthropic && npm install && npm start
cd repos/warden-ai-py/examples && python langchain_recipe.py
```

### 10.8 One-click deploy (Fly.io)

**Concept.** Make the first run a single click. The `warden-lite` repo ships a `fly.toml` + Dockerfile sized for Fly.io's free tier and a "Deploy to Fly" button in the README; clicking it runs `fly launch` against the upstream `ghcr.io/vanteguardlabs/warden-lite` multi-arch image and the new instance lands on a public hostname in ~60 seconds. The image defaults to `enforce` rather than `observe` because a misconfigured deploy must fail closed; entry-point docs walk operators through flipping to observe for the tuning window.

**Implementation.** `repos/warden-lite/fly.toml` + multi-stage Dockerfile (rust:1-bookworm builder → debian:bookworm-slim runtime). Multi-arch (`linux/amd64,linux/arm64`) image push to ghcr.io on tag. README's `[![Deploy](https://fly.io/static/images/launch/deploy.svg)](https://fly.io/launch?...)` button points at the public image + a Fly launch template. CI gate: `smoke-e2e` runs an end-to-end `/mcp` happy path against the built image so a busted Dockerfile fails the release.

**Verify.**

```bash
cd repos/warden-lite && fly launch --image ghcr.io/vanteguardlabs/warden-lite:latest
```

### 10.9 Unified docs site (`/docs/`)

**Concept.** Until v0.5.0, evaluators had to read per-repo READMEs + the spec to learn warden. The unified docs site collapses that into a single portal with the four entry points operators actually need: a 5-minute quickstart, a concepts overview, an API reference, and a recipe cookbook. Vanilla HTML/CSS — no framework, no build step — so the site survives any future Node rev and the page weight stays under 50 KB per route.

**Implementation.** `repos/warden-website/docs/`. Five HTML pages: `index.html` (landing — 4 cards), `quickstart.html` (zero-to-verdict in 5 minutes), `concepts.html` (the four-layer model + three security signals + HIL tiers + observe-vs-enforce + the hash-chained ledger), `api.html` (every wire contract summarised, cross-referenced to `warden-specs/TECH_SPEC.md`), `recipes.html` (12 cookbook patterns: TS SDK, Python SDK, LangChain, Vercel AI, Anthropic Computer Use, OpenAI Realtime, Slack HIL deep-link, SAML/SSO setup, Postgres ledger, Helm sidecar deploy, observe-mode rollout, Splunk/Datadog egress). Shares `styles.css` with the marketing pages — same primitives (`.section`, `.spec-toc`, `.spec-steps`, `.codeblock`, `.spec-verdict-grid`); small additive `.docs-subnav` / `.docs-cards` / `.docs-continue` primitives keep the docs nav consistent. Top-nav "Docs" link backfilled across all marketing pages so the 9-page site has one consistent navigation surface.

**Verify.**

```bash
open https://warden.vanteguardlabs.com/docs/
```

---

## 11. Test infrastructure

### 11.1 `warden-e2e/dev/run.sh`

**Concept.** The host-cargo runner. Boots all six services + Docker NATS/Vault + a stub upstream; runs the happy path; runs the chaos-monkey red-team suite; tears down. Source of truth for "does the stack work end-to-end." Builds in **debug profile on purpose** — Apple clang segfaults on `ring`'s release C build on some macOS versions.

**Implementation.** Bash script at `repos/warden-e2e/dev/run.sh`. Env knobs: `E2E_SKIP_CHAOS=1` for fast happy-path runs, `E2E_KEEP_LOGS=1` to retain logs and the temp work dir.

**Verify.**

```bash
./repos/warden-e2e/dev/run.sh                         # full
E2E_SKIP_CHAOS=1 ./repos/warden-e2e/dev/run.sh        # fast
E2E_KEEP_LOGS=1 ./repos/warden-e2e/dev/run.sh         # debug
```

### 11.2 `warden-e2e/dev/run-federation.sh`

**Concept.** Two-tenant federation runner. Boots two `warden-identity` instances under different trust domains and asserts the SPIFFE federation freshness gate: fresh peer bundle → A2A succeeds; staled-out → `peer_bundle_stale`.

**Implementation.** `repos/warden-e2e/dev/run-federation.sh`. Configures `WARDEN_FEDERATION_PEERS` on each instance pointing at the other's `/.well-known/spiffe-bundle`. Triggers a peer-bundle staleness by stopping one instance's bundle endpoint, waiting past the freshness window, attempting A2A.

**Verify.**

```bash
./repos/warden-e2e/dev/run-federation.sh
```

### 11.3 `warden-e2e/dev/run-onboarding.sh`

**Concept.** WAO § 13.1 runner. Boots a `dexidp/dex` mock IdP container, drives `wardenctl agents create / suspend / decommission / migrate`, asserts `/svid` + `/grant` gating in `warn` and `enforce` modes (including § 13.1.7 bulk-enrollment migration replay).

**Implementation.** `repos/warden-e2e/dev/run-onboarding.sh`. Dex mock configured with two static users:

- `admin@acme.com` with `groups: [warden-platform-admins]` (mapped to `agents:create + agents:admin`)
- `dev@acme.com` with `groups: [payments]` (no Warden capabilities — tests `403 missing_capability:agents:create`)

**Verify.**

```bash
./repos/warden-e2e/dev/run-onboarding.sh
```

### 11.4 Compose stack (`--profile stack`)

**Concept.** The console-with-data demo. Boots everything in containers + the simulator + upstream-stub; surfaces a populated console for screenshots, evaluator walkthroughs, and operator practice. Identity boots in `enforce` registration mode end-to-end so the demo matches the production default.

**Implementation.** `repos/warden-e2e/prod/docker-compose.yml --profile stack`. First cold build is ~15 min (release profile, no shared cargo target across the six service Dockerfiles). Subsequent runs are image-cached. `run-stack-smoke.sh` is the lighter health check; `run-stack-e2e.sh` is the full assertion suite (see §11.8).

**Verify.**

```bash
docker compose -f repos/warden-e2e/prod/docker-compose.yml --profile stack up -d
open http://localhost:8085
./repos/warden-e2e/prod/run-stack-smoke.sh
docker compose -f repos/warden-e2e/prod/docker-compose.yml --profile stack down -v
```

### 11.5 `warden-chaos-monkey`

**Concept.** Curated red-team catalog. Each scenario fires a specific attack at a live proxy and asserts the predicted verdict. The list grows as the threat model expands; removing a scenario requires explaining why the attack is no longer relevant.

**Implementation.** Rust CLI at `repos/warden-chaos-monkey/`. Current scenarios:

- Layer 2/3: `denylist`, `injection`, `velocity_breaker` (must run last), `business_hours`, `control`
- HIL: `hil_yellow_denied`, `hil_yellow_expired`
- Identity: `unattested_binary`, `stolen_svid_replay`, `expired_grant`, `cross_tenant_unfederated`
- WAO: `unregistered_agent_enforce`, `scope_outside_envelope`, `suspended_agent_grant`, `decommissioned_name_reuse`, `envelope_widen_unauthorized`, `owner_team_spoof`, `stale_oidc_token`, `migration_replay`

Identity scenarios accept either a wired (proxy + identity) or unwired (proxy only) deploy; deny shape varies (`a2a_redeem_failed:<inner>` vs `a2a_unavailable`), keyword match handles both.

**Verify.**

```bash
./repos/warden-chaos-monkey/target/release/warden-chaos-monkey \
  --proxy https://localhost:8443 --scenario stolen_svid_replay
# Asserts predicted verdict, exits 0 on match
```

### 11.6 `warden-simulator`

**Concept.** Continuous, persona-driven mTLS load generator. Mints per-agent client certs from the proxy's CA, fires a Poisson-distributed mix of MCP tool calls (auto-allow + Yellow-tier wire_transfer + drift into hard-deny), and runs an HIL auto-decision sidecar at configurable approve/deny/expire ratios. Every request carries `x-warden-source: simulator` so the proxy stamps `source="simulator"` on the forensic event.

**Implementation.** `repos/warden-simulator/`. Admin server (`SIM_ADMIN_PORT=9100`, default loopback-only): `GET /status`, `POST /multiplier`, `POST /running`, `POST /auto-decide`, `POST /agents`. Boots paused — operator clicks Start on the console (or sets `SIM_START_RUNNING=true` / `--start-running`) to fire traffic. HIL auto-decision sidecar boots **enabled** when `--hil-url` is set and is pausable; pausing leaves Yellow-tier pendings on the HIL queue for manual approval. Each persona is **enrolled in the agent registry before its first SVID is minted** — required for the stack's `enforce` registration mode (an unregistered name would otherwise hit `403 unregistered_agent`).

The `warden-upstream-stub` sub-binary is what compose uses as the proxy's downstream MCP echo target.

**Verify.**

```bash
docker compose -f repos/warden-e2e/prod/docker-compose.yml --profile stack up -d
curl -X POST http://localhost:9100/running -d '{"running":true}'
open http://localhost:8085/audit
# Sim traffic streams in
```

### 11.7 `warden-e2e/dev/run-policies.sh`

**Concept.** Console policy management e2e. Boots a minimal stack (`warden-policy-engine` + `warden-ledger` + NATS — no proxy/brain/HIL/identity) and drives the full mutation surface end-to-end: list, create, update with optimistic concurrency, deactivate / activate, rollback, soft delete. After every mutation, asserts a matching `policy.*` row landed in the ledger via `warden.forensic` and the chain still verifies. Mirrors `run-onboarding.sh`'s shape: focused on the §1.9 / §4.10 wire contract, not the full MCP path.

**Implementation.** `repos/warden-e2e/dev/run-policies.sh`. Same prereqs as `run.sh` (cargo / curl / jq / NATS). Honors `E2E_KEEP_LOGS=1` and dumps tails on failure.

**Verify.**

```bash
./repos/warden-e2e/dev/run-policies.sh
```

### 11.8 `warden-e2e/dev/run-stack-e2e.sh`

**Concept.** Same assertion depth as `run.sh` (correlation_id join, chain `/verify`, HIL Yellow-tier roundtrip, chaos-monkey red-team suite) but against the docker-compose `--profile stack` containers instead of the host-cargo debug build. Use this when iterating on Dockerfile / compose changes — `run-stack-smoke.sh` only proves the demo is healthy; `run-stack-e2e.sh` proves the production-style image build still passes the full suite.

**Implementation.** `repos/warden-e2e/dev/run-stack-e2e.sh`. Does **not** boot any service — expects the compose stack already running. PIDs / boot harness from `run.sh` are absent. `E2E_SKIP_CHAOS=1` skips the red-team tail.

**Verify.**

```bash
docker compose -f repos/warden-e2e/prod/docker-compose.yml --profile stack up -d
./repos/warden-e2e/dev/run-stack-e2e.sh
```

### 11.9 Cert-free local dev mode (`WARDEN_DEV_CERTS=1`)

**Concept.** Onboarding's #1 first-run gotcha used to be `./scripts/gen_certs.sh` — without certs the proxy panics at startup. Cert-free dev mode flips this for host-cargo runs: the proxy auto-mints an ephemeral CA + server + client triplet into `WARDEN_CERT_DIR` on first boot. Opt-in by env var (never auto-enabled) so a misconfigured prod deploy can't self-issue a CA root, and the script never overwrites existing PEMs.

**Implementation.** `warden-proxy/src/tls.rs`. When `WARDEN_DEV_CERTS=1`, the boot path uses `rcgen` to mint a self-signed CA + server cert (CN=`localhost`) + client cert (CN=`agent-001`) into `${WARDEN_CERT_DIR:-./certs}`. Subsequent boots reuse what's there. Container / production runs still go through `scripts/gen_certs.sh --env {prod,dev}` so the certs dir is operator-controlled. `warden-e2e/dev/deploy.sh` and `warden-e2e/prod/deploy.sh` ship a guard that runs `gen_certs.sh` automatically when the bind-mount source is empty — protects against the recurring "certs dir got wiped" failure mode.

**Verify.**

```bash
WARDEN_DEV_CERTS=1 cargo run --bin warden-proxy
# certs/ now contains ca.crt, server.crt, client.crt (all ephemeral)
```

### 11.10 Perf + chaos harness in CI

**Concept.** Nightly + weekly regression gates that catch a Brain regression, a policy slowdown, or a chaos-suite drift before a release. Chaos boots the full dev compose stack and runs `run-stack-e2e.sh` (happy path + the chaos-monkey catalog from §11.5). Perf boots with the velocity tracker disabled (the in-process tracker's 100 req/60s/agent circuit-breaker pins any meaningful load run), fires a benign ping for a fixed window, and emits a JSON report with p50 / p95 / p99 / throughput / errors. The reference baseline is checked in; a regression that moves p99 by >20% fails the run.

**Implementation.** `warden-chaos-monkey/src/bin/warden-perf-harness.rs` is a sister binary that reuses the chaos runner's mTLS plumbing (shared `mtls.rs` for cert loading + `reqwest::Client` build). New `--exclude-category` flag on the chaos runner so CI can drop the brain-touching `injection` family if no Anthropic key is wired. `warden-policy-engine` gains a third `WARDEN_VELOCITY_BACKEND=disabled` arm for perf measurement only (production keeps `inprocess` or `nats-kv`). Workflows at `warden-e2e/.github/workflows/`: `chaos.yml` (nightly + dispatch — boots dev compose, runs run-stack-e2e.sh), `perf.yml` (weekly + dispatch — boots with velocity disabled, fires harness 60s @ 30 concurrency, uploads `perf-report.json` artifact). First reference snapshot at `warden-e2e/perf/reference.json`: 1381 rps, p50 21.0 ms, p95 31.7 ms, p99 38.7 ms over 82880 requests, 0 errors.

**Verify.**

```bash
./repos/warden-chaos-monkey/target/release/warden-perf-harness \
  --proxy https://localhost:8443/mcp --duration 60 --concurrency 30
# Emits perf-report.json
```

### 11.11 Brain accuracy benchmark (`warden-brain-bench`)

**Concept.** Lakera, Prompt Security, Robust Intelligence — each publishes accuracy numbers on a private eval set. Hard to compare without a shared methodology. The Brain benchmark publishes both: a vendored eval suite (66 cases × 7 categories × 5 personas) and a sister binary that scores each case (TP / TN / FP / FN, precision / recall / F1, percentile latency) against the live `/inspect` router in-process. The published baseline is the floor; a CI gate fails any PR that regresses the deterministic-keyword subset. A transparent loss with reproducible methodology beats unverified closed-source claims.

**Implementation.** `warden-brain/src/bin/warden-brain-bench.rs` reuses the Router as a library and scores `benchmark/cases.json`. Personas: `support`, `finance`, `devops`, `code-review`, `marketing`. Categories: 7 (PII egress, prompt injection, persona drift stretch, etc.). First baseline at `benchmark/baseline.json`: deterministic-keyword subset 100% (54/54), overall 81.82% (54/66, precision 1.000 / recall 0.732 / F1 0.845). The 12 missed cases are the persona-drift-stretch category — cross-persona attacks with no keyword trigger that need live Voyage embeddings + Haiku classifier to catch; their absence in mock mode is the published "live Brain delta" rather than hidden. CI gate: `tests/compliance.rs` + the bench binary's `--deterministic-floor 1.0` flag fail any PR that regresses the keyword-supported subset. Methodology: `BENCHMARK.md` covers categories, scoring rule (positive = deny), reproduction commands for both mock and live mode, known limitations, and the promote-a-fresh-baseline workflow.

**Verify.**

```bash
cargo run -p warden-brain --bin warden-brain-bench -- --baseline benchmark/baseline.json
# Mock-mode scoreboard with deterministic floor enforced
```

---

## 12. Supply chain & threat model

### 12.1 Uniform `cargo-deny` config

**Concept.** Every Rust repo (14 of them) carries the same `deny.toml` and runs `cargo-deny check all` (advisories + licenses + bans + sources) on every push and PR. A new advisory against any transitive dep fails the next push. The license allow-list is the standard permissive set (MIT, Apache-2.0, BSD, ISC, MPL-2.0); GPL/AGPL/LGPL is denied transitively.

**Implementation.** `deny.toml` at every Rust repo root. CI job `supply-chain` in `.github/workflows/ci.yml`. Seven advisories ignored with documented rationale (rustls-pemfile via tonic 0.12; bincode via regorus; three rustls-webpki 0.101.7 vulns via openidconnect 3.5 + aws-smithy 1.x; rsa Marvin via openidconnect; paste via parquet — all "no safe upgrade" upstream).

**Verify.**

```bash
cd repos/warden-proxy
cargo deny check all
```

### 12.2 CycloneDX SBOM artifacts

**Concept.** Every PR build emits a CycloneDX 1.3 JSON SBOM per crate. Uploaded as a 90-day-retained workflow artifact. Operator-side: the security team can grep the SBOMs for affected versions across all 14 repos at once when a new advisory drops.

**Implementation.** Same `supply-chain` CI job uses `cargo-binstall` to install `cargo-cyclonedx`, runs it per crate, uploads each as a workflow artifact.

**Verify.**

```bash
gh run list --workflow ci.yml -R <org>/warden-proxy
gh run download <run-id> -R <org>/warden-proxy
# Find SBOMs in the downloaded artifacts
```

### 12.3 `SECURITY.md` + RFC 9116 `security.txt`

**Concept.** Disclosure policy. `SECURITY.md` at every repo root tells security researchers where to send vulnerability reports and what response time to expect. `security.txt` at `warden-website/.well-known/` is the RFC 9116 surface — automated scanners and bug-bounty platforms check that path.

**Implementation.** `SECURITY.md` (17 repos). `warden-website/public/.well-known/security.txt`. Both reference the same email contact and PGP key.

**Verify.**

```bash
cat repos/warden-proxy/SECURITY.md
cat repos/warden-website/public/.well-known/security.txt
```

### 12.4 STRIDE-organized threat model

**Concept.** Public threat model at `TECH_SPEC.md#threat-model`. Layer-by-layer (proxy → brain → policy → ledger → HIL → identity → console), STRIDE-organized inside each layer (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege). Explicit non-goals at the bottom — what we deliberately don't defend against.

**Implementation.** Hand-curated. Code is the source of truth; the model is reference material; re-verify against `git log` if the model and code disagree.

**Verify.**

```bash
open repos/warden-specs/TECH_SPEC.md     # navigate to # threat-model
```

### 12.5 Uniform `async-nats = 0.47`

**Concept.** Five services use NATS (proxy, identity, ledger, HIL, policy-engine). Version-skewed clients are a debugging trap. All five pin `async-nats = 0.47`, refreshed in lock-step on each bump.

**Implementation.** Per-repo `Cargo.toml`. The bump from 0.40 → 0.47 cleared one rustls-webpki advisory (RUSTSEC-2026-0049).

**Verify.**

```bash
grep -r "async-nats" repos/*/Cargo.toml
```

### 12.6 Cross-service consistency (health / readyz / metrics / logs)

**Concept.** Every shipping service exposes the same three observability endpoints under the same wire shape: `/health` for liveness, `/readyz` for readiness, `/metrics` for Prometheus scrape. Metric naming is uniform: `warden_<kebab-to-snake-service-slug>_*`. Logs switch to single-line JSON on the same env knob across services. Lets a single Helm probe template, a single Prometheus scrape config, and a single log-aggregator parser handle every service.

**Implementation.** All 8 services (proxy, brain, policy-engine, ledger, hil, identity, console, warden-lite) hit the same `/health` + `/readyz` + `/metrics` trio with the same JSON shape on `/readyz` (`ReadinessResponse { status, checks: BTreeMap }`). Metric prefixes uniformly use `warden_<service>_*` — the policy-engine rename `warden_policy_*` → `warden_policy_engine_*` aligns the last outlier. `WARDEN_LOG_FORMAT=json` is honored by every service for structured-event output. Refinement deferred: only `warden-proxy` currently threads `correlation_id` as a structured `tracing::span` field; the other services emit it via `tracing::info!("… correlation_id={}")` which lands in the JSON `message` field but isn't a top-level structured key. Migrating every handler to `tracing::info!(correlation_id = %x, …)` is per-handler work, not gating consistency.

**Verify.**

```bash
for s in warden-proxy:9001 warden-brain:9002 warden-policy-engine:9003 \
         warden-ledger:8083 warden-hil:8084 warden-identity:8086 \
         warden-console:8085 warden-lite:8443; do
    curl -fsS "http://localhost:${s##*:}/readyz" | jq .status
done
```

---

## 13. Wire contracts

### 13.1 Proxy → Brain

**Concept.** The proxy posts to brain for semantic inspection.

**Wire.** `POST /inspect`, body `BrainRequest { agent_id, correlation_id, jsonrpc fields... }`, response `{ authorized, intent_category, reason }`. Shared types are duplicated on each side — `warden-proxy/src/fork.rs` and `warden-brain/src/lib.rs`. **Grep both repos before renaming a shared field.**

**Verify.**

```bash
curl -X POST http://localhost:8081/inspect -H 'content-type: application/json' \
  -d '{"agent_id":"test","correlation_id":"00000000-0000-0000-0000-000000000000","method":"tools/call"}'
```

### 13.2 Proxy → Policy

**Concept.** The proxy posts the resolved Brain output + agent context to policy for rule evaluation.

**Wire.** `POST /evaluate`, body `PolicyInput { tool_type, agent_history, intent_score, agent_id, method, current_time, correlation_id, recent_request_count, attestation, agent_spiffe }`. Proxy maps Brain's `authorized` to `intent_score` (`0.1` if true, `0.5` if false) — Policy's `intent_score >= 0.2` rule means a Brain rejection alone fails policy.

**Verify.** See §1.4.

### 13.3 Proxy → HIL

**Concept.** The proxy parks Yellow-tier requests at HIL for human approval.

**Wire.** `POST /pending`, body `CreatePending { agent_id, correlation_id, method, request_payload, risk_summary, ttl_seconds, sandbox_report }`. Proxy long-polls `GET /pending/{id}` until status leaves `pending`. Approved → forward upstream. Denied/Expired/poll-timeout → 403.

**Verify.** See §2.1.

### 13.4 Proxy → Identity (signing + A2A)

**Concept.** The proxy calls identity for action signatures and for A2A actor token mint/redeem.

**Wire.** `POST /sign` body `{ correlation_id, method, prev_hash, payload_canonical_json }`, header `X-Caller-Spiffe`. `POST /actor-token` body `{ agent_spiffe, audience, scope, ttl_seconds }`. `POST /actor-token/redeem` body `{ token }`. All three gated on `WARDEN_IDENTITY_SIGN_ALLOWED_CALLERS`.

**Verify.** See §3.3, §3.6.

### 13.5 Identity → Ledger (chain v3)

**Concept.** Identity emits lifecycle events that anchor in chain v3 rows.

**Wire.** NATS publish via the identity-side outbox (`agents_ledger.rs`). Durable retry. Ledger dispatches v3 rows through `HashableEntryV3` keyed on `event_kind` + `payload_sha256`.

**Verify.** See §3.11.

### 13.6 Console → Policy-engine (mutations)

**Concept.** The console's `/policies` write surface (§4.10) and the `wardenctl` policy commands talk to `warden-policy-engine`'s mutation API; mutations anchor in chain v3 via the policy-engine outbox.

**Wire.** Endpoints listed in §1.9. Optimistic-concurrency body: `{reason: string, expected_current_version: int}`. Conflict response: `409 policy_version_conflict` with the new metadata so the UI can prompt-and-reload. Authz: every `POST/PUT/DELETE` requires `Role::Admin`. `policy.*` event kinds dispatch to chain v3 — no v4 bump (the chain is event-kind-polymorphic).

**Verify.** See §1.9, §11.7.

### 13.7 Console / `wardenctl` → Ledger (audit fan-out)

**Concept.** The console and CLI need the canonical "every agent that has ever logged a row" set for default audit fan-out and for `wardenctl agents list` joins.

**Wire.** `GET /agents` on `warden-ledger`. Body: `{ agents: ["spiffe-name-or-cn", ...] }` (string list, NFC-normalized lowercase, deduplicated and sorted). SDK helper: `LedgerClient::list_agents()`.

**Verify.** See §1.10, §4.1.

---

## 14. Known gaps

These are **explicit open items**, tracked here for completeness against the Implemented-Features inventory. Not a roadmap commitment — each one waits on a triggering event.

### 14.1 ~~`POST /revoke` endpoint~~ (shipped 2026-05-13 in v0.6.4)

`POST /revoke` revokes either a specific instance SVID or a delegation grant. Body discriminated on `kind`:

```json
POST /revoke
{ "kind": "svid",  "svid_id": "<id>",  "reason": "..." }
{ "kind": "grant", "jti":     "<jti>", "reason": "..." }
```

The handler validates the row exists, hasn't already been revoked, then sets `revoked_at` + `revoke_reason` on `svids` / `grants` and emits a chain v3 `svid.revoked` / `grant.revoked` lifecycle row via the existing outbox path (Vault-Transit signed). Auth: `agents:admin` capability in the row's tenant — spec called it "Operator WebAuthn" but identity terminates on OIDC + caps, admin is the cap-equivalent kill switch. **Today's effect**: `revoked_at` is set + the audit chain records the event. Proxy-side denylist consumption (so revocation kills in-flight requests) is a follow-up; combined with short-TTL SVIDs (≤1h) the effective revocation window is bounded by TTL expiry.

**Implementation.** `warden-identity/src/revoke.rs` (handler + tests); route at `lib.rs::build_app` between `/grant` and `/sign`.

**Verify.**

```bash
# happy path
curl -X POST -H "Authorization: Bearer <admin-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"kind":"svid","svid_id":"<svid-id>","reason":"compromise"}' \
  http://localhost:8086/revoke
# → 200 { "revoked_at": "2026-05-13T…" }

# double-revoke → 409 already_revoked
# unknown id → 404 not_found
# missing admin cap → 403 missing_capability:agents:admin
```

### 14.2 ~~`--delegation-mix` simulator flag~~ (shipped 2026-05-13 in v0.6.5)

`warden-simulator/src/delegation.rs` holds the pool parser + per-fire grant-crafting helper. CLI flag `--delegation-mix` (env `SIM_DELEGATION_MIX`) takes a comma-separated list of human-principal `act.sub` values. Each request fire picks one uniformly at random and crafts an unsigned `X-Warden-Grant` JWT carrying `{iss, jti, act.sub, exp, iat}` claims. The proxy parses the payload without signature verification (`warden-proxy/src/grant.rs` v1 trust model — grants are advisory metadata for the HIL pending row) and stamps `act.sub` onto the audit row. Empty pool is rejected at boot. Unset = no header attached (legacy CN-only audit shape preserved).

**Compose:** `SIM_DELEGATION_MIX=alice@acme.com,bob@acme.com,carol@globex.com,dana@globex.com` wired into both `warden-e2e/prod/docker-compose.yml` and `dev/docker-compose.yml`.

**Verify.** Check the console `/audit` page: the "Delegation" column now shows variety across the four principals. Or grep ledger rows for `delegation_jti` LIKE `sim-%`.

### 14.3 ~~Demo experience~~ (shipped — `demo.session_minted` closed 2026-05-13)

The entire demo flow has shipped — substrate flipped from Cloudflare Worker mint to in-stack Rust `warden-demo-mint`; `X-Warden-Demo-Prefix` proxy header splices the JWT prefix into correlation IDs; simulator `--hil-skip-agent-id-prefix demo-` keeps visitor pendings off the auto-decider. The last open hold-out — emitting a `demo.session_minted` ledger row — landed 2026-05-13 (see §14.7). The full historical-substrate-flip narrative lives at `TECH_SPEC.md#demo-experience`.

### 14.4 Spec-vs-code drift (documentation hygiene)

The 2026-05-13 spec audit (recorded in `/home/debian/claude/.claude/plans/replicated-enchanting-micali.md`) walked the spec against current code and closed the following items in `warden-specs@v0.6.3`. They're listed here as the historical record:

- **Registration mode default `enforce`, not `warn`** — *Fixed in spec v0.6.3* (Agent-onboarding §6.3).
- **HIL `WARDEN_HIL_DECIDE_TOKEN` per-request validation** — *Spec softened in v0.6.3* (Operator-auth §6); boot-time validation queued as roadmap entry B12.
- **Non-`text/*` body on `/export/regulatory` returns 400, not silently dropped** — *Fixed in spec v0.6.3* (Regulatory §10).
- **Action signing uses `GENESIS_PREV_HASH` placeholder, not ledger tail** — *Documented in spec v0.6.3* (Identity §5.2 carries the deviation note + integrator guidance).
- **Identity signing is Vault Transit only, not file-loaded Ed25519** — Threat-model §"warden-identity" had claimed in-process Ed25519 keypairs loaded from `WARDEN_IDENTITY_SIGNING_KEY_PATH`; reality is `vaultrs` to Vault Transit. *Spec softened in v0.6.3*; alt-backend shipped 2026-05-14 (v0.6.6) as `Ed25519FileSigner` (§14.8).
- **Deep-review PII sentinel names** — Spec said `[PEM]` / `[AWS_KEY]`; code emits `[PEM_PRIVATE_KEY]` / `[AWS_ACCESS_KEY_ID]`. *Fixed in spec v0.6.3* (Forensic-tier deep review §7).
- **Deep-review env-var table missing three knobs** — `WARDEN_DEEP_REVIEW_NATS_URL`, `_FORENSIC_SUBJECT`, `_FINDINGS_SUBJECT` were in code but not in spec table. *Fixed in spec v0.6.3* (Forensic-tier deep review §5).
- **Deep-review `/deep-review` console route + narrative strip shipped** — Spec §8 still listed under "Deferred". *Fixed in spec v0.6.3* — now under "Shipped" with v0.6.1 + v0.6.2 commit pointers.
- **"No admin role" vs. `Role::Admin`** — Operator-auth §3 contradicted Console-policy-management §8. *Fixed in spec v0.6.3* — Operator-auth §3 now acknowledges the policy-management admin tier explicitly.
- **Demo experience full-section drift** — Spec described 6-week build with CF Worker mint, `--auto-decide-skip-prefix` flag, etc. Reality is in-stack Rust `warden-demo-mint`, `X-Warden-Demo-Prefix` correlation-ID splicing, `--hil-skip-agent-id-prefix demo-` simulator flag. *Fixed in spec v0.6.3* with historical-substrate-flip callout preserved.
- **Brain `malicious_code` + `compromised_package` signals undocumented** — Shipped as v1.x roadmap; spec threat-model still listed three signals. *Fixed in spec v0.6.3* — now describes five signals.
- **HIL `/identities/*` CRUD endpoints undocumented** — Wire table added to Operator-auth §4 in v0.6.3.
- **`X-Warden-Demo-Prefix` proxy header undocumented** — Now mentioned in Demo experience §3.2 + §5.2.

### 14.5 Threat-model open items (deferred, intentional)

Tracked at `TECH_SPEC.md#threat-model` "Open items":

- **Internal s2s mTLS** (proxy↔brain/policy/hil/identity) — substrate choice (warden-identity SVID-based mTLS vs. mesh-layer at deploy time) depends on the deployment story.
- **Per-region key rotation runbook** for `warden-identity` — tracked as a follow-on supply-chain slice.
- **Identity-compromise runbook** — `TECH_SPEC.md` line 1778, `**TODO: write that runbook as a follow-on supply-chain slice.**`
- **Multi-tenant audit-log isolation** in console — year-2 product question.

### 14.6 Acknowledged future work (spec-level)

Listed in the relevant section's "What this spec deliberately does not include":

- **Receiving-team consent on agent transfer** (WAO §15)
- **Capability-change request workflow** on top of `widen` (WAO §15)
- **Bulk lifecycle ops** (WAO §15)
- **Terraform provider** (WAO §15 — `--if-absent` is the workaround)
- **Per-decision WebAuthn step-up over OIDC sessions** (Operator-auth §8)
- **Runtime role-management UI** (Operator-auth §8)
- **Admin role + agent-registry UI in console** (Operator-auth §8)
- **Four-eyes / separation-of-duties** (Operator-auth §8)
- **Federated config view, mutation surface, backend versions** on `/config` (Console-config §11)
- **Operator preferences** v2 (`/config` §10)

### 14.7 v0.6.4 ship log (2026-05-13)

Five v1.x+1 polish items shipped in lockstep on the 2026-05-13 quick-wins blitz. Spec text in `TECH_SPEC.md` updated in the same commit.

- **`POST /revoke` endpoint** — `warden-identity/src/revoke.rs`. Full wire shape + verification in §14.1 above.
- **`demo.session_minted` ledger event** — `warden-demo-mint` publishes a chain v1 forensic event to `warden.forensic` on every successful mint. `WARDEN_DEMO_MINT_NATS_URL=nats://nats:4222` in `warden-e2e/prod/docker-compose.yml`. Payload built by `mint::build_session_minted_payload`; `correlation_id = <prefix>-mint` so downstream visitor activity joins back to the session-creation row.
- **`warden_hil_avg_latency_seconds` metric** — `POST /decide/{id}` is wrapped with an RAII `DecideLatencyGuard` that records on every exit (success + error). Registered via `metrics::describe_histogram!` in `warden-hil/src/main.rs`. Runbooks already cited the name; it now actually exports. Prometheus average is `rate(_sum)/rate(_count)`.
- **`WARDEN_HIL_REQUIRE_DECIDE_TOKEN` boot guard** — opt-in env var. When set to `true`/`1`, HIL refuses to boot unless `WARDEN_HIL_DECIDE_TOKEN` is also set. Validation lives in `auth::validate_decide_token_requirement` (pure function so tests don't touch `std::env`). Matches the original spec promise softened in v0.6.3 (`TECH_SPEC.md#operator-authentication` §6).
- **Two chaos-monkey supply-chain scenarios** — `malicious_code_reverse_shell` (`write_file` tool + classic reverse-shell needle from brain's `MALICIOUS_CODE_NEEDLES`) and `compromised_package_install` (`execute_command` tool + `pip install jeIlyfish` — a PyPI typosquat in brain's bundled `compromised_packages.json`). New `Category::SupplyChain` variant. Both expect deny verdicts via brain's signal-fold `BLOCK: <signal>…` override.

### 14.8 v0.6.5 — v0.6.6 ship log (2026-05-13 / 2026-05-14)

Two further v1.x+1 items closed after the v0.6.4 quick-wins blitz. Spec text updated in the same commits.

- **`--delegation-mix` simulator flag (v0.6.5)** — `warden-simulator/src/delegation.rs`. Comma-separated principal pool stamped per fire as an unsigned `X-Warden-Grant` JWT. Proxy treats unsigned grants as advisory metadata (`warden-proxy/src/grant.rs` v1 trust model). Console `/audit` now renders varied "Delegation: alice@acme via cs-bot-1" badges. Compose default: `alice@acme.com,bob@acme.com,carol@globex.com,dana@globex.com`. See §14.2.
- **`Ed25519FileSigner` alt-backend (v0.6.6)** — second `Sign` impl in `warden-identity/src/signer.rs` for OSS / warden-lite deployments that skip Vault. Loads a PKCS#8 PEM key from `WARDEN_IDENTITY_SIGNING_KEY_PATH`, signs with `ed25519-dalek` directly, publishes the SPKI public PEM at `/jwks.json`. Wire envelope (`vault:v1:<base64>`) shared with the Vault path so the ledger verifier strip stays unchanged; `kid` (`warden-identity-file:v1` default, override via `WARDEN_IDENTITY_SIGNING_KEY_ID`) distinguishes the backend. Vault wins when both env vars are set — production posture unchanged. Security trade-off documented in `TECH_SPEC.md#threat-model` §"warden-identity" §Information disclosure: file backend trades "key out of process" for "no Vault dep" and is recommended only for single-replica OSS deployments.

---

## 15. Forensic-tier deep review

The async heavy-LLM auditor (`warden-deep-review`) layered on top of the four-layer security pipeline. It does *not* gate live traffic — that's HIL's job — but reviews a sampled slice of the audit stream with a substantially smarter model (Opus 4.7) to catch what Haiku missed and to deepen verdicts on what it flagged. See `TECH_SPEC.md#forensic-tier-deep-review` for the full design.

### 15.1 Async NATS consumer on `warden.forensic`

**Concept.** Deep-review subscribes to the same subject the ledger consumes from. Its emitted findings go back onto the same subject so the ledger picks them up via its existing consumer — no second subscription, no second envelope. The consumer filters its own emissions to prevent an infinite loop (matches on `method ∈ {deep_review_finding, deep_review_failed, deep_review_skipped}`).

**Implementation.** `warden-deep-review/src/consumer.rs`. NATS core pubsub (not JetStream — matches existing infra without an `-js` flag bump). Per-agent ring-buffer history populated unconditionally so the next event has full context regardless of sampling outcome. Tokio semaphore for bounded concurrency (default 4).

**Verify.**

```bash
# Boot the stack with the deep-review profile enabled
./repos/warden-e2e/dev/run.sh

# Drive any agent → see deep-review rows land in /audit
docker logs warden-dev-deep-review-1 | grep -E 'deep_review_(finding|failed|skipped)'
```

### 15.2 Per-event pipeline (sample → permit → budget → mask → prompt → review → emit)

**Concept.** Ten-step pipeline per incoming event: receive → self-emission filter → record in history → sample decision → semaphore permit → budget gate → PII mask → prompt build (strips brain verdict) → provider call (with retry/backoff) → emit finding (or sentinel).

**Implementation.** `warden-deep-review/src/lib.rs::review_one_event`. Brain verdict fields (`authorized`, `intent_category`, `reasoning`, `signal`, `persona_drift_score`, `injection_detected`, `malicious_code_detected`, `compromised_package_detected`, plus `policy_decision.{allow, reasons, review}`) are *stripped* from the prompt — independent reasoning is the entire value proposition.

### 15.3 `brain_delta` computation (server-side)

**Concept.** Three-valued summary of whether the heavy model agreed: `Agreed` / `Escalated` / `Downgraded`. The single number ops care about.

**Implementation.** `warden-deep-review/src/finding.rs::compute_brain_delta`. Table:

| Brain authorized | Deep verdict | brain_delta |
|---|---|---|
| true | Green | Agreed |
| true | Yellow | Escalated |
| true | Red | Escalated |
| false | Green | Downgraded |
| false | Yellow | Downgraded |
| false | Red | Agreed |

### 15.4 Three sentinel event types

**Concept.** Three `method` values on the existing `LogRequest` envelope distinguished by their `policy_decision` JSON payload shape — no `warden-ledger` wire change.

**Implementation.**

| `method` | When | Payload |
|---|---|---|
| `deep_review_finding` | Successful review | `{verdict, confidence, reasoning, brain_delta, reviewing_model, review_latency_ms, reviewed_at, original_method, original_correlation_id}` |
| `deep_review_failed` | Retry budget exhausted | `{reason ∈ Timeout\|Vendor5xx\|ParseError\|QuotaExceeded\|RateLimited\|UnknownVendorError, reviewing_model, original_method, original_correlation_id}` |
| `deep_review_skipped` | Daily token cap hit | `{reason: "budget", original_method, original_correlation_id}` |

**Verify.** `curl http://localhost:8083/audit | jq '.[] | select(.method | startswith("deep_review_"))'`.

### 15.5 Daily token budget (UTC midnight reset)

**Concept.** Per-day cap on `input + output` tokens to bound spend. Reset at UTC midnight by day-ordinal comparison.

**Implementation.** `warden-deep-review/src/budget.rs`. Default `WARDEN_DEEP_REVIEW_DAILY_TOKEN_CAP=1_000_000` (~$60/day Opus 4.7). Demo VPS pinned to `200_000` (~$12/day) so a stuck visitor session can never rack up a bill. `try_reserve` is the gate before any vendor call; `record_actual` reconciles the estimate with the response's `usage` field on success.

### 15.6 PII regex masker (six patterns, idempotent)

**Concept.** Defense in depth — every string leaf in the event JSON is regex-masked before the prompt builder strips brain-verdict fields, so even fields that get stripped never reach the vendor API in raw form.

**Implementation.** `warden-deep-review/src/pii.rs`. Patterns + sentinels:

| Pattern | Sentinel |
|---|---|
| SSN (`\d{3}-\d{2}-\d{4}` + variants) | `[SSN]` |
| Credit card (Luhn-shape 13-19 digit) | `[CC]` |
| Email | `[EMAIL]` |
| IPv4 | `[IPV4]` |
| PEM private-key block | `[PEM_PRIVATE_KEY]` |
| AWS access key (`AKIA…`) | `[AWS_ACCESS_KEY_ID]` |

The masker is idempotent — masking twice produces the same string — verified by the compliance harness on every benchmark case.

### 15.7 Alert webhook (Red + high-confidence, rate-limited per agent)

**Concept.** Page on `verdict == Red && confidence >= page_confidence` (default `0.85`). Rate-limited per agent (token bucket, refill 1/min) so a misbehaving agent can't storm the alert channel.

**Implementation.** `warden-deep-review/src/alert.rs`. Slack-shape JSON POST when `WARDEN_DEEP_REVIEW_ALERT_WEBHOOK` is set; over-limit pages are dropped silently — the finding still lands in the ledger so the alert can be reconstructed.

**Verify.**

```bash
# Stub sink
nc -lk 9999 &
WARDEN_DEEP_REVIEW_ALERT_WEBHOOK=http://localhost:9999/page ./run.sh
# Drive a scenario known to produce a Red verdict
# Observe one JSON POST on the sink; subsequent Reds from the same agent within 1min are dropped
```

### 15.8 25-case seed benchmark + hermetic compliance harness

**Concept.** Seed benchmark targeting the four Haiku blind-spot classes (slow exfiltration, persona drift, indirect injection via tool output, recon under varied encodings). Hermetic so CI runs without vendor tokens.

**Implementation.** `warden-deep-review/benchmark/cases.json` — 25 cases across 6 categories: slow_exfiltration (4), persona_drift (4), indirect_injection (4), recon_probing (6), benign_workflow (5), mixed (2). Verdict distribution: 11 Red / 8 Yellow / 6 Green. `tests/compliance.rs` drives the full corpus through prompt builder + PII mask + `MockProvider`; published baseline against real Opus is operator-run (token cost, network dependence).

### 15.9 Console `/deep-review` route + narrative summary strip

**Concept.** Operator surface for the new findings. Paginated list view + a summary strip on the per-agent `/audit/agents/{id}/narrative` so the answer to "did this thing earn its keep?" is one click away.

**Implementation.** `warden-console/src/handlers.rs::deep_review_index` + `templates/deep_review.html` (paginated 50/page, columns timestamp · correlation · agent · model · brain → deep verdict · confidence · latency, filters: kind/verdict/brain_delta/per_page). Narrative-strip in `templates/audit_narrative.html` shows last-7d findings count, brain_delta donut, top disagreement category, link to filtered `/deep-review`. Demo-prefix gate mirrors `/audit`.

**Verify.**

```bash
# Local
curl http://localhost:8085/deep-review

# Live demo VPS
curl -sf https://console-demo.vanteguardlabs.com/deep-review | grep -o 'Deep review'
```

---

## Verification — end to end

The single command that exercises ~80% of the features above:

```bash
./repos/warden-e2e/dev/run.sh
```

Boots all six services, drives the happy path through every layer, runs the chaos-monkey catalog, asserts the chain verifies, exits 0 on success. Read the runner's stdout — every assertion that passes corresponds to a feature in this document.
