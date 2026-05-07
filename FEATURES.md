# Agent Warden — Implemented Features

A complete inventory of what's shipped today (2026-05-07), with each feature explained on three axes:

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
./repos/warden-e2e/run.sh                                                   # host-cargo, full assertions
docker compose -f repos/warden-e2e/docker-compose.yml --profile stack up -d # console-with-data demo
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
./repos/warden-e2e/run.sh              # tail logs for "mtls accept"
```

Console `/audit` shows the resolved `agent_id` on every row — that's the CN/SPIFFE identity threaded through.

### 1.2 Security-first serial pipeline

**Concept.** When a request arrives, the proxy resolves the security verdict (Brain → Policy, then HIL if Yellow-tier) **before** any upstream call. Earlier commits raced security against upstream via `tokio::select!` to optimize latency, but that race re-opened a side-effect window for Yellow-tier tools — a wire transfer would have fired before HIL approval. The race was dropped on 2026-05-02. Today the proxy fails closed: upstream is only contacted on `Authorized` or HIL-Approved verdicts.

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
  -d '{"tool_type":"wire_transfer","agent_id":"test","method":"tools/call","intent_score":0.1,"current_time":"2026-05-07T12:00:00Z","recent_request_count":0}'
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
./repos/warden-e2e/run.sh        # produces a chain with all three versions
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

---

## 2. HIL — human-in-the-loop

### 2.1 Yellow-tier state machine

**Concept.** Some tool calls are too expensive (or too irreversible) to auto-approve even when Brain and Policy bless them. Wire transfers, account deletions, large refunds — the "Yellow tier." For these, the proxy parks the request at `warden-hil`, which surfaces it to a human approver and resolves the verdict on their click. The state machine is `Pending → Approved | Denied | Expired`. Approved → upstream fires (proxy treats it like Authorized). Denied/Expired/poll-timeout → 403 to the agent.

**Implementation.** `warden-hil:8084`. Wire surface: `POST /pending` (proxy creates) with body `CreatePending { agent_id, correlation_id, method, request_payload, risk_summary, ttl_seconds, sandbox_report }`; `GET /pending/{id}` long-polled by the proxy until status leaves `pending`; `POST /pending/{id}/decide` for approver clicks; `POST /pending/{id}/modify` for modify-and-resume. Each state transition emits a NATS forensic event that lands in the chain.

**Verify.** Drive the centerpiece scenario through the simulator and watch a row land in `/audit` with `tool_type=wire_transfer` in `Pending` state, then approve via console `/hil`, watch upstream fire.

```bash
# Boot stack
docker compose -f repos/warden-e2e/docker-compose.yml --profile stack up -d
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

---

## 3. Identity & agent onboarding (WAO)

### 3.1 SVID issuance (`POST /svid`)

**Concept.** Every agent has a verifiable workload identity — a SPIFFE SVID. The format is `spiffe://<trust-domain>/tenant/<tid>/agent/<agent-name>/instance/<uuidv7>`. Three layers:`tenant` is the billing/isolation boundary, `agent` is the stable logical identity (what policy keys off of), `instance` is the per-process replica (rotates on restart so we can revoke a single misbehaving replica without grounding the fleet). The SVID is short-TTL (≤1h) so a stolen cert has a tiny replay window.

**Implementation.** `warden-identity:8086`, `POST /svid`. Caller presents attestation evidence (TPM quote, SEV-SNP report, SGX-DCAP, Nitro, GCP-Shielded, or k8s-projected token); the identity service verifies it against the per-tenant config; on success, mints the cert. SVID metadata persists in the `svids` SQLite table (`id, spiffe_id, attestation_id, not_before, not_after, revoked_at`). In `enforce` registration mode, `/svid` consults the agent registry first — unregistered names get `403 unregistered_agent`.

**Verify.**

```bash
# The e2e runner's onboarding flow exercises this end-to-end
./repos/warden-e2e/run-onboarding.sh
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

**Implementation.** `POST /sign` on identity, body `{ correlation_id, method, prev_hash, payload_canonical_json }`, header `X-Caller-Spiffe` matched against `WARDEN_IDENTITY_SIGN_ALLOWED_CALLERS`. Returns `{ signature, key_id, signed_at }`. Ed25519 keys held in-process (loaded from `WARDEN_IDENTITY_SIGNING_KEY_PATH` at boot, exposed only as JWKS public material). Signing budget: p95 < 5ms.

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
wardenctl regulatory export --from 2026-05-01T00:00:00Z --to 2026-05-08T00:00:00Z --output bundle.tar.gz
tar -xzf bundle.tar.gz
cat manifest.sig    # 128 hex chars + LF
```

### 3.5 SPIFFE federation

**Concept.** Two Warden tenants need to A2A without sharing a CA. Tenant A publishes its trust bundle at a well-known URL; Tenant B's identity service polls that URL on a schedule. Cross-tenant actor tokens redeem against a freshness-gated peer-bundle store — if Tenant B's last-seen bundle for Tenant A is stale, A2A fails with `peer_bundle_stale:<td>` rather than silently accepting potentially-revoked keys.

**Implementation.** `GET /.well-known/spiffe-bundle` (public). Federation poller in `warden-identity` configured via `WARDEN_FEDERATION_PEERS`. `POST /actor-token` mints; `POST /actor-token/redeem` consults the peer-bundle freshness gate, returning `peer_bundle_unknown:<td>`, `peer_bundle_stale:<td>`, or `jti_already_used` (single-use enforcement).

**Verify.**

```bash
./repos/warden-e2e/run-federation.sh
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

**Implementation.** `WARDEN_IDENTITY_REGISTRATION_MODE` env var, parsed into `Mode::{Off, Warn, Enforce}`. **Today the default is `Enforce`** (the rollout flip happened on 2026-05-04). Operators bulk-enroll legacy fleets via `wardenctl agents migrate` before the flip.

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

**Implementation.** `warden-console/src/handlers.rs::audit`. Reads from `warden-ledger` via `warden-sdk::LedgerClient`. Joins related rows by `correlation_id`. Filter chips for signal column (`unregistered_agent`, `peer_bundle_stale:*`, `grant_expired`, etc.). The "Hide simulated traffic" filter joins by `correlation_id` so all sim-driven rows (proxy + policy + HIL) hide together — the `source` column on the forensic event is metadata; only the proxy's first event sets it, but the join means downstream rows hide too.

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
docker compose -f repos/warden-e2e/docker-compose.yml --profile stack-oidc up -d
open http://localhost:8085/login
# Redirects to Keycloak, returns with session
```

### 5.5 RBAC (viewer / approver)

**Concept.** Two static roles. `viewer` = read-only across the console. `approver` = viewer + ability to decide HIL pending items. No admin role in the console — admin operations go through `wardenctl` + direct identity API. No runtime role exceptions — the IdP's `groups` claim is the source of truth, mapped via config-as-code.

**Implementation.** `OidcGroupMap { approver_groups: Vec<String>, viewer_groups: Vec<String> }` in `warden-console/src/auth_session.rs`. Configured via env CSV. Session carries the resolved role; `require_viewer` and `require_approver` middleware check it.

**Verify.**

```bash
# In Keycloak, put the test user in only `viewer_groups`
# Login → /audit works → /hil works (read-only) → buttons hidden
```

### 5.6 Server-stamped `decided_by`

**Concept.** Pre-2026-05-03 the chain stamped `decided_by = "warden-console"` regardless of which human clicked. After the fix, HIL stamps `decided_by` server-side from the verified principal — the request body can't override it. Three formats: `webauthn:{name}`, `oidc:<sub>`, `basic:<username>`.

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
  --from 2026-05-01T00:00:00Z --to 2026-05-08T00:00:00Z \
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

**Implementation.** `repos/warden-lite/`. Single-binary crate; subset of the full feature set. No HIL, no identity, no NATS — all in-process.

**Verify.**

```bash
cargo run -p warden-lite -- --listen 127.0.0.1:8443
# Drive an MCP call, observe ledger row in lite's local SQLite
```

### 10.3 `warden-sdk`

**Concept.** The typed Rust client. Two artifacts share one source of truth: `warden-console` consumes it, `wardenctl` consumes it, external integrators consume it. SDK is the contract.

**Implementation.** `repos/warden-sdk/`. Clients: `LedgerClient`, `HilClient`, `SimClient`, `AgentsClient`. Each exposes `base_url() -> &Url` for the `/config` page redaction-safe readout. `AgentsClient::bearer_fingerprint() -> Option<String>` returns sha256[..8] hex of the configured token (never the raw token).

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

---

## 11. Test infrastructure

### 11.1 `warden-e2e/run.sh`

**Concept.** The host-cargo runner. Boots all six services + Docker NATS/Vault + a stub upstream; runs the happy path; runs the chaos-monkey red-team suite; tears down. Source of truth for "does the stack work end-to-end." Builds in **debug profile on purpose** — Apple clang segfaults on `ring`'s release C build on some macOS versions.

**Implementation.** Bash script at `repos/warden-e2e/run.sh`. Env knobs: `E2E_SKIP_CHAOS=1` for fast happy-path runs, `E2E_KEEP_LOGS=1` to retain logs and the temp work dir.

**Verify.**

```bash
./repos/warden-e2e/run.sh                         # full
E2E_SKIP_CHAOS=1 ./repos/warden-e2e/run.sh        # fast
E2E_KEEP_LOGS=1 ./repos/warden-e2e/run.sh         # debug
```

### 11.2 `warden-e2e/run-federation.sh`

**Concept.** Two-tenant federation runner. Boots two `warden-identity` instances under different trust domains and asserts the SPIFFE federation freshness gate: fresh peer bundle → A2A succeeds; staled-out → `peer_bundle_stale`.

**Implementation.** `repos/warden-e2e/run-federation.sh`. Configures `WARDEN_FEDERATION_PEERS` on each instance pointing at the other's `/.well-known/spiffe-bundle`. Triggers a peer-bundle staleness by stopping one instance's bundle endpoint, waiting past the freshness window, attempting A2A.

**Verify.**

```bash
./repos/warden-e2e/run-federation.sh
```

### 11.3 `warden-e2e/run-onboarding.sh`

**Concept.** WAO § 13.1 runner. Boots a `dexidp/dex` mock IdP container, drives `wardenctl agents create / suspend / decommission / migrate`, asserts `/svid` + `/grant` gating in `warn` and `enforce` modes (including § 13.1.7 bulk-enrollment migration replay).

**Implementation.** `repos/warden-e2e/run-onboarding.sh`. Dex mock configured with two static users:

- `admin@acme.com` with `groups: [warden-platform-admins]` (mapped to `agents:create + agents:admin`)
- `dev@acme.com` with `groups: [payments]` (no Warden capabilities — tests `403 missing_capability:agents:create`)

**Verify.**

```bash
./repos/warden-e2e/run-onboarding.sh
```

### 11.4 Compose stack (`--profile stack`)

**Concept.** The console-with-data demo. Boots everything in containers + the simulator + upstream-stub; surfaces a populated console for screenshots, evaluator walkthroughs, and operator practice.

**Implementation.** `repos/warden-e2e/docker-compose.yml --profile stack`. First cold build is ~15 min (release profile, no shared cargo target across the six service Dockerfiles). Subsequent runs are image-cached. `run-stack-smoke.sh` is the lighter health check.

**Verify.**

```bash
docker compose -f repos/warden-e2e/docker-compose.yml --profile stack up -d
open http://localhost:8085
./repos/warden-e2e/run-stack-smoke.sh
docker compose -f repos/warden-e2e/docker-compose.yml --profile stack down -v
```

### 11.5 `warden-chaos-monkey`

**Concept.** Curated red-team catalog. Each scenario fires a specific attack at a live proxy and asserts the predicted verdict. The list grows as the threat model expands; removing a scenario requires explaining why the attack is no longer relevant.

**Implementation.** Rust CLI at `repos/warden-chaos-monkey/`. Scenarios as of 2026-05-07:

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

**Implementation.** `repos/warden-simulator/`. Admin server (`SIM_ADMIN_PORT=9100`, default loopback-only): `GET /status`, `POST /multiplier`, `POST /running`, `POST /auto-decide`, `POST /agents`. Boots paused — operator clicks Start on the console (or sets `SIM_START_RUNNING=true` / `--start-running`) to fire traffic. HIL auto-decision sidecar boots **enabled** when `--hil-url` is set and is pausable; pausing leaves Yellow-tier pendings on the HIL queue for manual approval.

The `warden-upstream-stub` sub-binary is what compose uses as the proxy's downstream MCP echo target.

**Verify.**

```bash
docker compose -f repos/warden-e2e/docker-compose.yml --profile stack up -d
curl -X POST http://localhost:9100/running -d '{"running":true}'
open http://localhost:8085/audit
# Sim traffic streams in
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

---

## 14. Known gaps

These are **explicit open items**, tracked here for completeness against the Implemented-Features inventory. Not a roadmap commitment — each one waits on a triggering event.

### 14.1 `POST /revoke` endpoint (functional)

**Concept.** The spec table at `TECH_SPEC.md#identity-service` §4.1 lists `POST /revoke` for Operator-WebAuthn-gated revocation of SVIDs and grants. Today, revocation only happens implicitly via short-TTL expiry + suspend/decommission lifecycle rows.

**Status.** Not implemented; no route in `warden-identity/src/lib.rs::build_app`.

**Workaround.** `wardenctl agents suspend <id>` for the agent-record path; SVID expiry (≤1h TTL) for the cert path.

### 14.2 `--delegation-mix` simulator flag (test fidelity)

**Concept.** `TECH_SPEC.md#identity-service` §10 says the simulator should gain a `--delegation-mix` flag so persona-driven traffic spans multiple human principals — needed for console demo authenticity (the audit page's "Delegation: alice@acme via support-bot-3" badge).

**Status.** Not implemented in `warden-simulator/src/cli.rs`.

**Workaround.** Drive multi-principal traffic manually via direct `wardenctl agents create` + per-agent SVID issuance.

### 14.3 Demo experience (entire spec section)

**Concept.** `TECH_SPEC.md#demo-experience` describes a 6-week build plan: guided tour at `wardenlabs.com/demo`, Cloudflare Worker token mint, `warden-console` "demo-mode" with URL-fragment → cookie auth, token-scoped read filters in ledger and HIL, `warden-chaos-catalog` library extracted from `warden-chaos-monkey`, `/demo/fire` page, `demo.session_minted` event_kind, simulator `--auto-decide-skip-prefix`.

**Status.** Marketing-site mock exists (`warden-website/` 3-file static page); no backend integration. Module status line in the spec accurately says: "new, marketing/funnel work."

**Workaround.** None — book a demo or run the compose stack locally.

### 14.4 Spec-vs-code drift (documentation hygiene)

These are working code with stale spec wording:

- **Registration mode default is `enforce`, not `warn`** — `TECH_SPEC.md#agent-onboarding-wao` §6.3 line 483 still describes the rollout-phase `warn` default. Code hardwires `Enforce`.
- **HIL `WARDEN_HIL_DECIDE_TOKEN` validated per-request, not at boot** — Operator-auth §6 says "Both processes refuse to boot if the configured mode requires the token and it is missing." Console does; HIL only validates per-request.
- **Non-`text/*` body on `/export/regulatory` returns 400, not silently dropped** — Regulatory §10 says "ignored as readme." Code returns 400 with diagnostic. The code behavior is arguably better.
- **Action signing uses `GENESIS_PREV_HASH` placeholder, not ledger tail** — Identity §5.2 specifies signature commits to `prev_hash` from ledger. Proxy uses 64-zero constant to avoid two-RTT. Documented in `warden-proxy/src/sign.rs` module doc comment.

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

---

## Verification — end to end

The single command that exercises ~80% of the features above:

```bash
./repos/warden-e2e/run.sh
```

Boots all six services, drives the happy path through every layer, runs the chaos-monkey catalog, asserts the chain verifies, exits 0 on success. Read the runner's stdout — every assertion that passes corresponds to a feature in this document.
