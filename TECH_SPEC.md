# Warden Technical Specification

Consolidated technical record for Agent Warden. Each major section below was previously a standalone spec file in this repo; legacy cross-references in prose now resolve to the matching anchor in this document.

`SECURITY.md` (RFC 9116-style disclosure policy) remains a separate file at the repo root by convention — it is referenced by `security.txt` and surfaced in the GitHub Security tab.

## Contents

- [Identity service](#identity-service) — SVID issuance, OIDC delegation, action signing, attestation, federation
- [Agent onboarding (WAO)](#agent-onboarding-wao) — registration, capability envelope, lifecycle, chain v3
- [Console config page](#console-config-page) — `/config` diagnostic surface
- [Operator authentication](#operator-authentication) — console + HIL human auth, RBAC, cross-channel identity
- [Regulatory export](#regulatory-export) — EU AI Act Article 11/12 audit bundle
- [Demo experience](#demo-experience) — public-facing demo design
- [Console policy management](#console-policy-management) — read + CRUD + activate/deactivate of `*.rego` and `*.json` policies from the console
- [Forensic-tier deep review](#forensic-tier-deep-review) — async heavy-LLM auditor running against a sampled slice of the audit stream
- [Threat model](#threat-model) — STRIDE-organized, layer-by-layer
- [Runbooks](#runbooks) — five on-call failure modes

---

## Identity service


Companion spec to `README.md` §11.3 ("Agent identity — IAM for bots"). Scoped to what §11.3 commits to and grounded in the primitives Warden already ships (NATS forensic bus, hash-chained ledger, HIL, `regorus` policy engine).

**Module status:** **shipped.** Touches `warden-proxy`, `warden-policy-engine`, `warden-ledger`, `warden-hil`; introduced the `warden-identity` service (port 8086). The companion [Agent onboarding](#agent-onboarding-wao) section (also shipped) layers the agent-registry / lifecycle / capability-envelope work on top of these primitives.

### 1. What §11.3 actually commits to

The spec promises three capabilities. Restated as testable claims:

| Spec bullet | Operational claim |
|---|---|
| OIDC / SPIFFE federation | Every agent has a verifiable workload identity bound to a human/team/tenant principal. Agent-to-agent calls require a Warden-mediated handshake, not just transport mTLS. |
| Digital signatures for actions | Every Authorized or HIL-Approved tool call produces a Warden-issued, ledger-anchored signature over `(agent_id, correlation_id, method, request_payload, verdict, prev_hash)`. The signature is the legal proof. |
| Capability attestation | Sensitive tools (Yellow tier and a configurable allowlist) require fresh evidence the agent's runtime is unmodified — TPM/SGX quote, or remote-attestation token from a managed runtime. |

Identity, in Warden's threat model, is **necessary but insufficient** (§13.1). WI's job is not to replace Brain/Policy/HIL — it is to make the `agent_id` field they all key off of cryptographically meaningful end-to-end.

### 2. Threat model (in scope)

| # | Threat | Today | After WI |
|---|---|---|---|
| T1 | Stolen client cert replayed from a different host | Proxy accepts it (CN trusted unconditionally) | Cert short-TTL (≤1h) + attested issuance; replay window collapses |
| T2 | Agent A impersonates Agent B in an A→B call | No A2A check today; Brain sees the *receiving* agent's view only | SVID-bound `actor_token` + audience binding rejects mismatch |
| T3 | Compromised supply chain: agent binary swapped post-deploy | Undetected | Capability attestation gates Yellow-tier tools |
| T4 | Insider replays a ledger row claiming "the agent did it" | Possible — `agent_id` is not signed by the agent, only stamped by the proxy | Per-action signature chain anchored to ledger `prev_hash` provides non-repudiation |
| T5 | Human user repudiates an HIL approval ("not me") | WebAuthn approver auth covers approver side | WI binds the *delegation* user→agent so the agent's own action is also non-repudiable |

**Out of scope:** governing the human IdP itself (delegate to Okta/Entra), key custody for the issuing CA (delegate to Vault Transit / KMS), cross-tenant federation v1 (single-tenant first).

### 3. Identity model

#### 3.1 Names

```
spiffe://<trust-domain>/tenant/<tid>/agent/<agent-name>/instance/<uuidv7>
```

- `tenant/<tid>` — billing/isolation boundary; matches the existing `agent_id` prefix convention used by the simulator.
- `agent/<agent-name>` — stable logical identity (e.g. `support-bot-3`). This is what policy rules and Brain's persona-drift baseline key off.
- `instance/<uuidv7>` — per-process; rotates on restart. Lets us revoke a single misbehaving replica without grounding the fleet.

The existing `MtlsIdentity.cn` becomes a *projection* of this SPIFFE ID for backwards compatibility — the proxy parses the SAN URI and falls back to CN only for legacy clients during a deprecation window.

#### 3.2 Principals and delegation

```
Human (OIDC subject)
   │  delegates capabilities via signed grant
   ▼
Agent root identity (SPIFFE, long-lived, in attestation policy)
   │  mints
   ▼
Agent instance SVID (≤1h TTL, hardware-attested)
   │  on A→B call, mints
   ▼
Actor token (audience-bound, ≤60s TTL, single-use)
```

The delegation grant is the missing piece in today's architecture. It carries:

```json
{
  "iss":  "warden-identity",
  "sub":  "spiffe://wd.local/tenant/acme/agent/support-bot-3",
  "act":  { "sub": "user:alice@acme.com", "idp": "okta", "amr": ["webauthn"] },
  "scope": ["mcp:read:tickets", "mcp:write:tickets"],
  "yellow_scope": ["refund:<=50usd"],
  "exp":  1714694400,
  "jti":  "01HW..."
}
```

`act` is RFC 8693 actor-token semantics: "this agent is acting *on behalf of* this human." The proxy presents `act.sub` to HIL approvers verbatim ("Alice's support-bot-3 wants to refund $42") — this is what makes the audit story land for compliance officers reading EU AI Act Article 12 logs.

#### 3.3 Federation

- **Inbound (humans → Warden):** OIDC. Warden trusts an enterprise IdP for human auth; the IdP's `id_token` is exchanged at `warden-identity` for a delegation grant via OAuth 2.0 Token Exchange (RFC 8693).
- **Outbound (agents → other Warden tenants):** SPIFFE federation bundle. Tenant A's trust bundle is published at `https://identity.<tenant-a>/.well-known/spiffe-bundle`; Tenant B's identity service polls it. Cross-tenant A2A becomes possible without sharing a CA.

### 4. The new service: `warden-identity`

Standalone Rust service, port 8086. It is the only component allowed to mint SVIDs and delegation grants. It is a NATS forensic publisher for issuance/revocation events, so the ledger has a row for every cert minted.

#### 4.1 HTTP surface

| Method | Path | Purpose | Auth |
|---|---|---|---|
| `POST` | `/svid` | Issue an instance SVID against an attestation document | Attestation evidence (§6) |
| `POST` | `/grant` | Exchange OIDC `id_token` + agent SVID → delegation grant | OIDC `id_token` + SVID mTLS |
| `POST` | `/actor-token` | Mint an audience-bound A→B token | Caller SVID + grant |
| `POST` | `/sign` | Warden-side signing of a finalized verdict (§5) | Proxy SVID only |
| `POST` | `/revoke` | Revoke an instance or grant | Operator WebAuthn |
| `GET`  | `/jwks.json` | Public keys for grant/actor-token verification | Public |
| `GET`  | `/.well-known/spiffe-bundle` | SPIFFE federation bundle | Public |

#### 4.2 Storage

SQLite, mirroring the ledger's "boring + auditable" stance:

- `svids` (id, spiffe_id, attestation_id, not_before, not_after, revoked_at)
- `grants` (jti, agent_spiffe, human_sub, scope_json, yellow_scope_json, exp, revoked_at)
- `attestations` (id, kind {tpm-quote, sev-snp, sgx-dcap, gcp-tpm, aws-nitro, k8s-projected}, evidence_blob, verified_at, policy_version)

No JSON in queryable columns where it can be a column — we want SQL-grep-able audits.

#### 4.3 Keys

Issuer keys live in **Vault Transit** (Warden already runs Vault for credential injection). The identity service never holds private key material in-process — it calls `transit/sign/<key>` over the existing Vault client. Rotation is Vault-driven.

### 5. Action signing & ledger anchoring

This is the highest-value bullet — non-repudiation is what unlocks the §15 "trust dividend" insurance story.

#### 5.1 What gets signed

After the security verdict resolves and `forward_upstream` runs (or is denied), the proxy calls `warden-identity` `/sign` with:

```rust
struct SignRequest {
    agent_spiffe: String,
    correlation_id: Uuid,
    method: String,
    request_payload_sha256: [u8; 32],   // do NOT send payload itself
    verdict: Verdict,                    // Authorized | ReviewApproved | ReviewDenied | Violation
    upstream_outcome: Option<UpstreamOutcome>,
    prev_hash: String,                   // tail hash of the ledger chain
}
```

The signing service returns `{ signature, key_id, signed_at }`. The proxy's NATS forensic event then carries this triple, and the ledger's hashable becomes:

```
{ id, timestamp, agent_id, agent_spiffe, method, intent_category, authorized,
  reasoning, policy_decision, signature, key_id, seq, prev_hash }
```

**This is a chain-version bump.** The hashable field order is the chain version, so we ship it as `CURRENT_CHAIN_VERSION = 2`, dispatched per-row exactly like the existing version-negotiation machinery already in the ledger. Old rows verify under v1; new rows under v2. No retroactive re-signing.

#### 5.2 What the signature is *over*

`sha256(prev_hash || "|" || canonical_json(hashable_v2_minus_signature))` — the same shape as the chain hash, signed with the issuer key. This means:

- The signature transitively commits to *all prior ledger state* via `prev_hash`.
- Tampering with any historical row breaks the signature on every later row, not just the chain hash. Two-layer integrity.
- A regulator reproducing the chain only needs Warden's JWKS + the ledger export — no live service.

#### 5.3 What is *not* signed

`source` (client-controlled metadata, not in hashable) and any HIL approver identity that is not yet cryptographic. WebAuthn-backed approver signatures are the natural follow-on, but they sign a *separate* HIL state-transition event, not the proxy's verdict event.

### 6. Capability attestation

Gating model: Policy Engine consults a new `attestation_required` rule per tool/method, evaluated against fresh attestation evidence the proxy attaches to `PolicyInput`.

```rust
struct PolicyInput {
    // ... existing fields ...
    attestation: Option<AttestationClaims>,   // NEW
}

struct AttestationClaims {
    kind: AttestationKind,         // tpm | sev-snp | sgx-dcap | nitro | gcp-shielded | k8s-projected
    measurement: String,           // hex-encoded PCR/MRENCLAVE/etc.
    issued_at: DateTime<Utc>,      // freshness
    expires_at: DateTime<Utc>,     // ≤ 15min
    nonce_echo: String,            // proves liveness against a Warden-issued nonce
}
```

Rego rule sketch:

```rego
deny[msg] {
  tool_requires_attestation[input.method]
  not fresh_attestation(input.attestation)
  msg := "attestation required or stale"
}

deny[msg] {
  tool_requires_attestation[input.method]
  not allowed_measurements[input.method][input.attestation.measurement]
  msg := "agent measurement not in allowlist"
}
```

The allowlist is per-method, not per-tenant — the security claim is "the code that calls `wire_transfer` is the code we approved." Allowlist updates are a separate signed artifact (think Sigstore-style transparency log; v1 it's a checked-in JSON file in the policy repo).

**Performance note.** Attestation verification is expensive (10–50ms for a TPM quote). The proxy caches verified attestations keyed by `spiffe_id || measurement` for `min(expires_at, 5min)`. Cache misses block the request; cache hits add zero latency to the hot path. This is the only way to keep the §6 "every millisecond × 50 sub-calls" budget intact.

### 7. Wire-contract changes

Shared types are duplicated on each side of the wire. The fields below need to land **simultaneously** in both repos of each pair:

| Edge | Field added | Repos to grep |
|---|---|---|
| Proxy → Brain | `agent_spiffe: String` | `warden-proxy/src/fork.rs`, `warden-brain/src/lib.rs` |
| Proxy → Policy | `agent_spiffe: String`, `attestation: Option<AttestationClaims>` | `warden-proxy/src/fork.rs`, `warden-policy-engine/src/lib.rs` |
| Proxy → HIL | `agent_spiffe: String`, `delegation_jti: String` | `warden-proxy/src/sandbox_handoff.rs` (CreatePending site), `warden-hil/src/api.rs` |
| Proxy → Ledger (NATS) | `agent_spiffe`, `signature`, `key_id` (chain v2) | `warden-proxy`, `warden-ledger/src/chain.rs` |

Console (`warden-console`) needs a "Delegation: alice@acme via support-bot-3" badge on every audit row — wire it through the existing correlation-id join.

### 8. Failure & fallback semantics

| Failure | Behaviour | Reasoning |
|---|---|---|
| `warden-identity` unreachable on `/sign` | Proxy fails *closed* on Yellow-tier and any tool with `attestation_required`; fails *open* (no signature, ledger v1 row) on Authorized non-attested calls, with a `signing_unavailable` signal in Brain's signal aggregator | Don't take the whole stack down because a non-critical service blips; do refuse to sign forged-checks-from-the-future |
| Attestation expired mid-burst | Proxy returns 401 with `attestation_stale`; agent re-attests | Same model as expired SVID |
| Vault Transit unavailable | Identity service degrades to `signing_unavailable` (above) | Single failure domain — Vault is already a hard dep |
| Federation bundle stale (cross-tenant) | Reject A2A; allow same-tenant | Matches the §13.1 "identity is necessary but insufficient" framing — better to fail safe |

### 9. Migration & rollout

Five phases, each independently shippable. **All five shipped.**

1. **SVID issuance, no enforcement.** *(shipped)* `warden-identity` mints SVIDs alongside the existing CA. Proxy parses the SPIFFE SAN from the cert and falls back to CN for legacy clients.
2. **Delegation grants.** *(shipped)* `/grant` exchange wired; HIL records the delegation principal on pending rows; proxy threads `X-Warden-Grant` through and rejects expired grants with `grant_expired`.
3. **Action signing (chain v2).** *(shipped)* Ledger gained v2 dispatch (`HashableEntryV2` with `agent_spiffe`, `signature`, `key_id`); proxy calls `/sign` after the verdict resolves; verifier exposes JWKS-based per-row signature check; mixed-v1/v2 export verifies.
4. **Attestation enforcement.** *(shipped)* `policies/attestation.rego` ships with `attestation_required` rules keyed on `wire_transfer` and `delete_*`; `attestation_allowlist.json` carries the per-tool measurement list; proxy attaches `AttestationClaims` (with a per-spiffe-id cache and `X-Warden-Attestation` per-request header override) on every `/evaluate`; chaos-monkey `unattested_binary` asserts deny.
5. **Cross-tenant federation.** *(shipped)* SPIFFE bundle endpoint at `GET /.well-known/spiffe-bundle`; `/actor-token` mint + `/actor-token/redeem` with peer-bundle freshness gate (`peer_bundle_unknown:<td>` / `peer_bundle_stale:<td>`); federation poller; two-tenant `run-federation.sh` e2e in `warden-e2e`.

The §11.3 valuation claim (⭐⭐⭐⭐⭐, "zero-trust score" metric) and the §15 trust-dividend story are both unblocked.

### 10. Test surface

- **`warden-e2e`** gains: SVID issuance happy path; revocation kills next request within 1s; signed-row chain verification against a regulator-style export.
- **`warden-chaos-monkey`** gains: `stolen_svid_replay`, `unattested_binary`, `expired_grant`, `cross_tenant_unfederated`. All four must produce specific, predicted verdicts.
- **`warden-simulator`** gains a `--delegation-mix` flag so persona-driven traffic spans multiple human principals — needed to make the console demo look real.

### 11. What this spec deliberately does not include

- A bespoke PKI. We use SPIFFE + Vault Transit because they exist and are audited.
- A new HIL approver flow. WebAuthn approver auth is a separate workstream; this spec only ensures the *agent side* of the delegation is cryptographic. Both sides land independently.
- A custom revocation mechanism. Short-TTL SVIDs (≤1h) + grant `jti` denylist published over NATS is enough. CRLs are a 1990s answer to a 2026 problem.
- A new audit UI. The console's existing `/audit` correlation-id join is the right shape; we just add three columns.

---

## Agent onboarding (WAO)


Companion to the [Identity service](#identity-service) section. Where that section covers how a *running* agent gets a cryptographic identity (SVID, grant, action signature, attestation), this spec covers the missing pre-step: how an agent gets *registered with the platform* in the first place — who declared it should exist, with what capabilities, owned by which team — and how that record gates every downstream identity operation.

**Module status:** shipped. Extends `warden-identity` (no new service); introduces a new top-level CLI binary `wardenctl`; extends `warden-console` and `warden-ledger` (chain v3); touches `warden-e2e` and `warden-chaos-monkey`. Depends on the issuance, signing, and chain-version-negotiation primitives in the [Identity service](#identity-service) section.

### 1. What this closes

The [Identity service](#identity-service) section makes the `agent_id` field cryptographically meaningful end-to-end. It does not say where the field comes from. Today, `POST /svid` mints an instance cert for *any* `(tenant, agent_name)` pair as long as attestation passes — first call wins. `POST /grant` accepts arbitrary opaque scope strings from the caller. There is no record of "this agent should exist, owned by this human/team, scoped to these capabilities" prior to issuance.

The operational consequences:

| Gap | Today | After WAO |
|---|---|---|
| Namespace squat | Any compromised attestor can claim `wire-transfer-bot` and the platform issues | `(tenant, agent_name)` must be pre-registered or `/svid` rejects (in `enforce`) |
| Capability sprawl | `/grant` honors any scope string Brain/Policy hasn't explicitly denied | `/grant` rejects scopes outside the agent's registered envelope |
| Audit lineage | Chain shows "Alice's bot did X." Nobody can prove Alice ever said the bot should exist | Chain shows "Alice declared `support-bot-3` exists with envelope Y on date D" alongside every later verdict row, both signed |
| Incident lever | Only kill-switch is to revoke the SVID and refuse to mint a new one — terminal | Suspend (reversible, blocks new SVIDs + revokes existing) and decommission (terminal, name unreusable) |
| Routing accountability | `agent_id` is opaque to HIL approvers; "who owns this agent" is tribal knowledge | HIL pending rows carry `owner_team` and registering human; envelope shown inline so approvers can see the action is in-envelope |

The capability envelope is the load-bearing primitive. Without it, registration is namespace-only and adds nothing the chain doesn't already have. With it, the chain transitively binds *what was authorized* to *what was done*.

### 2. Threat model (in scope)

| # | Threat | Today | After WAO |
|---|---|---|---|
| T1 | Compromised attestor claims a high-privilege `agent_name` it never had | First-call wins; SVID issued; agent inherits whatever runtime privileges its name implies | `agent_name` must be pre-registered by a human with `agents:create`; unregistered names rejected (`enforce`) or flagged (`warn`) |
| T2 | Agent silently escalates its own capabilities via `/grant` request | `/grant` accepts arbitrary scopes; only Brain/Policy at runtime gate them | `/grant` intersects requested scopes with the registered envelope before issuance; out-of-envelope = `403 scope_outside_envelope` |
| T3 | Operator fakes a registration retroactively to cover an incident | Sidecar registry tables are operator-trusted | Lifecycle events anchored in chain v3, signed by `warden-identity` issuer key; tampering breaks every later signature |
| T4 | Compromised team member quietly hands their high-privilege agent to an attacker-controlled team | No ownership transfer concept | Transfer requires `agents:admin` (different capability than owner-team membership), emits `agent.owner_team_transferred` chain row |
| T5 | Decommissioned agent name re-registered with looser scope | No retention; name is reusable | `UNIQUE (tenant, agent_name)` includes Decommissioned; re-register attempt returns `409 agent_name_retired` |

**Out of scope:** receiving-team consent on transfer (admins can dump on unwilling teams in v1; flagged as v2 follow-on); a capability-change request workflow (the widen endpoint is the *terminal* action — any approval flow on top is a separate spec); bulk operations (per-team mass suspend); a Terraform provider (the `--if-absent` CLI flag covers IaC patterns until a customer asks for native Terraform).

### 3. The registration record

#### 3.1 Schema

Lives in `warden-identity`'s SQLite alongside `svids`, `grants`, `attestations`. One table:

```sql
CREATE TABLE agents (
    id                          TEXT PRIMARY KEY,           -- uuidv7
    tenant                      TEXT NOT NULL,
    agent_name                  TEXT NOT NULL,
    state                       TEXT NOT NULL,              -- Active | Suspended | Decommissioned
    scope_envelope              TEXT NOT NULL,              -- JSON array of opaque scope strings
    yellow_envelope             TEXT NOT NULL,              -- JSON array of opaque yellow-scope strings
    attestation_kinds_accepted  TEXT NOT NULL,              -- JSON array; [] = inherit global allowlist
    created_by_sub              TEXT NOT NULL,              -- OIDC subject; immutable
    created_by_idp              TEXT NOT NULL,              -- "okta" | "entra" | ...; immutable
    owner_team                  TEXT NOT NULL,              -- IdP group claim; mutable via transfer
    created_at                  TEXT NOT NULL,              -- RFC 3339; immutable
    state_changed_at            TEXT NOT NULL,
    state_changed_by            TEXT NOT NULL,              -- OIDC subject of last transition
    description                 TEXT,                       -- optional free text
    UNIQUE (tenant, agent_name)                             -- includes Decommissioned (no name reuse)
);

CREATE INDEX agents_by_tenant_state ON agents (tenant, state);
CREATE INDEX agents_by_owner_team   ON agents (tenant, owner_team);
```

Field rationale:

- **`scope_envelope` / `yellow_envelope` separately** mirror the `/grant` request shape (`scope` / `yellow_scope` in `grant.rs`). Per-field intersection at grant time produces per-field rejection reasons (`scope_outside_envelope` vs `yellow_scope_outside_envelope`) without forcing the handler to inspect each entry to know which side it belongs to.
- **`attestation_kinds_accepted`** is per-agent narrowing of the global attestation allowlist. Empty array means "any kind currently accepted by the global identity config." Closes the namespace-squat-with-stolen-attestation hole one click further than the global setting alone.
- **`created_by_sub` and `created_by_idp` are immutable.** No `UPDATE` path. Non-repudiation requires that a regulator reading the chain can always identify the human who authorized the agent's existence.
- **`state_changed_*` overwrite on transition.** The full history is in chain v3 rows; the mutable columns just serve fast "show me current state" reads. SQLite is not the audit log — the ledger is.
- **`UNIQUE (tenant, agent_name)` includes `Decommissioned`.** Name recycling is forbidden to prevent the "decommission `payments-bot`, immediately re-register with looser scope" attack. Decommission is terminal and the row stays as the audit anchor.
- **No `version` / `etag`.** Last-write-wins on the rare contended state transition; the second writer's chain row is a no-op the handler short-circuits.
- **No `tags`, `slack_channel`, `repo_url`, `runtime_hints`.** Identity holds only what `/svid`, `/grant`, `/sign`, the gating logic, and the ledger anchoring need. External metadata belongs in external systems.
- **Tenants are *not* a row.** `tenant` is a string, validated by the existing `validate_label` in `svid.rs:116`. A `tenants` table is a separate spec — it implies tenant lifecycle, billing, per-tenant IdP federation, and is a much bigger commitment than this feature warrants.

#### 3.2 Lifecycle state machine

Three states. Two reversible transitions, one terminal:

```
       agents:create                 owner-team or admin
            │                                │
            ▼                                ▼
        ┌──────┐  suspend     ┌────────────┐  decommission   ┌─────────────────┐
   ───▶ │Active│ ───────────▶ │ Suspended  │ ──────────────▶ │ Decommissioned  │
        └──────┘              └────────────┘                 └─────────────────┘
            ▲                       │                                ▲
            └─────── unsuspend ─────┘                                │
                       (admin only)                                  │
                                                                     │
                            decommission (admin only) ───────────────┘
```

- **Active → Suspended** is reachable by any owner-team member or any tenant admin. One-click pause for incident response.
- **Suspended → Active** requires `agents:admin`. If the team that suspended themselves can also unsuspend themselves, the suspend lever doesn't survive a compromised team account.
- **`* → Decommissioned`** requires `agents:admin`. Terminal. The row remains; the `(tenant, agent_name)` is permanently unreusable.
- **Suspend is hard.** Existing SVIDs are revoked via the NATS revocation broadcast that [Identity service](#identity-service) §8 already needs (denylist consulted on `/sign`). Outstanding grants reject. There is no "soft suspend that lets in-flight requests run to TTL."

#### 3.3 Ownership

Two principals on every record, doing different jobs:

- **`created_by_sub` (immutable):** non-repudiation. The human who declared this agent should exist. Their signature anchors the `agent.registered` chain row; nothing changes that fact later.
- **`owner_team` (mutable):** routing. The team responsible for operating the agent. HIL fans out Yellow-tier approvals to whatever Slack/Teams channel maps to the team. Transferable by `agents:admin` only; emits `agent.owner_team_transferred`.

The IdP `groups` claim is required. `POST /agents` with an `owner_team` not in the caller's `groups` returns `403 owner_team_not_in_token` — you cannot register an agent owned by a team you don't belong to. If a tenant's IdP doesn't emit `groups`, `POST /agents` returns `403 missing_team_claim` and the tenant is documented to configure the claim before onboarding.

### 4. The capability envelope

#### 4.1 Grammar

Scopes are opaque, NFC-normalized lowercase strings, ≤128 bytes, no whitespace. The existing `validate_label` in `grant.rs:267` is reused (extended to the new envelope columns). No DSL, no parser, no semantic comparison.

A scope is either in a set or it isn't. `refund:<=50usd` and `refund:<=100usd` are distinct strings; if the envelope contains the first, the second is rejected. Teams that want graduated tiers declare each tier as a separate envelope entry (`refund:<=50usd`, `refund:<=500usd`, `refund:<=5000usd`) and rely on `regorus` rules at runtime for the dollar comparison.

The conventions `mcp:read:<resource>`, `mcp:write:<resource>`, `yellow:<token>` are documented but not enforced by the parser. Forward compatibility: any future structured grammar is a strict superset (string equality is a degenerate case of any comparator), so opaque-string envelopes verify under every future grammar without invalidating chain v3 rows.

#### 4.2 Intersection at `/grant`

```
GrantRequest.scope          ⊆  Agent.scope_envelope          → 200, mint
GrantRequest.scope          ⊄  Agent.scope_envelope          → 403 scope_outside_envelope
GrantRequest.yellow_scope   ⊆  Agent.yellow_envelope         → 200, mint
GrantRequest.yellow_scope   ⊄  Agent.yellow_envelope         → 403 yellow_scope_outside_envelope
```

The 403 response body lists the offending scope(s) for debuggability:

```json
{ "error": "scope_outside_envelope", "offenders": ["wire_transfer"] }
```

Empty envelope (`[]`) is legal and means "this agent can hold an SVID but cannot be granted any capability." Useful as a Suspended → Active rehearsal state before scopes are restored. Any non-empty grant request against an empty envelope returns `scope_outside_envelope`.

### 5. Wire surface

#### 5.1 Registration & lifecycle

All endpoints below take `Authorization: Bearer <oidc_id_token>`. `warden-identity` validates against the per-tenant JWKS configured in `identity.toml`, extracts `sub`, `idp` (from issuer mapping), `groups` (for `owner_team` checks), and resolves capabilities by mapping `groups → [agents:create, agents:admin, ...]` per `[capabilities.tenants.<tid>]` config.

| Method | Path | Capability | Chain v3 event |
|---|---|---|---|
| `POST` | `/agents` | `agents:create` | `agent.registered` |
| `GET` | `/agents` | any tenant member | — |
| `GET` | `/agents/{id}` | any tenant member | — |
| `POST` | `/agents/{id}/suspend` | owner-team or `agents:admin` | `agent.suspended` |
| `POST` | `/agents/{id}/unsuspend` | `agents:admin` | `agent.unsuspended` |
| `POST` | `/agents/{id}/decommission` | `agents:admin` | `agent.decommissioned` |
| `POST` | `/agents/{id}/envelope/narrow` | owner-team or `agents:admin` | `agent.envelope_narrowed` |
| `POST` | `/agents/{id}/envelope/widen` | `agents:admin` | `agent.envelope_widened` |
| `POST` | `/agents/{id}/attestation-kinds` | dispatched per direction | `agent.attestation_kinds_changed` |
| `POST` | `/agents/{id}/owner-team` | `agents:admin` | `agent.owner_team_transferred` |
| `POST` | `/agents/{id}/description` | owner-team or `agents:admin` | `agent.description_changed` |

Asymmetric authority is the principle: narrowing the envelope (less capability) is owner-team self-service; widening (more capability) requires a different human with `agents:admin`. The original registering admin's signature covered the original envelope; widening is a *new* authorization event and must be a *new* authorization signature.

#### 5.2 Request and response shapes

```
POST /agents
Authorization: Bearer <oidc_id_token>

{
  "tenant":             "acme",
  "agent_name":         "support-bot-3",
  "owner_team":         "payments",
  "scope_envelope":     ["mcp:read:tickets", "mcp:write:tickets"],
  "yellow_envelope":    ["refund:<=50usd"],
  "attestation_kinds":  ["tpm", "sev-snp"],
  "description":        "Triage bot for tier-1 tickets"
}

200 → { "id": "<uuidv7>", "spiffe_id_pattern": "spiffe://wd.local/tenant/acme/agent/support-bot-3/instance/*",
        "state": "Active", "created_at": "...", ... }

401 → { "error": "invalid_token" }                  // OIDC validation failed
403 → { "error": "missing_capability:agents:create" }
403 → { "error": "owner_team_not_in_token" }        // owner_team not in caller's groups claim
403 → { "error": "missing_team_claim" }             // IdP doesn't emit groups
409 → { "error": "agent_name_taken" }
409 → { "error": "agent_name_retired" }             // decommissioned, name unreusable
422 → { "error": "scope_not_normalized", "field": "scope_envelope[2]" }
```

Lifecycle endpoints all take `{ "reason": "<free text>" }` (optional) and return `{ "state": "<new state>", "state_changed_at": "..." }`. The `reason` lands in the chain v3 payload for the corresponding event.

Envelope-narrow / -widen take the *full new envelope*, not a diff:

```
POST /agents/{id}/envelope/narrow
{ "scope_envelope":  ["mcp:read:tickets"],
  "yellow_envelope": [] }
```

The handler verifies the new envelope is a strict subset of the old (for narrow) or strict superset (for widen) and rejects otherwise (`422 envelope_not_narrower` / `422 envelope_not_wider`). Caller passes the whole intended state; no diff parsing, no JSON-merge-patch ambiguity.

### 6. Gate integration with `/svid` and `/grant`

The agent record is consulted in the same SQLite transaction as the issuance INSERT. No TOCTOU window between gating check and minting.

#### 6.1 `/svid` failure catalog (`enforce` mode)

| Status | Error | Condition |
|---|---|---|
| 200 | — | Record exists, Active, attestation kind in record's allowlist (or in global allowlist if record's is empty), attestation valid |
| 403 | `unregistered_agent` | No record for `(tenant, agent_name)` |
| 403 | `agent_suspended` | Record exists, state Suspended |
| 403 | `agent_decommissioned` | Record exists, state Decommissioned |
| 403 | `attestation_kind_not_accepted` | Record's `attestation_kinds_accepted` non-empty and presented kind not in it |
| 422 | (existing) | Existing attestation-evidence shape errors, unchanged |

#### 6.2 `/grant` failure catalog (always, regardless of mode for registered agents)

| Status | Error | Condition |
|---|---|---|
| 200 | — | Record exists, Active, requested scopes ⊆ envelope, requested yellow ⊆ yellow envelope |
| 403 | `scope_outside_envelope` | Body lists offending scopes |
| 403 | `yellow_scope_outside_envelope` | Body lists offending yellow scopes |
| 403 | `agent_suspended` / `agent_decommissioned` | Bad state |
| 403 | `unregistered_agent` (`enforce` only) | No record |

#### 6.3 Mode behaviour

`WARDEN_IDENTITY_REGISTRATION_MODE = off | warn | enforce`. Default `warn` for one minor version after this spec lands, then default flips to `enforce`.

| Mode | Unregistered name on `/svid` | Unregistered name on `/grant` | Registered agent + out-of-envelope grant |
|---|---|---|---|
| `off` | 200, no signal | 200, no signal | 200, no signal (envelope ignored) |
| `warn` | 200 + `unregistered_agent` signal on forensic event | 200 with wildcard envelope + `unregistered_agent` signal | **403 `scope_outside_envelope`** |
| `enforce` | 403 `unregistered_agent` | 403 `unregistered_agent` | 403 `scope_outside_envelope` |

The principle: **registration is opt-in to enforcement**. The mode flag governs the *unknown* case (no record). Once a record exists, its envelope is enforced regardless of mode — otherwise registration in `warn` would be decorative. This lets operators onboard their highest-risk agents first, get real enforcement immediately on those, and let lower-risk agents run unregistered until the global flip.

The signal vocabulary on the forensic event uses `unregistered_agent` (consistent with `peer_bundle_stale` / `grant_expired` naming from the [Identity service](#identity-service) section).

### 7. Chain v3 — lifecycle row anchoring

`CURRENT_CHAIN_VERSION = 3` after this lands. v1 (verdict, no signature), v2 (verdict + signature), and v3 (lifecycle event) coexist in the chain; verifier dispatches per-row. No retroactive re-signing.

#### 7.1 Two-tier hashable

The outer hashable is fixed at v3 launch and never altered without a v4 bump. Per-event-kind variation lives in a separate payload, content-hashed into `payload_sha256`:

```json
{
  "id":               "<uuidv7>",
  "timestamp":        "<RFC 3339 UTC>",
  "event_kind":       "agent.registered",
  "agent_id":         "<uuidv7 of the agents row>",
  "tenant":           "acme",
  "agent_name":       "support-bot-3",
  "actor_sub":        "user:alice@acme.com",
  "actor_idp":        "okta",
  "payload_sha256":   "<hex>",
  "signature":        "<base64>",
  "key_id":           "<warden-identity issuer key id>",
  "seq":              42,
  "prev_hash":        "<hex>"
}
```

Hash formula (same shape as v1/v2):

```
entry_hash[n] = sha256( prev_hash[n] || "|" || canonical_json(hashable_v3_minus_signature) )
signature      = sign(warden-identity issuer key, entry_hash[n])
payload_sha256 = sha256( canonical_json(payload) )
```

#### 7.2 Per-kind payloads

| `event_kind` | Payload |
|---|---|
| `agent.registered` | `{ scope_envelope, yellow_envelope, attestation_kinds_accepted, owner_team, description }` |
| `agent.suspended` / `agent.unsuspended` / `agent.decommissioned` | `{ state_before, state_after, reason }` |
| `agent.envelope_narrowed` / `agent.envelope_widened` | `{ scope_envelope_before, scope_envelope_after, yellow_envelope_before, yellow_envelope_after }` (all four always present) |
| `agent.attestation_kinds_changed` | `{ attestation_kinds_before, attestation_kinds_after }` |
| `agent.owner_team_transferred` | `{ owner_team_before, owner_team_after }` |
| `agent.description_changed` | (no payload — chain row's `actor_sub` + `timestamp` is the proof; description content lives in identity's local table) |

`canonical_json` for both the outer hashable and the payload is the existing v1/v2 canonicalizer in `warden-ledger` (sorted keys, no whitespace, UTF-8 NFC). One canonicalizer, no per-version variants.

#### 7.3 Ground rules

- **`actor_sub` is always a real human.** No `system:`, no `tofu:*`. Migration-CLI runs publish `actor_sub = "system:migration:<operator_oidc_sub>"` — the operator who ran the migration is recorded; never anonymous.
- **The outer hashable is locked.** New event kinds add only payload schemas. New optional outer fields are forbidden; if it matters enough to put outside the payload, it warrants a v4 bump.
- **Adding event kinds is free.** Specifically, future spec follow-ons (capability-change request flow, transfer-pending, etc.) add new payloads only — no chain version bump.

### 8. Authentication for human callers

#### 8.1 Transport

All `/agents` endpoints take a raw OIDC `id_token` in `Authorization: Bearer`. Stateless server-side validation against the configured per-tenant JWKS. No Warden-issued session token (would double the revocation surface for no security gain). No reuse of `/grant` for human auth (would conflate the human/agent boundary the rest of the spec maintains).

#### 8.2 Capability resolution

Capabilities (`agents:create`, `agents:admin`, ...) are derived from the IdP `groups` claim via server-side mapping in `identity.toml`:

```toml
[capabilities.tenants.acme]
"warden-agent-creators" = ["agents:create"]
"warden-platform-admins" = ["agents:create", "agents:admin"]
```

This avoids requiring per-tenant IdP claim customisation (the #1 enterprise SaaS onboarding failure mode). The tenant administrator only has to tell their IdP team "add a group called `warden-agent-creators` and put your developers in it."

#### 8.3 Per-tenant IdP

Multi-tenant `warden-identity` reads `[oidc.tenants.<tid>] issuer = "..." jwks_url = "..."` per tenant. Per-call routing is by the `tenant` field in the request body. A request whose `tenant` doesn't match the OIDC token's issuer mapping returns `403 tenant_mismatch`.

### 9. The `wardenctl` CLI

New top-level binary built on top of `warden-sdk`. Two artifacts, one source of truth: SDK is the typed library (consumed by `warden-console` and integrators); CLI is a `[[bin]]` in a new crate that depends on SDK.

#### 9.1 Auth

OIDC device authorization flow (RFC 8628), the same pattern as `gcloud auth login`, `aws sso login`, `gh auth login`.

```
wardenctl auth login --tenant acme        # device-flow; cache id_token + refresh_token in ~/.warden/credentials.json
wardenctl auth logout
wardenctl auth whoami                      # echoes sub, idp, groups, capabilities
```

No long-lived API tokens. No operator SVID requirement (would be a circular bootstrap). The CLI re-uses the cached refresh token transparently; expired refresh sends the operator back through device flow.

#### 9.2 Commands

```
wardenctl agents create \
  --tenant acme --name support-bot-3 \
  --owner-team payments \
  --scope mcp:read:tickets --scope mcp:write:tickets \
  --yellow-scope refund:<=50usd \
  --attestation-kind tpm --attestation-kind sev-snp \
  --description "Triage bot for tier-1 tickets" \
  [--if-absent]                            # idempotent: 200 if record matches; 409 if differs

wardenctl agents list --tenant acme [--state Active|Suspended|Decommissioned] [--owner-team payments] [--json]
wardenctl agents get <id> [--json]
wardenctl agents suspend <id> --reason "investigating anomaly"
wardenctl agents unsuspend <id>
wardenctl agents decommission <id> --reason "team disbanded"
wardenctl agents envelope narrow <id> --scope mcp:read:tickets
wardenctl agents envelope widen  <id> --scope mcp:write:knowledge-base --yellow-scope refund:<=500usd
wardenctl agents transfer <id> --to-team newteam
wardenctl agents description <id> --text "..."

wardenctl agents migrate \
  --identity-db /var/lib/warden-identity/identity.sqlite \
  [--dry-run] [--default-owner-team unassigned] [--default-envelope '*'] [--default-attestation-kinds '*']
```

#### 9.3 Conventions

- `--json` on every read command; tests and shadow-scanner integration depend on machine-readable output.
- `--if-absent` on `create` for IaC-without-Terraform patterns: a CI job loops a YAML file and runs `wardenctl agents create --if-absent` per entry. Returns 200 if the existing record matches the requested envelope, 409 if it differs.
- Exit codes are deterministic and documented: `0` success, `2` validation error, `3` auth/capability error, `4` conflict, `5` server error.

### 10. Console (`warden-console`) extensions

The console gets the same OIDC auth dance as the CLI (auth-code flow + PKCE), holds tokens server-side, never exposes them to user-facing JS. Tenant context is inferred from the OIDC `tenant` claim or per-IdP `console.toml`. No tenant switcher in v1.

#### 10.1 New pages

| Path | Content |
|---|---|
| `/agents` | Tenant-scoped index. Columns: name, state badge, owner team, # scopes, # yellow scopes, last activity (joined from latest ledger row by `agent_name`). Filters: state, owner team, search. |
| `/agents/new` | Form: tenant (auto-filled), name, owner-team (dropdown of caller's groups), scope envelope (multi-input), yellow envelope (multi-input), attestation kinds (checkboxes from global allowlist), description. Submits to `POST /agents`. |
| `/agents/{id}` | Full record + lifecycle timeline (chain v3 rows for this agent, newest first). htmx action buttons gated on caller's capability. |

#### 10.2 Cross-page weaving

The audit story is invisible without it.

- **`/audit`** gains an "Agent" column. Linkable to `/agents/{id}` if registered; italic name otherwise. New "Filter by owner team" dropdown. `unregistered_agent`-signal rows get a one-click "Register…" link that prefills `/agents/new` with the observed `(tenant, agent_name)`.
- **`/hil/{id}`** gets an "Authorization context" panel above the request body: agent name (linked), owner team, registering human (`created_by_sub`), registration date, full envelope. The requested method/payload is visually flagged in-envelope or outside-envelope. The latter shouldn't happen post-`enforce` but in `warn` mode it can — surface it loudly so approvers see the gap.

#### 10.3 Verbs

The console has no "delete" verb. Decommission is terminal but the row stays. The word "delete" is operationally dangerous for an audit log and we don't need it.

### 11. Failure & fallback semantics

| Failure | Behaviour | Reasoning |
|---|---|---|
| `warden-identity` SQLite unavailable | Same as today: `/svid`, `/grant`, `/agents` all 503 | Single failure domain — identity is already a hard dep |
| Per-tenant JWKS endpoint unreachable | Cached JWKS used until expiry; after expiry, 503 with `jwks_unavailable` for that tenant only | Don't take down all tenants because one IdP is down |
| Caller's `id_token` expired | `401 invalid_token` | CLI re-runs device flow; console re-runs auth-code flow |
| Agent record missing in `enforce` | `403 unregistered_agent` on `/svid` and `/grant` | The point |
| Agent record missing in `warn` | 200 + signal on forensic event | The point |
| Envelope intersection fails | `403 scope_outside_envelope` regardless of mode | Registration opts you into enforcement |
| Suspend racing with in-flight `/sign` | `/sign` denylist consults the revocation broadcast (NATS); next call after suspend rejects | Hard suspend semantics from §3.2 |
| Migration CLI partial failure | Idempotent; rerun completes from where it stopped; chain rows for already-migrated agents are no-ops | One operator, one transactional intent |

### 12. Migration & rollout

Five slices, each independently shippable.

1. **Schema + reads.** `agents` table created; `GET /agents`, `GET /agents/{id}`, `wardenctl agents list/get` work. `POST /agents` and lifecycle endpoints not yet wired. Mode flag defaults `off`. *Exit:* schema migration ships to all environments; SDK `Client::list_agents` callable.
2. **Writes + lifecycle (no gating).** `POST /agents` and the lifecycle endpoints all work. Console `/agents`, `/agents/new`, `/agents/{id}` ship. `wardenctl agents create/suspend/...` ship. Mode still `off`. *Exit:* operators can enroll and manage records; nothing breaks because no gate consults them yet.
3. **Chain v3.** Ledger gains v3 dispatch. Every `POST /agents` and lifecycle endpoint emits a chain v3 row. Console `/agents/{id}` timeline ships. Verifier exposes per-row signature check across v1, v2, v3. *Exit:* `verify_chain` passes against a mixed v1/v2/v3 export; `wardenctl ledger verify` succeeds.
4. **Mode `warn`.** `/svid` and `/grant` consult the registry; unregistered names succeed with a signal stamped on the forensic event. Registered agents get envelope enforcement immediately. Console `/audit` highlights `unregistered_agent` rows with the "Register…" link. *Exit:* `warden-e2e` happy path passes with the simulator agents either pre-registered (via migration CLI) or running unregistered with signals; chaos-monkey scenarios assert correct mode behaviour.
5. **Mode `enforce`.** Default flips. Migration CLI is the official adoption tool — operators run `wardenctl agents migrate --default-envelope '*'` to bulk-enroll existing agents before flipping. `warden-e2e`, `warden-simulator`, `warden-chaos-monkey` boot scripts run the migration in their setup. *Exit:* `warden-e2e` happy path passes with `enforce` and zero unregistered names; chaos-monkey `unregistered_agent_enforce` scenario denies as expected.

The first set of slices unblocks the §11.3 audit-lineage story (chain row "Alice declared this agent"); the later slices close the namespace-squat and capability-sprawl threats (T1, T2). The early slices are decoupled from capability-attestation enforcement and other downstream work.

### 13. Test surface

#### 13.1 `warden-e2e`

A new bash runner `run-onboarding.sh` (or fold into `run.sh` if boot time tolerates). Boots `warden-identity` + a `dexidp/dex` mock IdP container + the migration target stack. Asserts:

1. **Bootstrap.** Mock IdP issues `id_token` for `admin@acme.com` (in group `warden-platform-admins`); `wardenctl auth login` succeeds; `wardenctl agents create` returns 200; agent record present in identity SQLite; `agent.registered` chain v3 row present in ledger with the registering human's `actor_sub` and the full envelope in payload.
2. **First SVID against registered agent.** Existing SVID issuance flow runs; assert no `unregistered_agent` signal in forensic event; resulting cert SAN matches the registered `(tenant, agent_name)`.
3. **Grant intersection.** `/grant` with scopes inside envelope succeeds; `/grant` with one in-envelope and one out-of-envelope scope returns `403 scope_outside_envelope` with the offender named.
4. **End-to-end Yellow-tier with envelope-context.** Pre-registered simulator agent drives a wire_transfer that hits HIL; HIL pending row carries the agent's envelope and registering human; chain has both `agent.registered` and the verdict row signed by the same key.
5. **Suspend revokes in flight.** Issue SVID, suspend the agent, verify next `/grant` returns `agent_suspended` and next `/sign` returns `agent_suspended` (revocation broadcast worked).
6. **Lifecycle chain replay.** Run register → suspend → unsuspend → narrow envelope → decommission; `wardenctl ledger verify` against the export; chain valid; six v3 rows in the right order; signatures valid against JWKS.
7. **Migration CLI.** Boot stack with `WARDEN_IDENTITY_REGISTRATION_MODE=warn`, drive simulator to populate svids table, run `wardenctl agents migrate --default-envelope '*'`, assert all simulator agents now have records with wildcard envelope and `actor_sub` includes the operator's OIDC subject.
8. **Mode flip.** Flip `enforce`, drive an unregistered agent, assert `403 unregistered_agent`.

The dex mock is configured with two static users:

- `admin@acme.com` with `groups: [warden-platform-admins]` (mapped to `agents:create + agents:admin`)
- `dev@acme.com` with `groups: [payments]` (no Warden capabilities — tests `403 missing_capability:agents:create`)

#### 13.2 `warden-chaos-monkey`

New scenarios. Each must produce a specific predicted verdict (the existing pattern):

| Scenario | Asserted verdict |
|---|---|
| `unregistered_agent_enforce` | `/svid` for `(acme, brand-new-bot)` with no record → `403 unregistered_agent` |
| `scope_outside_envelope` | `/grant` with one in- and one out-of-envelope scope → `403 scope_outside_envelope`, offender named |
| `suspended_agent_grant` | Register, suspend, `/grant` → `403 agent_suspended`; bonus: `/svid` → `403 agent_suspended` |
| `decommissioned_name_reuse` | Register, decommission, re-register same `(tenant, agent_name)` → `409 agent_name_retired` |
| `envelope_widen_unauthorized` | Caller without `agents:admin` on widen → `403 missing_capability:agents:admin`; same call with admin → 200 |
| `owner_team_spoof` | `POST /agents` with `owner_team` not in caller's `groups` → `403 owner_team_not_in_token` |
| `stale_oidc_token` | `id_token` past `exp` → `403 invalid_token` |
| `migration_replay` | Run migration twice; second run is no-op; no duplicate ledger rows; no schema violation |

Onboarding scenarios are pure-identity, no policy-tracker hits, so they run early in the chaos-monkey order — explicitly *before* the existing `velocity_breaker` scenario, which must run last because the policy tracker records every `/evaluate`.

#### 13.3 Out of test scope

- **Real IdP integration tests.** Real Okta/Entra tenants don't fit in CI; the dex mock is the contract. Real-IdP setup is a docs deliverable.
- **Cross-tenant federation of agent records.** Agent records are tenant-local. Cross-tenant federation deals only with SPIFFE bundles (per [Identity service](#identity-service) §3.3). No behaviour to test.
- **Latency regression.** Adding `/agents` lookups on the `/svid` and `/grant` hot paths is real overhead; chasing latency budgets in CI is noisy. Document the expectation ("registered-agent gating adds <1ms p99 to `/svid`") and verify manually before the `enforce` flip.

### 14. Wire-contract changes (cross-repo grep before renaming)

| Edge | Field added | Repos to grep |
|---|---|---|
| Console → Identity (read) | `GET /agents` response shape | `warden-console`, `warden-identity/src/agents.rs`, `warden-sdk` |
| Console → Identity (write) | `POST /agents` and lifecycle bodies | `warden-console`, `warden-identity/src/agents.rs`, `warden-sdk` |
| `wardenctl` → Identity | All `/agents` shapes | `warden-sdk`, `warden-ctl/src/cmd/agents.rs`, `warden-identity/src/agents.rs` |
| Identity → Ledger (NATS) | Chain v3 outer hashable + per-kind payloads | `warden-identity/src/agents_ledger.rs`, `warden-ledger/src/chain.rs` (v3 dispatch), `warden-ledger/src/verify.rs` |
| Identity → Proxy/HIL (existing rejection signals) | New error codes (`unregistered_agent`, `scope_outside_envelope`, `agent_suspended`, `agent_decommissioned`, `attestation_kind_not_accepted`) | `warden-proxy/src/grant.rs`, `warden-proxy/src/sign.rs` (signal aggregator), `warden-brain` (signal display), `warden-console/src/audit.rs` (filter chips) |

The shared types are duplicated on each side of the wire (no shared crate, per repo convention); land changes simultaneously.

### 15. What this spec deliberately does not include

- **Receiving-team consent on transfer.** v1 lets `agents:admin` dump an agent on an unwilling team. v2 should add `pending_transfer_to: <team>` + accept/reject by receiving team. Out of scope.
- **Capability-change request workflow.** The widen endpoint is the *terminal* action. A workflow on top — owner-team submits request, admin or HIL approves, widen fires — is a separate spec. The endpoint shape is designed to be the workflow's terminal call.
- **Bulk operations.** "Suspend all agents owned by team X" is a real incident-response need; v1 admins iterate. Defer until an operator explicitly asks.
- **Terraform provider.** The `--if-absent` CLI flag covers IaC-shaped use cases. A native Terraform provider is the natural follow-on once a customer asks.
- **Tenant lifecycle.** Tenants are implicit (declared by first use of the string). A `tenants` table implies billing boundaries, per-tenant IdP federation, and tenant decommissioning — much bigger spec.
- **WebAuthn approver auth on lifecycle transitions.** Today's auth is OIDC-only on `/agents`. Step-up auth for high-impact transitions (decommission, widen) is a separate WebAuthn workstream; this spec only ensures the transitions are signed in the chain. WebAuthn lands independently.
- **Per-agent attestation policy beyond `attestation_kinds_accepted`.** Per-method attestation requirements (capability attestation in [Identity service](#identity-service) §6) remain global. Per-agent rule overrides — "this specific agent's `wire_transfer` calls require measurement X" — wait for the global rule to settle before being layered on.
- **Agent groups / hierarchies.** No nested ownership, no parent-child agents, no inheritance. Each agent is a flat record. If 50 agents share an envelope, register 50 records (the CLI's `--if-absent` makes this scriptable).

---

## Console config page


Companion to the [Agent onboarding](#agent-onboarding-wao) section only in form. Where that section is a multi-service initiative with a chain version bump, a new CLI binary, and five rollout slices, this section is the opposite end of the scale: one read-only HTML page at `/config` in `warden-console` that answers "what is this binary, what is it talking to, and is everything reachable?" — the implicit question every operator currently answers with `ps`, `printenv`, and `curl` against four URLs.

**Module status:** shipped. Local to `warden-console`; one additive change to `warden-sdk` (three new public getters). No new service. No chain version change. No new endpoints on any backend. The only cross-repo dependency is bumping the `warden-sdk` version `warden-console` consumes.

### 1. What this closes

Today, an operator who SSH-tunnels into the console host and asks "is this thing wired up correctly?" has to:

1. `ps -ef | grep warden-console` — find the process.
2. `cat /proc/$PID/environ | tr '\0' '\n'` — see what URLs and flags it booted with.
3. `curl http://localhost:8083/health` — check the ledger.
4. Repeat (3) for HIL, identity, simulator.
5. Cross-reference the env against a runbook to know which knobs are even in scope.

The operational consequences:

| Gap | Today | After CONFIG |
|---|---|---|
| URL drift | "Is the console pointing at staging-ledger or prod-ledger?" needs shell access on the console host | One page renders the URL the SDK is actually pinging |
| Wiring health | Need to remember each backend's port and curl them by hand | Four parallel probes, color-coded latency badges, truncated error reason on failure |
| Optional service status | "Is the simulator wired up here?" requires the operator to know the env var name | Card explicitly shows "configured" / "not configured (set `WARDEN_CONSOLE_SIMULATOR_URL`)" |
| Token rotation verification | "Did this binary pick up the new operator token after the env was updated?" cannot be answered without shell | sha256[..8] fingerprint of the bearer; matching fingerprints across operators prove same token, mismatched fingerprints prove the rotation hasn't reached every box |
| Build provenance | `cargo install warden-console` produces a binary with no version readout in the UI | Page renders `v0.x.y (abc12345)` from `CARGO_PKG_VERSION` and a short git SHA captured at build time |
| Auth posture readability | `cookie_secure` and `session_ttl_secs` live in env vars; verifying them against the deploy doc requires shell | One card |

The page is a diagnostic, not a control plane. Mutation is explicitly out of scope (§11).

### 2. Threat model and posture

#### 2.1 Posture

The console's existing read-only surface (`/audit`, `/velocity`, `/stats/*`, `/hil` listing, `/exports`, `/agents`, `/sim`) is **open** — auth gates only the `/hil/{id}/{approve,deny,modify}` POSTs. The README documents the deploy posture: bind to `127.0.0.1`, expose via SSH tunnel or reverse proxy. `/config` matches this posture.

The justification is operational. An auth-gated config page is *worse* during incidents because it hides the very wiring an operator needs to debug auth itself. If WebAuthn is broken, the page that says "your RP id is wrong" must not require WebAuthn.

#### 2.2 Threats

| # | Threat | Mitigation |
|---|---|---|
| T1 | Operator pastes a `/config` screenshot into a public Slack channel; the screenshot leaks an OIDC bearer token | Token is never in handler scope; only `bearer_fingerprint() -> Option<String>` (sha256 hex prefix) is available to the template. The fingerprint is non-invertible and safe to print. |
| T2 | Operator pastes a `/config` screenshot; screenshot leaks the HIL session cookie of the rendering operator | Cookie value is held in `AuthState.store` keyed by an opaque UUID; the handler reads `SessionData.name` and never the cookie value. |
| T3 | Future contributor adds `{{ operator_token }}` to a template, exposing the raw token | The handler doesn't have access to the raw token (T1 mitigation makes the regression impossible at the type level). The redaction integration test (§7) is a second line of defense, asserting the rendered body never contains the configured token string. |
| T4 | Operator inadvertently deploys with `cookie_secure=false` in production | Page surfaces the flag prominently; mismatch with deploy posture is visible at a glance. |
| T5 | Pinned build runs against the wrong ledger or HIL because of an env-typo at deploy time | Page renders the *effective* URL (sourced from the SDK client itself, not a copy maintained alongside) and an immediate health badge. |

**Out of threat-model scope:** unauthenticated reverse-proxy bypass (deployment-layer concern, not console concern); active attacker on the operator's host (any defense the page could offer is moot once `/proc/$PID/environ` is readable).

#### 2.3 Redaction discipline

Redact-by-architecture, not redact-by-template. The handler must never receive any value that should not be rendered. Concretely:

- The OIDC operator token is held by `AgentsClient` as a private field; the public surface exposes only `bearer_fingerprint() -> Option<String>`. The handler asks for and stores only the fingerprint.
- The HIL session cookie is held by `AuthState.store` keyed by an opaque UUID; the handler reads `SessionData.name` and never the cookie value.
- WebAuthn registered-credential identifiers live in HIL's database. The console does not query them; the page does not render them.

Treat every render as if it will be screenshotted into Slack. The redaction guard test (§7.2) is the mechanical check.

### 3. Page structure

Cards (`rounded-xl bg-white ring-1 ring-slate-200 shadow-card p-5`), single-column stack, four sections in this order. Single-column matches the established density; multi-column would create "the right column got truncated" cases on narrow screens for no information gain.

#### 3.1 Console

| Field | Source |
|---|---|
| Bind | `ProcessConfig.bind` (set in `main.rs` from `--bind`) |
| Port | `ProcessConfig.port` (set in `main.rs` from `--port`) |
| Version | `ProcessConfig.version = env!("CARGO_PKG_VERSION")` |
| Git SHA | `ProcessConfig.git_sha = option_env!("WARDEN_CONSOLE_GIT_SHA")` |
| `decided_by` fallback | `AppState.decided_by` |

Rendered as `v0.x.y` or `v0.x.y (abc12345)` depending on whether the build script captured a SHA (§5.3).

#### 3.2 Backends (required)

Two rows, ledger and HIL. Each row: URL + health badge.

URL via `LedgerClient::base_url()` (already exists in `warden-sdk`) and `HilClient::base_url()` (added by this spec to `warden-console`). Health badge from §4.

#### 3.3 Backends (optional)

Two rows, identity and simulator. Each row probes if the client is `Some`; renders a `not configured (set WARDEN_CONSOLE_IDENTITY_URL / WARDEN_SIMULATOR_URL)` placeholder if `None`.

The identity row also surfaces:

- `agents_tenant` — the tenant scope baked in via `--agents-tenant`.
- Operator token — `configured (sha256: ab12cd34)` or `unset`, sourced from `AgentsClient::bearer_fingerprint()`. The presence boolean and the fingerprint are the same readout (`Some(_)` vs `None`); no additional method needed.

#### 3.4 Auth

| Field | Source |
|---|---|
| Session TTL | `AuthState.config.session_ttl_secs` |
| `cookie_secure` | `AuthState.config.cookie_secure` |
| Currently logged in | Server-side: `extract_cookie(headers, SESSION_COOKIE)` → `AuthState.store.get(uuid).await` → `SessionData.name` or `(not logged in — open posture)` |

The "currently logged in" line is server-rendered, **not** JS-driven via `/auth/me`. JS-filled slots come out empty in `curl`, `wget`, headless screenshot capture, and view-source; the page is a screenshot artifact and must be self-contained. The nav stays JS-driven (separate concern; would otherwise require threading a `nav_user` field through every template).

The Auth card does **not** surface the WebAuthn RP id — that's HIL's configuration, not the console's, and the console doesn't hold it. If `/config` ever needs to display backend configuration (per [Agent onboarding](#agent-onboarding-wao)-style federation), it goes through the §11 federated-config follow-on, not this card.

The card does **not** surface the active session count, the current session's `expires_at`, or the list of registered WebAuthn credentials. The first two are screenshot footguns (operational signal, hard to keep current with the lazy-expiry session map); the third lives in HIL's database and belongs on a separate "credentials" page if at all.

### 4. Probe contract

```
GET <base_url>/health         # ledger, HIL, simulator
GET <base_url>/healthz        # identity (only service that uses /healthz)
```

| Aspect | Value | Reasoning |
|---|---|---|
| HTTP client | Dedicated `reqwest::Client` shared across probes | Probes need aggressive timeouts; SDK clients are tuned for real RPCs |
| Connect timeout | 500ms | Mostly catches "service not bound to expected port" |
| Total timeout | 1500ms | Page worst-case render is bounded by the slowest single probe |
| Concurrency | All probes via `tokio::join!` in the handler | Sum-of-latencies render is too slow; max-of-latencies is acceptable |
| Auth | None | `/health` and `/healthz` are unauthenticated across the stack |
| Body | Ignored | Most services return plain text; identity returns JSON; lowest common denominator is the status code |

Classification:

| Status | Latency | Render |
|---|---|---|
| 2xx | <500ms | Green badge with `42ms` |
| 2xx | 500–1500ms | Amber badge with the latency reading |
| Non-2xx, timeout, transport error | — | Red badge with truncated reason (`"connect refused"`, `"timeout after 1500ms"`, `"500 Internal"`) |
| Client = `None` | — | Grey "not configured" badge |

Red without a reason is useless during an incident. Always surface the truncated transport-error string.

Module location: new `warden-console/src/probe.rs`. Single function:

```rust
// Probe a /health-shaped endpoint and classify the result.
//
// `http`  — dedicated probe client (short timeouts, no auth).
// `base`  — the backend's base URL (taken from the SDK client).
// `path`  — `"/health"` or `"/healthz"`.
pub async fn probe(http: &Client, base: &Url, path: &str) -> Probe { ... }
```

Handler invokes it four times under one `tokio::join!`. Probe construction is `client.base_url().join(path).expect("static path")` — the SDK clients validate base URLs at startup, so the `expect` is unreachable for any base URL that successfully constructed a client.

### 5. Plumbing & wire surface

#### 5.1 Route

```
GET /config        # render the page; no other methods
```

No `POST`. No JSON-API counterpart. The page is server-rendered askama HTML, same shape as every other console page. Nav link added to `templates/base.html` after "Simulator", before the right-aligned subtitle/auth span.

#### 5.2 New SDK methods (additive, no behavior change)

| Crate | Method | Returns | Rationale |
|---|---|---|---|
| `warden-sdk::SimClient` | `pub fn base_url(&self) -> &Url` | The configured simulator URL | Page renders the URL the client is actually using |
| `warden-sdk::AgentsClient` | `pub fn has_bearer(&self) -> bool` | Whether `with_bearer` was called | Convenience; `bearer_fingerprint().is_some()` is equivalent |
| `warden-sdk::AgentsClient` | `pub fn bearer_fingerprint(&self) -> Option<String>` | sha256 hex prefix (first 8 chars) of the configured token | Diagnostic readout without exposing the token |

`LedgerClient::base_url()` already exists in `warden-sdk`; no change needed.

#### 5.3 New console-local additions

| File | Change |
|---|---|
| `warden-console/src/hil_client.rs` | Add `pub fn base_url(&self) -> &Url` (parity with the SDK clients) |
| `warden-console/build.rs` | New file. Shells out `git rev-parse --short=8 HEAD`; emits `cargo:rustc-env=WARDEN_CONSOLE_GIT_SHA=<sha>` on success, silent on failure. `cargo:rerun-if-changed=.git/HEAD` and `cargo:rerun-if-changed=.git/refs/heads`. |
| `warden-console/src/state.rs` | New struct `ProcessConfig { bind: String, port: u16, version: &'static str, git_sha: Option<&'static str> }`. New field `pub process: ProcessConfig` on `AppState`. |
| `warden-console/src/main.rs` | Build `ProcessConfig` from `Cli` before `AppState` construction. |
| `warden-console/src/probe.rs` | New module. See §4. |
| `warden-console/src/handlers.rs` | New `pub async fn config(...)` handler. Reads `AppState`, runs the four probes under `tokio::join!`, renders the template. |
| `warden-console/src/lib.rs` | Wire the route: `.route("/config", get(handlers::config))`. |
| `warden-console/templates/config.html` | New askama template. Four cards as in §3. |
| `warden-console/templates/base.html` | Add the nav link. |

The build script is allowed to fail silently. A release tarball without a `.git/` directory, or a build environment without `git` on PATH, must produce a working binary; `option_env!` returns `None` and the template renders the version without a SHA. **Build must not depend on git availability.**

### 6. Failure & fallback semantics

| Failure | Behaviour |
|---|---|
| Backend unreachable (connect refused) | Red badge with `"connect refused: ..."` reason; rest of the page renders |
| Backend slow (>1500ms) | Red badge with `"timeout after 1500ms"`; rest of the page renders |
| Backend returns 500 | Red badge with `"500 Internal Server Error"`; rest of the page renders |
| `WARDEN_CONSOLE_IDENTITY_URL` / `_SIMULATOR_URL` unset | Optional client is `None`; row renders "not configured" placeholder; no probe traffic to that URL |
| Operator token unset | Identity row renders `unset` for the token field; identity probe still runs |
| Build script unable to capture SHA | `option_env!` returns `None`; template renders `v0.x.y` without SHA |
| Operator hits `/config` while not logged in | Page renders; Auth card shows `(not logged in — open posture)` |
| `AuthState.store` lookup races with session expiry | `get` returns `None`; rendered as not-logged-in |
| Probe URL fails to construct (malformed base) | Should be unreachable — `LedgerClient::new` etc. validate base URLs at startup. If it happens anyway, render red with `"url construction failed"`. |

The handler does **not** 5xx on backend failure. A failed probe is a rendered red badge, not a server error — the entire purpose of the page is to display failure modes.

### 7. Test surface

#### 7.1 Unit tests

In `warden-console/src/probe.rs`:

- Probe classification — given `(status_code, latency)`, expect Green/Amber/Red. Doesn't open a socket; classification is a pure function.

In `warden-sdk/src/agents.rs`:

- `bearer_fingerprint` — same input always yields the same 8 hex chars; different inputs yield different 8 hex chars; absent bearer returns `None`.

#### 7.2 Integration tests

In `warden-console/tests/integration.rs`, reusing the existing `spawn_ledger`, `spawn_hil`, `spawn_sim` helpers:

| Test | Asserts |
|---|---|
| `config_renders_all_cards_when_all_backends_healthy` | All four cards render; all four URLs visible in body; all four probes green |
| `config_renders_optional_placeholders_when_clients_absent` | Identity URL and simulator URL absent → "not configured" placeholders; no probe traffic to those URLs |
| `config_renders_red_badge_when_backend_unreachable` | HIL stub closed (or 500s) → HIL row red with truncated error reason; ledger row still green; page still renders |
| `config_renders_logged_in_operator_when_session_present` | Pre-seed `AuthState.store`, set `warden_console_session` cookie on request → body contains operator name |
| `config_renders_not_logged_in_when_no_session` | No cookie → body contains "(not logged in — open posture)" |
| `config_redacts_operator_token` | **Load-bearing.** With `WARDEN_CONSOLE_OPERATOR_TOKEN=secret-jwt-blob.foo.bar` and a logged-in operator, body does NOT contain the raw token, does NOT contain the HIL session cookie value, DOES contain the 8-char fingerprint |
| `config_renders_mixed_health_classifications` | Green + amber + red coexist on one render |

The redaction test cannot be skipped. It's the only mechanical guard against a future contributor adding `{{ operator_token }}` to a template.

#### 7.3 Out of test scope

- Tailwind class / DOM structure assertions (brittle, low value).
- Exact latency-ms numbers (timing-flaky on CI).
- Concurrency tests on `tokio::join!` (stdlib semantics, no novel logic).
- `tests/common/mod.rs` extraction (refactor without payoff yet; defer until a third test file needs the helpers).
- `warden-e2e` coverage. The config page does not touch the security pipeline; integration tests in `warden-console` are authoritative.

### 8. Migration & rollout

Two PRs, sequential. No flag, no phased rollout — the page is purely additive and ships in one minor version.

1. **PR #1 — `warden-sdk`.** Add `SimClient::base_url`, `AgentsClient::has_bearer`, `AgentsClient::bearer_fingerprint`. Pure additions, no behavior change. Lands first so PR #2 can bump the SDK dep version.
2. **PR #2 — `warden-console`.** Bump SDK dep, add `HilClient::base_url`, `build.rs`, `ProcessConfig`, `probe.rs`, `/config` route + handler, `templates/config.html`, nav link, tests. One commit, or split plumbing/page/tests within the PR if review prefers smaller diffs; no separate intermediate-broken commit.

There is no `wardenctl` change. There is no chain version bump. There is no policy-engine change. There is no new endpoint on any backend.

### 9. Wire-contract changes (cross-repo grep before renaming)

| Edge | Field added | Repos to grep |
|---|---|---|
| SDK consumers | `SimClient::base_url`, `AgentsClient::has_bearer`, `AgentsClient::bearer_fingerprint` | `warden-sdk`, `warden-console`, `warden-ctl` (future), any external integrators |

No other edges. The page consumes existing `/health` and `/healthz` endpoints unchanged; no backend wire shape shifts.

### 10. Operator preferences (future v2)

Recorded so v1 doesn't paint into a corner. **Not** in this spec's scope.

The natural follow-on is a small set of UI knobs on `/config`:

- Default tenant for `/agents` (currently the `--agents-tenant` CLI flag at process scope).
- "Hide simulator traffic" default for `/audit` (currently a query-string opt-in).
- Default page size for paginated tables (currently hardcoded).

Likely persistence: **localStorage**, not cookie or server-side session map. Reasons:

- The read-only surface is open; cookie-based prefs would force every operator into the console's session machinery.
- Server-side prefs would create per-operator state (a multi-instance console deploy loses prefs on routing).
- localStorage keeps `/config` v2 entirely client-side; no handler change.

The v1 page does not include a "(future) Operator preferences" placeholder card. Aspirational empty cards are clutter.

### 11. What this spec deliberately does not include

- **Mutation surface.** The page is GET-only. Live config edits — adjusting velocity thresholds, HIL TTLs, brain confidence — would require new write endpoints on each backend, audit-trail entries in the chain, and WebAuthn gating. Out of scope; lives in a separate spec if it ever materializes.
- **Federated config view.** Showing every backend's effective config (proxy mTLS chain, policy velocity backend, ledger export sinks, brain model id) implies adding `/config` endpoints across the stack. Not done.
- **Backend versions and SHAs.** Identity exposes `version` on `/healthz`; the others return plain text. Surfacing a per-backend version row requires extending each `/health` to return JSON with a stable shape — a multi-repo change with no current ask. The v1 page renders only the *console's* own version.
- **Active console session count.** Surfacing the count of in-memory `AuthState` sessions is a screenshot footgun (operational signal exposing concurrent operators) and impossible to keep current with the lazy-expiry model.
- **Registered WebAuthn credential listing.** Lives in HIL's database; needs a new HIL endpoint we don't have; belongs on a separate "credentials" page if at all.
- **Build dirty marker.** Adds a second `git status --porcelain` invocation per build for marginal value; the SHA tells you the commit, and the dev case is the only one that benefits.
- **Build timestamp.** Poisons reproducible builds. The release tag is the timestamp that matters.
- **Policy bundle browse/edit.** Different feature, different route, different auth model.
- **Tenant switcher.** Per [Identity service](#identity-service) §10 and [Agent onboarding](#agent-onboarding-wao) §10, console v1 is one-tenant-per-process. The config page reflects whatever the process booted with.
- **Auth gating on `/config`.** §2.1 explains why; making the diagnostic page require working auth is exactly backwards.
- **An "Operator preferences" v1 placeholder card.** §10 explains why.

---

## Operator authentication


Console + HIL human-auth surface — what an operator presents to the console, how the console proves an approver to HIL, and how Slack / Teams approvers anchor cross-channel clicks to a stable operator identity. Companion to "Console config page" (the read-only `/config` diagnostic) and the HIL section of `README.md`.

**Module status:** **shipped.** WebAuthn approver auth, OIDC, basic-admin, RBAC, Slack / Teams self-link, and viewer-route gating are all in. Touches `warden-hil` (passkey credentials, session cookie, `Authn::*` server-side stamping) and `warden-console` (auth-mode selector, ceremony proxy, `/me/identities`, viewer / approver gates).

### 1. What this closes

Originally, WebAuthn was the only auth path. That was a dealbreaker for buyers with existing OIDC SSO and there was no solo-evaluation mode. Cross-channel approvers (Slack / Teams) had no way to anchor their clicks to a stable operator identity, so chain rows could carry inconsistent `decided_by` values across channels. Read routes had no viewer-or-better gate, so a misconfigured deploy could leak audit data to anyone who hit the URL.

### 2. Auth modes

Four modes selected via `WARDEN_CONSOLE_AUTH={disabled|basic-admin|webauthn|oidc}`:

| Mode | Use case | Bind constraint |
|---|---|---|
| `disabled` | dev / CI; mirrors `WARDEN_HIL_AUTH_DISABLED=true` under a console-side switch | loopback only (`--bind 127.0.0.1`) |
| `basic-admin` | solo evaluation; single hardcoded user from `WARDEN_CONSOLE_ADMIN_USER` + `WARDEN_CONSOLE_ADMIN_PASS_BCRYPT` | refuses non-loopback bind unless `WARDEN_CONSOLE_ALLOW_BASIC_ADMIN_NETWORK=true` |
| `webauthn` | self-hosted small-team default; HIL holds passkey credentials, console proxies the ceremony | none |
| `oidc` | production with existing SSO; generic OIDC code flow against any compliant IdP | none |

Mode selection is a runtime knob, not a build-time choice — operators flip modes without rebuilding.

### 3. RBAC

Two static roles, mapped via OIDC `groups` claim, config-as-code only:

- `viewer` — read-only access to audit / chain / agent registry / config / exports / velocity / stats / HIL queue / sim / live tail.
- `approver` — viewer + ability to decide HIL pending items.

Group mapping lives in console config:

```yaml
auth:
  oidc:
    approver_groups: ["security-team", "finance-ops"]
    viewer_groups: ["engineering", "compliance"]
```

No user table. No admin role (admin surface = `wardenctl` + direct identity API). No runtime role exceptions. The IdP is the source of truth.

The viewer-route gates (`require_viewer` / `require_viewer_api`) sit in front of every console read route; no-session HTML page requests get a `303 → /login`, no-session SSE / JSON requests get `401`. `disabled` mode short-circuits both gates with a synthetic Approver session for dev / CI. The HIL-queue template carries a `can_approve` flag so OIDC viewers see the queue contents but no Approve / Deny / Modify buttons.

### 4. Cross-channel identity

Slack and Teams approvers self-link via a `/me/identities` page in the console using Slack / Teams OAuth. Console persists the link in a small `user_identities` table:

```sql
CREATE TABLE user_identities (
  oidc_sub      TEXT PRIMARY KEY,
  slack_user_id TEXT UNIQUE,
  teams_user_id TEXT UNIQUE,
  linked_at     TIMESTAMP NOT NULL,
  last_verified TIMESTAMP NOT NULL
);
```

A Slack / Teams approve click looks up `user_id → oidc_sub` via this table. **If no mapping exists, the click is rejected** with "your Slack identity is not linked — link via the console first." This forces every chain row to consistently stamp the same identity (`oidc:<sub>`) regardless of which channel the approval came from.

**Schema caveat:** the table sketches a key on `oidc_sub`, but `webauthn` and `basic-admin` modes don't produce OIDC subs. Implementation chose nullable per-mode columns (`oidc_sub` / `webauthn_name` / `basic_username`) with a CHECK constraint that exactly one is set. Reversible — the PK choice doesn't bind the wire format.

Buyers create their own Slack / Teams app from a manifest published in `warden-console/docs/` (`slack-app-manifest.json` / `teams-app-manifest.md`) — no marketplace presence.

### 5. Chain `decided_by` schema

The literal `"warden-console"` value has been replaced — HIL now stamps `decided_by` server-side from the verified principal:

- `webauthn:{name}` — WebAuthn mode.
- `oidc:<sub>` — OIDC mode; also stamped on Slack / Teams clicks after self-link (the OAuth-linked `oidc_sub` flows through, not the underlying channel id).
- `basic:<username>` — basic-admin mode (auditor reads this and immediately knows the deployment was running in basic-admin mode).

The chain row also carries an `approver_assertion` JSON blob — extension hook for stronger per-decision claims:

- WebAuthn: `{ "method": "webauthn", "credential_id": "...", "iat": ... }`
- OIDC: `{ "method": "oidc-session", "sub": "...", "iat": ... }`
- Basic: `{ "method": "basic-admin", "username": "..." }` (intentionally cheap — no chain-of-trust to assert)

Existing WebAuthn rows in the chain don't get the field retroactively; only rows produced after the field landed carry it. No chain-version bump required; the field is additive.

### 6. Console → HIL trust

The trust path is **mode-dependent** because WebAuthn already has a stronger primitive and we don't tear it out:

- **WebAuthn mode (today, unchanged):** HIL is the credential authority. The console proxies WebAuthn ceremonies and shuttles HIL's session cookie back to the browser; subsequent `/decide` calls attach the HIL cookie and HIL stamps `decided_by` from the verified principal.
- **OIDC / basic-admin / disabled:** HIL has no credential to verify, so console and HIL share a bearer secret (`WARDEN_HIL_DECIDE_TOKEN`). Console verifies OIDC (or basic-admin), stamps `decided_by`, and presents the bearer on `/decide`. HIL trusts the request-body `decided_by` *only when* a valid bearer is present; without the bearer, the existing `Authn::Disabled` fallback applies. **Both processes refuse to boot if the configured mode requires the token and it is missing.**

The bearer is the interim posture for the non-WebAuthn modes; internal s2s mTLS via warden-identity SVIDs (deferred service-mesh work, see "Threat model — Open items") will replace it uniformly across all modes including WebAuthn.

### 7. Mechanical defaults

- OIDC token validation: JWKS, 1-hour cache TTL, reactive refresh on signature failure.
- Session: server-side encrypted cookie via `tower-sessions`, 8-hour rolling lifetime.
- Logout: clears server session, optionally calls IdP `end_session_endpoint`.
- CSRF: htmx + origin-check + per-session token; no separate state cookie.
- IdPs tested in CI: Keycloak (dockerizable). Quickstart docs only for Google / Okta / Azure AD / Auth0 — no CI fixtures (their public test infra is unreliable).

### 8. Future extensions

Triggers, not commitments — listed so a future contributor knows the hooks are deliberate, not accidental:

- **Per-decision WebAuthn step-up over OIDC sessions** — first design-partner from FinTech (PSD2 SCA), defense (FIPS / DoD impact level), or healthcare (HIPAA technical safeguards). The WebAuthn primitives already exist; v2 wires them as a step-up gating individual `/decide` calls on top of OIDC sessions, rather than a parallel auth mode.
- **Runtime role-management UI** — first buyer who demands non-GitOps role exceptions. Until then, config-as-code is sufficient.
- **Admin role + agent-registry UI in console** — first user who explicitly wants agent CRUD outside `wardenctl`. Until then, `wardenctl` + direct identity API are sufficient.
- **Four-eyes / separation-of-duties** — first buyer demanding per-human approval limits or "two distinct approvers required." This also triggers an upgrade from self-link to a more rigorous identity unification scheme.

---

## Regulatory export


EU AI Act Article 11 / 12 audit-bundle export from the existing hash chain. Operator-fetched, operator-stored, signed, time-window scoped. Companion to the cold-tier `/export` (Iceberg + Parquet analytics snapshots) but with a different audience: external regulators, not internal analysts.

**Module status:** **shipped (slices 1 + 2 + 3).** Lives in `warden-ledger` + `warden-identity` (new `POST /sign/blob`) + `warden-sdk` + `wardenctl`. No chain-version change.

### 1. What this closes

The existing `/export` produces Parquet for analytics; no auditor expects to reach for Parquet tooling. The Regulatory export gives auditors NDJSON + a verifiable manifest + a detached ed25519 signature in a tarball they can untar with `tar` and verify with `openssl` and `sha256sum`. The bundle is independently verifiable without a Warden binary in scope.

### 2. Articles in scope

- **EU AI Act Article 11** (technical documentation) and **Article 12** (automatic logging records) only.
- **Articles 14-15** (human oversight, accuracy) need operator-supplied prose; slice 3 covers prose embedding but doesn't auto-derive the content.
- **GDPR Article 30** has a different surface (data categories, recipients) and isn't auto-derivable from forensic events; deferred until a buyer asks.

### 3. Bundle format

`.tar.gz` containing:

```
manifest.json                 — schema v3, signed
manifest.sig                  — detached ed25519 sig (128 hex chars + LF)
entries.ndjson                — one LedgerEntry per line, seq ASC
technical_documentation.md    — operator-supplied prose (optional)
README.txt                    — auditor verification checklist (7 steps)
```

NDJSON over Parquet because the audience reaches for Python / Excel / `jq` more readily than Parquet tooling. Detached signature rather than embedded — keeps the `manifest.json` byte-stable across signing implementations. Half-open window `[from, to)`. Empty windows return a valid bundle with `row_count: 0` (auditors expect a verifiable artifact even for "we logged nothing"). Operator stores; Warden does not retain bundles server-side.

### 4. Wire surface

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | `/export/regulatory?from=…&to=…[&include_exports=true]` (warden-ledger) | optional `text/markdown` (≤ 1 MiB) | `application/gzip` (`.tar.gz`) |
| POST | `/sign/blob` (warden-identity) | `{ digest_hex, audience }` | `{ signature, key_id, algorithm: "ed25519", digest_alg: "sha256", signed_at }` |

`POST /export/regulatory` is the auditor-facing export. `POST /sign/blob` is the new signing primitive on warden-identity (sibling to `/sign`, same caller-allowlist gate, audience-tagged forensic event), wired via `WARDEN_IDENTITY_URL` + `WARDEN_LEDGER_SPIFFE` and routed through `warden-ledger::identity_client::ManifestSigner` / `HttpManifestSigner`.

### 5. Manifest schema (v3)

```jsonc
{
  "schema_version": "3",
  "generated_at": "<RFC 3339 UTC>",
  "window": { "from": "...", "to": "..." },
  "row_count": 1234,
  "seq_lo": 5000,
  "seq_hi": 6233,
  "chain_state": {
    "prev_hash_at_window_start": "...",
    "entry_hash_at_window_end": "..."
  },
  "ndjson_sha256": "...",
  "article_scope": ["EU-AI-Act-Article-11", "EU-AI-Act-Article-12"],
  "signature": {
    "sidecar": "manifest.sig",
    "algorithm": "ed25519",
    "digest_alg": "sha256",
    "key_id": "...",
    "signed_at": "..."
  },
  "technical_documentation": {     // optional, slice 3
    "filename": "technical_documentation.md",
    "sha256": "...",
    "byte_size": 2048
  },
  "parquet_pointers": [             // optional, with ?include_exports=true
    {
      "snapshot_id": "...",
      "written_at": "...",
      "data_uri": "...",
      "manifest_uri": "...",
      "data_sha256": "...",
      "byte_size": 1234567,
      "row_count": 50000,
      "seq_lo": 4000,
      "seq_hi": 6500
    }
  ]
}
```

The signature commits to `sha256(canonical_manifest_with_signature_blanked_to_null)` so `technical_documentation` and `parquet_pointers` are signed transitively — tampering with the prose breaks both signature verification and a cheap recompute. v1 was the unsigned shape (slice 1); v2 added the `signature` envelope (slice 2); v3 added the optional `technical_documentation` and `parquet_pointers` blocks (slice 3). v3 with neither optional field populated is byte-identical to v2 aside from `schema_version`.

### 6. Auditor verification recipe

The README.txt embedded in the bundle spells out a 7-step recipe:

1. Untar the bundle.
2. Verify `entries.ndjson` byte-hash matches `manifest.json`'s `ndjson_sha256`.
3. Verify chain continuity from `chain_state.prev_hash_at_window_start` through every NDJSON row to `chain_state.entry_hash_at_window_end`.
4. (Optional) Verify `technical_documentation.md` byte-hash matches `manifest.technical_documentation.sha256`.
5. Blank `manifest.signature` → `null`, re-serialize pretty-printed JSON, sha256.
6. `ed25519_verify` the digest from step 5 against `manifest.sig` using the operator-published public key (`key_id` in `manifest.signature`).
7. (Optional) For each entry in `manifest.parquet_pointers`, fetch `data_uri`, sha256, compare to `data_sha256`.

Steps 1-3 are the chain-integrity check; steps 5-6 are the signature check; steps 4 and 7 cover the optional artifacts. Steps 2 + 3 alone establish the chain row data is authentic; step 6 adds non-repudiation against the signing key.

### 7. Operator-supplied prose

`POST /export/regulatory` accepts an optional `text/markdown` (or any `text/*`) request body up to 1 MiB, embedded verbatim as `technical_documentation.md`. The manifest's `technical_documentation` sub-object commits to `{ filename, sha256, byte_size }`; the signature commits transitively. 1 MiB is the hard cap (`413 payload_too_large` on overrun); operators with longer documentation typically reference it as a URL inside the markdown rather than embed.

### 8. Parquet pointers

`?include_exports=true` triggers a seq-overlap scan against the `exports` table; pointers for cold-tier snapshots whose seq range overlaps the window land in `manifest.parquet_pointers`. The auditor can independently fetch the snapshots to cross-check analytical aggregates against the chain rows.

### 9. CLI

```
wardenctl regulatory export \
  --from <RFC3339> --to <RFC3339> \
  [--readme <PATH>] [--include-exports] \
  [--ledger-url <URL>] \
  --output bundle.tar.gz
```

Lives under a new top-level `regulatory` verb (own surface — distinct from `agents`; no identity gate today since the ledger doesn't gate `/export/regulatory`). The CLI is a thin pass-through to `LedgerClient::regulatory_export(window, RegulatoryExportOptions { readme, include_exports })` on `warden-sdk`.

### 10. Failure & fallback semantics

- **Identity unreachable** → `503 signing_unavailable`. Fail-closed: the ledger never emits an unsigned bundle. Operator runbook is "Identity service unreachable" in the [Runbooks](#runbooks) section.
- **Empty window** → `200 OK` with a valid bundle, `row_count: 0`.
- **Body too large** → `413 payload_too_large`.
- **Body content-type not `text/*`** → ignored as readme; the bundle is produced without `technical_documentation.md`.

---

## Demo experience


Companion to none of the existing sections in form. Where [Console config page](#console-config-page) is one read-only page and [Agent onboarding](#agent-onboarding-wao) is a multi-service initiative with a chain version bump, this section sits between: a public demo surface that spans the marketing site, a Cloudflare Worker, the existing operator console, and three backend services, but introduces no new long-running service and no chain version change.

**Module status:** new, marketing/funnel work. Extends `warden-website` (guided tour), `warden-console` (demo-mode), `warden-ledger` + `warden-hil` (token-scoped read filters and HIL approve enforcement), `warden-chaos-monkey` (extracted into a `warden-chaos-catalog` library + thin CLI wrapper). Adds one new artifact: a Cloudflare Worker for token mint. No new container in `docker-compose.yml`. No new chain version.

Design decided by a `/grill-me` walkthrough. Thirteen architectural decisions resolved in sequence; four confirmations on operational tradeoffs. This doc is the consolidated record so the implementation work can begin from a stable baseline.

### 1. What this closes

The marketing site today (`repos/warden-website/`) is a three-file static page with a client-side mock of an "attack scenario" button. The mock animates fake responses; nothing real happens. A technical evaluator (SRE / platform / security eng) clicking through has no way to see the actual chain, the actual HIL flow, or the actual layered defense — and "Book a demo" is the only path forward, which gates every evaluator behind a sales call.

The operational consequences:

| Gap | Today | After DEMO |
|---|---|---|
| Evaluator funnel | Every evaluator must book a sales call to see real verdicts | Self-serve: tour → real-console handoff with their own scoped session |
| Cryptographic-realness proof | Marketing copy claims "hash-chained ledger" — nothing to inspect | Visitor's actions land in the live chain; verifiable with `curl /verify` |
| HIL story | Yellow-tier flow only described in prose | Visitor approves their own pending wire transfer in real `/hil` |
| CISO funnel | Same dense marketing page as evaluator | Auto-play mode of the same tour serves CISO at no extra cost |
| Catalog reuse | Chaos-monkey scenarios live as a CLI binary, can't be invoked from anywhere else | `warden-chaos-catalog` library powers chaos-monkey CI, the demo, and (future) self-hosted "test your policy" feature |

The demo is *not* a sales-replacement and *not* a free trial. It's a self-serve proof-of-realness for the evaluator audience that already knows roughly what Warden does and wants to convince themselves the implementation is honest.

### 2. Audience and success metrics

**Primary audience: technical evaluator** (SRE, platform engineer, security engineer). Goal: kick the tires; see the architecture work; leave with enough conviction to schedule a deeper call. Auto-play mode of the same tour serves the **secondary audience** (CISO / non-technical buyer) for free — they watch, they bounce or click "Book a demo," they don't touch the backend.

**Funnel events** instrumented via Plausible (no cookie banner; GDPR-clean):

- `tour_started` — first scenario animation begins.
- `tour_completed` — all three scenarios finished (or click-through reached the handoff CTA).
- `handoff_clicked` — visitor clicks "open in console."

**Week-2 decision point** (set explicitly now, before bias accumulates):

- `handoff_clicked / tour_completed > 15%`: build full console handoff (weeks 3–6).
- `< 5%`: stop after week 2; ship receipts-page-only.
- `5–15%`: build week 3 only (basic console handoff), re-evaluate.
- Threshold needs ≥200 tour-completers to be meaningful; extend the timeline rather than lower the bar.

**Slow-burn metric**: `/demo` visit → `/contact` submission within 7 days, tracked across the whole project. If after week 6 this isn't lifting, the demo is decoration.

**Qualitative**: five named design-partner walkthroughs in week 4 (after console handoff is live). Watching, silent, "would you recommend this internally?"

### 3. UX surface

#### 3.1 Guided tour

Three-scenario tour on `vanteguardlabs.com/demo`:

| Order | Scenario | Length (auto-play) | Layer focus |
|---|---|---|---|
| 1 | Indirect injection blocked | 10–15s | Brain |
| 2 | Yellow-tier wire transfer + HIL approve | 45–60s | Brain + Policy + HIL + Ledger (the centerpiece) |
| 3 | Velocity breaker *or* stolen-SVID replay | 15–20s | Policy *or* Identity |

Total auto-play: ~90s. Click-through mode stretches to ~3 min with explanation panels expanded.

**Auto-play is the default** (CISO-friendly). A "step through with explanations" toggle in the corner gives evaluators a click-through path; same animation frames, denser annotation. The centerpiece scenario (wire transfer) is non-negotiable — it's the single most photogenic Warden moment, the only one that shows *control plane* rather than *filter*.

The tour is **fully client-side** (animations + pre-canned responses). No backend hit until the handoff CTA. This is the lazy-session decision: most marketing-site traffic should never touch the VPS.

#### 3.2 Console handoff

CTA at end of tour: "Open this in the real console." Click → Cloudflare Worker mints a 30-min HS256 JWT with a unique `correlation_prefix` and `agent_id` claim → handoff URL `https://console-demo.vanteguardlabs.com/audit#token=…&prefix=demo-7f3a-`.

Console reads the URL fragment on first hit, swaps it for an HTTP-only `SameSite=Strict` cookie, redirects to the clean URL. Standard fragment-auth pattern; the token never appears in server logs.

#### 3.3 In-console action surface

Visitor lands on `/audit`, scoped by token to:

- Their own `correlation_id LIKE 'demo-7f3a-%'` rows.
- *Plus* `source = 'simulator'` rows from the always-on simulator (ambient feel; visitor's actions accent-highlighted).

A new `/demo/fire` page renders the chaos-catalog scenarios as tiles. Click → demo console's backend handler validates the session token, calls `warden_chaos_catalog::fire(scenario_id, agent_id, correlation_prefix, proxy_url)`, redirects to `/audit?correlation_id=…&highlight=…` with the new rows scrolled into view.

HIL approve/deny works on the visitor's own pendings (per-prefix filter enforces). Auto-decision sidecar configured to skip `demo-` prefixes so visitors aren't raced.

### 4. Backend topology

```
Cloudflare (CDN + WAF + Workers + Turnstile)
    │
    ├──► vanteguardlabs.com           — CF Pages (3 static files, tour animation)
    │
    ├──► api.vanteguardlabs.com       — CF Worker (Turnstile validation + JWT mint)
    │       only. mint endpoint never reaches origin.
    │
    └──► console-demo.vanteguardlabs.com — Hetzner-class VPS, single region
            └── docker-compose --profile stack up -d
                ├── nats, vault, bootstrap
                ├── ledger, policy-engine, brain, hil, identity, proxy, console
                ├── upstream-stub, simulator (always running, ambient traffic)
                └── website
```

VPS firewall: accept only Cloudflare IP ranges. The mint endpoint is at the edge — there is no anonymous-traffic-touching surface on the VPS.

Marketing site and demo backend deliberately split: CDN for marketing latency, single-region VPS for demo backend. Subdomain isolation contains abuse blast radius.

### 5. Security model

#### 5.1 Token mint

CF Worker holds:

- `TURNSTILE_SECRET` — Cloudflare Turnstile siteverify secret.
- `DEMO_JWT_HS256` — HS256 signing key, shared with `warden-ledger` and `warden-hil` for validation. Rotated quarterly.

Worker shape:

```
POST /mint
  body: { "turnstile_token": "..." }
  →
  1. siteverify Turnstile (reject on fail)
  2. KV-counter increment for client IP, reject if >5/hour
  3. correlation_prefix = "demo-" + random4 + "-"
  4. agent_id = "demo-" + random4 + "-bot"
  5. JWT { sub, prefix: correlation_prefix, agent_id, exp: now+30min }
  6. return { token, correlation_prefix, expires_at }
```

The mint event is itself logged to the ledger as `event_kind: demo.session_minted` — every demo action including session creation is on the chain.

#### 5.2 Scope enforcement

**Defense-in-depth**: console proxy filters for performance, backends enforce for security.

- A small token-validator (shared crate or duplicated 50-line module) parses the JWT, verifies HS256 signature, returns `{ correlation_prefix, agent_id }` or rejects.
- `warden-ledger` read endpoints (`/audit`, `/audit/correlation/{id}`, `/stream/audit`) accept an optional `?demo_session_token=…`; when valid, filter to `correlation_id LIKE prefix || '%' OR source = 'simulator'`.
- `warden-hil` read endpoints filter the same way; **write endpoints reject if target pending's `correlation_id` doesn't match the prefix** — the load-bearing safety check.
- `warden-console` reads token from cookie, includes it on backend calls. Backends also re-validate.

The `OR source = 'simulator'` is essential — it's how the visitor sees ambient traffic and the audit page never feels dead. Don't accidentally tighten it during code review.

#### 5.3 Abuse layering

1. Cloudflare Bot Fight Mode + WAF (free, edge).
2. CF rate limit on `/api/mint-session`: 5/hour per IP.
3. Cloudflare Turnstile validation at mint endpoint.
4. Per-token quota: 50 ledger writes / 50 HIL pendings over 30-min lifetime, then 429.
5. VPS firewall: Cloudflare IP ranges only.

Brain stays in `mock-key` mode (no Anthropic cost).

### 6. Operations

#### 6.1 Hosting

- **Marketing**: Cloudflare Pages (free).
- **Demo backend**: Hetzner CCX13 or CCX23 (~$20–30/mo), Caddy or Cloudflare Tunnel for TLS, `docker compose --profile stack up -d`.
- **Worker**: Cloudflare Workers free tier (100k req/day; bump to Paid $5/mo if exceeded).
- **Backups**: weekly `tar` of `ledger-data` + `identity-data` + `hil-data` volumes to Cloudflare R2 (~$1/mo).

#### 6.2 Failure mode

**Fail-open**: marketing site (CDN) is independent of backend; tour always works. When the backend `/health` is down, the "open in console" CTA swaps to an email-us banner client-side. No 503 page, no spinner-of-doom. The visitor still gets the tour and a way to reach you.

`/health` composite endpoint is unauthenticated, internal-network-only between containers, returns 200 iff `ledger:8083/health AND hil:8084/health AND console:8085/health` all respond within 1s.

#### 6.3 Monitoring

- **UptimeRobot** free tier, 5-min ping to `/health`. Email + SMS on outage.
- **Plausible Analytics** for the funnel (no cookie banner needed).
- On-call truth: it's the operator. SLA = "best effort, business hours, ~15 min response time." Documented in `warden-website/README.md`.

No status page (broadcasts outages to competitors / journalists; CISOs don't subscribe). Failure-state banner is the entire status surface.

#### 6.4 Reset cadence

**Never auto-reset.** Chain grows forever — that's the cryptographic flex. ~1KB/row × ~10k rows/day = ~3.5 GB/year, trivial. Existing post-export vacuum tooling (`chain_vacuum_cursor`) is available if disk pressure ever bites; not needed day 1.

#### 6.5 Cost ceiling

~$40/mo total. If costs cross $100/mo, something is wrong — investigate before scaling.

### 7. Sequencing

| Week | Deliverable | What it proves |
|---|---|---|
| 1 | Tour animation (3 scenarios, auto-play + click-through) + polished marketing page + Plausible events wired | Visual story works; copy lands; conversion measurable |
| 2 | Receipts-page handoff (live chain rows fetched by sentinel correlation-id, `curl /verify` snippet) | Cryptographic-realness flex without backend complexity |
| **DECISION POINT — measure handoff click-through against thresholds in §2** |
| 3 | VPS + compose deployed at `console-demo.vanteguardlabs.com`; existing console behind hardcoded basic-auth (gate against forgotten lockdown); CF DNS+WAF+rate-limits | Real console URL works; ops baseline |
| 4 | CF Worker token mint + Turnstile gate; console demo-mode (URL-fragment → cookie); HIL approve-only filter enforcement | Per-session isolation; defense-in-depth |
| 5 | Ledger filter enforcement; `warden-chaos-catalog` extraction (chaos-monkey becomes thin wrapper); `/demo/fire` curated attack menu | Full kick-the-tires console |
| 6 | Auto-decide skip-prefix flag in simulator; UptimeRobot; weekly R2 backups; reset-cadence policy in `README.md`; reset-week test | Production-grade ops |

The week-3 watch-out: **don't deploy the console with auth disabled and forget to lock it down in week 4.** The hardcoded basic-auth password is the gate against this — it forces an explicit removal in week 4 rather than relying on memory.

### 8. Out of scope

- Per-visitor ephemeral stack (cost shape doesn't match traffic shape).
- Raw payload sandbox (anonymous-visitor abuse surface > marketing benefit).
- Public status page (broadcasts outages; CISOs don't subscribe).
- Email-gate at handoff (kills evaluator funnel; we already have "Book a demo" for lead capture).
- Multi-region failover, HA, formal SLA.
- Internationalization.
- A/B testing tour variants (premature optimization for v1).

### 9. Implementation questions deferred

These emerge during the build, not at design time:

- Specific attack scenario payloads (indirect-injection prompt text, wire-transfer JSON shape).
- Animation copy and narrative beats per scenario.
- Token-expiry-mid-session UX (probably: 401 → modal → re-Turnstile → fresh token → retry last action).
- CSS / brand polish on the demo console vs. operator console default.
- ~~Domain choice~~ — resolved 2026-05-08: `vanteguardlabs.com` (with `demo.` and `api.` subdomains as in §4).
- Where exactly the `warden-chaos-catalog` crate lives (new repo vs. submodule of warden-chaos-monkey).

### 10. Confirmed before writing code

The four operational tradeoffs that gate the green light, all confirmed:

1. The week-2 kill-switch is real — receipts-only ships if metrics say so.
2. Single VPS, no HA, "best effort business hours" demo SLA is acceptable.
3. `warden-chaos-catalog` extraction is in scope; chaos-monkey becomes a thin wrapper.
4. Shared HS256 JWT secret across CF Worker + ledger + HIL is acceptable, rotated quarterly.

---

## Console policy management


Companion to [Console config page](#console-config-page) (read-only diagnostic) and the policy-engine description in `README.md` §11.2 ("Layer 3 — The Law"). Where the config page exposes deployment metadata and four-backend health probes, this section adds a *write* surface: viewing, editing, activating, deactivating, and deleting the `*.rego` and `*.json` files that `warden-policy-engine` loads.

**Module status:** **shipped.** Lives in `warden-policy-engine` (SQLite-backed policy store, write API, atomic engine rebuild, NATS-published outbox), `warden-console` (`/policies` surface + `Role::Admin`), `warden-sdk` (`PoliciesClient`), and `warden-ledger` (consumes new `policy.*` chain v3 event kinds — no schema bump, chain v3 is event-kind-polymorphic). End-to-end coverage in `warden-e2e/dev/run-policies.sh`.

Design decided by a `/grill-me` walkthrough. Eight architectural decisions resolved in sequence. This doc is the consolidated record so the implementation work can begin from a stable baseline.

### 1. What this closes

`warden-policy-engine` today loads `policies/*.rego` + `policies/*.json` from disk via `build_engine_from_dir` at boot, then never re-reads them. The operational consequences:

| Gap | Today | After this section |
|---|---|---|
| Visibility | Operators read policies by `cat`-ing the container filesystem or browsing GitHub | `/policies` page lists every loaded policy with state, version, last editor |
| Tuning the allowlist | `attestation_allowlist.json` edit = PR + redeploy of policy-engine for a one-line "approve `delete_repo` at measurement `abc123`" | One textarea edit, atomic engine rebuild, no redeploy |
| Emergency rule changes | "Disable bulk-export business-hours rule for the maintenance window" requires a code push | Single Admin click toggles the rule's `active` flag |
| Audit trail of policy changes | `git log` on the policy directory; no anchor in the chain | Every mutation lands as a chain v3 lifecycle row with operator OIDC sub + reason |
| Rollback | Revert PR + redeploy | One-click "rollback to version N" against the version-history table |

The console UI is *not* a rule editor for non-engineers — it's still a rego textarea, the audience is still operators familiar with rego. The value is collapsing the change-loop from "PR + redeploy" to "edit + Save" while strengthening the audit trail.

### 2. Scope and non-goals

**In scope (v1):**

- File-level granularity: `governance.rego`, `attestation.rego`, `attestation_allowlist.json`, plus any new file an Admin creates.
- Two content types: `rego` (logic; validated via regorus compile) and `json` (data documents; validated via per-name JSON Schema).
- CRUD: create, read (current + any historical version), update (with diff modal), soft delete, activate, deactivate, rollback to a prior version.
- Append-only version history per policy.
- Required free-text `reason` on every mutation.
- Atomic engine rebuild: no in-flight `/evaluate` is interrupted; new requests after the swap see the new policy set.
- Outbox-backed durable chain v3 anchoring for every mutation.

**Explicitly out of scope (v1 non-goals):**

- Rule-level toggles inside a file (would require either rego AST rewriting or per-rule feature flags; defer until file-level granularity proves insufficient).
- Splitting `governance.rego` into per-axis files (`governance_denylist.rego`, `governance_velocity.rego`, …); a separate refactor with its own rollback story.
- Two-person approval (4-eyes) for deactivation/delete of "critical" policies; the v1 defense is `Admin` role + chain audit + required reason.
- Multi-replica `warden-policy-engine` consistency (NATS-KV invalidation à la velocity tracker); v1 ships single-replica.
- Codemirror / Monaco editor; v1 uses plain `<textarea>` and leans on regorus error messages for syntax feedback.
- Golden-test corpus gate on save; the chaos-monkey suite is *almost* this corpus today, but promoting it into a pre-save hook is its own project.
- Git-backed policy storage (PR-review workflow); a different product than the console-CRUD shape we're building.
- Higher-level DSL on top of rego (structured forms generating rego); ditto.

### 3. Service architecture

The write surface lives on `warden-policy-engine`. Console is a thin UI layer calling `warden-sdk` → policy-engine, matching the existing pattern where each service owns its own state (HIL owns pending decisions, identity owns agent records, ledger owns chain rows).

Three reasons over a console-owned model:

1. **Atomicity.** The new policy must compile, the regorus engine must rebuild, the SQLite write must commit, and the outbox row must be written — as a single failure domain. Splitting storage across services adds a window where storage and engine disagree.
2. **Pattern match.** Identity emits chain v3 lifecycle rows for agent state changes through its own outbox; policy mutations follow the same pattern.
3. **Boot-time integrity.** Engine has to rebuild from its own SQLite anyway; co-locating eliminates a network hop on every restart.

Single replica in v1. Multi-replica adds a NATS-KV-backed invalidation channel (mirroring `NatsKvTracker` for velocity) — deferred.

### 4. Data model (SQLite)

```sql
CREATE TABLE policies (
  name TEXT PRIMARY KEY,
  content_type TEXT NOT NULL CHECK (content_type IN ('rego','json')),
  active INTEGER NOT NULL,                   -- 0 / 1
  current_version INTEGER NOT NULL,
  deleted_at TIMESTAMP NULL,                 -- soft delete tombstone
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);

CREATE TABLE policy_versions (
  name TEXT NOT NULL,
  version INTEGER NOT NULL,
  body TEXT NOT NULL,
  body_sha256 TEXT NOT NULL,
  reason TEXT NOT NULL,                      -- required on every mutation
  actor_sub TEXT NOT NULL,
  actor_idp TEXT NOT NULL,
  chain_seq INTEGER NULL,                    -- nullable until ledger acks
  created_at TIMESTAMP NOT NULL,
  PRIMARY KEY (name, version),
  FOREIGN KEY (name) REFERENCES policies(name)
);

CREATE TABLE policy_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  payload_json TEXT NOT NULL,                -- canonical chain v3 LogRequest
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NULL,
  created_at TIMESTAMP NOT NULL,
  delivered_at TIMESTAMP NULL
);
```

`policies.current_version` is the only mutable column on the `policies` row that affects engine state (alongside `active`). The version table is append-only — rollback creates a new version whose body matches an older one, not by mutating `current_version` to point backwards. Reasons: (i) chain-side, every state change is an event with `prev_sha256` → `new_sha256`; (ii) the version-table sequence is monotonic, easier to reason about than a directed cycle.

### 5. Wire API (`warden-policy-engine`)

```
GET    /policies                                  list (Viewer)
GET    /policies/{name}                           current + metadata (Viewer)
GET    /policies/{name}/versions                  version timeline (Viewer)
GET    /policies/{name}/versions/{n}              historical body (Viewer)
GET    /policies/{name}/diff?from=N&to=M          unified diff (Viewer)

POST   /policies                                  create (Admin)
PUT    /policies/{name}                           update (Admin)
POST   /policies/{name}/activate                  (Admin)
POST   /policies/{name}/deactivate                (Admin)
DELETE /policies/{name}                           soft delete (Admin)
POST   /policies/{name}/rollback/{version}        (Admin)
```

All write requests carry a JSON body with `{reason: string, expected_current_version: int}` (create omits `expected_current_version`; rollback's body shape is `{reason}` only).

Failure modes:
- `400 Bad Request` — regorus compile error (rego) or JSON Schema validation error (json). Body carries the parser error verbatim.
- `409 Conflict` — `expected_current_version` doesn't match `policies.current_version`. Response body includes the new current version's metadata so the UI can prompt "policy was changed since you opened the editor; reload?".
- `403 Forbidden` — caller lacks `Admin` role.
- `503 Service Unavailable` — outbox or NATS unreachable past retry budget; the SQLite + engine state is consistent, but the chain row hasn't landed yet. (Not surfaced in v1's happy path; documented for completeness.)

### 6. Save flow

The order matters for crash safety. For a `PUT /policies/{name}`:

1. **Validate.** Compile rego via a throwaway `Engine::new()` + `add_policy`, or validate JSON against the per-name JSON Schema. Reject with `400` on failure; no state mutation.
2. **Build candidate.** Construct a fresh full-set `Engine` from SQLite's current active set with the new body substituted. Slow path (tens of ms for the full policy directory), runs *outside* the live `Mutex<Engine>`.
3. **Persist.** Begin SQLite transaction:
   - Insert `policy_versions` row for the new version.
   - Update `policies.current_version` (and `active` for activate/deactivate).
   - Insert `policy_outbox` row carrying the canonical chain v3 `LogRequest` payload.
   - Commit.
4. **Swap engine.** Take `Mutex<Engine>` lock; `*guard = candidate_engine`; release. Total lock-hold time is one struct assignment (microseconds). In-flight evaluations finish on the old engine; new ones see the new one.
5. **Respond.** Return `200` with the new version metadata.
6. **Outbox drain.** A background worker drains `policy_outbox`, publishes to NATS subject `warden.forensic`, and writes back `chain_seq` on the version row when the ledger acks.

Crash safety: if the process crashes between step 3's commit and step 4's swap, on reboot the engine rebuilds from SQLite, which already reflects the new state. Self-heals. No double-emit risk because step 6 is decoupled and idempotent (the outbox row carries a stable `id`; the ledger dedupes by chain row content if the worker retries after a partial publish).

### 7. Audit + chain integration

Every mutation publishes a chain v3 lifecycle row through the outbox. Event kinds:

- `policy.created`
- `policy.updated`
- `policy.activated`
- `policy.deactivated`
- `policy.deleted`

Each row carries `payload_sha256` over a canonical JSON object:

```json
{
  "name": "attestation.rego",
  "content_type": "rego",
  "prev_sha256": "…",        // null for policy.created
  "new_sha256": "…",         // matches policy_versions.body_sha256
  "reason": "approve dev-binary-hash for delete_repo per #INC-2138"
}
```

Standard chain v3 fields (`actor_sub`, `actor_idp`, `seq`, `prev_hash`, `signature`, `key_id`) are populated as for any other chain v3 row. `actor_sub` and `actor_idp` come from the OIDC session of the operator who clicked Save. The `reason` field is non-optional; the API rejects `400 Bad Request` on empty or whitespace-only input.

The ledger doesn't need a schema change. Chain v3's `HashableEntryV3` is event-kind-polymorphic via `payload_sha256` — adding `policy.*` event kinds is mechanical.

### 8. Authorization

Adds a third role to the existing two-role hierarchy in `warden-console/src/auth_session.rs`:

```rust
pub enum Role {
    Viewer,
    Approver,
    Admin,    // new
}
```

Hierarchy: `Viewer < Approver < Admin`. `Role::has(target)` is updated so `Admin` is a strict superset of both.

`RoleMap` gains an `admin_groups: Vec<String>` field, mirroring the existing `approver_groups` and `viewer_groups`. Resolution priority becomes admin > approver > viewer. Group mapping in console config:

```yaml
auth:
  oidc:
    admin_groups: ["warden-policy-admins"]
    approver_groups: ["security-team", "finance-ops"]
    viewer_groups: ["engineering", "compliance"]
```

A new `require_admin` gate guards every console-side write route (`POST/PUT/DELETE` on `/policies`); `require_viewer` continues to guard reads. The HIL pattern is reused: the `/policies` template carries a `can_edit_policies` flag, and the action buttons (Edit / Activate / Deactivate / Delete / Rollback) are rendered only when true. Viewers and Approvers see the policy list and bodies but no buttons.

`disabled` mode promotes the synthetic session to `Admin` (matching how it already promotes to `Approver`), so dev / CI flows work without OIDC wiring.

**Fail-closed on missing OIDC mapping.** If `admin_groups` is unset and console isn't in `disabled` mode, no operator gets `Admin`. Existing Approvers are *not* silently promoted. Operators must consciously add the group mapping. Mirrors the loud-fail-boot principle from §10 below.

### 9. Console UI

Five Askama templates under `repos/warden-console/templates/`:

- `policies.html` — list page. Table columns: name, content_type, state (active / inactive / deleted chip), current version, last updated by, last updated at. Filter chips for state. Active and inactive visible by default; deleted hidden behind a "show deleted" toggle. Action buttons rendered behind `can_edit_policies`.
- `policies_new.html` — Admin-only create form. Name + content_type radio + textarea + reason field.
- `policies_detail.html` — view page. Current body in a syntax-highlighted block (server-rendered with class hints for prism.js or similar). Lifecycle timeline sidebar mirroring `agents_detail.html`: every chain v3 row for this policy, oldest first, with "view diff" links. "Edit" button links to the edit page.
- `policies_edit.html` — Admin-only. Plain `<textarea>` (no client-side editor in v1). Reason field. Form submits via htmx; server returns either the updated detail page or an error fragment with the regorus / JSON Schema error inline.
- `policies_diff.html` — unified-diff view. Reusable for "edit confirmation modal" (current vs. proposed) and "audit history view" (version N vs. version M).

The confirm-diff modal on save (§3 of Q3) is implemented as: form submits to a `POST /policies/{name}/preview` endpoint (server-side, no SQLite write); response is an htmx-swapped modal showing the diff with a "Confirm and save" button that POSTs to the actual `PUT /policies/{name}`. Two-step interaction; no client-side diffing.

URL paths:

```
/policies                               list
/policies/new                           create form (Admin only)
/policies/{name}                        detail
/policies/{name}/edit                   edit form (Admin only)
/policies/{name}/versions/{n}           historical body
/policies/{name}/diff?from=N&to=M       unified diff
```

### 10. Boot-time integrity + initial seed

On boot, after loading the persisted policy set from SQLite, `warden-policy-engine` attempts the engine build *before* binding the HTTP port. If the build fails (regorus version bump rendered an old policy uncompilable, or someone hand-edited SQLite into invalidity), the process exits non-zero with the regorus error. No fallback to the bundled `policies/*.rego` files. No fallback to no-policies. Loud failure is correct: silent fallback would mask the divergence.

**Initial seed.** First boot with an empty `policies` table: ingest the on-disk `policies/*.rego` and `policies/*.json` files as version 1 of each, with `active=true`, `actor_sub="system"`, `actor_idp="bootstrap"`, `reason="initial seed from disk"`. Subsequent boots are no-ops (table non-empty). This is how today's deployments migrate without a separate seeding step.

### 11. Out of scope for v1

These emerge during build, not at design time:

- Whether the syntax-highlighting class hints in `policies_detail.html` should target prism.js, highlight.js, or skip highlighting and rely on monospace alone.
- Specific JSON Schema content for `attestation_allowlist.json` (the `additionalProperties: false` shape, allowed key patterns, etc.).
- Retention policy for `policy_versions` (keep all vs. prune after N days). v1 ships "keep all"; revisit when version-table size becomes operationally interesting.
- Whether create-form name validation enforces a regex or accepts any string; v1 takes any string but warns on non-matching `^[a-z0-9_]+\.(rego|json)$`.
- How `wardenctl` exposes policy management (probably `wardenctl policies list / get / edit …` mirroring `wardenctl agents …`); deferred until the console flow stabilizes.

### 12. Confirmed before writing code

The eight architectural decisions resolved by the `/grill-me` walkthrough, all confirmed:

1. File-level granularity (not rule-level, not DSL-on-top).
2. Write API on `warden-policy-engine` with single-replica SQLite (not console-owned, not external bundle service).
3. Atomic rebuild on save + diff modal + loud-fail boot (not draft+activate, not golden-test gate).
4. Both `*.rego` and `*.json` in scope, with per-name JSON Schema validation (not rego-only, not bundled with file split).
5. Append-only version table + chain v3 lifecycle events + soft delete (not chain-only audit, not content-addressed blob store).
6. New `Role::Admin` at top of hierarchy, Viewer reads + Admin writes, fail-closed on missing OIDC mapping (not reuse Approver, not per-policy ACL).
7. Required free-text `reason` on every mutation; defer two-person approval (not no-guardrails, not critical-policy-only protection).
8. Build-then-persist-then-swap ordering, optimistic concurrency via `expected_current_version`, boot-time integrity check (not pessimistic locking, not last-write-wins).

---

## Forensic-tier deep review


Companion to [Layer 2 — warden-brain](#layer-2--warden-brain) (sub-second classifier on the proxy hot path) and [Layer 4 — warden-ledger](#layer-4--warden-ledger) (the forensic store). Where brain's value proposition is sub-second verdicts via Haiku 4.5, `warden-deep-review` is the complementary forensic tier — asynchronous, slow, expensive, and substantially smarter. Runs Opus 4.7 (MVP single-provider) against a sampled slice of the audit stream to catch what Haiku missed and deepen verdicts on what it flagged.

**This service does not gate live traffic.** HIL is the inline blocking surface; deep-review is retrospective by design. A vendor outage, a quota burst, or a slow review must never back up the audit stream and starve brain → ledger writes. Every failure mode soft-fails per event with a queryable sentinel.

**Module status:** **shipped 2026-05-13** at `warden-specs/VERSION` 0.6.0. Lives in `warden-deep-review` (new repo, NATS consumer + LLM provider trait + per-agent history ring buffer + budget + retry + alert sink), wired into `warden-e2e/{prod,dev}/docker-compose.yml` as a service in the `stack` profile. **Adjacent surfaces deferred:** `/deep-review` console route, `warden-charts/` Helm values, baseline-accuracy benchmark publication.

### 1. What this closes

| Gap | Today (brain only) | After this section |
|---|---|---|
| Slow exfiltration across many events | Haiku sees one event at a time; cannot stitch 50 reads + one egress into a pattern | Per-agent history fed into Opus prompt; pattern-level reasoning |
| Persona drift over a session | Haiku sees current event in isolation | History + agent enrollment string in prompt; "support assistant now invoking shell" lights up |
| Indirect injection via tool output | Haiku scans current input; misses that the *prior* tool output injected the steering payload | History carries prior tool outputs; the injection → obey sequence is visible |
| Recon under varied encodings | Haiku evaluates each path on its own; `%2Fetc%2Fpasswd` looks like a stray bug | Sequence across encodings reads as probing |

The fast classifier remains in place — it's still the only thing fast enough to gate live traffic. Deep-review is the second-opinion layer; `brain_delta` (agreed / escalated / downgraded) is the operator-facing summary of whether the heavy model arrived at the same call.

### 2. Scope and non-goals

**In scope (v1.x MVP):**

- Single provider — `AnthropicOpusProvider` (Opus 4.7).
- NATS core pubsub consumer on `warden.forensic` (subject the proxy already publishes forensic rows to; matches existing infra without a JetStream upgrade).
- Per-event budget gate, retry, concurrency limit, paging.
- Three sentinel ledger event types (`deep_review_finding` / `deep_review_failed` / `deep_review_skipped`).
- Reuses existing `LogRequest` envelope — no `warden-ledger` wire change.
- Deterministic `MockProvider` in-repo so e2e and CI do not burn vendor tokens.
- 25-case seed benchmark covering all four blind-spot classes + hermetic compliance harness.

**Explicitly out of scope (v1.x non-goals):**

- Ensemble across vendors (Opus + Gemini + GPT majority vote) — speculative complexity before single-model benchmark data exists.
- Sequential escalation (Opus → Gemini → GPT on disagreement) — same reasoning.
- Per-tenant cost attribution — multi-tenant budgeting needs a deployment-level tenancy model warden doesn't have yet.
- Adaptive sampling (auto-tune sample rate against remaining budget) — manual knobs for v1; auto-tune is polish.
- Dead-letter queue for failed reviews — retry + soft-fail covers transient failures; add once telemetry shows sustained outages.
- Auto-quarantine via identity service on Red findings — structurally unsafe with async detection; reconsider only if false-positive rate is essentially zero.
- Pre-emptive HIL on agent's next request post-Red — cross-component state, TTL questions, race conditions; deferred with a proper design.
- Persona-aware prompting (feed `warden-brain/personas/` into the prompt) — worth measuring against v1 baseline first.
- JetStream-durable consumer — MVP uses core NATS to match existing `nats:2` container (no `-js` flag); upgrading is an e2e infra change.
- Path-dep on `warden-brain/src/pii.rs` — MVP ships a small in-tree regex masker (`warden-deep-review/src/pii.rs`); merging masker codebases is a v1.x+1 swap-in.

### 3. Architecture

```
                      proxy (publishes forensic row)
                                 ↓
                          warden.forensic ── NATS core
                          ↓                ↓
              warden-ledger        warden-deep-review
              (appends row)         (samples → review → emits finding)
                                              ↓
                                   warden.forensic (republishes)
                                              ↓
                                   warden-ledger
                                   (appends finding row)
```

Deep-review subscribes to the same subject the ledger consumes from. Its emitted findings go back onto the same subject so the ledger picks them up via its existing consumer — no second subscription, no second envelope. The consumer filters its own emissions to prevent an infinite loop (matches on `method ∈ {deep_review_finding, deep_review_failed, deep_review_skipped}`).

Per-event pipeline:

1. **Receive** — NATS message arrives, parsed as `Value`. Self-emission filter ignores own `method` values. Recorded in per-agent ring buffer (`History`) unconditionally so the next event has full context regardless of sampling outcome.
2. **Sample** — `should_sample(brain_authorized, rate_flagged, rate_green)`. Default: 100% flagged, 1% Green for blind-spot mitigation.
3. **Permit** — `tokio::sync::Semaphore::acquire_owned()`; bounded concurrent dispatch (default 4). Backpressure naturally surfaces through NATS subscriber queue.
4. **Budget gate** — `budget.try_reserve(estimated_tokens)`. On exceed: emit `deep_review_skipped { reason: "budget" }` sentinel and return.
5. **PII mask** — `pii::mask_pii` over every string leaf in the event JSON. Defense in depth; the prompt builder strips brain-verdict fields downstream regardless.
6. **Prompt build** — `prompt::build_user_message(masked_event, history)`. Brain verdict fields (`authorized`, `intent_category`, `reasoning`, `signal`, `persona_drift_score`, `injection_detected`, `malicious_code_detected`, `compromised_package_detected`, plus `policy_decision.{allow, reasons, review}`) are *stripped*. Independent reasoning is the entire value proposition — feeding brain's verdict in turns deep-review into a confirmation engine that structurally cannot find what Haiku missed.
7. **Provider call** — `provider.review(&prompt)` wrapped in `with_backoff` (1s / 4s / 16s exponential backoff + full jitter, 60s total wall-clock budget per event).
8. **Compute `brain_delta`** — server-side, from the (`brain_authorized`, `deep_verdict`) pair:

   ```
   (brain_authorized=true,  deep=Green)  → Agreed
   (brain_authorized=true,  deep=Yellow) → Escalated
   (brain_authorized=true,  deep=Red)    → Escalated
   (brain_authorized=false, deep=Green)  → Downgraded
   (brain_authorized=false, deep=Yellow) → Downgraded
   (brain_authorized=false, deep=Red)    → Agreed
   ```

9. **Emit** — publish `deep_review_finding` row to `warden.forensic`. If `verdict == Red && confidence ≥ page_confidence`: `alert_sink.maybe_page(...)` fires the configured Slack-shape webhook (rate-limited).
10. **Soft-fail on retry exhaust** — emit `deep_review_failed { reason }` where reason ∈ `timeout` / `vendor_5xx` / `parse_error` / `quota_exceeded` / `rate_limited` / `unknown_vendor_error`. Consumer advances.

History capacity defaults: last 20 events by `agent_id`, capped at 50 by `correlation_id` per the roadmap. Both knobs are env-tunable.

### 4. Wire surface

**Inbound:** the same `LogRequest` JSON envelope every other forensic-row publisher emits. No new schema. `LogRequest.method` and `LogRequest.policy_decision` are the only fields deep-review reads beyond identity/correlation.

**Outbound:** three new `method` values on the same `LogRequest` envelope, distinguished by their JSON payload shape inside `policy_decision`:

| `method` | `policy_decision` payload shape |
|---|---|
| `deep_review_finding` | `{verdict, confidence, reasoning, brain_delta, reviewing_model, review_latency_ms, reviewed_at, original_method, original_correlation_id}` |
| `deep_review_failed` | `{reason, reviewing_model, original_method, original_correlation_id}` |
| `deep_review_skipped` | `{reason, original_method, original_correlation_id}` |

- `verdict` ∈ `"Green" | "Yellow" | "Red"`.
- `brain_delta` ∈ `"Agreed" | "Escalated" | "Downgraded"`.
- `reason` (failed) ∈ `"Timeout" | "Vendor5xx" | "ParseError" | "QuotaExceeded" | "RateLimited" | "UnknownVendorError"`.
- `reason` (skipped) is a free-form string; v1 only emits `"budget"`.

The ledger needs no code change. Chain v3's `HashableEntryV3` is event-kind-polymorphic via `payload_sha256` — adding new `method` values is mechanical. Operators see the new rows in the existing audit table; the dedicated `/deep-review` console route is deferred (see §8).

### 5. Sampling, budgeting, retries, concurrency

All knobs are env-driven. Defaults in parens.

| Env | Default | Meaning |
|---|---|---|
| `WARDEN_DEEP_REVIEW_SAMPLE_RATE_GREEN` | `0.01` | Fraction of brain-Green events reviewed |
| `WARDEN_DEEP_REVIEW_SAMPLE_RATE_FLAGGED` | `1.0` | Fraction of brain-Yellow/Red events reviewed |
| `WARDEN_DEEP_REVIEW_CONCURRENCY` | `4` | Max concurrent in-flight reviews (tokio semaphore) |
| `WARDEN_DEEP_REVIEW_DAILY_TOKEN_CAP` | `1_000_000` | Input + output tokens per UTC day (~$60/day Opus). Demo VPS pins `200_000` |
| `WARDEN_DEEP_REVIEW_RETRY_BUDGET_SECS` | `60` | Per-event wall-clock budget across retries |
| `WARDEN_DEEP_REVIEW_PAGE_CONFIDENCE` | `0.85` | Confidence floor for paging on Red |
| `WARDEN_DEEP_REVIEW_ALERT_WEBHOOK` | (none) | Slack-shape webhook URL; disabled when unset |
| `WARDEN_DEEP_REVIEW_HISTORY_PER_AGENT` | `20` | Per-agent history ring-buffer capacity |
| `WARDEN_DEEP_REVIEW_HISTORY_PER_CORRELATION` | `50` | Per-correlation history cap |
| `WARDEN_DEEP_REVIEW_METRICS_PORT` | `8087` | Prometheus `/metrics` port. Sibling `identity` owns `8086` |
| `WARDEN_DEEP_REVIEW_ANTHROPIC_API_KEY` | `mock-key` | API key; sentinel `mock-key` selects `MockProvider` |

Retry algorithm: full-jitter exponential backoff at `1s / 4s / 16s`. Each delay is sampled uniformly from `[0, base]` per the AWS Architecture Blog full-jitter prescription. Total wall-clock is enforced via `retry_budget` even if individual sleeps complete fast — a slow vendor call that returns one second before the budget expires is not retried.

Budget tracker resets at UTC midnight via day-ordinal comparison (cheap; no tokio interval). `try_reserve` is the gate before any vendor call; `record_actual` reconciles the estimate with the response's `usage` field on success.

Paging is rate-limited per agent: `AlertRateLimiter` is a token bucket keyed by `agent_id`, refill 1 / minute. Over-limit pages are dropped silently — the finding still lands in the ledger, so the alert can be reconstructed.

### 6. Failure-mode posture

- **Vendor 5xx / timeout / parse error.** Retry 3× per the backoff schedule. On exhaust: emit `deep_review_failed` and advance the NATS consumer. Never blocks the audit stream.
- **Vendor 429.** Same retry path; mapped to `RateLimited` reason on exhaust.
- **Daily budget exceeded.** Emit `deep_review_skipped { reason: "budget" }` and advance. Counter resets at UTC midnight.
- **Sampling skip.** No sentinel emitted. `_skipped` events would dominate the ledger and obscure real coverage gaps; sampling decisions are recoverable from the brain's full event stream.
- **Alert rate-limit.** Page dropped silently; finding still landed.
- **Self-emission loop.** Filtered at the consumer entry by `method` prefix.
- **NATS publish failure on emit.** Logged at `warn`, the event is dropped (best-effort posture). A persistent NATS outage will surface in the brain → ledger path long before it affects deep-review, since brain has the same dependency on the same subject.

Three sentinel types (`finding` / `failed` / `skipped`) make every coverage gap queryable from the ledger.

### 7. PII handling

`warden-deep-review/src/pii.rs` is an in-tree regex masker. Patterns: SSN, email, IPv4, credit-card (Luhn-shape 13-19 digit), PEM blocks, AWS access keys. Sentinels: `[SSN]`, `[EMAIL]`, `[IPV4]`, `[CC]`, `[PEM]`, `[AWS_KEY]`. The masker is idempotent — masking twice produces the same string — verified by the compliance harness on every benchmark case.

Mask is applied to every string leaf in the event JSON *before* the prompt builder strips brain-verdict fields. Defense in depth: even fields that get stripped never reach the vendor API in raw form.

The masker is deliberately small. A future v1.x+1 task is to swap it for the more capable `warden-brain/src/pii.rs` masker (which has bigram embedding + regex). Two masker implementations is documented technical debt; the rationale for *not* path-dep'ing brain's masker at MVP is avoiding ~30 transitive deps and a BrainState coupling for a 60-line regex job.

### 8. Operator surface

**Today (shipped):**

- Findings appear as normal rows in `/audit` with `method` ∈ `deep_review_*`.
- `/verify` walks the chain over the new rows transparently (no ledger code change).
- Prometheus `/metrics` exposes per-verdict and per-failure-reason counters on the configured port.
- Slack-shape page on Red + confidence ≥ floor when `WARDEN_DEEP_REVIEW_ALERT_WEBHOOK` is set.

**Deferred (callout — see roadmap §"v1.x — in flight"):**

- `/deep-review` console route: paginated list (50/page), columns timestamp · correlation (short hash) · agent · model · brain → deep verdict · confidence · latency. Filters: date range, verdict, brain_delta.
- `/narrative` summary strip: last-7d findings count, brain_delta donut, top disagreement category.
- Click-through from a finding into the unified request timeline so brain verdict + deep-review finding + any HIL events are visible in chain order.
- Helm chart values under `warden-charts/` for K8s sidecar deployments.

### 9. Test surface

Hermetic test coverage at MVP:

- 57 unit tests across alert, budget, config, consumer, finding, history, pii, prompt, providers (mock + Opus wiremock), retry, review, sampler.
- 8 integration tests in `tests/compliance.rs` driving the full benchmark corpus through the prompt builder + PII mask + `MockProvider`.
- 25-case seed benchmark in `benchmark/cases.json` covering `slow_exfiltration` (4) / `persona_drift` (4) / `indirect_injection` (4) / `recon_probing` (6) / `benign_workflow` (5) / `mixed` (2). Each case is a (`history`, `event`, `expected_verdict`, `min_confidence`) tuple.
- System-prompt invariants: ≥14,500 chars (Opus prompt-cache ephemeral-prefix floor) and all four named blind-spot topics present, asserted via unit test.

Producing a published baseline accuracy number against real Opus (parallel to brain's 86.67%) requires an operator-run pass — out of CI by design (token cost, network dependence).

### 10. Confirmed before writing code

The architectural decisions resolved by `/grill-me`:

1. Async post-hoc execution mode, NATS consumer on the same `warden.forensic` subject (not on the hot path, not a separate JetStream stream at v1 to match existing infra).
2. Sampling: 100% flagged + configurable Green floor (not full traffic, not flagged-only — Green sampling is the blind-spot mitigator).
3. Single provider per deployment behind an `LlmProvider` trait (not ensemble, not sequential escalation — both deferred pending benchmark data).
4. Reuse `LogRequest` envelope with three new `method` values (not a new wire envelope, not a parallel chain).
5. Brain verdict stripped from prompt; `brain_delta` computed server-side (not "feed brain's verdict in for the model to react to" — that's a confirmation engine).
6. Per-event soft-fail with three sentinel types (not at-least-once durable redelivery, not best-effort silent drop).
7. In-tree regex PII masker at MVP (not path-dep on brain's masker — deferred swap with documented rationale).
8. Page on Red + high-confidence only, rate-limited per agent; no auto-block (async detection + auto-block is a self-DoS waiting to happen).

---

## Threat model


This document is the public threat model for Agent Warden. It is written
for two audiences:

1. **Security reviewers and pen-testers** — to know precisely where to
   attack, what defenses exist, and what is intentionally out of scope.
2. **Buyers and integrators** — to confirm that the security claims in
   the marketing site and `README.md` map to real, named controls.

It is layer-by-layer and STRIDE-organized inside each layer. STRIDE here
refers to the standard threat categories: Spoofing, Tampering,
Repudiation, Information disclosure, Denial of service, Elevation of
privilege.

The architecture and wire contracts are the source of truth — see
the cross-repo wire contracts in the per-service READMEs, the
[Identity service](#identity-service), and [Agent onboarding](#agent-onboarding-wao) sections for the system shape this model is grounded in.
Re-verify against `git log` if the model and the code disagree; code
wins.

### Trust boundaries

```
                            ┌────────────────────────┐
                            │   Operator             │  human, browser, mTLS
                            │  (console / wardenctl) │
                            └────────────┬───────────┘
                                         │ HTTPS + bearer (OIDC)
                                         ▼
┌───────────────┐   mTLS    ┌────────────────────────┐
│   AI agent    │──────────▶│  warden-proxy (L1)     │
│  (any LLM)    │   SVID    │  port 8443             │
└───────────────┘           │  • mTLS termination    │
                            │  • SPIFFE SAN parse    │
                            │  • Brain → Policy      │
                            │  • HIL gate (Yellow)   │
                            │  • A2A mint/redeem     │
                            │  • upstream forward    │
                            └─┬───┬──────┬──────┬────┘
                              │   │      │      │
              ┌───────────────┘   │      │      └───────────────┐
              ▼                   ▼      ▼                      ▼
    ┌─────────────┐   ┌──────────────────┐   ┌──────────────┐  ┌─────────────┐
    │ warden-brain│   │ warden-policy    │   │ warden-hil   │  │warden-      │
    │ (L2, 8081)  │   │ -engine (L3,8082)│   │ (8084)       │  │ identity    │
    └──────┬──────┘   └────────┬─────────┘   └──────┬───────┘  │ (8086)      │
           │                   │                    │          └──────┬──────┘
           │   NATS (warden.forensic) ─────────────────────────────────┤
           ▼                   ▼                    ▼                  ▼
                       ┌────────────────────────────────────┐
                       │         warden-ledger (L4, 8083)    │
                       │ SQLite + hash chain v1/v2/v3        │
                       └────────────────────────────────────┘
```

Every arrow above is a trust boundary. The threats below are organized
per-component; cross-component spoofing/tampering threats are grouped
under whichever component is the defender.

External trust dependencies:

- **NATS** (message bus) — runs inside the deployment perimeter; all
  forensic events transit it.
- **Vault** (credential store) — proxy fetches per-agent upstream creds
  from Vault.
- **SQLite** (ledger backing store) — assumed local, host-bound; OS
  filesystem ACLs are the only access control.
- **OIDC IdP** — operator and capability-resolver auth.
- **The operator's browser session** — console SSE + htmx + WebAuthn.

### Layer 1 — warden-proxy

The proxy is the single ingress for agent traffic. Everything else is
defense-in-depth behind it.

#### Spoofing

| Threat | Defense |
|---|---|
| An unauthenticated agent calls the proxy. | mTLS-only — `WebPkiClientVerifier` validates the cert chain against the proxy's CA root before any handler runs. |
| An agent presents a peer's certificate (replay). | The proxy's TLS stack only accepts the cert if the private key is held by the connecting peer (TLS finished MAC). Stolen private keys are still a real threat → defended by identity action signing + per-action JTI. |
| An agent forges an SVID by editing the SAN URI. | The SAN is bound to the cert by the issuing CA's signature. A forged SAN means a forged cert means chain verification fails. |
| A peer Warden cell mints an A2A token for a tenant it doesn't own. | `warden-identity` `/actor-token/redeem` consults the federation bundle and rejects with `peer_bundle_unknown:<td>` if the issuer isn't in the configured peer set. |

#### Tampering

| Threat | Defense |
|---|---|
| Network MitM modifies the JSON-RPC body in flight. | mTLS provides record-layer integrity. Plaintext is never on the wire. |
| An agent edits the `source` header to claim simulator origin. | `source` is metadata only, **not in the hashable** — untrusted by design. The console's "hide simulated traffic" filter is convenience, not authorization. |
| An agent sets `x-warden-actor-token` to bypass A2A verification. | Tokens are JWTs signed by the issuing identity; signature verification is what makes the bypass attempt fail, not the absence of the header. |

#### Repudiation

| Threat | Defense |
|---|---|
| An agent claims it never made a request. | Every verdict emits a forensic event keyed on a UUIDv4 `correlation_id`. The chain v2/v3 entries carry per-action signatures from `warden-identity` `/sign`, so the agent's identity is cryptographically anchored to each entry. |

#### Information disclosure

| Threat | Defense |
|---|---|
| Vault credentials leak through proxy logs. | The proxy never logs the credential value; it injects via the upstream HTTP request's headers and discards. Code path: `forward_upstream`. |
| Brain/policy verdicts leak across tenants in shared logs. | All logs are `correlation_id`-tagged; `agent_id` and `tenant` are present. Multi-tenant log separation is the operator's responsibility (Loki / OTLP collector tenant labels). |

#### Denial of service

| Threat | Defense |
|---|---|
| An agent floods `handle_mcp` to exhaust upstream quota. | `warden-policy-engine`'s velocity tracker (`InProcessTracker` or `NatsKvTracker`) breaks the circuit per-agent on configurable thresholds. |
| Brain/Anthropic call latency cascades. | Brain has per-call timeout + Voyage embedding fallback. Policy verdict resolves even if Brain is slow (`authorized=false` defaults to `intent_score=0.5`, which fails the policy gate — fail-closed). |
| Slowloris on the mTLS handshake. | axum's hyper backend has connection-level read timeouts. |

#### Elevation of privilege

| Threat | Defense |
|---|---|
| An agent escalates from auto-allow tier to wire-transfer tier by altering the JSON-RPC `method`. | Policy rego is keyed on `tool_type`, which the proxy derives from `method` — not from any agent-supplied field. The mapping table is server-side. |
| An agent bypasses HIL by abandoning the long-poll. | `forward_upstream` only fires on `Authorized` or HIL-Approved. A timed-out long-poll resolves to 403, never auto-Approve. |

### Layer 2 — warden-brain

Semantic inspection. Three signals: intent classifier (Haiku), persona
drift (Haiku), indirect-injection scanner (Haiku + heuristic).

#### Spoofing & Tampering

The Brain is called only by the proxy over an in-cluster network — the
trust boundary is the proxy-brain link. We don't run mTLS on this link
today; the assumption is the deployment perimeter (compose network /
k8s NetworkPolicy) is the perimeter.

→ **Action item, tracked under the deferred service-mesh work:** add SPIFFE
mTLS to the proxy↔brain, proxy↔policy, proxy↔hil, proxy↔identity links
so an attacker who lands on the cluster's overlay network cannot speak
directly to the brain and forge `BrainRequest` payloads.

#### Repudiation

Brain verdicts are emitted by the proxy (the proxy publishes the
forensic event after deriving the `authorized && policy_decision.allow`
final verdict). If brain misbehaves, that's recoverable from the
proxy-side forensic row. Brain itself is stateless.

#### Information disclosure

The Brain calls **Anthropic Claude 4.5 Haiku** (separate model from any
agent's primary LLM — the "Zero-Knowledge Bonus" invariant). Sensitive
payloads transit the Anthropic API. This is an explicit, documented
trust dependency in `README.md`.

The mock-mode path (`ANTHROPIC_API_KEY=mock-key`) does pure local regex
+ bigram embedding inspection — used by e2e and the simulator.

#### Denial of service

Brain has a per-request timeout in the proxy. A slow Anthropic API does
not stall the security verdict indefinitely.

#### Elevation of privilege

A compromised brain that returns `authorized=true` for everything would
fail-open at L2 only — Layer 3 (policy) still has independent veto, and
Layer 4 (ledger) still records the verdict. Defense-in-depth.

### Layer 3 — warden-policy-engine

Pure-Rust Rego (`regorus`) over `policies/*.rego`. Policy data is
file-system-loaded.

#### Tampering

| Threat | Defense |
|---|---|
| An attacker modifies `policies/*.rego` on disk. | Filesystem ACLs are the only control; the helm chart deploys policies as a configmap. Tamper detection is operator-side (file integrity monitoring). Policy changes show up in `git log` for audit. |
| Policy evaluation is influenced by `current_time` from the request. | The proxy stamps `current_time` (RFC 3339) explicitly. The rego fallback `time.now_ns()` only fires for non-proxy callers (tests). An attacker who fakes the proxy stamp is already past the Layer-1 boundary. |

#### Information disclosure

Policy-engine logs `correlation_id` + `agent_id` + `tool_type`. No
sensitive payload content is logged.

#### Denial of service

Velocity tracker is bounded — `InProcessTracker` is a `HashMap<String,
VecDeque<Instant>>` with bounded retention; `NatsKvTracker` uses
JetStream KV with a per-key CAS update loop. A pathological attack pattern
(e.g. millions of distinct agent IDs) would grow the in-process map.
NATS-KV backend rebalances under JetStream's own retention policy.

#### Elevation of privilege

Pure Rego cannot escape the policy engine. `regorus` is sandboxed —
no host bridge.

### Layer 4 — warden-ledger

SHA-256 hash-chained, SQLite-backed forensic store. Subscribes to
`warden.forensic` on NATS.

#### Tampering

| Threat | Defense |
|---|---|
| An attacker edits a row in the SQLite DB directly. | The hash chain detects it on the next `verify_chain` call — every entry's `entry_hash` covers the previous `prev_hash`, so any single-row edit invalidates every later row. Operator runbook ("ledger chain invalid" in [Runbooks](#runbooks)) covers detection. |
| An attacker adds a row claiming a forensic event that never happened. | Same — the new row has to satisfy the chain or it's detected. Chain v2/v3 rows carry per-action signatures from `warden-identity` `/sign`; an attacker forging both the chain and the signature needs the identity service's signing key. |
| An attacker replays a NATS forensic message. | NATS at-least-once semantics already mean the ledger may see duplicate publishes. Each `LogRequest` is content-hashed; duplicate appends produce identical `entry_hash`, which `record_entry` deduplicates by `(correlation_id, source_layer)`. |

#### Repudiation

The chain is append-only and signed. The export bundle (see
[Regulatory export](#regulatory-export)) is the long-term audit
artifact.

#### Information disclosure

Ledger rows carry intent, tool type, agent, verdict — not the raw
JSON-RPC body. The hashable explicitly excludes `signal` and `source`.

#### Denial of service

Append throughput is SQLite-bounded. NATS subscriber is single-threaded
by design (chain order matters). Operator runbook covers backlog
diagnosis.

### warden-deep-review

Async forensic auditor. Subscribes to the same `warden.forensic`
subject the ledger consumes from; emits findings via three new
`method` values on the existing `LogRequest` envelope. See
[Forensic-tier deep review](#forensic-tier-deep-review) for the
feature spec.

#### Spoofing & Tampering

Deep-review reads from NATS and posts to Anthropic. There is no
inbound HTTP request surface — its only published port is the
Prometheus `/metrics` endpoint.

→ **Same deferred service-mesh action item as brain / policy / hil:**
add SPIFFE mTLS to the NATS link so an attacker who lands on the
overlay network cannot publish forged forensic rows that deep-review
would dutifully feed into a paid vendor call.

#### Repudiation

Findings are anchored in the chain by the ledger's standard append
path — same audit trail as any other forensic row. `brain_delta` and
`reviewing_model` are part of the canonical hash; an after-the-fact
edit of which model said what is detectable on chain `verify`.

#### Information disclosure

Deep-review calls **Anthropic Claude Opus 4.7** by default. Sensitive
payloads transit the Anthropic API. Same explicit trust dependency as
brain's Haiku 4.5 call; the same "Zero-Knowledge Bonus" invariant
applies (Opus is separate from any agent's primary LLM).

PII regex masking runs before the vendor call (see §7 of
[Forensic-tier deep review](#forensic-tier-deep-review)). The
mock-mode path (`WARDEN_DEEP_REVIEW_ANTHROPIC_API_KEY=mock-key`)
bypasses the vendor entirely and is used by e2e + CI.

#### Denial of service

- **Vendor outage cannot stall the audit stream.** Retry budget +
  soft-fail + `deep_review_failed` sentinel make each per-event
  failure recoverable; the consumer keeps advancing.
- **Token bomb.** A pathological attacker who can publish to
  `warden.forensic` could try to drive deep-review into a budget
  exhaustion that hides their own subsequent events from review.
  Daily token cap defends against catastrophic spend; `_skipped`
  sentinels make the coverage gap auditable. The real defense is
  still the NATS perimeter (same as every other forensic publisher).
- **Alert storm.** Per-agent token bucket (1 page / minute) prevents
  Red-finding amplification from a single misbehaving agent.

#### Elevation of privilege

Deep-review issues **no inline blocking actions** — no proxy-side
veto, no auto-quarantine via identity, no pre-emptive HIL injection.
A compromised deep-review can only forge `deep_review_*` rows; the
brain → proxy → policy → ledger pipeline is unaffected by its
verdicts. Defense-in-depth.

### warden-hil

Pending → Approved/Denied/Expired state machine for Yellow-tier
requests.

#### Spoofing

| Threat | Defense |
|---|---|
| An attacker decides on a pending without approver auth. | OIDC + WebAuthn step-up gates `POST /pending/{id}/decide`. The HIL service requires a verified bearer for every state transition. The proxy never decides on its own behalf. |

#### Tampering

| Threat | Defense |
|---|---|
| An attacker modifies the `request_payload` between create and decide. | The payload is content-hashed into the chain on the `pending.created` row. The approver UI renders the hashed payload, so a mid-flight edit would mismatch the row. |
| An attacker modifies the verdict from Approved to Denied (or vice versa). | Each transition emits its own forensic event; the chain is the ground truth for what was decided. |

#### Repudiation

`decided_by` is anchored to the OIDC subject in chain v3 metadata. The
operator's identity is on the row.

#### Elevation of privilege

| Threat | Defense |
|---|---|
| An attacker auto-approves their own request. | OIDC + RBAC. The `approver` role is required to call `decide`. WebAuthn step-up adds a possession factor. |

### warden-identity

SVID issuance, OIDC delegation grants, per-action signing, SPIFFE
federation, agent registry / lifecycle.

#### Spoofing & Tampering

| Threat | Defense |
|---|---|
| An attacker calls `/sign` directly to mint a chain signature for a forged event. | `X-Caller-Spiffe` allowlist (`WARDEN_IDENTITY_SIGN_ALLOWED_CALLERS`). The identity service refuses signing requests from any SPIFFE ID not in the allowlist. |
| An attacker calls `/svid` to mint a cert for an arbitrary `agent_id`. | The agent registry (enforce mode) gates `/svid` on `(tenant, agent_name)` registration + lifecycle state. `unregistered_agent`, `agent_suspended`, `agent_decommissioned`, `scope_outside_envelope` all reject. |
| An attacker calls `/grant` to forge an OIDC delegation. | The IdP-issued bearer is verified against the trusted IdP's JWKS before any grant is minted. |
| An attacker mints an A2A token for a foreign tenant. | `/actor-token` is gated on `WARDEN_IDENTITY_SIGN_ALLOWED_CALLERS`. Cross-tenant minting requires the federation bundle exchange. |

#### Repudiation

Every lifecycle change (`agent.registered`, `suspended`, etc.) emits a
chain v3 row through the durable outbox (`agents_ledger.rs`). Identity
operator actions are anchored.

#### Information disclosure

Private keys never leave the identity service process — Ed25519
keypairs are loaded from `WARDEN_IDENTITY_SIGNING_KEY_PATH` at boot,
held in-memory only, exposed only as JWKS public material.

#### Denial of service

`/sign` is per-request signing — Ed25519 sign latency is sub-ms;
budgeted at p95 < 5ms in the perf test.

#### Elevation of privilege

A compromised identity service is the worst case — every chain
signature, every SVID, and every grant becomes attacker-controlled. The
ledger chain itself is recoverable (deterministic from the prev rows),
but the **signature** layer of v2/v3 is not. The deployment recovery
posture is: rotate the signing key, re-issue SVIDs, force every agent
to re-onboard. Documented in [Runbooks](#runbooks) "identity service
unreachable" with a follow-on "identity compromise" runbook
**TODO: write that runbook as a follow-on supply-chain slice.**

### warden-console

Operator UI. Reads ledger, drives HIL approve/deny, manages WAO
agent registry.

#### Spoofing & Tampering

| Threat | Defense |
|---|---|
| An attacker accesses the console without operator auth. | OIDC + WebAuthn (HIL holds passkeys; console proxies the ceremony). All routes except `/health` require an authenticated session. |
| An attacker abuses the `/sim` panel to flood the simulator. | The `/sim` panel only proxies to `WARDEN_SIMULATOR_URL`; the simulator's admin server is unauthenticated and only loopback-bound by default. In production deployments the simulator is not deployed. |
| An attacker tampers with the audit feed via SSE. | `/stream/audit` is read-only; the SSE stream is authenticated. |

#### Information disclosure

Console renders chain rows — same data classification as the ledger.
Multi-tenant: an operator from tenant A must not see tenant B's rows.
Today the console is single-tenant per deployment; multi-tenant is a
year-2 product question (out of scope, see "Out of scope" below).

### Cross-cutting concerns

#### Supply chain

| Threat | Defense |
|---|---|
| A malicious crate gets pulled into a service via a transitive dep. | `cargo-deny` advisories + sources gate every PR (`deny.toml` at every Rust repo root). `crates.io` is the only allowed source. SBOM (`cyclonedx`) is generated on every PR build and uploaded as a workflow artifact. |
| A copyleft-licensed crate sneaks in. | `cargo-deny` license allow-list — no GPL/AGPL/LGPL transitively allowed. Documented in `deny.toml` with rationale. |
| An advisory is filed against a crate we depend on after merge. | The PR gate runs on every push, so a new advisory will fail the next push. Operator-side: the SBOM artifact lets the security team grep for affected versions across all 14 repos at once. |

#### Operator authentication

The full operator surface lives in [Operator
authentication](#operator-authentication): OIDC for bootstrap,
WebAuthn for step-up on Yellow-tier approvals, basic-admin for solo
evaluation, RBAC, Slack / Teams self-link for cross-channel
identity, and viewer-or-better gates on every console read route.

#### Time

The proxy stamps RFC 3339 `current_time` on every policy input. Clock
skew between services is bounded by NTP; chain timestamps are operator
host clocks. Timestamp tampering is repudiation-class — defended by
the chain hash, not by the timestamp itself.

### Out of scope (and why)

These are **explicit non-goals** of the current threat model. The
threats are real but addressed elsewhere or deferred deliberately.

- **Insider threat from a fully compromised operator.** An operator
  with `admin` role + WebAuthn passkey can do anything an admin could
  do. The chain records what they did, but does not prevent it. This
  is a board / audit-committee concern, not a Warden control.
- **Physical access to the deployment host.** SQLite + private keys
  on disk; physical access defeats both. Customer's hosting
  responsibility.
- **Anthropic / Voyage / Qdrant compromise.** Brain depends on these
  external providers; they are explicit, named trust dependencies in
  `README.md`. A compromise of the upstream model is outside our
  defense scope but is partially mitigated by the Zero-Knowledge
  Bonus (Brain's model is separate from any agent's primary LLM).
- **Multi-tenant isolation in the console.** Today the console is
  single-tenant per deployment. Multi-tenant SaaS is a year-2
  product question.
- **Client-side typosquatting against `vanteguardlabs.com`.** Domain
  hygiene, not a Warden control.
- **DoS that requires resource limits the deployment guide already
  documents.** Operator's deployment configuration responsibility.

### Open items

The following threat-model gaps are tracked but not yet closed.

| Gap | Status |
|---|---|
| Internal s2s mTLS (proxy↔brain/policy/hil/identity). | Deferred service-mesh work; substrate choice (warden-identity SVID-based mTLS vs. mesh-layer at deploy time) depends on the deployment story. |
| Per-region key rotation runbook for `warden-identity`. | Tracked as a follow-on supply-chain slice (`TODO` in §"warden-identity" above). |
| Multi-tenant audit-log isolation in the console. | Year-2 product question. |

### Reporting

Report any threat that doesn't fit one of the above buckets — or
disagrees with the listed defense — to the address in `SECURITY.md`.
Reports that explicitly cite this document by section number make
triage faster.

---

## Runbooks


On-call response for the five "this paged me at 3am" failure modes.
Each runbook follows the same shape so the operator's eye lands in the
same place every time:

1. **Symptom** — what the alert / customer / dashboard is showing.
2. **Triage (≤5 min)** — quick checks to confirm the failure mode and
   contain blast radius.
3. **Diagnosis** — how to localize root cause.
4. **Remediation** — fix steps in priority order.
5. **Verification** — how to confirm recovery.
6. **Escalation** — who to page if remediation fails.

The observability stack (Prometheus `/metrics`, OTEL trace
export, JSON logs) is the source of truth — every runbook leads with
the metric or log line that confirms the failure rather than guessing
from symptoms. See `repos/warden-*/README.md` per service for the
metric catalogue.

---

### 1. Proxy crashed

**Symptom.** Agents see `connection refused` on `:8443`; the
`warden_proxy_requests_total` counter stops advancing; k8s liveness
probe failing (`/health` not 200).

**Triage.**
- Confirm process is gone, not hanging: `kubectl get pods -l app=warden-proxy` →
  CrashLoopBackOff or Error. If the pod is `Running` but `/health`
  is hanging, this is **not** a crash — see "Identity service unreachable"
  (proxy blocks on `/sign` if mis-configured) or check NATS.
- Confirm blast radius: is upstream traffic dropping for one tenant or
  the whole fleet? `kubectl logs --previous` for the last error.

**Diagnosis.** The proxy crashes loudly — `panic` lines in the previous
container's stderr. Three patterns we've actually seen:

| Stderr fragment | Cause | Fix |
|---|---|---|
| `failed to install rustls aws-lc-rs crypto provider` | Both `aws-lc-rs` and `ring` got pulled transitively and auto-selection panicked. | Code bug; the explicit `install_default()` at the top of `main` already fixes this. If it's back, a dependency upgrade reintroduced the conflict — pin transitively. |
| `failed to install tracer` | OTLP exporter init failed. Should not happen — the exporter buffers async. | Re-run with `OTEL_EXPORTER_OTLP_ENDPOINT` cleared; the default endpoint is unreachable but the exporter normally doesn't crash. File a bug. |
| `failed to load TLS certs` | `certs/` missing or expired in the pod. | Re-run `repos/warden-proxy/scripts/gen_certs.sh`; rotate via the helm secret. |

If none match, capture core / panic stack and treat as unknown.

**Remediation.**
1. Roll the pod: `kubectl rollout restart deploy/warden-proxy`.
2. If CrashLoopBackOff persists after 3 restarts, **roll back** to the
   previous image tag rather than debugging in production:
   `kubectl set image deploy/warden-proxy proxy=<prev-sha>`.
3. Once the previous image is up, root-cause on a non-prod pod.

**Verification.** `curl -k https://<proxy-host>:8443/health` returns
`{"status":"ok"}`; `warden_proxy_requests_total` resumes advancing.

**Escalation.** Page security on-call if certs are involved (rotation
gone wrong is a P1); dev on-call otherwise.

---

### 2. NATS down

**Symptom.** Ledger row count flat (`warden_ledger_chain_length` stops
advancing); `warden_ledger_nats_events_total` flat; proxy / policy /
hil / identity logs full of `NATS unreachable` / `forensic emission`
warnings; if the velocity tracker is on `nats-kv`, every policy
decision suddenly takes longer (it falls back to in-process per pod).

**Triage.**
- `kubectl get pods -l app=nats` — is the StatefulSet healthy?
- The Warden services **degrade gracefully** when NATS is unreachable:
  the proxy still serves `/`, brain still inspects, policy still
  decides, hil still queues. **Forensic events drop on the floor.**
  This is a P1 — the audit trail has a gap — but it is **not** a
  user-facing outage.

**Diagnosis.**
- `nats stream ls` from inside the cluster. If the JetStream stream
  for `warden_velocity` is missing/corrupt, the velocity tracker fell
  back to per-pod in-process counters; rate limits are now per-pod,
  not per-fleet.
- Disk pressure on the NATS PVC is the most common cause —
  `kubectl describe pod <nats>` and check `df` inside the container.

**Remediation.**
1. If disk-full, expand the PVC or evict cold streams.
2. If pod-level crash, `kubectl rollout restart statefulset/nats`.
3. **Do not** turn off the Warden services to "wait for NATS" — the
   degraded path is the supported path. The forensic gap during the
   outage is acceptable and visible (publish counter flat).

**Verification.** Trigger a request through the proxy; confirm a new
ledger row appears within a few seconds (NATS publish → ledger
subscriber → SQLite). `nats stream info` shows the velocity bucket
healthy.

**Escalation.** SRE on-call. Page security if forensic gap exceeds 1
hour — that's a compliance-relevant audit hole that needs an
incident report.

---

### 3. Ledger chain invalid

**Symptom.** `GET /verify` on warden-ledger returns
`{"valid": false, ...}` with a specific bad-row index; the
`mixed_v1_v2_chain_verifies_clean_with_jwks` integration test fails in
CI; an export Iceberg snapshot's `warden.parquet-sha256` doesn't
match its own data.

**Triage. Snapshot the DB before doing anything.**
```bash
kubectl exec -it <ledger-pod> -- sqlite3 /var/lib/warden/ledger.db ".backup /tmp/ledger-snapshot.db"
kubectl cp <ledger-pod>:/tmp/ledger-snapshot.db ./ledger-snapshot-$(date +%Y%m%d-%H%M).db
```

Chain invalidity is **either** a code bug **or** a tampering event.
Both require the original DB intact for forensics. **Do not** truncate,
re-init, or re-replay the chain until snapshot is captured.

**Diagnosis.** `verify_chain` returns the first bad seq and the
expected vs computed `entry_hash`. From there:

- **Chain-version mismatch.** If the bad row's stored
  `chain_version` is unknown to this build, an older deploy wrote a
  row in a future format. Look for a `unsupported_chain_version`
  signal in the `signal` column. Fix: deploy the build that
  understands `CURRENT_CHAIN_VERSION`.
- **Field-order regression.** Someone reordered fields in
  `HashableEntryV{1,2,3}`. The recompute will succeed but produce a
  different hash. Code review will catch it; CI verifies via the
  `mixed_v1_v2_chain_verifies_clean_with_jwks` test. Fix: revert.
- **Genesis pruned without cursor.** If
  `verify_chain` complains the first row's `prev_hash` is not all
  zeros and `chain_vacuum_cursor` is empty, an older vacuum ran
  before the cursor was added. Fix: backfill the cursor from the
  most-recent export's `expected_prev`.
- **Tampering.** Stored `entry_hash` differs from recomputed; no
  schema change explains it. **This is a security incident.** Stop —
  do not remediate; preserve evidence; page security lead.

**Remediation (non-tampering only).**
1. Identify the bug class above.
2. Patch and redeploy.
3. The hash chain is append-only by design — *do not* edit historic
   rows. If a row was written under a buggy build, the canonical move
   is to add a *new* row that supersedes it (audit trail intact, fix
   is forward-only).

**Verification.** `GET /verify` returns `{"valid": true}` end-to-end;
the `mixed_v1_v2_chain_verifies_clean_with_jwks` integration test
passes; export pipeline produces a fresh Iceberg snapshot with a
matching `warden.parquet-sha256`.

**Escalation.** Security lead **immediately** if tampering is
suspected; dev lead otherwise. The regulatory-export surface is the
audience that cares — they get the chain hash as the integrity proof.

---

### 4. HIL queue stuck

**Symptom.** `/agents` console page or `warden_hil_pending_count_gauge`
shows pending count climbing without ceiling; approvers reporting
they can't approve / deny; agents seeing 403 with `hil_timeout`
after the proxy long-poll caps; Slack/Teams approval cards stop
arriving.

**Triage.**
- Confirm the HIL service itself is up: `curl http://<hil>:8084/healthz`.
- Confirm the pending count is *climbing* vs *stuck*: `select count(*)
  from pending_requests where status='pending'` on two consecutive
  minutes. Climbing → throughput problem; flat-but-non-zero → either
  approvers AWOL or something blocking decisions.

**Diagnosis.** Three failure modes:

- **Approver auth broken.** Console `/auth/login` 5xx, or `/decide`
  rejects with `unauthorized`. Causes: WebAuthn config drift
  (`WARDEN_HIL_RP_ID` / `RP_ORIGIN` mismatched after a domain change),
  session cookie mis-configured (`COOKIE_SECURE=true` on a non-HTTPS
  origin). Fix: re-confirm env vars match the deployment hostname.
- **Notifier broken.** Slack/Teams card delivery silently failing;
  approvers don't know there's work. Confirm via
  `warden_hil_notifications_total{outcome="error"}`. Causes: webhook
  URL rotated, network egress blocked. Fix: rotate webhook secret.
- **Sweeper stalled.** TTL-based expiry not running, so old pendings
  pile up. `warden_hil_sweep_total` should advance every
  `WARDEN_HIL_SWEEP_INTERVAL_SECS`. If flat: check sweeper task panic
  in the pod logs.

**Remediation.**
1. **Drain emergency.** If pendings are blocking real customer work,
   set `WARDEN_HIL_AUTH_DISABLED=true` on a single HIL pod, drain the
   queue from the console (`/agents` lets a logged-in operator approve
   in bulk), then re-enable auth. **Audit trail keeps the
   `decided_by` of the operator who hit the bypass — the bypass is
   visible, not invisible.**
2. **Notifier outage.** Rotate the webhook URL via the helm secret
   and roll the pod.
3. **Sweeper stuck.** Roll the pod; the sweeper restarts on boot.

**Verification.** Pending count drops; new pendings reach `approved` /
`denied` / `expired` within their TTL; Slack/Teams cards posting
again.

**Escalation.** SRE on-call. If a Yellow-tier wire transfer expired
because of approver outage, that's a customer-visible business event
— page the on-call business stakeholder per the customer's runbook.

---

### 5. Identity service unreachable

**Symptom.** Proxy logs flooded with `signing_unavailable` /
`a2a_unavailable` warnings; chain v2 rows stop appearing (only v1 +
v3 lifecycle rows continue); SVID renewals failing; cross-tenant
A2A traffic rejecting with `peer_bundle_unknown` /
`peer_bundle_stale`.

**Triage.**
- `curl http://<identity>:8086/healthz` — is the service up?
- `curl http://<identity>:8086/readyz` — does the readiness probe
  flag a backend (SQLite, NATS, Vault)?
- The proxy **degrades gracefully** when identity is unreachable: it
  emits chain v1 rows (no `agent_spiffe` / `signature` / `key_id`)
  and rejects A2A inbound with 403. Local same-tenant traffic
  continues to flow. Cross-tenant traffic and signed-chain integrity
  are paused, **not the data plane.**

**Diagnosis.**
- **Process down.** Pod restart loop. Check `kubectl logs --previous`.
- **Vault Transit unreachable.** `/sign` returns 503
  `signing_unavailable` from the warm path; readiness probe should
  flag it. Vault outage is a higher-priority page than identity
  itself — the signer is the dependency.
- **SQLite db locked.** Concurrent write contention; rare but seen
  on hot-restart races. Logs will say `database is locked`.
- **Federation peer drifted.** The federation poller marks a peer
  bundle stale after `WARDEN_FEDERATION_POLL_TTL_SECS` without a
  successful refresh. Confirm via the bundle endpoint of the peer
  and the local poller's log.

**Remediation.**
1. **Vault outage** is the most common root cause — page Vault
   on-call. Identity will recover automatically when Vault returns.
2. **Process crash.** `kubectl rollout restart deploy/warden-identity`.
   The outbox in `agents_ledger.rs` is durable, so chain v3 lifecycle
   rows resume from where they left off without dropping events.
3. **Federation drift.** Force-refresh the peer bundle:
   `wardenctl federation refresh <trust_domain>`. If the peer
   themselves have outaged their bundle endpoint, this is a
   cross-tenant escalation.

**Verification.** Proxy logs `identity wired to Vault Transit signer`
and stops emitting `_unavailable` warnings; chain v2 rows resume in
the ledger; `/svid` issues a fresh SVID end-to-end (test with the
chaos-monkey `attestation_signed` scenario).

**Escalation.** Vault on-call first if Vault is the dependency that
broke; security on-call second; dev on-call last. The identity service
is on the trust-chain hot path so an outage longer than 1 hour is a
P0 — chain v2 signature gap will require a forensic explanation.
