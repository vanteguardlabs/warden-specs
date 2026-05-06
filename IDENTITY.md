# Warden Identity (WI) — Technical Specification

Companion spec to `README.md` §11.3 ("Agent identity — IAM for bots"). Scoped to what §11.3 commits to and grounded in the primitives Warden already ships (NATS forensic bus, hash-chained ledger, HIL, `regorus` policy engine).

**Module status:** **shipped** (P0–P5). Touches `warden-proxy`, `warden-policy-engine`, `warden-ledger`, `warden-hil`; introduced the `warden-identity` service (port 8086). The companion onboarding spec `ONBOARDING.md` (WAO P1–P5, also shipped) layers the agent-registry / lifecycle / capability-envelope work on top of these primitives.

## 1. What §11.3 actually commits to

The spec promises three capabilities. Restated as testable claims:

| Spec bullet | Operational claim |
|---|---|
| OIDC / SPIFFE federation | Every agent has a verifiable workload identity bound to a human/team/tenant principal. Agent-to-agent calls require a Warden-mediated handshake, not just transport mTLS. |
| Digital signatures for actions | Every Authorized or HIL-Approved tool call produces a Warden-issued, ledger-anchored signature over `(agent_id, correlation_id, method, request_payload, verdict, prev_hash)`. The signature is the legal proof. |
| Capability attestation | Sensitive tools (Yellow tier and a configurable allowlist) require fresh evidence the agent's runtime is unmodified — TPM/SGX quote, or remote-attestation token from a managed runtime. |

Identity, in Warden's threat model, is **necessary but insufficient** (§13.1). WI's job is not to replace Brain/Policy/HIL — it is to make the `agent_id` field they all key off of cryptographically meaningful end-to-end.

## 2. Threat model (in scope)

| # | Threat | Today | After WI |
|---|---|---|---|
| T1 | Stolen client cert replayed from a different host | Proxy accepts it (CN trusted unconditionally) | Cert short-TTL (≤1h) + attested issuance; replay window collapses |
| T2 | Agent A impersonates Agent B in an A→B call | No A2A check today; Brain sees the *receiving* agent's view only | SVID-bound `actor_token` + audience binding rejects mismatch |
| T3 | Compromised supply chain: agent binary swapped post-deploy | Undetected | Capability attestation gates Yellow-tier tools |
| T4 | Insider replays a ledger row claiming "the agent did it" | Possible — `agent_id` is not signed by the agent, only stamped by the proxy | Per-action signature chain anchored to ledger `prev_hash` provides non-repudiation |
| T5 | Human user repudiates an HIL approval ("not me") | WebAuthn approver auth (Tier 3, open) covers approver side | WI binds the *delegation* user→agent so the agent's own action is also non-repudiable |

**Out of scope:** governing the human IdP itself (delegate to Okta/Entra), key custody for the issuing CA (delegate to Vault Transit / KMS), cross-tenant federation v1 (single-tenant first).

## 3. Identity model

### 3.1 Names

```
spiffe://<trust-domain>/tenant/<tid>/agent/<agent-name>/instance/<uuidv7>
```

- `tenant/<tid>` — billing/isolation boundary; matches the existing `agent_id` prefix convention used by the simulator.
- `agent/<agent-name>` — stable logical identity (e.g. `support-bot-3`). This is what policy rules and Brain's persona-drift baseline key off.
- `instance/<uuidv7>` — per-process; rotates on restart. Lets us revoke a single misbehaving replica without grounding the fleet.

The existing `MtlsIdentity.cn` becomes a *projection* of this SPIFFE ID for backwards compatibility — the proxy parses the SAN URI and falls back to CN only for legacy clients during a deprecation window.

### 3.2 Principals and delegation

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

### 3.3 Federation

- **Inbound (humans → Warden):** OIDC. Warden trusts an enterprise IdP for human auth; the IdP's `id_token` is exchanged at `warden-identity` for a delegation grant via OAuth 2.0 Token Exchange (RFC 8693).
- **Outbound (agents → other Warden tenants):** SPIFFE federation bundle. Tenant A's trust bundle is published at `https://identity.<tenant-a>/.well-known/spiffe-bundle`; Tenant B's identity service polls it. Cross-tenant A2A becomes possible without sharing a CA.

## 4. The new service: `warden-identity`

Standalone Rust service, port 8086. It is the only component allowed to mint SVIDs and delegation grants. It is a NATS forensic publisher for issuance/revocation events, so the ledger has a row for every cert minted.

### 4.1 HTTP surface

| Method | Path | Purpose | Auth |
|---|---|---|---|
| `POST` | `/svid` | Issue an instance SVID against an attestation document | Attestation evidence (§6) |
| `POST` | `/grant` | Exchange OIDC `id_token` + agent SVID → delegation grant | OIDC `id_token` + SVID mTLS |
| `POST` | `/actor-token` | Mint an audience-bound A→B token | Caller SVID + grant |
| `POST` | `/sign` | Warden-side signing of a finalized verdict (§5) | Proxy SVID only |
| `POST` | `/revoke` | Revoke an instance or grant | Operator WebAuthn |
| `GET`  | `/jwks.json` | Public keys for grant/actor-token verification | Public |
| `GET`  | `/.well-known/spiffe-bundle` | SPIFFE federation bundle | Public |

### 4.2 Storage

SQLite, mirroring the ledger's "boring + auditable" stance:

- `svids` (id, spiffe_id, attestation_id, not_before, not_after, revoked_at)
- `grants` (jti, agent_spiffe, human_sub, scope_json, yellow_scope_json, exp, revoked_at)
- `attestations` (id, kind {tpm-quote, sev-snp, sgx-dcap, gcp-tpm, aws-nitro, k8s-projected}, evidence_blob, verified_at, policy_version)

No JSON in queryable columns where it can be a column — we want SQL-grep-able audits.

### 4.3 Keys

Issuer keys live in **Vault Transit** (Warden already runs Vault for credential injection). The identity service never holds private key material in-process — it calls `transit/sign/<key>` over the existing Vault client. Rotation is Vault-driven.

## 5. Action signing & ledger anchoring

This is the highest-value bullet — non-repudiation is what unlocks the §15 "trust dividend" insurance story.

### 5.1 What gets signed

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

### 5.2 What the signature is *over*

`sha256(prev_hash || "|" || canonical_json(hashable_v2_minus_signature))` — the same shape as the chain hash, signed with the issuer key. This means:

- The signature transitively commits to *all prior ledger state* via `prev_hash`.
- Tampering with any historical row breaks the signature on every later row, not just the chain hash. Two-layer integrity.
- A regulator reproducing the chain only needs Warden's JWKS + the ledger export — no live service.

### 5.3 What is *not* signed

`source` (client-controlled metadata, not in hashable) and any HIL approver identity that is not yet cryptographic. WebAuthn-backed approver signatures are the natural follow-on, but they sign a *separate* HIL state-transition event, not the proxy's verdict event.

## 6. Capability attestation

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

## 7. Wire-contract changes

Shared types are duplicated on each side of the wire. The fields below need to land **simultaneously** in both repos of each pair:

| Edge | Field added | Repos to grep |
|---|---|---|
| Proxy → Brain | `agent_spiffe: String` | `warden-proxy/src/fork.rs`, `warden-brain/src/lib.rs` |
| Proxy → Policy | `agent_spiffe: String`, `attestation: Option<AttestationClaims>` | `warden-proxy/src/fork.rs`, `warden-policy-engine/src/lib.rs` |
| Proxy → HIL | `agent_spiffe: String`, `delegation_jti: String` | `warden-proxy/src/sandbox_handoff.rs` (CreatePending site), `warden-hil/src/api.rs` |
| Proxy → Ledger (NATS) | `agent_spiffe`, `signature`, `key_id` (chain v2) | `warden-proxy`, `warden-ledger/src/chain.rs` |

Console (`warden-console`) needs a "Delegation: alice@acme via support-bot-3" badge on every audit row — wire it through the existing correlation-id join.

## 8. Failure & fallback semantics

| Failure | Behaviour | Reasoning |
|---|---|---|
| `warden-identity` unreachable on `/sign` | Proxy fails *closed* on Yellow-tier and any tool with `attestation_required`; fails *open* (no signature, ledger v1 row) on Authorized non-attested calls, with a `signing_unavailable` signal in Brain's signal aggregator | Don't take the whole stack down because a non-critical service blips; do refuse to sign forged-checks-from-the-future |
| Attestation expired mid-burst | Proxy returns 401 with `attestation_stale`; agent re-attests | Same model as expired SVID |
| Vault Transit unavailable | Identity service degrades to `signing_unavailable` (above) | Single failure domain — Vault is already a hard dep |
| Federation bundle stale (cross-tenant) | Reject A2A; allow same-tenant | Matches the §13.1 "identity is necessary but insufficient" framing — better to fail safe |

## 9. Migration & rollout

Five phases, each independently shippable. **All five shipped.**

1. **SVID issuance, no enforcement.** *(shipped)* `warden-identity` mints SVIDs alongside the existing CA. Proxy parses the SPIFFE SAN from the cert and falls back to CN for legacy clients.
2. **Delegation grants.** *(shipped)* `/grant` exchange wired; HIL records the delegation principal on pending rows; proxy threads `X-Warden-Grant` through and rejects expired grants with `grant_expired`.
3. **Action signing (chain v2).** *(shipped)* Ledger gained v2 dispatch (`HashableEntryV2` with `agent_spiffe`, `signature`, `key_id`); proxy calls `/sign` after the verdict resolves; verifier exposes JWKS-based per-row signature check; mixed-v1/v2 export verifies.
4. **Attestation enforcement.** *(shipped)* `policies/attestation.rego` ships with `attestation_required` rules keyed on `wire_transfer` and `delete_*`; `attestation_allowlist.json` carries the per-tool measurement list; proxy attaches `AttestationClaims` (with a per-spiffe-id cache and `X-Warden-Attestation` per-request header override) on every `/evaluate`; chaos-monkey `unattested_binary` asserts deny.
5. **Cross-tenant federation.** *(shipped)* SPIFFE bundle endpoint at `GET /.well-known/spiffe-bundle`; `/actor-token` mint + `/actor-token/redeem` with peer-bundle freshness gate (`peer_bundle_unknown:<td>` / `peer_bundle_stale:<td>`); federation poller; two-tenant `run-federation.sh` e2e in `warden-e2e`.

The §11.3 valuation claim (⭐⭐⭐⭐⭐, "zero-trust score" metric) and the §15 trust-dividend story are both unblocked.

## 10. Test surface

- **`warden-e2e`** gains: SVID issuance happy path; revocation kills next request within 1s; signed-row chain verification against a regulator-style export.
- **`warden-chaos-monkey`** gains: `stolen_svid_replay`, `unattested_binary`, `expired_grant`, `cross_tenant_unfederated`. All four must produce specific, predicted verdicts.
- **`warden-simulator`** gains a `--delegation-mix` flag so persona-driven traffic spans multiple human principals — needed to make the console demo look real.

## 11. What this spec deliberately does not include

- A bespoke PKI. We use SPIFFE + Vault Transit because they exist and are audited.
- A new HIL approver flow. WebAuthn approver auth is the existing Tier 3 ticket; this spec only ensures the *agent side* of the delegation is cryptographic. Both sides land independently.
- A custom revocation mechanism. Short-TTL SVIDs (≤1h) + grant `jti` denylist published over NATS is enough. CRLs are a 1990s answer to a 2026 problem.
- A new audit UI. The console's existing `/audit` correlation-id join is the right shape; we just add three columns.
