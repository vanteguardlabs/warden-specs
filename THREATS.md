# Threat Model

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
`CLAUDE.md` (`Cross-repo wire contracts`), `IDENTITY.md`, and
`ONBOARDING.md` for the system shape this model is grounded in.
Re-verify against `git log` if the model and the code disagree; code
wins.

## Trust boundaries

```
                            ┌────────────────────────┐
                            │   Operator             │  human, browser, mTLS
                            │  (console / wardenctl) │
                            └────────────┬───────────┘
                                         │ HTTPS + bearer (E1 OIDC)
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
- **OIDC IdP** (E1 / WAO) — operator and capability-resolver auth.
- **The operator's browser session** — console SSE + htmx + WebAuthn.

## Layer 1 — warden-proxy

The proxy is the single ingress for agent traffic. Everything else is
defense-in-depth behind it.

### Spoofing

| Threat | Defense |
|---|---|
| An unauthenticated agent calls the proxy. | mTLS-only — `WebPkiClientVerifier` validates the cert chain against the proxy's CA root before any handler runs. |
| An agent presents a peer's certificate (replay). | The proxy's TLS stack only accepts the cert if the private key is held by the connecting peer (TLS finished MAC). Stolen private keys are still a real threat → defended at Layer 6 (identity P3 signing + per-action JTI). |
| An agent forges an SVID by editing the SAN URI. | The SAN is bound to the cert by the issuing CA's signature. A forged SAN means a forged cert means chain verification fails. |
| A peer Warden cell mints an A2A token for a tenant it doesn't own. | `warden-identity` `/actor-token/redeem` consults the federation bundle and rejects with `peer_bundle_unknown:<td>` if the issuer isn't in the configured peer set. |

### Tampering

| Threat | Defense |
|---|---|
| Network MitM modifies the JSON-RPC body in flight. | mTLS provides record-layer integrity. Plaintext is never on the wire. |
| An agent edits the `source` header to claim simulator origin. | `source` is metadata only, **not in the hashable**. Documented as untrusted in `CLAUDE.md`. The console's "hide simulated traffic" filter is convenience, not authorization. |
| An agent sets `x-warden-actor-token` to bypass A2A verification. | Tokens are JWTs signed by the issuing identity; signature verification is what makes the bypass attempt fail, not the absence of the header. |

### Repudiation

| Threat | Defense |
|---|---|
| An agent claims it never made a request. | Every verdict emits a forensic event keyed on a UUIDv4 `correlation_id`. The chain v2/v3 entries carry per-action signatures from `warden-identity` `/sign`, so the agent's identity is cryptographically anchored to each entry. |

### Information disclosure

| Threat | Defense |
|---|---|
| Vault credentials leak through proxy logs. | The proxy never logs the credential value; it injects via the upstream HTTP request's headers and discards. Code path: `forward_upstream`. |
| Brain/policy verdicts leak across tenants in shared logs. | All logs are `correlation_id`-tagged; `agent_id` and `tenant` are present. Multi-tenant log separation is the operator's responsibility (Loki / OTLP collector tenant labels). |

### Denial of service

| Threat | Defense |
|---|---|
| An agent floods `handle_mcp` to exhaust upstream quota. | `warden-policy-engine`'s velocity tracker (`InProcessTracker` or `NatsKvTracker`) breaks the circuit per-agent on configurable thresholds. |
| Brain/Anthropic call latency cascades. | Brain has per-call timeout + Voyage embedding fallback. Policy verdict resolves even if Brain is slow (`authorized=false` defaults to `intent_score=0.5`, which fails the policy gate — fail-closed). |
| Slowloris on the mTLS handshake. | axum's hyper backend has connection-level read timeouts. |

### Elevation of privilege

| Threat | Defense |
|---|---|
| An agent escalates from auto-allow tier to wire-transfer tier by altering the JSON-RPC `method`. | Policy rego is keyed on `tool_type`, which the proxy derives from `method` — not from any agent-supplied field. The mapping table is server-side. |
| An agent bypasses HIL by abandoning the long-poll. | `forward_upstream` only fires on `Authorized` or HIL-Approved. A timed-out long-poll resolves to 403, never auto-Approve. |

## Layer 2 — warden-brain

Semantic inspection. Three signals: intent classifier (Haiku), persona
drift (Haiku), indirect-injection scanner (Haiku + heuristic).

### Spoofing & Tampering

The Brain is called only by the proxy over an in-cluster network — the
trust boundary is the proxy-brain link. We don't run mTLS on this link
today; the assumption is the deployment perimeter (compose network /
k8s NetworkPolicy) is the perimeter.

→ **Action item, tracked under E1.5 (s2s service mesh):** add SPIFFE
mTLS to the proxy↔brain, proxy↔policy, proxy↔hil, proxy↔identity links
so an attacker who lands on the cluster's overlay network cannot speak
directly to the brain and forge `BrainRequest` payloads.

### Repudiation

Brain verdicts are emitted by the proxy (the proxy publishes the
forensic event after deriving the `authorized && policy_decision.allow`
final verdict). If brain misbehaves, that's recoverable from the
proxy-side forensic row. Brain itself is stateless.

### Information disclosure

The Brain calls **Anthropic Claude 4.5 Haiku** (separate model from any
agent's primary LLM — the "Zero-Knowledge Bonus" invariant). Sensitive
payloads transit the Anthropic API. This is an explicit, documented
trust dependency in `README.md`.

The mock-mode path (`ANTHROPIC_API_KEY=mock-key`) does pure local regex
+ bigram embedding inspection — used by e2e and the simulator.

### Denial of service

Brain has a per-request timeout in the proxy. A slow Anthropic API does
not stall the security verdict indefinitely.

### Elevation of privilege

A compromised brain that returns `authorized=true` for everything would
fail-open at L2 only — Layer 3 (policy) still has independent veto, and
Layer 4 (ledger) still records the verdict. Defense-in-depth.

## Layer 3 — warden-policy-engine

Pure-Rust Rego (`regorus`) over `policies/*.rego`. Policy data is
file-system-loaded.

### Tampering

| Threat | Defense |
|---|---|
| An attacker modifies `policies/*.rego` on disk. | Filesystem ACLs are the only control; the helm chart deploys policies as a configmap. Tamper detection is operator-side (file integrity monitoring). Policy changes show up in `git log` for audit. |
| Policy evaluation is influenced by `current_time` from the request. | The proxy stamps `current_time` (RFC 3339) explicitly. The rego fallback `time.now_ns()` only fires for non-proxy callers (tests). An attacker who fakes the proxy stamp is already past the Layer-1 boundary. |

### Information disclosure

Policy-engine logs `correlation_id` + `agent_id` + `tool_type`. No
sensitive payload content is logged.

### Denial of service

Velocity tracker is bounded — `InProcessTracker` is a `HashMap<String,
VecDeque<Instant>>` with bounded retention; `NatsKvTracker` uses
JetStream KV with a per-key CAS update loop. A pathological attack pattern
(e.g. millions of distinct agent IDs) would grow the in-process map.
NATS-KV backend rebalances under JetStream's own retention policy.

### Elevation of privilege

Pure Rego cannot escape the policy engine. `regorus` is sandboxed —
no host bridge.

## Layer 4 — warden-ledger

SHA-256 hash-chained, SQLite-backed forensic store. Subscribes to
`warden.forensic` on NATS.

### Tampering

| Threat | Defense |
|---|---|
| An attacker edits a row in the SQLite DB directly. | The hash chain detects it on the next `verify_chain` call — every entry's `entry_hash` covers the previous `prev_hash`, so any single-row edit invalidates every later row. Operator runbook (`RUNBOOKS.md` "ledger chain invalid") covers detection. |
| An attacker adds a row claiming a forensic event that never happened. | Same — the new row has to satisfy the chain or it's detected. Chain v2/v3 rows carry per-action signatures from `warden-identity` `/sign`; an attacker forging both the chain and the signature needs the identity service's signing key. |
| An attacker replays a NATS forensic message. | NATS at-least-once semantics already mean the ledger may see duplicate publishes. Each `LogRequest` is content-hashed; duplicate appends produce identical `entry_hash`, which `record_entry` deduplicates by `(correlation_id, source_layer)`. |

### Repudiation

The chain is append-only and signed. The export bundle (planned E6
deliverable) is the long-term audit artifact.

### Information disclosure

Ledger rows carry intent, tool type, agent, verdict — not the raw
JSON-RPC body. The hashable explicitly excludes `signal` and `source`.

### Denial of service

Append throughput is SQLite-bounded. NATS subscriber is single-threaded
by design (chain order matters). Operator runbook covers backlog
diagnosis.

## warden-hil

Pending → Approved/Denied/Expired state machine for Yellow-tier
requests.

### Spoofing

| Threat | Defense |
|---|---|
| An attacker decides on a pending without approver auth. | E1 OIDC + WebAuthn step-up gates `POST /pending/{id}/decide`. The HIL service requires a verified bearer for every state transition. The proxy never decides on its own behalf. |

### Tampering

| Threat | Defense |
|---|---|
| An attacker modifies the `request_payload` between create and decide. | The payload is content-hashed into the chain on the `pending.created` row. The approver UI renders the hashed payload, so a mid-flight edit would mismatch the row. |
| An attacker modifies the verdict from Approved to Denied (or vice versa). | Each transition emits its own forensic event; the chain is the ground truth for what was decided. |

### Repudiation

`decided_by` is anchored to the OIDC subject in chain v3 metadata. The
operator's identity is on the row.

### Elevation of privilege

| Threat | Defense |
|---|---|
| An attacker auto-approves their own request. | OIDC + RBAC. The `approver` role is required to call `decide`. WebAuthn step-up adds a possession factor. |

## warden-identity

SVID issuance, OIDC delegation grants, per-action signing, SPIFFE
federation, agent registry / lifecycle.

### Spoofing & Tampering

| Threat | Defense |
|---|---|
| An attacker calls `/sign` directly to mint a chain signature for a forged event. | `X-Caller-Spiffe` allowlist (`WARDEN_IDENTITY_SIGN_ALLOWED_CALLERS`). The identity service refuses signing requests from any SPIFFE ID not in the allowlist. |
| An attacker calls `/svid` to mint a cert for an arbitrary `agent_id`. | The agent registry (WAO P5 — enforce mode) gates `/svid` on `(tenant, agent_name)` registration + lifecycle state. `unregistered_agent`, `agent_suspended`, `agent_decommissioned`, `scope_outside_envelope` all reject. |
| An attacker calls `/grant` to forge an OIDC delegation. | The IdP-issued bearer is verified against the trusted IdP's JWKS before any grant is minted. |
| An attacker mints an A2A token for a foreign tenant. | `/actor-token` is gated on `WARDEN_IDENTITY_SIGN_ALLOWED_CALLERS`. Cross-tenant minting requires the federation bundle exchange. |

### Repudiation

Every lifecycle change (`agent.registered`, `suspended`, etc.) emits a
chain v3 row through the durable outbox (`agents_ledger.rs`). Identity
operator actions are anchored.

### Information disclosure

Private keys never leave the identity service process — Ed25519
keypairs are loaded from `WARDEN_IDENTITY_SIGNING_KEY_PATH` at boot,
held in-memory only, exposed only as JWKS public material.

### Denial of service

`/sign` is per-request signing — Ed25519 sign latency is sub-ms;
budgeted at p95 < 5ms in the perf test.

### Elevation of privilege

A compromised identity service is the worst case — every chain
signature, every SVID, and every grant becomes attacker-controlled. The
ledger chain itself is recoverable (deterministic from the prev rows),
but the **signature** layer of v2/v3 is not. The deployment recovery
posture is: rotate the signing key, re-issue SVIDs, force every agent
to re-onboard. Documented in `RUNBOOKS.md` "identity service
unreachable" with a follow-on "identity compromise" runbook
**TODO: write that runbook as part of the next E5 slice.**

## warden-console

Operator UI. Reads ledger, drives HIL approve/deny, manages WAO
agent registry.

### Spoofing & Tampering

| Threat | Defense |
|---|---|
| An attacker accesses the console without operator auth. | E1 OIDC + WebAuthn (HIL holds passkeys; console proxies the ceremony). All routes except `/health` require an authenticated session. |
| An attacker abuses the `/sim` panel to flood the simulator. | The `/sim` panel only proxies to `WARDEN_SIMULATOR_URL`; the simulator's admin server is unauthenticated and only loopback-bound by default. In production deployments the simulator is not deployed. |
| An attacker tampers with the audit feed via SSE. | `/stream/audit` is read-only; the SSE stream is authenticated. |

### Information disclosure

Console renders chain rows — same data classification as the ledger.
Multi-tenant: an operator from tenant A must not see tenant B's rows.
Today the console is single-tenant per deployment; multi-tenant is a
year-2 product question (out of scope, see "Out of scope" below).

## Cross-cutting concerns

### Supply chain

| Threat | Defense |
|---|---|
| A malicious crate gets pulled into a service via a transitive dep. | `cargo-deny` advisories + sources gate every PR (`deny.toml` at every Rust repo root). `crates.io` is the only allowed source. SBOM (`cyclonedx`) is generated on every PR build and uploaded as a workflow artifact. |
| A copyleft-licensed crate sneaks in. | `cargo-deny` license allow-list — no GPL/AGPL/LGPL transitively allowed. Documented in `deny.toml` with rationale. |
| An advisory is filed against a crate we depend on after merge. | The PR gate runs on every push, so a new advisory will fail the next push. Operator-side: the SBOM artifact lets the security team grep for affected versions across all 14 repos at once. |

### Operator authentication

E1 covers the full operator surface: OIDC for bootstrap, WebAuthn for
step-up on Yellow-tier approvals, basic-admin role for agent
lifecycle, RBAC, Slack/Teams self-link for cross-channel identity.
Viewer-route gating remains open (E1 mod viewer-route — see
`ROADMAP.md`).

### Time

The proxy stamps RFC 3339 `current_time` on every policy input. Clock
skew between services is bounded by NTP; chain timestamps are operator
host clocks. Timestamp tampering is repudiation-class — defended by
the chain hash, not by the timestamp itself.

## Out of scope (and why)

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
  product question (see `ROADMAP.md` "Out of scope").
- **Client-side typosquatting against `vanteguardlabs.com`.** Domain
  hygiene, not a Warden control.
- **DoS that requires resource limits the deployment guide already
  documents.** Operator's deployment configuration responsibility.

## Open items

The following threat-model gaps are tracked but not yet closed. Each
maps to a roadmap epic where the work happens.

| Gap | Owner |
|---|---|
| Internal s2s mTLS (proxy↔brain/policy/hil/identity). | `ROADMAP.md` E1.5 |
| Per-region key rotation runbook for `warden-identity`. | E5 (next slice) |
| Multi-tenant audit-log isolation in the console. | Year-2 product |
| Regulatory export (EU AI Act 11/12) bundle integrity. | E6 |

## Reporting

Report any threat that doesn't fit one of the above buckets — or
disagrees with the listed defense — to the address in `SECURITY.md`.
Reports that explicitly cite this document by section number make
triage faster.
