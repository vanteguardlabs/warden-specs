# Warden Agent Onboarding (WAO) — Technical Specification

Companion to `IDENTITY.md`. Where `IDENTITY.md` covers how a *running* agent gets a cryptographic identity (SVID, grant, action signature, attestation), this spec covers the missing pre-step: how an agent gets *registered with the platform* in the first place — who declared it should exist, with what capabilities, owned by which team — and how that record gates every downstream identity operation.

**Module status:** new, Tier 3 hardening backlog. Extends `warden-identity` (no new service); introduces a new top-level CLI binary `wardenctl`; extends `warden-console` and `warden-ledger` (chain v3); touches `warden-e2e` and `warden-chaos-monkey`. Depends on the issuance, signing, and chain-version-negotiation primitives shipped in the `IDENTITY.md` P0–P3 + P5 work.

## 1. What this closes

`IDENTITY.md` makes the `agent_id` field cryptographically meaningful end-to-end. It does not say where the field comes from. Today, `POST /svid` mints an instance cert for *any* `(tenant, agent_name)` pair as long as attestation passes — first call wins. `POST /grant` accepts arbitrary opaque scope strings from the caller. There is no record of "this agent should exist, owned by this human/team, scoped to these capabilities" prior to issuance.

The operational consequences:

| Gap | Today | After WAO |
|---|---|---|
| Namespace squat | Any compromised attestor can claim `wire-transfer-bot` and the platform issues | `(tenant, agent_name)` must be pre-registered or `/svid` rejects (in `enforce`) |
| Capability sprawl | `/grant` honors any scope string Brain/Policy hasn't explicitly denied | `/grant` rejects scopes outside the agent's registered envelope |
| Audit lineage | Chain shows "Alice's bot did X." Nobody can prove Alice ever said the bot should exist | Chain shows "Alice declared `support-bot-3` exists with envelope Y on date D" alongside every later verdict row, both signed |
| Incident lever | Only kill-switch is to revoke the SVID and refuse to mint a new one — terminal | Suspend (reversible, blocks new SVIDs + revokes existing) and decommission (terminal, name unreusable) |
| Routing accountability | `agent_id` is opaque to HIL approvers; "who owns this agent" is tribal knowledge | HIL pending rows carry `owner_team` and registering human; envelope shown inline so approvers can see the action is in-envelope |

The capability envelope is the load-bearing primitive. Without it, registration is namespace-only and adds nothing the chain doesn't already have. With it, the chain transitively binds *what was authorized* to *what was done*.

## 2. Threat model (in scope)

| # | Threat | Today | After WAO |
|---|---|---|---|
| T1 | Compromised attestor claims a high-privilege `agent_name` it never had | First-call wins; SVID issued; agent inherits whatever runtime privileges its name implies | `agent_name` must be pre-registered by a human with `agents:create`; unregistered names rejected (`enforce`) or flagged (`warn`) |
| T2 | Agent silently escalates its own capabilities via `/grant` request | `/grant` accepts arbitrary scopes; only Brain/Policy at runtime gate them | `/grant` intersects requested scopes with the registered envelope before issuance; out-of-envelope = `403 scope_outside_envelope` |
| T3 | Operator fakes a registration retroactively to cover an incident | Sidecar registry tables are operator-trusted | Lifecycle events anchored in chain v3, signed by `warden-identity` issuer key; tampering breaks every later signature |
| T4 | Compromised team member quietly hands their high-privilege agent to an attacker-controlled team | No ownership transfer concept | Transfer requires `agents:admin` (different capability than owner-team membership), emits `agent.owner_team_transferred` chain row |
| T5 | Decommissioned agent name re-registered with looser scope | No retention; name is reusable | `UNIQUE (tenant, agent_name)` includes Decommissioned; re-register attempt returns `409 agent_name_retired` |

**Out of scope:** receiving-team consent on transfer (admins can dump on unwilling teams in v1; flagged as v2 follow-on); a capability-change request workflow (the widen endpoint is the *terminal* action — any approval flow on top is a separate spec); bulk operations (per-team mass suspend); a Terraform provider (the `--if-absent` CLI flag covers IaC patterns until a customer asks for native Terraform).

## 3. The registration record

### 3.1 Schema

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

### 3.2 Lifecycle state machine

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
- **Suspend is hard.** Existing SVIDs are revoked via the NATS revocation broadcast that `IDENTITY.md` §8 already needs (denylist consulted on `/sign`). Outstanding grants reject. There is no "soft suspend that lets in-flight requests run to TTL."

### 3.3 Ownership

Two principals on every record, doing different jobs:

- **`created_by_sub` (immutable):** non-repudiation. The human who declared this agent should exist. Their signature anchors the `agent.registered` chain row; nothing changes that fact later.
- **`owner_team` (mutable):** routing. The team responsible for operating the agent. HIL fans out Yellow-tier approvals to whatever Slack/Teams channel maps to the team. Transferable by `agents:admin` only; emits `agent.owner_team_transferred`.

The IdP `groups` claim is required. `POST /agents` with an `owner_team` not in the caller's `groups` returns `403 owner_team_not_in_token` — you cannot register an agent owned by a team you don't belong to. If a tenant's IdP doesn't emit `groups`, `POST /agents` returns `403 missing_team_claim` and the tenant is documented to configure the claim before onboarding.

## 4. The capability envelope

### 4.1 Grammar

Scopes are opaque, NFC-normalized lowercase strings, ≤128 bytes, no whitespace. The existing `validate_label` in `grant.rs:267` is reused (extended to the new envelope columns). No DSL, no parser, no semantic comparison.

A scope is either in a set or it isn't. `refund:<=50usd` and `refund:<=100usd` are distinct strings; if the envelope contains the first, the second is rejected. Teams that want graduated tiers declare each tier as a separate envelope entry (`refund:<=50usd`, `refund:<=500usd`, `refund:<=5000usd`) and rely on `regorus` rules at runtime for the dollar comparison.

The conventions `mcp:read:<resource>`, `mcp:write:<resource>`, `yellow:<token>` are documented but not enforced by the parser. Forward compatibility: any future structured grammar is a strict superset (string equality is a degenerate case of any comparator), so opaque-string envelopes verify under every future grammar without invalidating chain v3 rows.

### 4.2 Intersection at `/grant`

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

## 5. Wire surface

### 5.1 Registration & lifecycle

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

### 5.2 Request and response shapes

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

## 6. Gate integration with `/svid` and `/grant`

The agent record is consulted in the same SQLite transaction as the issuance INSERT. No TOCTOU window between gating check and minting.

### 6.1 `/svid` failure catalog (`enforce` mode)

| Status | Error | Condition |
|---|---|---|
| 200 | — | Record exists, Active, attestation kind in record's allowlist (or in global allowlist if record's is empty), attestation valid |
| 403 | `unregistered_agent` | No record for `(tenant, agent_name)` |
| 403 | `agent_suspended` | Record exists, state Suspended |
| 403 | `agent_decommissioned` | Record exists, state Decommissioned |
| 403 | `attestation_kind_not_accepted` | Record's `attestation_kinds_accepted` non-empty and presented kind not in it |
| 422 | (existing) | Existing attestation-evidence shape errors, unchanged |

### 6.2 `/grant` failure catalog (always, regardless of mode for registered agents)

| Status | Error | Condition |
|---|---|---|
| 200 | — | Record exists, Active, requested scopes ⊆ envelope, requested yellow ⊆ yellow envelope |
| 403 | `scope_outside_envelope` | Body lists offending scopes |
| 403 | `yellow_scope_outside_envelope` | Body lists offending yellow scopes |
| 403 | `agent_suspended` / `agent_decommissioned` | Bad state |
| 403 | `unregistered_agent` (`enforce` only) | No record |

### 6.3 Mode behaviour

`WARDEN_IDENTITY_REGISTRATION_MODE = off | warn | enforce`. Default `warn` for one minor version after this spec lands, then default flips to `enforce`.

| Mode | Unregistered name on `/svid` | Unregistered name on `/grant` | Registered agent + out-of-envelope grant |
|---|---|---|---|
| `off` | 200, no signal | 200, no signal | 200, no signal (envelope ignored) |
| `warn` | 200 + `unregistered_agent` signal on forensic event | 200 with wildcard envelope + `unregistered_agent` signal | **403 `scope_outside_envelope`** |
| `enforce` | 403 `unregistered_agent` | 403 `unregistered_agent` | 403 `scope_outside_envelope` |

The principle: **registration is opt-in to enforcement**. The mode flag governs the *unknown* case (no record). Once a record exists, its envelope is enforced regardless of mode — otherwise registration in `warn` would be decorative. This lets operators onboard their highest-risk agents first, get real enforcement immediately on those, and let lower-risk agents run unregistered until the global flip.

The signal vocabulary on the forensic event uses `unregistered_agent` (consistent with `peer_bundle_stale`, `grant_expired` naming from `IDENTITY.md`).

## 7. Chain v3 — lifecycle row anchoring

`CURRENT_CHAIN_VERSION = 3` after this lands. v1 (verdict, no signature), v2 (verdict + signature), and v3 (lifecycle event) coexist in the chain; verifier dispatches per-row. No retroactive re-signing.

### 7.1 Two-tier hashable

The outer hashable is fixed at v3 launch and never altered without a v4 bump. Per-event-kind variation lives in a separate payload, content-hashed into `payload_sha256`:

```json
{
  "id":               "<uuidv7>",
  "timestamp":        "2026-05-05T14:30:00Z",
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

### 7.2 Per-kind payloads

| `event_kind` | Payload |
|---|---|
| `agent.registered` | `{ scope_envelope, yellow_envelope, attestation_kinds_accepted, owner_team, description }` |
| `agent.suspended` / `agent.unsuspended` / `agent.decommissioned` | `{ state_before, state_after, reason }` |
| `agent.envelope_narrowed` / `agent.envelope_widened` | `{ scope_envelope_before, scope_envelope_after, yellow_envelope_before, yellow_envelope_after }` (all four always present) |
| `agent.attestation_kinds_changed` | `{ attestation_kinds_before, attestation_kinds_after }` |
| `agent.owner_team_transferred` | `{ owner_team_before, owner_team_after }` |
| `agent.description_changed` | (no payload — chain row's `actor_sub` + `timestamp` is the proof; description content lives in identity's local table) |

`canonical_json` for both the outer hashable and the payload is the existing v1/v2 canonicalizer in `warden-ledger` (sorted keys, no whitespace, UTF-8 NFC). One canonicalizer, no per-version variants.

### 7.3 Ground rules

- **`actor_sub` is always a real human.** No `system:`, no `tofu:*`. Migration-CLI runs publish `actor_sub = "system:migration:<operator_oidc_sub>"` — the operator who ran the migration is recorded; never anonymous.
- **The outer hashable is locked.** New event kinds add only payload schemas. New optional outer fields are forbidden; if it matters enough to put outside the payload, it warrants a v4 bump.
- **Adding event kinds is free.** Specifically, future spec follow-ons (capability-change request flow, transfer-pending, etc.) add new payloads only — no chain version bump.

## 8. Authentication for human callers

### 8.1 Transport

All `/agents` endpoints take a raw OIDC `id_token` in `Authorization: Bearer`. Stateless server-side validation against the configured per-tenant JWKS. No Warden-issued session token (would double the revocation surface for no security gain). No reuse of `/grant` for human auth (would conflate the human/agent boundary the rest of the spec maintains).

### 8.2 Capability resolution

Capabilities (`agents:create`, `agents:admin`, ...) are derived from the IdP `groups` claim via server-side mapping in `identity.toml`:

```toml
[capabilities.tenants.acme]
"warden-agent-creators" = ["agents:create"]
"warden-platform-admins" = ["agents:create", "agents:admin"]
```

This avoids requiring per-tenant IdP claim customisation (the #1 enterprise SaaS onboarding failure mode). The tenant administrator only has to tell their IdP team "add a group called `warden-agent-creators` and put your developers in it."

### 8.3 Per-tenant IdP

Multi-tenant `warden-identity` reads `[oidc.tenants.<tid>] issuer = "..." jwks_url = "..."` per tenant. Per-call routing is by the `tenant` field in the request body. A request whose `tenant` doesn't match the OIDC token's issuer mapping returns `403 tenant_mismatch`.

## 9. The `wardenctl` CLI

New top-level binary built on top of `warden-sdk`. Two artifacts, one source of truth: SDK is the typed library (consumed by `warden-console` and integrators); CLI is a `[[bin]]` in a new crate that depends on SDK.

### 9.1 Auth

OIDC device authorization flow (RFC 8628), the same pattern as `gcloud auth login`, `aws sso login`, `gh auth login`.

```
wardenctl auth login --tenant acme        # device-flow; cache id_token + refresh_token in ~/.warden/credentials.json
wardenctl auth logout
wardenctl auth whoami                      # echoes sub, idp, groups, capabilities
```

No long-lived API tokens. No operator SVID requirement (would be a circular bootstrap). The CLI re-uses the cached refresh token transparently; expired refresh sends the operator back through device flow.

### 9.2 Commands

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

### 9.3 Conventions

- `--json` on every read command; tests and shadow-scanner integration depend on machine-readable output.
- `--if-absent` on `create` for IaC-without-Terraform patterns: a CI job loops a YAML file and runs `wardenctl agents create --if-absent` per entry. Returns 200 if the existing record matches the requested envelope, 409 if it differs.
- Exit codes are deterministic and documented: `0` success, `2` validation error, `3` auth/capability error, `4` conflict, `5` server error.

## 10. Console (`warden-console`) extensions

The console gets the same OIDC auth dance as the CLI (auth-code flow + PKCE), holds tokens server-side, never exposes them to user-facing JS. Tenant context is inferred from the OIDC `tenant` claim or per-IdP `console.toml`. No tenant switcher in v1.

### 10.1 New pages

| Path | Content |
|---|---|
| `/agents` | Tenant-scoped index. Columns: name, state badge, owner team, # scopes, # yellow scopes, last activity (joined from latest ledger row by `agent_name`). Filters: state, owner team, search. |
| `/agents/new` | Form: tenant (auto-filled), name, owner-team (dropdown of caller's groups), scope envelope (multi-input), yellow envelope (multi-input), attestation kinds (checkboxes from global allowlist), description. Submits to `POST /agents`. |
| `/agents/{id}` | Full record + lifecycle timeline (chain v3 rows for this agent, newest first). htmx action buttons gated on caller's capability. |

### 10.2 Cross-page weaving

The audit story is invisible without it.

- **`/audit`** gains an "Agent" column. Linkable to `/agents/{id}` if registered; italic name otherwise. New "Filter by owner team" dropdown. `unregistered_agent`-signal rows get a one-click "Register…" link that prefills `/agents/new` with the observed `(tenant, agent_name)`.
- **`/hil/{id}`** gets an "Authorization context" panel above the request body: agent name (linked), owner team, registering human (`created_by_sub`), registration date, full envelope. The requested method/payload is visually flagged in-envelope or outside-envelope. The latter shouldn't happen post-`enforce` but in `warn` mode it can — surface it loudly so approvers see the gap.

### 10.3 Verbs

The console has no "delete" verb. Decommission is terminal but the row stays. The word "delete" is operationally dangerous for an audit log and we don't need it.

## 11. Failure & fallback semantics

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

## 12. Migration & rollout

Five phases, mirroring `IDENTITY.md`'s phasing convention. Each independently shippable.

1. **Schema + reads.** `agents` table created; `GET /agents`, `GET /agents/{id}`, `wardenctl agents list/get` work. `POST /agents` and lifecycle endpoints not yet wired. Mode flag defaults `off`. *Exit:* schema migration ships to all environments; SDK `Client::list_agents` callable.
2. **Writes + lifecycle (no gating).** `POST /agents` and the lifecycle endpoints all work. Console `/agents`, `/agents/new`, `/agents/{id}` ship. `wardenctl agents create/suspend/...` ship. Mode still `off`. *Exit:* operators can enroll and manage records; nothing breaks because no gate consults them yet.
3. **Chain v3.** Ledger gains v3 dispatch. Every `POST /agents` and lifecycle endpoint emits a chain v3 row. Console `/agents/{id}` timeline ships. Verifier exposes per-row signature check across v1, v2, v3. *Exit:* `verify_chain` passes against a mixed v1/v2/v3 export; `wardenctl ledger verify` succeeds.
4. **Mode `warn`.** `/svid` and `/grant` consult the registry; unregistered names succeed with a signal stamped on the forensic event. Registered agents get envelope enforcement immediately. Console `/audit` highlights `unregistered_agent` rows with the "Register…" link. *Exit:* `warden-e2e` happy path passes with the simulator agents either pre-registered (via migration CLI) or running unregistered with signals; chaos-monkey scenarios assert correct mode behaviour.
5. **Mode `enforce`.** Default flips. Migration CLI is the official adoption tool — operators run `wardenctl agents migrate --default-envelope '*'` to bulk-enroll existing agents before flipping. `warden-e2e`, `warden-simulator`, `warden-chaos-monkey` boot scripts run the migration in their setup. *Exit:* `warden-e2e` happy path passes with `enforce` and zero unregistered names; chaos-monkey `unregistered_agent_enforce` scenario denies as expected.

Phases 1–3 unblock the §11.3 audit-lineage story (chain row "Alice declared this agent"). Phases 4–5 close the namespace-squat and capability-sprawl threats (T1, T2). Phase 1 is decoupled from the other identity-spec phases — it does not depend on capability-attestation enforcement (`IDENTITY.md` P4) or any other unshipped work.

## 13. Test surface

### 13.1 `warden-e2e`

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

### 13.2 `warden-chaos-monkey`

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

Onboarding scenarios are pure-identity, no policy-tracker hits, so they run early in the chaos-monkey order — explicitly *before* the existing `velocity_breaker` scenario, which per `CLAUDE.md` must run last because the policy tracker records every `/evaluate`.

### 13.3 Out of test scope

- **Real IdP integration tests.** Real Okta/Entra tenants don't fit in CI; the dex mock is the contract. Real-IdP setup is a docs deliverable.
- **Cross-tenant federation of agent records.** Agent records are tenant-local. Cross-tenant federation deals only with SPIFFE bundles (per `IDENTITY.md` §3.3). No behaviour to test.
- **Latency regression.** Adding `/agents` lookups on the `/svid` and `/grant` hot paths is real overhead; chasing latency budgets in CI is noisy. Document the expectation ("registered-agent gating adds <1ms p99 to `/svid`") and verify manually before the `enforce` flip.

## 14. Wire-contract changes (cross-repo grep before renaming)

| Edge | Field added | Repos to grep |
|---|---|---|
| Console → Identity (read) | `GET /agents` response shape | `warden-console`, `warden-identity/src/agents.rs`, `warden-sdk` |
| Console → Identity (write) | `POST /agents` and lifecycle bodies | `warden-console`, `warden-identity/src/agents.rs`, `warden-sdk` |
| `wardenctl` → Identity | All `/agents` shapes | `warden-sdk`, `wardenctl/src/cmd/agents.rs`, `warden-identity/src/agents.rs` |
| Identity → Ledger (NATS) | Chain v3 outer hashable + per-kind payloads | `warden-identity/src/agents_ledger.rs`, `warden-ledger/src/chain.rs` (v3 dispatch), `warden-ledger/src/verify.rs` |
| Identity → Proxy/HIL (existing rejection signals) | New error codes (`unregistered_agent`, `scope_outside_envelope`, `agent_suspended`, `agent_decommissioned`, `attestation_kind_not_accepted`) | `warden-proxy/src/grant.rs`, `warden-proxy/src/sign.rs` (signal aggregator), `warden-brain` (signal display), `warden-console/src/audit.rs` (filter chips) |

The shared types are duplicated on each side of the wire (no shared crate, per repo convention); land changes simultaneously.

## 15. What this spec deliberately does not include

- **Receiving-team consent on transfer.** v1 lets `agents:admin` dump an agent on an unwilling team. v2 should add `pending_transfer_to: <team>` + accept/reject by receiving team. Out of scope.
- **Capability-change request workflow.** The widen endpoint is the *terminal* action. A workflow on top — owner-team submits request, admin or HIL approves, widen fires — is a separate spec. The endpoint shape is designed to be the workflow's terminal call.
- **Bulk operations.** "Suspend all agents owned by team X" is a real incident-response need; v1 admins iterate. Defer until an operator explicitly asks.
- **Terraform provider.** The `--if-absent` CLI flag covers IaC-shaped use cases. A native Terraform provider is the natural follow-on once a customer asks.
- **Tenant lifecycle.** Tenants are implicit (declared by first use of the string). A `tenants` table implies billing boundaries, per-tenant IdP federation, and tenant decommissioning — much bigger spec.
- **WebAuthn approver auth on lifecycle transitions.** Today's auth is OIDC-only on `/agents`. Step-up auth for high-impact transitions (decommission, widen) is the existing Tier 3 WebAuthn ticket; this spec only ensures the transitions are signed in the chain. WebAuthn lands independently.
- **Per-agent attestation policy beyond `attestation_kinds_accepted`.** Per-method attestation requirements (the `IDENTITY.md` P4 work) remain global. Per-agent rule overrides — "this specific agent's `wire_transfer` calls require measurement X" — wait for P4 to settle before being layered on.
- **Agent groups / hierarchies.** No nested ownership, no parent-child agents, no inheritance. Each agent is a flat record. If 50 agents share an envelope, register 50 records (the CLI's `--if-absent` makes this scriptable).
