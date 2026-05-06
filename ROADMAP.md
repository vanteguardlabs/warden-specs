# Warden Roadmap

Authoritative milestone plan for Tier 3 hardening. Companion to `IDENTITY.md` and `ONBOARDING.md`. This file is the "what's next" reference — re-verify against `git log --oneline -10` per repo before relying on any "shipped" claim.

## Status (as of 2026-05-06)

Phases 1-4 of the original plan: **done**. Tier 2 GTM (`warden-shadow-scanner`, `warden-lite`, `warden-sdk`, `warden-console`): **done**. Identity P0-P5, including P4 attestation enforcement (rego `attestation_required` + per-tool measurement allowlist + per-spiffe-id verifier cache + chaos-monkey `unattested_binary`): **done**. WAO (Warden Agent Onboarding) P1-P5 with default flipped to `Enforce` and `wardenctl agents migrate` shipped: **done**. WebAuthn approver auth (warden-hil + warden-console, HIL holds passkey credentials, console shuttles the HIL session cookie): **done** (2026-05-03). Console `/config` diagnostic page (`CONFIG.md`): **done**.

Active horizon: **Tier 3 — first-customer hardening**. E1 (Human Auth Surface — WebAuthn slice) and E2 (Identity P4 Attestation Enforcement) are closed; **E3 → E6 are the open backlog.**

No design partner yet. Milestones target the *median enterprise security review* — what every buyer asks regardless of vertical — rather than any specific vertical's procurement checklist. When a real design-partner appears, this roadmap will get re-shaped by their checklist; until then, optimize for optionality.

## Epic list

| # | Epic | Headline gap closed | Size (solo) |
|---|------|---------------------|-------------|
| **E1** | **Human Auth Surface** *(WebAuthn slice **shipped 2026-05-03**; OIDC + basic-admin remain open)* | OIDC SSO + basic-admin mode alongside the existing WebAuthn approver flow; Slack/Teams self-link; `WARDEN_CONSOLE_AUTH` selector with loopback guard. Closes the "WebAuthn is the only auth path; no enterprise SSO story" gap. | ~2 weeks |
| **E2** | **Identity P4 — Attestation Enforcement** *(**shipped**)* | `attestation_required` rego rule + per-tool measurement allowlist + chain v2 ledger dispatch + per-spiffe-id verifier cache + chaos-monkey `unattested_binary` scenario, all wired through proxy → policy → ledger. | ~2 weeks |
| **E3** | **Operability Foundation** | `/health` + `/readyz` everywhere, graceful shutdown, Dockerfile audit, per-repo GitHub Actions CI, helm chart skeleton. | ~3 weeks |
| **E4** | **Observability** | Prometheus `/metrics` per service, OTEL tracing across the security pipeline, structured JSON logging with `correlation_id` propagation, runbook set. | ~2-3 weeks |
| **E5** | **Supply Chain & Threat Model** | SBOM (CycloneDX) per binary, `cargo-audit` + `cargo-deny` in CI, license audit, `security.txt` + disclosure policy, public threat-model writeup. | ~2 weeks |
| **E6** | **Regulatory Export** | EU AI Act Article 11/12 export bundle on top of the existing chain — opt-in, signed, time-window-scoped. | ~2-3 weeks |
| **E1.5** | **Service Mesh** *(deferred)* | Service-to-service TLS+auth between proxy, brain, policy, HIL, ledger. Deferred from E1 because the right answer (service-level mTLS via warden-identity SVIDs vs. mesh-layer at deploy time) depends on the deployment substrate decided in E3. Revisit post-E3. | TBD |

**Total: ~14-16 weeks ≈ 4 months at observed pace.**

## Sequencing rationale

`E1 → E2 → E3 → E4 → E5 → E6`

- **E1 first** because WebAuthn-only auth is a dealbreaker for any buyer with existing SSO. Adding OIDC is the highest "are we enterprise-ready" yes/no.
- **E2 second** because it's *named open* in `CLAUDE.md` and `IDENTITY.md`. Closing it lets us write "Identity spec fully shipped" in one place and stop carrying mental load.
- **E3 third, not first**, because some of E1's work (which OIDC provider, which secrets, basic-admin posture) informs the deployment story; doing them in opposite order creates rework.
- **E4 after E3** because observability hooks land naturally into the CI + runbook structure built in E3.
- **E5 piggybacks on E3's CI** — adds more checks to the same workflow files, half the work if done after.
- **E6 last** because in the no-partner-yet world, regulatory export is the lowest-leverage epic; the first regulated buyer will likely re-shape it anyway.

## E1 — Human Auth Surface (in flight)

### Scope

Two components, both in the existing repos. **Out of scope:** service-to-service auth (split out as E1.5).

**Existing posture (shipped 2026-05-03):** WebAuthn approver auth, end-to-end. HIL holds passkey credentials; console proxies WebAuthn ceremonies and shuttles HIL's `Set-Cookie` back to the browser. HIL stamps `decided_by` server-side as `webauthn:{name}` and ignores the request body's `decided_by` when auth is enabled. `WARDEN_HIL_AUTH_DISABLED=true` keeps an unauthenticated mode for the e2e runner.

E1 extends that posture rather than replacing it:

1. **Console OIDC SSO** in `warden-console`, alongside the existing WebAuthn flow.
2. **HIL OIDC verification path** so OIDC-mode `/decide` traffic gets the same `Authn::*` enforcement WebAuthn already gets — `decided_by` stamped server-side from the verified token (not the request body).
3. **`basic-admin` mode** for solo evaluation.
4. **Slack/Teams self-link** via OAuth, surfaced as a new `/me/identities` page in the console.
5. **`WARDEN_CONSOLE_AUTH` selector** with four modes (see below) — runtime configuration, not a build-time choice.

### Auth modes

Four modes, selected via `WARDEN_CONSOLE_AUTH={disabled|basic-admin|webauthn|oidc}`:

- `disabled` — exposes today's `WARDEN_HIL_AUTH_DISABLED=true` posture under a console-side switch. Loopback only (`--bind 127.0.0.1`). For dev/CI.
- `basic-admin` — single hardcoded admin user from env (`WARDEN_CONSOLE_ADMIN_USER` + `WARDEN_CONSOLE_ADMIN_PASS_BCRYPT`). For solo evaluation. **Refuses to boot on a non-loopback bind unless `WARDEN_CONSOLE_ALLOW_BASIC_ADMIN_NETWORK=true` is set explicitly.**
- `webauthn` — current shipped posture. Default for self-hosted small-team deployments.
- `oidc` — generic OIDC code flow against any compliant IdP. For production with an existing SSO.

### RBAC

Two static roles, mapped via OIDC group claim, config-as-code only:

- `viewer` — read-only access to audit / chain / agent registry views.
- `approver` — viewer + ability to decide HIL pending items.

Group mapping lives in console config:

```yaml
auth:
  oidc:
    approver_groups: ["security-team", "finance-ops"]
    viewer_groups: ["engineering", "compliance"]
```

No user table. No admin role (admin surface = `wardenctl` + direct identity API). No runtime role exceptions. The IdP is the source of truth.

### Cross-channel identity

Slack and Teams approvers self-link their identities via a new `/me/identities` page in the console, using Slack/Teams OAuth. Console gains a small `user_identities` table:

```sql
CREATE TABLE user_identities (
  oidc_sub      TEXT PRIMARY KEY,
  slack_user_id TEXT UNIQUE,
  teams_user_id TEXT UNIQUE,
  linked_at     TIMESTAMP NOT NULL,
  last_verified TIMESTAMP NOT NULL
);
```

A Slack/Teams approve click looks up `user_id → oidc_sub` via this table. **If no mapping exists, the click is rejected** with "your Slack identity is not linked — link via the console first." This forces the chain row to consistently stamp the same identity (`oidc:<sub>`) regardless of which channel the approval came from.

**Schema caveat:** the table sketch above keys on `oidc_sub`, but `webauthn` and `basic-admin` modes don't produce OIDC subs. Implementation-time decision: either add per-mode columns (`oidc_sub` / `webauthn_name` / `basic_username`, all nullable, with a CHECK constraint that exactly one is set) or introduce an internal `user_id` PK with a separate `auth_identities` join. Both are reversible; the PK choice doesn't bind the wire format.

Buyer creates their own Slack/Teams app from a manifest published in `warden-console/docs/` — no marketplace presence.

### Chain `decided_by` schema

The literal `"warden-console"` value was replaced 2026-05-03 — HIL now stamps `decided_by` server-side from the verified WebAuthn principal. E1 extends the convention to the new modes:

- `webauthn:{name}` — already shipped.
- `oidc:<sub>` — added with OIDC mode; also stamped on Slack/Teams clicks after self-link (the OAuth-linked `oidc_sub` flows through, not the underlying channel id).
- `basic:<username>` — added with basic-admin mode (auditor reads this and immediately knows the deployment was running in basic-admin mode).

The chain row also gains an `approver_assertion` JSON blob — extension hook for stronger per-decision claims, populated forward from E1 onwards:

- WebAuthn: `{ "method": "webauthn", "credential_id": "...", "iat": ... }`
- OIDC: `{ "method": "oidc-session", "sub": "...", "iat": ... }`
- Basic: `{ "method": "basic-admin", "username": "..." }` (intentionally cheap — no chain-of-trust to assert)

Existing WebAuthn rows in the chain don't get the field retroactively; only rows produced after E1 lands carry it. No chain-version bump required; the field is additive.

### Console → HIL trust

The trust path is **mode-dependent** because WebAuthn already has a stronger one and we don't tear it out:

- **WebAuthn mode (today, unchanged):** HIL is the credential authority. The console proxies WebAuthn ceremonies and shuttles HIL's session cookie back to the browser; subsequent `/decide` calls attach the HIL cookie and HIL stamps `decided_by` from the verified principal.
- **OIDC / basic-admin / disabled (new in E1):** HIL has no credential to verify, so console and HIL share a bearer secret (`WARDEN_HIL_DECIDE_TOKEN`). Console verifies OIDC (or basic-admin), stamps `decided_by`, and presents the bearer on `/decide`. HIL trusts the request-body `decided_by` *only when* a valid bearer is present; without the bearer, the existing `Authn::Disabled` fallback applies. **Both processes refuse to boot if the configured mode requires the token and it is missing.**

The bearer is the interim posture for the non-WebAuthn modes; E1.5 replaces it with SVID-based mTLS uniformly across all modes (WebAuthn included).

### Mechanical defaults

- OIDC token validation: JWKS, 1-hour cache TTL, reactive refresh on signature failure.
- Session: server-side encrypted cookie via `tower-sessions`, 8-hour rolling lifetime.
- Logout: clears server session, optionally calls IdP `end_session_endpoint`.
- CSRF: htmx + origin-check + per-session token; no separate state cookie.
- IdPs tested in CI: Keycloak (dockerizable). Quickstart docs only for Google / Okta / Azure AD / Auth0 — no CI fixtures (their public test infra is unreliable).

### When v2 work would be triggered

- **Per-decision WebAuthn step-up over OIDC sessions**: trigger = first design-partner from FinTech (PSD2 SCA), defense (FIPS / DoD impact level), or healthcare (HIPAA technical safeguards). The WebAuthn primitives already exist (today's default mode); v2 wires them as a step-up gating individual `/decide` calls on top of OIDC sessions, rather than as a parallel auth mode.
- **Runtime role-management UI**: trigger = first buyer who demands non-GitOps role exceptions. Until then, config-as-code is sufficient.
- **Admin role + agent-registry UI in console**: trigger = first user who explicitly wants agent CRUD outside `wardenctl`. Until then, `wardenctl` + direct identity API are sufficient.
- **Four-eyes / separation-of-duties**: trigger = first buyer demanding per-human approval limits or "two distinct approvers required." This also triggers the upgrade from self-link to a more rigorous identity unification scheme.

## E2-E6 stubs

These are intentionally light. The right time to design each is when the prior epic ships and we have post-implementation hindsight on what's actually expensive.

### E2 — Identity P4 Attestation Enforcement *(shipped)*

Closed the named-open item from `IDENTITY.md`. As shipped:

- `policies/attestation.rego` denies when `tool_type == wire_transfer` (or any `delete_*`) and the attestation is absent, expired, or carries a measurement not in `attestation_allowlist.json`. Reasons stamped on the ledger as `attestation_stale` / measurement-not-in-allowlist.
- `PolicyInput` carries `attestation: Option<AttestationClaims>` (kind, measurement, issued_at, expires_at, nonce_echo) and `agent_spiffe`. The rule short-circuits for legacy CN-only callers — gating only fires when `agent_spiffe` is set, so chaos-monkey's `unattested_binary` scenario must mint a SPIFFE-SAN cert to be a real test.
- The proxy carries a per-spiffe-id verifier cache; `X-Warden-Attestation` is supported as a per-request header override.
- Chaos-monkey gained `unattested_binary` (and the related direct-to-identity onboarding-gating scenarios) asserting hard-deny.

Sub-questions deferred to a follow-on: which attestation *kinds* to support in v2 beyond `dev-binary-hash` (TPM-EK / SLSA / sigstore-cosign / k8s-pod-identity); how the per-method allowlist evolves toward a Sigstore-style signed transparency log; verifier-unreachable behaviour beyond today's fail-closed posture.

### E3 — Operability Foundation

`/health` (process up) + `/readyz` (dependencies reachable) on every service. Graceful shutdown: SIGTERM → drain in-flight → exit (max 30s). Audit existing Dockerfiles in `repos/warden-e2e/docker-compose.yml`'s `--profile stack`; produce a per-repo Dockerfile review (release-profile concerns from the macOS/`ring` issue still apply). Per-repo GitHub Actions CI (test + clippy `-D warnings` + cargo-audit). Helm chart skeleton with the six services + sane defaults; helm chart is opinionated, not a kitchen sink.

Likely sub-questions: helm chart vs raw k8s manifests vs kustomize as the canonical deployment artifact? `/readyz` semantics — does NATS being unreachable count as not-ready or degraded? Graceful shutdown ordering across services (proxy first or last?). CI matrix — Linux only or Linux+macOS+Windows for `cargo build`? Container base image — `debian:slim` vs `distroless` vs `alpine` (musl)?

### E4 — Observability

Prometheus `/metrics` per service: request counts, p50/p95/p99 latency, security-verdict distribution, HIL queue depth, chain length, NATS publish/subscribe rates, identity issuance rates. OpenTelemetry tracing across the security pipeline — `correlation_id` becomes a trace ID; spans for proxy → brain, proxy → policy, proxy → HIL, ledger ingest. Structured JSON logging via `tracing_subscriber` with `correlation_id` on every log line. Runbook set: "proxy crashed," "NATS down," "ledger chain invalid," "HIL queue stuck," "identity service unreachable."

**Shipped slice: structured logging substrate.** Every Rust service now respects `RUST_LOG` (default `info`) and `WARDEN_LOG_FORMAT={pretty|json}` (default `pretty`). The JSON layer surfaces the active span stack so `correlation_id` flows through once spans are instrumented. Metric collection (Prometheus `/metrics`) and OTEL trace export (proxy only) were shipped earlier. Still open: extending OTEL spans to brain / policy / hil / ledger / identity, threading `correlation_id` through `tracing::Span` fields end-to-end, and the runbook set.

Likely sub-questions: OTEL exporter target — OTLP / Jaeger / Tempo / vendor-specific? Metric cardinality budget (per-agent labels are tempting but explode high-cardinality). Log format — pure JSON or human-readable in dev? Runbook format — markdown in repo or Notion?

### E5 — Supply Chain & Threat Model

SBOM in CycloneDX format per binary, generated in CI (cargo-cyclonedx). `cargo-audit` + `cargo-deny` (license + advisory) gate every PR. License audit pass — flag any GPL/AGPL transitive dependencies. `security.txt` published at the warden-website root + a public security disclosure policy (`SECURITY.md`) in every repo. Public threat-model writeup in `warden-specs/THREATS.md`: STRIDE-organized, layer-by-layer, with explicit non-goals.

Likely sub-questions: SBOM publication — embed in container labels, attach to GitHub releases, or both? `cargo-deny` policy — strict or permissive on yanked crates? Threat-model audience — security buyers (more abstract) or pen-testers (more concrete)?

### E6 — Regulatory Export

`POST /export/regulatory` on warden-ledger producing an EU AI Act Article 11/12-compliant bundle: technical documentation snapshot (system architecture, data flow, training data sources for any AI components), automatic logging records (the chain itself), risk management documentation. Bundle is signed, time-window-scoped, and produced as a tar of canonical-form JSON + the existing Iceberg/Parquet exports.

Likely sub-questions: which articles in scope — 11 only, 12 only, both, plus 14-15 (human oversight + accuracy)? Bundle format — tar+sig vs zip vs Iceberg-native? GDPR Article 30 (records of processing) too, or strictly AI Act? Data retention policy — bundle includes a TTL? Article 12 logging includes "automatic recording of events ('logs')" which the chain already satisfies — is the export just a re-encoding, or do we need additional metadata?

## Out of scope (and why)

- **Behavioural learning (§10.4 of the original plan).** Research project, not hardening. Defer until there's real customer ledger data to mine — without that, you're building a demo of pattern-matching against synthetic chaos-monkey traffic, which doesn't generalize.
- **Multi-tenant SaaS console.** Only relevant for hosted-managed posture. (B) lane (abstract enterprise-readiness) targets self-hosted; SaaS is a year-2 product question.
- **Shadow-scanner GHE URL knob, incremental scanning.** Already over-shipped for a free top-of-funnel tool. Add when a buyer asks.
- **Brain cost controls.** Caching + mock-mode covers it; revisit when there's real spend signal.
- **HIL modify-and-resume v2.** Already shipped 2026-05-02; further iteration is buyer-driven.

## Decision log (E1 grilling, 2026-05-06)

| Q | Decision |
|---|----------|
| Q1 | Lane: first-customer hardening |
| Q2 | Mode: abstract — no specific buyer |
| Q3 | Roadmap shape: ordered backlog under named epics (hybrid) |
| Q4 | Epic list: E1-E6 as above; E1.5 deferred |
| Q5 | E1 scope: human auth only; s2s split into E1.5 |
| Q6 | HIL approver auth: OIDC, with `approver_assertion` extension hook for future WebAuthn step-up; `decided_by` fix included |
| Q7 | RBAC: two roles (`viewer` / `approver`); config-as-code only |
| Q8 | Cross-channel identity: self-link via OAuth (adds `user_identities` table) |
| Q9 | Auth modes: 3 modes (`disabled` / `basic-admin` / `oidc`); basic-admin refuses non-loopback bind by default |
| Q10 | Console → HIL trust: shared bearer secret as interim; replaced by E1.5 |

### Correction (2026-05-06, post-implementation audit)

The grilling above predates an audit of the shipped console + HIL code, which uncovered work the original Q&A treated as missing:

- WebAuthn approver auth shipped 2026-05-03 (`warden-hil@12ba0df`, `warden-console@8cd2630`). HIL holds passkey credentials; console proxies the ceremony and shuttles the HIL session cookie. The "console binds to localhost / no auth on Yellow-tier approvals" framing was stale on the day it was written.
- HIL already stamps `decided_by` server-side as `webauthn:{name}` and ignores the request body when auth is enabled. Q6's "decided_by literal `warden-console`" claim is stale.
- Q9 specified three modes; with WebAuthn as the existing default, four are needed.
- The Console → HIL trust path is mode-dependent rather than uniformly bearer-based — Q10's bearer choice still applies, but only to OIDC / basic-admin / disabled modes.

The E1 spec section above incorporates the correction and supersedes the rows in the decision-log table where they conflict.

## Pacing note

User pace: ~one major feature per session (~1500-2000 lines end-to-end with tests + clippy + README). Epic sizes above are calibrated to that pace. Each epic decomposes into 3-6 sessions; each session ships independently. No "release gates" — every shippable chunk goes out as soon as it's green. The epic name is the only milestone marker.
