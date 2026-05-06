# Warden Roadmap

Authoritative milestone plan for Tier 3 hardening. Companion to `IDENTITY.md` and `ONBOARDING.md`. This file is the "what's next" reference — re-verify against `git log --oneline -10` per repo before relying on any "shipped" claim.

## Status (as of 2026-05-06)

Phases 1-4 of the original plan: **done**. Tier 2 GTM (`warden-shadow-scanner`, `warden-lite`, `warden-sdk`, `warden-console`): **done**. Identity P0-P3 + P5 federation: **done**. WAO (Warden Agent Onboarding) P1-P5 with default flipped to `Enforce` and `wardenctl agents migrate` shipped: **done**.

Active horizon: **Tier 3 — first-customer hardening**.

No design partner yet. Milestones target the *median enterprise security review* — what every buyer asks regardless of vertical — rather than any specific vertical's procurement checklist. When a real design-partner appears, this roadmap will get re-shaped by their checklist; until then, optimize for optionality.

## Epic list

| # | Epic | Headline gap closed | Size (solo) |
|---|------|---------------------|-------------|
| **E1** | **Human Auth Surface** | Console & HIL approver authentication. Closes the "console binds to localhost / no auth on Yellow-tier approvals" gap. | ~2 weeks |
| **E2** | **Identity P4 — Attestation Enforcement** | Closes the explicitly-named open item in `IDENTITY.md`: `attestation_required` rego rule + per-method allowlist + chain v2 ledger dispatch + verifier cache + chaos-monkey `unattested_binary` scenario. | ~2 weeks |
| **E3** | **Operability Foundation** | `/health` + `/readyz` everywhere, graceful shutdown, Dockerfile audit, per-repo GitHub Actions CI, helm chart skeleton. | ~3 weeks |
| **E4** | **Observability** | Prometheus `/metrics` per service, OTEL tracing across the security pipeline, structured JSON logging with `correlation_id` propagation, runbook set. | ~2-3 weeks |
| **E5** | **Supply Chain & Threat Model** | SBOM (CycloneDX) per binary, `cargo-audit` + `cargo-deny` in CI, license audit, `security.txt` + disclosure policy, public threat-model writeup. | ~2 weeks |
| **E6** | **Regulatory Export** | EU AI Act Article 11/12 export bundle on top of the existing chain — opt-in, signed, time-window-scoped. | ~2-3 weeks |
| **E1.5** | **Service Mesh** *(deferred)* | Service-to-service TLS+auth between proxy, brain, policy, HIL, ledger. Deferred from E1 because the right answer (service-level mTLS via warden-identity SVIDs vs. mesh-layer at deploy time) depends on the deployment substrate decided in E3. Revisit post-E3. | TBD |

**Total: ~14-16 weeks ≈ 4 months at observed pace.**

## Sequencing rationale

`E1 → E2 → E3 → E4 → E5 → E6`

- **E1 first** because no-auth-on-the-console is the single most "this is a dev project" smell. Highest embarrassment-per-week-of-work.
- **E2 second** because it's *named open* in `CLAUDE.md` and `IDENTITY.md`. Closing it lets us write "Identity spec fully shipped" in one place and stop carrying mental load.
- **E3 third, not first**, because some of E1's work (which OIDC provider, which secrets, basic-admin posture) informs the deployment story; doing them in opposite order creates rework.
- **E4 after E3** because observability hooks land naturally into the CI + runbook structure built in E3.
- **E5 piggybacks on E3's CI** — adds more checks to the same workflow files, half the work if done after.
- **E6 last** because in the no-partner-yet world, regulatory export is the lowest-leverage epic; the first regulated buyer will likely re-shape it anyway.

## E1 — Human Auth Surface (in flight)

### Scope

Two components, both in the existing repos. **Out of scope:** service-to-service auth (split out as E1.5).

1. **Console OIDC SSO** in `warden-console`.
2. **HIL approver auth** via the same OIDC identity — no WebAuthn step-up in v1, but designed with hooks for future addition.
3. **Slack/Teams self-link** via OAuth, surfaced as a new `/me/identities` page in the console.
4. **Console → HIL trust** via shared bearer secret as an interim, replaced by E1.5.

### Auth modes

Three modes, selected via `WARDEN_CONSOLE_AUTH={disabled|basic-admin|oidc}`:

- `disabled` — today's behavior. Loopback only (`--bind 127.0.0.1`). For dev/CI.
- `basic-admin` — single hardcoded admin user from env (`WARDEN_CONSOLE_ADMIN_USER` + `WARDEN_CONSOLE_ADMIN_PASS_BCRYPT`). For solo evaluation. **Refuses to boot on a non-loopback bind unless `WARDEN_CONSOLE_ALLOW_BASIC_ADMIN_NETWORK=true` is set explicitly.**
- `oidc` — generic OIDC code flow against any compliant IdP. For production.

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

Buyer creates their own Slack/Teams app from a manifest published in `warden-console/docs/` — no marketplace presence.

### Chain `decided_by` schema

Today's chain row stamps the literal string `"warden-console"` as `decided_by`. **This is fixed in E1**. Post-E1 values:

- `oidc:<sub>` — console OIDC mode, or Slack/Teams click after self-link.
- `basic:<username>` — console basic-admin mode (auditor reads this and immediately knows the deployment was running in basic-admin mode).

The chain row also gains an `approver_assertion` JSON blob (extension hook for future WebAuthn step-up):

- Today: `{ "method": "oidc-session", "sub": "...", "iat": ... }`
- Future-compat: `{ "method": "webauthn", "credential_id": ..., "assertion": ... }`

No chain-version bump required; the field is additive.

### Console → HIL trust

Console and HIL share a bearer secret (`WARDEN_HIL_DECIDE_TOKEN`). Console presents on every `/decide` call; HIL validates the bearer and trusts `decided_by` from the request body because the bearer proves the caller *is* the console. **Both processes refuse to boot if `--auth` is not `disabled` and the token is missing.**

This is an interim posture that gets replaced by SVID-based mTLS in E1.5. When E1.5 lands, the env var and header check are removed.

### Mechanical defaults

- OIDC token validation: JWKS, 1-hour cache TTL, reactive refresh on signature failure.
- Session: server-side encrypted cookie via `tower-sessions`, 8-hour rolling lifetime.
- Logout: clears server session, optionally calls IdP `end_session_endpoint`.
- CSRF: htmx + origin-check + per-session token; no separate state cookie.
- IdPs tested in CI: Keycloak (dockerizable). Quickstart docs only for Google / Okta / Azure AD / Auth0 — no CI fixtures (their public test infra is unreliable).

### When v2 work would be triggered

- **WebAuthn step-up for HIL approvals**: trigger = first design-partner from FinTech (PSD2 SCA), defense (FIPS / DoD impact level), or healthcare (HIPAA technical safeguards). Until then, OIDC + IdP-enforced MFA is sufficient.
- **Runtime role-management UI**: trigger = first buyer who demands non-GitOps role exceptions. Until then, config-as-code is sufficient.
- **Admin role + agent-registry UI in console**: trigger = first user who explicitly wants agent CRUD outside `wardenctl`. Until then, `wardenctl` + direct identity API are sufficient.
- **Four-eyes / separation-of-duties**: trigger = first buyer demanding per-human approval limits or "two distinct approvers required." This also triggers the upgrade from self-link to a more rigorous identity unification scheme.

## E2-E6 stubs

These are intentionally light. The right time to design each is when the prior epic ships and we have post-implementation hindsight on what's actually expensive.

### E2 — Identity P4 Attestation Enforcement

Closes the named-open item from `IDENTITY.md`. Add a rego rule `attestation_required` keyed on per-method allowlist; warden-identity gains a verifier cache for attestation evidence; warden-ledger dispatches a chain v2 row carrying the attestation kind and verifier verdict. Chaos-monkey gains an `unattested_binary` scenario asserting hard-deny.

Likely sub-questions to grill at design time: which attestation kinds to support in v1 (TPM-EK / SLSA / sigstore-cosign / k8s-pod-identity / static-allowlist)? Cache TTL for verified evidence? Failure mode when verifier is unreachable (fail-open vs fail-closed)? Migration path for already-registered agents that have no attestation kind on file?

### E3 — Operability Foundation

`/health` (process up) + `/readyz` (dependencies reachable) on every service. Graceful shutdown: SIGTERM → drain in-flight → exit (max 30s). Audit existing Dockerfiles in `repos/warden-e2e/docker-compose.yml`'s `--profile stack`; produce a per-repo Dockerfile review (release-profile concerns from the macOS/`ring` issue still apply). Per-repo GitHub Actions CI (test + clippy `-D warnings` + cargo-audit). Helm chart skeleton with the six services + sane defaults; helm chart is opinionated, not a kitchen sink.

Likely sub-questions: helm chart vs raw k8s manifests vs kustomize as the canonical deployment artifact? `/readyz` semantics — does NATS being unreachable count as not-ready or degraded? Graceful shutdown ordering across services (proxy first or last?). CI matrix — Linux only or Linux+macOS+Windows for `cargo build`? Container base image — `debian:slim` vs `distroless` vs `alpine` (musl)?

### E4 — Observability

Prometheus `/metrics` per service: request counts, p50/p95/p99 latency, security-verdict distribution, HIL queue depth, chain length, NATS publish/subscribe rates, identity issuance rates. OpenTelemetry tracing across the security pipeline — `correlation_id` becomes a trace ID; spans for proxy → brain, proxy → policy, proxy → HIL, ledger ingest. Structured JSON logging via `tracing_subscriber` with `correlation_id` on every log line. Runbook set: "proxy crashed," "NATS down," "ledger chain invalid," "HIL queue stuck," "identity service unreachable."

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

## Pacing note

User pace: ~one major feature per session (~1500-2000 lines end-to-end with tests + clippy + README). Epic sizes above are calibrated to that pace. Each epic decomposes into 3-6 sessions; each session ships independently. No "release gates" — every shippable chunk goes out as soon as it's green. The epic name is the only milestone marker.
