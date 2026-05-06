# Warden Roadmap

Authoritative milestone plan for Tier 3 hardening. Companion to `IDENTITY.md` and `ONBOARDING.md`. This file is the "what's next" reference — re-verify against `git log --oneline -10` per repo before relying on any "shipped" claim.

## Status (as of 2026-05-07)

Phases 1-4 of the original plan: **done**. Tier 2 GTM (`warden-shadow-scanner`, `warden-lite`, `warden-sdk`, `warden-console`): **done**. Identity P0-P5, including P4 attestation enforcement (rego `attestation_required` + per-tool measurement allowlist + per-spiffe-id verifier cache + chaos-monkey `unattested_binary`): **done**. WAO (Warden Agent Onboarding) P1-P5 with default flipped to `Enforce` and `wardenctl agents migrate` shipped: **done**. WebAuthn approver auth (warden-hil + warden-console, HIL holds passkey credentials, console shuttles the HIL session cookie): **done** (2026-05-03). Console `/config` diagnostic page (`CONFIG.md`): **done**. E1 viewer-route gating: **done** (2026-05-07).

Active horizon: **Tier 3 — first-customer hardening**. E1 (Human Auth Surface — WebAuthn + OIDC + basic-admin + RBAC + viewer-route gating), E2 (Identity P4 Attestation), E3 (Operability), E4 (Observability), and E5 (Supply Chain & Threat Model) are closed; **E6 Regulatory Export shipped 2026-05-07 (slices 1, 2, and 3 — bundle shape, detached signature, operator prose + Parquet pointers + `wardenctl regulatory export`)**.

No design partner yet. Milestones target the *median enterprise security review* — what every buyer asks regardless of vertical — rather than any specific vertical's procurement checklist. When a real design-partner appears, this roadmap will get re-shaped by their checklist; until then, optimize for optionality.

## Epic list

| # | Epic | Headline gap closed | Size (solo) |
|---|------|---------------------|-------------|
| **E1** | **Human Auth Surface** *(**shipped**: WebAuthn 2026-05-03, OIDC + basic-admin + RBAC + Slack/Teams self-link 2026-05-04…06, viewer-route gating 2026-05-07)* | OIDC SSO + basic-admin mode alongside the existing WebAuthn approver flow; Slack/Teams self-link; `WARDEN_CONSOLE_AUTH` selector with loopback guard; viewer-or-better gate on every read route (`/audit`, `/agents`, `/config`, `/exports`, …) with 303 → /login on no-session and 401 on SSE/JSON. Closes the "WebAuthn is the only auth path; no enterprise SSO story" gap. | ~2 weeks |
| **E2** | **Identity P4 — Attestation Enforcement** *(**shipped**)* | `attestation_required` rego rule + per-tool measurement allowlist + chain v2 ledger dispatch + per-spiffe-id verifier cache + chaos-monkey `unattested_binary` scenario, all wired through proxy → policy → ledger. | ~2 weeks |
| **E3** | **Operability Foundation** | `/health` + `/readyz` everywhere, graceful shutdown, Dockerfile audit, per-repo GitHub Actions CI, helm chart skeleton. | ~3 weeks |
| **E4** | **Observability** *(**shipped**)* | Prometheus `/metrics` per service, OTEL trace export across all six services, structured JSON logging with `correlation_id` span propagation through every request handler, on-call runbook set (`RUNBOOKS.md`). | ~2-3 weeks |
| **E5** | **Supply Chain & Threat Model** *(**shipped**)* | SBOM (CycloneDX) per binary, `cargo-deny` (advisories + licenses + bans + sources) in CI, license audit, `security.txt` + disclosure policy, public threat-model writeup. | ~2 weeks |
| **E6** | **Regulatory Export** *(shipped 2026-05-07; slices 1+2+3)* | EU AI Act Article 11/12 export bundle on top of the existing chain — opt-in, signed, time-window-scoped. Slice 1: `POST /export/regulatory?from=…&to=…` returning `.tar.gz` of NDJSON + manifest with chain pointers + sha256. Slice 2: detached `manifest.sig` ed25519 sidecar via warden-identity `/sign/blob`; manifest schema v2 with `signature` envelope; fail-closed 503 if identity unreachable. Slice 3: operator-supplied technical-documentation README (`text/markdown` body, embedded as `technical_documentation.md` with sha256 commit); `?include_exports=true` flag scans the `exports` table and embeds Parquet pointers whose seq range overlaps the window; manifest schema bumped to v3; `wardenctl regulatory export --from … --to … [--readme …] [--include-exports] --output bundle.tar.gz` CLI. | ~1-2 weeks |
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

**E4 shipped end-to-end.** Every Rust service now respects `RUST_LOG` (default `info`), `WARDEN_LOG_FORMAT={pretty|json}` (default `pretty`), and the standard `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://localhost:4317`). Each service installs a `tracing-opentelemetry` pipeline with a distinguishing `service.name` resource attribute (`warden-proxy` / `warden-brain` / `warden-policy-engine` / `warden-ledger` / `warden-hil` / `warden-identity`) so spans land under one collector but stay attributable. The exporter buffers and silently drops spans when no collector is reachable, so dev runs without a sidecar still work. Every request handler now opens a `#[tracing::instrument]` span keyed on `correlation_id` (plus `agent_id` / `method` / `tool_type` where applicable): proxy `handle_mcp` records the fields after they're derived inside the body; brain `inspect_intent`, policy `evaluate_policy`, ledger `record_entry`, hil `create_pending`, and identity `sign::issue` lift them straight from the request body; and the ledger NATS subscriber loop wraps each forensic-event append in a `ledger.nats_append` span via `tracing::Instrument` so the span follows the future across `.await` points. The JSON log layer surfaces the active span stack so every log line in a single request carries the same join key. Metric collection (Prometheus `/metrics`) was already in place. The on-call runbook set lives in `RUNBOOKS.md` — five incidents (proxy crashed, NATS down, ledger chain invalid, HIL queue stuck, identity service unreachable), each with symptom / triage / diagnosis / remediation / verification / escalation in a uniform shape.

Likely sub-questions: OTEL exporter target — OTLP / Jaeger / Tempo / vendor-specific? Metric cardinality budget (per-agent labels are tempting but explode high-cardinality). Log format — pure JSON or human-readable in dev? Runbook format — markdown in repo or Notion?

### E5 — Supply Chain & Threat Model

SBOM in CycloneDX format per binary, generated in CI (cargo-cyclonedx). `cargo-audit` + `cargo-deny` (license + advisory) gate every PR. License audit pass — flag any GPL/AGPL transitive dependencies. `security.txt` published at the warden-website root + a public security disclosure policy (`SECURITY.md`) in every repo. Public threat-model writeup in `warden-specs/THREATS.md`: STRIDE-organized, layer-by-layer, with explicit non-goals.

**E5 shipped end-to-end.** Every Rust repo (14 of them) carries an identical `deny.toml` at the repo root and runs `cargo-deny check all` (advisories + licenses + bans + sources) on every push and PR via the `supply-chain` job in `.github/workflows/ci.yml`. cargo-deny's `advisories` check supersedes `cargo-audit` (same RUSTSEC database; broader coverage), so the gate is `cargo-deny`-only — documented in the workflow comment. The license allow-list is the standard permissive set (MIT / Apache-2.0 / BSD / ISC / Zlib / MPL-2.0 / CC0 / 0BSD / MIT-0 / BSL-1.0 / Unlicense / OpenSSL / CDLA-Permissive-2.0 / Unicode-DFS-2016 / Unicode-3.0); GPL/AGPL/LGPL is denied. Six advisory IDs are explicitly ignored with documented rationale in `deny.toml` (rustls-pemfile, bincode, four rustls-webpki vulns gated on async-nats 0.36→0.47 upgrade, rsa Marvin attack via openidconnect, paste via parquet — all pinned to "no safe upgrade" upstream constraints). On the same `supply-chain` job, `cargo-cyclonedx` generates a CycloneDX 1.3 JSON SBOM per crate and uploads it as a build artifact (`sbom-<repo>-<sha>`, 90-day retention). `SECURITY.md` lives at every repo root (17 repos) with the same disclosure policy: contact, scope, safe harbor, response targets. RFC 9116 `security.txt` lives at `warden-website/.well-known/security.txt` pointing to `vanteguardlabs@gmail.com`, the GitHub policy URL, and a 1-year expiration. The public threat model lives at `warden-specs/THREATS.md` — STRIDE-organized layer by layer (proxy / brain / policy / ledger / HIL / identity / console + cross-cutting supply chain / operator auth / time), with explicit non-goals (insider operator threat, physical access, Anthropic compromise, multi-tenant console, typosquatting) and a tracked open-items table linking unfinished gaps back to specific roadmap epics.

Likely sub-questions: SBOM publication — embed in container labels, attach to GitHub releases, or both? `cargo-deny` policy — strict or permissive on yanked crates? Threat-model audience — security buyers (more abstract) or pen-testers (more concrete)?

### E6 — Regulatory Export *(shipped 2026-05-07)*

`POST /export/regulatory` on warden-ledger producing an EU AI Act Article 11/12-compliant bundle: technical documentation snapshot (system architecture, data flow, training data sources for any AI components), automatic logging records (the chain itself), risk management documentation. Bundle is signed, time-window-scoped, and produced as a tar of canonical-form JSON + the existing Iceberg/Parquet exports.

**Sub-questions resolved at slice-1 grilling 2026-05-07:**

- **Articles in scope:** 11 + 12 only. 14-15 (human oversight, accuracy) need operator-supplied prose; deferred. GDPR Article 30 has a different surface (data categories, recipients) and isn't auto-derivable from forensic events; deferred until a buyer asks.
- **Bundle format:** `.tar.gz` containing NDJSON + `manifest.json` + plain-text `README.txt`. NDJSON over Parquet because the audience reaches for Python / Excel / `jq` more readily than Parquet tooling; the cold-tier `/export` still produces Parquet for analytics. Detached `.sig` rather than embedded — keeps the `manifest.json` byte-stable across signing implementations.
- **Re-encoding vs. metadata layer:** Re-encoding. The chain rows land verbatim in NDJSON; the manifest adds chain-state pointers (`prev_hash_at_window_start`, `entry_hash_at_window_end`) so the bundle is independently verifiable without a warden binary.
- **Retention/TTL:** Bundle is operator-fetched + operator-stored. We don't retain bundles server-side; auditors set their own retention. Manifest carries `generated_at` so the operator's downstream archive knows when each bundle was produced.

**Slices:**

- **Slice 1 — bundle shape (shipped 2026-05-07).** `POST /export/regulatory?from=…&to=…` returning `.tar.gz`. Half-open window `[from, to)`. Manifest schema v1 with `row_count`, `seq_lo`, `seq_hi`, `chain_state.{prev_hash_at_window_start,entry_hash_at_window_end}`, `ndjson_sha256`, `article_scope: ["EU-AI-Act-Article-11", "EU-AI-Act-Article-12"]`, `signature: null`. Empty windows return a valid bundle with `row_count: 0` (auditors expect a verifiable artifact even for "we logged nothing"). 11 unit + 5 integration tests. `tar = "0.4"` and `flate2 = "1"` deps added to `warden-ledger`.
- **Slice 2 — detached signature (shipped 2026-05-07).** New `POST /sign/blob` endpoint on warden-identity (sibling to `/sign`, reuses the same caller-allowlist gate, signs an arbitrary 32-byte SHA-256 digest with the existing Vault Transit ed25519 key, returns raw signature hex + `key_id` + `algorithm` + `signed_at`, audience-tagged forensic event). New `warden-ledger::identity_client::ManifestSigner` trait + `HttpManifestSigner` impl wired through `WARDEN_IDENTITY_URL` + `WARDEN_LEDGER_SPIFFE`. Manifest schema bumped to `"2"`: `signature: Option<SignatureRef { sidecar, algorithm: "ed25519", digest_alg: "sha256", key_id, signed_at }>`. The signature commits to `sha256(canonical_manifest_with_signature_blanked_to_null)`; the bundle gains a `manifest.sig` sidecar (128 hex chars + LF). Auditor verification recipe: parse manifest, blank `signature` → null, re-serialize pretty, sha256, ed25519_verify against sidecar bytes. Fail-closed: signing failures surface as `503 signing_unavailable` rather than emitting an unsigned bundle. 12 sign_blob unit tests + 5 new build_bundle tests + 2 end-to-end http_integration tests (real ed25519 keypair, full audit recipe round-trip + tamper detection).
- **Slice 3 — operator-supplied prose + Parquet pointers + CLI (shipped 2026-05-07).** `POST /export/regulatory` now accepts an optional `text/markdown` (or any `text/*`) request body up to 1 MiB, embedded verbatim as `technical_documentation.md`. The manifest's `technical_documentation` sub-object commits to `{ filename, sha256, byte_size }`; the signature commits transitively via the canonical no-signature form so a tamper of the prose breaks both signature verification and a cheap recompute. `?include_exports=true` triggers a seq-overlap scan against the `exports` table; pointers (`{ snapshot_id, written_at, data_uri, manifest_uri, data_sha256, byte_size, row_count, seq_lo, seq_hi }`) for cold-tier snapshots whose seq range overlaps the window land in `manifest.parquet_pointers`. Manifest schema bumped to `"3"`; v3 with neither field populated is byte-identical to v2 aside from `schema_version`. `BundleOptions` struct on `build_bundle` collects readme + pointers + signer (extension point for future slices). New `LedgerClient::regulatory_export(window, RegulatoryExportOptions { readme, include_exports })` on `warden-sdk`. New `wardenctl regulatory export --from <RFC3339> --to <RFC3339> [--readme <PATH>] [--include-exports] [--ledger-url <URL>] --output <PATH>` subcommand under a new top-level `regulatory` verb (own surface — distinct from `agents`; no identity gate today since the ledger doesn't gate `/export/regulatory`). 6 new build_bundle unit tests + 4 new http_integration tests (text-content-type sniff, 413 oversize cap, include_exports overlap, readme round-trip + sha256 commit) + 3 SDK tests (mock-server query/header capture, 4xx propagation, request shape) + 3 CLI parse tests. README.txt embedded in the bundle expanded to a 7-step verification checklist.

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
