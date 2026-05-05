# Warden Console Configuration Page — Technical Specification

Companion to `ONBOARDING.md` only in form. Where `ONBOARDING.md` is a multi-service initiative with a chain version bump, a new CLI binary, and five rollout phases, this spec is the opposite end of the scale: one read-only HTML page at `/config` in `warden-console` that answers "what is this binary, what is it talking to, and is everything reachable?" — the implicit question every operator currently answers with `ps`, `printenv`, and `curl` against four URLs.

**Module status:** new, Tier 3 hardening backlog. Local to `warden-console`; one additive change to `warden-sdk` (three new public getters). No new service. No chain version change. No new endpoints on any backend. The only cross-repo dependency is bumping the `warden-sdk` version `warden-console` consumes.

## 1. What this closes

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

## 2. Threat model and posture

### 2.1 Posture

The console's existing read-only surface (`/audit`, `/velocity`, `/stats/*`, `/hil` listing, `/exports`, `/agents`, `/sim`) is **open** — auth gates only the `/hil/{id}/{approve,deny,modify}` POSTs. The README documents the deploy posture: bind to `127.0.0.1`, expose via SSH tunnel or reverse proxy. `/config` matches this posture.

The justification is operational. An auth-gated config page is *worse* during incidents because it hides the very wiring an operator needs to debug auth itself. If WebAuthn is broken, the page that says "your RP id is wrong" must not require WebAuthn.

### 2.2 Threats

| # | Threat | Mitigation |
|---|---|---|
| T1 | Operator pastes a `/config` screenshot into a public Slack channel; the screenshot leaks an OIDC bearer token | Token is never in handler scope; only `bearer_fingerprint() -> Option<String>` (sha256 hex prefix) is available to the template. The fingerprint is non-invertible and safe to print. |
| T2 | Operator pastes a `/config` screenshot; screenshot leaks the HIL session cookie of the rendering operator | Cookie value is held in `AuthState.store` keyed by an opaque UUID; the handler reads `SessionData.name` and never the cookie value. |
| T3 | Future contributor adds `{{ operator_token }}` to a template, exposing the raw token | The handler doesn't have access to the raw token (T1 mitigation makes the regression impossible at the type level). The redaction integration test (§7) is a second line of defense, asserting the rendered body never contains the configured token string. |
| T4 | Operator inadvertently deploys with `cookie_secure=false` in production | Page surfaces the flag prominently; mismatch with deploy posture is visible at a glance. |
| T5 | Pinned build runs against the wrong ledger or HIL because of an env-typo at deploy time | Page renders the *effective* URL (sourced from the SDK client itself, not a copy maintained alongside) and an immediate health badge. |

**Out of threat-model scope:** unauthenticated reverse-proxy bypass (deployment-layer concern, not console concern); active attacker on the operator's host (any defense the page could offer is moot once `/proc/$PID/environ` is readable).

### 2.3 Redaction discipline

Redact-by-architecture, not redact-by-template. The handler must never receive any value that should not be rendered. Concretely:

- The OIDC operator token is held by `AgentsClient` as a private field; the public surface exposes only `bearer_fingerprint() -> Option<String>`. The handler asks for and stores only the fingerprint.
- The HIL session cookie is held by `AuthState.store` keyed by an opaque UUID; the handler reads `SessionData.name` and never the cookie value.
- WebAuthn registered-credential identifiers live in HIL's database. The console does not query them; the page does not render them.

Treat every render as if it will be screenshotted into Slack. The redaction guard test (§7.2) is the mechanical check.

## 3. Page structure

Cards (`rounded-xl bg-white ring-1 ring-slate-200 shadow-card p-5`), single-column stack, four sections in this order. Single-column matches the established density; multi-column would create "the right column got truncated" cases on narrow screens for no information gain.

### 3.1 Console

| Field | Source |
|---|---|
| Bind | `ProcessConfig.bind` (set in `main.rs` from `--bind`) |
| Port | `ProcessConfig.port` (set in `main.rs` from `--port`) |
| Version | `ProcessConfig.version = env!("CARGO_PKG_VERSION")` |
| Git SHA | `ProcessConfig.git_sha = option_env!("WARDEN_CONSOLE_GIT_SHA")` |
| `decided_by` fallback | `AppState.decided_by` |

Rendered as `v0.x.y` or `v0.x.y (abc12345)` depending on whether the build script captured a SHA (§5.3).

### 3.2 Backends (required)

Two rows, ledger and HIL. Each row: URL + health badge.

URL via `LedgerClient::base_url()` (already exists in `warden-sdk`) and `HilClient::base_url()` (added by this spec to `warden-console`). Health badge from §4.

### 3.3 Backends (optional)

Two rows, identity and simulator. Each row probes if the client is `Some`; renders a `not configured (set WARDEN_CONSOLE_IDENTITY_URL / WARDEN_SIMULATOR_URL)` placeholder if `None`.

The identity row also surfaces:

- `agents_tenant` — the tenant scope baked in via `--agents-tenant`.
- Operator token — `configured (sha256: ab12cd34)` or `unset`, sourced from `AgentsClient::bearer_fingerprint()`. The presence boolean and the fingerprint are the same readout (`Some(_)` vs `None`); no additional method needed.

### 3.4 Auth

| Field | Source |
|---|---|
| Session TTL | `AuthState.config.session_ttl_secs` |
| `cookie_secure` | `AuthState.config.cookie_secure` |
| Currently logged in | Server-side: `extract_cookie(headers, SESSION_COOKIE)` → `AuthState.store.get(uuid).await` → `SessionData.name` or `(not logged in — open posture)` |

The "currently logged in" line is server-rendered, **not** JS-driven via `/auth/me`. JS-filled slots come out empty in `curl`, `wget`, headless screenshot capture, and view-source; the page is a screenshot artifact and must be self-contained. The nav stays JS-driven (separate concern; would otherwise require threading a `nav_user` field through every template).

The Auth card does **not** surface the WebAuthn RP id — that's HIL's configuration, not the console's, and the console doesn't hold it. If `/config` ever needs to display backend configuration (per `ONBOARDING.md`-style federation), it goes through the §11 federated-config follow-on, not this card.

The card does **not** surface the active session count, the current session's `expires_at`, or the list of registered WebAuthn credentials. The first two are screenshot footguns (operational signal, hard to keep current with the lazy-expiry session map); the third lives in HIL's database and belongs on a separate "credentials" page if at all.

## 4. Probe contract

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

## 5. Plumbing & wire surface

### 5.1 Route

```
GET /config        # render the page; no other methods
```

No `POST`. No JSON-API counterpart. The page is server-rendered askama HTML, same shape as every other console page. Nav link added to `templates/base.html` after "Simulator", before the right-aligned subtitle/auth span.

### 5.2 New SDK methods (additive, no behavior change)

| Crate | Method | Returns | Rationale |
|---|---|---|---|
| `warden-sdk::SimClient` | `pub fn base_url(&self) -> &Url` | The configured simulator URL | Page renders the URL the client is actually using |
| `warden-sdk::AgentsClient` | `pub fn has_bearer(&self) -> bool` | Whether `with_bearer` was called | Convenience; `bearer_fingerprint().is_some()` is equivalent |
| `warden-sdk::AgentsClient` | `pub fn bearer_fingerprint(&self) -> Option<String>` | sha256 hex prefix (first 8 chars) of the configured token | Diagnostic readout without exposing the token |

`LedgerClient::base_url()` already exists in `warden-sdk`; no change needed.

### 5.3 New console-local additions

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

## 6. Failure & fallback semantics

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

## 7. Test surface

### 7.1 Unit tests

In `warden-console/src/probe.rs`:

- Probe classification — given `(status_code, latency)`, expect Green/Amber/Red. Doesn't open a socket; classification is a pure function.

In `warden-sdk/src/agents.rs`:

- `bearer_fingerprint` — same input always yields the same 8 hex chars; different inputs yield different 8 hex chars; absent bearer returns `None`.

### 7.2 Integration tests

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

### 7.3 Out of test scope

- Tailwind class / DOM structure assertions (brittle, low value).
- Exact latency-ms numbers (timing-flaky on CI).
- Concurrency tests on `tokio::join!` (stdlib semantics, no novel logic).
- `tests/common/mod.rs` extraction (refactor without payoff yet; defer until a third test file needs the helpers).
- `warden-e2e` coverage. The config page does not touch the security pipeline; integration tests in `warden-console` are authoritative.

## 8. Migration & rollout

Two PRs, sequential. No flag, no phased rollout — the page is purely additive and ships in one minor version.

1. **PR #1 — `warden-sdk`.** Add `SimClient::base_url`, `AgentsClient::has_bearer`, `AgentsClient::bearer_fingerprint`. Pure additions, no behavior change. Lands first so PR #2 can bump the SDK dep version.
2. **PR #2 — `warden-console`.** Bump SDK dep, add `HilClient::base_url`, `build.rs`, `ProcessConfig`, `probe.rs`, `/config` route + handler, `templates/config.html`, nav link, tests. One commit, or split plumbing/page/tests within the PR if review prefers smaller diffs; no separate intermediate-broken commit.

There is no `wardenctl` change. There is no chain version bump. There is no policy-engine change. There is no new endpoint on any backend.

## 9. Wire-contract changes (cross-repo grep before renaming)

| Edge | Field added | Repos to grep |
|---|---|---|
| SDK consumers | `SimClient::base_url`, `AgentsClient::has_bearer`, `AgentsClient::bearer_fingerprint` | `warden-sdk`, `warden-console`, `warden-ctl` (future), any external integrators |

No other edges. The page consumes existing `/health` and `/healthz` endpoints unchanged; no backend wire shape shifts.

## 10. Operator preferences (future v2)

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

## 11. What this spec deliberately does not include

- **Mutation surface.** The page is GET-only. Live config edits — adjusting velocity thresholds, HIL TTLs, brain confidence — would require new write endpoints on each backend, audit-trail entries in the chain, and WebAuthn gating. Out of scope; lives in a separate spec if it ever materializes.
- **Federated config view.** Showing every backend's effective config (proxy mTLS chain, policy velocity backend, ledger export sinks, brain model id) implies adding `/config` endpoints across the stack. Not done.
- **Backend versions and SHAs.** Identity exposes `version` on `/healthz`; the others return plain text. Surfacing a per-backend version row requires extending each `/health` to return JSON with a stable shape — a multi-repo change with no current ask. The v1 page renders only the *console's* own version.
- **Active console session count.** Surfacing the count of in-memory `AuthState` sessions is a screenshot footgun (operational signal exposing concurrent operators) and impossible to keep current with the lazy-expiry model.
- **Registered WebAuthn credential listing.** Lives in HIL's database; needs a new HIL endpoint we don't have; belongs on a separate "credentials" page if at all.
- **Build dirty marker.** Adds a second `git status --porcelain` invocation per build for marginal value; the SHA tells you the commit, and the dev case is the only one that benefits.
- **Build timestamp.** Poisons reproducible builds. The release tag is the timestamp that matters.
- **Policy bundle browse/edit.** Different feature, different route, different auth model.
- **Tenant switcher.** Per `IDENTITY.md` §10 and `ONBOARDING.md` §10, console v1 is one-tenant-per-process. The config page reflects whatever the process booted with.
- **Auth gating on `/config`.** §2.1 explains why; making the diagnostic page require working auth is exactly backwards.
- **An "Operator preferences" v1 placeholder card.** §10 explains why.
