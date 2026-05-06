# First-Class Demo Experience — Design Specification

Companion to none of the existing specs in form. Where `CONFIG.md` is one read-only page and `ONBOARDING.md` is a multi-service initiative with a chain version bump, this spec sits between: a public demo surface that spans the marketing site, a Cloudflare Worker, the existing operator console, and three backend services, but introduces no new long-running service and no chain version change.

**Module status:** new, marketing/funnel work. Extends `warden-website` (guided tour), `warden-console` (demo-mode), `warden-ledger` + `warden-hil` (token-scoped read filters and HIL approve enforcement), `warden-chaos-monkey` (extracted into a `warden-chaos-catalog` library + thin CLI wrapper). Adds one new artifact: a Cloudflare Worker for token mint. No new container in `docker-compose.yml`. No new chain version.

Design decided by the `/grill-me` walkthrough on 2026-05-06. Thirteen architectural decisions resolved in sequence; four confirmations on operational tradeoffs. This doc is the consolidated record so the implementation work can begin from a stable baseline.

## 1. What this closes

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

## 2. Audience and success metrics

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

## 3. UX surface

### 3.1 Guided tour

Three-scenario tour on `wardenlabs.com/demo`:

| Order | Scenario | Length (auto-play) | Layer focus |
|---|---|---|---|
| 1 | Indirect injection blocked | 10–15s | Brain |
| 2 | Yellow-tier wire transfer + HIL approve | 45–60s | Brain + Policy + HIL + Ledger (the centerpiece) |
| 3 | Velocity breaker *or* stolen-SVID replay | 15–20s | Policy *or* Identity |

Total auto-play: ~90s. Click-through mode stretches to ~3 min with explanation panels expanded.

**Auto-play is the default** (CISO-friendly). A "step through with explanations" toggle in the corner gives evaluators a click-through path; same animation frames, denser annotation. The centerpiece scenario (wire transfer) is non-negotiable — it's the single most photogenic Warden moment, the only one that shows *control plane* rather than *filter*.

The tour is **fully client-side** (animations + pre-canned responses). No backend hit until the handoff CTA. This is the lazy-session decision: most marketing-site traffic should never touch the VPS.

### 3.2 Console handoff

CTA at end of tour: "Open this in the real console." Click → Cloudflare Worker mints a 30-min HS256 JWT with a unique `correlation_prefix` and `agent_id` claim → handoff URL `https://demo.wardenlabs.com/audit#token=…&prefix=demo-7f3a-`.

Console reads the URL fragment on first hit, swaps it for an HTTP-only `SameSite=Strict` cookie, redirects to the clean URL. Standard fragment-auth pattern; the token never appears in server logs.

### 3.3 In-console action surface

Visitor lands on `/audit`, scoped by token to:

- Their own `correlation_id LIKE 'demo-7f3a-%'` rows.
- *Plus* `source = 'simulator'` rows from the always-on simulator (ambient feel; visitor's actions accent-highlighted).

A new `/demo/fire` page renders the chaos-catalog scenarios as tiles. Click → demo console's backend handler validates the session token, calls `warden_chaos_catalog::fire(scenario_id, agent_id, correlation_prefix, proxy_url)`, redirects to `/audit?correlation_id=…&highlight=…` with the new rows scrolled into view.

HIL approve/deny works on the visitor's own pendings (per-prefix filter enforces). Auto-decision sidecar configured to skip `demo-` prefixes so visitors aren't raced.

## 4. Backend topology

```
Cloudflare (CDN + WAF + Workers + Turnstile)
    │
    ├──► wardenlabs.com           — CF Pages (3 static files, tour animation)
    │
    ├──► api.wardenlabs.com       — CF Worker (Turnstile validation + JWT mint)
    │       only. mint endpoint never reaches origin.
    │
    └──► demo.wardenlabs.com      — Hetzner-class VPS, single region
            └── docker-compose --profile stack up -d
                ├── nats, vault, bootstrap
                ├── ledger, policy-engine, brain, hil, identity, proxy, console
                ├── upstream-stub, simulator (always running, ambient traffic)
                └── website (added 2026-05-06)
```

VPS firewall: accept only Cloudflare IP ranges. The mint endpoint is at the edge — there is no anonymous-traffic-touching surface on the VPS.

Marketing site and demo backend deliberately split: CDN for marketing latency, single-region VPS for demo backend. Subdomain isolation contains abuse blast radius.

## 5. Security model

### 5.1 Token mint

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

### 5.2 Scope enforcement

**Defense-in-depth**: console proxy filters for performance, backends enforce for security.

- A small token-validator (shared crate or duplicated 50-line module) parses the JWT, verifies HS256 signature, returns `{ correlation_prefix, agent_id }` or rejects.
- `warden-ledger` read endpoints (`/audit`, `/audit/correlation/{id}`, `/stream/audit`) accept an optional `?demo_session_token=…`; when valid, filter to `correlation_id LIKE prefix || '%' OR source = 'simulator'`.
- `warden-hil` read endpoints filter the same way; **write endpoints reject if target pending's `correlation_id` doesn't match the prefix** — the load-bearing safety check.
- `warden-console` reads token from cookie, includes it on backend calls. Backends also re-validate.

The `OR source = 'simulator'` is essential — it's how the visitor sees ambient traffic and the audit page never feels dead. Don't accidentally tighten it during code review.

### 5.3 Abuse layering

1. Cloudflare Bot Fight Mode + WAF (free, edge).
2. CF rate limit on `/api/mint-session`: 5/hour per IP.
3. Cloudflare Turnstile validation at mint endpoint.
4. Per-token quota: 50 ledger writes / 50 HIL pendings over 30-min lifetime, then 429.
5. VPS firewall: Cloudflare IP ranges only.

Brain stays in `mock-key` mode (no Anthropic cost).

## 6. Operations

### 6.1 Hosting

- **Marketing**: Cloudflare Pages (free).
- **Demo backend**: Hetzner CCX13 or CCX23 (~$20–30/mo), Caddy or Cloudflare Tunnel for TLS, `docker compose --profile stack up -d`.
- **Worker**: Cloudflare Workers free tier (100k req/day; bump to Paid $5/mo if exceeded).
- **Backups**: weekly `tar` of `ledger-data` + `identity-data` + `hil-data` volumes to Cloudflare R2 (~$1/mo).

### 6.2 Failure mode

**Fail-open**: marketing site (CDN) is independent of backend; tour always works. When the backend `/health` is down, the "open in console" CTA swaps to an email-us banner client-side. No 503 page, no spinner-of-doom. The visitor still gets the tour and a way to reach you.

`/health` composite endpoint is unauthenticated, internal-network-only between containers, returns 200 iff `ledger:8083/health AND hil:8084/health AND console:8085/health` all respond within 1s.

### 6.3 Monitoring

- **UptimeRobot** free tier, 5-min ping to `/health`. Email + SMS on outage.
- **Plausible Analytics** for the funnel (no cookie banner needed).
- On-call truth: it's the operator. SLA = "best effort, business hours, ~15 min response time." Documented in `warden-website/README.md`.

No status page (broadcasts outages to competitors / journalists; CISOs don't subscribe). Failure-state banner is the entire status surface.

### 6.4 Reset cadence

**Never auto-reset.** Chain grows forever — that's the cryptographic flex. ~1KB/row × ~10k rows/day = ~3.5 GB/year, trivial. Existing post-export vacuum tooling (`chain_vacuum_cursor`) is available if disk pressure ever bites; not needed day 1.

### 6.5 Cost ceiling

~$40/mo total. If costs cross $100/mo, something is wrong — investigate before scaling.

## 7. Sequencing

| Week | Deliverable | What it proves |
|---|---|---|
| 1 | Tour animation (3 scenarios, auto-play + click-through) + polished marketing page + Plausible events wired | Visual story works; copy lands; conversion measurable |
| 2 | Receipts-page handoff (live chain rows fetched by sentinel correlation-id, `curl /verify` snippet) | Cryptographic-realness flex without backend complexity |
| **DECISION POINT — measure handoff click-through against thresholds in §2** |
| 3 | VPS + compose deployed at `demo.wardenlabs.com`; existing console behind hardcoded basic-auth (gate against forgotten lockdown); CF DNS+WAF+rate-limits | Real console URL works; ops baseline |
| 4 | CF Worker token mint + Turnstile gate; console demo-mode (URL-fragment → cookie); HIL approve-only filter enforcement | Per-session isolation; defense-in-depth |
| 5 | Ledger filter enforcement; `warden-chaos-catalog` extraction (chaos-monkey becomes thin wrapper); `/demo/fire` curated attack menu | Full kick-the-tires console |
| 6 | Auto-decide skip-prefix flag in simulator; UptimeRobot; weekly R2 backups; reset-cadence policy in `README.md`; reset-week test | Production-grade ops |

The week-3 watch-out: **don't deploy the console with auth disabled and forget to lock it down in week 4.** The hardcoded basic-auth password is the gate against this — it forces an explicit removal in week 4 rather than relying on memory.

## 8. Out of scope

- Per-visitor ephemeral stack (cost shape doesn't match traffic shape).
- Raw payload sandbox (anonymous-visitor abuse surface > marketing benefit).
- Public status page (broadcasts outages; CISOs don't subscribe).
- Email-gate at handoff (kills evaluator funnel; we already have "Book a demo" for lead capture).
- Multi-region failover, HA, formal SLA.
- Internationalization.
- A/B testing tour variants (premature optimization for v1).

## 9. Implementation questions deferred

These emerge during the build, not at design time:

- Specific attack scenario payloads (indirect-injection prompt text, wire-transfer JSON shape).
- Animation copy and narrative beats per scenario.
- Token-expiry-mid-session UX (probably: 401 → modal → re-Turnstile → fresh token → retry last action).
- CSS / brand polish on the demo console vs. operator console default.
- Domain choice (assumes `wardenlabs.com`).
- Where exactly the `warden-chaos-catalog` crate lives (new repo vs. submodule of warden-chaos-monkey).

## 10. Confirmed before writing code

The four operational tradeoffs that gate the green light, all confirmed 2026-05-06:

1. The week-2 kill-switch is real — receipts-only ships if metrics say so.
2. Single VPS, no HA, "best effort business hours" demo SLA is acceptable.
3. `warden-chaos-catalog` extraction is in scope; chaos-monkey becomes a thin wrapper.
4. Shared HS256 JWT secret across CF Worker + ledger + HIL is acceptable, rotated quarterly.
