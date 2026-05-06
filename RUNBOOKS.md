# Runbooks

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

The Tier 3 observability stack (Prometheus `/metrics`, OTEL trace
export, JSON logs) is the source of truth — every runbook leads with
the metric or log line that confirms the failure rather than guessing
from symptoms. See `repos/warden-*/README.md` per service for the
metric catalogue.

---

## 1. Proxy crashed

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

## 2. NATS down

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

## 3. Ledger chain invalid

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
suspected; dev lead otherwise. Tier 3 E6 (regulatory export) is the
audience that cares — they get the chain hash as the integrity proof.

---

## 4. HIL queue stuck

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

## 5. Identity service unreachable

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
