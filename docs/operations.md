# Operations Runbook

## Scope

Customs v1 is an artifact-only install clearance proof. It does not mutate production infrastructure and it does not publish packages automatically. The operational control plane is the CLI gate, the CI/Omar checks, and the signed evidence artifacts.

## Release Health Gates

Every release candidate must pass:

1. `npm ci`
2. `npm run typecheck`
3. `npm run test:unit`
4. `npm run test:integration`
5. `npm run test:redteam`
6. `npm run demo:poisoned-install`
7. `npm run customs:verify-receipt -- artifacts/poisoned-install-receipt.json --trusted-public-key artifacts/customs-issuer-public.jwk.json`
8. `npm run test:provenance`
9. `npm run audit:critical`
10. `npm run release:rollback:smoke`
11. Omar Gate with P0=0 and P1=0 before merge

The exact gate-to-behavior mapping is maintained in `docs/ci-quality-gates.md`.
Incident response and kill-switch execution steps are maintained in `docs/runbooks/incident-response.md`.
The release workflow also publishes a GitHub OIDC provenance attestation for `artifacts/provenance/customs-build-provenance.json`.

Required evidence artifacts:

- `artifacts/poisoned-install-receipt.json`
- `artifacts/customs-issuer-public.jwk.json`
- `artifacts/demo-delegation-public.jwk.json`
- `artifacts/customs-receipts.jsonl`
- `artifacts/provenance/customs-build-provenance.json`

Rollback evidence:

- `.github/workflows/rollback.yml` can be dispatched manually with a target artifact and reason.
- `npm run release:rollback:smoke` records `artifacts/rollback.json` locally and in release failure handling.

Operational issuer state:

- `$HOME/.customs/issuer-private.jwk.json` is the default persisted local signing key. Operators may override it with `CUSTOMS_ISSUER_KEY_PATH` or `--issuer-key`.
- Missing issuer keys fail closed unless the caller explicitly bootstraps with `--create-issuer-key`.
- Demo runs may create `artifacts/customs-issuer-private.jwk.json` as local ignored runtime state. It must not be uploaded as release evidence or distributed to verifiers.
- Verifiers pin only `artifacts/customs-issuer-public.jwk.json`.
- If the private key is rotated, regenerate the public anchor and invalidate old receipts unless the verifier explicitly trusts both old and new keys.
- Production readiness requires replacing the local file signer with managed key custody such as KMS/HSM, plus documented owner, rotation cadence, bootstrap ceremony, and public-anchor distribution. The local persisted key is acceptable for the hackathon proof because it is stable and pinnable; it is not the final customer trust-root design.

Operational delegation trust:

- Delegation proofs are not trusted because they contain a valid signature. The verifier must receive a trusted delegation public key from configuration, CLI flag, or `delegationTrustPolicy`.
- `customs-install --delegation <proof.json>` without `--trusted-delegation-public-key <public.jwk.json>` treats the proof as untrusted and denies the request.
- Demo runs write `artifacts/demo-delegation-public.jwk.json` as public evidence. Delegation private keys must remain local runtime state.
- Rotating a delegation issuer requires updating the trusted public key distributed to callers.

Secrets and credential rotation:

- Owner: the release operator owns the hackathon-local receipt issuer key and delegation issuer key. Production must assign a named security owner before customer traffic.
- Inventory: receipt issuer private key, receipt issuer public anchor, delegation issuer private key, delegation issuer public anchor, `SENTINELAYER_TOKEN`, and GitHub release/provenance credentials.
- Cadence: rotate local demo keys after every public demo or immediately after any suspected exposure. Production keys must rotate at least every 90 days, with emergency rotation on exposure, anomalous receipt issuance, stale owner, or failed verifier trust check.
- Bootstrap: create a new private key only through `customs-install --create-issuer-key --issuer-key <path>` or the managed KMS/HSM ceremony. Export only the public anchor and distribute it out-of-band to verifiers.
- Validation: run `npm run demo:poisoned-install`, `npm run customs:verify-receipt -- artifacts/poisoned-install-receipt.json --trusted-public-key artifacts/customs-issuer-public.jwk.json`, and an Omar Gate pass before trusting the new anchor.
- Rollback: keep the previous public anchor only if verifiers explicitly trust both old and new keys during a bounded migration window. Remove the old anchor when migration completes and treat receipts signed by unknown keys as untrusted.

Telemetry:

- CLI commands emit mandatory JSON telemetry for start, success/block/failure, and error exits on critical trust paths.
- Every event includes `runId`, `traceId`, `correlationId`, `rootSpanId`, `spanId`, `parentSpanId`, `operation`, and `status`.
- `CUSTOMS_CORRELATION_ID` may be provided by an upstream runner; otherwise the CLI uses the generated `traceId` as the correlation id.
- JSON telemetry is emitted to stderr by default so CI and operators have latency/failure signal without parsing command stdout.
- Set `CUSTOMS_TELEMETRY_FILE=/path/to/customs.ndjson` to persist JSON lines without changing stdout/stderr contracts.
- Set `CUSTOMS_TELEMETRY_STDERR=0` to suppress stderr only when `CUSTOMS_TELEMETRY_FILE` is set; otherwise stderr remains the mandatory fallback sink.
- Install operation statuses are `started`, `allowed`, `blocked`, and `error`. Receipt verification statuses are `started`, `ok`, `failed`, and `error`.
- Adapter and kernel SLI events include `durationMs` for `install.materialize_package`, `install.read_manifest`, `install.verify_delegation`, `install.evaluate_policy`, `install.load_receipt_issuer`, `install.cleanup_staging`, `receipt.issue`, `receipt.write`, `receipt.read`, `receipt.verify`, `receipt.chain.read_previous`, and `receipt.chain.append`.
- Events include command, decision/result, `durationMs`, and `errorCode`/`errorMessage` on failures. The integration tests fail if any command path loses trace/correlation propagation or the install/receipt SLI events.
- Page on any `customs_install_error`, any `customs_verify_receipt_error`, or any event missing `traceId`, `correlationId`, `spanId`, `operation`, or `status`.
- Page when `customs_install_error` exceeds 0 in 5 minutes, `customs_install_failure_rate` exceeds 2% over 5 minutes, `customs_install_p95_latency_ms` exceeds 30000 over 15 minutes, or `customs_missing_correlation_id_count` exceeds 0 over 5 minutes.
- Alert when `customs_verify_receipt` non-ok results exceed 1% over 5 minutes.

Reliability objectives and dashboards:

- SLI: install gate success means the CLI emits `customs_install_finished` with `status` `allowed` or `blocked` and no `customs_install_error`.
- SLO: install gate success rate must be >= 99.5% over 7 days for valid operator invocations; receipt verification success for genuine release evidence must be 100%.
- Latency objective: `customs_install_p95_latency_ms` < 30000 over 15 minutes and `customs_verify_receipt_p95_latency_ms` < 5000 over 15 minutes.
- Error budget: if the 7-day install gate success SLO is breached, stop release promotion until the failing package target, issuer key id, delegation key id, and Omar run id are recorded.
- Required dashboard panels: install attempts by status, install p95/p99 latency, receipt verification ok/failed count, missing correlation id count, issuer key id distribution, delegation verification failures by reason, rollback workflow runs, and Omar P0/P1 count.
- Dashboard owner: release operator for the hackathon proof; production must assign security and platform owners with pager escalation before customer traffic.

Demo safety:

- The demo runner generates a temporary marker-only package for proving block-before-exec.
- Its generated `postinstall.js` writes `POSTINSTALL_RAN.txt` and does not read environment variables, spawn child processes, or perform network/file exfiltration.

## Kill Switch

The v1 kill switch is fail-closed:

- Remove or rotate the trusted issuer public key distributed to verifiers.
- Remove or rotate the trusted delegation public key distributed to gate callers.
- Rotate the configured private issuer key before issuing new receipts.
- Disable the `customs-install` wrapper in the caller path and fall back to manual review.
- Dispatch `.github/workflows/rollback.yml` against the previous signed evidence artifact or run `npm run release:rollback:smoke` locally to capture rollback evidence.
- Treat any `customs-verify-receipt` result other than `ok: true` as a hard stop.
- Do not accept a receipt that lacks an out-of-band trusted issuer key.
- Do not accept a `verified_agent` claim unless the delegation proof verified against an out-of-band trusted delegation key.

Emergency command path:

```bash
# Local evidence capture
npm run release:rollback:smoke

# GitHub workflow dispatch after the repo has a remote
gh workflow run rollback.yml -f target_artifact=<previous-signed-evidence-artifact> -f reason=<incident-id>
```

Post-checks:

```bash
npm run demo:poisoned-install
npm run customs:verify-receipt -- artifacts/poisoned-install-receipt.json --trusted-public-key artifacts/customs-issuer-public.jwk.json
sentinelayer-cli /omargate deep --path . --json
```

## Incident Response

Use `docs/runbooks/incident-response.md` for the detailed procedure. The short path for forged receipts, unexpected `allow`, marker-file execution, or receipt-chain mismatch is:

1. Stop release promotion.
2. Preserve `artifacts/`, `.sentinelayer/reviews/`, and `.sentinelayer/runs/`.
3. Run `npm test` and `node C:/tmp/redteam-customs/rt-attack.mjs` if the red-team corpus is available.
4. Rotate the trusted issuer key before issuing any new receipts.
5. Record the failing receipt, trusted public key, package target, and Omar run id in the incident note.

## Known Boundary

Customs v1 only gates install-time lifecycle execution. Import-time/runtime execution is deliberately out of scope until a runtime/import boundary exists. The B5 test must keep proving and documenting that limitation. External claims must use the lifecycle qualifier: "blocks poisoned install-lifecycle hooks before execution," not generic "blocks poisoned packages."
