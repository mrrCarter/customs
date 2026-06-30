# Customs Incident Response Runbook

## Triggers

Open an incident if any of these happen:

- A package lifecycle marker appears after a Customs deny.
- `customs-verify-receipt` returns `ok: true` for an untrusted, forged, spoofed, or tampered receipt.
- The receipt signer key does not match the distributed `artifacts/customs-issuer-public.jwk.json` anchor.
- A forged delegation proof with an attacker-controlled key produces `verified_agent`.
- A delegation proof verifies without an out-of-band trusted delegation public key.
- Omar Gate reports P0 or P1 findings on the release PR.
- A private issuer or delegation key is found in git history, release artifacts, logs, or chat transcripts.

## Escalation And Ownership

| Severity | Trigger | Decision owner | Response target |
| --- | --- | --- | --- |
| SEV1 | Forged receipt verifies, forged delegation becomes `verified_agent`, lifecycle marker appears after deny, or private key exposure | release operator plus security owner | acknowledge in 15 minutes, kill switch before any further release promotion |
| SEV2 | Omar P0/P1 on PR, receipt-chain mismatch, verifier trust-anchor mismatch | release operator | acknowledge in 30 minutes, block merge until fixed |
| SEV3 | Documentation, dashboard, or nonblocking P2/P3 operational gap | builder or release operator | triage in one working day |

Required authority:

- Local demo/hackathon: filesystem access to the configured issuer key path and permission to stop callers from using `customs-install`.
- GitHub workflow rollback: repo write access with `workflow_dispatch` permission.
- Production follow-up: managed key-custody role for KMS/HSM rotation plus approval from the security owner.

## Kill Switch

Customs v1 is fail-closed. To stop trust in new receipts:

1. Stop release promotion and package installation through the affected gate.
2. Remove the affected public issuer key from any verifier trust policy.
3. Remove the affected public delegation key from any gate trust policy.
4. Rotate the configured private issuer key before issuing new receipts (`CUSTOMS_ISSUER_KEY_PATH`, `--issuer-key`, or the default `$HOME/.customs/issuer-private.jwk.json`).
5. Rotate the affected delegation issuer key before accepting new `verified_agent` claims.
6. Disable `customs-install` in the caller path and require manual package review.
7. Treat every receipt signed by the revoked key as untrusted unless a separate incident review explicitly blesses it.

Environment-specific invocation:

| Environment | Command or action | Expected result |
| --- | --- | --- |
| Local/demo | Remove the affected public anchor from the verifier command and do not pass `--create-issuer-key` until a new key is approved. | `customs-verify-receipt` fails closed instead of accepting receipts from the revoked key. |
| Local/demo | Move the affected private key out of use: `Move-Item -LiteralPath $env:USERPROFILE\\.customs\\issuer-private.jwk.json -Destination $env:USERPROFILE\\.customs\\issuer-private.jwk.revoked.json` on Windows, or `mv ~/.customs/issuer-private.jwk.json ~/.customs/issuer-private.jwk.revoked.json` on macOS/Linux. | New receipt issuance fails closed with `issuer private key not found` until an operator explicitly bootstraps or points at a replacement key. |
| Caller integration | Remove `customs-install` from the package-install path and require manual package review. | No automated package install proceeds through a suspect trust root. |
| GitHub rollback | `gh workflow run rollback.yml -f target_artifact=<previous-signed-evidence-artifact> -f reason=<incident-id>` | `artifacts/rollback.json` is uploaded with `ok: true`, target, reason, and timestamp. |

Capture rollback evidence immediately:

```bash
npm run release:rollback:smoke
```

When the repository has a GitHub remote, dispatch the rollback workflow with the previous signed evidence artifact or release id:

```bash
gh workflow run rollback.yml -f target_artifact=<previous-signed-evidence-artifact> -f reason=<incident-id>
```

Post-invocation verification:

```bash
npm run demo:poisoned-install
npm run customs:verify-receipt -- artifacts/poisoned-install-receipt.json --trusted-public-key artifacts/customs-issuer-public.jwk.json
sentinelayer-cli /omargate deep --path . --json
```

Reactivation criteria:

1. Replacement issuer and delegation public anchors are distributed out-of-band.
2. Genuine receipts verify only against the replacement issuer public anchor.
3. Forged receipts and delegations fail with the expected untrusted/mismatch reasons.
4. Omar Gate reports P0=0 and P1=0 on the PR head.
5. The verifier records approval under the PR or Senti thread.

## Containment

Preserve evidence before cleanup:

- `artifacts/poisoned-install-receipt.json`
- `artifacts/customs-issuer-public.jwk.json`
- `artifacts/demo-delegation-public.jwk.json`
- `artifacts/customs-receipts.jsonl`
- `.sentinelayer/reports/`
- `.sentinelayer/reviews/`
- the package tarball or package directory that triggered the incident

Do not upload or paste any private issuer key, including demo-local `$HOME/.customs/demo-issuer-private.jwk.json` or a path supplied through `CUSTOMS_DEMO_ISSUER_KEY_PATH` / `CUSTOMS_ISSUER_KEY_PATH`. Do not upload or paste delegation private keys.

## Verification Checks

Run these from a clean checkout:

```bash
npm ci
npm run typecheck
npm run test:unit
npm run test:integration
npm run test:redteam
npm run demo:poisoned-install
npm run customs:verify-receipt -- artifacts/poisoned-install-receipt.json --trusted-public-key artifacts/customs-issuer-public.jwk.json
npm run test:provenance
npm run audit:critical
sl /omargate deep --path . --json
```

If the external red-team corpus is available, also run:

```bash
node C:/tmp/redteam-customs/rt-attack.mjs
node C:/tmp/redteam-customs/rt-retest-f2.mjs
```

## Rollback Verification

Rollback is not complete until these checks pass:

```bash
npm run release:rollback:smoke
npm run test:provenance
npm run demo:poisoned-install
npm run customs:verify-receipt -- artifacts/poisoned-install-receipt.json --trusted-public-key artifacts/customs-issuer-public.jwk.json
```

Expected rollback evidence is `artifacts/rollback.json` with `ok: true`, the selected target artifact, and the incident reason. Preserve that file with the incident record.

## Recovery Criteria

Do not resume release promotion until all are true:

- `postinstallRan=false` for the poisoned-install proof.
- Genuine receipts verify against the shipped public anchor.
- Forged, spoofed, and tampered receipts fail.
- Genuine delegations verify only against a trusted delegation public key.
- Forged delegation proofs with attacker keys fail as untrusted and never produce `verified_agent`.
- Omar Gate reports P0=0 and P1=0 on the PR head.
- The verifier has re-run the cross-process signer-anchor check and the forged-delegation check.

Recovery execution checklist:

1. Confirm the dependency path is healthy by rerunning `npm ci`, `npm run typecheck`, and the release smoke.
2. Confirm telemetry shows no `customs_install_error` spike and no missing correlation ids for 15 minutes of test traffic.
3. Confirm the current release artifact, rollback evidence, and Omar report paths are attached to the incident record.
4. Get release-operator sign-off and verifier sign-off before re-enabling automated install clearance.
5. Open a follow-up ticket for any remaining P2/P3 findings, including owner and target date.

## Post-Incident

Record:

- incident trigger and timeline
- affected package target
- revoked key id and replacement key id
- revoked delegation key id and replacement delegation key id, if affected
- Omar run id
- failing receipt and verification output
- follow-up tests or policy changes
