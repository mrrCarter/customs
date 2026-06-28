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

## Immediate Kill Switch

Customs v1 is fail-closed. To stop trust in new receipts:

1. Stop release promotion and package installation through the affected gate.
2. Remove the affected public issuer key from any verifier trust policy.
3. Remove the affected public delegation key from any gate trust policy.
4. Rotate the configured private issuer key before issuing new receipts (`CUSTOMS_ISSUER_KEY_PATH`, `--issuer-key`, or the default `$HOME/.customs/issuer-private.jwk.json`).
5. Rotate the affected delegation issuer key before accepting new `verified_agent` claims.
6. Disable `customs-install` in the caller path and require manual package review.
7. Treat every receipt signed by the revoked key as untrusted unless a separate incident review explicitly blesses it.

## Containment

Preserve evidence before cleanup:

- `artifacts/poisoned-install-receipt.json`
- `artifacts/customs-issuer-public.jwk.json`
- `artifacts/demo-delegation-public.jwk.json`
- `artifacts/customs-receipts.jsonl`
- `.sentinelayer/reports/`
- `.sentinelayer/reviews/`
- the package tarball or package directory that triggered the incident

Do not upload or paste any private issuer key, including demo-local `artifacts/customs-issuer-private.jwk.json`. Do not upload or paste delegation private keys.

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

## Recovery Criteria

Do not resume release promotion until all are true:

- `postinstallRan=false` for the poisoned-install proof.
- Genuine receipts verify against the shipped public anchor.
- Forged, spoofed, and tampered receipts fail.
- Genuine delegations verify only against a trusted delegation public key.
- Forged delegation proofs with attacker keys fail as untrusted and never produce `verified_agent`.
- Omar Gate reports P0=0 and P1=0 on the PR head.
- The verifier has re-run the cross-process signer-anchor check and the forged-delegation check.

## Post-Incident

Record:

- incident trigger and timeline
- affected package target
- revoked key id and replacement key id
- revoked delegation key id and replacement delegation key id, if affected
- Omar run id
- failing receipt and verification output
- follow-up tests or policy changes
