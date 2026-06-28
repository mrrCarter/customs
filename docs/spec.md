# Spec

## Project
customs

## Goal
Customs is a local clearance layer for autonomous software actions. The v1 proof blocks poisoned install-time package lifecycle hooks through a SentinelLayer install gate and prints a real offline-verifiable signed receipt backed by a hash chain. The correct v1 claim is lifecycle scoped; runtime/import package execution remains a separate boundary.

## V1 Acceptance

- `npm run demo:poisoned-install` must block `@customs-demo/poisoned-postinstall` before `postinstall.js` runs.
- `customs-install <package.tgz>` must stage tarball inputs with npm lifecycle scripts disabled before policy evaluation.
- The block decision must be `deny` with `poisoned_postinstall_detected`.
- The receipt must be signed with real Ed25519 through Node crypto.
- `npm run customs:verify-receipt -- artifacts/poisoned-install-receipt.json --trusted-public-key artifacts/customs-issuer-public.jwk.json` must verify offline against a trusted issuer key supplied outside the receipt.
- The signing key must be stable across gate runs and independent of caller cwd. CLI installs use `$HOME/.customs/issuer-private.jwk.json` by default, with `CUSTOMS_ISSUER_KEY_PATH` or `--issuer-key` overrides.
- Missing issuer private keys must fail closed unless the caller explicitly bootstraps with `--create-issuer-key` or `createIssuerKeyIfMissing: true`.
- Production trust-root custody must be a follow-up before customer traffic: the local persisted signer must move to KMS/HSM or equivalent managed key custody with explicit ownership, rotation, and public-anchor distribution.
- Delegation verification must fail closed unless the caller supplies a trusted delegation public key outside the proof (`--trusted-delegation-public-key` or `delegationTrustPolicy`).
- The hash-chain record must link `previousHash` to `entryHash`; the first record uses the 64-zero genesis hash.
- `customs-install` and `customs-verify-receipt` must emit structured JSON telemetry with `runId`, `traceId`, `correlationId`, span ids, `operation`, `status`, and `durationMs` for critical install, receipt issue/write/read/verify, and failure paths.
- Red-team tests must prove p1 postinstall, p2 secret-scan, and B1 hook-alias payloads execute under ungated npm controls but do not execute through Customs treatment.
- B5 import-time execution is out of scope for the install gate and must remain explicitly documented until a runtime/import boundary exists.
- Marketing and demo material must say "install-lifecycle execution" and must not claim generic poisoned-package blocking without the lifecycle qualifier.
- Self-signed forged receipts with attacker-controlled embedded public keys must be rejected as `untrusted_issuer_key`; mismatched embedded public-key metadata must be rejected as `receipt_public_key_mismatch`.
- Self-signed forged delegations with attacker-controlled embedded public keys must be rejected as `untrusted_delegation_issuer`; delegation key-id spoofing must be rejected as `delegation_public_key_mismatch`.

## Target audience
developer

## Preferred provider
openai

## Project type
greenfield

## Suggested stack
Node.js, TypeScript, Ed25519, SentinelLayer CLI

## Key features
1. AIdenID decision kernel with Ed25519 verification, delegation proof, policy engine, six-outcome ladder, signed receipt, and hash-chain evidence
2. sl install gate that safely stages package directories and tarballs before lifecycle execution
3. local poisoned-install demo with offline receipt verification
