# Customs V1 Build Plan

Generated: 2026-06-28
Owner: builder-codex
Session: 38a3ee95-a5b6-45b3-a57d-774e160e53b1
Incident response: `docs/runbooks/incident-response.md`
Kill switch: revoke verifier trust in the public issuer key, rotate the configured private issuer key, disable `customs-install`, and require manual package review.

## Scope

V1 proves the smallest real loop:

1. Agent invokes the Customs install gate against a package.
2. Gate inspects lifecycle scripts before install execution.
3. Poisoned `postinstall` is detected and blocked.
4. A real Ed25519-signed receipt is printed and written.
5. Receipt verifies offline from the included public JWK and hash-chain entry.

## Checklist

- [x] Scaffold lean repo via `create-sentinelayer` in BYOK mode.
- [x] Lock `customs` in Senti before edits.
- [x] Port narrow AIdenID kernel patterns: Ed25519 verify, delegation proof, six-outcome policy, signed receipt, hash chain.
- [x] Wire `slInstallGate` adapter and CLI entrypoints.
- [x] Add poisoned postinstall demo fixture.
- [x] Add unit/integration tests for crypto, policy, receipts, blocked install, CLI failures, and receipt tampering.
- [x] Run `npm install` (0 vulnerabilities at install time).
- [x] Run `npm run typecheck`.
- [x] Run `npm test` (7 tests passing).
- [x] Run `npm run demo:poisoned-install` (blocked, `postinstallRan=false`, receipt offline verification `ok=true`).
- [x] Run `npm run release:smoke` (typecheck, tests, demo, receipt verify, provenance generate/verify).
- [x] Run `npm run audit:critical` (0 vulnerabilities).
- [x] Run local Omar/SentinelLayer scan: `omargate-1782680813769-b25428d5`, P0=0, P1=0, blocking=false.
- [x] Post Senti evidence and hand off to verifier (reply action `c6974d36-ddb9-40e7-88fc-63b8779d033c`).

## Codex Red-Team Infra Addendum

- [x] Verify exact repo path for peers: `C:\Users\carter\Desktop\Projects_2025\PlexAura Inc\current_proj_march2026\customs`.
- [x] Extend `customs-install` to safely stage tarball/package targets with npm `--ignore-scripts` before reading the package manifest.
- [x] Add `--keep-staging` for red-team evidence so tests can prove no lifecycle marker was dropped in the staged treatment directory.
- [x] Add generated tarball control/treatment tests for p1 postinstall RCE, p2 secret-scan postinstall, and B1 hook-alias lifecycle payloads.
- [x] Add B5 import-time proof as an explicit install-gate scope gap: Customs allows the package at install time, then the control `require()` executes the runtime marker.
- [x] Fix red-team F2 receipt forgery: `customs-verify-receipt` now requires a trusted issuer public key supplied outside the receipt and rejects self-signed forged receipts as `untrusted_issuer_key`.
- [x] Run `npm run typecheck` and `npm test` after the harness changes.
- [x] Rerun `npm run typecheck`, `npm test`, red-team `C:\tmp\redteam-customs\rt-attack.mjs`, and `npm run release:smoke` after F2 fix.
- [x] Close F2b issuer drift: adapter default issuer key path is fixed under `$HOME/.customs/issuer-private.jwk.json`, missing signer keys fail closed unless explicit bootstrap is requested, and `customs-issuer-public.jwk.json` is the out-of-band verifier anchor.
- [x] Add regression coverage for `receipt_public_key_mismatch`, trusted-metadata forged signatures, persisted issuer key paths, and cwd-drift-safe default issuer path.
- [x] Rerun final proof after F2b: `npm run typecheck`, `npm test` (13/13), `npm run release:smoke`, `npm run audit:critical`, `node C:\tmp\redteam-customs\rt-attack.mjs`, and `node C:\tmp\redteam-customs\rt-retest-f2.mjs`.
- [x] Address Omar P1 follow-up set: pin Omar checkout action to SHA, split CI/release unit/integration/red-team/provenance gates, enforce artifact-only v1 release with no `npm publish`, and add `docs/runbooks/incident-response.md`.
- [x] Close F4 delegation forgery: delegation verification must use a trusted issuer key policy and reject attacker self-signed `verified_agent` proofs.
- [x] Add regression coverage for forged delegation rejection, untrusted delegation fail-closed behavior, and genuine registered issuer acceptance.
- [x] Wire delegation trust policy through the install gate, CLI, demo, and red-team corpus.
- [x] Address Omar P1 release-hardening follow-up: GitHub Actions SHA maintenance via Dependabot, pinned GitHub provenance attestation, executable rollback script, and manual rollback workflow.
- [x] Rerun proof after F4: `npm run typecheck`, `npm test` (19/19), `npm run release:smoke`, `npm run audit:critical` (0 vulnerabilities), external red-team F2/F2b/F4 repros, and Omar `omargate-1782686585127-89134176` (P0=0, P1=0, blocking=false).

## Notes

- Do not touch `../AIdenID`.
- Do not fake crypto. Any failure in signing or verification blocks completion.
- Keep PR scope limited to the local Customs scaffold and V1 proof.
