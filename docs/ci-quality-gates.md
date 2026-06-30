# CI Quality Gates

Customs v1 treats the install gate, receipt verifier, red-team corpus, and provenance scripts as release-blocking paths.

## Required Checks

| Gate | Command | Covers |
| --- | --- | --- |
| Typecheck | `npm run typecheck` | TypeScript source and test compile safety |
| Unit tests | `npm run test:unit` | trusted delegation proofs, forged delegation rejection, install policy, receipt signing and verification |
| CLI and install-gate integration | `npm run test:integration` | `customs-install`, `customs-verify-receipt`, tarball staging support, persisted issuer keys, trusted delegation key wiring, mandatory trace/correlation telemetry events, install-stage `durationMs`, receipt issue/write/read/verify `durationMs`, failure telemetry on missing issuer keys |
| Red-team corpus | `npm run test:redteam` | p1 postinstall RCE, p2 secret-scan, B1 hook aliases, B5 import-time scope gap |
| Critical dependency audit | `npm run audit:critical` | critical npm advisories |
| Poisoned install proof | `npm run demo:poisoned-install` | live deny receipt and `postinstallRan=false` proof |
| Offline receipt verification | `npm run customs:verify-receipt -- artifacts/poisoned-install-receipt.json --trusted-public-key artifacts/customs-issuer-public.jwk.json` | trusted-key receipt validation |
| Provenance | `npm run test:provenance` | generated build provenance and verification |
| Rollback drill | `npm run release:rollback:smoke` | executable artifact-retention rollback evidence |
| Omar Gate | `.github/workflows/omar-gate.yml` | P0=0 and P1=0 before merge |

`npm run release:smoke` runs the full local release proof: typecheck, the three test lanes, poisoned-install proof, offline receipt verification, provenance verification, and rollback drill evidence.

`.github/workflows/release.yml` adds a pinned GitHub OIDC provenance-attestation step for the local signed provenance artifact. `.github/dependabot.yml` keeps commit-SHA-pinned GitHub Actions current through reviewable update PRs.

## Artifact Boundary

Generated `artifacts/` output is ignored by git. CI uploads only evidence artifacts: receipts, public issuer key, public delegation key, receipt chain, provenance, and rollback evidence when applicable. Private issuer and delegation keys remain local runtime state, default to `$HOME/.customs/issuer-private.jwk.json` for CLI receipt signing and `$HOME/.customs/demo-issuer-private.jwk.json` for the poisoned-install demo, and must not be uploaded or committed.
