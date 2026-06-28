# Customs

Local clearance layer for autonomous software actions. V1 proves a package-install gate: inspect before lifecycle execution, block poisoned lifecycle hooks from package directories or tarballs, and print an offline-verifiable Ed25519 signed receipt with hash-chain evidence.

## Commands

```bash
npm install
npm test
npm run demo:poisoned-install
npm run customs:install -- ./package.tgz --delegation ./delegation.json --trusted-delegation-public-key ./delegation-public.jwk.json --receipt ./receipt.json --chain ./chain.jsonl --create-issuer-key --keep-staging
npm run customs:verify-receipt -- artifacts/poisoned-install-receipt.json --trusted-public-key artifacts/customs-issuer-public.jwk.json
npm run release:smoke
```

The demo generates a temporary marker-only package with a `postinstall.js` that writes `POSTINSTALL_RAN.txt` if executed; a passing gate blocks before that file appears.

`customs-install` signs receipts with a persisted local issuer key. The default CLI key path is `$HOME/.customs/issuer-private.jwk.json` (or `%USERPROFILE%\.customs\issuer-private.jwk.json` on Windows), overrideable with `CUSTOMS_ISSUER_KEY_PATH` or `--issuer-key`. Missing keys fail closed unless `--create-issuer-key` is supplied for explicit bootstrap. The verifier receives only the exported public anchor at `artifacts/customs-issuer-public.jwk.json`; private keys must stay local.

Delegation proofs are also fail-closed. A proof signature is verified only with a trusted delegation public key supplied out-of-band by `--trusted-delegation-public-key` or `delegationTrustPolicy`; the embedded `publicJwk` in the proof never grants trust by itself. The demo emits `artifacts/demo-delegation-public.jwk.json` as the public delegation anchor.

## Red-Team Proof Scope

`npm test` includes generated tarball controls for the first red-team corpus:

- p1 Clinejection-style `postinstall` RCE: control npm install executes the marker; Customs stages with `--ignore-scripts`, denies, and writes a verifiable receipt.
- p2 Nx-style secret-scan `postinstall`: control npm install executes the marker; Customs denies before the scanner can run.
- B1 hook-alias payload in `preinstall` and `prepare`: control npm install executes the marker; Customs catches the denied lifecycle surface.
- B5 import-time payload: Customs records this as an install-gate scope gap. A package with no lifecycle script is allowed by the install gate, then the control `require()` proves runtime execution still needs a later runtime/import boundary.
- F2 receipt forgery: receipt verification requires a trusted issuer public key supplied outside the receipt. A self-signed attacker receipt with an embedded attacker key is rejected as `untrusted_issuer_key`, and a receipt whose embedded public key no longer matches its `keyId` is rejected as `receipt_public_key_mismatch`.
- F4 delegation forgery: delegation verification requires a trusted delegation public key supplied outside the proof. A self-signed attacker proof with a fake issuer is rejected as `untrusted_delegation_issuer`, and key-id spoofing is rejected as `delegation_public_key_mismatch`.

## Kernel

- Real Ed25519 delegation proof verification against an out-of-band trusted delegation public key.
- Six outcomes: `allow`, `throttle`, `queue`, `sandbox`, `deny`, `price_required`.
- Deterministic install policy for lifecycle scripts.
- Ed25519 compact JWS receipt.
- Append-only hash-chain record.

## Project Structure

`src/kernel` contains the decision kernel. `src/adapters/slInstallGate.ts` is the install enforcement adapter. `src/cli` exposes local commands.

Operational release, kill-switch, rollback, and incident steps live in `docs/operations.md` and `docs/runbooks/incident-response.md`. CI and release-blocking test coverage is mapped in `docs/ci-quality-gates.md`.
