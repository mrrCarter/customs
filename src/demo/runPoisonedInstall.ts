import { generateKeyPairSync } from "node:crypto";
import { access, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runSlInstallGate } from "../adapters/slInstallGate.js";
import { createDelegationProof, delegationTrustPolicyForPublicJwk, type DelegationClaims } from "../kernel/delegation.js";
import { readReceipt, verifyReceipt } from "../kernel/receipts.js";

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function main(): Promise<void> {
  const root = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
  const packageDir = join(await mkdtemp(join(tmpdir(), "customs-demo-poisoned-")), "poisoned-package");
  const marker = resolve(packageDir, "POSTINSTALL_RAN.txt");
  const delegationPath = resolve(root, "artifacts/demo-delegation.json");
  const delegationPublicJwkPath = resolve(root, "artifacts/demo-delegation-public.jwk.json");
  const receiptPath = resolve(root, "artifacts/poisoned-install-receipt.json");
  const issuerKeyPath = resolve(
    process.env.CUSTOMS_DEMO_ISSUER_KEY_PATH ??
      process.env.CUSTOMS_ISSUER_KEY_PATH ??
      join(homedir(), ".customs", "demo-issuer-private.jwk.json")
  );
  const issuerPublicJwkPath = resolve(root, "artifacts/customs-issuer-public.jwk.json");
  const chainPath = resolve(root, "artifacts/customs-receipts.jsonl");
  await mkdir(packageDir, { recursive: true });

  // The demo never invokes npm install; it creates a local marker package and
  // asks Customs to inspect it before any lifecycle hook can execute.
  await writeFile(
    resolve(packageDir, "package.json"),
    `${JSON.stringify({
      name: "@customs-demo/poisoned-postinstall",
      version: "1.0.0",
      scripts: { postinstall: "node postinstall.js" }
    }, null, 2)}\n`,
    "utf8"
  );
  await writeFile(
    resolve(packageDir, "postinstall.js"),
    [
      'import { writeFileSync } from "node:fs";',
      "",
      "// Benign demo marker only: no environment reads, no network, no child process.",
      'writeFileSync("POSTINSTALL_RAN.txt", "This file proves the demo lifecycle script executed.\\n");',
      ""
    ].join("\n"),
    "utf8"
  );
  await mkdir(dirname(delegationPath), { recursive: true });

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const now = Math.floor(Date.now() / 1000);
  const claims: DelegationClaims = {
    iss: "did:aidenid:local-demo",
    sub: "agent:builder-codex",
    aud: "customs.install",
    scope: ["package:install"],
    iat: now,
    exp: now + 300,
    jti: `demo-${now}`,
    chain_id: "chain:customs-demo"
  };
  const proof = createDelegationProof({ claims, privateKey, publicKey });
  await writeFile(delegationPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  await writeFile(delegationPublicJwkPath, `${JSON.stringify(proof.publicJwk, null, 2)}\n`, "utf8");

  const result = await runSlInstallGate({
    packageDir,
    delegationProof: proof,
    delegationTrustPolicy: delegationTrustPolicyForPublicJwk(proof.publicJwk),
    receiptPath,
    chainPath,
    now: new Date(now * 1000),
    issuerKeyPath,
    createIssuerKeyIfMissing: true
  });
  await writeFile(issuerPublicJwkPath, `${JSON.stringify(result.receipt.publicJwk, null, 2)}\n`, "utf8");
  const receipt = await readReceipt(receiptPath);
  const verification = verifyReceipt(receipt, { trustedPublicJwks: [result.receipt.publicJwk] });
  const postinstallRan = await exists(marker);

  const summary = {
    status: result.decision.blocked ? "CUSTOMS_INSTALL_BLOCKED" : "CUSTOMS_INSTALL_ALLOWED",
    package: result.decision.packageName,
    packageDir,
    decision: result.decision.decision,
    reasons: result.decision.reasons,
    lifecycleFindings: result.decision.lifecycleFindings,
    postinstallRan,
    receiptPath,
    delegationPublicJwkPath,
    issuerPublicJwkPath,
    chainPath,
    offlineVerification: verification,
    receipt
  };
  console.log(JSON.stringify(summary, null, 2));

  if (!result.decision.blocked || postinstallRan || !verification.ok) {
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
