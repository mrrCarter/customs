import { generateKeyPairSync } from "node:crypto";
import { existsSync } from "node:fs";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { test } from "node:test";

import { DEFAULT_RECEIPT_ISSUER_KEY_PATH, runSlInstallGate } from "../src/adapters/slInstallGate.js";
import { createDelegationProof, delegationTrustPolicyForPublicJwk, type DelegationClaims } from "../src/kernel/delegation.js";
import { GENESIS_HASH, LocalReceiptIssuer, readReceipt, verifyReceipt } from "../src/kernel/receipts.js";

test("default receipt issuer path is anchored against cwd drift", () => {
  assert.equal(isAbsolute(DEFAULT_RECEIPT_ISSUER_KEY_PATH), true);
});

test("sl install gate blocks poisoned postinstall before execution and writes verifiable receipt", async () => {
  const temp = await mkdtemp(join(tmpdir(), "customs-install-"));
  const packageDir = join(temp, "poisoned");
  await mkdir(packageDir, { recursive: true });
  await writeFile(
    join(packageDir, "package.json"),
    JSON.stringify({
      name: "@demo/poisoned",
      version: "1.0.0",
      scripts: { postinstall: "node postinstall.js" }
    }),
    "utf8"
  );
  await writeFile(
    join(packageDir, "postinstall.js"),
    "import { writeFileSync } from 'node:fs'; writeFileSync('POSTINSTALL_RAN.txt', 'bad');\n",
    "utf8"
  );

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const now = Math.floor(Date.now() / 1000);
  const claims: DelegationClaims = {
    iss: "did:aidenid:test",
    sub: "agent:builder-codex",
    aud: "customs.install",
    scope: ["package:install"],
    iat: now,
    exp: now + 60,
    jti: "install-test",
    chain_id: "chain:test"
  };
  const delegationProof = createDelegationProof({ claims, privateKey, publicKey });
  const result = await runSlInstallGate({
    packageDir,
    delegationProof,
    delegationTrustPolicy: delegationTrustPolicyForPublicJwk(delegationProof.publicJwk),
    receiptPath: join(temp, "receipt.json"),
    chainPath: join(temp, "chain.jsonl"),
    now: new Date(now * 1000),
    receiptIssuer: new LocalReceiptIssuer()
  });

  assert.equal(result.decision.decision, "deny");
  assert.equal(result.decision.blocked, true);
  assert.equal(existsSync(join(packageDir, "POSTINSTALL_RAN.txt")), false);

  const receipt = await readReceipt(join(temp, "receipt.json"));
  assert.equal(verifyReceipt(receipt, { trustedPublicJwks: [result.receipt.publicJwk] }).ok, true);
  assert.equal(receipt.chain.previousHash, GENESIS_HASH);

  const chain = await readFile(join(temp, "chain.jsonl"), "utf8");
  assert.match(chain, /"decision":"deny"/);
  assert.match(chain, new RegExp(receipt.chain.entryHash));
});

test("sl install gate rejects forged delegation even when the package is clean", async () => {
  const temp = await mkdtemp(join(tmpdir(), "customs-install-forged-delegation-"));
  const packageDir = join(temp, "safe");
  await mkdir(packageDir, { recursive: true });
  await writeFile(
    join(packageDir, "package.json"),
    JSON.stringify({
      name: "@demo/safe-forged-delegation",
      version: "1.0.0",
      scripts: {}
    }),
    "utf8"
  );

  const trusted = generateKeyPairSync("ed25519");
  const attacker = generateKeyPairSync("ed25519");
  const now = Math.floor(Date.now() / 1000);
  const trustedProof = createDelegationProof({
    claims: {
      iss: "did:aidenid:trusted",
      sub: "agent:trusted",
      aud: "customs.install",
      scope: ["package:install"],
      iat: now,
      exp: now + 60,
      jti: "trusted-install-test",
      chain_id: "chain:trusted"
    },
    privateKey: trusted.privateKey,
    publicKey: trusted.publicKey
  });
  const forgedProof = createDelegationProof({
    claims: {
      iss: "did:aidenid:TOTALLY-FAKE-ISSUER",
      sub: "agent:attacker-controlled",
      aud: "customs.install",
      scope: ["package:install"],
      iat: now,
      exp: now + 60,
      jti: "forged-install-test",
      chain_id: "chain:attacker-invented"
    },
    privateKey: attacker.privateKey,
    publicKey: attacker.publicKey
  });

  const result = await runSlInstallGate({
    packageDir,
    delegationProof: forgedProof,
    delegationTrustPolicy: delegationTrustPolicyForPublicJwk(trustedProof.publicJwk),
    receiptPath: join(temp, "receipt.json"),
    chainPath: join(temp, "chain.jsonl"),
    now: new Date(now * 1000),
    receiptIssuer: new LocalReceiptIssuer()
  });

  assert.equal(result.decision.decision, "deny");
  assert.equal(result.decision.blocked, true);
  assert.equal(result.decision.actorClass, "signed_agent");
  assert.ok(result.decision.reasons.includes("untrusted_delegation_issuer"));
  assert.equal(result.decision.delegationSubject, undefined);
});

test("sl install gate persists issuer identity when given an issuer key path", async () => {
  const temp = await mkdtemp(join(tmpdir(), "customs-install-issuer-"));
  const packageDir = join(temp, "safe");
  const issuerKeyPath = join(temp, "issuer-private.jwk.json");
  const chainPath = join(temp, "chain.jsonl");
  await mkdir(packageDir, { recursive: true });
  await writeFile(
    join(packageDir, "package.json"),
    JSON.stringify({
      name: "@demo/safe",
      version: "1.0.0",
      scripts: {}
    }),
    "utf8"
  );

  const first = await runSlInstallGate({
    packageDir,
    receiptPath: join(temp, "receipt-1.json"),
    chainPath,
    issuerKeyPath,
    createIssuerKeyIfMissing: true
  });
  const second = await runSlInstallGate({
    packageDir,
    receiptPath: join(temp, "receipt-2.json"),
    chainPath,
    issuerKeyPath
  });

  assert.equal(existsSync(issuerKeyPath), true);
  assert.equal(first.receipt.keyId, second.receipt.keyId);
  assert.equal(verifyReceipt(second.receipt, { trustedPublicJwks: [first.receipt.publicJwk] }).ok, true);
});

test("sl install gate fails closed when issuer key is missing and bootstrap is not explicit", async () => {
  const temp = await mkdtemp(join(tmpdir(), "customs-install-missing-issuer-"));
  const packageDir = join(temp, "safe");
  await mkdir(packageDir, { recursive: true });
  await writeFile(
    join(packageDir, "package.json"),
    JSON.stringify({
      name: "@demo/safe-missing-issuer",
      version: "1.0.0",
      scripts: {}
    }),
    "utf8"
  );

  await assert.rejects(
    runSlInstallGate({
      packageDir,
      receiptPath: join(temp, "receipt.json"),
      chainPath: join(temp, "chain.jsonl"),
      issuerKeyPath: join(temp, "missing-issuer-private.jwk.json")
    }),
    /issuer private key not found/
  );
});
