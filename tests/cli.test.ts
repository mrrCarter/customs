import { generateKeyPairSync } from "node:crypto";
import { existsSync } from "node:fs";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { test } from "node:test";

import { sha256Hex } from "../src/kernel/canonicalJson.js";
import { createDelegationProof, type DelegationClaims } from "../src/kernel/delegation.js";
import { LocalReceiptIssuer } from "../src/kernel/receipts.js";

interface CommandResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

interface TelemetryLine {
  readonly schema: string;
  readonly event: string;
  readonly command: string;
  readonly runId: string;
  readonly traceId: string;
  readonly correlationId: string;
  readonly rootSpanId: string;
  readonly spanId: string;
  readonly parentSpanId: string;
  readonly operation: string;
  readonly status: string;
  readonly durationMs?: number;
  readonly errorCode?: string;
}

function parseTelemetryLines(output: string): TelemetryLine[] {
  assert.notEqual(output.trim(), "");
  return output.trim().split(/\r?\n/).map((line) => JSON.parse(line) as TelemetryLine);
}

function assertNonEmptyString(value: string | undefined): asserts value is string {
  if (typeof value !== "string") {
    assert.fail("expected a string");
  }
  assert.ok(value.length > 0);
}

function assertCliTelemetryContext(lines: readonly TelemetryLine[], expectedOperation: string): void {
  assert.ok(lines.length >= 2);
  const first = lines[0]!;
  assert.equal(first.schema, "customs.cli_event.v1");
  assert.equal(first.operation, expectedOperation);
  assert.equal(first.status, "started");
  assertNonEmptyString(first.command);
  assertNonEmptyString(first.runId);
  assertNonEmptyString(first.traceId);
  assertNonEmptyString(first.correlationId);
  assertNonEmptyString(first.rootSpanId);
  const spanIds = new Set<string>();
  for (const line of lines) {
    assert.equal(line.schema, "customs.cli_event.v1");
    assert.equal(line.command, first.command);
    assert.equal(line.runId, first.runId);
    assert.equal(line.traceId, first.traceId);
    assert.equal(line.correlationId, first.correlationId);
    assert.equal(line.rootSpanId, first.rootSpanId);
    assert.equal(line.parentSpanId, first.rootSpanId);
    assertNonEmptyString(line.operation);
    assertNonEmptyString(line.status);
    assertNonEmptyString(line.event);
    assertNonEmptyString(line.spanId);
    spanIds.add(line.spanId);
  }
  assert.equal(spanIds.size, lines.length);
}

function runNode(args: readonly string[], env: Readonly<Record<string, string>> = {}): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...args], {
      cwd: process.cwd(),
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"]
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8")
      });
    });
  });
}

async function writePoisonedPackage(packageDir: string): Promise<void> {
  await mkdir(packageDir, { recursive: true });
  await writeFile(
    join(packageDir, "package.json"),
    JSON.stringify({
      name: "@demo/poisoned-cli",
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
}

async function writeDelegationProof(path: string, trustedPublicKeyPath: string): Promise<void> {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const now = Math.floor(Date.now() / 1000);
  const claims: DelegationClaims = {
    iss: "did:aidenid:test",
    sub: "agent:builder-codex",
    aud: "customs.install",
    scope: ["package:install"],
    iat: now,
    exp: now + 3600,
    jti: `cli-${now}`,
    chain_id: "chain:cli"
  };
  const proof = createDelegationProof({ claims, privateKey, publicKey });
  await writeFile(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  await writeFile(trustedPublicKeyPath, `${JSON.stringify(proof.publicJwk, null, 2)}\n`, "utf8");
}

test("customs-install CLI blocks poisoned postinstall and writes a receipt", async () => {
  const temp = await mkdtemp(join(tmpdir(), "customs-cli-install-"));
  const packageDir = join(temp, "poisoned");
  const delegationPath = join(temp, "delegation.json");
  const delegationPublicKeyPath = join(temp, "delegation-public.jwk.json");
  const receiptPath = join(temp, "receipt.json");
  const chainPath = join(temp, "chain.jsonl");
  const issuerKeyPath = join(temp, "issuer-private.jwk.json");
  await writePoisonedPackage(packageDir);
  await writeDelegationProof(delegationPath, delegationPublicKeyPath);

  const result = await runNode([
    join("dist", "src", "cli", "customs-install.js"),
    packageDir,
    "--delegation",
    delegationPath,
    "--trusted-delegation-public-key",
    delegationPublicKeyPath,
    "--receipt",
    receiptPath,
    "--chain",
    chainPath,
    "--issuer-key",
    issuerKeyPath,
    "--create-issuer-key"
  ]);

  assert.equal(result.code, 42);
  const telemetryLines = parseTelemetryLines(result.stderr);
  assertCliTelemetryContext(telemetryLines, "install");
  assert.ok(telemetryLines.some((line) => line.event === "customs_install_materialize_package" && line.operation === "install.materialize_package" && line.status === "started"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_install_materialize_package" && line.operation === "install.materialize_package" && typeof line.durationMs === "number"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_install_evaluate_policy" && line.operation === "install.evaluate_policy" && line.status === "started"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_install_evaluate_policy" && line.operation === "install.evaluate_policy" && typeof line.durationMs === "number"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_receipt_issue" && line.operation === "receipt.issue" && line.status === "started"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_receipt_issue" && line.operation === "receipt.issue" && typeof line.durationMs === "number"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_receipt_write" && line.operation === "receipt.write" && typeof line.durationMs === "number"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_install_finished" && line.status === "blocked" && typeof line.durationMs === "number"));
  assert.equal(existsSync(join(packageDir, "POSTINSTALL_RAN.txt")), false);
  assert.equal(existsSync(receiptPath), true);
  const parsed = JSON.parse(result.stdout) as { readonly decision: { readonly decision: string; readonly blocked: boolean } };
  assert.equal(parsed.decision.decision, "deny");
  assert.equal(parsed.decision.blocked, true);
});

test("customs-install CLI fails closed when issuer key is missing", async () => {
  const temp = await mkdtemp(join(tmpdir(), "customs-cli-missing-issuer-"));
  const packageDir = join(temp, "poisoned");
  const receiptPath = join(temp, "receipt.json");
  const telemetryPath = join(temp, "install-telemetry.ndjson");
  await writePoisonedPackage(packageDir);

  const result = await runNode(
    [
      join("dist", "src", "cli", "customs-install.js"),
      packageDir,
      "--receipt",
      receiptPath,
      "--chain",
      join(temp, "chain.jsonl"),
      "--issuer-key",
      join(temp, "missing-issuer-private.jwk.json")
    ],
    { CUSTOMS_TELEMETRY_FILE: telemetryPath }
  );

  assert.equal(result.code, 1);
  assert.match(result.stderr, /issuer private key not found/);
  assert.equal(existsSync(join(packageDir, "POSTINSTALL_RAN.txt")), false);
  assert.equal(existsSync(receiptPath), false);
  const telemetryLines = parseTelemetryLines(await readFile(telemetryPath, "utf8"));
  assertCliTelemetryContext(telemetryLines, "install");
  assert.ok(telemetryLines.some((line) => line.event === "customs_install_load_receipt_issuer" && line.operation === "install.load_receipt_issuer" && line.status === "started"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_install_load_receipt_issuer" && line.operation === "install.load_receipt_issuer" && line.status === "failed" && typeof line.durationMs === "number"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_install_error" && line.status === "error" && line.errorCode === "Error" && typeof line.durationMs === "number"));
});

test("customs-verify-receipt CLI verifies valid receipts and rejects signature tampering", async () => {
  const temp = await mkdtemp(join(tmpdir(), "customs-cli-verify-"));
  const packageDir = join(temp, "poisoned");
  const delegationPath = join(temp, "delegation.json");
  const delegationPublicKeyPath = join(temp, "delegation-public.jwk.json");
  const receiptPath = join(temp, "receipt.json");
  const trustedPublicKeyPath = join(temp, "trusted-public.jwk.json");
  const telemetryPath = join(temp, "verify-telemetry.ndjson");
  const chainPath = join(temp, "chain.jsonl");
  const issuerKeyPath = join(temp, "issuer-private.jwk.json");
  await writePoisonedPackage(packageDir);
  await writeDelegationProof(delegationPath, delegationPublicKeyPath);
  await runNode([
    join("dist", "src", "cli", "customs-install.js"),
    packageDir,
    "--delegation",
    delegationPath,
    "--trusted-delegation-public-key",
    delegationPublicKeyPath,
    "--receipt",
    receiptPath,
    "--chain",
    chainPath,
    "--issuer-key",
    issuerKeyPath,
    "--create-issuer-key"
  ]);

  const receipt = JSON.parse(await readFile(receiptPath, "utf8")) as {
    readonly publicJwk: Record<string, unknown>;
    jws: string;
    jwsSha256: string;
  };
  await writeFile(trustedPublicKeyPath, `${JSON.stringify(receipt.publicJwk, null, 2)}\n`, "utf8");

  const valid = await runNode(
    [join("dist", "src", "cli", "verify-receipt.js"), receiptPath, "--trusted-public-key", trustedPublicKeyPath],
    { CUSTOMS_TELEMETRY_FILE: telemetryPath }
  );
  assert.equal(valid.code, 0);
  assert.equal(JSON.parse(valid.stdout).ok, true);
  const telemetryLines = parseTelemetryLines(await readFile(telemetryPath, "utf8"));
  assertCliTelemetryContext(telemetryLines, "verify_receipt");
  assert.ok(telemetryLines.some((line) => line.event === "customs_receipt_read" && line.operation === "receipt.read" && line.status === "started"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_receipt_read" && line.operation === "receipt.read" && typeof line.durationMs === "number"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_verify_receipt_read_trusted_public_key" && line.operation === "verify_receipt.read_trusted_public_key" && typeof line.durationMs === "number"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_receipt_verify" && line.operation === "receipt.verify" && line.status === "started"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_receipt_verify" && line.operation === "receipt.verify" && typeof line.durationMs === "number"));
  assert.ok(telemetryLines.some((line) => line.event === "customs_verify_receipt_finished" && line.status === "ok" && typeof line.durationMs === "number"));

  const jwsParts = receipt.jws.split(".");
  assert.equal(jwsParts.length, 3);
  jwsParts[2] = `${jwsParts[2]!.startsWith("A") ? "B" : "A"}${jwsParts[2]!.slice(1)}`;
  receipt.jws = jwsParts.join(".");
  receipt.jwsSha256 = sha256Hex(receipt.jws);
  const tamperedReceiptPath = join(temp, "receipt-tampered.json");
  await writeFile(tamperedReceiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");

  const tampered = await runNode([join("dist", "src", "cli", "verify-receipt.js"), tamperedReceiptPath, "--trusted-public-key", trustedPublicKeyPath]);
  assert.equal(tampered.code, 1);
  const verification = JSON.parse(tampered.stdout) as { readonly ok: boolean; readonly reason: string };
  assert.equal(verification.ok, false);
  assert.equal(verification.reason, "JWS signature verification failed");

  const forged = new LocalReceiptIssuer().issue({
    actionType: "package_install",
    packageName: "@demo/poisoned-cli",
    packageVersion: "1.0.0",
    actorClass: "verified_agent",
    decision: "allow",
    recommendedDecision: "allow",
    mode: "enforce",
    httpStatus: 200,
    blocked: false,
    reasons: ["matched_policy"],
    lifecycleFindings: [],
    delegationChainId: "chain:attacker",
    delegationSubject: "agent:attacker",
    occurredAt: new Date().toISOString()
  });
  const forgedReceiptPath = join(temp, "receipt-forged.json");
  await writeFile(forgedReceiptPath, `${JSON.stringify(forged, null, 2)}\n`, "utf8");
  const forgedVerification = await runNode([join("dist", "src", "cli", "verify-receipt.js"), forgedReceiptPath, "--trusted-public-key", trustedPublicKeyPath]);
  assert.equal(forgedVerification.code, 1);
  const forgedParsed = JSON.parse(forgedVerification.stdout) as { readonly ok: boolean; readonly reason: string };
  assert.equal(forgedParsed.ok, false);
  assert.equal(forgedParsed.reason, "untrusted_issuer_key");

  const mismatchedReceipt = {
    ...receipt,
    publicJwk: new LocalReceiptIssuer().trustedPublicJwk()
  };
  const mismatchedReceiptPath = join(temp, "receipt-mismatched-public-key.json");
  await writeFile(mismatchedReceiptPath, `${JSON.stringify(mismatchedReceipt, null, 2)}\n`, "utf8");
  const mismatched = await runNode([join("dist", "src", "cli", "verify-receipt.js"), mismatchedReceiptPath, "--trusted-public-key", trustedPublicKeyPath]);
  assert.equal(mismatched.code, 1);
  const mismatchedParsed = JSON.parse(mismatched.stdout) as { readonly ok: boolean; readonly reason: string };
  assert.equal(mismatchedParsed.ok, false);
  assert.equal(mismatchedParsed.reason, "receipt_public_key_mismatch");
});

test("CLI entrypoints fail closed for malformed inputs", async () => {
  const temp = await mkdtemp(join(tmpdir(), "customs-cli-fail-"));
  const malformedReceiptPath = join(temp, "malformed-receipt.json");
  const trustedPublicKeyPath = join(temp, "trusted-public.jwk.json");
  await writeFile(malformedReceiptPath, "{not-json", "utf8");
  await writeFile(trustedPublicKeyPath, "{}\n", "utf8");

  const malformedReceipt = await runNode([join("dist", "src", "cli", "verify-receipt.js"), malformedReceiptPath, "--trusted-public-key", trustedPublicKeyPath]);
  assert.equal(malformedReceipt.code, 1);
  assert.match(malformedReceipt.stderr, /JSON|Expected property name|Unexpected token/);

  const missingPackageReceipt = join(temp, "missing-package-receipt.json");
  const missingPackage = await runNode([
    join("dist", "src", "cli", "customs-install.js"),
    join(temp, "missing-package"),
    "--receipt",
    missingPackageReceipt,
    "--chain",
    join(temp, "chain.jsonl"),
    "--issuer-key",
    join(temp, "issuer-private.jwk.json")
  ]);
  assert.equal(missingPackage.code, 1);
  assert.match(missingPackage.stderr, /package\.json|no such file|ENOENT/);
  assert.equal(existsSync(missingPackageReceipt), false);
});
