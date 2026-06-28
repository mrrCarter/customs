#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import { readReceipt, verifyReceipt } from "../kernel/receipts.js";
import type { PublicJwk } from "../kernel/crypto.js";
import { measuredAsyncOperation, type OperationTelemetrySink } from "../kernel/operationTelemetry.js";
import { createCliTelemetrySink, createCliTrace, elapsedMs, emitCliEvent, errorCode, errorMessage, type CliTrace } from "./telemetry.js";

interface CliOptions {
  readonly receiptPath: string;
  readonly trustedPublicKeyPath: string;
}

function usage(): never {
  throw new Error("Usage: customs-verify-receipt <receipt.json> --trusted-public-key <public-jwk.json>");
}

function parseArgs(argv: readonly string[]): CliOptions {
  const receiptPath = argv[0];
  if (receiptPath === undefined || receiptPath.startsWith("-")) {
    usage();
  }
  let trustedPublicKeyPath: string | undefined;
  for (let index = 1; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = argv[index + 1];
    if (arg === "--trusted-public-key" && next !== undefined) {
      trustedPublicKeyPath = next;
      index += 1;
      continue;
    }
    usage();
  }
  if (trustedPublicKeyPath === undefined) {
    usage();
  }
  return { receiptPath, trustedPublicKeyPath };
}

async function readTrustedPublicKey(path: string, telemetry: OperationTelemetrySink): Promise<PublicJwk> {
  return measuredAsyncOperation(telemetry, "verify_receipt.read_trusted_public_key", { path }, async () => {
    const parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`${path} must contain a public JWK object`);
    }
    return parsed as PublicJwk;
  });
}

async function main(trace: CliTrace): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const telemetry = createCliTelemetrySink(trace);
  emitCliEvent(trace, "customs_verify_receipt_started", {
    operation: "verify_receipt",
    status: "started",
    receiptPath: options.receiptPath,
    trustedPublicKeyPath: options.trustedPublicKeyPath
  });
  const receipt = await readReceipt(options.receiptPath, telemetry);
  const trustedPublicJwk = await readTrustedPublicKey(options.trustedPublicKeyPath, telemetry);
  const verification = verifyReceipt(receipt, { trustedPublicJwks: [trustedPublicJwk] }, telemetry);
  emitCliEvent(trace, "customs_verify_receipt_finished", {
    operation: "verify_receipt",
    status: verification.ok ? "ok" : "failed",
    verificationOk: verification.ok,
    reason: verification.reason,
    decision: verification.decision,
    durationMs: elapsedMs(trace)
  });
  console.log(JSON.stringify(verification, null, 2));
  if (!verification.ok) {
    process.exitCode = 1;
  }
}

const trace = createCliTrace("customs-verify-receipt");
main(trace).catch((error: unknown) => {
  emitCliEvent(trace, "customs_verify_receipt_error", {
    operation: "verify_receipt",
    status: "error",
    errorCode: errorCode(error),
    errorMessage: errorMessage(error),
    durationMs: elapsedMs(trace)
  });
  console.error(errorMessage(error));
  process.exitCode = 1;
});
