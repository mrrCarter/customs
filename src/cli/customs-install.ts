#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import { DEFAULT_RECEIPT_ISSUER_KEY_PATH, runSlInstallGate } from "../adapters/slInstallGate.js";
import {
  delegationTrustPolicyForPublicJwk,
  type DelegationProof,
  type DelegationTrustPolicy
} from "../kernel/delegation.js";
import type { PublicJwk } from "../kernel/crypto.js";
import { createCliTelemetrySink, createCliTrace, elapsedMs, emitCliEvent, errorCode, errorMessage, type CliTrace } from "./telemetry.js";

interface CliOptions {
  readonly packageDir: string;
  readonly delegationPath?: string | undefined;
  readonly trustedDelegationPublicKeyPath?: string | undefined;
  readonly receiptPath: string;
  readonly chainPath: string;
  readonly keepStaging: boolean;
  readonly issuerKeyPath: string;
  readonly createIssuerKey: boolean;
}

function usage(): never {
  throw new Error(
    "Usage: customs-install <package-dir-or-tarball> --delegation <proof.json> [--trusted-delegation-public-key <public.jwk.json>] --receipt <receipt.json> --chain <chain.jsonl> [--issuer-key <private.jwk.json>] [--create-issuer-key] [--keep-staging]"
  );
}

function parseArgs(argv: readonly string[]): CliOptions {
  const packageDir = argv[0];
  if (packageDir === undefined || packageDir.startsWith("-")) {
    usage();
  }
  let delegationPath: string | undefined;
  let trustedDelegationPublicKeyPath: string | undefined;
  let receiptPath = "artifacts/customs-install-receipt.json";
  let chainPath = "artifacts/customs-receipts.jsonl";
  let issuerKeyPath = process.env.CUSTOMS_ISSUER_KEY_PATH ?? DEFAULT_RECEIPT_ISSUER_KEY_PATH;
  let keepStaging = false;
  let createIssuerKey = false;
  for (let index = 1; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = argv[index + 1];
    if (arg === "--delegation" && next !== undefined) {
      delegationPath = next;
      index += 1;
      continue;
    }
    if (arg === "--trusted-delegation-public-key" && next !== undefined) {
      trustedDelegationPublicKeyPath = next;
      index += 1;
      continue;
    }
    if (arg === "--receipt" && next !== undefined) {
      receiptPath = next;
      index += 1;
      continue;
    }
    if (arg === "--chain" && next !== undefined) {
      chainPath = next;
      index += 1;
      continue;
    }
    if (arg === "--issuer-key" && next !== undefined) {
      issuerKeyPath = next;
      index += 1;
      continue;
    }
    if (arg === "--keep-staging") {
      keepStaging = true;
      continue;
    }
    if (arg === "--create-issuer-key") {
      createIssuerKey = true;
      continue;
    }
    usage();
  }
  return { packageDir, delegationPath, trustedDelegationPublicKeyPath, receiptPath, chainPath, keepStaging, issuerKeyPath, createIssuerKey };
}

async function readDelegation(path: string | undefined): Promise<DelegationProof | undefined> {
  if (path === undefined) {
    return undefined;
  }
  return JSON.parse(await readFile(path, "utf8")) as DelegationProof;
}

async function readDelegationTrustPolicy(path: string | undefined): Promise<DelegationTrustPolicy | undefined> {
  if (path === undefined) {
    return undefined;
  }
  const publicJwk = JSON.parse(await readFile(path, "utf8")) as PublicJwk;
  return delegationTrustPolicyForPublicJwk(publicJwk);
}

async function main(trace: CliTrace): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const telemetry = createCliTelemetrySink(trace);
  emitCliEvent(trace, "customs_install_started", {
    operation: "install",
    status: "started",
    packageTarget: options.packageDir,
    receiptPath: options.receiptPath,
    chainPath: options.chainPath,
    keepStaging: options.keepStaging
  });
  const result = await runSlInstallGate({
    packageDir: options.packageDir,
    delegationProof: await readDelegation(options.delegationPath),
    delegationTrustPolicy: await readDelegationTrustPolicy(options.trustedDelegationPublicKeyPath),
    receiptPath: options.receiptPath,
    chainPath: options.chainPath,
    issuerKeyPath: options.issuerKeyPath,
    createIssuerKeyIfMissing: options.createIssuerKey,
    keepStaging: options.keepStaging,
    telemetry
  });
  emitCliEvent(trace, "customs_install_finished", {
    operation: "install",
    status: result.decision.blocked ? "blocked" : "allowed",
    decision: result.decision.decision,
    packageName: result.decision.packageName,
    actorClass: result.decision.actorClass,
    receiptPath: result.receiptPath,
    chainPath: result.chainPath,
    durationMs: elapsedMs(trace)
  });
  console.log(JSON.stringify(result, null, 2));
  if (result.decision.blocked) {
    process.exitCode = 42;
  }
}

const trace = createCliTrace("customs-install");
main(trace).catch((error: unknown) => {
  emitCliEvent(trace, "customs_install_error", {
    operation: "install",
    status: "error",
    errorCode: errorCode(error),
    errorMessage: errorMessage(error),
    durationMs: elapsedMs(trace)
  });
  console.error(errorMessage(error));
  process.exitCode = 1;
});
