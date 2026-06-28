import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { canonicalJson, sha256Hex, toJsonObject, type JsonValue } from "./canonicalJson.js";
import {
  canonicalJwkThumbprintBase64Url,
  publicJwkFromKey,
  signCompactJws,
  verifyCompactJws,
  type PublicJwk
} from "./crypto.js";
import {
  emitOperationTelemetry,
  measuredAsyncOperation,
  operationDurationMs,
  operationErrorCode,
  operationErrorMessage,
  operationStartedMs,
  type OperationTelemetrySink
} from "./operationTelemetry.js";
import type { InstallDecision } from "./policy.js";

export const GENESIS_HASH = "0".repeat(64);
const RECEIPT_TYPE = "customs.install_receipt.v1";
const RECEIPT_AUDIENCE = "customs.offline_verifier";

export interface ReceiptChain {
  readonly previousHash: string;
  readonly entryHash: string;
}

export interface SignedInstallReceipt {
  readonly payload: { readonly [key: string]: JsonValue };
  readonly payloadSha256: string;
  readonly jws: string;
  readonly jwsSha256: string;
  readonly publicJwk: PublicJwk;
  readonly keyId: string;
  readonly chain: ReceiptChain;
}

export interface ReceiptVerification {
  readonly ok: boolean;
  readonly reason?: string | undefined;
  readonly decision?: string | undefined;
  readonly entryHash?: string | undefined;
}

export interface ReceiptTrustPolicy {
  readonly trustedKeyIds?: readonly string[] | undefined;
  readonly trustedPublicJwks?: readonly PublicJwk[] | undefined;
}

export function receiptKeyIdForPublicJwk(publicJwk: PublicJwk): string {
  return `customs-ed25519-${canonicalJwkThumbprintBase64Url(publicJwk)}`;
}

export function receiptTrustPolicyForPublicJwk(publicJwk: PublicJwk): ReceiptTrustPolicy {
  return {
    trustedKeyIds: [receiptKeyIdForPublicJwk(publicJwk)],
    trustedPublicJwks: [publicJwk]
  };
}

export class LocalReceiptIssuer {
  private readonly issuer: string;
  private readonly keyId: string;
  private readonly privateKey: KeyObject;
  private readonly publicJwk: PublicJwk;
  private readonly telemetry: OperationTelemetrySink | undefined;

  constructor(input: {
    readonly issuer?: string | undefined;
    readonly privateKey?: KeyObject | undefined;
    readonly publicKey?: KeyObject | undefined;
    readonly telemetry?: OperationTelemetrySink | undefined;
  } = {}) {
    if ((input.privateKey === undefined) !== (input.publicKey === undefined)) {
      throw new Error("receipt issuer requires privateKey and publicKey together");
    }
    const generated = input.privateKey === undefined ? generateKeyPairSync("ed25519") : undefined;
    this.privateKey = input.privateKey ?? generated!.privateKey;
    this.publicJwk = publicJwkFromKey(input.publicKey ?? generated!.publicKey);
    this.issuer = input.issuer ?? "customs.local";
    this.keyId = receiptKeyIdForPublicJwk(this.publicJwk);
    this.telemetry = input.telemetry;
  }

  trustedPublicJwk(): PublicJwk {
    return this.publicJwk;
  }

  trustPolicy(): ReceiptTrustPolicy {
    return receiptTrustPolicyForPublicJwk(this.publicJwk);
  }

  issue(decision: InstallDecision, previousHash = GENESIS_HASH, telemetry = this.telemetry): SignedInstallReceipt {
    const startedMs = operationStartedMs();
    emitOperationTelemetry(telemetry, {
      operation: "receipt.issue",
      status: "started",
      packageName: decision.packageName,
      decision: decision.decision,
      blocked: decision.blocked,
      keyId: this.keyId
    });
    try {
      const payload = toJsonObject({
        typ: RECEIPT_TYPE,
        action_type: decision.actionType,
        package_name: decision.packageName,
        package_version: decision.packageVersion,
        actor_class: decision.actorClass,
        decision: decision.decision,
        recommended_decision: decision.recommendedDecision,
        mode: decision.mode,
        blocked: decision.blocked,
        reasons: decision.reasons,
        lifecycle_findings: decision.lifecycleFindings,
        delegation_chain_id: decision.delegationChainId,
        delegation_subject: decision.delegationSubject,
        occurred_at: decision.occurredAt
      });
      const payloadSha256 = sha256Hex(canonicalJson(payload));
      const jwtPayload = toJsonObject({
        iss: this.issuer,
        aud: RECEIPT_AUDIENCE,
        typ: RECEIPT_TYPE,
        iat: Math.floor(Date.parse(decision.occurredAt) / 1000),
        package_name: decision.packageName,
        decision: decision.decision,
        blocked: decision.blocked,
        receipt_key_id: this.keyId,
        payload_sha256: payloadSha256,
        previous_hash: previousHash
      });
      const jws = signCompactJws(jwtPayload, this.privateKey, { kid: this.keyId, typ: RECEIPT_TYPE });
      const jwsSha256 = sha256Hex(jws);
      const entryHash = sha256Hex(canonicalJson({ key_id: this.keyId, jws_sha256: jwsSha256, payload_sha256: payloadSha256, previous_hash: previousHash }));
      const receipt = {
        payload,
        payloadSha256,
        jws,
        jwsSha256,
        publicJwk: this.publicJwk,
        keyId: this.keyId,
        chain: { previousHash, entryHash }
      };
      emitOperationTelemetry(telemetry, {
        operation: "receipt.issue",
        status: "ok",
        durationMs: operationDurationMs(startedMs),
        packageName: decision.packageName,
        decision: decision.decision,
        blocked: decision.blocked,
        keyId: this.keyId
      });
      return receipt;
    } catch (error) {
      emitOperationTelemetry(telemetry, {
        operation: "receipt.issue",
        status: "failed",
        durationMs: operationDurationMs(startedMs),
        packageName: decision.packageName,
        decision: decision.decision,
        blocked: decision.blocked,
        keyId: this.keyId,
        errorCode: operationErrorCode(error),
        errorMessage: operationErrorMessage(error)
      });
      throw error;
    }
  }
}

function trustedIssuerPublicJwk(receipt: SignedInstallReceipt, policy: ReceiptTrustPolicy): PublicJwk | undefined {
  const trustedPublicJwks = policy.trustedPublicJwks ?? [];
  if (trustedPublicJwks.length === 0) {
    return undefined;
  }
  const trustedKeyIds = new Set(policy.trustedKeyIds ?? []);
  if (trustedKeyIds.size > 0 && !trustedKeyIds.has(receipt.keyId)) {
    return undefined;
  }
  return trustedPublicJwks.find((jwk) => receiptKeyIdForPublicJwk(jwk) === receipt.keyId);
}

export function verifyReceipt(
  receipt: SignedInstallReceipt,
  policy: ReceiptTrustPolicy = {},
  telemetry?: OperationTelemetrySink | undefined
): ReceiptVerification {
  const startedMs = operationStartedMs();
  emitOperationTelemetry(telemetry, {
    operation: "receipt.verify",
    status: "started",
    keyId: receipt.keyId,
    trustedKeyCount: policy.trustedPublicJwks?.length ?? 0
  });
  const finish = (verification: ReceiptVerification): ReceiptVerification => {
    emitOperationTelemetry(telemetry, {
      operation: "receipt.verify",
      status: verification.ok ? "ok" : "failed",
      durationMs: operationDurationMs(startedMs),
      keyId: receipt.keyId,
      decision: verification.decision,
      reason: verification.reason,
      trustedKeyCount: policy.trustedPublicJwks?.length ?? 0
    });
    return verification;
  };
  try {
    if (receiptKeyIdForPublicJwk(receipt.publicJwk) !== receipt.keyId) {
      return finish({ ok: false, reason: "receipt_public_key_mismatch" });
    }
    const trustedPublicJwk = trustedIssuerPublicJwk(receipt, policy);
    if (trustedPublicJwk === undefined) {
      return finish({ ok: false, reason: "untrusted_issuer_key" });
    }
    const payloadSha256 = sha256Hex(canonicalJson(receipt.payload));
    if (payloadSha256 !== receipt.payloadSha256) {
      return finish({ ok: false, reason: "payload_sha256_mismatch" });
    }
    if (sha256Hex(receipt.jws) !== receipt.jwsSha256) {
      return finish({ ok: false, reason: "jws_sha256_mismatch" });
    }
    const decoded = verifyCompactJws(receipt.jws, trustedPublicJwk);
    if (
      decoded.header.kid !== receipt.keyId ||
      decoded.header.typ !== RECEIPT_TYPE ||
      decoded.payload.typ !== RECEIPT_TYPE ||
      decoded.payload.aud !== RECEIPT_AUDIENCE ||
      decoded.payload.receipt_key_id !== receipt.keyId ||
      decoded.payload.payload_sha256 !== receipt.payloadSha256 ||
      decoded.payload.previous_hash !== receipt.chain.previousHash ||
      decoded.payload.package_name !== receipt.payload.package_name ||
      decoded.payload.decision !== receipt.payload.decision ||
      decoded.payload.blocked !== receipt.payload.blocked
    ) {
      return finish({ ok: false, reason: "jws_payload_mismatch" });
    }
    const entryHash = sha256Hex(canonicalJson({
      key_id: receipt.keyId,
      jws_sha256: receipt.jwsSha256,
      payload_sha256: receipt.payloadSha256,
      previous_hash: receipt.chain.previousHash
    }));
    if (entryHash !== receipt.chain.entryHash) {
      return finish({ ok: false, reason: "entry_hash_mismatch" });
    }
    return finish({ ok: true, decision: String(receipt.payload.decision), entryHash });
  } catch (error) {
    return finish({ ok: false, reason: error instanceof Error ? error.message : String(error) });
  }
}

function parseReceipt(value: unknown): SignedInstallReceipt {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("receipt must be an object");
  }
  return value as SignedInstallReceipt;
}

export async function readReceipt(path: string, telemetry?: OperationTelemetrySink | undefined): Promise<SignedInstallReceipt> {
  return measuredAsyncOperation(telemetry, "receipt.read", { path }, async () =>
    parseReceipt(JSON.parse(await readFile(path, "utf8")) as unknown)
  );
}

export async function writeReceipt(path: string, receipt: SignedInstallReceipt, telemetry?: OperationTelemetrySink | undefined): Promise<void> {
  await measuredAsyncOperation(telemetry, "receipt.write", { path, keyId: receipt.keyId }, async () => {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  });
}

export async function readPreviousHash(chainPath: string, telemetry?: OperationTelemetrySink | undefined): Promise<string> {
  return measuredAsyncOperation(telemetry, "receipt.chain.read_previous", { chainPath }, async () => {
    try {
      const contents = await readFile(chainPath, "utf8");
      const lines = contents.split(/\r?\n/).filter((line) => line.trim().length > 0);
      const last = lines.at(-1);
      if (last === undefined) {
        return GENESIS_HASH;
      }
      const parsed = JSON.parse(last) as { readonly entryHash?: unknown };
      return typeof parsed.entryHash === "string" ? parsed.entryHash : GENESIS_HASH;
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") {
        emitOperationTelemetry(telemetry, {
          operation: "receipt.chain.genesis",
          status: "ok",
          chainPath,
          reason: "chain_missing"
        });
        return GENESIS_HASH;
      }
      throw error;
    }
  });
}

export async function appendReceiptChainRecord(
  chainPath: string,
  receipt: SignedInstallReceipt,
  telemetry?: OperationTelemetrySink | undefined
): Promise<void> {
  await measuredAsyncOperation(telemetry, "receipt.chain.append", { chainPath, keyId: receipt.keyId, entryHash: receipt.chain.entryHash }, async () => {
    await mkdir(dirname(chainPath), { recursive: true });
    const line = JSON.stringify({
      entryHash: receipt.chain.entryHash,
      previousHash: receipt.chain.previousHash,
      payloadSha256: receipt.payloadSha256,
      jwsSha256: receipt.jwsSha256,
      keyId: receipt.keyId,
      packageName: receipt.payload.package_name,
      decision: receipt.payload.decision
    });
    let current = "";
    try {
      current = await readFile(chainPath, "utf8");
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) {
        throw error;
      }
    }
    await writeFile(chainPath, `${current}${line}\n`, "utf8");
  });
}
