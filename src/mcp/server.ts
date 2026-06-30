#!/usr/bin/env node
import { createInterface } from "node:readline";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { DelegationProof, DelegationTrustPolicy } from "../kernel/delegation.js";
import { delegationKeyIdForPublicJwk, verifyDelegationProof } from "../kernel/delegation.js";
import { loadOrCreateLocalReceiptIssuer } from "../kernel/issuerKeyStore.js";
import { defaultInstallPolicy, evaluateInstall, type InstallDecision, type InstallPolicy } from "../kernel/policy.js";
import { LocalReceiptIssuer, verifyReceipt, type ReceiptTrustPolicy, type SignedInstallReceipt } from "../kernel/receipts.js";
import type { PublicJwk } from "../kernel/crypto.js";

export const CUSTOMS_MCP_PROTOCOL_VERSION = "2025-11-25";
export const DEFAULT_CUSTOMS_MCP_ISSUER_KEY_PATH =
  process.env.CUSTOMS_MCP_ISSUER_KEY_PATH ??
  process.env.CUSTOMS_ISSUER_KEY_PATH ??
  join(homedir(), ".customs", "issuer-private.jwk.json");

type JsonRpcId = string | number | null;

interface JsonRpcRequest {
  readonly jsonrpc?: string | undefined;
  readonly id?: JsonRpcId | undefined;
  readonly method?: string | undefined;
  readonly params?: unknown;
}

interface JsonRpcSuccess {
  readonly jsonrpc: "2.0";
  readonly id: JsonRpcId;
  readonly result: unknown;
}

interface JsonRpcFailure {
  readonly jsonrpc: "2.0";
  readonly id: JsonRpcId;
  readonly error: {
    readonly code: number;
    readonly message: string;
  };
}

type JsonRpcResponse = JsonRpcSuccess | JsonRpcFailure;

export interface CustomsMcpServerOptions {
  readonly receiptIssuer: LocalReceiptIssuer;
  readonly delegationTrustPolicy?: DelegationTrustPolicy | undefined;
  readonly installPolicy?: InstallPolicy | undefined;
}

export interface CustomsClearInstallResult {
  readonly decision: InstallDecision["decision"];
  readonly blocked: boolean;
  readonly reasons: readonly string[];
  readonly actorClass: string;
  readonly lifecycleFindings: InstallDecision["lifecycleFindings"];
  readonly receipt: SignedInstallReceipt;
  readonly issuerPublicJwk: PublicJwk;
}

interface ToolDefinition {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly inputSchema: unknown;
  readonly annotations?: {
    readonly readOnlyHint?: boolean | undefined;
    readonly destructiveHint?: boolean | undefined;
  } | undefined;
  readonly security?: {
    readonly requires_human_approval: boolean;
    readonly scopes: readonly string[];
  } | undefined;
}

export const CUSTOMS_MCP_TOOLS: readonly ToolDefinition[] = [
  {
    name: "customs_clear_install",
    title: "Customs: clear a package install",
    description:
      "Route a package-install action through the real Customs clearance kernel. Returns allow/deny plus a signed offline-verifiable receipt before lifecycle execution.",
    inputSchema: {
      type: "object",
      properties: {
        packageName: { type: "string" },
        packageVersion: { type: "string" },
        scripts: {
          type: "object",
          additionalProperties: { type: "string" },
          description: "package.json scripts map"
        },
        delegationProof: {
          type: "object",
          additionalProperties: true,
          description: "Ed25519 AIdenID/Customs delegation proof"
        }
      },
      required: ["packageName"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
    security: { requires_human_approval: false, scopes: ["customs.install.clear"] }
  },
  {
    name: "customs_verify_receipt",
    title: "Customs: verify a receipt offline",
    description:
      "Verify a Customs clearance receipt against a trusted issuer public key. If no key is supplied, the server's configured issuer public key is used.",
    inputSchema: {
      type: "object",
      properties: {
        receipt: { type: "object", additionalProperties: true },
        trustedPublicJwks: {
          type: "array",
          items: { type: "object", additionalProperties: true }
        }
      },
      required: ["receipt"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
    security: { requires_human_approval: false, scopes: ["customs.receipt.verify"] }
  },
  {
    name: "search",
    title: "search",
    description: "Discover Customs MCP capabilities.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
    security: { requires_human_approval: false, scopes: ["customs.discovery"] }
  },
  {
    name: "fetch",
    title: "fetch",
    description: "Fetch a Customs MCP capability by id.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"]
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
    security: { requires_human_approval: false, scopes: ["customs.discovery"] }
  }
];

function jsonRpcId(value: unknown): JsonRpcId {
  return typeof value === "string" || typeof value === "number" || value === null ? value : null;
}

function objectRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function optionalStringMap(value: unknown, label: string): Readonly<Record<string, string>> {
  if (value === undefined) {
    return {};
  }
  const input = objectRecord(value, label);
  const output: Record<string, string> = {};
  for (const [key, item] of Object.entries(input)) {
    if (typeof item !== "string") {
      throw new Error(`${label}.${key} must be a string`);
    }
    output[key] = item;
  }
  return output;
}

function optionalDelegationProof(value: unknown): DelegationProof | undefined {
  if (value === undefined) {
    return undefined;
  }
  return objectRecord(value, "delegationProof") as unknown as DelegationProof;
}

function publicJwkFromUnknown(value: unknown, label: string): PublicJwk {
  const jwk = objectRecord(value, label);
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error(`${label} must be an Ed25519 public JWK`);
  }
  return jwk as unknown as PublicJwk;
}

function publicJwksFromUnknown(value: unknown, label: string): readonly PublicJwk[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value.map((item, index) => publicJwkFromUnknown(item, `${label}[${index}]`));
}

function trustPolicyForPublicJwks(publicJwks: readonly PublicJwk[]): DelegationTrustPolicy {
  return {
    trustedKeyIds: publicJwks.map((jwk) => delegationKeyIdForPublicJwk(jwk)),
    trustedPublicJwks: publicJwks
  };
}

function toolResult(id: JsonRpcId, value: unknown): JsonRpcSuccess {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text: JSON.stringify(value) }],
      structuredContent: value
    }
  };
}

function errorResponse(id: JsonRpcId, code: number, message: string): JsonRpcFailure {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

export class CustomsMcpServer {
  private readonly receiptIssuer: LocalReceiptIssuer;
  private readonly delegationTrustPolicy: DelegationTrustPolicy;
  private readonly installPolicy: InstallPolicy;

  constructor(options: CustomsMcpServerOptions) {
    this.receiptIssuer = options.receiptIssuer;
    this.delegationTrustPolicy = options.delegationTrustPolicy ?? {};
    this.installPolicy = options.installPolicy ?? defaultInstallPolicy();
  }

  clearInstall(args: unknown): CustomsClearInstallResult {
    const input = objectRecord(args, "customs_clear_install arguments");
    if (typeof input.packageName !== "string" || input.packageName.length === 0) {
      throw new Error("packageName is required");
    }
    const packageVersion = input.packageVersion;
    if (packageVersion !== undefined && typeof packageVersion !== "string") {
      throw new Error("packageVersion must be a string");
    }
    const delegation = verifyDelegationProof(optionalDelegationProof(input.delegationProof), {
      expectedAudience: "customs.install",
      requiredScopes: ["package:install"],
      trustPolicy: this.delegationTrustPolicy
    });
    const decision = evaluateInstall({
      packageName: input.packageName,
      ...(packageVersion === undefined ? {} : { packageVersion }),
      scripts: optionalStringMap(input.scripts, "scripts"),
      delegation,
      policy: this.installPolicy
    });
    const receipt = this.receiptIssuer.issue(decision);
    return {
      decision: decision.decision,
      blocked: decision.blocked,
      reasons: decision.reasons,
      actorClass: decision.actorClass,
      lifecycleFindings: decision.lifecycleFindings,
      receipt,
      issuerPublicJwk: this.receiptIssuer.trustedPublicJwk()
    };
  }

  verifyReceipt(args: unknown): ReturnType<typeof verifyReceipt> {
    const input = objectRecord(args, "customs_verify_receipt arguments");
    const receipt = objectRecord(input.receipt, "receipt") as unknown as SignedInstallReceipt;
    const trustedPublicJwks = publicJwksFromUnknown(input.trustedPublicJwks, "trustedPublicJwks") ?? [
      this.receiptIssuer.trustedPublicJwk()
    ];
    const trustPolicy: ReceiptTrustPolicy = { trustedPublicJwks };
    return verifyReceipt(receipt, trustPolicy);
  }

  search(args: unknown): unknown {
    const input = objectRecord(args, "search arguments");
    if (typeof input.query !== "string") {
      throw new Error("query is required");
    }
    const query = input.query.toLowerCase();
    return {
      results: CUSTOMS_MCP_TOOLS
        .filter((tool) => tool.name !== "search" && tool.name !== "fetch")
        .filter((tool) => `${tool.name} ${tool.title} ${tool.description}`.toLowerCase().includes(query) || query.length === 0)
        .map((tool) => ({ id: tool.name, title: tool.title, text: tool.description }))
    };
  }

  fetchCapability(args: unknown): unknown {
    const input = objectRecord(args, "fetch arguments");
    if (typeof input.id !== "string") {
      throw new Error("id is required");
    }
    const tool = CUSTOMS_MCP_TOOLS.find((item) => item.name === input.id);
    if (tool === undefined) {
      return { id: input.id, text: "unknown Customs MCP capability" };
    }
    return {
      id: tool.name,
      title: tool.title,
      text: tool.description,
      inputSchema: tool.inputSchema
    };
  }

  handle(message: JsonRpcRequest): JsonRpcResponse | null {
    const id = jsonRpcId(message.id);
    try {
      if (message.method === "initialize") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: CUSTOMS_MCP_PROTOCOL_VERSION,
            capabilities: { tools: {} },
            serverInfo: { name: "customs-mcp", version: "0.1.0" }
          }
        };
      }
      if (message.method === "tools/list") {
        return { jsonrpc: "2.0", id, result: { tools: CUSTOMS_MCP_TOOLS } };
      }
      if (message.method === "tools/call") {
        const params = objectRecord(message.params, "tools/call params");
        if (typeof params.name !== "string") {
          throw new Error("tools/call params.name is required");
        }
        const args = params.arguments ?? {};
        if (params.name === "customs_clear_install") {
          return toolResult(id, this.clearInstall(args));
        }
        if (params.name === "customs_verify_receipt") {
          return toolResult(id, this.verifyReceipt(args));
        }
        if (params.name === "search") {
          return toolResult(id, this.search(args));
        }
        if (params.name === "fetch") {
          return toolResult(id, this.fetchCapability(args));
        }
        return errorResponse(id, -32601, `unknown tool ${params.name}`);
      }
      if (message.method?.startsWith("notifications/")) {
        return null;
      }
      return errorResponse(id, -32601, `unknown method ${message.method ?? "missing"}`);
    } catch (error) {
      return errorResponse(id, -32000, error instanceof Error ? error.message : String(error));
    }
  }
}

export async function createDefaultCustomsMcpServer(env: NodeJS.ProcessEnv = process.env): Promise<CustomsMcpServer> {
  const issuerKeyPath = env.CUSTOMS_MCP_ISSUER_KEY_PATH ?? env.CUSTOMS_ISSUER_KEY_PATH ?? DEFAULT_CUSTOMS_MCP_ISSUER_KEY_PATH;
  const receiptIssuer = await loadOrCreateLocalReceiptIssuer(issuerKeyPath, {
    createIfMissing: env.CUSTOMS_MCP_CREATE_ISSUER_KEY === "1"
  });
  const trustedDelegationJwk = env.CUSTOMS_TRUSTED_DELEGATION_JWK === undefined
    ? undefined
    : publicJwkFromUnknown(JSON.parse(env.CUSTOMS_TRUSTED_DELEGATION_JWK) as unknown, "CUSTOMS_TRUSTED_DELEGATION_JWK");
  return new CustomsMcpServer({
    receiptIssuer,
    delegationTrustPolicy: trustedDelegationJwk === undefined ? {} : trustPolicyForPublicJwks([trustedDelegationJwk])
  });
}

export async function runCustomsMcpStdio(server?: CustomsMcpServer | undefined): Promise<void> {
  const activeServer = server ?? (await createDefaultCustomsMcpServer());
  const rl = createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (trimmed.length === 0) {
      return;
    }
    let parsed: JsonRpcRequest;
    try {
      parsed = JSON.parse(trimmed) as JsonRpcRequest;
    } catch {
      process.stdout.write(`${JSON.stringify(errorResponse(null, -32700, "parse error"))}\n`);
      return;
    }
    const response = activeServer.handle(parsed);
    if (response !== null) {
      process.stdout.write(`${JSON.stringify(response)}\n`);
    }
  });
}

const invokedPath = process.argv[1] === undefined ? undefined : resolve(process.argv[1]);
if (invokedPath !== undefined && invokedPath === fileURLToPath(import.meta.url)) {
  runCustomsMcpStdio().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
