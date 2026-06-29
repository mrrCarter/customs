import { generateKeyPairSync } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  createDelegationProof,
  delegationTrustPolicyForPublicJwk,
  type DelegationClaims,
  type DelegationProof
} from "../src/kernel/delegation.js";
import { LocalReceiptIssuer, verifyReceipt, type SignedInstallReceipt } from "../src/kernel/receipts.js";
import { createDefaultCustomsMcpServer, CustomsMcpServer, CUSTOMS_MCP_PROTOCOL_VERSION } from "../src/mcp/server.js";

function claims(overrides: Partial<DelegationClaims> = {}): DelegationClaims {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: "did:aidenid:mcp-test",
    sub: "agent:builder-codex",
    aud: "customs.install",
    scope: ["package:install"],
    iat: now,
    exp: now + 60,
    jti: `mcp-test-${now}`,
    chain_id: "chain:mcp-test",
    ...overrides
  };
}

function delegationProof(input: Partial<DelegationClaims> = {}): DelegationProof {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return createDelegationProof({ claims: claims(input), privateKey, publicKey });
}

function serverForTrustedProof(proof: DelegationProof): CustomsMcpServer {
  return new CustomsMcpServer({
    receiptIssuer: new LocalReceiptIssuer(),
    delegationTrustPolicy: delegationTrustPolicyForPublicJwk(proof.publicJwk)
  });
}

function assertToolResult<T>(value: unknown): T {
  assert.ok(value !== null && typeof value === "object");
  assert.ok("result" in value);
  const result = (value as { readonly result: { readonly structuredContent: T } }).result;
  return result.structuredContent;
}

function callTool<T>(server: CustomsMcpServer, name: string, args: unknown): T {
  return assertToolResult<T>(server.handle({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args }
  }));
}

test("Customs MCP initializes and exposes clearance tools", () => {
  const proof = delegationProof();
  const server = serverForTrustedProof(proof);
  const initialized = server.handle({ jsonrpc: "2.0", id: "init", method: "initialize" });
  assert.ok(initialized !== null && "result" in initialized);
  assert.equal((initialized.result as { readonly protocolVersion: string }).protocolVersion, CUSTOMS_MCP_PROTOCOL_VERSION);

  const listed = server.handle({ jsonrpc: "2.0", id: "list", method: "tools/list" });
  assert.ok(listed !== null && "result" in listed);
  const tools = (listed.result as { readonly tools: readonly { readonly name: string }[] }).tools.map((tool) => tool.name);
  assert.ok(tools.includes("customs_clear_install"));
  assert.ok(tools.includes("customs_verify_receipt"));

  const search = callTool<{ readonly results: readonly { readonly id: string }[] }>(server, "search", { query: "receipt" });
  assert.ok(search.results.some((item) => item.id === "customs_verify_receipt"));
});

test("customs_clear_install denies poisoned lifecycle scripts and returns a verifiable signed receipt", () => {
  const proof = delegationProof();
  const server = serverForTrustedProof(proof);
  const result = callTool<{
    readonly decision: string;
    readonly blocked: boolean;
    readonly reasons: readonly string[];
    readonly receipt: SignedInstallReceipt;
    readonly issuerPublicJwk: SignedInstallReceipt["publicJwk"];
  }>(server, "customs_clear_install", {
    packageName: "@demo/poisoned-postinstall",
    packageVersion: "1.0.0",
    scripts: { postinstall: "node postinstall.js" },
    delegationProof: proof
  });

  assert.equal(result.decision, "deny");
  assert.equal(result.blocked, true);
  assert.ok(result.reasons.includes("poisoned_postinstall_detected"));

  const verification = verifyReceipt(result.receipt, { trustedPublicJwks: [result.issuerPublicJwk] });
  assert.equal(verification.ok, true);

  const mcpVerification = callTool<{ readonly ok: boolean; readonly decision?: string }>(server, "customs_verify_receipt", {
    receipt: result.receipt,
    trustedPublicJwks: [result.issuerPublicJwk]
  });
  assert.equal(mcpVerification.ok, true);
  assert.equal(mcpVerification.decision, "deny");
});

test("Customs MCP allows clean installs only with trusted delegation", () => {
  const trusted = delegationProof();
  const server = serverForTrustedProof(trusted);
  const allowed = callTool<{ readonly decision: string; readonly blocked: boolean; readonly reasons: readonly string[] }>(
    server,
    "customs_clear_install",
    {
      packageName: "@demo/clean",
      packageVersion: "1.0.0",
      scripts: {},
      delegationProof: trusted
    }
  );
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.blocked, false);
  assert.deepEqual(allowed.reasons, ["matched_policy"]);

  const missingDelegation = callTool<{ readonly decision: string; readonly blocked: boolean; readonly reasons: readonly string[] }>(
    server,
    "customs_clear_install",
    {
      packageName: "@demo/no-delegation",
      scripts: {}
    }
  );
  assert.equal(missingDelegation.decision, "deny");
  assert.equal(missingDelegation.blocked, true);
  assert.ok(missingDelegation.reasons.includes("missing_delegation"));
});

test("Customs MCP rejects forged delegation from an unregistered issuer", () => {
  const trusted = delegationProof({ iss: "did:aidenid:trusted" });
  const forged = delegationProof({ iss: "did:aidenid:attacker", sub: "agent:attacker" });
  const server = serverForTrustedProof(trusted);

  const result = callTool<{ readonly decision: string; readonly blocked: boolean; readonly reasons: readonly string[] }>(
    server,
    "customs_clear_install",
    {
      packageName: "@demo/clean-forged-delegation",
      scripts: {},
      delegationProof: forged
    }
  );

  assert.equal(result.decision, "deny");
  assert.equal(result.blocked, true);
  assert.ok(result.reasons.includes("untrusted_delegation_issuer"));
});

test("default Customs MCP server fails closed when the persisted issuer key is missing", async () => {
  const temp = await mkdtemp(join(tmpdir(), "customs-mcp-issuer-"));
  const issuerKeyPath = join(temp, "missing-issuer-private.jwk.json");

  await assert.rejects(
    createDefaultCustomsMcpServer({
      CUSTOMS_MCP_ISSUER_KEY_PATH: issuerKeyPath
    }),
    /issuer private key not found/
  );
  assert.equal(existsSync(issuerKeyPath), false);

  await createDefaultCustomsMcpServer({
    CUSTOMS_MCP_ISSUER_KEY_PATH: issuerKeyPath,
    CUSTOMS_MCP_CREATE_ISSUER_KEY: "1"
  });
  assert.equal(existsSync(issuerKeyPath), true);
});
