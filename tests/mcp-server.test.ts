import { generateKeyPairSync } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import {
  createDelegationProof,
  delegationTrustPolicyForPublicJwk,
  type DelegationClaims,
  type DelegationProof
} from "../src/kernel/delegation.js";
import { LocalReceiptIssuer, verifyReceipt, type SignedInstallReceipt } from "../src/kernel/receipts.js";
import { createDefaultCustomsMcpServer, CustomsMcpServer, CUSTOMS_MCP_PROTOCOL_VERSION } from "../src/mcp/server.js";

const stagedDirs: string[] = [];

after(async () => {
  await Promise.all(stagedDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

// Materialize a REAL package directory that the Customs gate will stage + inspect. The gate reads
// THIS package.json, so the fixture's own scripts are ground truth — the MCP tool exposes no
// `scripts` input, so a caller can neither declare nor omit scripts to steer the decision.
async function stagePackage(
  name: string,
  scripts: Readonly<Record<string, string>>,
  version = "1.0.0"
): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "customs-mcp-fixture-"));
  stagedDirs.push(dir);
  await writeFile(join(dir, "package.json"), JSON.stringify({ name, version, scripts }, null, 2), "utf8");
  return dir;
}

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

async function callTool<T>(server: CustomsMcpServer, name: string, args: unknown): Promise<T> {
  return assertToolResult<T>(await server.handle({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args }
  }));
}

const mcpInstallTimePayloads: readonly {
  readonly name: string;
  readonly scripts: Readonly<Record<string, string>>;
  readonly expectedHooks: readonly string[];
  readonly expectedReason: string;
}[] = [
  {
    name: "openclaw",
    scripts: { postinstall: "node postinstall.js" },
    expectedHooks: ["postinstall"],
    expectedReason: "poisoned_postinstall_detected"
  },
  {
    name: "nx-telemetry-replay",
    scripts: { postinstall: "node telemetry.js" },
    expectedHooks: ["postinstall"],
    expectedReason: "poisoned_postinstall_detected"
  },
  {
    name: "openclaw-pro",
    scripts: {
      preinstall: "node hook.js preinstall",
      prepare: "node hook.js prepare"
    },
    expectedHooks: ["preinstall", "prepare"],
    expectedReason: "lifecycle_script_detected"
  }
];

test("Customs MCP initializes and exposes clearance tools", async () => {
  const proof = delegationProof();
  const server = serverForTrustedProof(proof);
  const initialized = await server.handle({ jsonrpc: "2.0", id: "init", method: "initialize" });
  assert.ok(initialized !== null && "result" in initialized);
  assert.equal((initialized.result as { readonly protocolVersion: string }).protocolVersion, CUSTOMS_MCP_PROTOCOL_VERSION);

  const listed = await server.handle({ jsonrpc: "2.0", id: "list", method: "tools/list" });
  assert.ok(listed !== null && "result" in listed);
  const tools = (listed.result as { readonly tools: readonly { readonly name: string }[] }).tools.map((tool) => tool.name);
  assert.ok(tools.includes("customs_clear_install"));
  assert.ok(tools.includes("customs_verify_receipt"));

  const search = await callTool<{ readonly results: readonly { readonly id: string }[] }>(server, "search", { query: "receipt" });
  assert.ok(search.results.some((item) => item.id === "customs_verify_receipt"));
});

test("customs_clear_install denies poisoned lifecycle scripts and returns a verifiable signed receipt", async () => {
  const proof = delegationProof();
  const server = serverForTrustedProof(proof);
  const packageRef = await stagePackage("@demo/poisoned-postinstall", { postinstall: "node postinstall.js" });
  const result = await callTool<{
    readonly decision: string;
    readonly blocked: boolean;
    readonly reasons: readonly string[];
    readonly inspectedPackage: string;
    readonly receipt: SignedInstallReceipt;
    readonly issuerPublicJwk: SignedInstallReceipt["publicJwk"];
  }>(server, "customs_clear_install", {
    packageRef,
    delegationProof: proof
  });

  assert.equal(result.decision, "deny");
  assert.equal(result.blocked, true);
  assert.equal(result.inspectedPackage, "@demo/poisoned-postinstall");
  assert.ok(result.reasons.includes("poisoned_postinstall_detected"));

  const verification = verifyReceipt(result.receipt, { trustedPublicJwks: [result.issuerPublicJwk] });
  assert.equal(verification.ok, true);

  const mcpVerification = await callTool<{ readonly ok: boolean; readonly decision?: string }>(server, "customs_verify_receipt", {
    receipt: result.receipt,
    trustedPublicJwks: [result.issuerPublicJwk]
  });
  assert.equal(mcpVerification.ok, true);
  assert.equal(mcpVerification.decision, "deny");
});

test("customs_clear_install blocks install-time red-team payload surfaces through MCP", async () => {
  for (const fixture of mcpInstallTimePayloads) {
    const proof = delegationProof({ jti: `mcp-redteam-${fixture.name}` });
    const server = serverForTrustedProof(proof);
    const packageRef = await stagePackage(fixture.name, fixture.scripts);
    const result = await callTool<{
      readonly decision: string;
      readonly blocked: boolean;
      readonly reasons: readonly string[];
      readonly lifecycleFindings: readonly { readonly name: string; readonly command: string }[];
      readonly receipt: SignedInstallReceipt;
      readonly issuerPublicJwk: SignedInstallReceipt["publicJwk"];
    }>(server, "customs_clear_install", {
      packageRef,
      delegationProof: proof
    });

    assert.equal(result.decision, "deny");
    assert.equal(result.blocked, true);
    assert.ok(result.reasons.includes(fixture.expectedReason));
    assert.ok(result.reasons.includes("permission_scope_mismatch"));
    for (const hook of fixture.expectedHooks) {
      assert.ok(result.lifecycleFindings.some((finding) => finding.name === hook), `${fixture.name} should flag ${hook}`);
    }
    assert.equal(verifyReceipt(result.receipt, { trustedPublicJwks: [result.issuerPublicJwk] }).ok, true);
  }
});

test("customs_clear_install closes the caller-declared-scripts bypass (A1 regression)", async () => {
  const proof = delegationProof({ jti: "mcp-a1-regression" });
  const server = serverForTrustedProof(proof);
  // The poisoned package hides a real postinstall in its OWN manifest. Pre-fix, a caller could pass
  // `scripts: {}` to launder it into an ALLOW + signed receipt. The tool now exposes no `scripts`
  // input at all: it stages + inspects the real package, so the manifest's own postinstall is found.
  const packageRef = await stagePackage("openclaw", { postinstall: "node steal-secrets.js" });
  const result = await callTool<{
    readonly decision: string;
    readonly blocked: boolean;
    readonly reasons: readonly string[];
    readonly inspectedPackage: string;
    readonly lifecycleFindings: readonly { readonly name: string }[];
    readonly receipt: SignedInstallReceipt;
    readonly issuerPublicJwk: SignedInstallReceipt["publicJwk"];
  }>(server, "customs_clear_install", { packageRef, delegationProof: proof });

  assert.equal(result.decision, "deny");
  assert.equal(result.blocked, true);
  assert.equal(result.inspectedPackage, "openclaw");
  assert.ok(result.reasons.includes("poisoned_postinstall_detected"));
  assert.ok(result.lifecycleFindings.some((finding) => finding.name === "postinstall"));
  // The signed DENY receipt attests a decision derived from the real staged package, not caller input.
  assert.equal(verifyReceipt(result.receipt, { trustedPublicJwks: [result.issuerPublicJwk] }).ok, true);

  // There is no scripts-only decision path anymore: a call without a packageRef is a hard error,
  // never a silent ALLOW.
  const missing = await server.handle({
    jsonrpc: "2.0",
    id: "no-ref",
    method: "tools/call",
    params: { name: "customs_clear_install", arguments: { delegationProof: proof } }
  });
  assert.ok(missing !== null && "error" in missing);
});

test("Customs MCP allows clean installs only with trusted delegation", async () => {
  const trusted = delegationProof();
  const server = serverForTrustedProof(trusted);
  const cleanRef = await stagePackage("@demo/clean", {});
  const allowed = await callTool<{ readonly decision: string; readonly blocked: boolean; readonly reasons: readonly string[] }>(
    server,
    "customs_clear_install",
    {
      packageRef: cleanRef,
      delegationProof: trusted
    }
  );
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.blocked, false);
  assert.deepEqual(allowed.reasons, ["matched_policy"]);

  const noDelegationRef = await stagePackage("@demo/no-delegation", {});
  const missingDelegation = await callTool<{ readonly decision: string; readonly blocked: boolean; readonly reasons: readonly string[] }>(
    server,
    "customs_clear_install",
    {
      packageRef: noDelegationRef
    }
  );
  assert.equal(missingDelegation.decision, "deny");
  assert.equal(missingDelegation.blocked, true);
  assert.ok(missingDelegation.reasons.includes("missing_delegation"));
});

test("Customs MCP rejects forged delegation from an unregistered issuer", async () => {
  const trusted = delegationProof({ iss: "did:aidenid:trusted" });
  const forged = delegationProof({ iss: "did:aidenid:attacker", sub: "agent:attacker" });
  const server = serverForTrustedProof(trusted);
  const cleanRef = await stagePackage("@demo/clean-forged-delegation", {});

  const result = await callTool<{ readonly decision: string; readonly blocked: boolean; readonly reasons: readonly string[] }>(
    server,
    "customs_clear_install",
    {
      packageRef: cleanRef,
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
