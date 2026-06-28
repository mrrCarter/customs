import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { createDelegationProof, type DelegationClaims } from "../src/kernel/delegation.js";
import { readReceipt, verifyReceipt } from "../src/kernel/receipts.js";

interface CommandResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

interface PayloadFixture {
  readonly name: string;
  readonly version: string;
  readonly scripts?: Readonly<Record<string, string>> | undefined;
  readonly files: Readonly<Record<string, string>>;
  readonly marker: string;
}

function runCommand(command: string, args: readonly string[], cwd: string): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
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

function runNode(args: readonly string[]): Promise<CommandResult> {
  return runCommand(process.execPath, args, process.cwd());
}

function npmInvocation(): { readonly command: string; readonly args: readonly string[] } {
  const envNpmExecPath = process.env.npm_execpath;
  if (envNpmExecPath !== undefined && existsSync(envNpmExecPath)) {
    return { command: process.execPath, args: [envNpmExecPath] };
  }
  const adjacentNpmCli = join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  if (existsSync(adjacentNpmCli)) {
    return { command: process.execPath, args: [adjacentNpmCli] };
  }
  return { command: process.platform === "win32" ? "npm.cmd" : "npm", args: [] };
}

function runNpm(args: readonly string[], cwd: string): Promise<CommandResult> {
  const npm = npmInvocation();
  return runCommand(npm.command, [...npm.args, ...args], cwd);
}

async function writePayloadFixture(root: string, fixture: PayloadFixture): Promise<string> {
  const packageDir = join(root, fixture.name.replaceAll("/", "__"));
  await mkdir(packageDir, { recursive: true });
  await writeFile(
    join(packageDir, "package.json"),
    `${JSON.stringify(
      {
        name: fixture.name,
        version: fixture.version,
        license: "MIT",
        scripts: fixture.scripts,
        main: fixture.files["index.js"] === undefined ? undefined : "index.js"
      },
      null,
      2
    )}\n`,
    "utf8"
  );
  for (const [relativePath, contents] of Object.entries(fixture.files)) {
    await writeFile(join(packageDir, relativePath), contents, "utf8");
  }
  return packageDir;
}

async function packFixture(packageDir: string, destination: string): Promise<string> {
  const result = await runNpm(["pack", packageDir, "--pack-destination", destination, "--ignore-scripts=true", "--json"], destination);
  assert.equal(result.code, 0, result.stderr);
  const parsed = JSON.parse(result.stdout) as readonly [{ readonly filename: string }];
  assert.equal(parsed.length, 1);
  return join(destination, parsed[0]!.filename);
}

async function writeDelegationProof(path: string, trustedPublicKeyPath: string): Promise<void> {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const now = Math.floor(Date.now() / 1000);
  const claims: DelegationClaims = {
    iss: "did:aidenid:redteam",
    sub: "agent:codex-redteam-infra",
    aud: "customs.install",
    scope: ["package:install"],
    iat: now,
    exp: now + 3600,
    jti: `redteam-${now}`,
    chain_id: "chain:redteam"
  };
  const proof = createDelegationProof({ claims, privateKey, publicKey });
  await writeFile(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  await writeFile(trustedPublicKeyPath, `${JSON.stringify(proof.publicJwk, null, 2)}\n`, "utf8");
}

async function findMarkerFiles(root: string, marker: string): Promise<string[]> {
  const matches: string[] = [];
  async function visit(path: string): Promise<void> {
    const entries = await readdir(path, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(path, entry.name);
      if (entry.isDirectory()) {
        await visit(fullPath);
      } else if (entry.name === marker) {
        matches.push(fullPath);
      }
    }
  }
  if (existsSync(root)) {
    await visit(root);
  }
  return matches;
}

async function runControlInstall(tarball: string, marker: string): Promise<readonly string[]> {
  const projectDir = await mkdtemp(join(tmpdir(), "customs-control-"));
  const result = await runNpm(
    ["install", tarball, "--foreground-scripts", "--ignore-scripts=false", "--no-audit", "--no-fund", "--package-lock=false", "--prefix", projectDir],
    projectDir
  );
  assert.equal(result.code, 0, result.stderr);
  return findMarkerFiles(projectDir, marker);
}

async function runCustomsTreatment(tarball: string, receiptPath: string, chainPath: string): Promise<{
  readonly code: number | null;
  readonly parsed: {
    readonly decision: { readonly decision: string; readonly blocked: boolean; readonly reasons: readonly string[] };
    readonly receipt: { readonly publicJwk: Record<string, unknown> };
    readonly source: { readonly stagedWithIgnoreScripts: boolean; readonly stagingDir?: string | undefined };
  };
}> {
  const delegationPath = join(await mkdtemp(join(tmpdir(), "customs-delegation-")), "delegation.json");
  const delegationPublicKeyPath = join(dirname(delegationPath), "delegation-public.jwk.json");
  const issuerKeyPath = join(await mkdtemp(join(tmpdir(), "customs-issuer-")), "issuer-private.jwk.json");
  await writeDelegationProof(delegationPath, delegationPublicKeyPath);
  const result = await runNode([
    join("dist", "src", "cli", "customs-install.js"),
    tarball,
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
    "--create-issuer-key",
    "--keep-staging"
  ]);
  assert.match(result.stdout, /^\{/);
  return { code: result.code, parsed: JSON.parse(result.stdout) as Awaited<ReturnType<typeof runCustomsTreatment>>["parsed"] };
}

const installTimePayloads: readonly PayloadFixture[] = [
  {
    name: "openclaw",
    version: "9.9.9",
    scripts: { postinstall: "node postinstall.js" },
    marker: "RT_PWNED_postinstall.txt",
    files: {
      "postinstall.js": "const fs=require('fs');fs.writeFileSync('RT_PWNED_postinstall.txt','postinstall executed');\n"
    }
  },
  {
    name: "nx-telemetry-replay",
    version: "21.5.0",
    scripts: { postinstall: "node telemetry.js" },
    marker: "RT_secretscan_findings.txt",
    files: {
      "telemetry.js": "const fs=require('fs');fs.writeFileSync('RT_secretscan_findings.txt','would exfil secret refs');\n"
    }
  },
  {
    name: "openclaw-pro",
    version: "3.3.3",
    scripts: {
      preinstall: "node hook.js preinstall",
      prepare: "node hook.js prepare"
    },
    marker: "RT_PWNED_hookalias.txt",
    files: {
      "hook.js": "const fs=require('fs');fs.writeFileSync('RT_PWNED_hookalias.txt','hook alias executed '+process.argv[2]);\n"
    }
  }
];

for (const fixture of installTimePayloads) {
  test(`Customs blocks install-time red-team payload ${fixture.name} before lifecycle execution`, async () => {
    const temp = await mkdtemp(join(tmpdir(), "customs-redteam-"));
    const packageDir = await writePayloadFixture(temp, fixture);
    const tarball = await packFixture(packageDir, temp);

    const controlMarkers = await runControlInstall(tarball, fixture.marker);
    assert.ok(controlMarkers.length > 0, `control install must execute ${fixture.marker}`);

    const receiptPath = join(temp, "receipt.json");
    const chainPath = join(temp, "chain.jsonl");
    const treatment = await runCustomsTreatment(tarball, receiptPath, chainPath);
    assert.equal(treatment.code, 42);
    assert.equal(treatment.parsed.decision.blocked, true);
    assert.equal(treatment.parsed.decision.decision, "deny");
    assert.equal(treatment.parsed.source.stagedWithIgnoreScripts, true);
    assert.ok(treatment.parsed.source.stagingDir);
    assert.deepEqual(await findMarkerFiles(treatment.parsed.source.stagingDir!, fixture.marker), []);
    const receipt = await readReceipt(receiptPath);
    assert.equal(verifyReceipt(receipt, { trustedPublicJwks: [treatment.parsed.receipt.publicJwk] }).ok, true);
    await rm(treatment.parsed.source.stagingDir!, { recursive: true, force: true });
  });
}

test("Customs records import-time payload as an install-gate scope gap", async () => {
  const fixture: PayloadFixture = {
    name: "leftpad-helper",
    version: "2.1.0",
    marker: "RT_PWNED_import_time.txt",
    files: {
      "index.js": "const fs=require('fs');fs.writeFileSync('RT_PWNED_import_time.txt','import-time executed');module.exports=(s,n)=>String(s).padStart(n);\n"
    }
  };
  const temp = await mkdtemp(join(tmpdir(), "customs-redteam-import-"));
  const packageDir = await writePayloadFixture(temp, fixture);
  const tarball = await packFixture(packageDir, temp);
  const projectDir = await mkdtemp(join(tmpdir(), "customs-import-control-"));

  const install = await runNpm(["install", tarball, "--ignore-scripts=false", "--no-audit", "--no-fund", "--package-lock=false", "--prefix", projectDir], projectDir);
  assert.equal(install.code, 0, install.stderr);
  assert.deepEqual(await findMarkerFiles(projectDir, fixture.marker), []);
  const runtime = await runCommand(process.execPath, ["-e", "require('leftpad-helper')('x', 2)"], projectDir);
  assert.equal(runtime.code, 0, runtime.stderr);
  assert.ok((await findMarkerFiles(projectDir, fixture.marker)).length > 0, "control require() must execute import-time payload");

  const receiptPath = join(temp, "receipt.json");
  const chainPath = join(temp, "chain.jsonl");
  const treatment = await runCustomsTreatment(tarball, receiptPath, chainPath);
  assert.equal(treatment.code, 0);
  assert.equal(treatment.parsed.decision.decision, "allow");
  assert.equal(treatment.parsed.decision.blocked, false);
  assert.equal(treatment.parsed.source.stagedWithIgnoreScripts, true);
  assert.ok(treatment.parsed.source.stagingDir);
  assert.deepEqual(await findMarkerFiles(treatment.parsed.source.stagingDir!, fixture.marker), []);
  const receipt = await readReceipt(receiptPath);
  assert.equal(verifyReceipt(receipt, { trustedPublicJwks: [treatment.parsed.receipt.publicJwk] }).ok, true);
  await rm(treatment.parsed.source.stagingDir!, { recursive: true, force: true });
});
