import { spawn } from "node:child_process";
import { homedir, tmpdir } from "node:os";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { mkdtemp, readdir, rm, stat } from "node:fs/promises";

import type { DelegationProof, DelegationTrustPolicy } from "../kernel/delegation.js";
import { verifyDelegationProof } from "../kernel/delegation.js";
import { loadOrCreateLocalReceiptIssuer } from "../kernel/issuerKeyStore.js";
import { measuredAsyncOperation, measuredOperation, type OperationTelemetrySink } from "../kernel/operationTelemetry.js";
import { evaluateInstall, type InstallDecision, type InstallPolicy } from "../kernel/policy.js";
import {
  appendReceiptChainRecord,
  LocalReceiptIssuer,
  readPreviousHash,
  writeReceipt,
  type SignedInstallReceipt
} from "../kernel/receipts.js";

export const DEFAULT_RECEIPT_ISSUER_KEY_PATH = process.env.CUSTOMS_ISSUER_KEY_PATH ?? join(homedir(), ".customs", "issuer-private.jwk.json");

export interface PackageManifest {
  readonly name: string;
  readonly version?: string | undefined;
  readonly scripts?: Readonly<Record<string, string>> | undefined;
}

export interface InstallGateResult {
  readonly decision: InstallDecision;
  readonly receipt: SignedInstallReceipt;
  readonly receiptPath: string;
  readonly chainPath: string;
  readonly source: InstallGateSource;
}

export interface InstallGateOptions {
  readonly packageDir: string;
  readonly delegationProof?: DelegationProof | undefined;
  readonly delegationTrustPolicy?: DelegationTrustPolicy | undefined;
  readonly receiptPath: string;
  readonly chainPath: string;
  readonly policy?: InstallPolicy | undefined;
  readonly now?: Date | undefined;
  readonly keepStaging?: boolean | undefined;
  readonly receiptIssuer?: LocalReceiptIssuer | undefined;
  readonly issuerKeyPath?: string | undefined;
  readonly createIssuerKeyIfMissing?: boolean | undefined;
  readonly telemetry?: OperationTelemetrySink | undefined;
}

export interface InstallGateSource {
  readonly input: string;
  readonly inspectedPackageDir: string;
  readonly stagedWithIgnoreScripts: boolean;
  readonly stagingDir?: string | undefined;
}

function stringRecord(value: unknown): Readonly<Record<string, string>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  const output: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === "string") {
      output[key] = item;
    }
  }
  return output;
}

export async function readPackageManifest(packageDir: string): Promise<PackageManifest> {
  const manifestPath = join(packageDir, "package.json");
  const parsed = JSON.parse(await readFile(manifestPath, "utf8")) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${manifestPath} must contain a JSON object`);
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.name !== "string" || record.name.length === 0) {
    throw new Error(`${manifestPath} is missing package name`);
  }
  return {
    name: record.name,
    version: typeof record.version === "string" ? record.version : undefined,
    scripts: stringRecord(record.scripts)
  };
}

async function isDirectory(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
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

function runNpm(args: readonly string[], cwd: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const npm = npmInvocation();
    const child = spawn(npm.command, [...npm.args, ...args], {
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
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new Error(
          `npm ${args.join(" ")} failed with exit ${code ?? "unknown"}\n${Buffer.concat(stdout).toString("utf8")}${Buffer.concat(stderr).toString("utf8")}`
        )
      );
    });
  });
}

async function stagedPackageDirs(nodeModulesDir: string): Promise<string[]> {
  const entries = await readdir(nodeModulesDir, { withFileTypes: true });
  const packages: string[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name === ".bin") {
      continue;
    }
    if (entry.name.startsWith("@")) {
      const scoped = await readdir(join(nodeModulesDir, entry.name), { withFileTypes: true });
      for (const scopedEntry of scoped) {
        if (scopedEntry.isDirectory()) {
          packages.push(join(nodeModulesDir, entry.name, scopedEntry.name));
        }
      }
      continue;
    }
    packages.push(join(nodeModulesDir, entry.name));
  }
  return packages;
}

async function materializePackageTarget(input: string, keepStaging = false): Promise<{
  readonly source: InstallGateSource;
  readonly cleanup: () => Promise<void>;
}> {
  if (await isDirectory(input)) {
    return {
      source: {
        input,
        inspectedPackageDir: input,
        stagedWithIgnoreScripts: false
      },
      cleanup: async () => {}
    };
  }

  const stagingDir = await mkdtemp(join(tmpdir(), "customs-stage-"));
  try {
    // Customs stages tarballs only for inspection; lifecycle scripts must never execute here.
    await runNpm(
      [
        "install",
        input,
        "--ignore-scripts",
        "--package-lock=false",
        "--no-audit",
        "--no-fund",
        "--foreground-scripts",
        "--prefix",
        stagingDir
      ],
      stagingDir
    );
    const packages = await stagedPackageDirs(join(stagingDir, "node_modules"));
    if (packages.length !== 1) {
      throw new Error(`Customs expected one staged top-level package, found ${packages.length}. Use a package directory for multi-package targets.`);
    }
    return {
      source: {
        input,
        inspectedPackageDir: packages[0]!,
        stagedWithIgnoreScripts: true,
        stagingDir: keepStaging ? stagingDir : undefined
      },
      cleanup: keepStaging ? async () => {} : async () => {
        await rm(stagingDir, { recursive: true, force: true });
      }
    };
  } catch (error) {
    if (!keepStaging) {
      await rm(stagingDir, { recursive: true, force: true });
    }
    throw error;
  }
}

export async function runSlInstallGate(options: InstallGateOptions): Promise<InstallGateResult> {
  const telemetry = options.telemetry;
  const materialized = await measuredAsyncOperation(telemetry, "install.materialize_package", {
    packageTarget: options.packageDir,
    keepStaging: options.keepStaging === true
  }, async () => materializePackageTarget(options.packageDir, options.keepStaging));
  try {
    const manifest = await measuredAsyncOperation(telemetry, "install.read_manifest", {
      inspectedPackageDir: materialized.source.inspectedPackageDir
    }, async () => readPackageManifest(materialized.source.inspectedPackageDir));
    const delegation = measuredOperation(telemetry, "install.verify_delegation", {
      packageName: manifest.name,
      hasDelegationProof: options.delegationProof !== undefined,
      hasTrustPolicy: options.delegationTrustPolicy !== undefined
    }, () => verifyDelegationProof(options.delegationProof, {
      expectedAudience: "customs.install",
      requiredScopes: ["package:install"],
      now: options.now,
      trustPolicy: options.delegationTrustPolicy
    }));
    const decision = measuredOperation(telemetry, "install.evaluate_policy", {
      packageName: manifest.name,
      delegationOk: delegation.ok,
      delegationReason: delegation.reason
    }, () => evaluateInstall({
      packageName: manifest.name,
      packageVersion: manifest.version,
      scripts: manifest.scripts ?? {},
      delegation,
      policy: options.policy
    }));
    const previousHash = await readPreviousHash(options.chainPath, telemetry);
    const issuer = options.receiptIssuer ?? (await measuredAsyncOperation(telemetry, "install.load_receipt_issuer", {
      issuerKeyPath: options.issuerKeyPath ?? DEFAULT_RECEIPT_ISSUER_KEY_PATH,
      createIfMissing: options.createIssuerKeyIfMissing === true
    }, async () => loadOrCreateLocalReceiptIssuer(options.issuerKeyPath ?? DEFAULT_RECEIPT_ISSUER_KEY_PATH, {
      createIfMissing: options.createIssuerKeyIfMissing === true
    })));
    const receipt = issuer.issue(decision, previousHash, telemetry);
    await writeReceipt(options.receiptPath, receipt, telemetry);
    await appendReceiptChainRecord(options.chainPath, receipt, telemetry);
    return {
      decision,
      receipt,
      receiptPath: options.receiptPath,
      chainPath: options.chainPath,
      source: materialized.source
    };
  } finally {
    await measuredAsyncOperation(telemetry, "install.cleanup_staging", {
      stagedWithIgnoreScripts: materialized.source.stagedWithIgnoreScripts,
      stagingDir: materialized.source.stagingDir
    }, async () => materialized.cleanup());
  }
}
