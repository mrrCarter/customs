import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";

const root = process.cwd();
const outputPath = join(root, "artifacts", "provenance", "customs-build-provenance.json");
const excludedDirs = new Set([".git", ".sentinelayer", "artifacts", "dist", "node_modules"]);

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  return `{${Object.entries(value)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
    .join(",")}}`;
}

function sha256Hex(input) {
  return createHash("sha256").update(input).digest("hex");
}

async function filesUnder(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (excludedDirs.has(entry.name)) {
      continue;
    }
    const absolute = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await filesUnder(absolute)));
      continue;
    }
    if (entry.isFile()) {
      files.push(absolute);
    }
  }
  return files;
}

const files = await filesUnder(root);
const materials = [];
for (const file of files.sort()) {
  const bytes = await readFile(file);
  materials.push({
    path: relative(root, file).replaceAll("\\", "/"),
    sha256: sha256Hex(bytes)
  });
}

const predicate = {
  predicateType: "https://slsa.dev/provenance/v1",
  subject: {
    name: "customs",
    digest: {
      sha256: sha256Hex(canonicalJson(materials))
    }
  },
  builder: {
    id: "customs-local-release-smoke"
  },
  buildType: "https://plexaura.local/customs/v1/local-artifact-release",
  invocation: {
    configSource: {
      uri: "local:customs",
      entryPoint: "npm run release:smoke"
    }
  },
  metadata: {
    buildStartedOn: new Date().toISOString(),
    completeness: {
      parameters: true,
      environment: false,
      materials: true
    },
    reproducible: false
  },
  materials
};

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const predicateJson = canonicalJson(predicate);
const signature = sign(null, Buffer.from(predicateJson, "utf8"), privateKey).toString("base64url");
const envelope = {
  mediaType: "application/vnd.customs.provenance+json;version=1",
  alg: "Ed25519",
  predicate,
  predicateSha256: sha256Hex(predicateJson),
  signature,
  publicJwk: publicKey.export({ format: "jwk" })
};

await mkdir(join(root, "artifacts", "provenance"), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(envelope, null, 2)}\n`, "utf8");
console.log(JSON.stringify({ ok: true, outputPath, subjectSha256: predicate.subject.digest.sha256 }, null, 2));
