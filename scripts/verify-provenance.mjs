import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";

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

const path = process.argv[2];
if (!path) {
  throw new Error("Usage: node scripts/verify-provenance.mjs <provenance.json>");
}

const envelope = JSON.parse(await readFile(path, "utf8"));
const predicateJson = canonicalJson(envelope.predicate);
const predicateSha256 = sha256Hex(predicateJson);
const publicKey = createPublicKey({ key: envelope.publicJwk, format: "jwk" });
const ok =
  envelope.alg === "Ed25519" &&
  predicateSha256 === envelope.predicateSha256 &&
  verify(null, Buffer.from(predicateJson, "utf8"), publicKey, Buffer.from(envelope.signature, "base64url"));

console.log(JSON.stringify({ ok, predicateSha256, subjectSha256: envelope.predicate?.subject?.digest?.sha256 }, null, 2));
if (!ok) {
  process.exitCode = 1;
}
