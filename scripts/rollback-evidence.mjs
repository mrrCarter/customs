import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

function argValue(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) {
    return fallback;
  }
  const value = process.argv[index + 1];
  if (value === undefined || value.startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

const root = process.cwd();
const outputPath = argValue("--output", join(root, "artifacts", "rollback.json"));
const target = argValue("--target", process.env.CUSTOMS_ROLLBACK_TARGET ?? "previous-signed-evidence-artifact");
const reason = argValue("--reason", process.env.CUSTOMS_ROLLBACK_REASON ?? "release-smoke-drill");
const operator = argValue("--operator", process.env.GITHUB_ACTOR ?? "local");
const runId = process.env.GITHUB_RUN_ID ?? "local";

const evidence = {
  schema: "customs.rollback.v1",
  status: "recorded",
  rollback: "artifact-only release; no production mutation performed",
  target,
  reason,
  operator,
  runId,
  recordedAt: new Date().toISOString(),
  validation: {
    action: "retain previous signed release evidence and require manual package review until gates pass",
    requiredFollowUp: "rerun release:smoke and Omar Gate before promotion resumes"
  }
};

await mkdir(join(root, "artifacts"), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
console.log(JSON.stringify({ ok: true, outputPath, target, reason }, null, 2));
