import { createHash } from "node:crypto";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

function assertJsonValue(value: unknown, path: string): asserts value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`${path} must be finite`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertJsonValue(item, `${path}[${index}]`));
    return;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) {
        throw new Error(`${path}.${key} cannot be undefined`);
      }
      assertJsonValue(item, `${path}.${key}`);
    }
    return;
  }
  throw new Error(`${path} is not canonical JSON`);
}

export function canonicalJson(value: JsonValue): string {
  assertJsonValue(value, "$");
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function toJsonValue(value: unknown, path = "$"): JsonValue {
  if (value === undefined) {
    throw new Error(`${path} cannot be undefined`);
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`${path} must be finite`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => toJsonValue(item, `${path}[${index}]`));
  }
  if (typeof value === "object") {
    const output: Record<string, JsonValue> = {};
    for (const [key, item] of Object.entries(value)) {
      if (item !== undefined) {
        output[key] = toJsonValue(item, `${path}.${key}`);
      }
    }
    return output;
  }
  throw new Error(`${path} cannot be encoded as JSON`);
}

export function toJsonObject(value: Readonly<Record<string, unknown>>, path = "$"): { readonly [key: string]: JsonValue } {
  const converted = toJsonValue(value, path);
  if (converted === null || typeof converted !== "object" || Array.isArray(converted)) {
    throw new Error(`${path} must be an object`);
  }
  return converted as { readonly [key: string]: JsonValue };
}
