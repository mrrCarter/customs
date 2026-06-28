import {
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
  type JsonWebKey,
  type KeyObject
} from "node:crypto";

import { sha256Hex } from "./canonicalJson.js";

export type PublicJwk = Record<string, unknown>;

export function base64Url(input: Uint8Array): string {
  return Buffer.from(input).toString("base64url");
}

export function base64UrlToBuffer(input: string): Buffer {
  return Buffer.from(input, "base64url");
}

function publicKeyFromJwk(publicJwk: PublicJwk): KeyObject {
  return createPublicKey({ key: publicJwk as JsonWebKey, format: "jwk" });
}

export interface VerifySignatureInput {
  readonly publicJwk: PublicJwk;
  readonly payload: string | Uint8Array;
  readonly signature: string | Uint8Array;
}

function toBuffer(input: string | Uint8Array): Buffer {
  return typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
}

export function verifyEd25519Signature(input: VerifySignatureInput): boolean {
  return nodeVerify(null, toBuffer(input.payload), publicKeyFromJwk(input.publicJwk), toBuffer(input.signature));
}

function jsonToBase64Url(value: Record<string, unknown>): string {
  return base64Url(Buffer.from(JSON.stringify(value), "utf8"));
}

function parseJsonPart(part: string, name: string): Record<string, unknown> {
  const parsed = JSON.parse(base64UrlToBuffer(part).toString("utf8")) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`compact JWS ${name} must be a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

export interface DecodedCompactJws {
  readonly header: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
  readonly signingInput: string;
  readonly signature: Buffer;
}

export function signCompactJws(
  payload: Record<string, unknown>,
  privateKey: KeyObject,
  protectedHeader: Record<string, unknown> = {}
): string {
  const header = { typ: "JWT", ...protectedHeader, alg: "EdDSA" };
  const signingInput = `${jsonToBase64Url(header)}.${jsonToBase64Url(payload)}`;
  const signature = nodeSign(null, Buffer.from(signingInput, "ascii"), privateKey);
  return `${signingInput}.${base64Url(signature)}`;
}

export function decodeCompactJws(token: string): DecodedCompactJws {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error("compact JWS must contain three non-empty parts");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  return {
    header: parseJsonPart(encodedHeader, "header"),
    payload: parseJsonPart(encodedPayload, "payload"),
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature: base64UrlToBuffer(encodedSignature)
  };
}

export function verifyCompactJws(token: string, publicJwk: PublicJwk): DecodedCompactJws {
  const decoded = decodeCompactJws(token);
  if (decoded.header.alg !== "EdDSA") {
    throw new Error(`unsupported JWS alg: ${String(decoded.header.alg)}`);
  }
  const verified = nodeVerify(
    null,
    Buffer.from(decoded.signingInput, "ascii"),
    publicKeyFromJwk(publicJwk),
    decoded.signature
  );
  if (!verified) {
    throw new Error("JWS signature verification failed");
  }
  return decoded;
}

const OKP_THUMBPRINT_MEMBERS = ["crv", "kty", "x"] as const;

function requireStringMember(jwk: PublicJwk, member: string): string {
  const value = jwk[member];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`JWK member '${member}' is required`);
  }
  return value;
}

export function canonicalJwkThumbprintSha256(jwk: PublicJwk): string {
  if (requireStringMember(jwk, "kty") !== "OKP") {
    throw new Error("only OKP Ed25519 JWK thumbprints are supported in Customs v1");
  }
  const canonical: Record<string, string> = {};
  for (const member of OKP_THUMBPRINT_MEMBERS) {
    canonical[member] = requireStringMember(jwk, member);
  }
  return sha256Hex(JSON.stringify(canonical));
}

export function canonicalJwkThumbprintBase64Url(jwk: PublicJwk): string {
  return base64Url(Buffer.from(canonicalJwkThumbprintSha256(jwk), "hex"));
}

export function publicJwkFromKey(publicKey: KeyObject): PublicJwk {
  return publicKey.export({ format: "jwk" }) as PublicJwk;
}
