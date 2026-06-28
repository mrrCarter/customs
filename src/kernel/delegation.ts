import { sign as nodeSign, type KeyObject } from "node:crypto";

import { canonicalJson, toJsonObject } from "./canonicalJson.js";
import {
  base64Url,
  base64UrlToBuffer,
  canonicalJwkThumbprintBase64Url,
  publicJwkFromKey,
  verifyEd25519Signature,
  type PublicJwk
} from "./crypto.js";

export interface DelegationClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: "customs.install";
  readonly scope: readonly string[];
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
  readonly chain_id: string;
}

export interface DelegationProof {
  readonly claims: DelegationClaims;
  readonly publicJwk: PublicJwk;
  readonly keyId?: string | undefined;
  readonly signature: string;
}

export interface DelegationVerification {
  readonly ok: boolean;
  readonly reason?: string | undefined;
  readonly claims?: DelegationClaims | undefined;
}

export interface DelegationTrustPolicy {
  readonly trustedKeyIds?: readonly string[] | undefined;
  readonly trustedPublicJwks?: readonly PublicJwk[] | undefined;
}

export function delegationKeyIdForPublicJwk(publicJwk: PublicJwk): string {
  return `customs-delegation-ed25519-${canonicalJwkThumbprintBase64Url(publicJwk)}`;
}

export function delegationTrustPolicyForPublicJwk(publicJwk: PublicJwk): DelegationTrustPolicy {
  return {
    trustedKeyIds: [delegationKeyIdForPublicJwk(publicJwk)],
    trustedPublicJwks: [publicJwk]
  };
}

function signingPayload(claims: DelegationClaims): string {
  return canonicalJson(toJsonObject(claims as unknown as Readonly<Record<string, unknown>>, "delegation.claims"));
}

export function createDelegationProof(input: {
  readonly claims: DelegationClaims;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}): DelegationProof {
  const payload = signingPayload(input.claims);
  const signature = nodeSign(null, Buffer.from(payload, "utf8"), input.privateKey);
  const publicJwk = publicJwkFromKey(input.publicKey);
  return {
    claims: input.claims,
    publicJwk,
    keyId: delegationKeyIdForPublicJwk(publicJwk),
    signature: base64Url(signature)
  };
}

function trustedDelegationPublicJwk(
  proof: DelegationProof,
  policy: DelegationTrustPolicy
): { readonly publicJwk?: PublicJwk | undefined; readonly reason?: string | undefined } {
  const proofKeyId = delegationKeyIdForPublicJwk(proof.publicJwk);
  if (proof.keyId !== undefined && proof.keyId !== proofKeyId) {
    return { reason: "delegation_public_key_mismatch" };
  }
  const expectedKeyId = proof.keyId ?? proofKeyId;
  const trustedPublicJwks = policy.trustedPublicJwks ?? [];
  if (trustedPublicJwks.length === 0) {
    return { reason: "untrusted_delegation_issuer" };
  }
  const trustedKeyIds = new Set(policy.trustedKeyIds ?? []);
  if (trustedKeyIds.size > 0 && !trustedKeyIds.has(expectedKeyId)) {
    return { reason: "untrusted_delegation_issuer" };
  }
  const trustedPublicJwk = trustedPublicJwks.find((jwk) => delegationKeyIdForPublicJwk(jwk) === expectedKeyId);
  if (trustedPublicJwk === undefined) {
    return { reason: "untrusted_delegation_issuer" };
  }
  return { publicJwk: trustedPublicJwk };
}

export function verifyDelegationProof(
  proof: DelegationProof | undefined,
  input: {
    readonly expectedAudience: "customs.install";
    readonly requiredScopes: readonly string[];
    readonly now?: Date | undefined;
    readonly trustPolicy?: DelegationTrustPolicy | undefined;
  }
): DelegationVerification {
  if (proof === undefined) {
    return { ok: false, reason: "missing_delegation" };
  }
  try {
    const nowSeconds = Math.floor((input.now ?? new Date()).getTime() / 1000);
    if (proof.claims.aud !== input.expectedAudience) {
      return { ok: false, reason: "delegation_audience_mismatch" };
    }
    if (proof.claims.exp <= nowSeconds) {
      return { ok: false, reason: "delegation_expired" };
    }
    const missingScopes = input.requiredScopes.filter((scope) => !proof.claims.scope.includes(scope));
    if (missingScopes.length > 0) {
      return { ok: false, reason: `delegation_scope_missing:${missingScopes.join(",")}` };
    }
    const trusted = trustedDelegationPublicJwk(proof, input.trustPolicy ?? {});
    if (trusted.publicJwk === undefined) {
      return { ok: false, reason: trusted.reason ?? "untrusted_delegation_issuer" };
    }
    const payload = signingPayload(proof.claims);
    const verified = verifyEd25519Signature({
      publicJwk: trusted.publicJwk,
      payload,
      signature: base64UrlToBuffer(proof.signature)
    });
    if (!verified) {
      return { ok: false, reason: "bad_delegation_signature" };
    }
    return { ok: true, claims: proof.claims };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) };
  }
}
