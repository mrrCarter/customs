import { generateKeyPairSync } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createDelegationProof,
  delegationTrustPolicyForPublicJwk,
  type DelegationClaims,
  verifyDelegationProof
} from "../src/kernel/delegation.js";
import { DECISION_ACTIONS, evaluateInstall } from "../src/kernel/policy.js";
import { LocalReceiptIssuer, verifyReceipt } from "../src/kernel/receipts.js";

function claims(overrides: Partial<DelegationClaims> = {}): DelegationClaims {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: "did:aidenid:test",
    sub: "agent:test",
    aud: "customs.install",
    scope: ["package:install"],
    iat: now,
    exp: now + 60,
    jti: "jti-test",
    chain_id: "chain:test",
    ...overrides
  };
}

test("delegation proof uses real Ed25519 verification", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const proof = createDelegationProof({ claims: claims(), privateKey, publicKey });
  assert.equal(
    verifyDelegationProof(proof, {
      expectedAudience: "customs.install",
      requiredScopes: ["package:install"],
      trustPolicy: delegationTrustPolicyForPublicJwk(proof.publicJwk)
    }).ok,
    true
  );

  const tampered = { ...proof, claims: { ...proof.claims, sub: "agent:attacker" } };
  assert.equal(
    verifyDelegationProof(tampered, {
      expectedAudience: "customs.install",
      requiredScopes: ["package:install"],
      trustPolicy: delegationTrustPolicyForPublicJwk(proof.publicJwk)
    }).ok,
    false
  );
});

test("delegation proof fails closed without trusted issuer key material", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const proof = createDelegationProof({ claims: claims(), privateKey, publicKey });
  const verification = verifyDelegationProof(proof, {
    expectedAudience: "customs.install",
    requiredScopes: ["package:install"]
  });

  assert.equal(verification.ok, false);
  assert.equal(verification.reason, "untrusted_delegation_issuer");
});

test("delegation proof rejects attacker self-signed verified-agent forgery", () => {
  const trusted = generateKeyPairSync("ed25519");
  const attacker = generateKeyPairSync("ed25519");
  const forged = createDelegationProof({
    claims: claims({
      iss: "did:aidenid:TOTALLY-FAKE-ISSUER",
      sub: "agent:attacker-controlled",
      chain_id: "chain:attacker-invented"
    }),
    privateKey: attacker.privateKey,
    publicKey: attacker.publicKey
  });
  const trustedProof = createDelegationProof({ claims: claims(), privateKey: trusted.privateKey, publicKey: trusted.publicKey });
  const verification = verifyDelegationProof(forged, {
    expectedAudience: "customs.install",
    requiredScopes: ["package:install"],
    trustPolicy: delegationTrustPolicyForPublicJwk(trustedProof.publicJwk)
  });

  assert.equal(verification.ok, false);
  assert.equal(verification.reason, "untrusted_delegation_issuer");
});

test("delegation proof rejects key-id spoofing against a trusted issuer", () => {
  const trusted = generateKeyPairSync("ed25519");
  const attacker = generateKeyPairSync("ed25519");
  const trustedProof = createDelegationProof({ claims: claims(), privateKey: trusted.privateKey, publicKey: trusted.publicKey });
  const forged = createDelegationProof({ claims: claims({ sub: "agent:attacker" }), privateKey: attacker.privateKey, publicKey: attacker.publicKey });
  const spoofed = { ...forged, keyId: trustedProof.keyId };
  const verification = verifyDelegationProof(spoofed, {
    expectedAudience: "customs.install",
    requiredScopes: ["package:install"],
    trustPolicy: delegationTrustPolicyForPublicJwk(trustedProof.publicJwk)
  });

  assert.equal(verification.ok, false);
  assert.equal(verification.reason, "delegation_public_key_mismatch");
});

test("policy engine exposes the six-outcome ladder and blocks poisoned postinstall", () => {
  assert.deepEqual([...DECISION_ACTIONS], ["allow", "throttle", "queue", "sandbox", "deny", "price_required"]);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const proof = createDelegationProof({ claims: claims(), privateKey, publicKey });
  const delegation = verifyDelegationProof(proof, {
    expectedAudience: "customs.install",
    requiredScopes: ["package:install"],
    trustPolicy: delegationTrustPolicyForPublicJwk(proof.publicJwk)
  });
  const decision = evaluateInstall({
    packageName: "@demo/poisoned",
    scripts: { postinstall: "node postinstall.js" },
    delegation
  });
  assert.equal(decision.decision, "deny");
  assert.equal(decision.blocked, true);
  assert.ok(decision.reasons.includes("poisoned_postinstall_detected"));
  assert.ok(decision.reasons.includes("permission_scope_mismatch"));
});

test("signed receipts verify offline and fail on tampering", () => {
  const decision = evaluateInstall({
    packageName: "@demo/safe",
    scripts: {},
    delegation: { ok: false, reason: "missing_delegation" }
  });
  const issuer = new LocalReceiptIssuer();
  const receipt = issuer.issue(decision);
  assert.equal(verifyReceipt(receipt).ok, false);
  assert.equal(verifyReceipt(receipt).reason, "untrusted_issuer_key");
  assert.equal(verifyReceipt(receipt, issuer.trustPolicy()).ok, true);

  const attackerIssuer = new LocalReceiptIssuer();
  const misleadingEmbeddedJwk = {
    ...receipt,
    publicJwk: attackerIssuer.trustedPublicJwk()
  };
  const mismatchedEmbeddedKey = verifyReceipt(misleadingEmbeddedJwk, issuer.trustPolicy());
  assert.equal(mismatchedEmbeddedKey.ok, false);
  assert.equal(mismatchedEmbeddedKey.reason, "receipt_public_key_mismatch");

  const tampered = {
    ...receipt,
    payload: {
      ...receipt.payload,
      decision: "allow"
    }
  };
  assert.equal(verifyReceipt(tampered, issuer.trustPolicy()).ok, false);

  const forged = attackerIssuer.issue({
    ...decision,
    decision: "allow",
    recommendedDecision: "allow",
    httpStatus: 200,
    blocked: false,
    reasons: ["matched_policy"],
    lifecycleFindings: []
  });
  const forgedVerification = verifyReceipt(forged, issuer.trustPolicy());
  assert.equal(forgedVerification.ok, false);
  assert.equal(forgedVerification.reason, "untrusted_issuer_key");

  const forgedWithTrustedKeyId = {
    ...forged,
    keyId: receipt.keyId
  };
  const keyIdSpoofVerification = verifyReceipt(forgedWithTrustedKeyId, issuer.trustPolicy());
  assert.equal(keyIdSpoofVerification.ok, false);
  assert.equal(keyIdSpoofVerification.reason, "receipt_public_key_mismatch");

  const forgedWithTrustedMetadata = {
    ...forged,
    keyId: receipt.keyId,
    publicJwk: receipt.publicJwk
  };
  const forgedTrustedMetadataVerification = verifyReceipt(forgedWithTrustedMetadata, issuer.trustPolicy());
  assert.equal(forgedTrustedMetadataVerification.ok, false);
  assert.equal(forgedTrustedMetadataVerification.reason, "JWS signature verification failed");
});
