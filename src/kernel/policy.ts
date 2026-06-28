import type { DelegationVerification } from "./delegation.js";

export const ACTOR_CLASSES = ["verified_agent", "signed_agent", "likely_human", "suspicious_automation", "unknown"] as const;
export type ActorClass = (typeof ACTOR_CLASSES)[number];

export const DECISION_ACTIONS = ["allow", "throttle", "queue", "sandbox", "deny", "price_required"] as const;
export type DecisionAction = (typeof DECISION_ACTIONS)[number];

export const VERIFIER_MODES = ["observe", "recommend", "enforce"] as const;
export type VerifierMode = (typeof VERIFIER_MODES)[number];

export type ReasonCode =
  | "matched_policy"
  | "missing_delegation"
  | "bad_delegation_signature"
  | "untrusted_delegation_issuer"
  | "delegation_public_key_mismatch"
  | "delegation_expired"
  | "delegation_audience_mismatch"
  | "permission_scope_mismatch"
  | "lifecycle_script_detected"
  | "poisoned_postinstall_detected"
  | "price_required"
  | "sandbox_policy"
  | "rate_limited"
  | "queued_for_review";

export interface PackageScriptFinding {
  readonly name: string;
  readonly command: string;
  readonly suspiciousTokens: readonly string[];
}

export interface InstallPolicy {
  readonly mode: VerifierMode;
  readonly deniedLifecycleScripts: readonly string[];
  readonly suspiciousScriptTokens: readonly string[];
  readonly packageOverrides: readonly PackageDecisionOverride[];
}

export interface PackageDecisionOverride {
  readonly packageName: string;
  readonly decision: DecisionAction;
  readonly reason?: ReasonCode | undefined;
}

export interface InstallEvaluationInput {
  readonly packageName: string;
  readonly packageVersion?: string | undefined;
  readonly scripts: Readonly<Record<string, string>>;
  readonly delegation: DelegationVerification;
  readonly policy?: InstallPolicy | undefined;
}

export interface InstallDecision {
  readonly actionType: "package_install";
  readonly packageName: string;
  readonly packageVersion?: string | undefined;
  readonly actorClass: ActorClass;
  readonly decision: DecisionAction;
  readonly recommendedDecision: DecisionAction;
  readonly mode: VerifierMode;
  readonly httpStatus: number;
  readonly blocked: boolean;
  readonly reasons: readonly ReasonCode[];
  readonly lifecycleFindings: readonly PackageScriptFinding[];
  readonly delegationChainId?: string | undefined;
  readonly delegationSubject?: string | undefined;
  readonly occurredAt: string;
}

const DEFAULT_POLICY: InstallPolicy = {
  mode: "enforce",
  deniedLifecycleScripts: ["preinstall", "install", "postinstall"],
  suspiciousScriptTokens: ["curl", "wget", "Invoke-WebRequest", "powershell", "rm -rf", "bash -c", "node -e"],
  packageOverrides: []
};

function decisionHttpStatus(action: DecisionAction): number {
  switch (action) {
    case "allow":
    case "sandbox":
      return 200;
    case "throttle":
      return 429;
    case "queue":
      return 202;
    case "deny":
      return 403;
    case "price_required":
      return 402;
  }
}

function actorClassForDelegation(delegation: DelegationVerification): ActorClass {
  return delegation.ok ? "verified_agent" : "signed_agent";
}

function findingsForScripts(scripts: Readonly<Record<string, string>>, policy: InstallPolicy): PackageScriptFinding[] {
  const denied = new Set(policy.deniedLifecycleScripts);
  const findings: PackageScriptFinding[] = [];
  for (const [name, command] of Object.entries(scripts)) {
    if (!denied.has(name)) {
      continue;
    }
    const lower = command.toLowerCase();
    const suspiciousTokens = policy.suspiciousScriptTokens.filter((token) => lower.includes(token.toLowerCase()));
    findings.push({ name, command, suspiciousTokens });
  }
  return findings;
}

function enforceMode(candidate: DecisionAction, mode: VerifierMode): { decision: DecisionAction; recommended: DecisionAction } {
  if (mode === "enforce" || candidate === "allow") {
    return { decision: candidate, recommended: candidate };
  }
  return { decision: "allow", recommended: candidate };
}

export function defaultInstallPolicy(overrides: Partial<InstallPolicy> = {}): InstallPolicy {
  return {
    mode: overrides.mode ?? DEFAULT_POLICY.mode,
    deniedLifecycleScripts: overrides.deniedLifecycleScripts ?? DEFAULT_POLICY.deniedLifecycleScripts,
    suspiciousScriptTokens: overrides.suspiciousScriptTokens ?? DEFAULT_POLICY.suspiciousScriptTokens,
    packageOverrides: overrides.packageOverrides ?? DEFAULT_POLICY.packageOverrides
  };
}

export function evaluateInstall(input: InstallEvaluationInput): InstallDecision {
  const policy = input.policy ?? DEFAULT_POLICY;
  const actorClass = actorClassForDelegation(input.delegation);
  const reasons: ReasonCode[] = [];
  let candidate: DecisionAction = "allow";

  if (!input.delegation.ok) {
    candidate = "deny";
    const reason = input.delegation.reason;
    if (reason === "bad_delegation_signature") {
      reasons.push("bad_delegation_signature");
    } else if (reason === "untrusted_delegation_issuer") {
      reasons.push("untrusted_delegation_issuer");
    } else if (reason === "delegation_public_key_mismatch") {
      reasons.push("delegation_public_key_mismatch");
    } else if (reason === "delegation_expired") {
      reasons.push("delegation_expired");
    } else if (reason === "delegation_audience_mismatch") {
      reasons.push("delegation_audience_mismatch");
    } else {
      reasons.push("missing_delegation");
    }
  }

  const override = policy.packageOverrides.find((item) => item.packageName === input.packageName);
  if (override !== undefined) {
    candidate = override.decision;
    reasons.push(override.reason ?? "matched_policy");
  }

  const lifecycleFindings = findingsForScripts(input.scripts, policy);
  if (lifecycleFindings.length > 0) {
    const hasDeniedPostinstall = lifecycleFindings.some((finding) => finding.name === "postinstall");
    candidate = "deny";
    reasons.push(hasDeniedPostinstall ? "poisoned_postinstall_detected" : "lifecycle_script_detected");
    if (input.delegation.ok) {
      const claims = input.delegation.claims;
      if (
        claims === undefined ||
        !claims.scope.some((scope) => scope === "lifecycle:*" || lifecycleFindings.some((finding) => scope === `lifecycle:${finding.name}`))
      ) {
        reasons.push("permission_scope_mismatch");
      }
    }
  }

  if (candidate === "price_required") {
    reasons.push("price_required");
  } else if (candidate === "sandbox") {
    reasons.push("sandbox_policy");
  } else if (candidate === "throttle") {
    reasons.push("rate_limited");
  } else if (candidate === "queue") {
    reasons.push("queued_for_review");
  } else if (reasons.length === 0) {
    reasons.push("matched_policy");
  }

  const modeDecision = enforceMode(candidate, policy.mode);
  return {
    actionType: "package_install",
    packageName: input.packageName,
    packageVersion: input.packageVersion,
    actorClass,
    decision: modeDecision.decision,
    recommendedDecision: modeDecision.recommended,
    mode: policy.mode,
    httpStatus: decisionHttpStatus(modeDecision.decision),
    blocked: modeDecision.decision !== "allow",
    reasons: [...new Set(reasons)],
    lifecycleFindings,
    delegationChainId: input.delegation.claims?.chain_id,
    delegationSubject: input.delegation.claims?.sub,
    occurredAt: new Date().toISOString()
  };
}
