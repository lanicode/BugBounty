import { normalizePolicy } from "../../packages/control-plane/policy.js";
import type {
  CampaignRecord,
  OwnedObjectRecord,
  ProgramRecord,
  TestIdentityRecord,
} from "../../packages/control-plane/types.js";

export const NOW = "2026-07-13T12:00:00.000Z";
export const LATER = "2026-07-13T13:00:00.000Z";
export const POLICY_HASH = normalizePolicy({
  text: "Local simulation policy",
  allowedAssets: ["demo.local.test"],
  excludedAssets: ["admin.demo.local.test"],
  requestLimits: {
    requestsPerMinute: 10,
    maxRequestsTotal: 20,
    maxConcurrency: 1,
  },
  allowedTestClasses: ["offline_simulation"],
  forbiddenTestClasses: ["active_security_test"],
  rules: ["Use local simulation only"],
  unclearRules: [],
}).policyHash;

export function controlPlanePolicy(versionText = "Local simulation policy") {
  return normalizePolicy({
    text: versionText,
    allowedAssets: ["demo.local.test"],
    excludedAssets: ["admin.demo.local.test"],
    requestLimits: {
      requestsPerMinute: 10,
      maxRequestsTotal: 20,
      maxConcurrency: 1,
    },
    allowedTestClasses: ["offline_simulation"],
    forbiddenTestClasses: ["active_security_test"],
    rules: ["Use local simulation only"],
    unclearRules: [],
  });
}

export function programInput(): Omit<
  ProgramRecord,
  | "createdAt"
  | "currentPolicyHash"
  | "currentPolicyVersion"
  | "ruleAcceptanceStatus"
> {
  return {
    id: "program-local",
    name: "Local Mock Program",
    platform: "local_mock",
    status: "available",
    description: "In-process fixture only",
    programUrl: "https://program.invalid/local-metadata-only",
    programType: "simulation",
    allowedAssets: ["demo.local.test"],
    excludedAssets: ["admin.demo.local.test"],
    lastSynchronizedAt: NOW,
    automationPermission: "allowed",
    notes: "Never fetched",
    lifecycle: "active",
  };
}

export function campaign(
  overrides: Partial<CampaignRecord> = {},
): CampaignRecord {
  return Object.freeze({
    id: "campaign-local",
    programId: "program-local",
    policyVersion: 1,
    policyHash: POLICY_HASH,
    approvedAssets: Object.freeze(["demo.local.test"]),
    approvedRiskTiers: Object.freeze(["tier_0_offline"] as const),
    accountRefs: Object.freeze(["identity-owner"]),
    allowedActionClasses: Object.freeze(["offline_simulation"] as const),
    contract: Object.freeze({
      allowedHosts: Object.freeze(["demo.local.test"]),
      excludedHosts: Object.freeze(["admin.demo.local.test"]),
      maxRequests: 20,
      requestsPerMinute: 10,
      maxConcurrency: 1,
      allowedRiskTiers: Object.freeze(["tier_0_offline"] as const),
      allowedMethods: Object.freeze(["GET", "HEAD"] as const),
      writeActionsAllowed: false,
      rollbackRequired: true,
      humanCheckpoints: Object.freeze(["campaign_approval"]),
      validFrom: "2026-07-13T00:00:00.000Z",
      validUntil: "2026-07-14T00:00:00.000Z",
      policyHash: POLICY_HASH,
    }),
    state: "draft",
    revision: 0,
    humanApprovedBy: null,
    humanApprovedAt: null,
    lastPolicyCheckAt: null,
    killSwitchStatus: "clear",
    createdAt: NOW,
    ...overrides,
  });
}

export function identity(): TestIdentityRecord {
  return Object.freeze({
    id: "identity-owner",
    programId: "program-local",
    role: "Owner",
    status: "ready",
    emailReference: "ref:/mock-email-owner",
    secretReferences: Object.freeze([]),
    browserProfileReference: null,
    platformAccountReference: "ref:/mock-account-owner",
    createdAt: NOW,
    verifiedAt: NOW,
    suspendedAt: null,
    retiredAt: null,
    lastSuccessfulLoginAt: NOW,
    humanActionRequired: false,
    organizationRef: "local-org",
    ownedObjectRefs: Object.freeze(["object-local"]),
  });
}

export function ownedObject(
  overrides: Partial<OwnedObjectRecord> = {},
): OwnedObjectRecord {
  return Object.freeze({
    objectRef: "object-local",
    protectedActualIdRef: "protected-ref:object-local-pseudonym",
    programId: "program-local",
    campaignId: "campaign-local",
    accountId: "identity-owner",
    tenantRef: "local-org",
    objectType: "document",
    canaryHmac: "c".repeat(64),
    createdAt: NOW,
    status: "active",
    researcherControlled: true,
    allowedActions: Object.freeze(["offline_inspect"]),
    expiresAt: "2026-07-14T00:00:00.000Z",
    policyHash: POLICY_HASH,
    ...overrides,
  });
}
