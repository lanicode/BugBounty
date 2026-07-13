import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

export type DemoRole = "External" | "Member" | "Owner";

export interface DemoIdentity {
  readonly identityRef: string;
  readonly displayName: string;
  readonly role: DemoRole;
}

export interface DemoOrganization {
  readonly organizationRef: string;
  readonly displayName: string;
  readonly identities: readonly DemoIdentity[];
}

export interface DemoProject {
  readonly projectRef: string;
  readonly organizationRef: string;
  readonly displayName: string;
  readonly createdByRef: string;
  readonly createdAt: string;
}

export interface DemoDocument {
  readonly documentRef: string;
  readonly projectRef: string;
  readonly title: string;
  readonly classification: "internal" | "shared";
  readonly createdByRef: string;
  readonly createdAt: string;
}

export interface DemoInvitation {
  readonly invitationRef: string;
  readonly organizationRef: string;
  readonly inviteeRef: string;
  readonly role: "External" | "Member";
  readonly status: "pending";
  readonly createdByRef: string;
  readonly createdAt: string;
}

export interface DemoTestObject {
  readonly objectRef: string;
  readonly projectRef: string;
  readonly controlledByRef: string;
  readonly canary: string;
  readonly status: "active";
  readonly createdAt: string;
}

export interface DemoPolicyRules {
  readonly requestLimit: number;
  readonly allowedActions: readonly string[];
  readonly prohibitedTestClasses: readonly string[];
}

export interface DemoPolicyVersion {
  readonly version: number;
  readonly contentHash: string;
  readonly effectiveAt: string;
  readonly rules: DemoPolicyRules;
}

export type DemoPolicyChangedField =
  "allowedActions" | "prohibitedTestClasses" | "requestLimit";

export interface DemoPolicyDrift {
  readonly previousVersion: number;
  readonly previousHash: string;
  readonly nextVersion: number;
  readonly nextHash: string;
  readonly changedFields: readonly DemoPolicyChangedField[];
  readonly detectedAt: string;
}

export interface DemoSaasSnapshot {
  readonly mode: "simulation";
  readonly externalIntegrationsEnabled: false;
  readonly revision: number;
  readonly organization: DemoOrganization;
  readonly projects: readonly DemoProject[];
  readonly documents: readonly DemoDocument[];
  readonly invitations: readonly DemoInvitation[];
  readonly testObjects: readonly DemoTestObject[];
  readonly currentPolicy: DemoPolicyVersion;
  readonly policyVersions: readonly DemoPolicyVersion[];
  readonly lastPolicyDrift: DemoPolicyDrift | null;
}

const INITIAL_TIME = "2026-07-13T12:00:00.000Z";
const SAFE_REF = /^[a-z][a-z0-9_-]{2,63}$/u;
const SAFE_CANARY = /^canary-[A-Za-z0-9_-]{1,100}$/u;
const SAFE_TEXT = /^[^\u0000-\u001f\u007f]{1,100}$/u;
const SAFE_RULE = /^[a-z][a-z0-9_.:-]{0,63}$/u;
const MAX_RECORDS_PER_KIND = 1_000;

const SEEDED_IDENTITIES: readonly DemoIdentity[] = Object.freeze([
  Object.freeze({
    identityRef: "identity-owner-001",
    displayName: "Demo Owner",
    role: "Owner" as const,
  }),
  Object.freeze({
    identityRef: "identity-member-001",
    displayName: "Demo Member",
    role: "Member" as const,
  }),
  Object.freeze({
    identityRef: "identity-external-001",
    displayName: "Demo External",
    role: "External" as const,
  }),
]);

const SEEDED_ORGANIZATION: DemoOrganization = Object.freeze({
  organizationRef: "org-demo-001",
  displayName: "Loopback Demo Organization",
  identities: SEEDED_IDENTITIES,
});

const INITIAL_RULES: DemoPolicyRules = Object.freeze({
  requestLimit: 20,
  allowedActions: Object.freeze(["document.read", "project.read"]),
  prohibitedTestClasses: Object.freeze(["active_security_test"]),
});

export class DemoSaas {
  readonly #projects = new Map<string, DemoProject>();
  readonly #documents = new Map<string, DemoDocument>();
  readonly #invitations = new Map<string, DemoInvitation>();
  readonly #testObjects = new Map<string, DemoTestObject>();
  readonly #policyVersions: DemoPolicyVersion[] = [];
  #lastPolicyDrift: DemoPolicyDrift | null = null;
  #revision = 1;

  public constructor(
    private readonly now: () => Date = () => new Date(INITIAL_TIME),
  ) {
    const policy = makePolicyVersion(1, INITIAL_RULES, INITIAL_TIME);
    this.#policyVersions.push(policy);
    this.#projects.set(
      "project-demo-001",
      Object.freeze({
        projectRef: "project-demo-001",
        organizationRef: SEEDED_ORGANIZATION.organizationRef,
        displayName: "Deterministic Demo Project",
        createdByRef: "identity-owner-001",
        createdAt: INITIAL_TIME,
      }),
    );
    this.#documents.set(
      "document-demo-001",
      Object.freeze({
        documentRef: "document-demo-001",
        projectRef: "project-demo-001",
        title: "Simulation Notes",
        classification: "internal",
        createdByRef: "identity-member-001",
        createdAt: INITIAL_TIME,
      }),
    );
    this.#invitations.set(
      "invitation-demo-001",
      Object.freeze({
        invitationRef: "invitation-demo-001",
        organizationRef: SEEDED_ORGANIZATION.organizationRef,
        inviteeRef: "fixture-invitee-001",
        role: "External",
        status: "pending",
        createdByRef: "identity-owner-001",
        createdAt: INITIAL_TIME,
      }),
    );
    this.#testObjects.set(
      "object-demo-001",
      Object.freeze({
        objectRef: "object-demo-001",
        projectRef: "project-demo-001",
        controlledByRef: "identity-owner-001",
        canary: "canary-demo-001",
        status: "active",
        createdAt: INITIAL_TIME,
      }),
    );
  }

  public snapshot(): DemoSaasSnapshot {
    return Object.freeze({
      mode: "simulation",
      externalIntegrationsEnabled: false,
      revision: this.#revision,
      organization: SEEDED_ORGANIZATION,
      projects: frozenSorted(this.#projects),
      documents: frozenSorted(this.#documents),
      invitations: frozenSorted(this.#invitations),
      testObjects: frozenSorted(this.#testObjects),
      currentPolicy: this.currentPolicy(),
      policyVersions: Object.freeze([...this.#policyVersions]),
      lastPolicyDrift: this.#lastPolicyDrift,
    });
  }

  public createProject(input: {
    readonly actorRef: string;
    readonly projectRef: string;
    readonly displayName: string;
  }): DemoProject {
    this.assertRole(input.actorRef, new Set(["Owner"]));
    assertRef(input.projectRef);
    assertText(input.displayName);
    assertCapacity(this.#projects);
    assertAbsent(this.#projects, input.projectRef, "DEMO_PROJECT_CONFLICT");
    const project = Object.freeze({
      projectRef: input.projectRef,
      organizationRef: SEEDED_ORGANIZATION.organizationRef,
      displayName: input.displayName,
      createdByRef: input.actorRef,
      createdAt: this.timestamp(),
    });
    this.#projects.set(project.projectRef, project);
    this.#revision += 1;
    return project;
  }

  public createDocument(input: {
    readonly actorRef: string;
    readonly documentRef: string;
    readonly projectRef: string;
    readonly title: string;
    readonly classification: DemoDocument["classification"];
  }): DemoDocument {
    this.assertRole(input.actorRef, new Set(["Member", "Owner"]));
    assertRef(input.documentRef);
    assertRef(input.projectRef);
    assertText(input.title);
    if (!this.#projects.has(input.projectRef))
      throw new SecurityError("DEMO_PROJECT_NOT_FOUND");
    assertCapacity(this.#documents);
    assertAbsent(this.#documents, input.documentRef, "DEMO_DOCUMENT_CONFLICT");
    const document = Object.freeze({
      documentRef: input.documentRef,
      projectRef: input.projectRef,
      title: input.title,
      classification: input.classification,
      createdByRef: input.actorRef,
      createdAt: this.timestamp(),
    });
    this.#documents.set(document.documentRef, document);
    this.#revision += 1;
    return document;
  }

  public createInvitation(input: {
    readonly actorRef: string;
    readonly invitationRef: string;
    readonly inviteeRef: string;
    readonly role: DemoInvitation["role"];
  }): DemoInvitation {
    this.assertRole(input.actorRef, new Set(["Owner"]));
    assertRef(input.invitationRef);
    assertRef(input.inviteeRef);
    assertCapacity(this.#invitations);
    assertAbsent(
      this.#invitations,
      input.invitationRef,
      "DEMO_INVITATION_CONFLICT",
    );
    const invitation = Object.freeze({
      invitationRef: input.invitationRef,
      organizationRef: SEEDED_ORGANIZATION.organizationRef,
      inviteeRef: input.inviteeRef,
      role: input.role,
      status: "pending" as const,
      createdByRef: input.actorRef,
      createdAt: this.timestamp(),
    });
    this.#invitations.set(invitation.invitationRef, invitation);
    this.#revision += 1;
    return invitation;
  }

  public createTestObject(input: {
    readonly actorRef: string;
    readonly objectRef: string;
    readonly projectRef: string;
    readonly canary: string;
  }): DemoTestObject {
    this.assertRole(input.actorRef, new Set(["Member", "Owner"]));
    assertRef(input.objectRef);
    assertRef(input.projectRef);
    if (!SAFE_CANARY.test(input.canary))
      throw new SecurityError("DEMO_CANARY_INVALID");
    if (!this.#projects.has(input.projectRef))
      throw new SecurityError("DEMO_PROJECT_NOT_FOUND");
    if (
      [...this.#testObjects.values()].some(
        (existing) => existing.canary === input.canary,
      )
    )
      throw new SecurityError("DEMO_CANARY_CONFLICT");
    assertCapacity(this.#testObjects);
    assertAbsent(this.#testObjects, input.objectRef, "DEMO_OBJECT_CONFLICT");
    const object = Object.freeze({
      objectRef: input.objectRef,
      projectRef: input.projectRef,
      controlledByRef: input.actorRef,
      canary: input.canary,
      status: "active" as const,
      createdAt: this.timestamp(),
    });
    this.#testObjects.set(object.objectRef, object);
    this.#revision += 1;
    return object;
  }

  public simulatePolicyDrift(input: {
    readonly expectedPolicyHash: string;
    readonly rules: DemoPolicyRules;
  }): DemoPolicyDrift {
    const current = this.currentPolicy();
    if (input.expectedPolicyHash !== current.contentHash)
      throw new SecurityError("DEMO_POLICY_REVISION_CONFLICT");
    const rules = normalizeRules(input.rules);
    const nextHash = hashRules(rules);
    if (nextHash === current.contentHash)
      throw new SecurityError("DEMO_POLICY_UNCHANGED");
    const next = makePolicyVersion(
      current.version + 1,
      rules,
      this.timestamp(),
    );
    const changedFields = changedPolicyFields(current.rules, next.rules);
    const drift = Object.freeze({
      previousVersion: current.version,
      previousHash: current.contentHash,
      nextVersion: next.version,
      nextHash: next.contentHash,
      changedFields,
      detectedAt: next.effectiveAt,
    });
    this.#policyVersions.push(next);
    this.#lastPolicyDrift = drift;
    this.#revision += 1;
    return drift;
  }

  private currentPolicy(): DemoPolicyVersion {
    const policy = this.#policyVersions.at(-1);
    if (policy === undefined) throw new SecurityError("DEMO_POLICY_MISSING");
    return policy;
  }

  private assertRole(
    actorRef: string,
    allowedRoles: ReadonlySet<DemoRole>,
  ): void {
    const identity = SEEDED_IDENTITIES.find(
      (candidate) => candidate.identityRef === actorRef,
    );
    if (identity === undefined)
      throw new SecurityError("DEMO_IDENTITY_NOT_FOUND");
    if (!allowedRoles.has(identity.role))
      throw new SecurityError("DEMO_ROLE_BLOCKED");
  }

  private timestamp(): string {
    const value = this.now();
    if (!Number.isFinite(value.getTime()))
      throw new SecurityError("DEMO_CLOCK_INVALID");
    return value.toISOString();
  }
}

function makePolicyVersion(
  version: number,
  rawRules: DemoPolicyRules,
  effectiveAt: string,
): DemoPolicyVersion {
  const rules = normalizeRules(rawRules);
  return Object.freeze({
    version,
    contentHash: hashRules(rules),
    effectiveAt,
    rules,
  });
}

function normalizeRules(rawRules: DemoPolicyRules): DemoPolicyRules {
  if (
    !Number.isInteger(rawRules.requestLimit) ||
    rawRules.requestLimit < 1 ||
    rawRules.requestLimit > 1_000
  )
    throw new SecurityError("DEMO_POLICY_REQUEST_LIMIT_INVALID");
  const allowedActions = normalizeRuleList(rawRules.allowedActions);
  const prohibitedTestClasses = normalizeRuleList(
    rawRules.prohibitedTestClasses,
  );
  return Object.freeze({
    requestLimit: rawRules.requestLimit,
    allowedActions,
    prohibitedTestClasses,
  });
}

function normalizeRuleList(values: readonly string[]): readonly string[] {
  if (values.length > 100 || values.some((value) => !SAFE_RULE.test(value)))
    throw new SecurityError("DEMO_POLICY_RULE_INVALID");
  const normalized = [...new Set(values)].sort(compareText);
  if (normalized.length !== values.length)
    throw new SecurityError("DEMO_POLICY_RULE_DUPLICATE");
  return Object.freeze(normalized);
}

function hashRules(rules: DemoPolicyRules): string {
  return sha256(canonicalJson(rules));
}

function changedPolicyFields(
  previous: DemoPolicyRules,
  next: DemoPolicyRules,
): readonly DemoPolicyChangedField[] {
  const fields: DemoPolicyChangedField[] = [];
  if (previous.requestLimit !== next.requestLimit) fields.push("requestLimit");
  if (
    canonicalJson(previous.allowedActions) !==
    canonicalJson(next.allowedActions)
  )
    fields.push("allowedActions");
  if (
    canonicalJson(previous.prohibitedTestClasses) !==
    canonicalJson(next.prohibitedTestClasses)
  )
    fields.push("prohibitedTestClasses");
  return Object.freeze(fields);
}

function frozenSorted<T>(values: ReadonlyMap<string, T>): readonly T[] {
  return Object.freeze(
    [...values.entries()]
      .sort(([left], [right]) => compareText(left, right))
      .map(([, value]) => value),
  );
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertRef(value: string): void {
  if (!SAFE_REF.test(value)) throw new SecurityError("DEMO_REFERENCE_INVALID");
}

function assertText(value: string): void {
  if (!SAFE_TEXT.test(value)) throw new SecurityError("DEMO_TEXT_INVALID");
}

function assertCapacity(values: ReadonlyMap<string, unknown>): void {
  if (values.size >= MAX_RECORDS_PER_KIND)
    throw new SecurityError("DEMO_CAPACITY_EXCEEDED");
}

function assertAbsent(
  values: ReadonlyMap<string, unknown>,
  reference: string,
  reason: string,
): void {
  if (values.has(reference)) throw new SecurityError(reason);
}
