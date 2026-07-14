import { canonicalJson, sha256 } from "../shared/canonical.js";

export const LOCAL_JOURNEY_CATALOG_ID =
  "phase7-local-demo-role-boundary" as const;

export const JOURNEY_ROLES = Object.freeze([
  "Owner",
  "Member",
  "External",
] as const);

export type LocalJourneyCatalogId = typeof LOCAL_JOURNEY_CATALOG_ID;
export type JourneyRole = (typeof JOURNEY_ROLES)[number];
export type JourneyState = "ready" | "running" | "completed" | "blocked";

export type JourneyPath =
  | "/"
  | "/api/v1/documents"
  | "/api/v1/invitations"
  | "/api/v1/organization"
  | "/api/v1/policy"
  | "/api/v1/projects"
  | "/api/v1/state"
  | "/api/v1/test-objects";

export type JourneyCapability =
  | "documents.read"
  | "invitations.read"
  | "organization.read"
  | "policy.read"
  | "projects.read"
  | "service.read"
  | "state.read"
  | "test_objects.read";

export interface JourneyStep {
  readonly index: number;
  readonly method: "GET";
  readonly path: JourneyPath;
  readonly capability: JourneyCapability;
  readonly fromState: "ready" | "running";
  readonly successState: "running" | "completed";
}

export interface JourneyReplayProfile {
  readonly role: JourneyRole;
  readonly purpose: "deterministic_local_replay_only";
  readonly authentication: "not_modeled";
  readonly authorization: "not_an_authorization_decision";
  readonly capabilities: readonly JourneyCapability[];
}

export interface LocalJourneyCatalog {
  readonly version: 1;
  readonly id: LocalJourneyCatalogId;
  readonly roles: typeof JOURNEY_ROLES;
  readonly rolePlans: Readonly<Record<JourneyRole, readonly JourneyStep[]>>;
  readonly replayProfiles: Readonly<Record<JourneyRole, JourneyReplayProfile>>;
  readonly digestSha256: string;
}

const PATH_CAPABILITIES: Readonly<Record<JourneyPath, JourneyCapability>> =
  Object.freeze({
    "/": "service.read",
    "/api/v1/documents": "documents.read",
    "/api/v1/invitations": "invitations.read",
    "/api/v1/organization": "organization.read",
    "/api/v1/policy": "policy.read",
    "/api/v1/projects": "projects.read",
    "/api/v1/state": "state.read",
    "/api/v1/test-objects": "test_objects.read",
  });

const ROLE_PATHS: Readonly<Record<JourneyRole, readonly JourneyPath[]>> =
  Object.freeze({
    Owner: Object.freeze([
      "/",
      "/api/v1/organization",
      "/api/v1/projects",
      "/api/v1/documents",
      "/api/v1/invitations",
      "/api/v1/test-objects",
      "/api/v1/policy",
      "/api/v1/state",
    ] as const),
    Member: Object.freeze([
      "/",
      "/api/v1/organization",
      "/api/v1/projects",
      "/api/v1/documents",
      "/api/v1/test-objects",
      "/api/v1/policy",
      "/api/v1/state",
    ] as const),
    External: Object.freeze([
      "/",
      "/api/v1/organization",
      "/api/v1/projects",
      "/api/v1/policy",
      "/api/v1/state",
    ] as const),
  });

export const LOCAL_JOURNEY_ROLE_PLANS: Readonly<
  Record<JourneyRole, readonly JourneyStep[]>
> = Object.freeze({
  Owner: makePlan(ROLE_PATHS.Owner),
  Member: makePlan(ROLE_PATHS.Member),
  External: makePlan(ROLE_PATHS.External),
});

export const LOCAL_JOURNEY_REPLAY_PROFILES: Readonly<
  Record<JourneyRole, JourneyReplayProfile>
> = Object.freeze({
  Owner: makeReplayProfile("Owner"),
  Member: makeReplayProfile("Member"),
  External: makeReplayProfile("External"),
});

const CATALOG_DOCUMENT = Object.freeze({
  version: 1 as const,
  id: LOCAL_JOURNEY_CATALOG_ID,
  roles: JOURNEY_ROLES,
  rolePlans: LOCAL_JOURNEY_ROLE_PLANS,
  replayProfiles: LOCAL_JOURNEY_REPLAY_PROFILES,
});

export const LOCAL_JOURNEY_CATALOG_DIGEST_SHA256 = sha256(
  canonicalJson(CATALOG_DOCUMENT),
);

export const LOCAL_JOURNEY_CATALOG: LocalJourneyCatalog = Object.freeze({
  ...CATALOG_DOCUMENT,
  digestSha256: LOCAL_JOURNEY_CATALOG_DIGEST_SHA256,
});

export function journeyCatalog(catalogId: unknown): LocalJourneyCatalog {
  assertCatalogId(catalogId);
  return LOCAL_JOURNEY_CATALOG;
}

export function journeyPlanFor(
  catalogId: unknown,
  role: unknown,
): readonly JourneyStep[] {
  const catalog = journeyCatalog(catalogId);
  assertJourneyRole(role);
  return catalog.rolePlans[role];
}

export function journeyCapabilitiesFor(
  catalogId: unknown,
  role: unknown,
): JourneyReplayProfile {
  const catalog = journeyCatalog(catalogId);
  assertJourneyRole(role);
  return catalog.replayProfiles[role];
}

function makePlan(paths: readonly JourneyPath[]): readonly JourneyStep[] {
  return Object.freeze(
    paths.map((path, index) =>
      Object.freeze({
        index,
        method: "GET" as const,
        path,
        capability: PATH_CAPABILITIES[path],
        fromState: index === 0 ? ("ready" as const) : ("running" as const),
        successState:
          index === paths.length - 1
            ? ("completed" as const)
            : ("running" as const),
      }),
    ),
  );
}

function makeReplayProfile(role: JourneyRole): JourneyReplayProfile {
  return Object.freeze({
    role,
    purpose: "deterministic_local_replay_only",
    authentication: "not_modeled",
    authorization: "not_an_authorization_decision",
    capabilities: Object.freeze(
      LOCAL_JOURNEY_ROLE_PLANS[role].map(({ capability }) => capability),
    ),
  });
}

function assertCatalogId(
  value: unknown,
): asserts value is LocalJourneyCatalogId {
  if (value !== LOCAL_JOURNEY_CATALOG_ID)
    throw new Error("LOCAL_JOURNEY_CATALOG_ID_INVALID");
}

function assertJourneyRole(value: unknown): asserts value is JourneyRole {
  if (!JOURNEY_ROLES.some((role) => role === value))
    throw new Error("LOCAL_JOURNEY_ROLE_INVALID");
}
