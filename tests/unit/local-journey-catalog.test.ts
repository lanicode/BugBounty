import { describe, expect, it } from "vitest";
import {
  JOURNEY_ROLES,
  LOCAL_JOURNEY_CATALOG,
  LOCAL_JOURNEY_CATALOG_DIGEST_SHA256,
  LOCAL_JOURNEY_CATALOG_ID,
  LOCAL_JOURNEY_REPLAY_PROFILES,
  LOCAL_JOURNEY_ROLE_PLANS,
  journeyCapabilitiesFor,
  journeyCatalog,
  journeyPlanFor,
} from "../../packages/local-journey-catalog/index.js";
import { canonicalJson, sha256 } from "../../packages/shared/canonical.js";
import {
  JOURNEY_ROLES as HARNESS_ROLES,
  LOCAL_JOURNEY_CATALOG_ID as HARNESS_CATALOG_ID,
  capabilitiesFor as harnessCapabilitiesFor,
  journeyPlan as harnessJourneyPlan,
} from "../browser/support/journey-model.js";

const PINNED_CATALOG_DIGEST =
  "f93fda8ba5203f1de6c7c4e2983c78c62d0767597a837d530324e6dc740673e5";

function expectDeepFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const nested of Object.values(value)) expectDeepFrozen(nested, seen);
}

describe("local Phase-7 journey catalog", () => {
  it("publishes the fixed catalog ID, roles, plans and capabilities deeply frozen", () => {
    expect(LOCAL_JOURNEY_CATALOG_ID).toBe("phase7-local-demo-role-boundary");
    expect(LOCAL_JOURNEY_CATALOG).toMatchObject({
      version: 1,
      id: LOCAL_JOURNEY_CATALOG_ID,
      roles: ["Owner", "Member", "External"],
    });
    expectDeepFrozen(LOCAL_JOURNEY_CATALOG);
    expect(LOCAL_JOURNEY_CATALOG.rolePlans).toBe(LOCAL_JOURNEY_ROLE_PLANS);
    expect(LOCAL_JOURNEY_CATALOG.replayProfiles).toBe(
      LOCAL_JOURNEY_REPLAY_PROFILES,
    );

    for (const role of JOURNEY_ROLES) {
      const plan = journeyPlanFor(LOCAL_JOURNEY_CATALOG_ID, role);
      const profile = journeyCapabilitiesFor(LOCAL_JOURNEY_CATALOG_ID, role);
      expect(plan).toBe(LOCAL_JOURNEY_CATALOG.rolePlans[role]);
      expect(profile).toBe(LOCAL_JOURNEY_CATALOG.replayProfiles[role]);
      expect(profile.capabilities).toEqual(
        plan.map(({ capability }) => capability),
      );
      expect(plan.map(({ method }) => method)).toEqual(plan.map(() => "GET"));
    }
  });

  it("pins a deterministic digest over the complete catalog document", () => {
    const recomputed = sha256(
      canonicalJson({
        version: LOCAL_JOURNEY_CATALOG.version,
        id: LOCAL_JOURNEY_CATALOG.id,
        roles: LOCAL_JOURNEY_CATALOG.roles,
        rolePlans: LOCAL_JOURNEY_CATALOG.rolePlans,
        replayProfiles: LOCAL_JOURNEY_CATALOG.replayProfiles,
      }),
    );
    expect(LOCAL_JOURNEY_CATALOG_DIGEST_SHA256).toBe(PINNED_CATALOG_DIGEST);
    expect(LOCAL_JOURNEY_CATALOG.digestSha256).toBe(PINNED_CATALOG_DIGEST);
    expect(recomputed).toBe(PINNED_CATALOG_DIGEST);
    expect(journeyCatalog(LOCAL_JOURNEY_CATALOG_ID)).toBe(
      LOCAL_JOURNEY_CATALOG,
    );
  });

  it("fails closed for every unknown catalog ID or role", () => {
    for (const invalidId of [
      undefined,
      null,
      "",
      "phase7-local-demo-role-boundary-v2",
      { id: LOCAL_JOURNEY_CATALOG_ID },
    ]) {
      expect(() => journeyCatalog(invalidId)).toThrow(
        "LOCAL_JOURNEY_CATALOG_ID_INVALID",
      );
      expect(() => journeyPlanFor(invalidId, "Owner")).toThrow(
        "LOCAL_JOURNEY_CATALOG_ID_INVALID",
      );
    }

    for (const invalidRole of [undefined, null, "", "Admin", 1, {}]) {
      expect(() =>
        journeyPlanFor(LOCAL_JOURNEY_CATALOG_ID, invalidRole),
      ).toThrow("LOCAL_JOURNEY_ROLE_INVALID");
      expect(() =>
        journeyCapabilitiesFor(LOCAL_JOURNEY_CATALOG_ID, invalidRole),
      ).toThrow("LOCAL_JOURNEY_ROLE_INVALID");
    }
  });

  it("keeps the Phase-7 harness bound to the exact production-neutral catalog objects", () => {
    expect(HARNESS_CATALOG_ID).toBe(LOCAL_JOURNEY_CATALOG_ID);
    expect(HARNESS_ROLES).toBe(JOURNEY_ROLES);
    for (const role of JOURNEY_ROLES) {
      expect(harnessJourneyPlan(role)).toBe(
        journeyPlanFor(LOCAL_JOURNEY_CATALOG_ID, role),
      );
      expect(harnessCapabilitiesFor(role)).toBe(
        journeyCapabilitiesFor(LOCAL_JOURNEY_CATALOG_ID, role),
      );
    }
  });
});
