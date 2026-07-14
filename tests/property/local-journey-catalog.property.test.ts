import fc from "fast-check";
import { expect, it } from "vitest";
import {
  JOURNEY_ROLES,
  LOCAL_JOURNEY_CATALOG_DIGEST_SHA256,
  LOCAL_JOURNEY_CATALOG_ID,
  journeyCapabilitiesFor,
  journeyCatalog,
  journeyPlanFor,
} from "../../packages/local-journey-catalog/index.js";

it("rejects arbitrary unknown catalog IDs and roles without fallback", () => {
  fc.assert(
    fc.property(
      fc.string().filter((value) => value !== LOCAL_JOURNEY_CATALOG_ID),
      fc
        .string()
        .filter((value) => !JOURNEY_ROLES.some((role) => role === value)),
      (unknownId, unknownRole) => {
        expect(() => journeyCatalog(unknownId)).toThrow(
          "LOCAL_JOURNEY_CATALOG_ID_INVALID",
        );
        expect(() => journeyPlanFor(unknownId, "Owner")).toThrow(
          "LOCAL_JOURNEY_CATALOG_ID_INVALID",
        );
        expect(() =>
          journeyPlanFor(LOCAL_JOURNEY_CATALOG_ID, unknownRole),
        ).toThrow("LOCAL_JOURNEY_ROLE_INVALID");
        expect(() =>
          journeyCapabilitiesFor(LOCAL_JOURNEY_CATALOG_ID, unknownRole),
        ).toThrow("LOCAL_JOURNEY_ROLE_INVALID");
      },
    ),
    { numRuns: 500 },
  );
});

it("returns stable plans, profiles and catalog digest for every fixed role", () => {
  fc.assert(
    fc.property(fc.constantFrom(...JOURNEY_ROLES), (role) => {
      const firstCatalog = journeyCatalog(LOCAL_JOURNEY_CATALOG_ID);
      const secondCatalog = journeyCatalog(LOCAL_JOURNEY_CATALOG_ID);
      expect(secondCatalog).toBe(firstCatalog);
      expect(secondCatalog.digestSha256).toBe(
        LOCAL_JOURNEY_CATALOG_DIGEST_SHA256,
      );
      expect(journeyPlanFor(LOCAL_JOURNEY_CATALOG_ID, role)).toBe(
        firstCatalog.rolePlans[role],
      );
      expect(journeyCapabilitiesFor(LOCAL_JOURNEY_CATALOG_ID, role)).toBe(
        firstCatalog.replayProfiles[role],
      );
    }),
    { numRuns: 100 },
  );
});
