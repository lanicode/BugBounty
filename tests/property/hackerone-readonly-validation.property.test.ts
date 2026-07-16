import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  validateProgramDocument,
  validateProgramPage,
} from "../../packages/hackerone-readonly/validation.js";

const SYNCHRONIZED_AT = "2026-07-14T12:00:00.000Z";

function extensions(values: readonly unknown[]): Record<string, unknown> {
  return Object.fromEntries(
    values.map((value, index) => [`extension_${index}`, value]),
  );
}

function programResource(): Record<string, unknown> {
  return {
    id: "synthetic-property-program",
    type: "program",
    attributes: {
      handle: "synthetic_property_program",
      name: "Synthetic Property Program",
      currency: "USD",
      policy: "Synthetic local-only policy.",
      submission_state: "open",
      state: "public_mode",
      offers_bounties: true,
      open_scope: false,
      gold_standard_safe_harbor: true,
      bookmarked: false,
      number_of_reports_for_user: 0,
      number_of_valid_reports_for_user: 0,
      started_accepting_at: null,
      created_at: null,
      updated_at: null,
    },
  };
}

describe("HackerOne response extension projection properties", () => {
  it("canonicalizes every positive safe-integer program ID exactly", () => {
    fc.assert(
      fc.property(
        fc.maxSafeNat().filter((id) => id > 0),
        (id) => {
          const resource = programResource();
          const normalized = validateProgramDocument(
            { data: { ...resource, id } },
            SYNCHRONIZED_AT,
          );
          expect(normalized.hackerOneId).toBe(String(id));
        },
      ),
      { numRuns: 200 },
    );
  });

  it("discards arbitrary bounded JSON extensions while preserving the trusted projection", () => {
    const baseline = validateProgramPage(
      {
        data: [programResource()],
        links: { next: null },
        meta: { current_page: 1, total_count: 1, total_pages: 1 },
      },
      SYNCHRONIZED_AT,
    );

    fc.assert(
      fc.property(
        fc.record({
          top: fc.array(fc.jsonValue(), { maxLength: 10 }),
          resource: fc.array(fc.jsonValue(), { maxLength: 10 }),
          attributes: fc.array(fc.jsonValue(), { maxLength: 10 }),
          links: fc.array(fc.jsonValue(), { maxLength: 10 }),
          meta: fc.array(fc.jsonValue(), { maxLength: 10 }),
        }),
        (generated) => {
          const resource = programResource();
          const projected = validateProgramPage(
            {
              data: [
                {
                  ...resource,
                  ...extensions(generated.resource),
                  attributes: {
                    ...(resource["attributes"] as Record<string, unknown>),
                    ...extensions(generated.attributes),
                  },
                },
              ],
              links: { next: null, ...extensions(generated.links) },
              meta: {
                current_page: 1,
                total_count: 1,
                total_pages: 1,
                ...extensions(generated.meta),
              },
              ...extensions(generated.top),
            },
            SYNCHRONIZED_AT,
          );

          expect(projected).toEqual(baseline);
          expect(JSON.stringify(projected)).not.toContain("extension_");
        },
      ),
      { numRuns: 200 },
    );
  });
});
