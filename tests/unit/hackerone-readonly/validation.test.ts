import { describe, expect, it } from "vitest";
import { sha256 } from "../../../packages/shared/canonical.js";
import {
  validateProgramDocument,
  validateProgramPage,
  validateScopeExclusionPage,
  validateStructuredScopePage,
} from "../../../packages/hackerone-readonly/validation.js";

const SYNCHRONIZED_AT = "2026-07-14T12:00:00.000Z";

function programResource(): Record<string, unknown> {
  return {
    id: "synthetic-program-001",
    type: "program",
    attributes: {
      handle: "synthetic_program",
      name: " Synthetic Program ",
      currency: "USD",
      policy: "Synthetic local policy text.",
      submission_state: "open",
      state: "public_mode",
      offers_bounties: true,
      open_scope: false,
      gold_standard_safe_harbor: true,
      bookmarked: false,
      number_of_reports_for_user: 3,
      number_of_valid_reports_for_user: 2,
      started_accepting_at: "2026-01-02T03:04:05+00:00",
      created_at: null,
      updated_at: "2026-07-01T09:30:00Z",
    },
  };
}

function programPage(): Record<string, unknown> {
  return {
    data: [programResource()],
    links: {
      first:
        "https://api.hackerone.com/v1/hackers/programs?page[number]=1&page[size]=1",
      last: null,
      next: "https://api.hackerone.com/v1/hackers/programs?page[number]=2&page[size]=1",
      prev: null,
      self: "https://api.hackerone.com/v1/hackers/programs?page[number]=1&page[size]=1",
    },
    meta: { current_page: 1, total_count: 2, total_pages: 2 },
  };
}

function scopeResource(): Record<string, unknown> {
  return {
    id: "synthetic-scope-001",
    type: "structured-scope",
    attributes: {
      asset_type: "URL",
      asset_identifier: "https://synthetic-asset.invalid/path",
      eligible_for_submission: true,
      eligible_for_bounty: false,
      instruction: null,
      max_severity: "high",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: null,
      confidentiality_requirement: "high",
      integrity_requirement: null,
      availability_requirement: "low",
    },
  };
}

function exclusionResource(): Record<string, unknown> {
  return {
    id: "synthetic-exclusion-001",
    type: "scope-exclusion",
    attributes: {
      category: "Synthetic excluded class",
      details: "Never request this synthetic metadata identifier.",
      created_at: null,
      updated_at: "2026-06-30T10:00:00Z",
    },
  };
}

describe("HackerOne program response validation", () => {
  it("strictly normalizes and freezes a synthetic program page", () => {
    const page = validateProgramPage(programPage(), SYNCHRONIZED_AT);

    expect(page.next).toBe(
      "https://api.hackerone.com/v1/hackers/programs?page[number]=2&page[size]=1",
    );
    expect(page.records).toHaveLength(1);
    expect(page.records[0]).toEqual({
      hackerOneId: "synthetic-program-001",
      handle: "synthetic_program",
      name: "Synthetic Program",
      currency: "USD",
      policy: "Synthetic local policy text.",
      submissionState: "open",
      programState: "public_mode",
      offersBounties: true,
      openScope: false,
      goldStandardSafeHarbor: true,
      bookmarked: false,
      ownReportCount: 3,
      ownValidReportCount: 2,
      startedAcceptingAt: "2026-01-02T03:04:05.000Z",
      createdAt: null,
      updatedAt: "2026-07-01T09:30:00.000Z",
      synchronizedAt: SYNCHRONIZED_AT,
      source: "hackerone_api_authenticated",
    });
    expect(Object.isFrozen(page)).toBe(true);
    expect(Object.isFrozen(page.records)).toBe(true);
    expect(Object.isFrozen(page.records[0])).toBe(true);
  });

  it("normalizes a detail document without treating sync as acceptance", () => {
    const program = validateProgramDocument(
      { data: programResource() },
      SYNCHRONIZED_AT,
      "manual_unverified",
    );
    expect(program.source).toBe("manual_unverified");
    expect(program.synchronizedAt).toBe(SYNCHRONIZED_AT);
    expect(program).not.toHaveProperty("accepted");
    expect(program).not.toHaveProperty("acceptance");
    expect(Object.isFrozen(program)).toBe(true);
  });

  it("discards bounded additive API extensions without persisting their values", () => {
    const page = programPage();
    const resource = (page["data"] as Record<string, unknown>[])[0] ?? {};
    const attributes = resource["attributes"] as Record<string, unknown>;
    const value = {
      ...page,
      extension_top: { canary: "TOP_EXTENSION_CANARY" },
      data: [
        {
          ...resource,
          extension_resource: "RESOURCE_EXTENSION_CANARY",
          attributes: {
            ...attributes,
            extension_attribute: "ATTRIBUTE_EXTENSION_CANARY",
          },
        },
      ],
      links: {
        ...(page["links"] as Record<string, unknown>),
        extension_link: "LINK_EXTENSION_CANARY",
      },
      meta: {
        ...(page["meta"] as Record<string, unknown>),
        extension_meta: "META_EXTENSION_CANARY",
      },
    };

    const normalized = validateProgramPage(value, SYNCHRONIZED_AT);

    expect(normalized).toEqual(
      validateProgramPage(programPage(), SYNCHRONIZED_AT),
    );
    expect(JSON.stringify(normalized)).not.toContain("EXTENSION_CANARY");
  });

  it("rejects hostile response objects without invoking accessors", () => {
    let getterInvocations = 0;
    const accessorPage = Object.defineProperty({}, "data", {
      enumerable: true,
      get: () => {
        getterInvocations += 1;
        return [];
      },
    });

    expect(() => validateProgramPage(accessorPage, SYNCHRONIZED_AT)).toThrow(
      "HACKERONE_RESPONSE_SCHEMA_INVALID",
    );
    expect(getterInvocations).toBe(0);
    expect(() =>
      validateProgramPage(new Proxy({ data: [] }, {}), SYNCHRONIZED_AT),
    ).toThrow("HACKERONE_RESPONSE_SCHEMA_INVALID");

    const unsafeName = { data: [] };
    Object.defineProperty(unsafeName, "constructor", {
      enumerable: true,
      value: "synthetic",
    });
    expect(() => validateProgramPage(unsafeName, SYNCHRONIZED_AT)).toThrow(
      "HACKERONE_RESPONSE_SCHEMA_INVALID",
    );

    const oversized: Record<string, unknown> = { data: [] };
    for (let index = 0; index < 128; index += 1)
      oversized[`extension_${index}`] = index;
    expect(() => validateProgramPage(oversized, SYNCHRONIZED_AT)).toThrow(
      "HACKERONE_RESPONSE_SCHEMA_INVALID",
    );
  });

  it.each([
    [
      "missing required attribute",
      () => {
        const resource = programResource();
        const attributes = {
          ...(resource["attributes"] as Record<string, unknown>),
        };
        delete attributes["handle"];
        return { data: [{ ...resource, attributes }] };
      },
    ],
    [
      "invalid handle",
      () => {
        const resource = programResource();
        return {
          data: [
            {
              ...resource,
              attributes: {
                ...(resource["attributes"] as Record<string, unknown>),
                handle: "../synthetic/path",
              },
            },
          ],
        };
      },
    ],
    [
      "wrong boolean type",
      () => {
        const resource = programResource();
        return {
          data: [
            {
              ...resource,
              attributes: {
                ...(resource["attributes"] as Record<string, unknown>),
                offers_bounties: "true",
              },
            },
          ],
        };
      },
    ],
    [
      "invalid timestamp",
      () => {
        const resource = programResource();
        return {
          data: [
            {
              ...resource,
              attributes: {
                ...(resource["attributes"] as Record<string, unknown>),
                updated_at: "not-a-timestamp",
              },
            },
          ],
        };
      },
    ],
    [
      "more than one hundred records",
      () => ({ data: Array.from({ length: 101 }, programResource) }),
    ],
  ])("rejects %s fail closed", (_label, makeValue) => {
    expect(() => validateProgramPage(makeValue(), SYNCHRONIZED_AT)).toThrow(
      "HACKERONE_RESPONSE_SCHEMA_INVALID",
    );
  });

  it("rejects an invalid local synchronization timestamp", () => {
    expect(() =>
      validateProgramPage({ data: [programResource()] }, "not-a-timestamp"),
    ).toThrow("HACKERONE_RESPONSE_SCHEMA_INVALID");
  });

  it("accepts an empty page and canonicalizes a missing next link to null", () => {
    expect(validateProgramPage({ data: [] }, SYNCHRONIZED_AT)).toEqual({
      records: [],
      next: null,
    });
    expect(
      validateProgramPage({ data: [], links: { next: null } }, SYNCHRONIZED_AT)
        .next,
    ).toBeNull();
  });
});

describe("HackerOne structured-scope response validation", () => {
  it("keeps an asset identifier as bounded metadata and derives only its digest", () => {
    const page = validateStructuredScopePage({
      data: [scopeResource()],
      links: { next: null },
      meta: { current_page: 1, total_count: 1, total_pages: 1 },
    });

    expect(page.next).toBeNull();
    expect(page.records).toEqual([
      {
        id: "synthetic-scope-001",
        assetType: "URL",
        assetIdentifier: "https://synthetic-asset.invalid/path",
        assetIdentifierDigest: sha256("https://synthetic-asset.invalid/path"),
        eligibleForSubmission: true,
        eligibleForBounty: false,
        instruction: "",
        maximumSeverity: "high",
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: null,
        confidentialityRequirement: "high",
        integrityRequirement: null,
        availabilityRequirement: "low",
      },
    ]);
    expect(Object.isFrozen(page.records[0])).toBe(true);
  });

  it("accepts only the two explicit structured-scope type spellings", () => {
    const underscore = {
      ...scopeResource(),
      type: "structured_scope",
    };
    expect(
      validateStructuredScopePage({ data: [underscore] }).records,
    ).toHaveLength(1);
    expect(() =>
      validateStructuredScopePage({
        data: [{ ...scopeResource(), type: "scope" }],
      }),
    ).toThrow("HACKERONE_RESPONSE_SCHEMA_INVALID");
  });

  it("discards bounded scope extensions before normalization", () => {
    const resource = scopeResource();
    const page = validateStructuredScopePage({
      data: [
        {
          ...resource,
          extension_resource: "SCOPE_RESOURCE_CANARY",
          attributes: {
            ...(resource["attributes"] as Record<string, unknown>),
            extension_attribute: "SCOPE_ATTRIBUTE_CANARY",
          },
        },
      ],
      extension_top: "SCOPE_TOP_CANARY",
    });

    expect(page).toEqual(
      validateStructuredScopePage({ data: [scopeResource()] }),
    );
    expect(JSON.stringify(page)).not.toContain("CANARY");
  });

  it.each([
    [
      "a missing asset identifier",
      () => {
        const resource = scopeResource();
        const attributes = {
          ...(resource["attributes"] as Record<string, unknown>),
        };
        delete attributes["asset_identifier"];
        return { data: [{ ...resource, attributes }] };
      },
    ],
    [
      "an empty asset identifier",
      () => {
        const resource = scopeResource();
        return {
          data: [
            {
              ...resource,
              attributes: {
                ...(resource["attributes"] as Record<string, unknown>),
                asset_identifier: "",
              },
            },
          ],
        };
      },
    ],
    [
      "an invalid eligibility type",
      () => {
        const resource = scopeResource();
        return {
          data: [
            {
              ...resource,
              attributes: {
                ...(resource["attributes"] as Record<string, unknown>),
                eligible_for_submission: 1,
              },
            },
          ],
        };
      },
    ],
    [
      "more than one hundred scopes",
      () => ({ data: Array.from({ length: 101 }, scopeResource) }),
    ],
  ])("rejects %s", (_label, makeValue) => {
    expect(() => validateStructuredScopePage(makeValue())).toThrow(
      "HACKERONE_RESPONSE_SCHEMA_INVALID",
    );
  });
});

describe("HackerOne scope-exclusion response validation", () => {
  it("normalizes and freezes strict synthetic exclusions", () => {
    const page = validateScopeExclusionPage({
      data: [exclusionResource()],
      links: { next: null },
    });
    expect(page).toEqual({
      records: [
        {
          id: "synthetic-exclusion-001",
          category: "Synthetic excluded class",
          details: "Never request this synthetic metadata identifier.",
          createdAt: null,
          updatedAt: "2026-06-30T10:00:00.000Z",
        },
      ],
      next: null,
    });
    expect(Object.isFrozen(page)).toBe(true);
    expect(Object.isFrozen(page.records)).toBe(true);
    expect(Object.isFrozen(page.records[0])).toBe(true);
  });

  it("accepts only explicit exclusion types and rejects schema drift", () => {
    expect(
      validateScopeExclusionPage({
        data: [{ ...exclusionResource(), type: "scope_exclusion" }],
      }).records,
    ).toHaveLength(1);
    expect(() =>
      validateScopeExclusionPage({
        data: [{ ...exclusionResource(), type: "exclusion" }],
      }),
    ).toThrow("HACKERONE_RESPONSE_SCHEMA_INVALID");
  });

  it("discards bounded exclusion extensions before normalization", () => {
    const resource = exclusionResource();
    const page = validateScopeExclusionPage({
      data: [
        {
          ...resource,
          extension_resource: "EXCLUSION_RESOURCE_CANARY",
          attributes: {
            ...(resource["attributes"] as Record<string, unknown>),
            extension_attribute: "EXCLUSION_ATTRIBUTE_CANARY",
          },
        },
      ],
      extension_top: "EXCLUSION_TOP_CANARY",
    });

    expect(page).toEqual(
      validateScopeExclusionPage({ data: [exclusionResource()] }),
    );
    expect(JSON.stringify(page)).not.toContain("CANARY");
  });

  it("rejects missing fields, invalid dates, and oversized pages", () => {
    const resource = exclusionResource();
    const missingCategory = {
      ...(resource["attributes"] as Record<string, unknown>),
    };
    delete missingCategory["category"];
    expect(() =>
      validateScopeExclusionPage({
        data: [{ ...resource, attributes: missingCategory }],
      }),
    ).toThrow("HACKERONE_RESPONSE_SCHEMA_INVALID");

    expect(() =>
      validateScopeExclusionPage({
        data: [
          {
            ...resource,
            attributes: {
              ...(resource["attributes"] as Record<string, unknown>),
              updated_at: "invalid-date",
            },
          },
        ],
      }),
    ).toThrow("HACKERONE_RESPONSE_SCHEMA_INVALID");

    expect(() =>
      validateScopeExclusionPage({
        data: Array.from({ length: 101 }, exclusionResource),
      }),
    ).toThrow("HACKERONE_RESPONSE_SCHEMA_INVALID");
  });
});
