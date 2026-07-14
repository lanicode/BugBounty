import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  createInitialHackerOneMetadataRequestPlan,
  createNextHackerOneMetadataRequestPlan,
  isStrongHackerOneProgramHandle,
} from "../../packages/hackerone-readonly/request-policy.js";
import {
  HACKERONE_METADATA_READ_CAPABILITY,
  resolveHackerOneMetadataReadRuntime,
} from "../../packages/hackerone-readonly/runtime.js";

function runtime() {
  return resolveHackerOneMetadataReadRuntime({
    version: 1,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    external_integrations_enabled: true,
    enabled: true,
    request_budget: {
      max_requests_total: 1_000,
      requests_per_minute: 100,
      max_concurrency: 1,
    },
  });
}

const budget = Object.freeze({
  consumedRequests: 0,
  activeRequests: 0,
  requestsInCurrentMinute: 0,
});

function programsIntent(size: number): Record<string, unknown> {
  return {
    version: 1,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    operation: "programs",
    handle: null,
    page: { number: 1, size },
  };
}

describe("HackerOne request-policy properties", () => {
  it("canonicalizes every allowed page size and rejects every nearby invalid size", () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 100 }), (size) => {
        const plan = createInitialHackerOneMetadataRequestPlan(
          programsIntent(size),
          runtime(),
          budget,
        );
        expect(plan.query).toBe(`?page[number]=1&page[size]=${String(size)}`);
      }),
    );
    fc.assert(
      fc.property(
        fc.oneof(
          fc.integer({ min: -10_000, max: 0 }),
          fc.integer({ min: 101, max: 10_000 }),
        ),
        (size) => {
          expect(() =>
            createInitialHackerOneMetadataRequestPlan(
              programsIntent(size),
              runtime(),
              budget,
            ),
          ).toThrow("HACKERONE_PAGE_INVALID");
        },
      ),
    );
  });

  it("never places a non-strong handle into a request path", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 140 }), (handle) => {
        if (isStrongHackerOneProgramHandle(handle)) return;
        expect(() =>
          createInitialHackerOneMetadataRequestPlan(
            {
              version: 1,
              capability: HACKERONE_METADATA_READ_CAPABILITY,
              operation: "program",
              handle,
              page: null,
            },
            runtime(),
            budget,
          ),
        ).toThrow("HACKERONE_HANDLE_INVALID");
      }),
    );
  });

  it("advances canonical pagination by exactly one for arbitrary bounded runs", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 100 }),
        fc.integer({ min: 1, max: 25 }),
        (size, continuations) => {
          let plan = createInitialHackerOneMetadataRequestPlan(
            programsIntent(size),
            runtime(),
            budget,
          );
          for (let page = 2; page <= continuations + 1; page += 1) {
            const next = createNextHackerOneMetadataRequestPlan(
              plan,
              `https://api.hackerone.com/v1/hackers/programs?page[number]=${String(page)}&page[size]=${String(size)}`,
              runtime(),
              budget,
            );
            expect(next).not.toBeNull();
            if (next === null) throw new Error("PROPERTY_NEXT_MISSING");
            expect(next.page?.number).toBe(page);
            plan = next;
          }
        },
      ),
    );
  });

  it("rejects any additional query key on an otherwise valid next link", () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-z]{1,16}$/u),
        fc.stringMatching(/^[a-z0-9]{1,16}$/u),
        (key, value) => {
          const first = createInitialHackerOneMetadataRequestPlan(
            programsIntent(10),
            runtime(),
            budget,
          );
          expect(() =>
            createNextHackerOneMetadataRequestPlan(
              first,
              `https://api.hackerone.com/v1/hackers/programs?page[number]=2&page[size]=10&${key}=${value}`,
              runtime(),
              budget,
            ),
          ).toThrow("HACKERONE_PAGINATION_BLOCKED");
        },
      ),
    );
  });

  it("keeps malformed runtime budgets fail closed", () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.integer({ min: -10_000, max: 0 }),
          fc.integer({ min: 10_001, max: 100_000 }),
          fc
            .double({ noNaN: true, noDefaultInfinity: true })
            .filter((value) => !Number.isSafeInteger(value)),
        ),
        (maximum) => {
          const state = resolveHackerOneMetadataReadRuntime({
            version: 1,
            capability: HACKERONE_METADATA_READ_CAPABILITY,
            external_integrations_enabled: true,
            enabled: true,
            request_budget: {
              max_requests_total: maximum,
              requests_per_minute: 10,
              max_concurrency: 1,
            },
          });
          expect(state.enabled).toBe(false);
          expect(state.externalIntegrationsEnabled).toBe(false);
          expect(state.requestBudget.maxRequestsTotal).toBe(0);
        },
      ),
    );
  });
});
