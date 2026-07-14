import { describe, expect, it } from "vitest";
import {
  JOURNEY_ROLES,
  assertLoopbackOrigin,
  capabilitiesFor,
  finalizeJourneyEvidence,
  isAllowedJourneyRequest,
  journeyPlan,
  type JourneyRole,
  type JourneyStepEvidence,
} from "../browser/support/journey-model.js";

const ORIGIN = "http://127.0.0.1:4173";
const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);

const EXPECTED_PATHS: Readonly<Record<JourneyRole, readonly string[]>> = {
  Owner: [
    "/",
    "/api/v1/organization",
    "/api/v1/projects",
    "/api/v1/documents",
    "/api/v1/invitations",
    "/api/v1/test-objects",
    "/api/v1/policy",
    "/api/v1/state",
  ],
  Member: [
    "/",
    "/api/v1/organization",
    "/api/v1/projects",
    "/api/v1/documents",
    "/api/v1/test-objects",
    "/api/v1/policy",
    "/api/v1/state",
  ],
  External: [
    "/",
    "/api/v1/organization",
    "/api/v1/projects",
    "/api/v1/policy",
    "/api/v1/state",
  ],
};

describe("closed local browser journey model", () => {
  it("exposes only the three fixed roles and their acyclic GET plans", () => {
    expect(JOURNEY_ROLES).toEqual(["Owner", "Member", "External"]);
    expect(Object.isFrozen(JOURNEY_ROLES)).toBe(true);

    for (const role of JOURNEY_ROLES) {
      const plan = journeyPlan(role);
      expect(plan.map(({ path }) => path)).toEqual(EXPECTED_PATHS[role]);
      expect(plan.map(({ index }) => index)).toEqual(
        plan.map((_, index) => index),
      );
      expect(new Set(plan.map(({ path }) => path)).size).toBe(plan.length);
      expect(plan.map(({ method }) => method)).toEqual(plan.map(() => "GET"));
      expect(plan[0]?.fromState).toBe("ready");
      expect(plan.at(-1)?.successState).toBe("completed");
      expect(
        plan
          .slice(0, -1)
          .every(({ successState }) => successState === "running"),
      ).toBe(true);
      expect(Object.isFrozen(plan)).toBe(true);
      expect(plan.every((step) => Object.isFrozen(step))).toBe(true);
    }
    expect(() => journeyPlan("Admin")).toThrow("LOCAL_JOURNEY_ROLE_INVALID");
  });

  it("publishes replay capabilities that explicitly provide no authentication or authorization", () => {
    for (const role of JOURNEY_ROLES) {
      const profile = capabilitiesFor(role);
      expect(profile).toEqual({
        role,
        purpose: "deterministic_local_replay_only",
        authentication: "not_modeled",
        authorization: "not_an_authorization_decision",
        capabilities: journeyPlan(role).map(({ capability }) => capability),
      });
      expect(Object.isFrozen(profile)).toBe(true);
      expect(Object.isFrozen(profile.capabilities)).toBe(true);
    }
    expect(capabilitiesFor("Owner").capabilities).toContain("invitations.read");
    expect(capabilitiesFor("Member").capabilities).not.toContain(
      "invitations.read",
    );
    expect(capabilitiesFor("External").capabilities).toEqual([
      "service.read",
      "organization.read",
      "projects.read",
      "policy.read",
      "state.read",
    ]);
  });

  it("accepts only canonical non-privileged IPv4 loopback origins", () => {
    for (const valid of [
      "http://127.0.0.1:1024",
      ORIGIN,
      "http://127.0.0.1:49152",
      "http://127.0.0.1:65535",
    ])
      expect(assertLoopbackOrigin(valid)).toBe(valid);

    for (const invalid of [
      null,
      4173,
      "http://127.0.0.1:0",
      "http://127.0.0.1:80",
      "http://127.0.0.1:1023",
      "http://127.0.0.1:04173",
      "http://127.0.0.1:65536",
      "http://127.0.0.1:4173/",
      "http://127.0.0.1:4173?query=1",
      "http://127.0.0.1:4173#fragment",
      "http://user@127.0.0.1:4173",
      "http://localhost:4173",
      "http://[::1]:4173",
      "https://127.0.0.1:4173",
      "HTTP://127.0.0.1:4173",
    ])
      expect(() => assertLoopbackOrigin(invalid)).toThrow(
        "LOCAL_JOURNEY_ORIGIN_INVALID",
      );
  });

  it("allows only the exact current GET URL and fails closed for every variant", () => {
    for (const role of JOURNEY_ROLES) {
      const plan = journeyPlan(role);
      for (const step of plan) {
        const url = `${ORIGIN}${step.path}`;
        expect(
          isAllowedJourneyRequest(role, step.index, url, "GET", ORIGIN),
        ).toBe(true);
        expect(
          isAllowedJourneyRequest(
            role,
            step.index,
            `${url}?x=1`,
            "GET",
            ORIGIN,
          ),
        ).toBe(false);
        expect(
          isAllowedJourneyRequest(role, step.index, `${url}#x`, "GET", ORIGIN),
        ).toBe(false);
        expect(
          isAllowedJourneyRequest(role, step.index, url, "get", ORIGIN),
        ).toBe(false);
        expect(
          isAllowedJourneyRequest(role, step.index, url, "POST", ORIGIN),
        ).toBe(false);
        expect(
          isAllowedJourneyRequest(
            role,
            step.index,
            url,
            "GET",
            "http://127.0.0.1:4174",
          ),
        ).toBe(false);
      }
      expect(
        isAllowedJourneyRequest(role, -1, `${ORIGIN}/`, "GET", ORIGIN),
      ).toBe(false);
      expect(
        isAllowedJourneyRequest(
          role,
          plan.length,
          `${ORIGIN}/api/v1/state`,
          "GET",
          ORIGIN,
        ),
      ).toBe(false);
    }
    expect(
      isAllowedJourneyRequest(
        "Owner",
        0,
        "http://user@127.0.0.1:4173/",
        "GET",
        ORIGIN,
      ),
    ).toBe(false);
    expect(
      isAllowedJourneyRequest("Admin", 0, `${ORIGIN}/`, "GET", ORIGIN),
    ).toBe(false);
  });
});

describe("minimal journey evidence", () => {
  it("finalizes completed and fail-closed evidence without raw values", () => {
    const completedSteps = journeyPlan("External").map(
      (_, index): JourneyStepEvidence => ({
        outcome: "success",
        recordCount: index,
        redactedScreenshotByteLength: 1_024 + index,
        redactedScreenshotDigestSha256: index % 2 === 0 ? DIGEST_B : DIGEST_A,
        responseDigestSha256: index % 2 === 0 ? DIGEST_A : DIGEST_B,
        statusCode: 200,
      }),
    );
    const completed = finalizeJourneyEvidence({
      role: "External",
      status: "completed",
      blockedRequestCount: 0,
      steps: completedSteps,
    });
    expect(completed).toMatchObject({
      version: 1,
      role: "External",
      status: "completed",
      plannedStepCount: 5,
      observedStepCount: 5,
      successfulStepCount: 5,
      blockedRequestCount: 0,
      statusCodes: [200, 200, 200, 200, 200],
      recordCounts: [0, 1, 2, 3, 4],
      redactedScreenshotByteLengths: [1024, 1025, 1026, 1027, 1028],
      redactedScreenshotDigestsSha256: [
        DIGEST_B,
        DIGEST_A,
        DIGEST_B,
        DIGEST_A,
        DIGEST_B,
      ],
    });
    expect(completed.planDigestSha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(completed.evidenceDigestSha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(Object.isFrozen(completed)).toBe(true);
    expect(Object.isFrozen(completed.statusCodes)).toBe(true);
    expect(Object.isFrozen(completed.recordCounts)).toBe(true);
    expect(Object.isFrozen(completed.redactedScreenshotByteLengths)).toBe(true);
    expect(Object.isFrozen(completed.redactedScreenshotDigestsSha256)).toBe(
      true,
    );
    expect(Reflect.ownKeys(completed).sort()).toEqual(
      [
        "version",
        "role",
        "status",
        "plannedStepCount",
        "observedStepCount",
        "successfulStepCount",
        "blockedRequestCount",
        "statusCodes",
        "recordCounts",
        "redactedScreenshotByteLengths",
        "redactedScreenshotDigestsSha256",
        "planDigestSha256",
        "evidenceDigestSha256",
      ].sort(),
    );
    expect(JSON.stringify(completed)).not.toContain("/api/");
    expect(JSON.stringify(completed)).not.toContain("127.0.0.1");

    const egressBlocked = finalizeJourneyEvidence({
      role: "Owner",
      status: "blocked",
      blockedRequestCount: 1,
      steps: completedSteps.slice(0, 2),
    });
    expect(egressBlocked).toMatchObject({
      status: "blocked",
      observedStepCount: 2,
      successfulStepCount: 2,
      blockedRequestCount: 1,
    });

    const httpBlocked = finalizeJourneyEvidence({
      role: "External",
      status: "blocked",
      blockedRequestCount: 0,
      steps: [
        completedSteps[0],
        {
          outcome: "http_error",
          recordCount: 0,
          redactedScreenshotByteLength: 2_048,
          redactedScreenshotDigestSha256: DIGEST_A,
          responseDigestSha256: DIGEST_B,
          statusCode: 503,
        },
      ],
    });
    expect(httpBlocked).toMatchObject({
      status: "blocked",
      observedStepCount: 2,
      successfulStepCount: 1,
      blockedRequestCount: 0,
      statusCodes: [200, 503],
    });
  });

  it("rejects inconsistent, extra, accessor, proxy and exotic evidence without invoking getters", () => {
    const validStep = {
      outcome: "success",
      recordCount: 0,
      redactedScreenshotByteLength: 1_024,
      redactedScreenshotDigestSha256: DIGEST_B,
      responseDigestSha256: DIGEST_A,
      statusCode: 200,
    };
    const valid = {
      role: "External",
      status: "blocked",
      blockedRequestCount: 1,
      steps: [],
    };
    const oversizedSparseSteps: unknown[] = [];
    oversizedSparseSteps.length = 1_000_000_000;
    const invalid: readonly unknown[] = [
      { ...valid, extra: "raw-body" },
      { ...valid, role: "Admin" },
      { ...valid, status: "running" },
      { ...valid, blockedRequestCount: 2 },
      { ...valid, status: "completed" },
      Object.assign(Object.create(null), valid),
      new Proxy(valid, {}),
      { ...valid, steps: new Proxy([], {}) },
      { ...valid, steps: oversizedSparseSteps },
      {
        ...valid,
        steps: [{ ...validStep, responseDigestSha256: "raw-response" }],
      },
      {
        ...valid,
        steps: [{ ...validStep, statusCode: 404 }],
      },
      { ...valid, steps: [{ ...validStep, recordCount: -1 }] },
      { ...valid, steps: [{ ...validStep, recordCount: 1.5 }] },
      { ...valid, steps: [{ ...validStep, recordCount: 1_001 }] },
      {
        ...valid,
        steps: [{ ...validStep, redactedScreenshotByteLength: 0 }],
      },
      {
        ...valid,
        steps: [{ ...validStep, redactedScreenshotByteLength: 1.5 }],
      },
      {
        ...valid,
        steps: [{ ...validStep, redactedScreenshotByteLength: 1_048_577 }],
      },
      {
        ...valid,
        steps: [
          { ...validStep, redactedScreenshotDigestSha256: "raw-screenshot" },
        ],
      },
      { ...valid, steps: [{ ...validStep, rawBody: "forbidden" }] },
      { ...valid, steps: [Object.freeze({ ...validStep })] },
    ];
    for (const value of invalid)
      expect(() => finalizeJourneyEvidence(value)).toThrow(
        "LOCAL_JOURNEY_EVIDENCE_INVALID",
      );

    let getterCalls = 0;
    const accessor = Object.defineProperty({ ...valid }, "role", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "External";
      },
    });
    expect(() => finalizeJourneyEvidence(accessor)).toThrow(
      "LOCAL_JOURNEY_EVIDENCE_INVALID",
    );
    const nestedAccessor = Object.defineProperty(
      { ...validStep },
      "statusCode",
      {
        enumerable: true,
        get: () => {
          getterCalls += 1;
          return 200;
        },
      },
    );
    expect(() =>
      finalizeJourneyEvidence({
        role: "External",
        status: "blocked",
        blockedRequestCount: 1,
        steps: [nestedAccessor],
      }),
    ).toThrow("LOCAL_JOURNEY_EVIDENCE_INVALID");
    expect(getterCalls).toBe(0);
  });
});
