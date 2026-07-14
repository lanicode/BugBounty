import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DemoSaas } from "../../packages/demo-saas/domain.js";
import { validateDemoResponse } from "../browser/support/demo-response.js";
import type { JourneyPath } from "../browser/support/journey-model.js";

const NOW = "2026-07-13T12:00:00.000Z";

describe("strict local Demo-SaaS browser response projection", () => {
  it("validates every fixed response and releases only counts, flags and a digest", () => {
    const snapshot = new DemoSaas(() => new Date(NOW)).snapshot();
    const cases: readonly [JourneyPath, unknown, number][] = [
      [
        "/",
        {
          service: "bug-bounty-copilot-demo-saas",
          mode: "simulation",
          externalIntegrationsEnabled: false,
          routes: [
            "/health",
            "/api/v1/state",
            "/api/v1/organization",
            "/api/v1/projects",
            "/api/v1/documents",
            "/api/v1/invitations",
            "/api/v1/test-objects",
            "/api/v1/policy",
          ],
        },
        8,
      ],
      ["/api/v1/organization", snapshot.organization, 3],
      ["/api/v1/projects", { projects: snapshot.projects }, 1],
      ["/api/v1/documents", { documents: snapshot.documents }, 1],
      ["/api/v1/invitations", { invitations: snapshot.invitations }, 1],
      ["/api/v1/test-objects", { testObjects: snapshot.testObjects }, 1],
      [
        "/api/v1/policy",
        {
          currentPolicy: snapshot.currentPolicy,
          policyVersions: snapshot.policyVersions,
          lastPolicyDrift: snapshot.lastPolicyDrift,
        },
        1,
      ],
      ["/api/v1/state", snapshot, 5],
    ];

    for (const [path, body, expectedCount] of cases) {
      const bytes = Buffer.from(JSON.stringify(body));
      const expectedDigest = createHash("sha256").update(bytes).digest("hex");
      const result = validateDemoResponse(path, bytes);
      expect(result.responseDigestSha256).toBe(expectedDigest);
      expect(result.recordCount).toBe(expectedCount);
      expect(Reflect.ownKeys(result).sort()).toEqual(
        [
          "responseDigestSha256",
          "recordCount",
          "simulationMode",
          "externalIntegrationsDisabled",
          "revision",
        ].sort(),
      );
      expect(JSON.stringify(result)).not.toContain("canary-demo");
      expect(JSON.stringify(result)).not.toContain("identity-owner");
      expect(JSON.stringify(result)).not.toContain("Simulation Notes");
    }
  });

  it("fails closed for non-canonical, extended, invalid UTF-8 and oversized bodies", () => {
    const snapshot = new DemoSaas(() => new Date(NOW)).snapshot();
    expect(() =>
      validateDemoResponse(
        "/api/v1/state",
        Buffer.from(` ${JSON.stringify(snapshot)}`),
      ),
    ).toThrow("LOCAL_JOURNEY_RESPONSE_NOT_CANONICAL");
    expect(() =>
      validateDemoResponse(
        "/api/v1/projects",
        Buffer.from(
          JSON.stringify({ projects: snapshot.projects, rawSecret: "blocked" }),
        ),
      ),
    ).toThrow("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
    expect(() =>
      validateDemoResponse(
        "/api/v1/projects",
        Buffer.from([0x7b, 0xc3, 0x28, 0x7d]),
      ),
    ).toThrow("LOCAL_JOURNEY_RESPONSE_UTF8_INVALID");
    expect(() => validateDemoResponse("/", Buffer.alloc(65_537, 0x61))).toThrow(
      "LOCAL_JOURNEY_RESPONSE_SIZE_INVALID",
    );
  });
});
