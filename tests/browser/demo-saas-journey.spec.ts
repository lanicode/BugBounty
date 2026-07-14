import { expect, test } from "./fixtures/local-demo.js";
import {
  capabilitiesFor,
  JOURNEY_ROLES,
  journeyPlan,
  type JourneyEvidence,
  type JourneyRole,
} from "./support/journey-model.js";

test("replays the closed local Demo-SaaS role journey deterministically", async ({
  runJourney,
}) => {
  const firstPass = new Map<JourneyRole, JourneyEvidence>();
  for (const role of JOURNEY_ROLES) firstPass.set(role, await runJourney(role));

  const secondPass = new Map<JourneyRole, JourneyEvidence>();
  for (const role of [...JOURNEY_ROLES].reverse())
    secondPass.set(role, await runJourney(role));

  for (const role of JOURNEY_ROLES) {
    const first = firstPass.get(role);
    const second = secondPass.get(role);
    expect(first).toBeDefined();
    expect(second).toEqual(first);
    expect(first).toMatchObject({
      version: 1,
      role,
      status: "completed",
      plannedStepCount: journeyPlan(role).length,
      observedStepCount: journeyPlan(role).length,
      successfulStepCount: journeyPlan(role).length,
      blockedRequestCount: 0,
      statusCodes: journeyPlan(role).map(() => 200),
    });
    expect(first?.redactedScreenshotDigestsSha256).toHaveLength(
      journeyPlan(role).length,
    );
    expect(new Set(first?.redactedScreenshotDigestsSha256).size).toBe(
      journeyPlan(role).length,
    );
    expect(
      first?.redactedScreenshotDigestsSha256.every((digest) =>
        /^[a-f0-9]{64}$/u.test(digest),
      ),
    ).toBe(true);
    expect(capabilitiesFor(role)).toMatchObject({
      purpose: "deterministic_local_replay_only",
      authentication: "not_modeled",
      authorization: "not_an_authorization_decision",
    });
    expect(JSON.stringify(first)).not.toContain("127.0.0.1");
    expect(JSON.stringify(first)).not.toContain("PHASE7_RAW");
  }

  expect(capabilitiesFor("Owner").capabilities).toContain("invitations.read");
  expect(capabilitiesFor("Member").capabilities).not.toContain(
    "invitations.read",
  );
  expect(capabilitiesFor("External").capabilities).not.toContain(
    "documents.read",
  );
});

test("blocks a second loopback port before the server receives a request", async ({
  proveForeignPortBlocked,
}) => {
  await expect(proveForeignPortBlocked()).resolves.toEqual({
    blockedRequestCount: 1,
    blockedServerHits: 0,
  });
});
