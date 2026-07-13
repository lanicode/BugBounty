import { request } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  DemoSaas,
  startDemoSaasServer,
  type RunningDemoSaasServer,
} from "../../packages/demo-saas/index.js";

const runningServers: RunningDemoSaasServer[] = [];

afterEach(async () => {
  await Promise.all(runningServers.splice(0).map((server) => server.close()));
});

describe("deterministic in-memory demo SaaS", () => {
  it("starts with stable organization, roles and controlled fixture data", () => {
    const first = new DemoSaas().snapshot();
    const second = new DemoSaas().snapshot();

    expect(first).toEqual(second);
    expect(first).toMatchObject({
      mode: "simulation",
      externalIntegrationsEnabled: false,
      organization: { organizationRef: "org-demo-001" },
      projects: [{ projectRef: "project-demo-001" }],
      documents: [{ documentRef: "document-demo-001" }],
      invitations: [{ status: "pending" }],
      testObjects: [{ canary: "canary-demo-001", status: "active" }],
      currentPolicy: { version: 1 },
    });
    expect(first.organization.identities.map(({ role }) => role)).toEqual([
      "Owner",
      "Member",
      "External",
    ]);
    expect(Object.isFrozen(first)).toBe(true);
  });

  it("permits bounded local domain mutations but no external-role writes", () => {
    const demo = new DemoSaas(() => new Date("2026-07-13T13:00:00.000Z"));
    demo.createProject({
      actorRef: "identity-owner-001",
      projectRef: "project-demo-002",
      displayName: "Second Demo Project",
    });
    demo.createDocument({
      actorRef: "identity-member-001",
      documentRef: "document-demo-002",
      projectRef: "project-demo-002",
      title: "Member Document",
      classification: "shared",
    });
    demo.createInvitation({
      actorRef: "identity-owner-001",
      invitationRef: "invitation-demo-002",
      inviteeRef: "fixture-invitee-002",
      role: "Member",
    });
    demo.createTestObject({
      actorRef: "identity-member-001",
      objectRef: "object-demo-002",
      projectRef: "project-demo-002",
      canary: "canary-demo-002",
    });

    expect(demo.snapshot()).toMatchObject({
      revision: 5,
      projects: [
        { projectRef: "project-demo-001" },
        { projectRef: "project-demo-002" },
      ],
      testObjects: [
        { objectRef: "object-demo-001" },
        {
          objectRef: "object-demo-002",
          controlledByRef: "identity-member-001",
        },
      ],
    });
    expect(() =>
      demo.createDocument({
        actorRef: "identity-external-001",
        documentRef: "document-blocked-001",
        projectRef: "project-demo-001",
        title: "Blocked",
        classification: "shared",
      }),
    ).toThrow("DEMO_ROLE_BLOCKED");
    expect(() =>
      demo.createTestObject({
        actorRef: "identity-owner-001",
        objectRef: "object-demo-003",
        projectRef: "project-demo-001",
        canary: "canary-demo-002",
      }),
    ).toThrow("DEMO_CANARY_CONFLICT");
  });

  it("versions policy drift deterministically and rejects stale or unchanged input", () => {
    const demo = new DemoSaas(() => new Date("2026-07-13T14:00:00.000Z"));
    const initial = demo.snapshot().currentPolicy;
    const drift = demo.simulatePolicyDrift({
      expectedPolicyHash: initial.contentHash,
      rules: {
        requestLimit: 10,
        allowedActions: ["document.read"],
        prohibitedTestClasses: ["active_security_test", "write_test"],
      },
    });

    expect(drift).toMatchObject({
      previousVersion: 1,
      nextVersion: 2,
      changedFields: [
        "requestLimit",
        "allowedActions",
        "prohibitedTestClasses",
      ],
    });
    expect(demo.snapshot()).toMatchObject({
      currentPolicy: { version: 2, contentHash: drift.nextHash },
      policyVersions: [{ version: 1 }, { version: 2 }],
      lastPolicyDrift: drift,
    });
    expect(() =>
      demo.simulatePolicyDrift({
        expectedPolicyHash: initial.contentHash,
        rules: demo.snapshot().currentPolicy.rules,
      }),
    ).toThrow("DEMO_POLICY_REVISION_CONFLICT");
    expect(() =>
      demo.simulatePolicyDrift({
        expectedPolicyHash: drift.nextHash,
        rules: demo.snapshot().currentPolicy.rules,
      }),
    ).toThrow("DEMO_POLICY_UNCHANGED");
  });
});

describe("read-only loopback demo SaaS server", () => {
  it("binds to 127.0.0.1 and exposes only fixed JSON state routes", async () => {
    const server = await startDemoSaasServer(new DemoSaas());
    runningServers.push(server);

    expect(server.host).toBe("127.0.0.1");
    expect(server.origin).toBe(`http://127.0.0.1:${server.port}`);
    const response = await fetch(`${server.origin}/api/v1/state`);
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-security-policy")).toContain(
      "default-src 'none'",
    );
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    await expect(response.json()).resolves.toMatchObject({
      mode: "simulation",
      externalIntegrationsEnabled: false,
      organization: { organizationRef: "org-demo-001" },
    });

    const missing = await fetch(`${server.origin}/api/v1/unknown`);
    expect(missing.status).toBe(404);
    const queried = await fetch(`${server.origin}/api/v1/state?unexpected=1`);
    expect(queried.status).toBe(404);
    const nonCanonical = await rawLoopbackRequest(
      server,
      "GET",
      `127.0.0.1:${server.port}`,
      "/ignored/../api/v1/state",
    );
    expect(nonCanonical.statusCode).toBe(404);
  });

  it("blocks forged hosts and every HTTP mutation without changing state", async () => {
    const demo = new DemoSaas();
    const server = await startDemoSaasServer(demo);
    runningServers.push(server);
    const revision = demo.snapshot().revision;

    const forged = await rawLoopbackRequest(server, "GET", "attacker.invalid");
    expect(forged).toMatchObject({ statusCode: 403 });
    expect(forged.body).toContain("DEMO_HOST_BLOCKED");

    const mutation = await rawLoopbackRequest(
      server,
      "POST",
      `127.0.0.1:${server.port}`,
    );
    expect(mutation).toMatchObject({ statusCode: 405 });
    expect(mutation.body).toContain("DEMO_METHOD_BLOCKED");
    expect(demo.snapshot().revision).toBe(revision);
  });

  it("closes cleanly and idempotently", async () => {
    const server = await startDemoSaasServer(new DemoSaas());
    await server.close();
    await expect(server.close()).resolves.toBeUndefined();
  });
});

function rawLoopbackRequest(
  server: RunningDemoSaasServer,
  method: string,
  host: string,
  path = "/api/v1/state",
): Promise<{ readonly body: string; readonly statusCode: number }> {
  return new Promise((resolve, reject) => {
    const call = request(
      {
        host: "127.0.0.1",
        port: server.port,
        path,
        method,
        headers: { host },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => {
          chunks.push(chunk);
        });
        response.on("end", () => {
          resolve({
            body: Buffer.concat(chunks).toString("utf8"),
            statusCode: response.statusCode ?? 0,
          });
        });
      },
    );
    call.on("error", reject);
    call.end();
  });
}
