import { describe, expect, it } from "vitest";
import {
  DisabledHackerOneAdapter,
  MockPlatformAdapter,
} from "../../../packages/platform/adapters.js";
import { ProgramCatalogService } from "../../../packages/platform/catalog.js";
import { compilePlatformPolicy } from "../../../packages/platform-source/compiler.js";
import { validateProgramSnapshot } from "../../../packages/platform-source/fixture-source.js";
import { snapshotValue } from "../../fixtures/platform-source.factory.js";

describe("mock-only program catalog", () => {
  it("synchronizes local fixtures without creating an acceptance", async () => {
    const catalog = new ProgramCatalogService();
    const entries = await catalog.synchronize(
      new MockPlatformAdapter([snapshotValue()]),
      {},
      new AbortController().signal,
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]?.acceptance).toBe("pending_human_acceptance");
  });

  it("recognizes only an explicit matching human acceptance", async () => {
    const policy = compilePlatformPolicy(
      validateProgramSnapshot(snapshotValue()),
    );
    const acceptance = {
      sourceRevision: policy.sourceRevision,
      sourceSnapshotHash: policy.sourceSnapshotHash,
      upstreamPolicyHash: policy.upstreamPolicyHash,
      acceptedBy: "local-reviewer",
      acceptedAt: "2026-07-13T12:01:00Z",
    };
    const entries = await new ProgramCatalogService().synchronize(
      new MockPlatformAdapter([snapshotValue()]),
      { [policy.handle]: acceptance },
      new AbortController().signal,
    );
    expect(entries[0]?.acceptance).toBe("accepted");
  });

  it("never invokes the disabled real adapter", async () => {
    await expect(
      new ProgramCatalogService().synchronize(
        new DisabledHackerOneAdapter(),
        {},
        new AbortController().signal,
      ),
    ).rejects.toThrow("EXTERNAL_INTEGRATIONS_DISABLED");
  });
});
