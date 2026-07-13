import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  assertGenuineMockPlatformAdapter,
  DisabledHackerOneAdapter,
  MockPlatformAdapter,
  PlatformAdapterRegistry,
  type PlatformAdapter,
} from "../../../packages/platform/adapters.js";
import { ProgramCatalogService } from "../../../packages/platform/catalog.js";
import { snapshotValue } from "../../fixtures/platform-source.factory.js";

const signal = () => new AbortController().signal;

describe("platform adapter boundary", () => {
  it("implements the complete interface from immutable local fixtures", async () => {
    const adapter: PlatformAdapter = new MockPlatformAdapter([snapshotValue()]);
    const programs = await adapter.listPrograms(signal());
    expect(programs).toHaveLength(1);
    const handle = programs[0]?.handle;
    if (handle === undefined) throw new Error("MISSING_PROGRAM");

    await expect(adapter.listProgramSnapshots(signal())).resolves.toHaveLength(
      1,
    );
    await expect(adapter.getProgram(handle, signal())).resolves.toMatchObject({
      handle,
    });
    await expect(adapter.getPolicy(handle, signal())).resolves.toMatchObject({
      programHandle: handle,
      policyHash: "b".repeat(64),
    });
    await expect(
      adapter.getStructuredScope(handle, signal()),
    ).resolves.toMatchObject({ programHandle: handle });
    await expect(
      adapter.getPolicyVersion(handle, signal()),
    ).resolves.toMatchObject({
      programHandle: handle,
      version: "fixture-001",
    });
    await expect(adapter.listReports(handle, signal())).resolves.toEqual([]);
  });

  it("creates drafts only in process and deterministically blocks submission", async () => {
    const adapter = new MockPlatformAdapter([snapshotValue()]);
    const input = {
      reportRef: "report-1",
      programHandle: "local_fixture_program",
      title: "Local mock finding",
      summary: "Simulation only",
    };
    await expect(adapter.createReportDraft(input, signal())).resolves.toEqual({
      ...input,
      status: "draft",
      delivery: "in_process_mock_only",
    });
    await expect(
      adapter.listReports(input.programHandle, signal()),
    ).resolves.toEqual([
      { ...input, status: "draft", delivery: "in_process_mock_only" },
    ]);
    await expect(adapter.createReportDraft(input, signal())).rejects.toThrow(
      "MOCK_REPORT_DRAFT_CONFLICT",
    );
    await expect(
      adapter.submitReport(input.reportRef, signal()),
    ).rejects.toThrow("REPORT_SUBMISSION_DISABLED_PHASE2");
  });

  it("fails closed for every disabled HackerOne operation", async () => {
    const adapter: PlatformAdapter = new DisabledHackerOneAdapter();
    const draft = {
      reportRef: "report-1",
      programHandle: "program",
      title: "title",
      summary: "summary",
    };
    const calls: readonly (() => Promise<unknown>)[] = [
      () => adapter.listProgramSnapshots(signal()),
      () => adapter.listPrograms(signal()),
      () => adapter.getProgram("program", signal()),
      () => adapter.getPolicy("program", signal()),
      () => adapter.getStructuredScope("program", signal()),
      () => adapter.getPolicyVersion("program", signal()),
      () => adapter.listReports("program", signal()),
      () => adapter.createReportDraft(draft, signal()),
      () => adapter.submitReport("report-1", signal()),
    ];
    for (const call of calls)
      await expect(call()).rejects.toThrow("EXTERNAL_INTEGRATIONS_DISABLED");
  });

  it("uses a closed registry and rejects unknown, real and spoofed adapters", async () => {
    const registry = new PlatformAdapterRegistry([snapshotValue()]);
    const adapter = registry.create("local_mock");
    expect(adapter).toBeInstanceOf(MockPlatformAdapter);
    expect(() => {
      assertGenuineMockPlatformAdapter(adapter);
    }).not.toThrow();
    for (const real of ["hackerone", "bugcrowd"])
      expect(() => registry.create(real)).toThrow(
        "EXTERNAL_INTEGRATIONS_DISABLED",
      );
    expect(() => registry.create("unknown")).toThrow(
      "PLATFORM_ADAPTER_UNKNOWN",
    );
    expect(() => registry.create({ kind: "local_mock" })).toThrow(
      "PLATFORM_ADAPTER_UNKNOWN",
    );

    const spoof = {
      kind: "local_mock",
      platform: "local_mock",
      listProgramSnapshots: () => Promise.resolve([]),
      listPrograms: () => Promise.resolve([]),
      getProgram: () => Promise.reject(new Error("SPOOF")),
      getPolicy: () => Promise.reject(new Error("SPOOF")),
      getStructuredScope: () => Promise.reject(new Error("SPOOF")),
      getPolicyVersion: () => Promise.reject(new Error("SPOOF")),
      listReports: () => Promise.resolve([]),
      createReportDraft: () => Promise.reject(new Error("SPOOF")),
      submitReport: () => Promise.reject(new Error("SPOOF")),
    } as PlatformAdapter;
    expect(() => {
      assertGenuineMockPlatformAdapter(spoof);
    }).toThrow("PLATFORM_ADAPTER_UNREGISTERED");
    await expect(
      new ProgramCatalogService().synchronize(spoof, {}, signal()),
    ).rejects.toThrow("PLATFORM_ADAPTER_UNREGISTERED");
  });

  it("checks the kill signal before every mock operation", async () => {
    const controller = new AbortController();
    controller.abort();
    const adapter = new MockPlatformAdapter([snapshotValue()]);
    await expect(adapter.listPrograms(controller.signal)).rejects.toThrow(
      "PHASE2_GLOBAL_KILL_SWITCH",
    );
    await expect(
      adapter.createReportDraft(
        {
          reportRef: "report-1",
          programHandle: "local_fixture_program",
          title: "title",
          summary: "summary",
        },
        controller.signal,
      ),
    ).rejects.toThrow("PHASE2_GLOBAL_KILL_SWITCH");
    await expect(
      adapter.submitReport("report-1", controller.signal),
    ).rejects.toThrow("PHASE2_GLOBAL_KILL_SWITCH");
  });

  it("contains no HTTP, socket, browser or LLM implementation", async () => {
    const source = await readFile("packages/platform/adapters.ts", "utf8");
    for (const forbidden of [
      "node:http",
      "node:https",
      "node:net",
      "node:tls",
      "node:dns",
      "fetch(",
      "undici",
      "playwright",
      "axios",
      "openai",
    ])
      expect(source).not.toContain(forbidden);
  });
});
