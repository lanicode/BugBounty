import { Script } from "node:vm";
import { describe, expect, it } from "vitest";
import {
  ACTIVE_TESTING_DASHBOARD_HTML,
  ACTIVE_TESTING_DASHBOARD_JAVASCRIPT,
} from "../../packages/dashboard/active-testing-assets.js";

describe("active testing dashboard asset contract", () => {
  it("renders exactly three initially disabled explicit action steps", () => {
    expect(
      ACTIVE_TESTING_DASHBOARD_HTML.match(/Schritt [123] von 3/gu),
    ).toHaveLength(3);
    for (const id of [
      "active-testing-prepare-plan",
      "active-testing-approve-plan",
      "active-testing-start-execution",
    ])
      expect(ACTIVE_TESTING_DASHBOARD_HTML).toMatch(
        new RegExp(`<button id="${id}"[^>]* disabled>`, "u"),
      );

    expect(
      ACTIVE_TESTING_DASHBOARD_HTML.match(/type="checkbox" disabled/gu),
    ).toHaveLength(4);
    expect(
      ACTIVE_TESTING_DASHBOARD_HTML.match(/<select id="active-testing-/gu),
    ).toHaveLength(3);
    expect(ACTIVE_TESTING_DASHBOARD_HTML).toContain(
      "Planfreigabe startet keinen Request.",
    );
    expect(ACTIVE_TESTING_DASHBOARD_HTML).toContain(
      "Asset-Identifier werden ausschließlich als Text dargestellt und niemals als Link verwendet.",
    );
  });

  it("contains no free-form target or request-material controls", () => {
    expect(ACTIVE_TESTING_DASHBOARD_HTML).not.toMatch(
      /<(?:a|form|textarea)\b|href=|contenteditable|type="(?:email|password|text|url)"/iu,
    );
    expect(ACTIVE_TESTING_DASHBOARD_HTML).not.toMatch(
      /name="(?:body|header|host|method|path|query|url)"/iu,
    );
    expect(ACTIVE_TESTING_DASHBOARD_HTML.match(/<button\b/gu)).toHaveLength(3);
  });

  it("uses only the three fixed same-origin mutation routes", () => {
    expect(
      ACTIVE_TESTING_DASHBOARD_JAVASCRIPT.match(
        /"\/api\/active-testing\/[^"\s]+"/gu,
      ),
    ).toEqual([
      '"/api/active-testing/plan/prepare"',
      '"/api/active-testing/plan/approve"',
      '"/api/active-testing/execution/start"',
    ]);
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      'state: "/api/state"',
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      'credentials: "same-origin"',
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain('redirect: "error"');
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      '"x-csrf-token": csrfToken',
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).not.toContain("http://");
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).not.toContain("https://");
  });

  it("prepares a plan with only exact projected references and four confirmations", () => {
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT)
      .toContain(`return postJson(ROUTES.preparePlan, {
          programRef: selected.binding.program.programRef,
          snapshotDigest: selected.binding.snapshot.snapshotDigest,
          scopeId: selected.asset.scopeId,
          assetIdentifierDigest: selected.asset.assetIdentifierDigest,
          testClass: selected.catalog.id,
          confirmations: {
            automationPermissionReviewed: true,
            scopeInstructionReviewed: true,
            scopeExclusionsReviewed: true,
            noSideEffectsConfirmed: true
          }
        });`);

    const prepareStart = ACTIVE_TESTING_DASHBOARD_JAVASCRIPT.indexOf(
      "return postJson(ROUTES.preparePlan",
    );
    const prepareEnd = ACTIVE_TESTING_DASHBOARD_JAVASCRIPT.indexOf(
      'element("active-testing-approve-plan")',
      prepareStart,
    );
    const prepareBlock = ACTIVE_TESTING_DASHBOARD_JAVASCRIPT.slice(
      prepareStart,
      prepareEnd,
    );
    expect(prepareBlock).not.toMatch(
      /\b(?:body|header|host|method|path|query|target|url)\s*:/iu,
    );
    expect(prepareBlock).not.toContain("displayIdentifier");
  });

  it("keeps plan approval and execution as separate exact confirmations", () => {
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT)
      .toContain(`return postJson(ROUTES.approvePlan, {
          approvalId: approval.approvalId,
          planId: plan.planId,
          confirmed: true
        });`);
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT)
      .toContain(`return postJson(ROUTES.startExecution, {
          approvalId: approval.approvalId,
          planId: plan.planId,
          confirmed: true
        });`);
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      'plan.status !== "prepared" || approval.status !== "open"',
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      'plan.status !== "approved" || approval.status !== "accepted"',
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).not.toContain(
      "postJson(ROUTES.startExecution, {})",
    );
  });

  it("validates the full activeTesting projection and readiness fail closed", () => {
    for (const field of [
      "capability.available",
      "capability.configured",
      "capability.enabled",
      "capability.secureCoreReady",
      "capability.killSwitchActive",
      "capability.reasonCodes",
      "projection.programs",
      "projection.snapshots",
      "projection.assetCandidates",
      "projection.testCatalog",
      "projection.currentPlan",
      "projection.currentApproval",
      "projection.attempts",
      "projection.reports",
    ])
      expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(field);

    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      'program.source === "hackerone_api_authenticated"',
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      "program.catalogDriftPending === false",
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      "snapshot.accepted === true",
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      'asset.assetType === "URL"',
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      "asset.supported === true",
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      "asset.eligibleForSubmission === true",
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      "asset.eligibleForBounty === true",
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      "var projection = root && record(root.activeTesting);",
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      "disableAllControls();",
    );
  });

  it("renders all server values through textContent without executable links", () => {
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(".textContent =");
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      'option.textContent = asset.assetType + " · " + asset.displayIdentifier;',
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).not.toMatch(
      /innerHTML|insertAdjacentHTML|document\.write|createElement\("a"\)|\.href\s*=|window\.open|location\s*=|eval\s*\(|new Function/iu,
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).not.toMatch(
      /localStorage|sessionStorage|indexedDB|document\.cookie|navigator\.clipboard/iu,
    );
  });

  it("shows only local unsubmitted report summaries and has no submission action", () => {
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      'report.reviewStatus === "local_draft_unsubmitted"',
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).toContain(
      "report.externalSubmissionPerformed === false",
    );
    expect(ACTIVE_TESTING_DASHBOARD_HTML).toContain("LOCAL · UNSUBMITTED");
    expect(ACTIVE_TESTING_DASHBOARD_HTML).not.toMatch(
      /<button[^>]*>[^<]*(?:einreich|submit)/iu,
    );
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).not.toMatch(
      /\/api\/[^"\s]*(?:report|submission|submit)/iu,
    );
  });

  it("performs no automatic mutation and is valid standalone JavaScript", () => {
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT.match(/fetch\(/gu)).toHaveLength(
      2,
    );
    expect(
      ACTIVE_TESTING_DASHBOARD_JAVASCRIPT.match(/postJson\(/gu),
    ).toHaveLength(4);
    expect(
      ACTIVE_TESTING_DASHBOARD_JAVASCRIPT.match(/addEventListener\("click"/gu),
    ).toHaveLength(3);
    expect(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT).not.toMatch(
      /setInterval|setTimeout|WebSocket|EventSource|Worker\s*\(/u,
    );
    expect(() => new Script(ACTIVE_TESTING_DASHBOARD_JAVASCRIPT)).not.toThrow();
  });
});
