import { describe, expect, it } from "vitest";
import {
  HACKERONE_DASHBOARD_HTML,
  HACKERONE_DASHBOARD_JAVASCRIPT,
} from "../../packages/dashboard/hackerone-assets.js";

describe("HackerOne dashboard assets", () => {
  it("renders the mandatory read-only boundary badges with a transient local credential form", () => {
    for (const badge of [
      "HACKERONE READ-ONLY",
      "KEINE ZIELREQUESTS",
      "KEINE REPORT-EINREICHUNG",
      "EXTERNE METADATENINTEGRATION DEAKTIVIERT",
    ])
      expect(HACKERONE_DASHBOARD_HTML).toContain(badge);

    expect(HACKERONE_DASHBOARD_HTML).toContain("Credentials lokal speichern");
    expect(HACKERONE_DASHBOARD_HTML).toContain(
      "pnpm hackerone:credentials store",
    );
    expect(HACKERONE_DASHBOARD_HTML.match(/type="password"/gu)).toHaveLength(2);
    expect(HACKERONE_DASHBOARD_HTML).toContain(
      '<form id="hackerone-credential-form" autocomplete="off">',
    );
    expect(HACKERONE_DASHBOARD_HTML).not.toMatch(
      /name="(?:identifier|token)"/u,
    );
    expect(HACKERONE_DASHBOARD_HTML).toContain(
      "Programmregeln und die aktuelle Policy werden niemals automatisch akzeptiert.",
    );
  });

  it("uses only the closed same-origin route registry and exact current request keys", () => {
    for (const route of [
      "/api/state",
      "/api/hackerone/credentials/store",
      "/api/hackerone/credentials/remove",
      "/api/hackerone/integration/enable",
      "/api/hackerone/integration/disable",
      "/api/hackerone/connection-test",
      "/api/hackerone/programs/synchronize",
      "/api/hackerone/program/select",
      "/api/hackerone/program/synchronize",
      "/api/hackerone/campaign/bind",
      "/api/hackerone/policy/accept",
      "/api/hackerone/manual-import",
    ])
      expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(`"${route}"`);

    for (const operation of [
      "removeCredentials",
      "enable",
      "disable",
      "connectionTest",
      "synchronizePrograms",
    ])
      expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
        `postJson(ROUTES.${operation}, {})`,
      );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "postJson(ROUTES.selectProgram, { programRef: draftProgramLocalRef() })",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "postJson(ROUTES.synchronizeProgram, { programRef: persistedProgramLocalRef() })",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "programRef: persistedProgramLocalRef(),",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "campaignId: selectedCampaignId()",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "programRef: programLocalRef,",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain("confirmed: true");
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).not.toContain(
      "programLocalRef: draftProgramLocalRef()",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      '"content-type": "application/octet-stream"',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "postCredentialFrame(frame)",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "view.setUint16(5, identifierBytes.byteLength, false)",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "view.setUint16(7, tokenBytes.byteLength, false)",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain("frame.fill(0)");
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).not.toContain("text/plain");
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).not.toContain("https://");
  });

  it("preserves an explicit program draft without implicitly selecting the first catalog entry", () => {
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'placeholder.textContent = "Programm ausdrücklich auswählen"',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "if (persistedRef !== lastPersistedProgramRef)",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "select.value = pendingProgramRef",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "var selectionAligned = selected && pendingProgramRef === projection.selectedProgramRef",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "killed || !selectionAligned",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "!selectionAligned || !campaignsAvailable",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-program-select").addEventListener("change"',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).not.toContain(
      "option.selected = stored.localRef === selectedRef",
    );
  });

  it("keeps credential transport binary and browser persistence APIs out of the client", () => {
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).not.toContain(
      "JSON.stringify({ identifier",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).not.toContain(
      "JSON.stringify({ token",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).not.toMatch(
      /(?:localStorage|sessionStorage|indexedDB|document\.cookie)/u,
    );
  });

  it("renders asset identifiers only as text with an explicit clipboard action", () => {
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'copyRow("Asset-Identifier", scope.assetIdentifier)',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "navigator.clipboard.writeText(value)",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(".textContent =");
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).not.toContain("innerHTML");
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).not.toMatch(
      /createElement\(["']a["']\)|\.href\s*=|window\.open|location\.(?:assign|replace)|fetch\(scope\.assetIdentifier/u,
    );
    expect(HACKERONE_DASHBOARD_HTML).not.toMatch(/<a\b|\shref=/u);
  });

  it("renders bounded campaign binding and prior-policy review context as plain text", () => {
    expect(HACKERONE_DASHBOARD_HTML).toContain(
      "Ausgewähltes Programm an Kampagne binden",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'previousHeading.textContent = "Vorheriger Policy-Text";',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "var campaigns = array(projection.campaigns);",
    );
    for (const changeCode of [
      "PROGRAM_STATE_CHANGED",
      "OPEN_SCOPE_CHANGED",
      "SAFE_HARBOR_CHANGED",
    ])
      expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(changeCode);
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).not.toContain("innerHTML");
  });

  it("disables request controls whenever the adapter is disabled or the kill switch is active", () => {
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "var killed = status.killSwitchActive !== false;",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-test").disabled = operationRunning || !activation.secureCoreReady || !enabled || killed;',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-sync-catalog").disabled = operationRunning || !activation.secureCoreReady || !enabled || killed;',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-sync-program").disabled = operationRunning || !activation.secureCoreReady || !enabled || killed || !selectionAligned;',
    );
  });

  it("keeps every security-core-dependent control disabled in setup-shell mode", () => {
    for (const id of [
      "hackerone-test",
      "hackerone-sync-catalog",
      "hackerone-program-select",
      "hackerone-select-program",
      "hackerone-sync-program",
      "hackerone-campaign-select",
      "hackerone-bind-campaign",
      "hackerone-manual-json",
      "hackerone-manual-import",
    ])
      expect(HACKERONE_DASHBOARD_JAVASCRIPT).toMatch(
        new RegExp(
          `element\\("${id}"\\)\\.disabled = [^;]*!activation\\.secureCoreReady`,
          "u",
        ),
      );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-policy-confirm").disabled = !secureCoreReady || !pending || operationRunning;',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-accept-policy").disabled = !secureCoreReady || !pending || !confirmed || operationRunning;',
    );
  });

  it("shows every activation prerequisite and never leaves a disabled activation unexplained", () => {
    for (const id of [
      "hackerone-activation-readiness-badge",
      "hackerone-activation-requirements",
      "hackerone-activation-context",
    ])
      expect(HACKERONE_DASHBOARD_HTML).toContain(`id="${id}"`);

    expect(HACKERONE_DASHBOARD_HTML).toContain(
      'aria-describedby="hackerone-activation-context"',
    );
    for (const field of [
      "projection.secureCoreReady === true",
      "projection.secureCoreReasonCodes",
      "status.externalIntegrationsEnabled === true",
      "status.adapterConfigured === true",
      "status.identifierPresent === true && status.tokenPresent === true",
      "status.killSwitchActive === false",
    ])
      expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(field);

    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-enable").disabled = operationRunning || enabled || !activation.ready;',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "Der Aktivierungsbutton bleibt gesperrt, bis alle oben sichtbaren Voraussetzungen erfüllt sind.",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED=true fehlt",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "BUGBOUNTY_HACKERONE_READONLY_ENABLED=true fehlt oder ist ungültig",
    );
  });

  it("keeps local credential management independent from activation prerequisites", () => {
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-save-credentials").disabled = operationRunning || !available;',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-remove-credentials").disabled = operationRunning || !available;',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "Credentials können unabhängig davon lokal gespeichert oder entfernt werden.",
    );
  });

  it("ships all mutation controls disabled and disables them again after a state failure", () => {
    for (const id of [
      "hackerone-identifier",
      "hackerone-token",
      "hackerone-save-credentials",
      "hackerone-remove-credentials",
      "hackerone-enable",
      "hackerone-disable",
      "hackerone-test",
      "hackerone-sync-catalog",
      "hackerone-program-select",
      "hackerone-select-program",
      "hackerone-sync-program",
      "hackerone-campaign-select",
      "hackerone-bind-campaign",
      "hackerone-manual-json",
      "hackerone-manual-import",
      "hackerone-policy-confirm",
      "hackerone-accept-policy",
    ])
      expect(HACKERONE_DASHBOARD_HTML).toMatch(
        new RegExp(`id="${id}"[^>]*\\bdisabled\\b`, "u"),
      );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      "function disableAllControls()",
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-identifier").value = "";',
    );
    expect(HACKERONE_DASHBOARD_JAVASCRIPT).toContain(
      'element("hackerone-token").value = "";',
    );
  });
});
