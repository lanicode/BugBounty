import { describe, expect, it } from "vitest";
import {
  DASHBOARD_HTML,
  DASHBOARD_JAVASCRIPT,
} from "../../packages/dashboard/assets.js";

describe("Core provisioning dashboard assets", () => {
  it("ships one disabled local action and explicit fail-closed restart guidance", () => {
    expect(DASHBOARD_HTML).toContain(
      'id="core-provisioning-action" type="button" disabled',
    );
    expect(DASHBOARD_HTML).toContain("KEINE SECRETEINGABE");
    expect(DASHBOARD_HTML).toContain(
      "Das Dashboard nimmt keine Schlüssel, Tokens oder Passwörter entgegen.",
    );
    expect(DASHBOARD_JAVASCRIPT).toContain('postJson("/api/core/provision", {');
    expect(DASHBOARD_JAVASCRIPT).toContain(
      'confirmation: "provision_local_security_core"',
    );
    expect(DASHBOARD_JAVASCRIPT).toContain(
      "Diese laufende Instanz bleibt fail-closed.",
    );
    expect(DASHBOARD_JAVASCRIPT).toContain("BUGBOUNTY_EVENT_KEY_MIN_VERSION=1");
    expect(DASHBOARD_JAVASCRIPT).toContain("mit pnpm app neu starten");
  });

  it("submits only the fixed confirmation, nonce, and digest contract", () => {
    const callStart = DASHBOARD_JAVASCRIPT.indexOf(
      'postJson("/api/core/provision", {',
    );
    expect(callStart).toBeGreaterThan(-1);
    const callEnd = DASHBOARD_JAVASCRIPT.indexOf("});", callStart);
    const call = DASHBOARD_JAVASCRIPT.slice(callStart, callEnd);
    for (const field of [
      "version: 1",
      'confirmation: "provision_local_security_core"',
      "nonce: challenge.nonce",
      "contextDigestSha256: challenge.contextDigestSha256",
    ])
      expect(call).toContain(field);
    for (const forbidden of [
      "mode:",
      "operatorId:",
      "eventKey:",
      "privateKey:",
      "secret:",
      "token:",
      "password:",
    ])
      expect(call).not.toContain(forbidden);
    expect(DASHBOARD_JAVASCRIPT).not.toMatch(
      /(?:localStorage|sessionStorage|indexedDB|document\.cookie)/u,
    );
  });
});
