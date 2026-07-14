import { errorCode } from "../../packages/shared/errors.js";
import { startLocalApplication } from "./runtime.js";

async function main(): Promise<void> {
  const application = await startLocalApplication();
  process.stdout.write(
    [
      "Bug Bounty Copilot läuft ausschließlich lokal.",
      `Dashboard-URL: ${application.dashboard.origin}`,
      `Dashboard-Port-Fallback: ${application.dashboardPortFallback ? "aktiv" : "nicht benötigt"}`,
      `Demo-SaaS-URL: ${application.demo.origin}`,
      `Runtime-Modus: ${application.runtimeMode}`,
      `Secure-Control-Plane-Status: ${application.readiness.status}`,
      "External-Integrationen: deaktiviert",
      `AI-Provider: ${application.readiness.aiProviderStatus}`,
      "Kill-Switch: aktiv / fail-closed",
      "Keine reale Report-Einreichung.",
    ].join("\n") + "\n",
  );

  let shuttingDown = false;
  const shutdown = (): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    void application
      .close()
      .then(() => {
        process.exitCode = 0;
      })
      .catch(() => {
        process.exitCode = 1;
      });
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

main().catch((error: unknown) => {
  process.stderr.write(`${errorCode(error)}\n`);
  process.exitCode = 1;
});
