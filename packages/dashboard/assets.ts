import { ACTIVE_TESTING_DASHBOARD_HTML } from "./active-testing-assets.js";
import { HACKERONE_DASHBOARD_HTML } from "./hackerone-assets.js";

export const DASHBOARD_HTML = `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bug Bounty Copilot — Lokale Control Plane</title>
  <link rel="stylesheet" href="/styles.css">
  <script src="/app.js" defer></script>
  <script src="/phase8.js" defer></script>
  <script src="/hackerone.js" defer></script>
  <script src="/active-testing.js" defer></script>
</head>
<body>
  <header class="masthead">
    <div class="brand-row">
      <div>
        <p class="eyebrow">Bug Bounty Copilot</p>
        <h1>Lokale Control Plane</h1>
      </div>
      <div class="banner-stack" aria-label="Sicherheitsstatus">
        <strong class="banner simulation">SIMULATIONSMODUS</strong>
        <strong class="banner disabled">ALLGEMEINE EXTERNE INTEGRATIONEN DEAKTIVIERT</strong>
        <strong class="banner disabled">KEINE REALE REPORT-EINREICHUNG</strong>
      </div>
    </div>
    <nav aria-label="Bereiche">
      <a href="#overview">Übersicht</a>
      <a href="#phase8-onboarding">Einrichtung</a>
      <a href="#phase8-workflow">Demo-Ablauf</a>
      <a href="#programs">Programme</a>
      <a href="#policies">Policies</a>
      <a href="#campaigns">Kampagnen</a>
      <a href="#approvals">Freigaben</a>
      <a href="#phase8-journey">Journeys</a>
      <a href="#phase8-inventory">Inventory</a>
      <a href="#phase8-candidates">Kandidaten</a>
      <a href="#phase8-evidence">Evidence</a>
      <a href="#hackerone-integration">HackerOne</a>
      <a href="#active-testing">Aktive Tests</a>
      <a href="#system">System</a>
      <a href="#expert">Expertenansicht</a>
    </nav>
  </header>

  <main>
    <section id="overview" class="panel hero-panel">
      <div class="section-heading">
        <div><p class="eyebrow">Live-Zustand</p><h2>Übersicht</h2></div>
        <p id="last-refresh" class="muted" aria-live="polite">Wird geladen …</p>
      </div>
      <div class="metric-grid">
        <article class="metric"><span id="count-programs">0</span><p>Programme</p></article>
        <article class="metric"><span id="count-active-campaigns">0</span><p>Aktive Kampagnen</p></article>
        <article class="metric"><span id="count-paused-campaigns">0</span><p>Pausierte Kampagnen</p></article>
        <article class="metric"><span id="count-open-approvals">0</span><p>Offene Freigaben</p></article>
        <article class="metric"><span id="count-privacy-alerts">0</span><p>Datenschutzalarme</p></article>
        <article class="metric"><span id="count-reports">0</span><p>Report-Entwürfe</p></article>
      </div>
      <div class="status-strip">
        <p>Simulation: <strong id="simulation-status">bereit</strong></p>
        <p>Phase-1-Sicherheitskern: <strong id="phase1-status">unbekannt</strong></p>
        <p>Kill Switch: <strong id="overview-kill-status">unbekannt</strong></p>
      </div>
    </section>

    <section id="phase8-onboarding" class="panel phase8-panel">
      <div class="section-heading">
        <div><p class="eyebrow">Geführte Einrichtung</p><h2>Lokales Onboarding</h2></div>
        <span id="phase8-onboarding-status" class="capability-badge">Wird geprüft …</span>
      </div>
      <div class="feature-badges" aria-label="Funktionsgrenzen">
        <span>LOKAL SIMULIERT</span><span>EXTERN DEAKTIVIERT</span><span>KEINE SECRETEINGABE</span>
      </div>
      <div class="core-setup-card">
        <div class="section-heading">
          <div><p class="eyebrow">OS-Keychain</p><h3>Lokalen Sicherheitskern einrichten</h3></div>
          <span id="core-provisioning-status" class="capability-badge">Wird geprüft …</span>
        </div>
        <p>Event-Key und Ed25519-Operator-Key werden ausschließlich durch den nativen macOS-Helper erzeugt. Das Dashboard nimmt keine Schlüssel, Tokens oder Passwörter entgegen.</p>
        <p>Gebundene lokale Operator-ID: <strong id="core-provisioning-operator">wird ermittelt</strong></p>
        <button id="core-provisioning-action" type="button" disabled>Sicherheitskern einmalig im OS-Keychain anlegen</button>
        <p id="core-provisioning-operation" class="operation-status" aria-live="polite"></p>
        <p id="core-provisioning-restart" class="review-package">Die Setup-Grenzen werden geprüft. Diese Instanz aktiviert neue Schlüssel niemals ohne Neustart.</p>
      </div>
      <ol id="phase8-onboarding-steps" class="step-list" aria-live="polite"></ol>
      <div id="phase8-onboarding-details" class="product-grid" aria-live="polite"></div>
      <p id="phase8-guidance" class="review-package">Der lokale Zustand wird geladen …</p>
    </section>

    <section id="phase8-workflow" class="panel phase8-panel">
      <div class="section-heading">
        <div><p class="eyebrow">Ohne YAML oder JSON</p><h2>Geführter vollständiger Demoablauf</h2></div>
        <span id="phase8-stage" class="capability-badge">nicht gestartet</span>
      </div>
      <div class="feature-badges" aria-label="Funktionsgrenzen">
        <span>LOKALER DEMOMODUS</span><span>DETERMINISTISCH</span><span>0 EXTERNE AKTIONEN</span>
      </div>
      <div class="guided-config" aria-label="Sichere lokale Demoauswahl">
        <label for="phase8-testmail-schema">Testmail-Schema
          <select id="phase8-testmail-schema"><option value="plus_addressing_fixture">Plus-Addressing-Fixture</option><option value="subaddress_fixture">Subaddress-Fixture</option></select>
        </label>
        <label for="phase8-ai-provider">AIProvider
          <select id="phase8-ai-provider"><option value="disabled">Deaktiviert (Phase 8)</option></select>
        </label>
        <label for="phase8-program-name">Programmname
          <select id="phase8-program-name"><option value="Local Demo Program">Local Demo Program</option><option value="Local Demo Program Reviewed">Local Demo Program Reviewed</option></select>
        </label>
        <fieldset><legend>Assets</legend>
          <label><input id="phase8-asset-primary" type="checkbox" checked> asset-local-primary</label>
          <label><input id="phase8-exclude-admin" type="checkbox" checked> asset-local-administration ausschließen</label>
        </fieldset>
        <label for="phase8-policy-representation">Policy-Import
          <select id="phase8-policy-representation"><option value="human_readable_text">Lesbarer Policy-Text</option><option value="structured_fixture">Strukturierte Policy-Fixture</option></select>
        </label>
        <label for="phase8-policy-version">Policy-Version
          <select id="phase8-policy-version"><option value="1">Version 1</option></select>
        </label>
        <fieldset><legend>Kampagnenrollen</legend>
          <label><input id="phase8-role-owner" type="checkbox" checked> Owner</label>
          <label><input id="phase8-role-member" type="checkbox" checked> Member</label>
          <label><input id="phase8-role-external" type="checkbox" checked> External</label>
          <p class="muted">Für die feste Baseline/Test/Kontrolltest-Evidence sind Owner, Member und External gemeinsam erforderlich.</p>
        </fieldset>
        <label for="phase8-risk-tier">Risikostufe
          <select id="phase8-risk-tier"><option value="tier_0_offline">Tier 0 · offline</option></select>
        </label>
        <label for="phase8-max-requests">Request-Budget
          <select id="phase8-max-requests"><option value="0">0</option><option value="4">4</option><option value="8" selected>8</option></select>
        </label>
        <label for="phase8-requests-per-minute">Requests pro Minute
          <select id="phase8-requests-per-minute"><option value="0">0</option><option value="1">1</option><option value="2" selected>2</option></select>
        </label>
        <label for="phase8-max-concurrency">Parallelität
          <select id="phase8-max-concurrency"><option value="1">1</option></select>
        </label>
        <label for="phase8-journey-id">Lokale Journey
          <select id="phase8-journey-id"><option value="phase7-local-demo-role-boundary">Phase-7 Local Demo Role Boundary</option></select>
        </label>
        <fieldset><legend>Journey-Rollen</legend>
          <label><input id="phase8-journey-role-owner" type="checkbox" checked> Owner</label>
          <label><input id="phase8-journey-role-member" type="checkbox" checked> Member</label>
          <label><input id="phase8-journey-role-external" type="checkbox" checked> External</label>
          <p class="muted">Der feste Rollengrenzfall benötigt alle drei Demo-Rollen; Teilmengen werden fail-closed blockiert.</p>
        </fieldset>
      </div>
      <div id="phase8-flow" class="workflow-grid" aria-live="polite"></div>
      <div class="button-row">
        <button id="phase8-primary-action" type="button" disabled>Nächsten sicheren Schritt ausführen</button>
        <button id="phase8-edit-program" type="button" disabled>Programmmetadaten bearbeiten</button>
        <button id="phase8-archive-program" class="danger" type="button" disabled>Programm archivieren</button>
        <button id="phase8-start-sessions" type="button" disabled>Lokale Fixture-Sessions starten</button>
        <button id="phase8-pause-campaign" type="button" disabled>Kampagne pausieren</button>
        <button id="phase8-cancel-campaign" class="danger" type="button" disabled>Kampagne abbrechen</button>
      </div>
      <p id="phase8-operation-status" class="operation-status" aria-live="polite"></p>
      <div class="product-grid">
        <article><h3>Programm & Policy</h3><div id="phase8-program"></div></article>
        <article><h3>Vertrag &amp; Budget</h3><div id="phase8-campaign"></div></article>
        <article><h3>Rollen &amp; Sessions</h3><div id="phase8-identities"></div></article>
      </div>
    </section>

    <section id="phase8-journey" class="panel phase8-panel">
      <div class="section-heading"><div><p class="eyebrow">Geschlossenes Profil</p><h2>Lokale Journey</h2></div><span class="capability-badge test-only">PHASE-7-KATALOGGEBUNDEN</span></div>
      <div class="feature-badges"><span>KEINE FREIEN URLS</span><span>KEINE LOCATORS</span><span>KEIN PRODUKT-BROWSERSTART</span></div>
      <div id="phase8-journey-details" class="data-list"></div>
      <div class="button-row">
        <button id="phase8-open-journey-result" type="button" disabled>Journey-Ergebnis öffnen</button>
        <button id="phase8-pause-journey" type="button" disabled>Journey pausieren</button>
        <button id="phase8-cancel-journey" class="danger" type="button" disabled>Journey abbrechen</button>
      </div>
      <pre id="phase8-journey-result-preview" class="result" aria-live="polite">Das lokale Journey-Ergebnis ist noch nicht verfügbar.</pre>
    </section>

    <section id="phase8-inventory" class="panel phase8-panel">
      <div class="section-heading"><div><p class="eyebrow">Scope & Kontrolle</p><h2>Inventory und Ownership</h2></div><span class="capability-badge simulated">LOKAL SIMULIERT</span></div>
      <div id="phase8-inventory-details" class="product-grid"></div>
    </section>

    <section id="phase8-candidates" class="panel phase8-panel">
      <div class="section-heading"><div><p class="eyebrow">Nur Hypothesen</p><h2>Finding-Kandidaten</h2></div><span class="capability-badge simulated">TIER 0 / OFFLINE</span></div>
      <p>Keine aktive Sicherheitsprüfung: Kandidaten werden ausschließlich aus festen lokalen Demo-Metadaten abgeleitet.</p>
      <div id="phase8-candidate-details" class="data-list"></div>
    </section>

    <section id="phase8-evidence" class="panel phase8-panel">
      <div class="section-heading"><div><p class="eyebrow">Redigierte Metadaten</p><h2>Evidence und lokale Reports</h2></div><span class="capability-badge">KEINE EINREICHUNG</span></div>
      <div id="phase8-evidence-details" class="product-grid"></div>
      <div class="button-row">
        <button id="phase8-report-markdown" type="button" disabled>Markdown öffnen</button>
        <button id="phase8-report-html" type="button" disabled>HTML öffnen</button>
        <button id="phase8-report-json" type="button" disabled>JSON öffnen</button>
      </div>
      <pre id="phase8-report-preview" class="result" aria-live="polite">Noch kein lokaler Reportentwurf.</pre>
    </section>

    <section id="phase8-product-status" class="panel phase8-panel">
      <div class="section-heading"><div><p class="eyebrow">Zentrale Readiness</p><h2>Produktstatus</h2></div><span id="phase8-runtime-state" class="capability-badge">FAIL-CLOSED</span></div>
      <div id="phase8-runtime-details" class="product-grid" aria-live="polite"></div>
    </section>

    ${HACKERONE_DASHBOARD_HTML}

    ${ACTIVE_TESTING_DASHBOARD_HTML}

    <section id="programs" class="panel">
      <div class="section-heading"><div><p class="eyebrow">Registry</p><h2>Programme</h2></div></div>
      <div class="two-column">
        <div>
          <h3>Expertenimport (optional)</h3>
          <p class="muted">Der geführte Demoablauf oben benötigt keine manuelle JSON- oder YAML-Bearbeitung.</p>
          <label for="import-format">Format</label>
          <select id="import-format"><option value="json">JSON</option><option value="yaml">YAML</option></select>
          <label for="import-source">Lokaler Dateiinhalt</label>
          <textarea id="import-source" rows="14" spellcheck="false"></textarea>
          <button id="import-program" type="button">Programm lokal importieren</button>
          <p id="import-status" class="operation-status" aria-live="polite"></p>
        </div>
        <div id="program-list" class="data-list" aria-live="polite"></div>
      </div>
    </section>

    <section id="policies" class="panel">
      <div class="section-heading"><div><p class="eyebrow">Versionierung & Drift</p><h2>Policies und Änderungen</h2></div></div>
      <div id="policy-list" class="data-list"></div>
      <h3>Änderungsansicht</h3>
      <div id="policy-diff-list" class="data-list"></div>
    </section>

    <section id="campaigns" class="panel">
      <div class="section-heading"><div><p class="eyebrow">Verträge</p><h2>Kampagnen</h2></div></div>
      <div id="campaign-list" class="data-list"></div>
    </section>

    <section id="approvals" class="panel">
      <div class="section-heading"><div><p class="eyebrow">Human-in-the-loop</p><h2>Aktionen erforderlich</h2></div></div>
      <div id="approval-list" class="data-list"></div>
    </section>

    <section id="identities" class="panel">
      <div class="section-heading"><div><p class="eyebrow">Lokale Fixtures</p><h2>Testidentitäten</h2></div></div>
      <div id="identity-list" class="data-list"></div>
    </section>

    <section id="objects" class="panel">
      <div class="section-heading"><div><p class="eyebrow">Ownership</p><h2>Eigene Testobjekte</h2></div></div>
      <div id="object-list" class="data-list"></div>
    </section>

    <section id="reports" class="panel">
      <div class="section-heading"><div><p class="eyebrow">Nur Entwürfe</p><h2>Reports und Report-Entwürfe</h2></div></div>
      <div id="report-list" class="data-list"></div>
    </section>

    <section id="system" class="panel">
      <div class="section-heading"><div><p class="eyebrow">Fail-closed</p><h2>Systemstatus und globaler Kill Switch</h2></div></div>
      <div class="kill-card">
        <div><p class="eyebrow">Aktueller Zustand</p><strong id="kill-status" class="large-status">UNBEKANNT</strong></div>
        <div class="button-row">
          <button id="engage-kill" class="danger" type="button">Kill Switch aktivieren</button>
          <button id="clear-kill" type="button">Kill Switch ausdrücklich freigeben</button>
        </div>
      </div>
      <p id="kill-operation-status" class="operation-status" aria-live="polite"></p>

      <div class="simulation-card">
        <h3>Vollständige lokale Simulation</h3>
        <p>Prüfe das versions- und hashgebundene Review-Paket. Die Kontrollpunkte werden anschließend nur in der vorgegebenen Reihenfolge freigeschaltet; es wird nichts extern eingereicht.</p>
        <div id="simulation-review" class="review-package" aria-live="polite">Review-Paket wird geladen …</div>
        <label for="simulation-actor">Lokaler Akteur</label>
        <input id="simulation-actor" value="" autocomplete="off">
        <div class="confirmation-grid">
          <label><input id="confirm-clearKillSwitch" type="checkbox" disabled> Kill Switch für diesen lokalen Lauf freigeben</label>
          <label><input id="confirm-acceptPolicyV1" type="checkbox" disabled> Angezeigte Policy Version 1 samt Hash lokal akzeptieren</label>
          <label><input id="confirm-approveCampaignV1" type="checkbox" disabled> Angezeigten Kampagnenvertrag Version 1 freigeben</label>
          <label><input id="confirm-acceptPolicyV2" type="checkbox" disabled> Angezeigte Policy Version 2 nach geprüftem Drift-Diff akzeptieren</label>
          <label><input id="confirm-approveCampaignV2" type="checkbox" disabled> Angezeigten Kampagnenvertrag Version 2 freigeben</label>
          <label><input id="confirm-queueReportReview" type="checkbox" disabled> Report ausschließlich zur lokalen menschlichen Prüfung einreihen</label>
        </div>
        <button id="run-simulation" type="button" disabled>18-Schritte-Simulation starten</button>
        <pre id="simulation-result" class="result" aria-live="polite"></pre>
      </div>
    </section>

    <section id="expert" class="panel">
      <div class="section-heading"><div><p class="eyebrow">Diagnose</p><h2>Expertenansicht</h2></div></div>
      <div class="expert-grid">
        <article><h3>Policy-Entscheidungen</h3><div id="expert-policy"></div></article>
        <article><h3>Audit-Log</h3><div id="expert-audit"></div></article>
        <article><h3>Request-Budgets</h3><div id="expert-budgets"></div></article>
        <article><h3>Ownership Ledger</h3><div id="expert-ownership"></div></article>
        <article><h3>Adapterstatus</h3><div id="expert-adapters"></div></article>
        <article><h3>Event Store</h3><div id="expert-event-store"></div></article>
        <article><h3>Konfigurationsdiagnose</h3><div id="expert-config"></div></article>
      </div>
    </section>
  </main>

  <footer>Lokale Phase-2-Control-Plane · keine realen Plattform- oder Bug-Bounty-Verbindungen</footer>
</body>
</html>`;

export const DASHBOARD_CSS = `
:root {
  color-scheme: dark;
  --bg: #07111f;
  --panel: rgba(15, 29, 49, 0.9);
  --panel-2: #132844;
  --line: #294562;
  --text: #eef7ff;
  --muted: #9db1c5;
  --cyan: #4ce3d7;
  --amber: #ffc862;
  --red: #ff7383;
  --blue: #79a9ff;
  --shadow: 0 18px 45px rgba(0, 0, 0, 0.24);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--text);
  background:
    radial-gradient(circle at 15% -5%, rgba(76, 227, 215, 0.16), transparent 36rem),
    radial-gradient(circle at 95% 10%, rgba(121, 169, 255, 0.12), transparent 32rem),
    var(--bg);
}
.masthead {
  position: sticky;
  top: 0;
  z-index: 10;
  padding: 1.25rem max(1.25rem, calc((100vw - 1240px) / 2));
  border-bottom: 1px solid var(--line);
  background: rgba(7, 17, 31, 0.94);
  backdrop-filter: blur(18px);
}
.brand-row, .section-heading, .kill-card, .button-row, .status-strip {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}
h1, h2, h3, p { margin-top: 0; }
h1 { margin-bottom: 0; font-size: clamp(1.45rem, 3vw, 2.15rem); letter-spacing: -0.04em; }
h2 { margin-bottom: 0; font-size: 1.5rem; letter-spacing: -0.02em; }
h3 { margin-bottom: 0.65rem; font-size: 1rem; }
.eyebrow { margin-bottom: 0.25rem; color: var(--cyan); font-size: 0.72rem; font-weight: 800; letter-spacing: 0.13em; text-transform: uppercase; }
.muted { color: var(--muted); }
.banner-stack { display: grid; gap: 0.35rem; text-align: right; }
.banner { padding: 0.35rem 0.65rem; border: 1px solid; border-radius: 999px; font-size: 0.68rem; letter-spacing: 0.08em; }
.banner.simulation { color: var(--cyan); border-color: rgba(76, 227, 215, 0.6); background: rgba(76, 227, 215, 0.08); }
.banner.disabled { color: var(--amber); border-color: rgba(255, 200, 98, 0.6); background: rgba(255, 200, 98, 0.08); }
.phase8-panel { border-color: rgba(121, 169, 255, 0.38); }
.feature-badges { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0.8rem 0; }
.feature-badges span, .capability-badge { display: inline-flex; width: fit-content; padding: 0.28rem 0.55rem; border: 1px solid rgba(255, 200, 98, 0.55); border-radius: 999px; color: var(--amber); background: rgba(255, 200, 98, 0.07); font-size: 0.68rem; font-weight: 800; letter-spacing: 0.05em; }
.capability-badge.simulated { color: var(--cyan); border-color: rgba(76, 227, 215, 0.55); background: rgba(76, 227, 215, 0.07); }
.capability-badge.test-only { color: var(--blue); border-color: rgba(121, 169, 255, 0.55); background: rgba(121, 169, 255, 0.07); }
.step-list { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.55rem; padding: 0; list-style: none; }
.step-list li { padding: 0.65rem; border: 1px solid var(--line); border-radius: 0.6rem; color: var(--muted); background: rgba(9, 24, 41, 0.72); font-size: 0.78rem; }
.step-list li.done { color: var(--cyan); border-color: rgba(76, 227, 215, 0.5); }
.step-list li.current { color: var(--text); border-color: var(--blue); box-shadow: inset 3px 0 var(--blue); }
.guided-config { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.65rem; margin: 1rem 0; padding: 0.8rem; border: 1px solid var(--line); border-radius: 0.75rem; background: rgba(9, 24, 41, 0.55); }
.guided-config label { margin: 0; }
.guided-config fieldset { min-width: 0; margin: 0; border: 1px solid var(--line); border-radius: 0.6rem; }
.guided-config legend { color: var(--muted); font-size: 0.76rem; }
.guided-config fieldset label { display: flex; align-items: center; gap: 0.4rem; margin: 0.35rem 0; }
.guided-config input[type="checkbox"] { width: auto; accent-color: var(--cyan); }
.workflow-grid { display: grid; grid-template-columns: repeat(7, minmax(100px, 1fr)); gap: 0.45rem; margin: 1rem 0; overflow-x: auto; }
.workflow-step { min-width: 100px; padding: 0.65rem; border: 1px solid var(--line); border-radius: 0.6rem; color: var(--muted); background: rgba(9, 24, 41, 0.72); font-size: 0.72rem; }
.workflow-step.done { color: var(--cyan); border-color: rgba(76, 227, 215, 0.5); }
.workflow-step.current { color: var(--text); border-color: var(--blue); }
.product-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.75rem; margin-top: 1rem; }
.product-grid article { min-width: 0; padding: 0.9rem; border: 1px solid var(--line); border-radius: 0.72rem; background: rgba(9, 24, 41, 0.75); }
.product-grid p { margin: 0.32rem 0; color: var(--muted); font-size: 0.78rem; overflow-wrap: anywhere; }
nav { display: flex; gap: 0.4rem; margin-top: 1rem; overflow-x: auto; padding-bottom: 0.1rem; }
nav a { flex: 0 0 auto; color: var(--muted); text-decoration: none; padding: 0.4rem 0.65rem; border-radius: 0.5rem; font-size: 0.82rem; }
nav a:hover, nav a:focus-visible { color: var(--text); background: var(--panel-2); outline: none; }
main { width: min(1240px, calc(100% - 2rem)); margin: 2rem auto 4rem; display: grid; gap: 1.2rem; }
.panel { scroll-margin-top: 10rem; padding: clamp(1rem, 2.5vw, 1.6rem); border: 1px solid var(--line); border-radius: 1rem; background: var(--panel); box-shadow: var(--shadow); }
.hero-panel { border-color: rgba(76, 227, 215, 0.35); }
.metric-grid { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 0.75rem; margin: 1.25rem 0; }
.metric { padding: 1rem; border: 1px solid var(--line); border-radius: 0.8rem; background: rgba(19, 40, 68, 0.65); }
.metric span { color: var(--cyan); font-size: 1.8rem; font-weight: 850; }
.metric p { margin: 0.25rem 0 0; color: var(--muted); font-size: 0.78rem; }
.status-strip { align-items: stretch; }
.status-strip p { flex: 1; margin: 0; padding: 0.75rem; border-left: 2px solid var(--blue); background: rgba(121, 169, 255, 0.06); }
.two-column { display: grid; grid-template-columns: minmax(280px, 0.85fr) minmax(0, 1.5fr); gap: 1.25rem; margin-top: 1.25rem; }
label { display: block; margin: 0.65rem 0 0.35rem; color: var(--muted); font-size: 0.82rem; }
input, select, textarea, button { font: inherit; }
input, select, textarea { width: 100%; border: 1px solid var(--line); border-radius: 0.6rem; color: var(--text); background: #091829; padding: 0.72rem; }
textarea { resize: vertical; min-height: 12rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.76rem; line-height: 1.45; }
button { margin-top: 0.8rem; border: 1px solid rgba(76, 227, 215, 0.6); border-radius: 0.6rem; color: #03201e; background: var(--cyan); padding: 0.65rem 0.9rem; font-weight: 800; cursor: pointer; }
button:hover:not(:disabled), button:focus-visible:not(:disabled) { filter: brightness(1.08); transform: translateY(-1px); }
button:disabled { cursor: not-allowed; opacity: 0.45; }
button.danger { color: #2d050b; border-color: var(--red); background: var(--red); }
.button-row { justify-content: flex-start; flex-wrap: wrap; }
.data-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 0.7rem; margin-top: 1rem; }
.data-item, .expert-grid article { min-width: 0; padding: 0.9rem; border: 1px solid var(--line); border-radius: 0.72rem; background: rgba(9, 24, 41, 0.75); }
.data-item p, .expert-grid p { margin: 0.32rem 0; color: var(--muted); font-size: 0.78rem; overflow-wrap: anywhere; }
.data-item strong { color: var(--text); }
.empty { color: var(--muted); font-style: italic; }
.kill-card, .simulation-card { margin-top: 1rem; padding: 1rem; border: 1px solid var(--line); border-radius: 0.8rem; background: rgba(9, 24, 41, 0.82); }
.core-setup-card { margin: 1rem 0; padding: 1rem; border: 1px solid rgba(76, 227, 215, 0.35); border-radius: 0.8rem; background: rgba(9, 24, 41, 0.82); }
.core-setup-card .section-heading { margin-bottom: 0.5rem; }
.large-status { color: var(--amber); font-size: 1.45rem; }
.simulation-card { margin-top: 1.2rem; }
.review-package { margin: 0.8rem 0; padding: 0.8rem; border-left: 3px solid var(--cyan); border-radius: 0.4rem; color: var(--muted); background: rgba(76, 227, 215, 0.06); white-space: pre-wrap; overflow-wrap: anywhere; }
.confirmation-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.45rem 1rem; margin: 1rem 0; }
.confirmation-grid label { display: flex; align-items: flex-start; gap: 0.55rem; margin: 0; padding: 0.65rem; border: 1px solid var(--line); border-radius: 0.55rem; background: rgba(19, 40, 68, 0.45); }
.confirmation-grid input { width: auto; margin-top: 0.15rem; accent-color: var(--cyan); }
.result { min-height: 3rem; max-height: 22rem; overflow: auto; margin: 1rem 0 0; padding: 0.8rem; border-radius: 0.6rem; color: var(--cyan); background: #050e19; white-space: pre-wrap; }
.operation-status { min-height: 1.2rem; margin: 0.65rem 0 0; color: var(--cyan); }
.expert-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.75rem; margin-top: 1rem; }
footer { padding: 2rem; border-top: 1px solid var(--line); color: var(--muted); text-align: center; font-size: 0.78rem; }
@media (max-width: 950px) {
  .metric-grid { grid-template-columns: repeat(3, 1fr); }
  .two-column, .expert-grid { grid-template-columns: 1fr; }
  .guided-config { grid-template-columns: 1fr 1fr; }
  .product-grid { grid-template-columns: 1fr 1fr; }
  .step-list { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 620px) {
  .brand-row, .section-heading, .kill-card, .status-strip { align-items: flex-start; flex-direction: column; }
  .banner-stack { text-align: left; }
  .metric-grid, .confirmation-grid { grid-template-columns: 1fr 1fr; }
  .product-grid, .step-list, .guided-config { grid-template-columns: 1fr; }
  main { width: min(100% - 1rem, 1240px); margin-top: 0.75rem; }
}
`;

export const DASHBOARD_JAVASCRIPT = `
"use strict";
(function () {
  var csrfToken = "";
  var reviewDigest = "";
  var confirmationTimes = {};
  var operatorAvailable = false;
  var secureCoreReady = false;
  var secureSimulationAvailable = false;
  var coreProvisioningChallenge = null;
  var lastConfirmationMillis = 0;
  var serverGeneratedMillis = 0;
  var confirmationNames = [
    "clearKillSwitch",
    "acceptPolicyV1",
    "approveCampaignV1",
    "acceptPolicyV2",
    "approveCampaignV2",
    "queueReportReview"
  ];

  function element(id) {
    var found = document.getElementById(id);
    if (!found) throw new Error("UI_ELEMENT_MISSING:" + id);
    return found;
  }

  function setText(id, value) {
    element(id).textContent = String(value);
  }

  function makeItem(title, lines) {
    var item = document.createElement("article");
    item.className = "data-item";
    var heading = document.createElement("h3");
    heading.textContent = title;
    item.appendChild(heading);
    lines.forEach(function (line) {
      var paragraph = document.createElement("p");
      paragraph.textContent = line;
      item.appendChild(paragraph);
    });
    return item;
  }

  function renderList(id, values, describe) {
    var container = element(id);
    var nodes = [];
    values.forEach(function (value) {
      var description = describe(value);
      nodes.push(makeItem(description.title, description.lines));
    });
    if (nodes.length === 0) {
      var empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = "Noch keine lokalen Datensätze.";
      nodes.push(empty);
    }
    container.replaceChildren.apply(container, nodes);
  }

  function renderExpert(id, lines) {
    var container = element(id);
    var nodes = lines.map(function (line) {
      var paragraph = document.createElement("p");
      paragraph.textContent = line;
      return paragraph;
    });
    container.replaceChildren.apply(container, nodes);
  }

  function renderApprovals(values) {
    var container = element("approval-list");
    var nodes = [];
    values.forEach(function (record) {
      var item = makeItem(record.summary, [
        "Typ: " + record.kind + " · Status: " + record.status,
        "Technische Details: " + record.technicalDetails,
        "Policy: " + (record.policyVersion === null ? "keine" : "v" + record.policyVersion + " / " + record.policyHash),
        record.impact,
        "Audit: " + record.auditReference,
        "Payload-Hash: " + record.payloadHash,
        "Entscheidung: " + (record.decidedAt === null ? "ausstehend" : record.decidedBy + " um " + record.decidedAt + " / " + record.userAction)
      ]);
      if (record.status === "open" && operatorAvailable && secureCoreReady) {
        var accept = document.createElement("button");
        accept.type = "button";
        accept.textContent = "Ausdrücklich akzeptieren";
        accept.addEventListener("click", function () {
          void decideApproval(record, "accepted");
        });
        var reject = document.createElement("button");
        reject.type = "button";
        reject.className = "danger";
        reject.textContent = "Ablehnen";
        reject.addEventListener("click", function () {
          void decideApproval(record, "rejected");
        });
        item.appendChild(accept);
        item.appendChild(reject);
      }
      nodes.push(item);
    });
    if (nodes.length === 0) {
      var empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = "Noch keine lokalen Datensätze.";
      nodes.push(empty);
    }
    container.replaceChildren.apply(container, nodes);
  }

  function render(state) {
    csrfToken = state.csrfToken;
    operatorAvailable = state.operatorAuthentication.signerConfigured === true;
    secureCoreReady = state.runtimeReadiness.ready === true;
    secureSimulationAvailable = state.simulationAvailable === true;
    renderCoreProvisioning(state);
    reviewDigest = state.simulationReview.reviewDigest;
    serverGeneratedMillis = Date.parse(state.generatedAt);
    element("simulation-actor").value = state.operatorAuthentication.operatorId || "local-operator";
    element("simulation-actor").readOnly = state.operatorAuthentication.signerConfigured;
    element("clear-kill").disabled = !operatorAvailable || !secureCoreReady;
    element("import-program").disabled = !secureCoreReady;
    setText("count-programs", state.counts.programs);
    setText("count-active-campaigns", state.counts.activeCampaigns);
    setText("count-paused-campaigns", state.counts.pausedCampaigns);
    setText("count-open-approvals", state.counts.openApprovals);
    setText("count-privacy-alerts", state.counts.privacyAlerts);
    setText("count-reports", state.counts.reportDrafts);
    setText("simulation-status", state.simulationStatus);
    setText("phase1-status", state.phase1SecurityStatus);
    setText("last-refresh", "Stand: " + state.generatedAt);
    setText("kill-status", state.killSwitch.active ? "AKTIV / BLOCKIERT" : "FREIGEGEBEN");
    setText("overview-kill-status", state.killSwitch.active ? "aktiv" : "frei");
    setText(
      "simulation-review",
      "Review-Digest: " + state.simulationReview.reviewDigest +
      "\\nPolicy v1: " + state.simulationReview.policyV1.hash +
      " · Assets " + state.simulationReview.policyV1.allowedAssets.join(", ") +
      " · ausgeschlossen " + state.simulationReview.policyV1.excludedAssets.join(", ") +
      " · erlaubte Klassen " + state.simulationReview.policyV1.allowedTestClasses.join(", ") +
      " · verbotene Klassen " + state.simulationReview.policyV1.forbiddenTestClasses.join(", ") +
      " · Regeln " + state.simulationReview.policyV1.rules.join(", ") +
      " · Limit " + state.simulationReview.policyV1.requestLimits.maxRequestsTotal +
      "\\nKampagne v1: Digest " + state.simulationReview.campaignV1.approvalDigest +
      " · Hosts " + state.simulationReview.campaignV1.contract.allowedHosts.join(", ") +
      " · ausgeschlossen " + state.simulationReview.campaignV1.contract.excludedHosts.join(", ") +
      " · Methoden " + state.simulationReview.campaignV1.contract.allowedMethods.join(", ") +
      " · Konten " + state.simulationReview.campaignV1.accountRefs.join(", ") +
      " · Aktionen " + state.simulationReview.campaignV1.allowedActionClasses.join(", ") +
      " · Limits " + state.simulationReview.campaignV1.contract.maxRequests + "/" + state.simulationReview.campaignV1.contract.requestsPerMinute +
      " · Write " + state.simulationReview.campaignV1.contract.writeActionsAllowed +
      " · Rollback " + state.simulationReview.campaignV1.contract.rollbackRequired +
      " · Checkpoints " + state.simulationReview.campaignV1.contract.humanCheckpoints.join(", ") +
      " · Gueltigkeit " + state.simulationReview.campaignV1.contract.validFrom + " bis " + state.simulationReview.campaignV1.contract.validUntil +
      "\\nPolicy-Drift: " + state.simulationReview.policyDiff.changedRequestLimits.join(", ") +
      " · neue Verbote " + state.simulationReview.policyDiff.newlyForbiddenTestClasses.join(", ") +
      " · neue Freigaben " + state.simulationReview.policyDiff.newlyAllowedTestClasses.join(", ") +
      " · Regeln hinzugefuegt " + state.simulationReview.policyDiff.changedRulesAdded.join(", ") +
      " · Regeln entfernt " + state.simulationReview.policyDiff.changedRulesRemoved.join(", ") +
      "\\nPolicy v2: " + state.simulationReview.policyV2.hash +
      " · Assets " + state.simulationReview.policyV2.allowedAssets.join(", ") +
      " · ausgeschlossen " + state.simulationReview.policyV2.excludedAssets.join(", ") +
      " · erlaubte Klassen " + state.simulationReview.policyV2.allowedTestClasses.join(", ") +
      " · verbotene Klassen " + state.simulationReview.policyV2.forbiddenTestClasses.join(", ") +
      " · Regeln " + state.simulationReview.policyV2.rules.join(", ") +
      " · Limit " + state.simulationReview.policyV2.requestLimits.maxRequestsTotal +
      " · unklar " + state.simulationReview.policyV2.unclearRules.join(", ") +
      "\\nKampagne v2: Digest " + state.simulationReview.campaignV2.approvalDigest +
      " · Hosts " + state.simulationReview.campaignV2.contract.allowedHosts.join(", ") +
      " · ausgeschlossen " + state.simulationReview.campaignV2.contract.excludedHosts.join(", ") +
      " · Methoden " + state.simulationReview.campaignV2.contract.allowedMethods.join(", ") +
      " · Konten " + state.simulationReview.campaignV2.accountRefs.join(", ") +
      " · Aktionen " + state.simulationReview.campaignV2.allowedActionClasses.join(", ") +
      " · Limits " + state.simulationReview.campaignV2.contract.maxRequests + "/" + state.simulationReview.campaignV2.contract.requestsPerMinute +
      " · Write " + state.simulationReview.campaignV2.contract.writeActionsAllowed +
      " · Rollback " + state.simulationReview.campaignV2.contract.rollbackRequired +
      " · Checkpoints " + state.simulationReview.campaignV2.contract.humanCheckpoints.join(", ") +
      " · Gueltigkeit " + state.simulationReview.campaignV2.contract.validFrom + " bis " + state.simulationReview.campaignV2.contract.validUntil +
      "\\nReport-Aktion: nur lokale Review-Warteschlange, keine Einreichung" +
      "\\n\\nVollstaendiges hashgebundenes Review-Paket:\\n" + JSON.stringify(state.simulationReview, null, 2)
    );

    renderList("program-list", state.programs, function (record) {
      return {
        title: record.name,
        lines: [
          "ID: " + record.id,
          "Plattform: " + record.platform + " · Status: " + record.lifecycle,
          "Policy: " + (record.currentPolicyVersion === null ? "ausstehend" : "v" + record.currentPolicyVersion),
          "Regelannahme: " + record.ruleAcceptanceStatus,
          "Assets: " + record.allowedAssets.join(", ")
        ]
      };
    });
    renderList("policy-list", state.policies, function (record) {
      return {
        title: record.programId + " · v" + record.version,
        lines: [
          "Hash: " + record.policyHash,
          "Annahme: " + (record.acceptedBy === null ? "ausstehend" : "durch " + record.acceptedBy),
          "Request-Limit: " + record.requestLimits.maxRequestsTotal,
          "Verboten: " + record.forbiddenTestClasses.join(", "),
          "Unklar: " + record.unclearRules.join(", ")
        ]
      };
    });
    renderList("policy-diff-list", state.policyDiffs, function (record) {
      return {
        title: record.programId + " · v" + record.fromVersion + " → v" + record.toVersion,
        lines: [
          "Hinzugefügte Assets: " + record.addedAssets.join(", "),
          "Entfernte Assets: " + record.removedAssets.join(", "),
          "Neue Verbote: " + record.newlyForbiddenTestClasses.join(", "),
          "Neue Freigaben: " + record.newlyAllowedTestClasses.join(", "),
          "Geänderte Limits: " + record.changedRequestLimits.join(", "),
          "Sonstige Regeln hinzugefügt: " + record.changedRules.added.join(", "),
          "Sonstige Regeln entfernt: " + record.changedRules.removed.join(", "),
          "Unklare Regeln: " + record.unclearRules.join(", ")
        ]
      };
    });
    renderList("campaign-list", state.campaigns, function (record) {
      return {
        title: record.id,
        lines: [
          "Status: " + record.state,
          "Programm: " + record.programId + " · Policy v" + record.policyVersion,
          "Budget: " + record.maxRequests + " gesamt / " + record.requestsPerMinute + " pro Minute",
          "Parallelität: " + record.maxConcurrency,
          "Freigabe: " + (record.humanApprovedBy === null ? "ausstehend" : record.humanApprovedBy)
        ]
      };
    });
    renderApprovals(state.approvals);
    renderList("identity-list", state.identities, function (record) {
      return {
        title: record.id + " · " + record.role,
        lines: [
          "Status: " + record.status,
          "Programm: " + record.programId,
          "Organisation: " + (record.organizationRef || "nicht zugeordnet"),
          "Menschliche Aktion: " + (record.humanActionRequired ? "erforderlich" : "nein")
        ]
      };
    });
    renderList("object-list", state.ownedObjects, function (record) {
      return {
        title: record.objectRef,
        lines: [
          "Status: " + record.status + " · Typ: " + record.objectType,
          "Kampagne: " + record.campaignId,
          "Account: " + record.accountId,
          "Aktionen: " + record.allowedActions.join(", "),
          "Ablauf: " + record.expiresAt
        ]
      };
    });
    renderList("report-list", state.reports, function (record) {
      return {
        title: record.title,
        lines: [
          "Status: " + record.status,
          "Kampagne: " + record.campaignId,
          record.summary,
          "Extern eingereicht: nein"
        ]
      };
    });

    renderExpert("expert-policy", state.expert.policyDecisions);
    renderExpert("expert-audit", state.expert.auditLog);
    renderExpert("expert-budgets", state.expert.requestBudgets);
    renderExpert("expert-ownership", state.expert.ownershipLedger);
    renderExpert("expert-adapters", state.expert.adapterStatus);
    renderExpert("expert-event-store", state.expert.eventStore);
    renderExpert("expert-config", state.expert.configurationDiagnosis);
    updateConfirmationFlow();

    if (state.simulationStatus === "completed") element("run-simulation").disabled = true;
  }

  function renderCoreProvisioning(state) {
    var core = state.coreProvisioning;
    var button = element("core-provisioning-action");
    coreProvisioningChallenge = null;
    if (!core || core.version !== 1 || core.secretInputAccepted !== false) {
      button.disabled = true;
      setText("core-provisioning-status", "FAIL-CLOSED");
      setText("core-provisioning-operator", "nicht verfügbar");
      setText("core-provisioning-restart", "Blockiert: Der lokale Provisionierungsstatus ist ungültig.");
      return;
    }
    setText("core-provisioning-status", core.status.toUpperCase());
    setText("core-provisioning-operator", core.operatorId || "nicht verfügbar");
    if (
      core.canProvision === true &&
      core.status === "ready" &&
      core.challenge &&
      typeof core.challenge.nonce === "string" &&
      typeof core.challenge.contextDigestSha256 === "string"
    ) {
      coreProvisioningChallenge = core.challenge;
      button.disabled = false;
      button.textContent = core.proposedMode === "legacy_complete"
        ? "Vorhandenen Event-Key sicher vervollständigen"
        : "Sicherheitskern einmalig im OS-Keychain anlegen";
      setText(
        "core-provisioning-restart",
        "Bereit: Ein Klick erzeugt die Schlüssel lokal im OS-Keychain. Es werden keine Secretfelder übertragen. Danach bleibt diese Instanz gesperrt und muss beendet werden."
      );
      return;
    }
    button.disabled = true;
    if (core.restartRequired === true || core.status === "restart_required") {
      setText(
        "core-provisioning-restart",
        "Provisionierung abgeschlossen. Diese laufende Instanz bleibt fail-closed. App beenden, BUGBOUNTY_EVENT_KEY_MIN_VERSION=1 konfigurieren und anschließend mit pnpm app neu starten."
      );
      return;
    }
    if (
      core.status === "configured" &&
      state.runtimeReadiness.eventKeyMinimumVersionStatus !== "ready"
    ) {
      setText(
        "core-provisioning-restart",
        "Schlüssel sind im OS-Keychain vorhanden. BUGBOUNTY_EVENT_KEY_MIN_VERSION muss ausdrücklich gesetzt sein; danach die App mit pnpm app neu starten."
      );
      return;
    }
    setText(
      "core-provisioning-restart",
      "Keine Provisionierung möglich: " + core.reasonCode + ". Der Sicherheitskern bleibt gesperrt."
    );
  }

  async function readJson(response) {
    var body = await response.json();
    if (!response.ok) throw new Error(body.error || "DASHBOARD_REQUEST_FAILED");
    return body;
  }

  async function loadState() {
    var response = await fetch("/api/state", {
      method: "GET",
      cache: "no-store",
      credentials: "same-origin",
      headers: { "accept": "application/json" }
    });
    var nextState = await readJson(response);
    window.dispatchEvent(new CustomEvent("bugbounty:dashboard-state", { detail: nextState }));
  }

  async function postJson(path, payload) {
    var response = await fetch(path, {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      headers: {
        "accept": "application/json",
        "content-type": "application/json",
        "x-csrf-token": csrfToken
      },
      body: JSON.stringify(payload)
    });
    return readJson(response);
  }

  async function decideApproval(record, decision) {
    setText("simulation-result", "Lokale Freigabeentscheidung wird geprüft …");
    try {
      await postJson("/api/approvals/decide", {
        id: record.id,
        expectedRevision: record.revision,
        expectedPayloadHash: record.payloadHash,
        decision: decision,
        actor: actor(),
        userAction: "explicit_local_dashboard_" + decision
      });
      setText("simulation-result", "Freigabe wurde lokal " + (decision === "accepted" ? "akzeptiert." : "abgelehnt."));
      await loadState();
    } catch (error) {
      setText("simulation-result", "Blockiert: " + (error instanceof Error ? error.message : "UNKNOWN"));
    }
  }

  function confirmationsComplete() {
    return confirmationNames.every(function (name) {
      return element("confirm-" + name).checked;
    });
  }

  function confirmationPayload() {
    var values = {};
    confirmationNames.forEach(function (name) {
      values[name] = element("confirm-" + name).checked;
    });
    return values;
  }

  function confirmationTimesPayload() {
    var values = {};
    confirmationNames.forEach(function (name) {
      values[name] = confirmationTimes[name];
    });
    return values;
  }

  function updateConfirmationFlow() {
    confirmationNames.forEach(function (name, index) {
      var input = element("confirm-" + name);
      input.disabled = index === 0
        ? reviewDigest.length !== 64 || !operatorAvailable || !secureSimulationAvailable
        : !element("confirm-" + confirmationNames[index - 1]).checked;
    });
    element("run-simulation").disabled = !confirmationsComplete() || reviewDigest.length !== 64 || !operatorAvailable || !secureSimulationAvailable;
  }

  function actor() {
    return element("simulation-actor").value.trim();
  }

  function sampleProgram() {
    return {
      id: "program-ui-import",
      name: "Lokales UI-Programm",
      platform: "local_mock",
      status: "available",
      description: "Nur lokaler Dashboard-Import",
      program_url: "http://127.0.0.1/local-metadata-only",
      program_type: "simulation",
      allowed_assets: ["ui.demo.local"],
      excluded_assets: ["admin.ui.demo.local"],
      last_synchronized_at: null,
      automation_permission: "allowed",
      notes: "Diese URL wird nie aufgerufen.",
      lifecycle: "active"
    };
  }

  element("import-source").value = JSON.stringify(sampleProgram(), null, 2);
  confirmationNames.forEach(function (name) {
    element("confirm-" + name).addEventListener("change", function () {
      var index = confirmationNames.indexOf(name);
      if (element("confirm-" + name).checked) {
        var now = Math.max(serverGeneratedMillis, lastConfirmationMillis + 1);
        lastConfirmationMillis = now;
        confirmationTimes[name] = new Date(now).toISOString();
      } else {
        confirmationNames.slice(index).forEach(function (laterName) {
          element("confirm-" + laterName).checked = false;
          delete confirmationTimes[laterName];
        });
      }
      updateConfirmationFlow();
    });
  });
  updateConfirmationFlow();

  element("import-program").addEventListener("click", async function () {
    setText("import-status", "Import läuft …");
    try {
      var imported = await postJson("/api/programs/import", {
        format: element("import-format").value,
        source: element("import-source").value
      });
      setText("import-status", "Importiert: " + imported.program.id);
      await loadState();
    } catch (error) {
      setText("import-status", "Blockiert: " + (error instanceof Error ? error.message : "UNKNOWN"));
    }
  });

  element("core-provisioning-action").addEventListener("click", async function () {
    var challenge = coreProvisioningChallenge;
    var button = element("core-provisioning-action");
    if (!challenge) return;
    coreProvisioningChallenge = null;
    button.disabled = true;
    setText("core-provisioning-operation", "Native lokale Provisionierung wird geprüft …");
    try {
      var result = await postJson("/api/core/provision", {
        version: 1,
        confirmation: "provision_local_security_core",
        nonce: challenge.nonce,
        contextDigestSha256: challenge.contextDigestSha256
      });
      if (!result.coreProvisioning || result.coreProvisioning.restartRequired !== true)
        throw new Error("CORE_PROVISIONING_RESPONSE_INVALID");
      setText("core-provisioning-operation", "Lokal provisioniert. Vor dem Neustart bleibt alles gesperrt.");
      await loadState();
    } catch (error) {
      setText("core-provisioning-operation", "Fail-closed blockiert: " + (error instanceof Error ? error.message : "UNKNOWN"));
      await loadState().catch(function () {});
    }
  });

  element("run-simulation").addEventListener("click", async function () {
    var button = element("run-simulation");
    button.disabled = true;
    setText("simulation-result", "Simulation läuft ausschließlich lokal …");
    try {
      var summary = await postJson("/api/simulation/run", {
        actor: actor(),
        confirmations: confirmationPayload(),
        confirmationTimes: confirmationTimesPayload(),
        reviewDigest: reviewDigest
      });
      setText(
        "simulation-result",
        "Simulation abgeschlossen: " + summary.steps.length + " Schritte\\n" + summary.steps.join("\\n") + "\\nExterne Einreichungen: " + summary.externalSubmissions
      );
      await loadState();
    } catch (error) {
      setText("simulation-result", "Blockiert: " + (error instanceof Error ? error.message : "UNKNOWN"));
      button.disabled = !confirmationsComplete();
    }
  });

  async function changeKillSwitch(path, label) {
    setText("kill-operation-status", label + " …");
    try {
      var result = await postJson(path, { actor: actor(), confirmed: true });
      setText("kill-operation-status", result.active ? "Kill Switch ist aktiv." : "Kill Switch wurde ausdrücklich lokal freigegeben.");
      await loadState();
    } catch (error) {
      setText("kill-operation-status", "Blockiert: " + (error instanceof Error ? error.message : "UNKNOWN"));
    }
  }

  element("engage-kill").addEventListener("click", function () {
    void changeKillSwitch("/api/kill-switch/engage", "Aktivierung");
  });
  element("clear-kill").addEventListener("click", function () {
    void changeKillSwitch("/api/kill-switch/clear", "Freigabe");
  });

  window.addEventListener("bugbounty:dashboard-state", function (event) {
    var nextState = event.detail;
    if (!nextState || nextState.version !== 1 || nextState.externalIntegrationsEnabled !== false) return;
    render(nextState);
  });

  void loadState().catch(function (error) {
    setText("last-refresh", "Fail-closed: " + (error instanceof Error ? error.message : "UNKNOWN"));
    setText("kill-status", "AKTIV / STATUSFEHLER");
    setText("overview-kill-status", "aktiv");
  });
})();
`;
