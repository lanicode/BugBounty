export const HACKERONE_DASHBOARD_HTML = `
<section id="hackerone-integration" class="panel" aria-labelledby="hackerone-heading">
  <div class="section-heading">
    <div>
      <p class="eyebrow">Einstellungen › Integrationen</p>
      <h2 id="hackerone-heading">HackerOne</h2>
    </div>
    <span id="hackerone-integration-badge" class="capability-badge">EXTERNE METADATENINTEGRATION DEAKTIVIERT</span>
  </div>

  <div class="feature-badges" aria-label="Verbindliche HackerOne-Grenzen">
    <span>HACKERONE READ-ONLY</span>
    <span>KEINE ZIELREQUESTS</span>
    <span>KEINE REPORT-EINREICHUNG</span>
    <span id="hackerone-dynamic-boundary">EXTERNE METADATENINTEGRATION DEAKTIVIERT</span>
  </div>

  <p class="muted">Diese Integration liest ausschließlich Programm-, Policy- und Scope-Metadaten. Programmregeln und die aktuelle Policy werden niemals automatisch akzeptiert.</p>

  <div id="hackerone-status-grid" class="product-grid" aria-live="polite"></div>
  <p id="hackerone-operation-status" class="operation-status" aria-live="polite"></p>

  <div class="two-column">
    <article>
      <h3>Credentials im macOS-Schlüsselbund</h3>
      <p class="muted">Diese einmalige lokale Aktion überträgt beide Werte ausschließlich binär an den loopbackgebundenen Dashboard-Prozess und speichert sie im macOS-Schlüsselbund. Die Werte werden weder angezeigt noch in Browser-Speichern persistiert. Alternativ steht der lokale TTY-Adminbefehl <code>pnpm hackerone:credentials store</code> bereit.</p>
      <form id="hackerone-credential-form" autocomplete="off">
        <label for="hackerone-identifier">API-Identifier</label>
        <input id="hackerone-identifier" type="password" autocomplete="off" spellcheck="false" maxlength="3000" disabled>
        <label for="hackerone-token">API-Token</label>
        <input id="hackerone-token" type="password" autocomplete="off" spellcheck="false" maxlength="3000" disabled>
      </form>
      <div class="button-row">
        <button id="hackerone-save-credentials" type="button" disabled>Credentials lokal speichern</button>
        <button id="hackerone-remove-credentials" class="danger" type="button" disabled>Credentials entfernen</button>
      </div>
    </article>

    <article>
      <div class="section-heading">
        <h3>Integrationskontrolle</h3>
        <span id="hackerone-activation-readiness-badge" class="capability-badge">VORAUSSETZUNGEN WERDEN GEPRÜFT</span>
      </div>
      <p class="muted">Aktivierung erweitert ausschließlich die Capability HACKERONE_METADATA_READ. Der globale Kill Switch bleibt vorrangig.</p>
      <ul id="hackerone-activation-requirements" class="step-list" aria-label="Voraussetzungen für die HackerOne-Aktivierung" aria-live="polite"></ul>
      <p id="hackerone-activation-context" class="review-package" aria-live="polite">Aktivierungsvoraussetzungen werden geprüft.</p>
      <div class="button-row">
        <button id="hackerone-enable" type="button" aria-describedby="hackerone-activation-context" disabled>Read-only-Integration aktivieren</button>
        <button id="hackerone-disable" class="danger" type="button" disabled>Integration deaktivieren</button>
        <button id="hackerone-test" type="button" disabled>Verbindung testen</button>
        <button id="hackerone-sync-catalog" type="button" disabled>Programmkatalog synchronisieren</button>
      </div>
    </article>
  </div>

  <section aria-labelledby="hackerone-program-selection-heading">
    <div class="section-heading">
      <div><p class="eyebrow">Lokale Auswahl</p><h3 id="hackerone-program-selection-heading">Programm auswählen und Details synchronisieren</h3></div>
    </div>
    <label for="hackerone-program-select">Importiertes Programm</label>
    <select id="hackerone-program-select" disabled><option value="">Kein Programm verfügbar</option></select>
    <div class="button-row">
      <button id="hackerone-select-program" type="button" disabled>Auswahl übernehmen</button>
      <button id="hackerone-sync-program" type="button" disabled>Programmdetails, Scopes und Ausschlüsse synchronisieren</button>
    </div>
  </section>

  <section aria-labelledby="hackerone-campaign-binding-heading">
    <div class="section-heading">
      <div><p class="eyebrow">Lokale Abhängigkeit</p><h3 id="hackerone-campaign-binding-heading">Ausgewähltes Programm an Kampagne binden</h3></div>
    </div>
    <p class="muted">Die Bindung verwendet ausschließlich exakte lokale Referenzen. Bei späterem Policy-Drift können nur ausdrücklich gebundene aktive Kampagnen pausiert werden.</p>
    <label for="hackerone-campaign-select">Lokale Kampagne</label>
    <select id="hackerone-campaign-select" disabled><option value="">Keine Kampagne verfügbar</option></select>
    <button id="hackerone-bind-campaign" type="button" disabled>Abhängige Kampagne binden</button>
  </section>

  <section aria-labelledby="hackerone-manual-import-heading">
    <div class="section-heading">
      <div><p class="eyebrow">Offline-Fallback</p><h3 id="hackerone-manual-import-heading">Manueller JSON-Import</h3></div>
      <span class="capability-badge test-only">MANUELL · UNGEPRÜFT</span>
    </div>
    <p class="muted">Der Import bleibt als manuell und ungeprüft markiert. Er stellt keine Policy-Annahme dar.</p>
    <label for="hackerone-manual-json">Striktes lokales JSON-Dokument</label>
    <textarea id="hackerone-manual-json" rows="12" spellcheck="false" autocomplete="off" disabled></textarea>
    <button id="hackerone-manual-import" type="button" disabled>JSON lokal importieren</button>
  </section>

  <section aria-labelledby="hackerone-policy-accept-heading">
    <div class="section-heading">
      <div><p class="eyebrow">Human-in-the-loop</p><h3 id="hackerone-policy-accept-heading">Aktuelle Policy ausdrücklich akzeptieren</h3></div>
      <span id="hackerone-policy-acceptance-badge" class="capability-badge">KEINE AUSWAHL</span>
    </div>
    <p id="hackerone-policy-acceptance-context" class="review-package">Keine aktuelle Policy ausgewählt.</p>
    <label><input id="hackerone-policy-confirm" type="checkbox" disabled> Ich habe die aktuelle Policy, Scopes, Ausschlüsse und den Diff geprüft und akzeptiere exakt diese lokale Snapshot-Version.</label>
    <button id="hackerone-accept-policy" type="button" disabled>Aktuelle Policy explizit akzeptieren</button>
  </section>

  <section aria-labelledby="hackerone-program-heading">
    <div class="section-heading"><div><p class="eyebrow">Metadaten</p><h3 id="hackerone-program-heading">Programm</h3></div></div>
    <div id="hackerone-program-details" class="data-list" aria-live="polite"></div>
  </section>

  <section aria-labelledby="hackerone-policy-heading">
    <div class="section-heading"><div><p class="eyebrow">Nur Text</p><h3 id="hackerone-policy-heading">Policy</h3></div></div>
    <div id="hackerone-policy-details" class="data-list" aria-live="polite"></div>
  </section>

  <section aria-labelledby="hackerone-scopes-heading">
    <div class="section-heading"><div><p class="eyebrow">Strukturierter Scope</p><h3 id="hackerone-scopes-heading">Assets und Scopes</h3></div></div>
    <p class="muted">Asset-Identifier erscheinen ausschließlich als Plain Text. Die Oberfläche erzeugt daraus keine Links und keine Navigation.</p>
    <div id="hackerone-scope-list" class="data-list" aria-live="polite"></div>
  </section>

  <section aria-labelledby="hackerone-exclusions-heading">
    <div class="section-heading"><div><p class="eyebrow">Nicht im Scope</p><h3 id="hackerone-exclusions-heading">Scope-Ausschlüsse</h3></div></div>
    <div id="hackerone-exclusion-list" class="data-list" aria-live="polite"></div>
  </section>

  <section aria-labelledby="hackerone-versions-heading">
    <div class="section-heading"><div><p class="eyebrow">Append-only</p><h3 id="hackerone-versions-heading">Policy-Versionen</h3></div></div>
    <div id="hackerone-version-list" class="data-list" aria-live="polite"></div>
  </section>

  <section aria-labelledby="hackerone-diff-heading">
    <div class="section-heading"><div><p class="eyebrow">Drift-Stopp</p><h3 id="hackerone-diff-heading">Policy-Diff</h3></div></div>
    <div id="hackerone-diff-details" class="data-list" aria-live="polite"></div>
  </section>

  <section aria-labelledby="hackerone-suitability-heading">
    <div class="section-heading"><div><p class="eyebrow">Lokale Einordnung</p><h3 id="hackerone-suitability-heading">Eignung</h3></div></div>
    <div id="hackerone-suitability-details" class="data-list" aria-live="polite"></div>
  </section>
</section>
`;

export const HACKERONE_DASHBOARD_JAVASCRIPT = `
"use strict";
(function () {
  var ROUTES = Object.freeze({
    state: "/api/state",
    storeCredentials: "/api/hackerone/credentials/store",
    removeCredentials: "/api/hackerone/credentials/remove",
    enable: "/api/hackerone/integration/enable",
    disable: "/api/hackerone/integration/disable",
    connectionTest: "/api/hackerone/connection-test",
    synchronizePrograms: "/api/hackerone/programs/synchronize",
    selectProgram: "/api/hackerone/program/select",
    synchronizeProgram: "/api/hackerone/program/synchronize",
    bindCampaign: "/api/hackerone/campaign/bind",
    acceptPolicy: "/api/hackerone/policy/accept",
    manualImport: "/api/hackerone/manual-import"
  });
  var JSON_POST_ROUTES = Object.freeze([
    ROUTES.removeCredentials,
    ROUTES.enable,
    ROUTES.disable,
    ROUTES.connectionTest,
    ROUTES.synchronizePrograms,
    ROUTES.selectProgram,
    ROUTES.synchronizeProgram,
    ROUTES.bindCampaign,
    ROUTES.acceptPolicy,
    ROUTES.manualImport
  ]);
  var csrfToken = "";
  var currentProjection = null;
  var operationRunning = false;
  var refreshRunning = false;
  var CREDENTIAL_FRAME_HEADER_BYTES = 9;
  var MAX_CREDENTIAL_BYTES = 3000;
  var CONTROL_IDS = Object.freeze([
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
    "hackerone-accept-policy"
  ]);

  function element(id) {
    var found = document.getElementById(id);
    if (!found) throw new Error("HACKERONE_UI_ELEMENT_MISSING:" + id);
    return found;
  }

  function disableAllControls() {
    CONTROL_IDS.forEach(function (id) {
      element(id).disabled = true;
    });
  }

  function record(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? value
      : null;
  }

  function array(value) {
    return Array.isArray(value) ? value : [];
  }

  function plain(value, fallback) {
    if (value === null || value === undefined || value === "")
      return fallback || "—";
    if (Array.isArray(value))
      return value.length === 0 ? "—" : value.map(String).join(", ");
    if (typeof value === "boolean") return value ? "ja" : "nein";
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
    if (typeof value === "string") return value;
    return fallback || "—";
  }

  function translated(value) {
    var labels = {
      configured: "konfiguriert",
      connected: "verbunden",
      deactivated: "deaktiviert",
      error: "Fehler",
      blocked_by_kill_switch: "durch Kill Switch blockiert",
      blocked_by_policy: "durch Policy blockiert",
      invalid_credentials: "Credentials ungültig",
      malformed_response: "Antwortschema ungültig",
      rate_limited: "Rate Limit erreicht",
      secret_store_unavailable: "Secret Store nicht verfügbar",
      unauthorized: "nicht autorisiert",
      unavailable: "nicht verfügbar",
      failed: "fehlgeschlagen",
      succeeded: "erfolgreich",
      hackerone_api_authenticated: "authentifizierte HackerOne API",
      manual_unverified: "manuell und ungeprüft",
      allowed: "ausdrücklich erlaubt",
      forbidden: "verboten",
      unknown_requires_human_review: "unklar · menschliche Prüfung erforderlich",
      manual_review_required: "manuelle Prüfung erforderlich"
    };
    return typeof value === "string" && Object.prototype.hasOwnProperty.call(labels, value)
      ? labels[value]
      : plain(value);
  }

  function setText(id, value) {
    element(id).textContent = plain(value);
  }

  function paragraph(label, value) {
    var node = document.createElement("p");
    node.textContent = label + ": " + plain(value);
    return node;
  }

  function card(title, rows) {
    var article = document.createElement("article");
    var heading = document.createElement("h4");
    heading.textContent = title;
    article.appendChild(heading);
    rows.forEach(function (row) {
      article.appendChild(paragraph(row[0], row[1]));
    });
    return article;
  }

  function empty(message) {
    var node = document.createElement("p");
    node.className = "empty";
    node.textContent = message;
    return node;
  }

  function replace(id, nodes, emptyMessage) {
    var container = element(id);
    var safeNodes = nodes.length === 0 ? [empty(emptyMessage)] : nodes;
    container.replaceChildren.apply(container, safeNodes);
  }

  function copyRow(label, value) {
    var row = document.createElement("div");
    row.className = "button-row";
    var textNode = document.createElement("code");
    textNode.textContent = label + ": " + plain(value);
    var button = document.createElement("button");
    button.type = "button";
    button.textContent = "Kopieren";
    button.setAttribute("aria-label", label + " als Plain Text kopieren");
    button.addEventListener("click", function () {
      void copyText(plain(value), button);
    });
    row.appendChild(textNode);
    row.appendChild(button);
    return row;
  }

  async function copyText(value, button) {
    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function")
        throw new Error("CLIPBOARD_UNAVAILABLE");
      await navigator.clipboard.writeText(value);
      button.textContent = "Kopiert";
      window.setTimeout(function () {
        button.textContent = "Kopieren";
      }, 1200);
    } catch {
      operationStatus("Kopieren ist in diesem Browser nicht verfügbar.", true);
    }
  }

  function operationStatus(message, failed) {
    var node = element("hackerone-operation-status");
    node.textContent = message;
    node.className = failed
      ? "operation-status error"
      : "operation-status success";
  }

  function snapshotRecord(projection) {
    var stored = record(projection.currentSnapshot);
    if (!stored) return null;
    return record(stored.snapshot) || stored;
  }

  function selectedProgram(projection) {
    var selectedRef =
      typeof projection.selectedProgramRef === "string"
        ? projection.selectedProgramRef
        : null;
    return array(projection.programs).find(function (candidate) {
      var item = record(candidate);
      return item && item.localRef === selectedRef;
    }) || null;
  }

  function renderStatus(projection) {
    var status = record(projection.status) || {};
    var enabled = status.adapterEnabled === true;
    var boundary = enabled
      ? "EXTERNE METADATENINTEGRATION AKTIV"
      : "EXTERNE METADATENINTEGRATION DEAKTIVIERT";
    setText("hackerone-integration-badge", boundary);
    setText("hackerone-dynamic-boundary", boundary);
    replace("hackerone-status-grid", [
      card("Capability", [
        ["Klasse", plain(status.actionClass, "HACKERONE_METADATA_READ")],
        ["Status", translated(status.status)],
        ["API-Modus", status.apiMode === "read_only" ? "nur lesend" : "blockiert"],
        ["Globale externe Integrationen", status.externalIntegrationsEnabled === true],
        ["Adapter konfiguriert", status.adapterConfigured === true],
        ["Adapter aktiviert", enabled]
      ]),
      card("Sicherheitsgrenzen", [
        ["Kill Switch aktiv", status.killSwitchActive !== false],
        ["Zielrequests", status.targetRequestsEnabled === true ? "unerwartet aktiv" : "deaktiviert"],
        ["Report-Einreichung", status.reportSubmissionEnabled === true ? "unerwartet aktiv" : "deaktiviert"]
      ]),
      card("Credentials", [
        ["Identifier vorhanden", status.identifierPresent === true],
        ["Token vorhanden", status.tokenPresent === true],
        ["Token-Fingerprint", plain(status.tokenFingerprint)],
        ["Secret-Werte", "werden niemals angezeigt"]
      ]),
      card("Letzte Operationen", [
        ["Verbindungstest", plain(status.lastConnectionTestAt)],
        ["Letzte erfolgreiche Prüfung", plain(status.lastSuccessfulConnectionAt)],
        ["Testergebnis", translated(status.lastConnectionResult)],
        ["Synchronisierung", plain(status.lastSynchronizationAt)],
        ["Sync-Ergebnis", translated(status.lastSynchronizationResult)],
        ["Programme", plain(status.importedProgramCount, "0")],
        ["Letzter Fehlercode", plain(status.lastErrorCode)],
        ["Ausgewählter Handle", plain(status.selectedHandle)]
      ])
    ], "HackerOne-Status nicht verfügbar.");
  }

  function renderProgramSelector(projection) {
    var select = element("hackerone-program-select");
    var programs = array(projection.programs);
    var selectedRef =
      typeof projection.selectedProgramRef === "string"
        ? projection.selectedProgramRef
        : "";
    var options = [];
    if (programs.length === 0) {
      var unavailable = document.createElement("option");
      unavailable.value = "";
      unavailable.textContent = "Kein Programm verfügbar";
      options.push(unavailable);
    } else {
      programs.forEach(function (candidate) {
        var stored = record(candidate);
        var program = stored && record(stored.program);
        if (!stored || !program || typeof stored.localRef !== "string") return;
        var option = document.createElement("option");
        option.value = stored.localRef;
        var suitability = record(stored.suitability);
        var score = suitability && typeof suitability.score === "number"
          ? " · Score " + String(suitability.score)
          : " · Score nach Detail-Sync";
        option.textContent = plain(program.name) + " · " + plain(program.handle) + score + " · " + translated(program.source);
        option.selected = stored.localRef === selectedRef;
        options.push(option);
      });
      if (projection.programsTruncated === true) {
        var truncated = document.createElement("option");
        truncated.value = "";
        truncated.disabled = true;
        truncated.textContent = "Weitere lokale Programme sind aus Sicherheitsgründen nicht in dieser Ansicht geladen.";
        options.push(truncated);
      }
    }
    select.replaceChildren.apply(select, options);
    if (selectedRef !== "" && options.some(function (option) { return option.value === selectedRef; }))
      select.value = selectedRef;
  }

  function renderProgram(projection) {
    var stored = record(selectedProgram(projection));
    var snapshot = snapshotRecord(projection);
    var program = snapshot && record(snapshot.program);
    if (!program && stored) program = record(stored.program);
    if (!program) {
      replace("hackerone-program-details", [], "Kein Programm ausgewählt.");
      return;
    }
    replace("hackerone-program-details", [
      card(plain(program.name, "Programm"), [
        ["Handle", program.handle],
        ["Lokale Referenz", stored && stored.localRef],
        ["Quelle", translated(program.source)],
        ["Programmstatus", program.programState],
        ["Einreichungsstatus", program.submissionState],
        ["Währung", program.currency],
        ["Bounties", program.offersBounties === true],
        ["Open Scope", program.openScope === true],
        ["Gold Standard Safe Harbor", program.goldStandardSafeHarbor === true],
        ["Bookmark", program.bookmarked === true],
        ["Eigene Reports", program.ownReportCount],
        ["Eigene gültige Reports", program.ownValidReportCount],
        ["Annahme gestartet", program.startedAcceptingAt],
        ["API-Datensatz erstellt", program.createdAt],
        ["API-Datensatz aktualisiert", program.updatedAt],
        ["Synchronisiert", program.synchronizedAt],
        ["Aktueller Snapshot", stored && stored.currentSnapshotDigest],
        ["Katalog-Drift ausstehend", stored && stored.catalogDriftPending === true]
      ])
    ], "Kein Programm ausgewählt.");
  }

  function renderCampaignSelector(projection) {
    var select = element("hackerone-campaign-select");
    var campaigns = array(projection.campaigns);
    var options = [];
    if (campaigns.length === 0) {
      var unavailable = document.createElement("option");
      unavailable.value = "";
      unavailable.textContent = "Keine Kampagne verfügbar";
      options.push(unavailable);
    } else {
      campaigns.forEach(function (candidate) {
        var campaign = record(candidate);
        if (!campaign || typeof campaign.id !== "string") return;
        var option = document.createElement("option");
        option.value = campaign.id;
        option.textContent = plain(campaign.id) + " · " + plain(campaign.state) + " · Revision " + plain(campaign.revision);
        options.push(option);
      });
    }
    select.replaceChildren.apply(select, options);
  }

  function renderPolicy(projection) {
    var stored = record(projection.currentSnapshot);
    var snapshot = snapshotRecord(projection);
    var program = snapshot && record(snapshot.program);
    if (!snapshot || !program) {
      replace("hackerone-policy-details", [], "Noch keine lokale Policy-Version vorhanden.");
      return;
    }
    var article = document.createElement("article");
    article.appendChild(paragraph("Snapshot-Digest", snapshot.snapshotDigest));
    article.appendChild(paragraph("Policy-Digest", snapshot.policyDigest));
    article.appendChild(paragraph("Quelle", translated(snapshot.source)));
    article.appendChild(paragraph("Abgerufen", snapshot.fetchedAt));
    article.appendChild(paragraph("Annahme ausstehend", stored && stored.acceptancePending === true));
    var heading = document.createElement("h4");
    heading.textContent = "Policy-Text";
    article.appendChild(heading);
    var policyText = document.createElement("pre");
    policyText.className = "result";
    policyText.textContent = plain(program.policy, "Kein Policy-Text vorhanden.");
    article.appendChild(policyText);
    article.appendChild(copyRow("Policy-Text", plain(program.policy, "")));
    var previous = record(projection.previousPolicy);
    var previousHeading = document.createElement("h4");
    previousHeading.textContent = "Vorheriger Policy-Text";
    article.appendChild(previousHeading);
    if (previous) {
      article.appendChild(paragraph("Vorheriger Snapshot", previous.snapshotDigest));
      article.appendChild(paragraph("Vorheriger Policy-Digest", previous.policyDigest));
      var previousPolicyText = document.createElement("pre");
      previousPolicyText.className = "result";
      previousPolicyText.textContent = plain(previous.policy, "Kein vorheriger Policy-Text vorhanden.");
      article.appendChild(previousPolicyText);
      article.appendChild(copyRow("Vorheriger Policy-Text", plain(previous.policy, "")));
    } else {
      article.appendChild(paragraph("Vorherige Version", "Keine; dies ist die erste lokale Snapshot-Version."));
    }
    replace("hackerone-policy-details", [article], "Noch keine lokale Policy-Version vorhanden.");
  }

  function renderScopes(projection) {
    var snapshot = snapshotRecord(projection);
    var scopes = snapshot ? array(snapshot.structuredScopes) : [];
    var nodes = scopes.map(function (candidate, index) {
      var scope = record(candidate) || {};
      var article = document.createElement("article");
      var heading = document.createElement("h4");
      heading.textContent = "Scope " + String(index + 1) + " · " + plain(scope.assetType);
      article.appendChild(heading);
      article.appendChild(copyRow("Asset-Identifier", scope.assetIdentifier));
      article.appendChild(paragraph("Asset-Digest", scope.assetIdentifierDigest));
      article.appendChild(paragraph("Einreichungsberechtigt", scope.eligibleForSubmission === true));
      article.appendChild(paragraph("Bounty-berechtigt", scope.eligibleForBounty === true));
      article.appendChild(paragraph("Maximale Severity", scope.maximumSeverity));
      article.appendChild(paragraph("Anweisung", scope.instruction));
      article.appendChild(paragraph("Vertraulichkeit", scope.confidentialityRequirement));
      article.appendChild(paragraph("Integrität", scope.integrityRequirement));
      article.appendChild(paragraph("Verfügbarkeit", scope.availabilityRequirement));
      return article;
    });
    replace("hackerone-scope-list", nodes, "Keine strukturierten Scopes vorhanden.");
  }

  function renderExclusions(projection) {
    var snapshot = snapshotRecord(projection);
    var exclusions = snapshot ? array(snapshot.scopeExclusions) : [];
    var nodes = exclusions.map(function (candidate, index) {
      var exclusion = record(candidate) || {};
      return card("Ausschluss " + String(index + 1), [
        ["Kategorie", exclusion.category],
        ["Details", exclusion.details],
        ["Erstellt", exclusion.createdAt],
        ["Aktualisiert", exclusion.updatedAt]
      ]);
    });
    replace("hackerone-exclusion-list", nodes, "Keine Scope-Ausschlüsse vorhanden.");
  }

  function renderVersions(projection) {
    var versions = array(projection.policyVersions);
    var nodes = versions.map(function (candidate, index) {
      var stored = record(candidate) || {};
      var snapshot = record(stored.snapshot) || stored;
      return card("Version " + plain(stored.versionNumber, String(index + 1)), [
        ["Snapshot-Digest", snapshot.snapshotDigest],
        ["Policy-Digest", snapshot.policyDigest],
        ["Vorheriger Snapshot", snapshot.previousSnapshotDigest],
        ["Quelle", translated(snapshot.source)],
        ["Abgerufen", snapshot.fetchedAt],
        ["Schema-Version", snapshot.schemaVersion],
        ["Adapter-Version", snapshot.adapterVersion],
        ["Annahme ausstehend", stored.acceptancePending === true]
      ]);
    });
    if (projection.policyVersionsTruncated === true) {
      var notice = document.createElement("p");
      notice.textContent = "Angezeigt werden die letzten " + String(versions.length) + " von " + plain(projection.policyVersionCount) + " lokalen Versionen.";
      nodes.unshift(notice);
    }
    replace("hackerone-version-list", nodes, "Keine Policy-Versionen vorhanden.");
  }

  function renderDiff(projection) {
    var diff = record(projection.drift);
    if (!diff) {
      replace("hackerone-diff-details", [], "Kein Diff vorhanden.");
      return;
    }
    replace("hackerone-diff-details", [
      card("Aktueller Drift-Status", [
        ["Änderung erkannt", diff.changed === true],
        ["Änderungen", array(diff.changes).map(translateChange)],
        ["Abhängige Kampagnen pausiert", diff.campaignsPaused === true],
        ["Neue menschliche Annahme erforderlich", diff.requiresHumanAcceptance === true]
      ])
    ], "Kein Diff vorhanden.");
  }

  function translateChange(value) {
    var labels = {
      BOUNTY_ELIGIBILITY_CHANGED: "Bounty-Berechtigung geändert",
      INSTRUCTIONS_CHANGED: "Anweisungen geändert",
      MAXIMUM_SEVERITY_CHANGED: "Maximale Severity geändert",
      POLICY_TEXT_CHANGED: "Policy-Text geändert",
      PROGRAM_STATE_CHANGED: "Programmstatus geändert",
      OPEN_SCOPE_CHANGED: "Open-Scope-Status geändert",
      SAFE_HARBOR_CHANGED: "Safe-Harbor-Status geändert",
      SCOPE_EXCLUSIONS_CHANGED: "Scope-Ausschlüsse geändert",
      SCOPES_CHANGED: "Scopes geändert",
      SUBMISSION_ELIGIBILITY_CHANGED: "Einreichungsberechtigung geändert"
    };
    return typeof value === "string" && Object.prototype.hasOwnProperty.call(labels, value)
      ? labels[value]
      : plain(value);
  }

  function renderSuitability(projection) {
    var snapshot = snapshotRecord(projection);
    var suitability = snapshot && record(snapshot.suitability);
    if (!suitability) {
      replace("hackerone-suitability-details", [], "Noch keine lokale Eignungsbewertung vorhanden.");
      return;
    }
    replace("hackerone-suitability-details", [
      card("Konservative lokale Einordnung", [
        ["Score", suitability.score],
        ["Gründe", array(suitability.reasons).map(translateSuitabilityReason)],
        ["Automationsregel", translated(suitability.automationPermission)],
        ["Account-Workflow", translated(suitability.accountWorkflows)],
        ["Rechtliche Entscheidung getroffen", suitability.legalDecisionMade === true ? "unerwartet" : "nein"]
      ])
    ], "Noch keine lokale Eignungsbewertung vorhanden.");
  }

  function translateSuitabilityReason(value) {
    var labels = {
      BOUNTIES_AVAILABLE: "Bounties verfügbar",
      BOUNTIES_UNAVAILABLE: "Keine Bounties",
      OPEN_SUBMISSIONS: "Einreichungen offen",
      POLICY_MISSING: "Policy fehlt",
      POLICY_PRESENT: "Policy vorhanden",
      SAFE_HARBOR_PRESENT: "Safe Harbor vorhanden",
      SCOPE_EXCLUSIONS_PRESENT: "Scope-Ausschlüsse vorhanden",
      STRUCTURED_SCOPE_CLEAR: "Strukturierter Scope vorhanden",
      STRUCTURED_SCOPE_MISSING: "Strukturierter Scope fehlt",
      WEB_OR_API_ASSET_PRESENT: "Web- oder API-Asset vorhanden"
    };
    return typeof value === "string" && Object.prototype.hasOwnProperty.call(labels, value)
      ? labels[value]
      : plain(value);
  }

  function renderPolicyAcceptance(projection) {
    var stored = record(projection.currentSnapshot);
    var snapshot = snapshotRecord(projection);
    var pending = !!(stored && stored.acceptancePending === true && snapshot);
    var secureCoreReady = projection.secureCoreReady === true;
    var confirmed = element("hackerone-policy-confirm").checked;
    var previous = record(projection.previousPolicy);
    var diff = record(projection.drift);
    setText("hackerone-policy-acceptance-badge", pending ? "ANNAHME AUSSTEHEND" : snapshot ? "AKZEPTIERT" : "KEINE AUSWAHL");
    setText(
      "hackerone-policy-acceptance-context",
      snapshot
        ? "Snapshot " + plain(snapshot.snapshotDigest) + " · Policy " + plain(snapshot.policyDigest) + " · Quelle " + translated(snapshot.source) + " · Vorherige Policy " + (previous ? plain(previous.policyDigest) : "keine") + " · Diff " + (diff ? plain(array(diff.changes).map(translateChange)) : "erste Version")
        : "Keine aktuelle Policy ausgewählt."
    );
    element("hackerone-policy-confirm").disabled = !secureCoreReady || !pending || operationRunning;
    element("hackerone-accept-policy").disabled = !secureCoreReady || !pending || !confirmed || operationRunning;
  }

  function activationState(projection) {
    var status = record(projection.status) || {};
    var secureCoreReasonCodes = array(projection.secureCoreReasonCodes)
      .filter(function (value) {
        return typeof value === "string" && /^[A-Z][A-Z0-9_]{2,127}$/.test(value);
      })
      .slice(0, 16);
    var state = {
      secureCoreReady: projection.secureCoreReady === true,
      externalIntegrationsEnabled: status.externalIntegrationsEnabled === true,
      adapterConfigured: status.adapterConfigured === true,
      credentialPairPresent:
        status.identifierPresent === true && status.tokenPresent === true,
      killSwitchReleased: status.killSwitchActive === false,
      secureCoreReasonCodes: secureCoreReasonCodes
    };
    state.ready =
      state.secureCoreReady &&
      state.externalIntegrationsEnabled &&
      state.adapterConfigured &&
      state.credentialPairPresent &&
      state.killSwitchReleased;
    return state;
  }

  function renderActivationReadiness(projection) {
    var activation = activationState(projection);
    var requirements = [
      {
        label: "Sicherheitskern",
        ready: activation.secureCoreReady,
        detail: activation.secureCoreReady
          ? "bereit"
          : activation.secureCoreReasonCodes.length > 0
            ? activation.secureCoreReasonCodes.join(", ")
            : "DASHBOARD_SECURE_CORE_NOT_READY"
      },
      {
        label: "Externe Integrationen",
        ready: activation.externalIntegrationsEnabled,
        detail: activation.externalIntegrationsEnabled
          ? "Startup-Schalter aktiv"
          : "BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED=true fehlt"
      },
      {
        label: "HackerOne Read-only",
        ready: activation.adapterConfigured,
        detail: activation.adapterConfigured
          ? "Capability konfiguriert"
          : "BUGBOUNTY_HACKERONE_READONLY_ENABLED=true fehlt oder ist ungültig"
      },
      {
        label: "Credential-Paar",
        ready: activation.credentialPairPresent,
        detail: activation.credentialPairPresent
          ? "Identifier und Token im Schlüsselbund vorhanden"
          : "Identifier und Token müssen beide im Schlüsselbund vorhanden sein"
      },
      {
        label: "Globaler Kill Switch",
        ready: activation.killSwitchReleased,
        detail: activation.killSwitchReleased
          ? "signiert freigegeben"
          : "aktiv; zuerst über die lokale Operatorgrenze freigeben"
      }
    ];
    var nodes = requirements.map(function (requirement) {
      var item = document.createElement("li");
      item.className = requirement.ready ? "done" : "current";
      item.textContent =
        (requirement.ready ? "Bereit: " : "Offen: ") +
        requirement.label +
        " · " +
        requirement.detail;
      return item;
    });
    element("hackerone-activation-requirements").replaceChildren.apply(
      element("hackerone-activation-requirements"),
      nodes
    );
    setText(
      "hackerone-activation-readiness-badge",
      activation.ready ? "AKTIVIERUNG BEREIT" : "AKTIVIERUNG BLOCKIERT"
    );
    setText(
      "hackerone-activation-context",
      activation.ready
        ? "Alle fünf Voraussetzungen sind erfüllt. Die Read-only-Integration kann jetzt ausdrücklich aktiviert werden."
        : "Der Aktivierungsbutton bleibt gesperrt, bis alle oben sichtbaren Voraussetzungen erfüllt sind. Credentials können unabhängig davon lokal gespeichert oder entfernt werden."
    );
    return activation;
  }

  function renderControls(projection) {
    var status = record(projection.status) || {};
    var activation = activationState(projection);
    var available = projection.available === true;
    var enabled = status.adapterEnabled === true;
    var killed = status.killSwitchActive !== false;
    var programsAvailable = array(projection.programs).length > 0;
    var campaignsAvailable = array(projection.campaigns).length > 0;
    var selected = typeof projection.selectedProgramRef === "string" && projection.selectedProgramRef !== "";
    element("hackerone-identifier").disabled = operationRunning || !available;
    element("hackerone-token").disabled = operationRunning || !available;
    element("hackerone-save-credentials").disabled = operationRunning || !available;
    element("hackerone-remove-credentials").disabled = operationRunning || !available;
    element("hackerone-enable").disabled = operationRunning || enabled || !activation.ready;
    element("hackerone-enable").title = enabled
      ? "Read-only-Integration ist bereits aktiviert."
      : activation.ready
        ? "Alle Aktivierungsvoraussetzungen sind erfüllt."
        : "Aktivierung blockiert; offene Voraussetzungen stehen direkt oberhalb des Buttons.";
    element("hackerone-disable").disabled = operationRunning || !enabled;
    element("hackerone-test").disabled = operationRunning || !activation.secureCoreReady || !enabled || killed;
    element("hackerone-sync-catalog").disabled = operationRunning || !activation.secureCoreReady || !enabled || killed;
    element("hackerone-program-select").disabled = operationRunning || !activation.secureCoreReady || !programsAvailable;
    element("hackerone-select-program").disabled = operationRunning || !activation.secureCoreReady || !programsAvailable;
    element("hackerone-sync-program").disabled = operationRunning || !activation.secureCoreReady || !enabled || killed || !selected;
    element("hackerone-campaign-select").disabled = operationRunning || !activation.secureCoreReady || !campaignsAvailable;
    element("hackerone-bind-campaign").disabled = operationRunning || !activation.secureCoreReady || !selected || !campaignsAvailable;
    element("hackerone-manual-json").disabled = operationRunning || !activation.secureCoreReady || !available;
    element("hackerone-manual-import").disabled = operationRunning || !activation.secureCoreReady || !available;
    renderPolicyAcceptance(projection);
  }

  function render(projection) {
    currentProjection = projection;
    renderStatus(projection);
    renderProgramSelector(projection);
    renderProgram(projection);
    renderCampaignSelector(projection);
    renderPolicy(projection);
    renderScopes(projection);
    renderExclusions(projection);
    renderVersions(projection);
    renderDiff(projection);
    renderSuitability(projection);
    renderActivationReadiness(projection);
    renderControls(projection);
  }

  async function refresh() {
    if (refreshRunning) return;
    refreshRunning = true;
    try {
      var response = await fetch(ROUTES.state, {
        method: "GET",
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
        headers: { accept: "application/json" }
      });
      if (!response.ok) throw new Error("HACKERONE_STATE_UNAVAILABLE");
      var state = await response.json();
      var root = record(state);
      var projection = root && record(root.hackerOne);
      if (!root || !projection || typeof root.csrfToken !== "string" || root.csrfToken.length < 16)
        throw new Error("HACKERONE_STATE_INVALID");
      csrfToken = root.csrfToken;
      render(projection);
    } catch {
      currentProjection = null;
      csrfToken = "";
      element("hackerone-identifier").value = "";
      element("hackerone-token").value = "";
      disableAllControls();
      operationStatus("HackerOne-Zustand ist fail-closed nicht verfügbar.", true);
    } finally {
      refreshRunning = false;
    }
  }

  async function postJson(route, body) {
    if (JSON_POST_ROUTES.indexOf(route) === -1)
      throw new Error("HACKERONE_ROUTE_BLOCKED");
    if (csrfToken === "") throw new Error("HACKERONE_CSRF_UNAVAILABLE");
    var response = await fetch(route, {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "x-csrf-token": csrfToken
      },
      body: JSON.stringify(body)
    });
    var result = await response.json().catch(function () {
      return { error: "HACKERONE_DASHBOARD_RESPONSE_INVALID" };
    });
    if (!response.ok) {
      var error = record(result);
      var code = error && typeof error.error === "string" && /^[A-Z][A-Z0-9_]{2,127}$/.test(error.error)
        ? error.error
        : "HACKERONE_DASHBOARD_REQUEST_FAILED";
      throw new Error(code);
    }
    return result;
  }

  function encodeCredential(value) {
    var bytes = new TextEncoder().encode(value);
    if (
      bytes.byteLength < 1 ||
      bytes.byteLength > MAX_CREDENTIAL_BYTES ||
      !bytes.every(function (byte) { return byte >= 0x21 && byte <= 0x7e; })
    ) {
      bytes.fill(0);
      throw new Error("HACKERONE_CREDENTIAL_INPUT_INVALID");
    }
    return bytes;
  }

  function createCredentialFrame(identifierBytes, tokenBytes) {
    var frame = new Uint8Array(
      CREDENTIAL_FRAME_HEADER_BYTES + identifierBytes.byteLength + tokenBytes.byteLength
    );
    frame.set([0x48, 0x31, 0x43, 0x52, 0x01], 0);
    var view = new DataView(frame.buffer, frame.byteOffset, CREDENTIAL_FRAME_HEADER_BYTES);
    view.setUint16(5, identifierBytes.byteLength, false);
    view.setUint16(7, tokenBytes.byteLength, false);
    frame.set(identifierBytes, CREDENTIAL_FRAME_HEADER_BYTES);
    frame.set(tokenBytes, CREDENTIAL_FRAME_HEADER_BYTES + identifierBytes.byteLength);
    return frame;
  }

  async function postCredentialFrame(frame) {
    if (csrfToken === "") throw new Error("HACKERONE_CSRF_UNAVAILABLE");
    var response = await fetch(ROUTES.storeCredentials, {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      headers: {
        accept: "application/json",
        "content-type": "application/octet-stream",
        "x-csrf-token": csrfToken
      },
      body: frame
    });
    var result = await response.json().catch(function () {
      return { error: "HACKERONE_DASHBOARD_RESPONSE_INVALID" };
    });
    if (!response.ok) {
      var error = record(result);
      var code = error && typeof error.error === "string" && /^[A-Z][A-Z0-9_]{2,127}$/.test(error.error)
        ? error.error
        : "HACKERONE_DASHBOARD_REQUEST_FAILED";
      throw new Error(code);
    }
    return result;
  }

  async function runOperation(label, operation) {
    if (operationRunning) return;
    operationRunning = true;
    if (currentProjection) renderControls(currentProjection);
    operationStatus(label + " läuft …", false);
    try {
      await operation();
      operationStatus(label + " erfolgreich.", false);
      await refresh();
    } catch (error) {
      var code = error instanceof Error && /^[A-Z][A-Z0-9_]{2,127}$/.test(error.message)
        ? error.message
        : "HACKERONE_DASHBOARD_REQUEST_FAILED";
      operationStatus(label + " blockiert: " + code, true);
    } finally {
      operationRunning = false;
      if (currentProjection) renderControls(currentProjection);
    }
  }

  function selectedLocalRef() {
    var value = element("hackerone-program-select").value;
    if (!/^(?:h1a|h1m)_[a-f0-9]{64}$/.test(value))
      throw new Error("HACKERONE_PROGRAM_REFERENCE_INVALID");
    return value;
  }

  function selectedCampaignId() {
    var value = element("hackerone-campaign-select").value;
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(value))
      throw new Error("HACKERONE_CAMPAIGN_REFERENCE_INVALID");
    return value;
  }

  function bindActions() {
    element("hackerone-save-credentials").addEventListener("click", function () {
      if (operationRunning) return;
      var identifierInput = element("hackerone-identifier");
      var tokenInput = element("hackerone-token");
      var identifierValue = identifierInput.value;
      var tokenValue = tokenInput.value;
      var identifierBytes;
      var tokenBytes;
      var frame;
      identifierInput.value = "";
      tokenInput.value = "";
      try {
        identifierBytes = encodeCredential(identifierValue);
        tokenBytes = encodeCredential(tokenValue);
        frame = createCredentialFrame(identifierBytes, tokenBytes);
      } catch (error) {
        identifierBytes && identifierBytes.fill(0);
        tokenBytes && tokenBytes.fill(0);
        frame && frame.fill(0);
        identifierValue = "";
        tokenValue = "";
        operationStatus("Credentials speichern blockiert: HACKERONE_CREDENTIAL_INPUT_INVALID", true);
        return;
      }
      identifierValue = "";
      tokenValue = "";
      void runOperation("Credentials lokal speichern", async function () {
        try {
          await postCredentialFrame(frame);
        } finally {
          identifierBytes.fill(0);
          tokenBytes.fill(0);
          frame.fill(0);
        }
      });
    });
    element("hackerone-credential-form").addEventListener("submit", function (event) {
      event.preventDefault();
    });
    element("hackerone-remove-credentials").addEventListener("click", function () {
      void runOperation("Credentials entfernen", function () {
        return postJson(ROUTES.removeCredentials, {});
      });
    });
    element("hackerone-enable").addEventListener("click", function () {
      void runOperation("Read-only-Integration aktivieren", function () {
        return postJson(ROUTES.enable, {});
      });
    });
    element("hackerone-disable").addEventListener("click", function () {
      void runOperation("Integration deaktivieren", function () {
        return postJson(ROUTES.disable, {});
      });
    });
    element("hackerone-test").addEventListener("click", function () {
      void runOperation("Verbindungstest", function () {
        return postJson(ROUTES.connectionTest, {});
      });
    });
    element("hackerone-sync-catalog").addEventListener("click", function () {
      void runOperation("Programmkatalog synchronisieren", function () {
        return postJson(ROUTES.synchronizePrograms, {});
      });
    });
    element("hackerone-select-program").addEventListener("click", function () {
      void runOperation("Programm auswählen", function () {
        return postJson(ROUTES.selectProgram, { programRef: selectedLocalRef() });
      });
    });
    element("hackerone-sync-program").addEventListener("click", function () {
      void runOperation("Programmdetails synchronisieren", function () {
        return postJson(ROUTES.synchronizeProgram, { programRef: selectedLocalRef() });
      });
    });
    element("hackerone-bind-campaign").addEventListener("click", function () {
      void runOperation("Abhängige Kampagne binden", function () {
        return postJson(ROUTES.bindCampaign, {
          programRef: selectedLocalRef(),
          campaignId: selectedCampaignId()
        });
      });
    });
    element("hackerone-manual-import").addEventListener("click", function () {
      var sourceInput = element("hackerone-manual-json");
      var source = sourceInput.value;
      sourceInput.value = "";
      void runOperation("Manuellen JSON-Import", async function () {
        try {
          await postJson(ROUTES.manualImport, { source: source });
        } finally {
          source = "";
        }
      });
    });
    element("hackerone-policy-confirm").addEventListener("change", function () {
      if (currentProjection) renderPolicyAcceptance(currentProjection);
    });
    element("hackerone-accept-policy").addEventListener("click", function () {
      var projection = currentProjection;
      var stored = projection && record(projection.currentSnapshot);
      var snapshot = projection && snapshotRecord(projection);
      var programLocalRef = stored && stored.programLocalRef;
      var snapshotDigest = snapshot && snapshot.snapshotDigest;
      if (
        !stored ||
        stored.acceptancePending !== true ||
        typeof programLocalRef !== "string" ||
        typeof snapshotDigest !== "string" ||
        element("hackerone-policy-confirm").checked !== true
      ) {
        operationStatus("Policy-Annahme blockiert: explizite, aktuelle Bestätigung fehlt.", true);
        return;
      }
      element("hackerone-policy-confirm").checked = false;
      void runOperation("Aktuelle Policy akzeptieren", function () {
        return postJson(ROUTES.acceptPolicy, {
          programRef: programLocalRef,
          snapshotDigest: snapshotDigest,
          confirmed: true
        });
      });
    });
  }

  function start() {
    disableAllControls();
    bindActions();
    window.addEventListener("bugbounty:dashboard-state", function (event) {
      var root = record(event.detail);
      var projection = root && record(root.hackerOne);
      if (!root || !projection || typeof root.csrfToken !== "string" || root.csrfToken.length < 16)
        return;
      csrfToken = root.csrfToken;
      render(projection);
    });
    void refresh();
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();
`;
