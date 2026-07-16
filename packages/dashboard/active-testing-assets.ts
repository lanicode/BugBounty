export const ACTIVE_TESTING_DASHBOARD_HTML = `
<section id="active-testing" class="panel" aria-labelledby="active-testing-heading">
  <div class="section-heading">
    <div>
      <p class="eyebrow">HackerOne · expliziter Live-Ablauf</p>
      <h2 id="active-testing-heading">Aktive Tests</h2>
    </div>
    <span id="active-testing-capability-badge" class="capability-badge">FAIL-CLOSED BLOCKIERT</span>
  </div>

  <div class="feature-badges" aria-label="Verbindliche Active-Testing-Grenzen">
    <span>API-SNAPSHOT-GEBUNDEN</span>
    <span>EXAKTES ASSET</span>
    <span>GESCHLOSSENE TESTKLASSE</span>
    <span>EIN REQUEST · KEINE RETRIES</span>
    <span>KEINE REPORT-EINREICHUNG</span>
  </div>

  <p class="muted">Jeder Schritt benötigt einen aktuellen serverseitigen Zustand und eine eigene ausdrückliche Aktion. Planfreigabe startet keinen Request. Asset-Identifier werden ausschließlich als Text dargestellt und niemals als Link verwendet.</p>
  <div id="active-testing-capability-details" class="product-grid" aria-live="polite"></div>
  <p id="active-testing-operation-status" class="operation-status" aria-live="polite">Active-Testing-Zustand wird geprüft.</p>

  <article aria-labelledby="active-testing-step-1-heading">
    <div class="section-heading">
      <div><p class="eyebrow">Schritt 1 von 3</p><h3 id="active-testing-step-1-heading">Exakten Plan vorbereiten</h3></div>
      <span class="capability-badge">NOCH KEIN REQUEST</span>
    </div>
    <div id="active-testing-source-details" class="data-list" aria-live="polite"></div>

    <label for="active-testing-program-select">API-synchronisiertes und akzeptiertes Programm</label>
    <select id="active-testing-program-select" disabled>
      <option value="">Kein freigegebenes Programm ausgewählt</option>
    </select>

    <label for="active-testing-asset-select">Exakt serverprojiziertes Asset</label>
    <select id="active-testing-asset-select" disabled>
      <option value="">Kein Asset ausgewählt</option>
    </select>

    <label for="active-testing-class-select">Geschlossene Testklasse</label>
    <select id="active-testing-class-select" disabled>
      <option value="">Keine Testklasse ausgewählt</option>
    </select>

    <fieldset class="confirmation-grid">
      <legend>Verbindliche manuelle Prüfung</legend>
      <label><input id="active-testing-review-automation" type="checkbox" disabled> Automationsregel der aktuellen Policy geprüft</label>
      <label><input id="active-testing-review-instruction" type="checkbox" disabled> Exakte Scope-Anweisung geprüft</label>
      <label><input id="active-testing-review-exclusions" type="checkbox" disabled> Alle Scope-Ausschlüsse geprüft</label>
      <label><input id="active-testing-review-side-effects" type="checkbox" disabled> Keine Seiteneffekte für exakt diese Testklasse bestätigt</label>
    </fieldset>

    <p id="active-testing-selection-context" class="review-package" aria-live="polite">Programm, Asset und Testklasse müssen vollständig serverseitig verfügbar sein.</p>
    <button id="active-testing-prepare-plan" type="button" disabled>Exakten Plan vorbereiten</button>
  </article>

  <article aria-labelledby="active-testing-step-2-heading">
    <div class="section-heading">
      <div><p class="eyebrow">Schritt 2 von 3</p><h3 id="active-testing-step-2-heading">Plan ausdrücklich freigeben</h3></div>
      <span class="capability-badge">STARTET NICHT</span>
    </div>
    <div id="active-testing-plan-details" class="data-list" aria-live="polite"></div>
    <p id="active-testing-approval-context" class="review-package" aria-live="polite">Noch kein aktueller Plan mit offener Freigabe.</p>
    <button id="active-testing-approve-plan" type="button" disabled>Exakt diesen Plan freigeben</button>
  </article>

  <article aria-labelledby="active-testing-step-3-heading">
    <div class="section-heading">
      <div><p class="eyebrow">Schritt 3 von 3</p><h3 id="active-testing-step-3-heading">Separat starten</h3></div>
      <span class="capability-badge">EIN LIVE-REQUEST</span>
    </div>
    <p id="active-testing-execution-context" class="review-package" aria-live="polite">Start bleibt bis zur aktuellen, ausdrücklichen Planfreigabe blockiert.</p>
    <button id="active-testing-start-execution" class="danger" type="button" disabled>Exakt diesen freigegebenen Plan jetzt starten</button>
    <div id="active-testing-attempt-details" class="data-list" aria-live="polite"></div>
  </article>

  <section aria-labelledby="active-testing-report-heading">
    <div class="section-heading">
      <div><p class="eyebrow">Lokale Evidence</p><h3 id="active-testing-report-heading">Nicht eingereichte Reportentwürfe</h3></div>
      <span class="capability-badge">LOCAL · UNSUBMITTED</span>
    </div>
    <p class="muted">Angezeigt werden ausschließlich lokale Metadaten und Digests mit <code>externalSubmissionPerformed=false</code>. Diese Oberfläche besitzt keine Report-Submission-Aktion.</p>
    <div id="active-testing-report-details" class="data-list" aria-live="polite"></div>
  </section>
</section>
`;

export const ACTIVE_TESTING_DASHBOARD_JAVASCRIPT = `
"use strict";
(function () {
  var ROUTES = Object.freeze({
    state: "/api/state",
    preparePlan: "/api/active-testing/plan/prepare",
    approvePlan: "/api/active-testing/plan/approve",
    startExecution: "/api/active-testing/execution/start"
  });
  var POST_ROUTES = Object.freeze([
    ROUTES.preparePlan,
    ROUTES.approvePlan,
    ROUTES.startExecution
  ]);
  var CONTROL_IDS = Object.freeze([
    "active-testing-program-select",
    "active-testing-asset-select",
    "active-testing-class-select",
    "active-testing-review-automation",
    "active-testing-review-instruction",
    "active-testing-review-exclusions",
    "active-testing-review-side-effects",
    "active-testing-prepare-plan",
    "active-testing-approve-plan",
    "active-testing-start-execution"
  ]);
  var REVIEW_IDS = Object.freeze([
    "active-testing-review-automation",
    "active-testing-review-instruction",
    "active-testing-review-exclusions",
    "active-testing-review-side-effects"
  ]);
  var TEST_CLASSES = Object.freeze({
    http_headers: Object.freeze({
      method: "HEAD",
      headerProfile: "metadata_v1",
      pathMode: "exact_scope_path"
    }),
    cors_preflight: Object.freeze({
      method: "OPTIONS",
      headerProfile: "cors_probe_v1",
      pathMode: "exact_scope_path"
    }),
    security_txt: Object.freeze({
      method: "GET",
      headerProfile: "metadata_v1",
      pathMode: "security_txt_root"
    })
  });
  var PROGRAM_REFERENCE = /^h1a_[a-f0-9]{64}$/;
  var DIGEST = /^[a-f0-9]{64}$/;
  var IDENTIFIER = /^[A-Za-z0-9._-]{1,128}$/;
  var REASON_CODE = /^[A-Z][A-Z0-9_]{2,127}$/;
  var csrfToken = "";
  var currentProjection = null;
  var operationRunning = false;
  var refreshRunning = false;

  function element(id) {
    var found = document.getElementById(id);
    if (!found) throw new Error("ACTIVE_TESTING_UI_ELEMENT_MISSING:" + id);
    return found;
  }

  function record(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? value
      : null;
  }

  function array(value) {
    return Array.isArray(value) ? value : [];
  }

  function boundedText(value, maximum) {
    return typeof value === "string" && value.length > 0 && value.length <= maximum;
  }

  function plain(value, fallback) {
    if (typeof value === "string" && value !== "") return value;
    if (typeof value === "boolean") return value ? "ja" : "nein";
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
    return fallback || "—";
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
    heading.textContent = plain(title, "Eintrag");
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

  function disableAllControls() {
    CONTROL_IDS.forEach(function (id) {
      element(id).disabled = true;
    });
  }

  function clearSelect(id, label) {
    var select = element(id);
    var option = document.createElement("option");
    option.value = "";
    option.textContent = label;
    select.replaceChildren(option);
    select.value = "";
  }

  function resetReviews() {
    REVIEW_IDS.forEach(function (id) {
      element(id).checked = false;
    });
  }

  function reviewsComplete() {
    return REVIEW_IDS.every(function (id) {
      return element(id).checked === true;
    });
  }

  function validReasonCodes(value) {
    return Array.isArray(value) && value.length <= 16 && value.every(function (code) {
      return typeof code === "string" && REASON_CODE.test(code);
    });
  }

  function canonicalTimestamp(value) {
    if (typeof value !== "string") return false;
    var parsed = Date.parse(value);
    return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
  }

  function validCapability(value) {
    var capability = record(value);
    return !!capability &&
      typeof capability.available === "boolean" &&
      typeof capability.configured === "boolean" &&
      typeof capability.enabled === "boolean" &&
      typeof capability.secureCoreReady === "boolean" &&
      typeof capability.killSwitchActive === "boolean" &&
      validReasonCodes(capability.reasonCodes);
  }

  function validProgram(value) {
    var program = record(value);
    return !!program &&
      typeof program.programRef === "string" && PROGRAM_REFERENCE.test(program.programRef) &&
      boundedText(program.name, 512) &&
      boundedText(program.handle, 256) &&
      program.source === "hackerone_api_authenticated" &&
      typeof program.catalogActive === "boolean" &&
      typeof program.catalogDriftPending === "boolean";
  }

  function validSnapshot(value) {
    var snapshot = record(value);
    return !!snapshot &&
      typeof snapshot.programRef === "string" && PROGRAM_REFERENCE.test(snapshot.programRef) &&
      typeof snapshot.snapshotDigest === "string" && DIGEST.test(snapshot.snapshotDigest) &&
      typeof snapshot.policyDigest === "string" && DIGEST.test(snapshot.policyDigest) &&
      snapshot.source === "hackerone_api_authenticated" &&
      typeof snapshot.current === "boolean" &&
      typeof snapshot.accepted === "boolean";
  }

  function validAsset(value) {
    var asset = record(value);
    if (!asset ||
      typeof asset.programRef !== "string" || !PROGRAM_REFERENCE.test(asset.programRef) ||
      typeof asset.snapshotDigest !== "string" || !DIGEST.test(asset.snapshotDigest) ||
      typeof asset.scopeId !== "string" || !IDENTIFIER.test(asset.scopeId) ||
      !boundedText(asset.assetType, 128) ||
      !boundedText(asset.displayIdentifier, 4096) ||
      typeof asset.assetIdentifierDigest !== "string" || !DIGEST.test(asset.assetIdentifierDigest) ||
      typeof asset.eligibleForSubmission !== "boolean" ||
      typeof asset.eligibleForBounty !== "boolean" ||
      typeof asset.supported !== "boolean" ||
      !validReasonCodes(asset.reasonCodes)) return false;
    return asset.supported
      ? asset.reasonCodes.length === 0
      : asset.reasonCodes.length > 0;
  }

  function validTestClass(value) {
    var item = record(value);
    if (!item || typeof item.id !== "string" ||
      !Object.prototype.hasOwnProperty.call(TEST_CLASSES, item.id)) return false;
    var expected = TEST_CLASSES[item.id];
    return boundedText(item.displayName, 256) &&
      boundedText(item.description, 2048) &&
      item.method === expected.method &&
      item.headerProfile === expected.headerProfile &&
      item.pathMode === expected.pathMode &&
      item.captureMode === "metadata_only" &&
      item.maximumRequests === 1 &&
      item.riskTier === "tier_1_public_read_only";
  }

  function validPlan(value) {
    if (value === null) return true;
    var plan = record(value);
    return !!plan &&
      typeof plan.planId === "string" && IDENTIFIER.test(plan.planId) &&
      typeof plan.planDigest === "string" && DIGEST.test(plan.planDigest) &&
      typeof plan.programRef === "string" && PROGRAM_REFERENCE.test(plan.programRef) &&
      typeof plan.snapshotDigest === "string" && DIGEST.test(plan.snapshotDigest) &&
      typeof plan.scopeId === "string" && IDENTIFIER.test(plan.scopeId) &&
      typeof plan.assetIdentifierDigest === "string" && DIGEST.test(plan.assetIdentifierDigest) &&
      typeof plan.testClass === "string" && Object.prototype.hasOwnProperty.call(TEST_CLASSES, plan.testClass) &&
      ["prepared", "approved", "running", "succeeded", "failed", "aborted", "expired"].indexOf(plan.status) !== -1;
  }

  function validApproval(value) {
    if (value === null) return true;
    var approval = record(value);
    return !!approval &&
      typeof approval.approvalId === "string" && IDENTIFIER.test(approval.approvalId) &&
      typeof approval.planId === "string" && IDENTIFIER.test(approval.planId) &&
      ["open", "accepted", "rejected", "expired"].indexOf(approval.status) !== -1;
  }

  function validAttempt(value) {
    var attempt = record(value);
    if (!attempt ||
      typeof attempt.authorizationId !== "string" || !IDENTIFIER.test(attempt.authorizationId) ||
      typeof attempt.planId !== "string" || !IDENTIFIER.test(attempt.planId) ||
      typeof attempt.testClass !== "string" || !Object.prototype.hasOwnProperty.call(TEST_CLASSES, attempt.testClass) ||
      ["reserved", "running", "succeeded", "failed", "aborted"].indexOf(attempt.status) === -1 ||
      !canonicalTimestamp(attempt.reservedAt) ||
      (attempt.startedAt !== null && !canonicalTimestamp(attempt.startedAt)) ||
      (attempt.finishedAt !== null && !canonicalTimestamp(attempt.finishedAt))) return false;
    return attempt.method === TEST_CLASSES[attempt.testClass].method;
  }

  function validReport(value) {
    var report = record(value);
    return !!report &&
      typeof report.reportId === "string" && IDENTIFIER.test(report.reportId) &&
      typeof report.planId === "string" && IDENTIFIER.test(report.planId) &&
      typeof report.planDigest === "string" && DIGEST.test(report.planDigest) &&
      typeof report.observationDigest === "string" && DIGEST.test(report.observationDigest) &&
      typeof report.markdownDigest === "string" && DIGEST.test(report.markdownDigest) &&
      typeof report.jsonDigest === "string" && DIGEST.test(report.jsonDigest) &&
      ["loopback_test", "production_https"].indexOf(report.transportKind) !== -1 &&
      typeof report.resolutionDigest === "string" && DIGEST.test(report.resolutionDigest) &&
      report.reviewStatus === "local_draft_unsubmitted" &&
      report.externalSubmissionPerformed === false &&
      canonicalTimestamp(report.createdAt);
  }

  function unique(values) {
    return new Set(values).size === values.length;
  }

  function projectionValid(value) {
    var projection = record(value);
    if (!projection || !validCapability(projection.capability) ||
      !Array.isArray(projection.programs) || projection.programs.length > 100 ||
      !Array.isArray(projection.snapshots) || projection.snapshots.length > 200 ||
      !Array.isArray(projection.assetCandidates) || projection.assetCandidates.length > 500 ||
      !Array.isArray(projection.testCatalog) || projection.testCatalog.length > 3 ||
      !Array.isArray(projection.attempts) || projection.attempts.length > 100 ||
      !Array.isArray(projection.reports) || projection.reports.length > 100 ||
      !validPlan(projection.currentPlan) ||
      !validApproval(projection.currentApproval) ||
      !projection.programs.every(validProgram) ||
      !projection.snapshots.every(validSnapshot) ||
      !projection.assetCandidates.every(validAsset) ||
      !projection.testCatalog.every(validTestClass) ||
      !projection.attempts.every(validAttempt) ||
      !projection.reports.every(validReport)) return false;

    var programRefs = projection.programs.map(function (program) { return program.programRef; });
    var snapshotKeys = projection.snapshots.map(function (snapshot) {
      return snapshot.programRef + ":" + snapshot.snapshotDigest;
    });
    var assetKeys = projection.assetCandidates.map(function (asset) {
      return asset.programRef + ":" + asset.snapshotDigest + ":" + asset.scopeId;
    });
    var classIds = projection.testCatalog.map(function (item) { return item.id; });
    if (!unique(programRefs) || !unique(snapshotKeys) || !unique(assetKeys) || !unique(classIds))
      return false;
    if (!projection.snapshots.every(function (snapshot) {
      return programRefs.indexOf(snapshot.programRef) !== -1;
    })) return false;
    if (!projection.assetCandidates.every(function (asset) {
      return snapshotKeys.indexOf(asset.programRef + ":" + asset.snapshotDigest) !== -1;
    })) return false;
    if (projection.programs.some(function (program) {
      return projection.snapshots.filter(function (snapshot) {
        return snapshot.programRef === program.programRef && snapshot.current === true;
      }).length > 1;
    })) return false;

    var plan = projection.currentPlan;
    var approval = projection.currentApproval;
    if (plan && !projection.assetCandidates.some(function (asset) {
      return asset.programRef === plan.programRef &&
        asset.snapshotDigest === plan.snapshotDigest &&
        asset.scopeId === plan.scopeId &&
        asset.assetIdentifierDigest === plan.assetIdentifierDigest;
    })) return false;
    if (plan && classIds.indexOf(plan.testClass) === -1) return false;
    if (plan && approval && approval.planId !== plan.planId) return false;
    if (approval && !plan) return false;
    if (approval && approval.status === "open" && plan.status !== "prepared") return false;
    if (approval && approval.status === "accepted" &&
      ["approved", "running", "succeeded", "failed", "aborted"].indexOf(plan.status) === -1)
      return false;
    return true;
  }

  function capabilityReady(projection) {
    var capability = projection.capability;
    return capability.available === true &&
      capability.configured === true &&
      capability.enabled === true &&
      capability.secureCoreReady === true &&
      capability.killSwitchActive === false &&
      capability.reasonCodes.length === 0;
  }

  function currentSnapshotForProgram(projection, programRef) {
    var matches = projection.snapshots.filter(function (snapshot) {
      return snapshot.programRef === programRef && snapshot.current === true;
    });
    return matches.length === 1 ? matches[0] : null;
  }

  function programEligible(projection, program) {
    var snapshot = currentSnapshotForProgram(projection, program.programRef);
    return program.source === "hackerone_api_authenticated" &&
      program.catalogActive === true &&
      program.catalogDriftPending === false &&
      !!snapshot &&
      snapshot.source === "hackerone_api_authenticated" &&
      snapshot.accepted === true;
  }

  function assetEligible(asset) {
    return asset.assetType === "URL" &&
      asset.supported === true &&
      asset.eligibleForSubmission === true &&
      asset.eligibleForBounty === true &&
      asset.reasonCodes.length === 0;
  }

  function selectedProgramBinding() {
    if (!currentProjection) return null;
    var selectedRef = element("active-testing-program-select").value;
    var program = currentProjection.programs.find(function (candidate) {
      return candidate.programRef === selectedRef;
    });
    if (!program || !programEligible(currentProjection, program)) return null;
    var snapshot = currentSnapshotForProgram(currentProjection, program.programRef);
    return snapshot ? { program: program, snapshot: snapshot } : null;
  }

  function currentSelection() {
    if (!currentProjection) return null;
    var binding = selectedProgramBinding();
    if (!binding) return null;
    var scopeId = element("active-testing-asset-select").value;
    var testClass = element("active-testing-class-select").value;
    var asset = currentProjection.assetCandidates.find(function (candidate) {
      return candidate.programRef === binding.program.programRef &&
        candidate.snapshotDigest === binding.snapshot.snapshotDigest &&
        candidate.scopeId === scopeId;
    });
    var catalog = currentProjection.testCatalog.find(function (candidate) {
      return candidate.id === testClass;
    });
    if (!asset || !assetEligible(asset) || !catalog) return null;
    return { binding: binding, asset: asset, catalog: catalog };
  }

  function renderCapability(projection) {
    var capability = projection.capability;
    var ready = capabilityReady(projection);
    setText(
      "active-testing-capability-badge",
      ready ? "EXPLIZITE SCHRITTE BEREIT" : "FAIL-CLOSED BLOCKIERT"
    );
    replace("active-testing-capability-details", [
      card("Capability", [
        ["Verfügbar", capability.available],
        ["Konfiguriert", capability.configured],
        ["Aktiviert", capability.enabled],
        ["Sicherheitskern bereit", capability.secureCoreReady]
      ]),
      card("Laufzeitgrenzen", [
        ["Kill Switch aktiv", capability.killSwitchActive],
        ["Reason Codes", capability.reasonCodes.length === 0 ? "keine" : capability.reasonCodes.join(", ")],
        ["Automatischer Start", "nein"],
        ["Report-Einreichung", "deaktiviert"]
      ])
    ], "Capability-Zustand nicht verfügbar.");
  }

  function renderSources(projection) {
    var nodes = [];
    projection.programs.forEach(function (program) {
      var snapshot = currentSnapshotForProgram(projection, program.programRef);
      nodes.push(card(program.name + " · " + program.handle, [
        ["Programm-Referenz", program.programRef],
        ["Quelle", program.source],
        ["Katalog aktiv", program.catalogActive],
        ["Katalog-Drift", program.catalogDriftPending],
        ["Aktueller Snapshot", snapshot ? snapshot.snapshotDigest : "nicht eindeutig"],
        ["Policy-Digest", snapshot ? snapshot.policyDigest : "nicht verfügbar"],
        ["Snapshot akzeptiert", snapshot ? snapshot.accepted : false]
      ]));
    });
    replace("active-testing-source-details", nodes, "Kein API-synchronisiertes Programm verfügbar.");
  }

  function renderProgramSelector(projection) {
    var select = element("active-testing-program-select");
    var previous = select.value;
    var placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Programm ausdrücklich auswählen";
    var options = [placeholder];
    projection.programs.forEach(function (program) {
      var option = document.createElement("option");
      option.value = program.programRef;
      option.textContent = program.name + " · " + program.handle;
      option.disabled = !programEligible(projection, program);
      options.push(option);
    });
    select.replaceChildren.apply(select, options);
    select.value = projection.programs.some(function (program) {
      return program.programRef === previous && programEligible(projection, program);
    }) ? previous : "";
  }

  function renderAssetSelector(projection) {
    var select = element("active-testing-asset-select");
    var previous = select.value;
    var placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Asset ausdrücklich auswählen";
    var options = [placeholder];
    var binding = selectedProgramBinding();
    var assets = binding ? projection.assetCandidates.filter(function (asset) {
      return asset.programRef === binding.program.programRef &&
        asset.snapshotDigest === binding.snapshot.snapshotDigest;
    }) : [];
    assets.forEach(function (asset) {
      var option = document.createElement("option");
      option.value = asset.scopeId;
      option.textContent = asset.assetType + " · " + asset.displayIdentifier;
      option.disabled = !assetEligible(asset);
      options.push(option);
    });
    select.replaceChildren.apply(select, options);
    select.value = assets.some(function (asset) {
      return asset.scopeId === previous && assetEligible(asset);
    }) ? previous : "";
  }

  function renderTestClassSelector(projection) {
    var select = element("active-testing-class-select");
    var previous = select.value;
    var placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Testklasse ausdrücklich auswählen";
    var options = [placeholder];
    projection.testCatalog.forEach(function (catalog) {
      var option = document.createElement("option");
      option.value = catalog.id;
      option.textContent = catalog.displayName + " · " + catalog.method + " · maximal 1 Request";
      options.push(option);
    });
    select.replaceChildren.apply(select, options);
    select.value = projection.testCatalog.some(function (catalog) {
      return catalog.id === previous;
    }) ? previous : "";
  }

  function renderSelectionContext() {
    var selected = currentSelection();
    setText(
      "active-testing-selection-context",
      selected
        ? "Programm " + selected.binding.program.programRef +
          " · Snapshot " + selected.binding.snapshot.snapshotDigest +
          " · Scope " + selected.asset.scopeId +
          " · Asset-Digest " + selected.asset.assetIdentifierDigest +
          " · Testklasse " + selected.catalog.id +
          ". Die vier manuellen Prüfungen gelten ausschließlich für diese Bindung."
        : "Programm, Asset und Testklasse müssen vollständig und aktuell serverseitig projiziert sein."
    );
  }

  function renderPlanAndApproval(projection) {
    var plan = projection.currentPlan;
    var approval = projection.currentApproval;
    replace(
      "active-testing-plan-details",
      plan ? [card("Aktueller Plan", [
        ["Plan-ID", plan.planId],
        ["Plan-Digest", plan.planDigest],
        ["Programm", plan.programRef],
        ["Snapshot", plan.snapshotDigest],
        ["Scope", plan.scopeId],
        ["Asset-Digest", plan.assetIdentifierDigest],
        ["Testklasse", plan.testClass],
        ["Status", plan.status]
      ])] : [],
      "Noch kein unveränderlicher Plan vorbereitet."
    );
    setText(
      "active-testing-approval-context",
      plan && approval
        ? "Approval " + approval.approvalId + " · Plan " + approval.planId + " · Status " + approval.status + ". Freigabe und Start bleiben getrennte Schritte."
        : "Noch kein aktueller Plan mit passender Freigabe."
    );
    setText(
      "active-testing-execution-context",
      plan && approval && approval.status === "accepted" && plan.status === "approved"
        ? "Plan " + plan.planId + " ist ausdrücklich freigegeben. Nur der separate Startbutton darf den einzelnen Lauf anfordern."
        : "Start bleibt bis zur aktuellen, ausdrücklichen Planfreigabe blockiert."
    );
  }

  function renderAttempts(projection) {
    var nodes = projection.attempts.map(function (attempt) {
      return card("Attempt · " + attempt.authorizationId, [
        ["Plan", attempt.planId],
        ["Testklasse", attempt.testClass],
        ["Methode", attempt.method],
        ["Status", attempt.status],
        ["Reserviert", attempt.reservedAt],
        ["Gestartet", attempt.startedAt || "nein"],
        ["Beendet", attempt.finishedAt || "nein"]
      ]);
    });
    replace("active-testing-attempt-details", nodes, "Noch kein Active-Testing-Attempt vorhanden.");
  }

  function renderReports(projection) {
    var reports = projection.reports.filter(function (report) {
      return report.reviewStatus === "local_draft_unsubmitted" &&
        report.externalSubmissionPerformed === false;
    });
    var nodes = reports.map(function (report) {
      return card("Lokaler Report · " + report.reportId, [
        ["Status", report.reviewStatus],
        ["Extern eingereicht", false],
        ["Plan", report.planId],
        ["Plan-Digest", report.planDigest],
        ["Observation-Digest", report.observationDigest],
        ["Transport", report.transportKind],
        ["DNS-Resolution-Digest", report.resolutionDigest],
        ["Markdown-Digest", report.markdownDigest],
        ["JSON-Digest", report.jsonDigest],
        ["Erstellt", report.createdAt]
      ]);
    });
    replace("active-testing-report-details", nodes, "Noch kein lokaler, nicht eingereichter Reportentwurf.");
  }

  function renderControls(projection) {
    disableAllControls();
    if (operationRunning || !capabilityReady(projection)) return;
    var noPlan = projection.currentPlan === null && projection.currentApproval === null;
    var selectedProgram = selectedProgramBinding();
    var selected = currentSelection();
    element("active-testing-program-select").disabled = !noPlan ||
      !projection.programs.some(function (program) { return programEligible(projection, program); });
    element("active-testing-asset-select").disabled = !noPlan || !selectedProgram;
    element("active-testing-class-select").disabled = !noPlan || projection.testCatalog.length === 0;
    REVIEW_IDS.forEach(function (id) {
      element(id).disabled = !noPlan || !selected;
    });
    element("active-testing-prepare-plan").disabled = !noPlan || !selected || !reviewsComplete();

    var plan = projection.currentPlan;
    var approval = projection.currentApproval;
    element("active-testing-approve-plan").disabled = !plan || !approval ||
      plan.status !== "prepared" || approval.status !== "open" || approval.planId !== plan.planId;
    element("active-testing-start-execution").disabled = !plan || !approval ||
      plan.status !== "approved" || approval.status !== "accepted" || approval.planId !== plan.planId;
  }

  function render(projection) {
    currentProjection = projection;
    renderCapability(projection);
    renderSources(projection);
    renderProgramSelector(projection);
    renderAssetSelector(projection);
    renderTestClassSelector(projection);
    renderSelectionContext();
    renderPlanAndApproval(projection);
    renderAttempts(projection);
    renderReports(projection);
    renderControls(projection);
  }

  function failClosed(message) {
    currentProjection = null;
    csrfToken = "";
    operationRunning = false;
    disableAllControls();
    resetReviews();
    clearSelect("active-testing-program-select", "Active-Testing-Zustand blockiert");
    clearSelect("active-testing-asset-select", "Active-Testing-Zustand blockiert");
    clearSelect("active-testing-class-select", "Active-Testing-Zustand blockiert");
    setText("active-testing-capability-badge", "FAIL-CLOSED BLOCKIERT");
    setText("active-testing-operation-status", message);
  }

  function captureRootState(value) {
    var root = record(value);
    var projection = root && record(root.activeTesting);
    if (!root || root.version !== 1 ||
      typeof root.csrfToken !== "string" || root.csrfToken.length < 16 ||
      !projection || !projectionValid(projection))
      throw new Error("ACTIVE_TESTING_STATE_INVALID");
    return { csrfToken: root.csrfToken, projection: projection };
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
      if (!response.ok) throw new Error("ACTIVE_TESTING_STATE_UNAVAILABLE");
      var captured = captureRootState(await response.json());
      csrfToken = captured.csrfToken;
      render(captured.projection);
    } finally {
      refreshRunning = false;
    }
  }

  async function postJson(route, body) {
    if (POST_ROUTES.indexOf(route) === -1)
      throw new Error("ACTIVE_TESTING_ROUTE_BLOCKED");
    if (csrfToken === "") throw new Error("ACTIVE_TESTING_CSRF_UNAVAILABLE");
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
      return { error: "ACTIVE_TESTING_RESPONSE_INVALID" };
    });
    if (!response.ok) {
      var resultRecord = record(result);
      var errorCode = resultRecord && typeof resultRecord.error === "string" &&
        REASON_CODE.test(resultRecord.error)
        ? resultRecord.error
        : "ACTIVE_TESTING_REQUEST_BLOCKED";
      throw new Error(errorCode);
    }
    return result;
  }

  async function runOperation(label, operation) {
    if (operationRunning) return;
    operationRunning = true;
    if (currentProjection) renderControls(currentProjection);
    setText("active-testing-operation-status", label + " wird serverseitig geprüft.");
    try {
      await operation();
      await refresh();
      setText("active-testing-operation-status", label + " abgeschlossen.");
    } catch (error) {
      var code = error instanceof Error && REASON_CODE.test(error.message)
        ? error.message
        : "ACTIVE_TESTING_REQUEST_BLOCKED";
      setText("active-testing-operation-status", label + " fail-closed blockiert: " + code);
    } finally {
      operationRunning = false;
      if (currentProjection) renderControls(currentProjection);
      else disableAllControls();
    }
  }

  function bindActions() {
    element("active-testing-program-select").addEventListener("change", function () {
      resetReviews();
      if (currentProjection) {
        renderAssetSelector(currentProjection);
        renderSelectionContext();
        renderControls(currentProjection);
      }
    });
    ["active-testing-asset-select", "active-testing-class-select"].forEach(function (id) {
      element(id).addEventListener("change", function () {
        resetReviews();
        if (currentProjection) {
          renderSelectionContext();
          renderControls(currentProjection);
        }
      });
    });
    REVIEW_IDS.forEach(function (id) {
      element(id).addEventListener("change", function () {
        if (currentProjection) renderControls(currentProjection);
      });
    });

    element("active-testing-prepare-plan").addEventListener("click", function () {
      var projection = currentProjection;
      var selected = currentSelection();
      if (!projection || !capabilityReady(projection) ||
        projection.currentPlan !== null || projection.currentApproval !== null ||
        !selected || !reviewsComplete()) {
        setText("active-testing-operation-status", "Planvorbereitung fail-closed blockiert: ACTIVE_TESTING_SELECTION_INCOMPLETE");
        return;
      }
      resetReviews();
      void runOperation("Planvorbereitung", function () {
        return postJson(ROUTES.preparePlan, {
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
        });
      });
    });

    element("active-testing-approve-plan").addEventListener("click", function () {
      var projection = currentProjection;
      var plan = projection && projection.currentPlan;
      var approval = projection && projection.currentApproval;
      if (!projection || !capabilityReady(projection) || !plan || !approval ||
        plan.status !== "prepared" || approval.status !== "open" ||
        approval.planId !== plan.planId) {
        setText("active-testing-operation-status", "Planfreigabe fail-closed blockiert: ACTIVE_TESTING_APPROVAL_NOT_CURRENT");
        return;
      }
      void runOperation("Explizite Planfreigabe", function () {
        return postJson(ROUTES.approvePlan, {
          approvalId: approval.approvalId,
          planId: plan.planId,
          confirmed: true
        });
      });
    });

    element("active-testing-start-execution").addEventListener("click", function () {
      var projection = currentProjection;
      var plan = projection && projection.currentPlan;
      var approval = projection && projection.currentApproval;
      if (!projection || !capabilityReady(projection) || !plan || !approval ||
        plan.status !== "approved" || approval.status !== "accepted" ||
        approval.planId !== plan.planId) {
        setText("active-testing-operation-status", "Start fail-closed blockiert: ACTIVE_TESTING_START_NOT_CURRENTLY_APPROVED");
        return;
      }
      void runOperation("Separater Active-Testing-Start", function () {
        return postJson(ROUTES.startExecution, {
          approvalId: approval.approvalId,
          planId: plan.planId,
          confirmed: true
        });
      });
    });
  }

  function acceptState(value) {
    try {
      var captured = captureRootState(value);
      csrfToken = captured.csrfToken;
      render(captured.projection);
    } catch {
      failClosed("Active-Testing-Zustand ist fail-closed ungültig oder nicht verfügbar.");
    }
  }

  function start() {
    disableAllControls();
    resetReviews();
    bindActions();
    window.addEventListener("bugbounty:dashboard-state", function (event) {
      acceptState(event.detail);
    });
    void refresh().catch(function () {
      failClosed("Active-Testing-Zustand ist fail-closed ungültig oder nicht verfügbar.");
    });
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();
`;
