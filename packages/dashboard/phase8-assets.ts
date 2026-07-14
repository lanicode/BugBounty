export const DASHBOARD_PHASE8_JAVASCRIPT = `
"use strict";
(function () {
  var csrfToken = "";
  var currentState = null;
  var statusRefreshRunning = false;
  var guidedActions = [
    "onboarding_system_check",
    "onboarding_secret_store_check",
    "onboarding_select_simulation",
    "onboarding_configure_testmail",
    "onboarding_disable_ai",
    "onboarding_confirm_boundaries",
    "onboarding_initialize_demo",
    "create_program",
    "import_policy",
    "accept_policy",
    "create_campaign",
    "approve_campaign",
    "prepare_identities",
    "start_journey",
    "inspect_inventory",
    "generate_candidates",
    "verify_candidate",
    "open_evidence",
    "create_report",
    "queue_report_review",
    "approve_local_report"
  ];
  var guidedLabels = [
    "Systemprüfung",
    "Secret-Store-Prüfung",
    "Simulationsmodus wählen",
    "Testmail-Schema festlegen",
    "AI deaktiviert bestätigen",
    "Sicherheitsgrenzen bestätigen",
    "Lokale Demo initialisieren",
    "Programm anlegen",
    "Policy importieren",
    "Policy ausdrücklich akzeptieren",
    "Kampagne erstellen",
    "Vertrag ausdrücklich freigeben",
    "Demo-Identitäten vorbereiten",
    "Geschlossene Journey starten",
    "Inventory ansehen",
    "Kandidat erzeugen",
    "Kandidat lokal verifizieren",
    "Evidence Bundle öffnen",
    "Reportentwurf erzeugen",
    "Lokale Review Queue",
    "Report lokal freigeben"
  ];
  var confirmedActions = new Set([
    "onboarding_confirm_boundaries",
    "accept_policy",
    "approve_campaign",
    "start_journey",
    "verify_candidate",
    "queue_report_review",
    "approve_local_report"
  ]);

  function element(id) {
    var found = document.getElementById(id);
    if (!found) throw new Error("PHASE8_UI_ELEMENT_MISSING:" + id);
    return found;
  }

  function setText(id, value) {
    element(id).textContent = String(value);
  }

  function text(value, fallback) {
    if (value === null || value === undefined || value === "") return fallback || "—";
    if (Array.isArray(value)) return value.length === 0 ? "—" : value.join(", ");
    if (typeof value === "boolean") return value ? "ja" : "nein";
    return String(value);
  }

  function paragraph(label, value) {
    var node = document.createElement("p");
    node.textContent = label + ": " + text(value);
    return node;
  }

  function card(title, lines) {
    var article = document.createElement("article");
    var heading = document.createElement("h3");
    heading.textContent = title;
    article.appendChild(heading);
    lines.forEach(function (line) {
      article.appendChild(paragraph(line[0], line[1]));
    });
    return article;
  }

  function replace(id, nodes) {
    var container = element(id);
    if (nodes.length === 0) {
      var empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = "Dieser lokale Schritt wurde noch nicht ausgeführt.";
      nodes.push(empty);
    }
    container.replaceChildren.apply(container, nodes);
  }

  function renderSteps(snapshot) {
    var completed = snapshot.progress.completedSteps;
    var onboardingNodes = [];
    guidedLabels.slice(0, 7).forEach(function (label, index) {
      var item = document.createElement("li");
      item.textContent = String(index + 1) + ". " + label;
      item.className = index < completed ? "done" : index === completed ? "current" : "";
      onboardingNodes.push(item);
    });
    replace("phase8-onboarding-steps", onboardingNodes);

    var flowNodes = [];
    guidedLabels.slice(7).forEach(function (label, relativeIndex) {
      var index = relativeIndex + 7;
      var item = document.createElement("div");
      item.className = "workflow-step" + (index < completed ? " done" : index === completed ? " current" : "");
      item.textContent = String(relativeIndex + 1) + ". " + label;
      flowNodes.push(item);
    });
    replace("phase8-flow", flowNodes);
  }

  function renderOnboarding(snapshot) {
    var onboarding = snapshot.onboarding;
    setText("phase8-onboarding-status", onboarding.status);
    setText("phase8-stage", snapshot.stage + " · " + String(snapshot.progress.completedSteps) + "/" + String(snapshot.progress.totalSteps));
    var guidance = snapshot.workflowStatus === "halted_fail_closed"
      ? "Fail-closed beendet: " + text(snapshot.terminalReason) + ". Ein Neustart erzeugt eine neue flüchtige Demo-Session."
      : snapshot.workflowStatus === "completed_local_only"
        ? "Der lokale Demoablauf ist vollständig abgeschlossen. Es gab keine externe Aktion und keine reale Einreichung."
        : "Jeder Schritt ist fest vorgegeben. Bestätigungsschritte werden erst durch einen ausdrücklichen Klick ausgeführt.";
    setText("phase8-guidance", guidance);
    renderSteps(snapshot);
    replace("phase8-onboarding-details", [
      card("Systemprüfung", [["System", onboarding.systemCheck], ["Datenbank", onboarding.databaseCheck]]),
      card("Sichere Ablage", [["Secret Store", onboarding.credentialStorageCheck], ["Keine Secreteingabe", true]]),
      card("Lokale Auswahl", [["Modus", onboarding.selectedMode], ["Testmail", onboarding.testMailbox], ["AIProvider", onboarding.aiProvider], ["Demo", onboarding.demo.status]])
    ]);
  }

  function renderProgram(snapshot) {
    var nodes = [];
    if (snapshot.program) {
      nodes.push(paragraph("Name", snapshot.program.displayName));
      nodes.push(paragraph("Lebenszyklus", snapshot.program.lifecycle));
      nodes.push(paragraph("Assets", snapshot.program.allowedAssetRefs));
      nodes.push(paragraph("Ausgeschlossen", snapshot.program.excludedAssetRefs));
      nodes.push(paragraph("Revision", snapshot.program.revision));
    }
    if (snapshot.policy) {
      nodes.push(paragraph("Policy-Version", snapshot.policy.version));
      nodes.push(paragraph("Importdarstellung", snapshot.policy.importRepresentation));
      nodes.push(paragraph("Importquelle", snapshot.policy.source.origin));
      nodes.push(paragraph("Policy-Inhalt", snapshot.policy.source.preview));
      nodes.push(paragraph("Policy-Status", snapshot.policy.status));
      nodes.push(paragraph("Policy-Hash", snapshot.policy.policyHash));
      nodes.push(paragraph("Policy-Diff", snapshot.policy.diff.changed ? "vorhanden" : "keiner"));
      nodes.push(paragraph("Baseline-Hash", snapshot.policy.diff.baselineHash));
      nodes.push(paragraph("Aktueller Hash", snapshot.policy.diff.currentHash));
      nodes.push(paragraph("Darstellung", snapshot.policy.diff.representationBefore + " → " + snapshot.policy.diff.representationAfter));
      nodes.push(paragraph("Neue Assets", snapshot.policy.diff.addedAllowedAssets));
      nodes.push(paragraph("Neue Ausschlüsse", snapshot.policy.diff.addedExcludedAssets));
      nodes.push(paragraph("Neue erlaubte Testklassen", snapshot.policy.diff.addedAllowedTestClasses));
      nodes.push(paragraph("Neue Verbote", snapshot.policy.diff.newlyForbiddenTestClasses));
      nodes.push(paragraph("Request-Limit", String(snapshot.policy.diff.requestLimitBefore) + " → " + String(snapshot.policy.diff.requestLimitAfter)));
      nodes.push(paragraph("Requests pro Minute", String(snapshot.policy.diff.requestsPerMinuteBefore) + " → " + String(snapshot.policy.diff.requestsPerMinuteAfter)));
      nodes.push(paragraph("Parallelität", String(snapshot.policy.diff.maxConcurrencyBefore) + " → " + String(snapshot.policy.diff.maxConcurrencyAfter)));
    }
    replace("phase8-program", nodes);
  }

  function renderCampaign(snapshot) {
    var campaign = snapshot.campaign;
    var nodes = [];
    if (campaign) {
      ["Owner", "Member", "External"].forEach(function (role) {
        element("phase8-journey-role-" + role.toLowerCase()).checked = campaign.contract.selectedRoles.includes(role);
      });
      nodes.push(paragraph("Status", campaign.status));
      nodes.push(paragraph("Policy-Hash", campaign.policyHash));
      nodes.push(paragraph("Risikostufen", campaign.contract.allowedRiskTiers));
      nodes.push(paragraph("Rollen", campaign.contract.selectedRoles));
      nodes.push(paragraph("Methoden", campaign.contract.allowedMethods));
      nodes.push(paragraph("Request-Budget", campaign.contract.maxRequests));
      nodes.push(paragraph("Pro Minute", campaign.contract.requestsPerMinute));
      nodes.push(paragraph("Parallelität", campaign.contract.maxConcurrency));
      nodes.push(paragraph("Write-Aktionen", campaign.contract.writeActionsAllowed));
      nodes.push(paragraph("External Actions", campaign.contract.externalActionsAllowed));
      nodes.push(paragraph("Kontrollpunkte", campaign.contract.humanCheckpoints));
    }
    replace("phase8-campaign", nodes);
  }

  function renderIdentities(snapshot) {
    var nodes = snapshot.identities.map(function (identity) {
      return card(identity.role + " · " + identity.id, [
        ["Status", identity.status],
        ["Session", identity.sessionStatus],
        ["Organisation", identity.organizationRef],
        ["Eigene Objekte", identity.ownedObjectRefs],
        ["Reale Registrierung", false]
      ]);
    });
    replace("phase8-identities", nodes);
  }

  function renderJourney(snapshot, integrity) {
    var journey = snapshot.journey;
    var nodes = [];
    if (journey) {
      nodes.push(card(journey.id, [
        ["Status", journey.status],
        ["Rollen", journey.roles],
        ["Ausführung", journey.execution],
        ["Phase-7-Katalog gebunden", journey.testHarnessValidated],
        ["Katalog-Digest", journey.catalogDigestSha256],
        ["Produkt-Browser gestartet", journey.browserStarted],
        ["Netzwerkrequests", journey.networkRequests]
      ]));
      journey.liveSteps.forEach(function (step) {
        nodes.push(card("Schritt " + String(step.sequence), [
          ["Rolle", step.role],
          ["Methode", step.method],
          ["Geschlossener Pfad", step.path],
          ["Capability", step.capability],
          ["Ausführung", step.execution],
          ["Ergebnis", step.result]
        ]));
      });
    }
    replace("phase8-journey-details", nodes);
    if (integrity.status !== "bound")
      setText("phase8-journey-result-preview", "BLOCKIERT: Demo-SaaS-Drift hat das lokale Journey-Ergebnis entwertet.");
  }

  function renderInventory(snapshot) {
    var inventory = snapshot.inventory;
    var nodes = [];
    if (inventory) {
      var applications = inventory.applicationInventory || [];
      nodes.push(card("Application Inventory", [["Einträge", applications.map(function (item) { return item.applicationRef; })]]));
      nodes.push(card("Endpoint Inventory", [["Einträge", inventory.endpointInventory.map(function (item) { return item.endpointRef + ":" + item.operation; })]]));
      nodes.push(card("Rollenmatrix", [["Rollen", inventory.roleMatrix.map(function (item) { return item.role + ":" + text(item.endpointRefs); })]]));
      nodes.push(card("Ownership Ledger", [
        ["Objekte", inventory.ownershipGraph.objectRefs],
        ["Kontrolliert", inventory.ownershipGraph.allObjectsResearcherControlled],
        ["Akteure", inventory.ownershipGraph.identityRefs]
      ]));
      nodes.push(card("Ownership Graph", [["Kanten", inventory.ownershipGraph.edges.map(function (edge) { return edge.from + "→" + edge.to + ":" + edge.relation; })]]));
      nodes.push(card("Canary", [
        ["Digest", inventory.canary.digest],
        ["Wert offengelegt", inventory.canary.valueExposed],
        ["Verifiziert", inventory.canary.verified]
      ]));
      nodes.push(card("Zuordnung", [
        ["Policy", inventory.policyAssignment.policyHash + ":" + inventory.policyAssignment.status],
        ["Demo-Quellpolicy", inventory.policyAssignment.demoSourcePolicyHash],
        ["Kampagne", inventory.campaignAssignment.campaignId + ":" + inventory.campaignAssignment.status]
      ]));
    }
    replace("phase8-inventory-details", nodes);
  }

  function renderCandidates(snapshot) {
    var nodes = snapshot.candidates.map(function (candidate) {
      return card(candidate.title, [
        ["Hypothese", candidate.hypothesis],
        ["Schwachstellenklasse", candidate.vulnerabilityClass || candidate.category],
        ["Rollen", candidate.roles],
        ["Eigene Objekte", candidate.ownedObjectRefs],
        ["Mutation", candidate.mutation],
        ["Risikostufe", candidate.riskTier || candidate.severity],
        ["Request-Budget", String(candidate.requestBudget.consumed) + "/" + String(candidate.requestBudget.maximum)],
        ["Priorität", candidate.priority],
        ["Fehlalarmgründe", candidate.falsePositiveReasons],
        ["Status", candidate.status],
        ["Verifikation", candidate.verificationResult || candidate.verificationMethod],
        ["Privacy", candidate.privacyStatus],
        ["Aktiver Test", candidate.activeTestPerformed]
      ]);
    });
    replace("phase8-candidate-details", nodes);
  }

  function renderEvidence(snapshot, integrity) {
    var nodes = [];
    if (snapshot.evidence) {
      snapshot.evidence.items.forEach(function (item) {
        nodes.push(card(item.kind, [
          ["Digest", item.digest],
          ["Rolle", item.metadata.role],
          ["Identity", item.metadata.identityRef],
          ["Beobachtung", item.metadata.observation],
          ["Projektion", item.metadata.projection],
          ["Rohpayload gespeichert", item.rawPayloadStored],
          ["Bildbytes gespeichert", item.visualBytesStored]
        ]));
      });
      nodes.push(card("Bundle-Nachweise", [
        ["Bundle-Digest", snapshot.evidence.bundleDigest],
        ["Ownership-Objekt", snapshot.evidence.ownershipProof.objectRef],
        ["Ownership-Controller", snapshot.evidence.ownershipProof.controllerIdentityRef],
        ["Ownership kontrolliert", snapshot.evidence.ownershipProof.researcherControlled],
        ["Ownership-Digest", snapshot.evidence.ownershipProof.digest],
        ["Canary-Digest", snapshot.evidence.canaryProof.digest],
        ["Canary-Wert offengelegt", snapshot.evidence.canaryProof.valueExposed],
        ["Policy-Hash", snapshot.evidence.policyHash],
        ["Demo-Policy-Hash", snapshot.evidence.demoPolicyHash],
        ["Demo-Snapshot-Digest", snapshot.evidence.demoSnapshotDigest],
        ["Journey", snapshot.evidence.journeyId],
        ["Journey-Katalog-Digest", snapshot.evidence.journeyCatalogDigest],
        ["Ausgewählte Rollen", snapshot.evidence.selectedRoles],
        ["Audit-Referenzen", snapshot.evidence.auditReferences]
      ]));
    }
    if (snapshot.report) {
      nodes.push(card("Lokaler Report", [
        ["Status", snapshot.report.reviewStatus],
        ["Redigiert", snapshot.report.redacted],
        ["Extern eingereicht", snapshot.report.externalSubmissionPerformed],
        ["Integrität", integrity.reportStatus],
        ["Markdown-Digest", snapshot.report.artifacts.markdownDigest],
        ["HTML-Digest", snapshot.report.artifacts.htmlDigest],
        ["JSON-Digest", snapshot.report.artifacts.jsonDigest]
      ]));
    }
    replace("phase8-evidence-details", nodes);
    if (integrity.status !== "bound")
      setText("phase8-report-preview", "BLOCKIERT: Demo-SaaS-Drift hat Evidence und Reportentwurf entwertet.");
    ["markdown", "html", "json"].forEach(function (format) {
      element("phase8-report-" + format).disabled = !snapshot.report || integrity.status !== "bound";
    });
  }

  function renderRuntime(state) {
    var runtime = state.runtimeReadiness;
    setText("phase8-runtime-state", runtime.status.toUpperCase());
    var nodes = [
      card("Sicherheitskern", [["Phase 1", state.phase1SecurityStatus], ["Kill Switch", state.killSwitch.active ? "aktiv" : "freigegeben"]]),
      card("Lokale Dienste", [["Datenbank", runtime.databaseStatus], ["Demo-SaaS", runtime.demoSaasStatus], ["Demo-Bindung", state.localProductIntegrity.status], ["Event-Key-Konfiguration", runtime.eventKeyMinimumVersionStatus], ["Event Store", state.eventStoreStatus], ["Secret Store", runtime.secretStoreStatus]]),
      card("Worker & Adapter", [["Browserworker", runtime.browserWorkerStatus], ["AIProvider", runtime.aiProviderStatus], ["Plattformadapter", "mock_only"], ["External Actions", "disabled"]]),
      card("Policy & Freigaben", [["Policy Drift", state.policyDiffs.length > 0 ? "sichtbar" : "keiner"], ["Offene Freigaben", state.counts.openApprovals]]),
      card("Lokale Speicherorte", [["Control Plane", state.localStorageLocations.controlPlane], ["Event Store", state.localStorageLocations.eventStore], ["Browser-Testdaten", state.localStorageLocations.browserHarness]]),
      card("Grenzen", [["External Integrationen", runtime.externalIntegrationsEnabled], ["Reale Report-Einreichung", false], ["Reason Codes", runtime.reasonCodes]])
    ];
    replace("phase8-runtime-details", nodes);
  }

  function renderButtons(snapshot, integrity) {
    var index = snapshot.progress.completedSteps;
    var nextAction = snapshot.nextAction;
    var primary = element("phase8-primary-action");
    primary.disabled = nextAction === null || snapshot.workflowStatus !== "guided" || integrity.status !== "bound";
    primary.dataset.action = nextAction || "";
    primary.textContent = nextAction === null
      ? "Demoablauf abgeschlossen"
      : (confirmedActions.has(nextAction) ? "Ausdrücklich bestätigen: " : "Ausführen: ") + guidedLabels[index];

    var available = new Set(snapshot.availableManagementActions);
    element("phase8-edit-program").disabled = !available.has("edit_program");
    element("phase8-archive-program").disabled = !available.has("archive_program");
    element("phase8-start-sessions").disabled = !available.has("start_identity_sessions");
    element("phase8-pause-campaign").disabled = !available.has("pause_campaign");
    element("phase8-cancel-campaign").disabled = !available.has("cancel_campaign");
    element("phase8-pause-journey").disabled = !available.has("pause_journey");
    element("phase8-cancel-journey").disabled = !available.has("cancel_journey");
    element("phase8-open-journey-result").disabled = !snapshot.journey || snapshot.journey.status !== "completed_local_simulation" || integrity.status !== "bound";

    setConfigurationEnabled([
      "phase8-testmail-schema"
    ], nextAction === "onboarding_configure_testmail");
    setConfigurationEnabled([
      "phase8-ai-provider"
    ], nextAction === "onboarding_disable_ai");
    setConfigurationEnabled([
      "phase8-program-name",
      "phase8-asset-primary",
      "phase8-exclude-admin"
    ], nextAction === "create_program");
    setConfigurationEnabled([
      "phase8-policy-representation"
    ], nextAction === "import_policy");
    setConfigurationEnabled([
      "phase8-policy-version",
      "phase8-role-owner",
      "phase8-role-member",
      "phase8-role-external",
      "phase8-risk-tier",
      "phase8-max-requests",
      "phase8-requests-per-minute",
      "phase8-max-concurrency"
    ], nextAction === "create_campaign");
    setConfigurationEnabled([
      "phase8-journey-id",
      "phase8-journey-role-owner",
      "phase8-journey-role-member",
      "phase8-journey-role-external"
    ], nextAction === "start_journey");
  }

  function setConfigurationEnabled(ids, enabled) {
    ids.forEach(function (id) { element(id).disabled = !enabled; });
  }

  function selectedRoles(prefix) {
    return ["Owner", "Member", "External"].filter(function (role) {
      return element(prefix + role.toLowerCase()).checked;
    });
  }

  function actionPayload(action) {
    switch (action) {
      case "onboarding_configure_testmail":
        return { action: action, schema: element("phase8-testmail-schema").value };
      case "onboarding_disable_ai":
        return { action: action, provider: element("phase8-ai-provider").value };
      case "create_program":
        return {
          action: action,
          displayName: element("phase8-program-name").value,
          allowedAssetRefs: element("phase8-asset-primary").checked ? ["asset-local-primary"] : [],
          excludedAssetRefs: element("phase8-exclude-admin").checked ? ["asset-local-administration"] : []
        };
      case "import_policy":
        return { action: action, representation: element("phase8-policy-representation").value };
      case "create_campaign":
        return {
          action: action,
          policyVersion: Number(element("phase8-policy-version").value),
          roles: selectedRoles("phase8-role-"),
          riskTiers: [element("phase8-risk-tier").value],
          maxRequests: Number(element("phase8-max-requests").value),
          requestsPerMinute: Number(element("phase8-requests-per-minute").value),
          maxConcurrency: Number(element("phase8-max-concurrency").value)
        };
      case "start_journey":
        return {
          action: action,
          confirmed: true,
          journeyId: element("phase8-journey-id").value,
          roles: selectedRoles("phase8-journey-role-")
        };
      default:
        return confirmedActions.has(action)
          ? { action: action, confirmed: true }
          : { action: action };
    }
  }

  function render(state) {
    currentState = state;
    csrfToken = state.csrfToken;
    var snapshot = state.localProduct;
    renderOnboarding(snapshot);
    renderProgram(snapshot);
    renderCampaign(snapshot);
    renderIdentities(snapshot);
    renderJourney(snapshot, state.localProductIntegrity);
    renderInventory(snapshot);
    renderCandidates(snapshot);
    renderEvidence(snapshot, state.localProductIntegrity);
    renderRuntime(state);
    renderButtons(snapshot, state.localProductIntegrity);
    if (state.localProductIntegrity.status !== "bound") {
      setText(
        "phase8-guidance",
        "BLOCKIERT: Der lokale Demo-SaaS-Zustand hat sich geändert. Evidence und Report sind entwertet. App beenden und mit pnpm app neu starten. Erwarteter Digest: " + state.localProductIntegrity.expectedDemoDigest + ". Aktueller Digest: " + state.localProductIntegrity.currentDemoDigest + "."
      );
      setText("phase8-operation-status", "Fail-closed Demo-Drift erkannt; Neustart erforderlich.");
    }
  }

  async function readJson(response) {
    var body = await response.json();
    if (!response.ok) throw new Error(body.error || "PHASE8_REQUEST_BLOCKED");
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

  async function perform(action) {
    setText("phase8-operation-status", "Lokaler Schritt wird validiert …");
    var payload = actionPayload(action);
    try {
      var response = await fetch("/api/local-product/action", {
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
      await readJson(response);
      setText("phase8-operation-status", "Schritt lokal abgeschlossen; keine externe Aktion.");
      await loadState();
    } catch (error) {
      setText("phase8-operation-status", "Fail-closed blockiert: " + (error instanceof Error ? error.message : "UNKNOWN"));
    }
  }

  element("phase8-primary-action").addEventListener("click", function () {
    var action = element("phase8-primary-action").dataset.action;
    if (action) void perform(action);
  });
  element("phase8-open-journey-result").addEventListener("click", function () {
    if (!currentState || currentState.localProductIntegrity.status !== "bound") return;
    var journey = currentState.localProduct.journey;
    if (!journey || journey.status !== "completed_local_simulation") return;
    setText(
      "phase8-journey-result-preview",
      [
        "Status: " + journey.status,
        "Journey: " + journey.id,
        "Rollen: " + journey.roles.join(", "),
        "Katalog-Digest: " + journey.catalogDigestSha256,
        "Projizierte Schritte: " + String(journey.liveSteps.length),
        "Produkt-Browser gestartet: nein",
        "Netzwerkrequests: 0"
      ].join("\\n")
    );
  });
  [
    ["phase8-edit-program", "edit_program"],
    ["phase8-archive-program", "archive_program"],
    ["phase8-start-sessions", "start_identity_sessions"],
    ["phase8-pause-campaign", "pause_campaign"],
    ["phase8-cancel-campaign", "cancel_campaign"],
    ["phase8-pause-journey", "pause_journey"],
    ["phase8-cancel-journey", "cancel_journey"]
  ].forEach(function (binding) {
    element(binding[0]).addEventListener("click", function () { void perform(binding[1]); });
  });
  ["markdown", "html", "json"].forEach(function (format) {
    element("phase8-report-" + format).addEventListener("click", function () {
      if (!currentState || currentState.localProductIntegrity.status !== "bound" || !currentState.localProduct.report) return;
      setText("phase8-report-preview", currentState.localProduct.report.artifacts[format]);
    });
  });

  window.addEventListener("bugbounty:dashboard-state", function (event) {
    var nextState = event.detail;
    if (!nextState || nextState.version !== 1 || nextState.externalIntegrationsEnabled !== false) return;
    render(nextState);
  });

  window.setInterval(function () {
    if (document.visibilityState !== "visible" || statusRefreshRunning) return;
    statusRefreshRunning = true;
    void loadState()
      .catch(function (error) {
        setText("phase8-operation-status", "Fail-closed Statusfehler: " + (error instanceof Error ? error.message : "UNKNOWN"));
        setText("phase8-runtime-state", "BLOCKED");
      })
      .finally(function () {
        statusRefreshRunning = false;
      });
  }, 2000);

  void loadState().catch(function (error) {
    setText("phase8-operation-status", "Fail-closed Statusfehler: " + (error instanceof Error ? error.message : "UNKNOWN"));
    setText("phase8-runtime-state", "BLOCKED");
  });
})();
`;
