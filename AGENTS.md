# Sicherheitsregeln für Repository-Agenten

## Geltungsbereich

Der produktive Code in `apps/` und `packages/` enthält den
Phase-1-Sicherheitskern, die lokale Phase-2-Control-Plane, den store-gebundenen
Phase-3-External-Action-Evaluator, die lokale signierte
Phase-4-Operatorgrenze, den restart-sicheren Phase-5-Event-Key-Lifecycle und
die lokale Phase-6-Crash-/Mehrprozesshärtung. Phase 7 ergänzt ausschließlich
testseitige lokale Browserqualifizierung unter `tests/browser`; sie ist kein
Produkt- oder External-Action-Runner und ändert keinen Phase-1-Pfad. Phase 8
ergänzt eine loopbackgebundene, fail-closed startbare Produktoberfläche und
einen rein lokalen, deterministischen Präsentationsworkflow. Dieser Workflow
ist weder Scan-Engine noch Browserrunner, erzeugt keine Netzwerkaktion und ist
deutlich als Simulation beziehungsweise Test-Harness-validierte Darstellung
gekennzeichnet. Innerhalb des Phase-1-Kerns änderte Phase 5 zwingend den Event
Store und Phase 6 zwingend das Audit-Log; beide Änderungen sind in ihren
Security-Core-Berichten dokumentiert. Phase 8 verändert den Phase-1-Kern
nicht. Pilot Readiness C ergänzt eine separat aktivierbare, standardmäßig
gesperrte Capability für niedrig-riskante aktive HTTPS-Prüfungen. Sie darf nur
exakt ausgewählte Assets aus einem aktuellen, authentifizierten und
ausdrücklich akzeptierten HackerOne-Snapshot verwenden. Jeder Plan bindet
Schema, Policy, Scope, Budget, Kill Switch, Operatorentscheidung und
deterministischen Runner; Entwicklung, CI und automatisierte Tests bleiben
Loopback-only. `legacy/mvp/` ist ausschließlich eine unsichere, nicht
produktive Audit-Referenz.

## Nicht verhandelbare Regeln

- Netzwerk- und Browsertests laufen ausschließlich gegen Loopback-Adressen. Beispielhosts werden nie aufgelöst oder kontaktiert.
- Playwright-Tests verwenden nur die eigene Fixture unter `tests/browser`.
  Ein Browserkontext muss vor der ersten Page durch den Phase-1-Egress-Guard
  und den exakten aktuellen Schritt-Guard geschützt sein. Ungeschützte
  `page`-/`context`-Fixtures, freie URLs, Retries und produktive Browserstarts
  sind verboten.
- Automatische Screenshots, Traces, Videos, HARs, Attachments, Storage-State
  und Page-Snapshots bleiben deaktiviert. Screenshotbytes dürfen nur nach
  verifizierter vollständiger lokaler Maskierung ohne Dateipfad entstehen,
  als streng validierter Digest freigegeben und anschließend genullt werden.
- Jede Netzwerkentscheidung erfolgt vor dem Request, deny-by-default und fail-closed.
- Aktive Sicherheitstests sind ausschließlich innerhalb der Pilot-Readiness-C-
  Capability zulässig: niedrig-riskante HTTPS-`GET`/`HEAD`/`OPTIONS`-Prüfungen,
  exakter aktueller HackerOne-Snapshot, ausdrückliche lokale Policyannahme,
  exakte Assetauswahl, frische signierte Planfreigabe, persistentes Budget und
  standardmäßig deaktivierter Transport. Reale Kontoerstellung,
  Credential-Angriffe, Exploitation mit Seiteneffekt, Schreibmethoden,
  automatische Report-Einreichung und LLM-gesteuerte Requests bleiben
  verboten.
- Phase-2-Quellen, Mock-Adapter, Demo-SaaS und Simulation bleiben vollständig
  lokal. Externe Transporte existieren ausschließlich für die feste
  HackerOne-Metadaten-API und die getrennte Pilot-Readiness-C-Capability;
  beide bleiben standardmäßig deaktiviert und benötigen ihre jeweils eigene
  signierte Freigabe. Das Dashboard selbst bleibt loopbackgebunden.
- Keine Roh-HARs, Rohbodys, Tokens, Cookies, Zugangsdaten oder Identitätsdaten persistieren oder loggen.
- Persistierung erfolgt erst nach Redaktion und Größenprüfung. Eventdaten werden ausschließlich authentifiziert verschlüsselt gespeichert.
- Produktionsschlüssel stammen ausschließlich aus dem OS-Keychain-Adapter. Es gibt keinen Klartext-Fallback.
- `BUGBOUNTY_EVENT_KEY_MIN_VERSION` ist für jeden Start des verschlüsselten
  Event-Runtimes und für jeden Event-Key-Adminstart verpflichtend. Es gibt
  keinen Default. `pnpm app` darf ohne diese Konfiguration ausschließlich die
  loopbackgebundene `local_setup_shell` öffnen: Der Event Store wird nicht
  konstruiert und alle positiven persistierenden Core-Routen bleiben
  serverseitig gesperrt; nur Kill-Switch-Engagement und der flüchtige, klar
  simulierte Guided Flow bleiben verfügbar. Ungültige oder unter dem
  authentifizierten Head liegende Konfiguration blockiert weiterhin
  fail-closed.
- Event-Key-Versionen werden monoton um exakt eins aktiviert: neue Events
  verwenden nur den neuen Head, alte Hüllen bleiben nur über ausdrücklich
  aktivierte historische Versionen lesbar. Automatisches Re-Keying und
  automatische Key-Löschung sind verboten.
- Init, Legacy-Adoption, Event-Writes und Rotation müssen die verzeichnisweite
  Mutation-Lease über den vollständigen Refresh-/Commit-Bereich halten. Eine
  verbliebene Lease oder Event-Temporärdatei blockiert; Recovery ist nur als
  ausdrücklich bestätigter lokaler Offline-Adminschritt erlaubt und darf eine
  nachweislich aktive Eigentümer-PID niemals verdrängen.
- Private Operator-Schlüssel werden ausschließlich als Ed25519-PKCS#8 über
  eine `keychain://`-Referenz geladen. Schlüsseldateien, Schlüsselmaterial in
  Umgebungsvariablen, unbeaufsichtigte Provisionierung und Klartext-Fallbacks
  sind verboten. Pilot Readiness C darf für einen nachweislich frischen,
  leeren Core eine ausdrücklich angeklickte lokale Einmal-Provisionierung über
  einen fest verdrahteten nativen Keychain-Helfer anbieten. Die einzige
  Legacy-Ausnahme ist ein konservativ validierter `legacy_ready`-Zustand: exakt
  der lesbare 32-Byte-Eintrag `event-store-v1` ist vorhanden, Operator-Eintrag,
  lokales Operator-Enrollment und Event-Store-Verzeichnis fehlen. Dann darf
  ausschließlich die fehlende Operator-Hülle neu angelegt werden; der
  bestehende Event-Key wird weder verändert noch ausgegeben. Teil- und
  Konfliktzustände blockieren. Provisionierung darf keine bestehenden
  Einträge überschreiben, keine Rotation/Recovery auslösen und keine
  Secretbytes an Browser, argv, Environment, Logs oder Dateien geben.
- Jede neue persistierte Approval-Entscheidung sowie jeder Kill-Switch-Clear benötigt eine gültige, frische, session-, nonce-, control-plane- und kontextgebundene Operator-Signatur. Freie Actor-Strings sind keine Credential.
- Signaturprüfung, Replay-Schutz, Decision-Evidence, Approval-Transition, Audit und External-Action-Binding bleiben atomar in `BEGIN IMMEDIATE`. Die store-eigene Uhr und ihr persistenter High-Water-Mark dürfen nicht umgangen werden.
- Policy-Drift, Redirects, Service Worker, WebSockets, unbekannte Content-Types und Budgetfehler blockieren.
- Regelannahmen, Kampagnenfreigaben, Account-Schritte, rechtliche Erklärungen und Reportfreigaben dürfen niemals automatisch bestätigt werden.
- Checkpoint-freie Demoidentitäten sind ausschließlich vorautorisierte In-Process-Fixtures. Sobald ein Mock-Account-Plan CAPTCHA, E-Mail, TOTP, Regeln, Bedingungen oder Rechtserklärungen enthält, muss der Workflow pausieren; kein Checkpoint darf automatisch erfüllt werden.
- Externe Aktionen müssen über Registry, Schema, Policy, Scope, Ownership, Budget, menschlichen Kontrollpunkt und deterministischen Runner laufen.
- Positive External-Action-Entscheidungen dürfen ausschließlich aus einem atomaren, aktuellen `ControlPlaneStore`-Snapshot entstehen. Caller-Booleans, Callback-Gates und Freitextsuche sind keine Autorisierung.
- Proposal, Policy, Kampagnenrevision/-digest, Scope, Accountrolle, Ownership, Payload, Approval, Operator, Budget und Audit müssen exakt gebunden und vor Start sowie Settlement erneut geprüft werden.
- Proposal-IDs, Attempts und Budgets sind persistent. Abbruch und Fehler erstatten kein Budget; Crash-Reservationen bleiben fail-closed blockierend.
- Das initiale Operator-Enrollment ist lokales TOFU bei aktivem Kill Switch.
  Es ist keine rechtliche Zustimmung, keine Hardwarebindung und kein Beweis
  menschlicher Anwesenheit. Enrollment oder Core-Provisionierung allein
  aktivieren niemals einen realen Runner; dafür bleiben separate Runtime-,
  Snapshot-, Policy-, Plan-, Budget- und Freigabegrenzen verpflichtend.
- Event-Key-Adoption, -Rotation und -Recovery sind lokale Offline-
  Adminoperationen bei beendetem Dashboard. Kein Dashboard-, HTTP-, Browser-,
  LLM- oder External-Action-Pfad darf sie auslösen. Davon getrennt ist nur die
  ausdrücklich bestätigte Einmal-Provisionierung eines nachweislich leeren
  Event Stores beziehungsweise der oben exakt begrenzte `legacy_ready`-
  Abschluss nach der Pilot-Readiness-C-Grenze zulässig.
- Das dateibasierte Audit-Log rehydriert und verifiziert den vollständigen
  kanonischen Head unter einer privaten prozessübergreifenden Mutation-Lease.
  Teilzeilen werden niemals still ignoriert oder gekürzt. Lease-Recovery ist
  nur als exakt bestätigter lokaler Offline-Schritt bei zweimal nachweislich
  nicht existierender Eigentümer-PID zulässig.
- File-backed SQLite verwendet einen privaten lokalen Pfad, `DELETE`-Journal,
  `synchronous=FULL`, `fullfsync=ON`, verifizierte Foreign Keys und
  Integritätsprüfungen beim Reopen. WAL/SHM, user-owned Symlink-Ahnen,
  unerwartete Sidecars und Busy/Locked-Zustände blockieren fail-closed.
- `external_integrations_enabled` bleibt standardmäßig sowie bei fehlender oder fehlerhafter Konfiguration effektiv `false`.
- Der globale Kill Switch ist fail-closed; Lesefehler, fehlende Audit-Referenzen, Revisionsfehler und inkonsistente Clear-Zustände gelten als aktiv. Engagement, durable Kampagnenpause und Audit-Fortsetzung bilden drei geordnete Grenzen. Ein Auditfehler darf weder Engagement noch Pause zurückrollen; Reopen versöhnt nur in Richtung `engaged`/`paused`.
- Sicherheitsgrenzen benötigen direkte Unit-, Property- und Integrationstests. Tests dürfen nicht zur Fehlerbehebung gelockert werden.
- Neue Abhängigkeiten werden exakt gepinnt und in `docs/DEPENDENCIES.md` begründet.

## Architekturgrenzen

- `packages/config`: untrusted YAML/JSON bis zur Schema- und Semantikvalidierung.
- `packages/egress-guard`: einzige Freigabestelle des Phase-1-Kerns für HTTP-/Browser-Egress.
- `packages/redaction`: einzige Transformation vor Eventpersistierung.
- `packages/secret-store`: Keychain-Produktion und In-Memory nur für Tests.
- `packages/active-testing`: geschlossene Pilot-C-Plan-, Approval-, Budget-,
  DNS-/TLS-, Evidence- und lokale Reportgrenze; kein allgemeiner HTTP-Client.
- `packages/event-store`: versionierte AES-256-GCM-Hüllen, explizit aktivierte
  Leseversionen, write-once-Dateien, enge Größengrenzen sowie Datei- und
  Verzeichnis-Durability; zwingende Phase-5-Security-Core-Änderung.
- `packages/event-key-lifecycle`: authentifizierte append-only State-Chain,
  Mindestversionsanker, verzeichnisweite Mutation-Lease und explizite lokale
  Recovery; einzige Aktivierungsgrenze für Event-Key-Versionen.
- `packages/policy`: Phase-1-Vertrag, Budgets, Kill Switch und deterministische Reason Codes.
- `packages/audit-log`: bodyfreies, kanonisches append-only JSONL mit
  Hash-Verkettung, prozessübergreifender Lease, Restart-Rehydration und
  expliziter lokaler stale-Lease-Recovery.
- `packages/platform-source`: lokale, strikt validierte Plattform-Snapshots ohne HTTP-Client.
- `packages/control-plane`: lokale SQLite-Datenmodelle, Migrationen und Zustandsmaschinen.
- `packages/external-actions`: einzige trusted Registry und allgemeine
  Simulations-/Gate-Pipeline für externe Wirkungen. Ein spezialisierter Runner
  wie Pilot C darf eine engere eigene Zustandsmaschine besitzen, muss aber die
  passende tief unveränderliche Registrydefinition und deren kanonischen
  Digest vor Vorbereitung, Reservation, Start und Abschluss konsumieren und
  erneut prüfen; er darf keine zweite Registry erfinden.
- `packages/operator-auth`: einzige lokale Ed25519-Signaturgrenze für Enrollment, Approval-Entscheidungen und Kill-Switch-Clear.
- `packages/dashboard` und `packages/demo-saas`: ausschließlich `127.0.0.1`, feste Routen und lokale Mocks.
- `packages/local-runtime`: reine, redigierte Readiness-Ableitung ohne I/O oder
  positive Capability-Erzeugung.
- `packages/local-product`: in-memory Präsentationszustand mit exakt
  validierten lokalen UI-Auswahlen für den geführten Phase-8-Ablauf; an den
  tatsächlichen Demo-SaaS-Snapshot und den gemeinsamen Phase-7-Journey-Katalog
  gebunden, aber keine Autorisierungsgrenze und kein Egress.
- `packages/local-journey-catalog`: einzige produktionsneutrale Quelle des
  geschlossenen lokalen Journey-Profils; Produktcode projiziert nur den
  Katalog, während ausschließlich der Phase-7-Test-Harness Browser-Evidence
  erzeugt.
- `tests/browser`: geschlossene lokale Playwright-Testinfrastruktur; niemals
  aus `apps/`, `packages/external-actions`, Control Plane oder LLM-Pfaden
  importieren.

Konservative Entscheidungen, bewusst deaktivierte Funktionen und jede zwingende Änderung am Phase-1-Kern sind in den Abschlussdokumenten festzuhalten.
