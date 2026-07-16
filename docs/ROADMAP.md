# Roadmap

## Phase 0 – Bestehenden MVP stilllegen

- README-Warnung ergänzen.
- Reale Nutzung bis zur Egress- und Datenschutzabsicherung vermeiden.

## Phase 1 – Sicherheitskern

1. Validiertes Programmschema.
2. Exakter Egress Guard für Scheme, Host, Port und Pfad.
3. Trennung von Targets, Supporting Hosts und Blocked Hosts.
4. Service-Worker- und Redirect-Kontrolle.
5. Pre-Disk-Redaktion, Größenlimits und Binär-Hashing.
6. Verschlüsselter lokaler Secret- und Event-Store.
7. Policy-Hash, Policy-Drift-Stop und Audit-Log.
8. Unit-, Property- und Egress-Tests.

## Phase 2 – lokale Control Plane (abgeschlossen)

1. Lokale Program Registry und JSON-/YAML-Import.
2. Mock-Plattformadapter hinter einem eigenen, geschlossenen Interface.
3. Policy-Versionierung, Hash, Diff, menschliche Annahme und Drift-Pause.
4. Kampagnen-, Testidentitäts- und Approval-Zustandsmaschinen.
5. Ownership Ledger, External Action Registry und fail-closed Kill Switch.
6. Loopback-Dashboard, Demo-SaaS und reproduzierbare 18-Schritte-Simulation.

Reale Plattformadapter, Account-Erstellung, Browser-Sessions, aktive Tests und Report-Einreichung bleiben deaktiviert.

## Phase 3 – store-gebundene External Actions (abgeschlossen)

1. External-Action-Evaluator an aktuelle, persistierte Policy-, Campaign-, Scope-, Ownership- und Approval-Evidence binden.
2. Proposal, Payload, Budget, Reservation, Runner-Start und Settlement atomar und restart-sicher revalidieren.
3. Ausschließlich den gebrandeten deterministischen In-Process-Mock ausführbar halten.

## Phase 4 – signierte lokale Operatorgrenze (abgeschlossen)

1. Lokal authentifizierte Ed25519-Operator-Identität aus dem OS-Keychain.
2. Signierte, session-, nonce-, context- und control-plane-gebundene Freigaben.
3. Replay-sicherer Kill-Clear und persistente Clock-High-Water-Mark.

## Phase 5 – Event-Key-Rotation und Wiederanlauf (abgeschlossen)

1. Authentifizierte append-only State-Chain für aktive und lesbare
   Event-Key-Versionen.
2. Strategie **write new -> read explicitly activated old**; kein
   automatisches Re-Keying und keine automatische Key-Löschung.
3. Verpflichtender `BUGBOUNTY_EVENT_KEY_MIN_VERSION`-Rollback-Anker ohne
   Default.
4. Verzeichnisweite Mutation-Lease für Init, Legacy-Adoption, Writes und
   Rotation sowie explizite, bestätigte Offline-Recovery.
5. Zwingende Security-Core-Härtung von `packages/event-store`: geschlossene
   versionierte Hüllen, Pre-write-Größenprüfung, restriktive Dateien und
   Verzeichnis-`fsync`.
6. Echte Kindprozess-, SIGKILL-, Pre-link-, Post-link-, Restart-, Property-
   und lokale Integrationstests.

## Phase 6 – weitere Crash-/Mehrprozesshärtung (abgeschlossen)

1. Approval Queue, Kill Switch, Audit Log und Control Plane gezielt gegen
   Crash, Restart und konkurrierende lokale Prozesse qualifizieren.
2. Eine explizite Recovery- und Betriebssemantik pro persistenter Komponente
   definieren und fault-injection-getrieben testen.
3. Erst danach rein lokale Browserjourneys gegen die Demo-SaaS erweitern.

Reale Integrationen bleiben auch in Phase 6 deaktiviert; alle Netzwerk- und
Browsertests bleiben auf Loopback beschränkt.

Umgesetzt sind private und integritätsgeprüfte SQLite-Persistenz mit
deterministischem Busy-Fail-Closed, echte Commit-/Rollback-/SIGKILL-Nachweise,
restart-sichere Kill-Switch-Reconciliation sowie ein kanonisches Audit-Log mit
prozessübergreifender Lease und expliziter Offline-Recovery. Allgemeiner
Active-active- oder Netzwerkdateisystembetrieb bleibt ausdrücklich
unqualifiziert.

## Phase 7 – rein lokale Browserjourneys (abgeschlossen)

1. Playwright-Testharness ausschließlich gegen die vorhandene Demo-SaaS auf
   `127.0.0.1` ausbauen.
2. Einen deterministischen Referenzablauf mit Rollen-/A/B-Replay und
   geschlossenem UI-Zustandsgraph definieren.
3. Screenshots nur nach lokaler Redaktion und niemals als Rohsession
   persistieren.
4. Keine Plattform-, Account-, Ziel- oder externe Browserintegration
   aktivieren.

Umgesetzt ist ein test-only Playwright-Harness mit festen read-only
Rollen-/Routengraphen, zwei isolierten A/B-Replays, exakter zweistufiger
Egress-Prüfung, strikter Responseprojektion und vollständig opaken,
rollen-/zustandsgebundenen In-Memory-Screenshot-Digests. Die Profile beweisen
keine serverseitige Authentisierung oder Autorisierung. Ein produktiver
`browser_journey_start`-Runner wurde nicht registriert. ID, Rollenpläne und
Replayprofile stammen aus dem produktneutralen, I/O-freien
`packages/local-journey-catalog`; nur die Tests führen diesen Katalog aus.

## Phase 8 – lokal nutzbare Produktoberfläche (abgeschlossen)

1. Control Plane, Dashboard und Demo-SaaS mit `pnpm app` gemeinsam starten.
2. Einen strikt sequenziellen, flüchtigen 21-Schritte-Demoablauf ohne YAML-,
   JSON-, SQLite- oder Quellcodebearbeitung anbieten.
3. Programme, Policies, Kampagnen, Fixture-Identitäten, Journey, Inventory,
   Kandidaten, Evidence und lokale Reportprüfung sichtbar verbinden.
4. Fehlende Keychain-/Event-Voraussetzungen als Setupzustand darstellen und
   signierte beziehungsweise verschlüsselte Aktionen weiter fail-closed
   deaktivieren.

Umgesetzt sind `local_setup_shell` ohne Event-Store-Konstruktion und
`local_simulation` mit sicherem Open-on-demand, begrenzte exakt validierte
UI-Auswahlen, ausdrückliche Kontrollpunkte und eine semantisch an die
validierte Demo-SaaS-Seed-Projektion gebundene Evidence-Kette. Demo-Drift
blockiert Aktionen und entwertet Evidence/Reports.

Die Journey projiziert den gemeinsamen gepinnten Katalog mit 20
Owner-/Member-/External-Schritten. Sie startet keinen Produktbrowser und führt
keine aktive Sicherheitsprüfung aus. Allgemeines persistentes CRUD,
produktive Browserworker, KI-Provider, reale Adapter und Report-Einreichung
bleiben deaktiviert.

## Pilot Readiness A–C – begrenzte HackerOne-Pipeline

1. Authentifizierte HackerOne-Programmdaten, Structured Scopes und Exclusions
   ausschließlich read-only synchronisieren.
2. Initialen lokalen Security Core über eine ausdrückliche secretfreie
   Keychain-Aktion provisionieren; laufende Instanz danach restart-locked.
3. Für exakte aktuelle API-URL-Scopes nur drei niedrig-riskante
   Einmaltestklassen anbieten: Header-`HEAD`, CORS-`OPTIONS` und Root-
   `security.txt`-`GET`.
4. Plan, signierte Freigabe und Start als getrennte Kontrollpunkte erzwingen;
   persistente Budgets, DNS-/SSRF-/TLS-Pinning, Kill Switch und redigierte
   lokale Reports verwenden.

Umgesetzt ist Pilot C als standardmäßig deaktivierte, geschlossene
Capability. Automatische Regelannahme, Accounts, Auth-/Credentialtests,
Browserautomation gegen reale Ziele, Schreibmethoden, allgemeines Scanning,
LLM-gesteuerte Requests und Report-Einreichung bleiben deaktiviert.

## Spätere Phase – Analyse und sichere Verifikation

1. Strukturelle Request-/Response-Normalisierung.
2. Objekt- und Tenant-Datenflussanalyse.
3. Deterministisches Kandidaten-Ranking.
4. KI-Ausgaben ausschließlich über strikte JSON-Schemas.
5. Test Contract plus Policy Engine.
6. Tier-1- und Tier-2-Runner mit Budgets, Canaries, Stop und Rollback.
7. Tier 3 standardmäßig deaktiviert.

## Spätere Phase – Reporting und Triage

1. Evidence Builder und Report Quality Gate.
2. HackerOne Report Intent/Report Adapter.
3. Batch-Freigabe für Einreichungen.
4. Triage-Monitor und Antwortentwürfe.
5. Feedback aus Valid/Duplicate/Informative in Ranking übernehmen.

## Spätere Phase – Skalierung

1. Isolierter Worker pro Programm und Account-Matrix.
2. Zentraler Scheduler mit per-Programm-Budgets.
3. Globaler Request-Cap und Kill Switch.
4. Ereignisbasierte Datenbank und vollständige Provenienz.
5. Offline-Analyse parallelisieren; Live-Anfragen seriell und gering halten.
6. Multi-Plattform-Adapter erst nach stabiler HackerOne-Pipeline.
