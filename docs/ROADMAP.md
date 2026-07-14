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

## Phase 3 – lokale Vertrauens- und Wiederanlaufhärtung (Teil 2 abgeschlossen)

1. **Abgeschlossen:** Den External-Action-Evaluator an aktuelle, persistierte Policy-, Campaign-, Scope-, Ownership- und Approval-Evidence binden.
2. **Abgeschlossen:** Lokal authentifizierte Ed25519-Operator-Identität, signierte Freigaben, replay-sicheren Kill-Clear und persistente Clock-Grenze ergänzen.
3. Rotation und Wiederanlauf für den bereits Keychain-referenzierten Event-Schlüssel definieren.
4. Crash-/Restart- und Mehrprozess-Tests für Approval Queue, Kill Switch und Event Store ergänzen.
5. Erst danach: rein lokale Browserjourneys gegen die Demo-SaaS.

## Spätere Phase – Journey-Automation

1. Playwright Test statt einfacher Library-Skripte.
2. Aufzeichnung eines Referenzablaufs.
3. Automatischer A/B-/Rollen-Replay.
4. Sicherer UI-Zustandsgraph.
5. Locator-Healing ohne neue Berechtigungen.
6. Screenshots nur nach lokaler Redaktion.

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
