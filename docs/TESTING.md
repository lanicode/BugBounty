# Testnachweis

Stand: 14. Juli 2026. Der vollständige Phase-3-Lauf steht in `PHASE3_TEST_RESULTS.txt`.

Alle Netzwerk- und Browser-Integrationstests liefen ausschließlich gegen kurzlebige Server auf `127.0.0.1`. Beispiel- und `.invalid`-Hosts wurden nur als nicht aufgelöste Testdaten verwendet.

## Aktuelles Ergebnis

- Vollständige Suite: 49 Testdateien, 247 Tests, alle bestanden.
- Phase-3-Fokussuite: 8 Testdateien, 65 Tests, alle bestanden.
- Property-Suite: 7 Testdateien, 12 Tests, alle bestanden.
- Integrationssuite: 9 Testdateien, 36 Tests, alle bestanden.
- Phase-1-Egress-Regression: 4 Testdateien, 11 Tests, alle bestanden.
- Lokale ProgramSource-Suite: 4 Testdateien, 12 Tests, alle bestanden.
- Statements: 87,73 % (3127/3564).
- Branches: 82,76 % (2161/2611).
- Funktionen: 94,90 % (670/706).
- Zeilen: 88,88 % (3016/3393).
- TypeScript-Typprüfung, ESLint ohne Warnungen, Prettier-Check und Build: bestanden.
- Dependency-Audit: keine bekannten Schwachstellen.

## Ergänzte Phase-3-Invarianten

Geschlossener Proposal-v2-Vertrag; kanonischer Digest über alle Evidence-Felder; atomare Store-Autorisierung mit `BEGIN IMMEDIATE`; strukturierte operatorgebundene Approval- und Audit-Evidence; persistenter Single-use-Replay-Schutz; globale und kampagnenbezogene Gesamt-, Concurrency-, Rate- und Clock-Rollback-Grenzen; Reopen- und Crash-Reservation; Pre-Start-Abbruch ohne Budgeterstattung; Drift vor Start und Settlement; immutable Audit- und Approval-Binding-Zeilen sowie immutable Attempt-Bindings mit trigger-erzwungenen Zustandsübergängen; Deny-All ohne Store-Evaluator; WeakSet-/Prototyp-/Proxy-/Accessor-/Method-Shadowing-Abwehr; ausschließlich gebrandeter In-Process-Mock; statische Abwesenheit neuer HTTP-, Browser-, DNS-, Socket-, Child-Process- und LLM-Transporte.

## Weiterhin abgedeckte Phase-2-Invarianten

Strikte JSON-/YAML-Importe; immutable Policy-Versionen und Diffs; Policy Drift; Kampagnenfreigaben und vollständige Vertragsdigests; Identitäts-Lifecycle und unveränderliche Account-Rollen-Scope-Snapshots; kryptografisch gebundene Ownership-Receipts; unbekannte, fremde, abgelaufene und policy-fremde Objekte; Approval-Tampering und doppelte Verarbeitung; SQLite-Migrationen einschließlich Cross-Program-Acceptance-Schutz; revisions- und auditgebundener fail-closed Kill Switch; Revalidierung aktiver Kampagnen beim Lesen; geschlossene Adapterregistrierung; deaktivierte externe Integrationen; vollständige Simulations-Gate-Kette; Demo-SaaS; interaktive CLI; 18-Schritte-Simulation; verschlüsselte Events; Dashboard-Host-/Origin-/CSRF-/Content-Type-/Größen-/UTF-8-Grenzen; echte Chromium-Navigation ausschließlich auf Loopback.

Die ursprünglichen Phase-1-Invarianten für Egress, Redaktion, Secret Store, Event Store, Policy, Audit und Browserkontrolle bleiben unverändert und vollständig in der Gesamtsuite enthalten.
