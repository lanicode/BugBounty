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

## Phase 2 – Plattform und Konten

1. HackerOne-Adapter für Programme, Policy, Scopes und Ausschlüsse.
2. Ranking und Scope-Change-Monitor.
3. Account Factory mit E-Mail-Alias, Keychain und Auth-State.
4. CAPTCHA-/2FA-Pause mit Wiederaufnahme.
5. Testdaten- und Ownership-Ledger.

## Phase 3 – Journey-Automation

1. Playwright Test statt einfacher Library-Skripte.
2. Aufzeichnung eines Referenzablaufs.
3. Automatischer A/B-/Rollen-Replay.
4. Sicherer UI-Zustandsgraph.
5. Locator-Healing ohne neue Berechtigungen.
6. Screenshots nur nach lokaler Redaktion.

## Phase 4 – Analyse und sichere Verifikation

1. Strukturelle Request-/Response-Normalisierung.
2. Objekt- und Tenant-Datenflussanalyse.
3. Deterministisches Kandidaten-Ranking.
4. KI-Ausgaben ausschließlich über strikte JSON-Schemas.
5. Test Contract plus Policy Engine.
6. Tier-1- und Tier-2-Runner mit Budgets, Canaries, Stop und Rollback.
7. Tier 3 standardmäßig deaktiviert.

## Phase 5 – Reporting und Triage

1. Evidence Builder und Report Quality Gate.
2. HackerOne Report Intent/Report Adapter.
3. Batch-Freigabe für Einreichungen.
4. Triage-Monitor und Antwortentwürfe.
5. Feedback aus Valid/Duplicate/Informative in Ranking übernehmen.

## Phase 6 – Skalierung

1. Isolierter Worker pro Programm und Account-Matrix.
2. Zentraler Scheduler mit per-Programm-Budgets.
3. Globaler Request-Cap und Kill Switch.
4. Ereignisbasierte Datenbank und vollständige Provenienz.
5. Offline-Analyse parallelisieren; Live-Anfragen seriell und gering halten.
6. Multi-Plattform-Adapter erst nach stabiler HackerOne-Pipeline.
