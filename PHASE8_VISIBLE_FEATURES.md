# Phase 8 – sichtbare Funktionen

## Kennzeichnung

Jede relevante Produktseite zeigt dauerhaft:

- **SIMULATIONSMODUS**
- **EXTERNE INTEGRATIONEN DEAKTIVIERT**
- **KEINE REALE REPORT-EINREICHUNG**

Die Oberfläche unterscheidet produktiv lokal, lokal simuliert, nur
Test-Harness und deaktiviert. Der Guided-Flow ist ein flüchtiger,
deterministischer Präsentationszustand und keine Autorisierung für den
persistierenden Security Core.

## Funktionsmatrix

| Funktion                                | Sichtbar/bedienbar       | Einordnung                 | Sicherheitsgrenze                                                               |
| --------------------------------------- | ------------------------ | -------------------------- | ------------------------------------------------------------------------------- |
| `pnpm app`                              | ja                       | produktiv lokal            | Control Plane, Dashboard und Demo-SaaS nur `127.0.0.1`                          |
| Runtime-Readiness                       | ja                       | produktiv lokal            | exakt validiert, redigiert, fail-closed                                         |
| Kill Switch                             | ja                       | produktiv lokal            | bei jedem Start aktiv; Engagement immer möglich                                 |
| Event Store                             | Status                   | produktiv lokal            | Setup-Shell: nicht konstruiert; sichere Runtime: open on demand                 |
| 7-Schritt-Onboarding                    | ja                       | lokal simuliert            | keine Tokens, Konten oder Secreteingabe                                         |
| Programm anlegen/bearbeiten/archivieren | ja                       | lokal simuliert            | zwei Whitelist-Namen, Primary Asset zwingend, Admin-Exclusion optional          |
| Policy-Import                           | ja                       | lokal simuliert            | lesbare oder strukturierte Seed-Fixture; Quelle, Inhalt, Hash und Diff sichtbar |
| Policy-Akzeptanz                        | ja                       | menschlicher Kontrollpunkt | nie automatisch                                                                 |
| Kampagnenvertrag                        | ja                       | lokal simuliert            | Policy v1, Tier 0, GET/HEAD, Budget `0                                          | 4   | 8`, RPM `0 | 1   | 2`, Parallelität 1 |
| Rollen                                  | ja                       | lokal simuliert            | der feste Evidence-Fall verlangt exakt Owner, Member und External               |
| Kampagnenfreigabe/pause/abbruch         | ja                       | lokal simuliert            | Freigabe explizit; Pause/Abbruch terminal fail-closed                           |
| Fixture-Identitäten/Sessions            | ja                       | lokal simuliert            | exakte Demo-SaaS-Refs; keine Registrierung oder Anmeldung                       |
| Journey                                 | ja                       | Katalogprojektion          | ID `phase7-local-demo-role-boundary`, 20 geschlossene GET-Schritte, 0 Requests  |
| Journey-Ergebnis öffnen                 | ja                       | lokal simuliert            | nur bei gültiger Demo-Bindung; kein Browserstart                                |
| Phase-7-Playwright-Replay               | nicht im Produkt         | nur Test-Harness           | separater Befehl, ausschließlich Loopback                                       |
| Inventory/Rollenmatrix                  | ja                       | lokal simuliert            | aus validierter Demo-Projektion und Katalog abgeleitet                          |
| Ownership/Canary                        | ja                       | lokal simuliert            | Objekt/Controller semantisch gebunden; Canary nur als Digest                    |
| Finding-Kandidat                        | ja                       | lokal simuliert            | Offline-Metadaten, kein aktiver Test, Budgetverbrauch 0                         |
| Evidence Bundle                         | ja                       | lokal simuliert            | bindet Demo, Journey, Rollen, Ownership, Canary, Policies und Auditref          |
| Report Markdown/HTML/JSON               | ja                       | lokal simuliert            | redigierte lokale Vorschau; keine Submission                                    |
| Lokale Review Queue/Freigabe            | ja                       | menschlicher Kontrollpunkt | nur lokale Freigabe, keine rechtliche Erklärung                                 |
| Systemstatus                            | ja                       | produktiv lokal            | Readiness, Core, Demo-Bindung, Adapter, Speicherorte und offene Core-Freigaben  |
| AIProvider                              | Status/Option `disabled` | deaktiviert                | keine LLM-Requests                                                              |
| Plattformadapter/External Actions       | Status                   | deaktiviert                | keine reale Implementierung/kein Transport                                      |

## Sichere UI-Auswahl

Der normale Ablauf benötigt keine manuelle Bearbeitung von YAML, JSON,
SQLite, Quellcode oder Terminalparametern. Die sichere Auswahl ist absichtlich
begrenzt:

- Testmail: `plus_addressing_fixture` oder `subaddress_fixture`;
- AIProvider: ausschließlich `disabled`;
- Programm: zwei lokale Namen, festes Primary Asset, optionale Admin-Exclusion;
- Policy: `human_readable_text` oder `structured_fixture`;
- Kampagne: Policy 1, drei feste Rollen, Tier 0, Budget 0/4/8, RPM 0/1/2,
  Parallelität 1;
- Journey: eine gepinnte lokale Katalog-ID.

## Demo- und Katalogbindung

Der Dashboard-Start akzeptiert nur die exakte Seed-Topologie der Demo-SaaS.
Die redigierte Projektion enthält Organisation, drei Identity-Refs,
kontrolliertes Objekt, Controller, Canary-Digest, Demo-Policy-Hash und den
kanonischen Snapshot-Digest. Jeder Guided-POST prüft den aktuellen Digest.
Drift markiert vorhandene Evidence und Reports als `stale_blocked` und sperrt
weitere Nutzung.

Der produktneutrale Journey-Katalog liegt in
`packages/local-journey-catalog`. Seine ID ist
`phase7-local-demo-role-boundary`, sein Digest
`f93fda8ba5203f1de6c7c4e2983c78c62d0767597a837d530324e6dc740673e5`.
Nur `tests/browser` führt ihn mit Playwright aus.
