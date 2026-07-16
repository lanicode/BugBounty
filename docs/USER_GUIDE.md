# Benutzerhandbuch

## Zweck und Grenzen

Phase 8 verbindet die vorhandenen lokalen Komponenten zu einer bedienbaren
Loopback-Anwendung. Sie ist kein allgemeiner Scanner und kein autonomer
Live-Bug-Bounty-Agent. Der normale Ablauf benötigt keine Bearbeitung von YAML,
JSON, SQLite oder Quellcode und keine Terminalparameter nach dem Start.

Produktiv lokal sind Start/Shutdown, Loopback-Server, sichere HTTP-Grenzen,
SQLite-Control-Plane, Kill Switch, Readiness und Statusprojektion. Der
21-Schritt-Produktablauf ist eine flüchtige lokale Simulation. Browser-Replay
existiert ausschließlich in der Phase-7-Testsuite. AI, reale Accounts und
Report-Einreichung sind deaktiviert. Die getrennte Pilot-C-Capability kann
nach expliziter Installation ausschließlich drei niedrig-riskante Einmaltests
für exakte, API-synchronisierte HTTPS-Assets freischalten; sie gehört nicht
zum 21-Schritte-Demoablauf.

## Start und Runtime-Modi

```sh
pnpm install --frozen-lockfile
pnpm app
```

Das Terminal gibt die tatsächlichen URLs und Sicherheitszustände aus. Das
Dashboard bevorzugt `http://127.0.0.1:4173`; bei Portkonflikt wird eine
ephemere Loopback-URL ausgegeben.

- `local_setup_shell`: fehlende sichere Core-Voraussetzungen; Event Store
  nicht konstruiert, positive persistierende Core-Routen gesperrt, Kill Switch
  aktiv, Guided-Flow nur als In-Memory-Simulation.
- `local_simulation`: vollständige, validierte macOS-Keychain-/Operator-
  Konfiguration; verschlüsselter Event Store sicher open on demand.
- `blocked`: der betroffene Onboarding-Check stoppt fail-closed.

## Onboarding: 7 Schritte

1. System und Datenbank prüfen.
2. Secret-Store-Status redigiert prüfen.
3. Simulationsmodus auswählen.
4. Plus-Addressing- oder Subaddress-Testmail-Fixture wählen.
5. bestätigen, dass AIProvider deaktiviert bleibt.
6. Sicherheitsgrenzen ausdrücklich bestätigen.
7. die digestgebundene lokale Demo initialisieren.

Es werden keine echten Tokens, Konten oder Credentials abgefragt.

## Produktablauf: 14 Schritte

1. Programm aus zwei lokalen Namen anlegen; Primary Asset bleibt zwingend,
   Admin-Asset kann ausgeschlossen werden.
2. lesbare oder strukturierte lokale Policy-Fixture importieren.
3. Quelle, Inhalt, Version, Hash und vollständigen Feld-Diff prüfen und die
   Policy ausdrücklich akzeptieren.
4. Kampagne mit Policy 1, Tier 0, drei Rollen, Request-Budget 0/4/8, RPM
   0/1/2 und Parallelität 1 anlegen.
5. Kampagnenvertrag ausdrücklich freigeben.
6. Owner-, Member- und External-Fixture-Identitäten vorbereiten.
7. geschlossene Journey ausdrücklich starten.
8. Application-/Endpoint-Inventory, Rollenmatrix, Ownership Graph, Canary,
   Policy- und Kampagnenzuordnung ansehen.
9. lokalen Offline-Kandidaten erzeugen.
10. Kandidatenmetadaten ausdrücklich lokal verifizieren.
11. Baseline/Test/Kontrolltest-Evidence öffnen.
12. redigierten Reportentwurf erzeugen.
13. Report ausdrücklich in die lokale Review Queue legen.
14. Report ausdrücklich nur lokal freigeben.

„Programm bearbeiten“ ändert nur vorgegebene Metadaten. Archivieren,
Kampagne/Journey pausieren oder abbrechen beendet die flüchtige Session
terminal und fail-closed.

## Journey

Die ID `phase7-local-demo-role-boundary` und der Digest
`f93fda8ba5203f1de6c7c4e2983c78c62d0767597a837d530324e6dc740673e5`
sind fest. Die Projektion zeigt 8 Owner-, 7 Member- und 5 External-Schritte,
insgesamt 20. Alle Pfade und Capabilities stammen aus dem gemeinsamen
I/O-freien Katalog. `browserStarted` bleibt `false`, `networkRequests` bleibt
`0`. Der Button „Journey-Ergebnis öffnen“ zeigt nur diese lokale
Zusammenfassung.

## Inventory, Kandidat und Evidence

Identitäten, Organisation, kontrolliertes Objekt und Controller stammen aus
der exakt validierten Demo-SaaS-Seed-Projektion. Der Canary überschreitet die
Grenze nur als Digest. Der Kandidat zeigt Hypothese, Klasse, Rollen, Objekt,
Mutation `none_read_only`, Tier 0, ausgewähltes Request-Budget mit Verbrauch
0, Priorität, Fehlalarmgründe, Verifikation und Privacy-Status.

Der Evidence-Bundle-Digest bindet:

- drei rollen- und identitygebundene Evidence-Items;
- Objekt, Controller und Ownership-Nachweis;
- Canary-Digest ohne Rohwert;
- lokalen Policy- und Demo-Policy-Hash;
- Demo-Snapshot-Digest;
- Journey-ID, Katalog-Digest und Rollenauswahl;
- lokale Auditreferenz.

## Reports und Review

Markdown, HTML und JSON werden als redigierter Text angezeigt. Sie enthalten
keine externe Zieladresse und lösen keine Submission aus. Queue und lokale
Freigabe sind getrennte, ausdrückliche Kontrollpunkte. Die persistente
Core-Review bleibt ein separater signierter Pfad.

## Pilot-C-Active-Testing

Der Active-Testing-Bereich ist standardmäßig serverseitig deaktiviert. Auf
macOS wird er nur durch einen ausdrücklichen erneuten Installerlauf mit
`--enable-hackerone-active-testing` verfügbar. Anschließend bleiben sichere
Core-Provisionierung, globaler Kill Switch, HackerOne-Credential,
Metadatenaktivierung, API-Synchronisierung, Programmauswahl und lokale Annahme
des aktuellen Snapshots separate Schritte.

Im Bereich **Aktive Tests** kann der Operator ausschließlich ein vom Server
projiziertes, exaktes In-Scope-HTTPS-Asset und eine der Klassen
`http_headers`, `cors_preflight` oder `security_txt` wählen. Freie URL-, Host-,
Pfad-, Methoden-, Header- oder Bodyfelder existieren nicht. Vier Checkboxen
erzwingen die manuelle Prüfung von Automationsregeln, Scope-Anweisung,
Ausschlüssen und Seiteneffekten. **Plan vorbereiten** sendet keinen Request;
**Plan freigeben** erzeugt eine plan- und snapshotgebundene signierte
Entscheidung und sendet ebenfalls keinen Request. Erst **separat starten**
darf exakt einen Request ausführen.

Der Runner nutzt nur Port 443, validiertes TLS 1.2/1.3, vollständig geprüfte
öffentliche DNS-Antworten und eine an genau eine Adresse gepinnte Verbindung.
Private, Loopback-, Link-Local-, CGNAT-, Dokumentations-, reservierte und
Multicast-Adressen blockieren den gesamten Lauf. Redirects, Upgrades,
Kompression, unbekannte Content-Types, übergroße Responses, Retries und
gleichzeitige Requests blockieren. Body, Rohheader und Cookie-Werte werden
nicht persistiert. Der erzeugte Report ist immer
`local_draft_unsubmitted` mit `externalSubmissionPerformed=false`.

Die vollständige Schrittfolge und Stopkriterien stehen in
`docs/ACTIVE_TESTING_USER_GUIDE.md`.

## Status und Drift

Die zentrale Seite zeigt Kill Switch, Secret Store, Event Store, Datenbank,
Browserworker, Demo-SaaS, AIProvider, Plattformadapter, External Actions,
Policy Drift, offene persistente Core-Freigaben und lokale Speicherorte. Der
Browser pollt den State alle zwei Sekunden.

Jeder Guided-POST prüft den aktuellen Demo-Snapshot-Digest. Bei Drift zeigt
die UI Expected-/Current-Digest, `blocked_demo_drift` und eine
Neustart-Anweisung. Bereits erzeugte Evidence/Reports werden `stale_blocked`;
Buttons und Vorschauen bleiben gesperrt.

## Niemals verfügbar

Freie URLs, Locators, Scripts, Browserbefehle, unbekannte Objekt-IDs, freie
HTTP-Requests, Roh-HARs, Auth-State-Dateien, echte Accounts, CAPTCHA-/Anti-Bot-
Umgehung, automatische rechtliche Zustimmung, LLM-gesteuerte Requests und
externe Report-Einreichung. Pilot C ist ausschließlich die oben beschriebene
geschlossene Einmaltest-Pipeline und erweitert diese Verbotsliste nicht.
