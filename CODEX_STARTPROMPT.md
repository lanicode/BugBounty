# Codex-Startprompt: Bug-Bounty-Copilot v2, Phase 1

Du arbeitest in diesem privaten Repository als **Principal Security Engineer und Principal Software Engineer**. Deine Aufgabe ist, aus dem vorhandenen Architektur-Blueprint und dem alten Demo-MVP einen belastbaren **Phase-1-Sicherheitskern** zu bauen.

## Repository-Kontext

- Die Zielarchitektur, Schemata, Beispielkonfigurationen und Roadmap liegen im Repository-Root.
- Der alte, unsichere Demo-MVP liegt unter `legacy/mvp/`.
- Lies zuerst vollständig:
  - `README.md`
  - `docs/MVP_AUDIT.md`
  - `docs/ROADMAP.md`
  - `docs/AUTOMATION_MATRIX.md`
  - `docs/PLATFORM_STRATEGY.md`
  - `config/program.example.yaml`
  - `config/approval-profile.example.yaml`
  - `schemas/*.json`
  - `policies/scope.rego`
  - alle Dateien unter `legacy/mvp/`

## Hauptziel

Implementiere ausschließlich **Phase 1 – Sicherheitskern** aus `docs/ROADMAP.md`.

Das Ergebnis muss eine sichere Grundlage für spätere Automatisierung sein. Es ist noch kein autonomer Live-Scanner und noch kein aktiver Bug-Bounty-Runner.

## Nicht verhandelbare Sicherheitsgrenzen

1. **Keine Verbindung zu realen Bug-Bounty-Zielen oder Plattformkonten.**
   - Führe während der Entwicklung und der Tests ausschließlich lokale Mock-Server auf Loopback-Adressen aus.
   - Beispielhosts aus Konfigurationsdateien dürfen niemals tatsächlich aufgerufen werden.
   - Paketinstallation aus offiziellen Paketquellen ist zulässig; sonstiger externer Netzwerkzugriff nicht.

2. **Deny by default.**
   - Kein Request darf den Browser oder HTTP-Client verlassen, bevor Scheme, normalisierter Host, Port, Methode und normalisierter Pfad geprüft wurden.
   - Unbekannte oder mehrdeutige Fälle werden blockiert.
   - Es gibt keinen unsicheren Fallback und keinen `--force`-Schalter, der Schutzmechanismen umgeht.

3. **Keine Rohdaten auf Datenträger.**
   - Keine vollständigen HAR-Dateien.
   - Cookies, Authorization-Header, Tokens, Passwörter, API-Schlüssel und sensible Query-/Body-Felder dürfen weder in Dateien, Logs, Exceptions noch Test-Snapshots gelangen.
   - Redaktion und Größenprüfung müssen vor jeder Persistierung stattfinden.
   - Binärinhalte werden standardmäßig nicht gespeichert, sondern nur gehasht.

4. **KI ist niemals Ausführungsinstanz.**
   - In Phase 1 gibt es keine LLM-Integration und keinen allgemeinen HTTP- oder Browser-Toolzugriff.
   - Die Policy Engine und der Egress Guard sind deterministisch.
   - Das vorhandene Rego-Dokument bleibt Referenz beziehungsweise testbare Policy-Basis.

5. **Keine aktiven Sicherheitstests.**
   - Kein Fuzzing, Crawling, ID-Tausch, Replay, Scanning, Brute Force, Login-Automation, Account-Erstellung, Report-Einreichung oder HackerOne-API-Integration.
   - Keine Mutation fremder oder unbekannter Objekte.
   - Phase 2 und spätere Roadmap-Punkte werden nicht vorgezogen.

6. **Fail closed.**
   - Bei Policy-Drift, ungültiger Konfiguration, fehlendem Secret Store, unbekanntem Content-Type, Redirect, Service Worker, WebSocket oder Budgetfehler stoppt beziehungsweise blockiert das System.
   - Wenn du bei einer sicherheitsrelevanten Entscheidung unsicher bist, wähle die restriktivere Variante und dokumentiere sie.

## Arbeitsweise

- Arbeite auf einem separaten Branch oder Worktree, zum Beispiel `codex/phase-1-security-core`.
- Beginne mit einer vollständigen Bestandsaufnahme.
- Schreibe danach `docs/IMPLEMENTATION_PLAN.md` und `docs/THREAT_MODEL.md`.
- Bleibe nicht beim Plan stehen: implementiere den vollständigen Phase-1-Sicherheitskern und führe alle Tests aus.
- Erstelle logische, kleine Commits. Nicht pushen, nicht mergen und keine Releases veröffentlichen.
- Frage nur nach, wenn eine fehlende Datei die Arbeit technisch unmöglich macht. Bei normalen Architekturentscheidungen triff eine konservative Entscheidung und dokumentiere sie.
- Keine TODO-Platzhalter für Sicherheitsgrenzen. Unfertige optionale Funktionen müssen deaktiviert und ausdrücklich als nicht implementiert markiert sein.
- Deaktiviere oder lockere keine Tests, um einen grünen Lauf zu erzwingen.

## Bevorzugte technische Richtung

Nutze für den sicherheitskritischen Kern **TypeScript im selben Ökosystem wie Playwright**. Der alte Python-/JavaScript-MVP bleibt unter `legacy/mvp/` als nicht produktive Referenz und darf nicht als Sicherheitsgrenze wiederverwendet werden.

Bevorzugte Struktur:

```text
apps/
  cli/
  recorder/
packages/
  config/
  egress-guard/
  redaction/
  event-store/
  secret-store/
  policy/
  audit-log/
schemas/
policies/
tests/
  unit/
  property/
  integration/
  fixtures/
legacy/
  mvp/
```

Nutze möglichst wenig Abhängigkeiten, bevorzuge Standardbibliotheken und begründe jede sicherheitsrelevante Abhängigkeit in `docs/DEPENDENCIES.md`. Erzeuge reproduzierbare Lockfiles und pinne Tooling nachvollziehbar. Verwende strikten TypeScript-Modus.

## Verbindliche Deliverables

### A. Repository und Tooling

- Root-`package.json` mit reproduzierbaren Scripts.
- Strikte TypeScript-Konfiguration.
- Linting, Formatprüfung, Typprüfung und Test-Suite.
- Sichere `.gitignore`, die mindestens Profile, Auth-State, Rohtraffic, Secrets, Quarantäne, lokale Datenbanken, Event Stores und temporäre Beweise ausschließt.
- `AGENTS.md` mit Architekturregeln für spätere Codex-Aufgaben.
- `SECURITY.md` mit sicherem Entwicklungs- und Testmodell.
- `docs/IMPLEMENTATION_PLAN.md`
- `docs/THREAT_MODEL.md`
- `docs/DEPENDENCIES.md`
- `docs/PHASE1_OPERATIONS.md`

### B. Validiertes Programmschema

Implementiere einen Loader und Validator für `config/program.example.yaml` und den Kampagnenvertrag.

Anforderungen:

- JSON-Schema-Validierung mit klaren, aber redigierten Fehlern.
- Unbekannte Felder werden abgelehnt.
- Placeholder wie `REPLACE_ME`, `example.com` und leere Targetlisten verhindern einen produktiven Start.
- Targets, Supporting Hosts und standardmäßig blockierte Ziele werden strikt getrennt.
- Konfiguration wird kanonisch serialisiert und mit SHA-256 gehasht.
- Akzeptierter Policy-Hash wird separat gespeichert beziehungsweise referenziert.
- Jede Abweichung erzeugt einen harten Policy-Drift-Stop.
- Keine Secrets in YAML oder JSON-Konfigurationen.

### C. Exakter Egress Guard

Implementiere einen kontextweiten Playwright-Egress-Guard, bevor die erste Seite oder Navigation entsteht.

Er muss mindestens prüfen:

- Scheme
- kanonisch normalisierten Host
- Port einschließlich Standardport-Normalisierung
- HTTP-Methode
- normalisierten, dekodierten Pfad gegen erlaubte Präfixe
- Target versus Supporting Host
- Capture-Modus
- Redirect-Verbot
- Service-Worker-Verbot
- WebSocket standardmäßig blockiert
- Popups, neue Seiten, Frames, XHR, Fetch, Form-Submits und Navigationen unter derselben Policy

Sicherheitsanforderungen:

- keine Suffix- oder Substring-Matches für Hosts
- Schutz gegen Userinfo-URLs
- Schutz gegen Groß-/Kleinschreibung, abschließenden Punkt, IDN/Punycode und IPv6-Mehrdeutigkeiten
- nicht freigegebene Ports blockieren
- Plain HTTP blockieren, sofern nicht explizit für lokale Tests erlaubt
- Pfadtraversal und kodierte Traversalvarianten dürfen Präfixregeln nicht umgehen
- Supporting Hosts dürfen nur explizit erlaubte Methoden nutzen und niemals als Finding-Ziel behandelt werden
- Entscheidung wird vor dem Request getroffen
- jede Entscheidung erhält einen maschinenlesbaren Reason Code

### D. Pre-Disk-Redaktion und Datensparsamkeit

Ersetze die HAR-basierte Aufzeichnung durch einen selektiven Event-Recorder.

Er muss:

- Header-Allowlist beziehungsweise sichere Denylist verwenden
- Cookies und Authorization immer vollständig verwerfen
- sensible Query-Parameter redigieren
- JSON rekursiv redigieren
- Textkörper begrenzen und redigieren
- Multipart/Form-Data sicher behandeln oder vollständig verwerfen, bis eine sichere Implementierung vorhanden ist
- stabile lokale HMAC-Pseudonyme erzeugen
- Response-Body nur für explizit erlaubte Content-Types und bis zur Größenobergrenze verarbeiten
- unbekannte, komprimierte, übergroße oder binäre Inhalte nur als Metadaten und SHA-256 erfassen
- niemals Rohbody in Debug-Logs schreiben
- unbekannte Identitätsdaten in einen verschlüsselten Quarantänestatus überführen, ohne sie an normale Analysekomponenten weiterzugeben

### E. Secret Store und verschlüsselter Event Store

Implementiere klare Interfaces und mindestens:

- einen sicheren Produktionsadapter für lokalen Secret-Speicher; bevorzugt nativer Betriebssystem-Keychain, ohne Klartext-Fallback
- einen `InMemorySecretStore` ausschließlich für Tests
- einen verschlüsselten lokalen Event Store mit authentifizierter Verschlüsselung, eindeutigen Nonces, Versionsfeld und Integritätsprüfung
- Schlüssel kommen ausschließlich über den Secret Store
- atomare Schreibvorgänge
- sichere Dateirechte, soweit das Betriebssystem dies unterstützt
- Rotation beziehungsweise Versionierung der Schlüsselhülle
- keine Secrets in Prozessargumenten, Dateinamen oder Logs

Wenn die Codex-Umgebung den nativen Produktionsadapter nicht ausführen kann, implementiere ihn trotzdem testbar über eine abstrahierte Schnittstelle und verwende in Tests ausschließlich den In-Memory-Adapter. Es darf keinen stillen Klartextmodus geben.

### F. Policy-Kern, Budgets und Audit-Log

- Implementiere den Kampagnenvertrag aus `schemas/test-contract.schema.json`.
- Spiegele die relevanten Regeln aus `policies/scope.rego` in einem deterministischen Policy-Adapter oder führe OPA kontrolliert als Policy Engine aus.
- Policy-Hash, Vertrag, Asset, Konto, Budget, Risiko-Tier und Laufzeit müssen prüfbar sein.
- In Phase 1 werden nur Offline-/Capture-Aktionen erlaubt; aktive Test-Tiers bleiben deaktiviert.
- Implementiere ein append-only Audit-Log mit Hash-Verkettung.
- Audit-Einträge enthalten keine Secrets oder Bodydaten.
- Baue einen Verifier, der die Hash-Kette und Policy-Entscheidungen prüft.
- Globaler Kill Switch und Abbruchsignal müssen vorhanden und getestet sein.

### G. CLI

Mindestens folgende Befehle:

```text
npm run doctor
npm run validate
npm run policy:hash
npm run policy:verify
npm run audit:verify
npm run test
npm run test:egress
npm run typecheck
npm run lint
```

Optional darf ein Recorder-CLI vorhanden sein, aber:

- Standard ist `dry-run` beziehungsweise lokaler Mock-Modus.
- Ein Start gegen nicht lokale Ziele muss ohne ausdrücklich akzeptierten, passenden Policy-Hash hart fehlschlagen.
- Codex selbst darf diesen Modus während dieser Aufgabe nicht gegen externe Hosts ausführen.

### H. Tests und Acceptance Criteria

Nutze Unit-, Property- und Integrations-Tests. Alle Netzwerktests laufen gegen kurzlebige lokale Mock-Server.

Mindestens folgende Fälle müssen automatisiert getestet werden:

1. Exakter erlaubter Target-Request passiert.
2. `api.example.test.evil.test` wird blockiert.
3. `https://api.example.test@evil.test/` wird blockiert.
4. Nicht freigegebener Port wird blockiert.
5. Plain HTTP wird außerhalb expliziter lokaler Testkonfiguration blockiert.
6. Großschreibung, abschließender Punkt und IDN/Punycode werden sicher kanonisiert oder blockiert.
7. Kodierte und doppelt kodierte Pfadtraversal kann kein Path-Prefix umgehen.
8. Redirect wird vor dem Folgen blockiert.
9. Supporting Host: erlaubtes `GET` passiert nur im konfigurierten Capture-Modus.
10. Supporting Host: nicht erlaubtes `POST` wird blockiert.
11. Popup, neue Seite, iframe, XHR, Fetch und Form-Submit unterliegen dem Guard.
12. Service Worker werden im Capture-Modus blockiert.
13. WebSocket wird standardmäßig blockiert.
14. Ein definierter Secret-Marker erscheint nach einem Lauf nirgends in Event Store, Audit-Log, stdout, stderr, Exceptions oder Testartefakten.
15. Übergrößenlimit liegende Bodies werden nicht persistiert.
16. Binärbody wird nur gehasht.
17. HMAC-Pseudonyme sind innerhalb eines lokalen Schlüssels stabil, aber ohne Schlüssel nicht reversibel.
18. Ungültige Config und unbekannte Felder failen geschlossen.
19. Placeholder-Config kann keinen Recorder starten.
20. Policy-Hash-Änderung stoppt den Lauf.
21. Abgelaufener Vertrag wird blockiert.
22. Budgetüberschreitung und Parallelität über 1 werden blockiert.
23. Kill Switch stoppt laufende beziehungsweise nächste Aktionen.
24. Manipulation eines verschlüsselten Events wird erkannt.
25. Manipulation der Audit-Hash-Kette wird erkannt.
26. Das gesamte Repository enthält nach den Tests keine erzeugte Roh-HAR-Datei und keine bekannten Testsecrets.

Füge zusätzliche Property-Tests für URL-Kanonisierung, Header-Redaktion und JSON-Redaktion hinzu.

### I. Dokumentation und Migration

- Markiere `legacy/mvp/README.md` oben unübersehbar als unsicher und nicht für Live-Ziele geeignet.
- Entferne nichts aus `legacy/mvp/`, das für das Audit benötigt wird.
- Dokumentiere klar, welche MVP-Funktionen ersetzt wurden.
- Erstelle eine Phase-1-Bedienungsanleitung mit lokalen Mock-Beispielen.
- Dokumentiere bekannte Grenzen ohne sie schönzureden.
- Lege keine echte Programmkonfiguration, Zugangsdaten oder Zielhosts an.

## Qualitätsanforderungen

- Kein `any` an Sicherheitsgrenzen.
- Keine ungeprüften Type Casts bei Config-, URL-, Policy- oder Eventdaten.
- Keine Shell-Aufrufe mit untrusted Input.
- Keine Secrets in Fehlermeldungen.
- Deterministische Reason Codes statt nur Freitext.
- Funktionen klein und testbar halten.
- Sicherheitskritische Parser und Normalisierer müssen direkte Tests besitzen.
- Kernmodule benötigen hohe Testabdeckung; dokumentiere die tatsächliche Abdeckung.
- Abhängigkeiten mit bekannten kritischen Schwachstellen dürfen nicht eingeführt werden.
- Der Build muss in einer frischen Checkout-Umgebung reproduzierbar sein.

## Abschlussformat

Arbeite bis alle realistisch ausführbaren Phase-1-Tests grün sind. Antworte am Ende mit:

1. kurzer Architekturzusammenfassung,
2. Liste der geänderten und neu erstellten Dateien,
3. exakten Installations- und Testbefehlen,
4. tatsächlich ausgeführten Tests und deren Ergebnissen,
5. Testabdeckung,
6. verbleibenden Risiken und bewusst deaktivierten Funktionen,
7. Bestätigung, dass kein externer Bug-Bounty-Host kontaktiert wurde,
8. Vorschlag für den kleinsten nächsten Schritt in Phase 2.

Beginne jetzt mit der Bestandsaufnahme und arbeite danach ohne weitere Rückfrage bis zum vollständigen Phase-1-Ergebnis.
