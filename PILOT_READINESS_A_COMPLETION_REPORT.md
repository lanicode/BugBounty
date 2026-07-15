# Pilot Readiness A – Abschlussbericht

## Status und Basis

- Branch: `codex/pilot-readiness-hackerone-readonly`
- Ausgangsstand: `d9b13eff0498d5162cf44c8fc319b238005a01db`
- Ausgangstag: `v0.3.0-alpha`
- Capability: `HACKERONE_METADATA_READ`
- Produktmodus: ausschließlich lesende Plattformmetadaten

Pilot Readiness A ergänzt eine eng begrenzte Integration der offiziellen
HackerOne Hacker API. Die Capability ist keine Freigabe für Zielrequests,
aktive Sicherheitstests, Account-Automation, Browserzugriffe auf HackerOne
oder Report-Einreichungen.

## Architekturzusammenfassung

Der neue Pfad ist geschlossen und fail-closed aufgebaut:

1. Untrusted Konfiguration wird in einen intern gebrandeten Runtime-Zustand
   überführt. Fehlende, fehlerhafte oder nicht exakt aktivierte Schalter
   ergeben ein Nullbudget und eine deaktivierte Capability.
2. `hackerone_metadata_read` ist in der zentralen External-Action-Registry
   mit dem festen Ziel `https://api.hackerone.com:443`, `GET`, einem
   erforderlichen Credential-Paar und dem menschlichen Aktivierungscheckpoint
   registriert.
3. Die Aktivierung benötigt eine frische, signierte lokale
   Operatorentscheidung mit Bindung an vollständigen 64-stelligen
   Token-Binding-Digest,
   Runtime-Digest und Adaptergeneration. Die Evidence und die
   Adaptertransition werden in derselben `BEGIN IMMEDIATE`-Transaktion
   persistiert.
4. Der Request-Planer akzeptiert nur vier geschlossene Operationen. Vor jedem
   GET erzwingt das persistente Action Gate Registry-, Schema-, Policy-,
   Scope-, Ownership-, Budget-, Kill-Switch- und Aktivierungsevidence.
5. Proposal, Requestplan, vollständiger 64-stelliger Credential-Binding-
   Digest, Aktivierung, Reservation, Start und Settlement werden persistent
   gebunden. Requestbudget und Transportgrenzen sind Teil des signierten
   Runtime-Digests. Minuten-, Per-Operation- und aktive Crash-Budgets bleiben
   auch nach Deaktivierung und Reaktivierung verbraucht.
6. Der spezialisierte Transport akzeptiert nur vom Action Gate gebrandete
   Pläne, prüft zusätzlich den Phase-1-Egress-Guard, verwendet Node HTTPS mit
   Zertifikatsprüfung, folgt keinen Redirects und begrenzt absolute Laufzeit
   sowie Antwortgröße.
7. Antworten werden ausschließlich im Speicher eindeutig dekodiert, streng
   validiert und normalisiert. Rohe API-Antworten werden nie persistiert.
8. Credentials werden als generation-gebundenes Paar in kanonischen,
   druckbaren Base64url-Hüllen unter zwei festen macOS-Keychain-Referenzen
   gehalten. Ein kleiner nativer Security.framework-Helfer validiert feste
   Operationen und kanonische Hüllen, härtet bestehende ACLs vor Änderungen
   und wird vor jeder Verwendung über Quell- und Binärdigest verifiziert. Der
   Transport konsumiert sowohl einen gebrandeten Plan als auch die
   Credential-Lease genau einmal. Es gibt keinen Environment-, Datei-,
   SQLite- oder Klartextfallback.
9. API- und manuelle Daten liegen in getrennten `STRICT`-Tabellen. Die
   tatsächliche SQLite-DDL einschließlich Tabellen, Indizes und Trigger wird
   beim Initialisieren und Wiederöffnen gegen eine feste Erwartung geprüft.
10. Snapshots sind append-only. Policy-Annahme ist eine separate signierte
    Operatorentscheidung mit Bindung an Snapshot, Policy, Quelle und
    Programm.
11. Bereits beim Katalogsync erkanntes Policy-Material setzt den persistenten,
    über spätere Katalogsyncs sticky bleibenden Marker
    `catalog_drift_pending`, pausiert gebundene Kampagnen sofort und blockiert
    die Annahme bis zum exakten Detailsnapshot. Katalog plus Syncstatus,
    Detailsnapshot plus Auswahl/Syncstatus, manueller Datensatz plus Snapshot
    sowie Snapshot/Drift/Pause/Audit committen jeweils atomar.
12. Das Loopback-Dashboard bietet eine eng begrenzte, einmalige lokale
    Credential-Eingabe. Die Werte werden ausschließlich als festes binäres
    `application/octet-stream`-Frame an denselben Loopbackprozess übertragen,
    nie als JSON, Browser-Storage oder Log. Lokale Credential-Ablage,
    -Löschung und Integrations-Deaktivierung bleiben im Setup-Modus verfügbar;
    alle Security-Core-abhängigen Frontendcontrols bleiben dort sichtbar
    blockiert. Alle übrigen Mutationen verwenden feste
    Same-Origin-JSON-Routen.
13. Ein lokal installierbarer macOS-App-Launcher startet die Anwendung ohne
    sichtbares Terminal. Er verwendet eine Minimalumgebung, validiert nur
    `127.0.0.1`, besitzt Startup- und Termination-Deadlines und hält eine
    Loopback-Single-Instance-Lease. Externe Schalter sind standardmäßig aus;
    nicht geheime Event-/Operator-Metadaten werden nur bei einem ausdrücklichen
    Installerlauf übernommen.

## Implementierter externer API-Umfang

Im Produktions-Transport sind ausschließlich `HTTPS`, Port `443`, Host
`api.hackerone.com` und Methode `GET` erreichbar.

| Operation         | Exakter Pfad                                                                    | Verwendung                                          |
| ----------------- | ------------------------------------------------------------------------------- | --------------------------------------------------- |
| Verbindungstest   | `/v1/hackers/programs?page[number]=1&page[size]=1`                              | eine Seite, kein Retry, keine Programmpersistierung |
| Programmkatalog   | `/v1/hackers/programs?page[number]=N&page[size]=100`                            | serielle, streng kontrollierte Pagination           |
| Programmdetail    | `/v1/hackers/programs/{handle}`                                                 | Handle nur aus aktivem API-Katalogdatensatz         |
| Structured Scopes | `/v1/hackers/programs/{handle}/structured_scopes?page[number]=N&page[size]=100` | serielle, streng kontrollierte Pagination           |
| Scope Exclusions  | `/v1/hackers/programs/{handle}/scope_exclusions?page[number]=N&page[size]=100`  | serielle, streng kontrollierte Pagination           |

`weaknesses`, schreibende Methoden, Reports, Report Intents, Anhänge,
Kommentare, Triage-Antworten, Bounties, Zahlungen, Customer-API-Endpunkte,
HackerOne-Webseiten und sämtliche Programmassets sind nicht registriert und
nicht erreichbar.

## Änderungen

- Neues Paket `packages/hackerone-readonly` mit Runtime-Auflösung,
  Request-Policy, Credential-Vault, spezialisiertem Transport, Client,
  Response-Validierung, Snapshot-/Driftlogik, manuellem Import, Store und
  Service-Orchestrierung.
- Neue Registry-Definition und persistentes Gate
  `packages/external-actions/hackerone-metadata.ts` für signierte Aktivierung,
  signierte Policy-Annahme, Proposal-/Planbindung, Budgets, Reservationen und
  Settlement.
- Neue gemeinsame SQLite-DDL-Prüfung in
  `packages/shared/sqlite-schema.ts`; Marker allein gelten nicht als
  Schemanachweis.
- Erweiterung der Control-Plane-Approval-Transaktion, damit HackerOne-
  Aktivierung beziehungsweise Snapshot-Annahme atomar mit signierter
  Decision-Evidence und Audit angewendet werden.
- Härtung des macOS-Secret-Store-Pfads durch konsequentes Nullsetzen gelesener
  CLI-Puffer und kanonische, printable Base64url-
  Credential-Paarhüllen mit gemeinsamer Generation.
- Neuer lokaler TTY-Adminbefehl `pnpm hackerone:credentials` mit den exakt
  erlaubten Unterbefehlen `store`, `status` und `remove`.
- Neue Dashboard-Sektion mit einmaliger lokaler Credential-Ablage,
  dauerhaft sichtbaren Grenzen, Status, Aktivierung/Deaktivierung,
  Verbindungstest, Synchronisierung, lokaler Auswahl, Kampagnenbindung,
  manuellem Import, Snapshots, vollständigem aktuellem und vorherigem
  Policytext, Drift und signierter Annahme.
- Spezialisierte Credential-Route mit festem `H1CR`-v1-Binärrahmen,
  verpflichtendem `application/octet-stream`, Origin, CSRF, exakter
  `Content-Length`, engen Größenlimits und Buffer-Zeroing; kein allgemeiner
  Secret- oder JSON-Endpunkt.
- Gehärteter Deaktivierungs- und Credential-Mutationsablauf: `disable`,
  Dashboard-Store und Dashboard-Remove abortieren vor jedem Storezugriff,
  persistieren danach die Deaktivierung, warten auf Quieszenz und mutieren
  erst dann den Keychain. Ein Storefehler kann den unmittelbaren Abort nicht
  überspringen.
- Neuer ausdrücklich manueller und TTY-gebundener Live-Befehl
  `pnpm hackerone:connection-test`. Er wurde nicht automatisch ausgeführt.
- Direkte Unit-, Property-, Security-, Store-, Dashboard- und lokale
  Integrationstests mit ausschließlich synthetischen Daten und
  Loopback-Mocks.
- Nachträgliche Korrektur des defekten macOS-Writers: fester nativer
  Keychain-Helfer statt TTY-gebundenem `/usr/bin/security -w`, verifizierter
  persistierter Readback, kanonische Rollen-/Generationshüllen, explizite ACL,
  Quell-/Binärintegrität und minimale Prozessumgebung.
- Ausführende TTY-Regressionen für zwei nacheinander abgeschlossene versteckte
  Eingaben und `Ctrl-C` mit Exitstatus 130; stdin wird nach jeder Eingabe
  pausiert.
- Sichtbare fünfteilige Aktivierungsreadiness und fail-closed Frontend-Gates;
  lokale Credential-Sicherheitsaktionen sind von einer externen Aktivierung
  getrennt.
- Lokaler macOS-App-Launcher mit privater Konfiguration, explizitem
  `local-only`-Standard, optionalem H1-Read-only-Modus, Minimalumgebung,
  Startup-/Shutdown-Grenzen und Single-Instance-Lease. Das weiterhin
  begrenzte Kaltstartfenster beträgt dreißig Sekunden; Timeout und ein
  erkannter paralleler Launcher-Start erhalten eigene lokale Hinweise,
  während alle anderen Fehler generisch fail-closed bleiben.

### Ausdrückliche Security-Core-Änderungen

- `packages/control-plane/store.ts`: notwendiger atomarer Integrationspunkt
  für signierte HackerOne-Aktivierung und Snapshot-Annahme. Die bestehende
  `BEGIN IMMEDIATE`-Decision-Transaktion prüft Store-/Datenbankbindung,
  Operator, Payload, Frische, aktuellen Snapshot und Katalog-Drift und schreibt
  Decision-Audit, Binding, Adaptergeneration beziehungsweise Acceptance-
  Evidence gemeinsam. Eine bei oder nach Ablauf entschiedene Aktivierung
  rollt vollständig zurück. Direkte Regressionen liegen im Action-Gate- und
  Control-Plane-Testpfad.
- `packages/secret-store/store.ts`: notwendige Härtung des produktiven
  macOS-Keychain-Readers. CLI-Ausgaben und Backing-Buffer werden auf Erfolgs-
  und Fehlerpfaden begrenzt und genullt; der zurückgegebene Wert ist eine
  kontrollierte Kopie. Direkte Regressionen liegen in
  `tests/unit/secret-store.test.ts`.

`packages/shared/sqlite-schema.ts` ist der neue gemeinsame, streng
fail-closed DDL-Verifier. Keine dieser Änderungen lockert eine bestehende
Sicherheitsprüfung.

Die nach der ursprünglichen Pilot-A-Abnahme ausgeführte Credential-,
Frontend- und Launcher-Korrektur verändert keinen Phase-1-Security-Core. Sie
bleibt auf `packages/hackerone-readonly`, die H1-Dashboardprojektion, die
beiden H1-Adminapps, den neuen lokalen Launcher, Dokumentation und direkte
Regressionstests begrenzt.

## Lokal gespeicherte Daten

Gespeichert werden ausschließlich:

- normalisierte Programmfelder und Quellkennzeichnung;
- Policytext, strukturierte Scopes, Asset-Identifier als Metadaten und
  Scope-Ausschlüsse;
- Abruf-/Importzeit, Adapter-/Schema-Versionen und Digests;
- Suitability-Score und deterministische Reason Codes;
- Integrationsstatus, Adaptergeneration und ausgewählte opaque Referenz;
- append-only Snapshots und Snapshotkette;
- signierte Aktivierungs- und Annahmebindungen einschließlich
  Decision-/Statement-Referenzen;
- bodyfreie Request-, Authorization-, Settlement-, Drift- und
  Kampagnenbindungs-Audits;
- persistente Action-Proposals/Attempts, Budgetverbrauch und Status;
- ausdrückliche lokale Kampagnenbindungen.

Die beiden Keychain-Referenzen sind:

- `keychain://bugbounty-copilot/hackerone-api-identifier`
- `keychain://bugbounty-copilot/hackerone-api-token`

Nie gespeichert werden rohe API-Antworten, Authorization-Header,
Basic-Auth-Werte, vollständige Credentials außerhalb der beiden festen
Keychain-Hüllen, Response-Bodys, Cookies, Browser-Sessions, HAR-Dateien,
Screenshots, Zielrequest-Ergebnisse oder Report-Submissions.

## Sichtbarer lokaler Ablauf

1. Sicheren Core und lokalen Operator gemäß den bestehenden Phase-4-/Phase-5-
   Anleitungen einrichten.
2. Credentials einmalig im lokalen Dashboard-Formular speichern oder
   alternativ in einem interaktiven Terminal mit
   `pnpm hackerone:credentials store` verborgen eingeben. Danach nur
   Paarpräsenz und den zwölfstelligen Anzeige-Fingerprint prüfen.
3. Dashboard mit beiden HackerOne-Schaltern exakt `true` starten.
4. Globalen Kill Switch über den bestehenden signierten Operatorpfad
   freigeben.
5. Read-only-Integration im Dashboard aktivieren. Dieser Klick erzeugt und
   entscheidet eine frische signierte Aktivierung für exakt den aktuellen
   vollständigen Token-Binding-Digest und die feste API-Zielklasse.
6. Verbindung mit der festen Ein-Datensatz-Abfrage testen.
7. Programmkatalog synchronisieren und ein Programm über seine opaque lokale
   Referenz auswählen.
8. Programmdetail, Structured Scopes und Scope Exclusions synchronisieren.
9. Optional das ausgewählte Programm ausdrücklich an eine lokale Kampagne
   binden, damit späterer Drift diese Kampagne pausieren kann.
10. Aktuellen und vorherigen Policytext, Digests, Drift, Scopes,
    Ausschlüsse und Suitability prüfen.
11. Nur den aktuellen Snapshot über Checkbox und frische signierte
    Operatorentscheidung lokal akzeptieren.

Der manuelle JSON-Import bleibt ohne HackerOne-Token nutzbar, erzeugt keinen
Netzwerkrequest und kennzeichnet jeden Datensatz als `manual_unverified`.

## Deaktivierte Funktionen

- Requests an Programmassets oder andere Zielhosts
- `POST`, `PUT`, `PATCH`, `DELETE` und freie Requests
- `weaknesses`-Abruf
- Report-Erstellung oder -Einreichung
- Anhänge, Kommentare, Triage, Bounties oder Zahlungen
- Account-Erstellung, Login- oder Browserautomation
- HackerOne-Web-Scraping
- CAPTCHA-, Anti-Bot-, E-Mail- oder TOTP-Automation
- LLM-gesteuerte HTTP-Requests
- automatische Annahme von Policy, Regeln, Bedingungen oder rechtlichen
  Erklärungen
- Credential-Eingabe über JSON, allgemeine HTTP-Endpunkte, Browser-Storage,
  Environment oder argv; die einzige Dashboardroute akzeptiert ausschließlich
  das feste lokale Binärframe
- automatischer Live-Smoke in Tests, Build, CI oder durch Codex

## Tatsächlich ausgeführte Prüfungen

Alle folgenden Prüfungen wurden auf dem finalen Arbeitsstand ausgeführt.

| Prüfung                   | Tatsächlich ausgeführter Befehl                                                                             | Finales Ergebnis                                                        |
| ------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Typecheck                 | `./node_modules/.bin/tsc --noEmit`                                                                          | bestanden                                                               |
| Lint                      | `./node_modules/.bin/eslint . --max-warnings 0`                                                             | bestanden, 0 Warnungen                                                  |
| Format                    | `./node_modules/.bin/prettier --check .`                                                                    | bestanden                                                               |
| Vollständige Suite        | `./node_modules/.bin/vitest run --maxWorkers=1`                                                             | 107 Dateien, 876/876 Tests                                              |
| Property-Tests            | `./node_modules/.bin/vitest run tests/property --maxWorkers=1`                                              | 17 Dateien, 45/45 Tests                                                 |
| Browser-Harness           | `PLAYWRIGHT_NO_COPY_PROMPT=1 ./node_modules/.bin/playwright test --config playwright.config.ts`             | 2/2 Tests                                                               |
| Egress-Regressionen       | `./node_modules/.bin/vitest run tests/unit/egress tests/integration/*loopback.test.ts --maxWorkers=1`       | 6 Dateien, 33/33 Tests                                                  |
| H1-Loopback/API/Dashboard | gezielter Vitest-Lauf der H1-Unit-, Property-, Security- und Loopbacktests                                  | 19 Dateien, 346/346 Tests                                               |
| Secret-Leak-Prüfung       | `./node_modules/.bin/vitest run tests/security --maxWorkers=1`                                              | 1 Datei, 5/5 Tests                                                      |
| Native Keychain           | `sh tests/native/macos-keychain-helper-contract.sh && sh tests/native/macos-keychain-helper-integration.sh` | Contract und synthetischer lokaler Keychain-Zyklus bestanden            |
| macOS-App-Launcher        | `./node_modules/.bin/vitest run tests/unit/macos-app-launcher.test.ts --maxWorkers=1`                       | 1 Datei, 7/7 Tests                                                      |
| Build                     | `./node_modules/.bin/tsc -p tsconfig.build.json`                                                            | bestanden                                                               |
| Coverage                  | `./node_modules/.bin/vitest run --coverage --maxWorkers=1`                                                  | 87,12 % Statements; 83,21 % Branches; 94,67 % Funktionen; 88,24 % Lines |
| Dependency-Audit          | `npx --yes pnpm@11.7.0 audit --audit-level high`                                                            | keine bekannten Schwachstellen gefunden                                 |

Der fest auf `api.hackerone.com:443` verdrahtete Produktions-Transport wird
in automatisierten Tests nicht live ausgeführt. Alle automatisierten
Netzwerkprüfungen sind auf In-Process-Fakes oder Loopback-Mocks begrenzt.

## Bekannte Restrisiken

Die vollständige Liste steht in
`PILOT_READINESS_A_KNOWN_LIMITATIONS.md`. Wesentlich sind:

- kein automatisierter Nachweis des aktuellen HackerOne-Produktionsschemas;
- lokale Metadaten liegen in der privaten SQLite-Datei, nicht zusätzlich in
  Event-Store-AES-GCM-Hüllen;
- macOS- und Einzelbenutzergrenze für den produktiven Credentialpfad;
- keine Retention-/Purge-Oberfläche;
- keine Recovery-Oberfläche für nach einem Prozesscrash gestrandete
  Action-Reservationen; sie bleiben absichtlich blockierend und werden nicht
  erstattet;
- begrenzte Dashboard-Projektionen und kategorischer statt zeilenweiser
  Policy-Diff;
- Suitability bleibt eine konservative Heuristik ohne rechtliche Wirkung.
- Der Adapter akzeptiert ausschließlich ein vollständiges
  API-Identifier-/Token-Paar; ein vom Plattformkonto nur als einzelner Token
  ausgegebenes Credential bleibt bis zu einer separat geprüften
  Auth-Kompatibilität fail-closed.
- Der Finder-Launcher ist noch nicht mit vollständig synthetisch
  provisioniertem Security-Core bis `secureCoreReady` end-to-end qualifiziert.

## Erklärung zu externen Kontakten

Während Implementierung, Dokumentation und automatisierten Tests wurde kein
realer HackerOne-, Plattform- oder Bug-Bounty-Zielhost kontaktiert. Es wurden
keine echten Credentials verwendet. Alle automatisierten Netzwerkprüfungen
liefen ausschließlich gegen lokale Loopback-Mocks. Insbesondere wurde
`pnpm hackerone:connection-test` nicht durch Codex, Tests oder Builds
ausgeführt.

## Späterer manueller Verbindungstest

Nur der Benutzer darf den Live-Smoke selbst in einem interaktiven Terminal
starten. Voraussetzung sind bereits sicher hinterlegte Credentials, beide
exakt aktivierten Runtime-Schalter, eine gültige signierte Adapteraktivierung
und ein freigegebener globaler Kill Switch:

```sh
BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED=true \
BUGBOUNTY_HACKERONE_READONLY_ENABLED=true \
pnpm hackerone:connection-test
```

Der Befehl führt ausschließlich den Ein-Datensatz-GET aus und gibt keine
Responseinhalte oder Secrets aus.
