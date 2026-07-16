# Pilot Readiness C – Abschlussbericht

## Status und Basis

- Branch: `codex/pilot-readiness-active-testing`
- Ausgangscommit: `4dcc9f322e6b03ac04af06bd466e60948136766d`
- Capability: `HACKERONE_ACTIVE_TEST`
- Runner: `pilot-readiness-c-v1`
- Status dieses Dokuments: Implementierung und realistisch ausführbare
  Abschlussprüfungen abgeschlossen am 16. Juli 2026.

Pilot Readiness C ergänzt einen eng begrenzten Produktpfad für
niedrig-riskante, aktive HTTPS-Einmalprüfungen. Das ist weder ein allgemeiner
Scanner noch eine pauschale Live-Freigabe. Jeder Request bleibt an einen
aktuellen, authentifizierten und lokal akzeptierten HackerOne-API-Snapshot, ein
exakt ausgewähltes unterstütztes Asset, eine geschlossene Testklasse, ein
persistentes Budget und eine frische signierte Operatorentscheidung gebunden.

## Architekturzusammenfassung

Der Ablauf erzwingt deny-by-default und fail-closed folgende Kette:

```text
authentifizierter HackerOne-API-Snapshot
  -> lokale, ausdrückliche Snapshot-Annahme
  -> exakte serverseitige Assetprojektion
  -> geschlossene Testklasse
  -> trusted External-Action-Registrydefinition
  -> strikte Plan-Schema- und Semantikvalidierung
  -> aktuelle Policy-/Scope-/Ownership-/Katalogprüfung
  -> persistente Budgetreservation
  -> frische, plan- und kontextgebundene Operator-Signatur
  -> separate ausdrückliche Startaktion
  -> DNS-Auflösung und SSRF-Prüfung aller Antworten
  -> IP-gepinnter TLS-Request
  -> attestierte redigierte Evidence
  -> lokaler, nicht eingereichter Reportentwurf
```

Die wesentlichen Grenzen sind:

1. `packages/hackerone-readonly` liefert ausschließlich authentifizierte,
   normalisierte API-Metadaten. Manuell importierte Datensätze sind für aktive
   Tests nicht verwendbar.
2. `packages/active-testing` besitzt einen geschlossenen Katalog, den
   Planvertrag, die persistente Action-Gate-State-Machine, DNS-/SSRF- und
   TLS-Transportgrenzen sowie Evidence- und Reporterzeugung.
3. Der Plan bindet Programmreferenz, Snapshot-, Policy- und Assetdigest,
   Scope-ID, Testklasse, Runner- und Katalogversion, exaktes Ziel, Requestprofil,
   Budget, vier manuelle Bestätigungen und Ablaufzeit.
4. Die signierte Planfreigabe startet keinen Request. Erst ein zweiter,
   separater Klick reserviert das Budget und startet exakt den freigegebenen
   Plan.
5. Die Control Plane prüft Plan, Registrydefinition, Approval, Signatur,
   Ownership, Audit, Runtime- und Katalogdigest sowie die aktuelle signierte
   HackerOne-Adaptergeneration und den höchstens 15 Minuten alten Snapshot
   erneut vor Reservation, Start und erfolgreichem Abschluss.
6. DNS-Antworten werden als vollständige Menge validiert und digestgebunden.
   Eine einzige private, Loopback-, Link-Local-, CGNAT-, Dokumentations-,
   reservierte, Multicast- oder IPv4-mapped-Adresse blockiert die gesamte
   Auflösung. Der Runner wählt deterministisch IPv4 vor IPv6 und innerhalb der
   Familie die numerisch kleinste Adresse.
7. Der HTTPS-Transport verwendet Port 443, TLS 1.2 oder 1.3, Zertifikats- und
   Hostprüfung, SNI und eine an die geprüfte IP gepinnte Verbindung. Redirects,
   Retries, Upgrades, komprimierte Antworten, unbekannte Content-Types,
   unzulässige ALPN-Protokolle und Größen- oder Zeitüberschreitungen blockieren.
8. Nur ein gebrandeter Produktionstransport kann produktive Transport-Evidence
   ausstellen. Die Loopback-HTTP-Engine liegt ausschließlich unter
   `tests/support`, wird aus Produktionsbuild und Runtimeexports ausgeschlossen
   und ersetzt das Transportmodul nur dateilokal in zwei Vitest-Suites.
   Evidence ist plan- und autorisierungsgebunden und nur einmal konsumierbar.
9. Rohbody, Rohheader, Cookies, Redirect-Ziele und Credentials werden nicht
   persistiert. Gespeichert werden nur geschlossene Klassifikationen, Status,
   Timing, Größen, Digests, TLS-Klassifikation, Transportart und
   Resolution-Digest.
10. Der Report bleibt lokal mit
    `reviewStatus=local_draft_unsubmitted` und
    `externalSubmissionPerformed=false`. Es existiert keine Submit-Route.

## Implementierte Testklassen

| Testklasse       | Request   | Exakter Pfad                                                         | Maximaler Umfang                                | Persistierte Auswertung                                                                |
| ---------------- | --------- | -------------------------------------------------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------- |
| `http_headers`   | `HEAD`    | exakter Pfad des akzeptierten URL-Scopes                             | ein Request, kein Retry                         | Vorhandensein ausgewählter Sicherheitsheader und redigierte Cookie-Flag-Klassifikation |
| `cors_preflight` | `OPTIONS` | exakter Pfad des akzeptierten URL-Scopes                             | ein Request mit festem Probe-Origin, kein Retry | ausschließlich klassifizierte CORS-Antwortmerkmale                                     |
| `security_txt`   | `GET`     | nur `/.well-known/security.txt`, und nur wenn der Scope-Pfad `/` ist | ein Request, begrenzte Antwort, kein Retry      | Verfügbarkeit, erlaubter Content-Type, Größe und Body-Digest; kein Rohbody             |

Unterstützt werden nur kanonische `https://`-URL-Scopes auf Port 443 ohne
Wildcard, IP-Literal, Benutzerinformationen, Query oder Fragment, die in der
aktuellen API-Scope-Struktur sowohl für Einreichung als auch Bounty berechtigt
sind. Geschlossene Programme, Katalogdrift, ausstehende Snapshot-Annahme und
eine als verboten erkannte Automationsregel blockieren.

## Budget- und Zustandsmodell

- Ein Plan enthält immer `max_requests_total=1`,
  `requests_per_minute=1` und `max_concurrency=1`.
- Die produktive Runtime ist zusätzlich auf höchstens zehn reservierte
  Requests insgesamt, zwei pro Minute und genau eine aktive Reservation
  begrenzt.
- Reservationen, Fehlversuche und Abbrüche werden nicht erstattet.
- Dieselbe Kombination aus Snapshot, Scope, Assetdigest und Testklasse kann in
  derselben Datenbank nicht erneut ausgeführt werden.
- Planlaufzeit: höchstens zehn Minuten. Signierte Approval-Bindung: höchstens
  fünf Minuten und niemals länger als der Plan.
- Reservation, Start, Observation, Report und Settlement sind über eine exakt
  geprüfte `STRICT`-SQLite-Struktur, Foreign Keys, Trigger und unveränderliche
  Auditbindungen verkettet.
- Uhr-Rollback, Schemaabweichung, unvollständige Crash-Reservation oder
  widersprüchliche Evidence blockiert fail-closed.

## Laufzeitschalter und Bediengrenze

Der aktive Runner ist nur konfiguriert, wenn alle folgenden Werte exakt gesetzt
sind:

```text
BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED=true
BUGBOUNTY_HACKERONE_READONLY_ENABLED=true
BUGBOUNTY_ACTIVE_TESTING_ENABLED=1
```

Fehlende, fehlerhafte oder nur teilweise Konfiguration deaktiviert die
Capability. Zusätzlich bleiben ein vollständig validierter lokaler Core, ein
verfügbarer Operator-Signer, ein freigegebener globaler Kill Switch, die
HackerOne-Metadatenvoraussetzungen, eine aktuelle lokale Snapshot-Annahme und
die planbezogene Signatur verpflichtend.

Der macOS-Launcher aktiviert diesen Modus nur nach einem ausdrücklichen,
erneuten Installerlauf:

```sh
BUGBOUNTY_EVENT_KEY_MIN_VERSION=1 \
  npx --yes pnpm@11.7.0 app:install-macos -- \
  --enable-hackerone-active-testing
```

Der Standard des Installers bleibt `local-only`. Das Flag startet noch keinen
Request; es macht lediglich den weiterhin gesperrten Active-Testing-Pfad
verfügbar.

## Änderungen

- Neues `packages/active-testing` mit Runtime-Auflösung, geschlossenem
  Testkatalog, strengem JSON-Schema, Plancompiler und digestsicherer
  Validierung.
- Dedizierte, tief unveränderliche External-Action-Registrydefinition für
  `hackerone_active_test`; ihr kanonischer Digest und die exakte Zuordnung von
  Testklasse, Methode, HTTPS-Schema, Port, Scope/Ownership, Budget und
  menschlichem Kontrollpunkt werden im Planpfad erneut geprüft.
- Persistentes Active-Testing-Gate mit Approval-Bindung, signierter
  Operatorentscheidung, Budgetreservation, one-shot Autorisierung,
  Zustandsmaschine, Audit, kanonischer JSON-Persistenz und vollständiger
  Reopen-Validierung.
- Produktions-HTTPS-Transport mit vollständiger DNS-Antwortprüfung,
  SSRF-Sperren, deterministischer IP-Auswahl, IP-Pinning, TLS-Härtung,
  Kill-Switch-Polling, Gesamtdeadline und Antwortgrenzen.
- Transport-Attestation, die syntaktisch nachgebaute Response-Metadaten und
  falsche beziehungsweise wiederverwendete Evidence blockiert.
- Deterministische Evidence-Analyse und lokale Markdown-/JSON-Reportentwürfe
  ohne Rohbody, Rohheader, Cookiewerte oder Submission-Funktion.
- Dashboard-Controller und dreistufige Oberfläche: Plan vorbereiten, Plan
  signiert freigeben, separat starten. Freie URL-, Host-, Method-, Header- oder
  Bodyeingaben existieren nicht.
- Serverseitige Dashboardrouten ausschließlich für die drei geschlossenen
  Schritte; vorhandene Host-, Origin-, CSRF-, JSON- und Loopbackgrenzen bleiben
  aktiv.
- Expliziter macOS-Installermodus
  `--enable-hackerone-active-testing`; aktive Tests implizieren den
  HackerOne-Read-only-Modus, nicht umgekehrt.
- Einmaliges lokales Core-Provisioning für einen nachweislich leeren oder eng
  definierten `legacy_ready`-Zustand über einen nativen macOS-Keychain-Helfer.
- Gemeinsame Core-aware-SecretStore-Komposition für Dashboard, Phase-2- und
  Event-Key-CLI: v1 kommt im Bundlemodus ausschließlich aus dem validierten
  Core-Bundle, rotierte v2+-Keys ausschließlich aus festen
  Generic-Keychain-Referenzen. Der bestehende kanonische Phase-4/5-Direktmodus
  wird als nicht provisionierbarer `legacy_direct_complete`-Zustand erkannt;
  Teilzustände, Receipt-Drift und Lesefehler blockieren ohne Fallback.
- Direkte Unit-, Property-, Loopback-Integration-, Native-Contract- und
  Regressionstests für die neuen Grenzen.
- Sicherheits- und Betriebsdokumentation für den aktiven Pilotpfad.

## Ausdrückliche Security-Core-Änderungen

Die vollständige Begründung steht in
`PILOT_READINESS_C_SECURITY_CORE_CHANGES.md`.

- `packages/control-plane/store.ts` stellt angrenzenden, store-gebundenen
  Gates die vertrauenswürdige Store-Uhr mit High-Water-Prüfung bereit und bindet
  Active-Testing-Approvalentscheidungen atomar in die bestehende signierte
  `BEGIN IMMEDIATE`-Transaktion ein.
- Derselbe atomare Store-Pfad löscht bei jeder neuen signierten
  HackerOne-Adaptergeneration den alten Verbindungs-, Synchronisations- und
  Programmauswahlzustand. Ein Scope aus einer früheren Credentialgeneration
  kann deshalb ohne neuen API-Sync und neue Snapshot-Annahme nicht ausgeführt
  werden.
- `packages/control-plane/database.ts` erzwingt und verifiziert rekursive
  SQLite-Trigger, damit `INSERT OR REPLACE` bestehende Append-only- und
  Evidence-Trigger nicht über implizite Deletes umgehen kann.
- `packages/secret-store` ergänzt den nativen, atomaren und
  nicht-überschreibenden Core-Keychain-Provisioningpfad sowie die fail-closed
  v1-/v2+-Laufzeitkomposition und die explizite Phase-4/5-Kompatibilität.
  Secretbytes werden weder über HTTP noch über argv, Environment, Logs oder
  Dateien übertragen. Event-Key-Rotation und Recovery bleiben ausschließlich
  lokale, bestätigte Offline-CLI-Operationen.

Keine Egress-, Redaction-, Event-Store-, Policy-, Audit- oder
Operator-Signaturprüfung wurde gelockert.

## Finale Prüfergebnisse

| Prüfung                   | Tatsächlich ausgeführter Befehl                                                                 | Ergebnis                                                                                 |
| ------------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Diff-Prüfung              | `git diff --check`                                                                              | erfolgreich                                                                              |
| Typecheck                 | `./node_modules/.bin/tsc --noEmit`                                                              | erfolgreich                                                                              |
| Lint                      | `./node_modules/.bin/eslint . --max-warnings 0`                                                 | erfolgreich, keine Warnungen                                                             |
| Format                    | `./node_modules/.bin/prettier --check .`                                                        | erfolgreich, alle Dateien formatiert                                                     |
| Build                     | `./node_modules/.bin/tsc -p tsconfig.build.json`                                                | erfolgreich                                                                              |
| Vollständige Vitest-Suite | `./node_modules/.bin/vitest run --maxWorkers=1`                                                 | **127/127 Dateien, 1099/1099 Tests erfolgreich**, 71,29 s                                |
| Property-Tests            | `./node_modules/.bin/vitest run tests/property --maxWorkers=1`                                  | **20/20 Dateien, 57/57 Tests erfolgreich**, 16,21 s                                      |
| Security-Tests            | `./node_modules/.bin/vitest run tests/security --maxWorkers=1`                                  | **1/1 Datei, 5/5 Tests erfolgreich**, 465 ms                                             |
| Browser-Harness           | `PLAYWRIGHT_NO_COPY_PROMPT=1 ./node_modules/.bin/playwright test --config playwright.config.ts` | **2/2 Tests erfolgreich**, 3,0 s; ausschließlich Loopback                                |
| Native Verträge           | drei einzelne `tests/native/*-contract.sh`                                                      | **3/3 erfolgreich**                                                                      |
| App-Wrapper-Integration   | `sh tests/native/macos-app-wrapper-integration.sh`                                              | erfolgreich; ausschließlich temporäre lokale Test-App                                    |
| Keychain-Integration      | `sh tests/native/macos-keychain-helper-integration.sh`                                          | nicht realistisch ausführbar: macOS verweigert Login-Keychain-Autorisierung mit Exit 152 |
| Coverage                  | `./node_modules/.bin/vitest run --coverage --maxWorkers=1`                                      | 1099/1099; **84,96 % Statements, 82,32 % Branches, 92,18 % Funktionen, 85,96 % Zeilen**  |
| Dependency-Audit          | lokales pnpm 11.7.0: `audit --audit-level high`                                                 | erfolgreich: `No known vulnerabilities found`                                            |
| Produktionsbuild-Canary   | `rg` nach den drei Loopback-Testsymbolen in `dist/packages` und `dist/apps`                     | erwarteter Exit 1 ohne Treffer; kein Loopback-Testtransport im Produktbuild              |

Der kombinierte `npm run test:native` kann in dieser verwalteten Sitzung
nicht vollständig erfolgreich enden, weil bereits
`/usr/bin/security show-keychain-info` mit
`Unable to obtain authorization for this operation` und Exit 152 blockiert.
Der Login-Schlüsselbund wurde nicht entsperrt, kein Passwort angefordert und
kein Klartext- oder alternativer Secret-Fallback eingebaut. Die beiden
Keychain-Helper-Verträge, der Core-Helper-Vertrag sowie Vertrag und Integration
des App-Wrappers wurden separat erfolgreich ausgeführt.

Automatisierte Netzwerk- und Browsertests dürfen dabei ausschließlich lokale
Mock-Server auf Loopback-Adressen verwenden. Der Produktionstransport wird im
automatisierten Testlauf nicht gegen HackerOne oder ein Programmasset
ausgeführt.

## Bewusst deaktiviert oder nicht implementiert

- automatische Zustimmung zu Programmregeln, Nutzungsbedingungen oder
  rechtlichen Erklärungen;
- automatische Report-Einreichung, Kommentare, Anhänge, Triage, Bounty- oder
  Zahlungsaktionen;
- Account-Erstellung, Login-, Credential-, Session-, TOTP-, E-Mail-, CAPTCHA-
  oder Anti-Bot-Automation;
- schreibende HTTP-Methoden, Exploitation, Fuzzing, Crawling, Portscans,
  Directory-Bruteforce oder allgemeine Scanner;
- frei konfigurierbare Hosts, URLs, Methoden, Header, Requestbodys oder
  Skripte;
- Redirects, Retries, Service Worker, WebSockets und Browserrunner;
- LLM-gesteuerte Requests oder ein allgemeiner HTTP-Client für Modelloutput;
- Integrationen mit Bugcrowd oder weiteren Plattformen.

## Externe Kontakte während Entwicklung und Tests

Während Implementierung und automatisierten Tests wurde kein realer
HackerOne-, Plattform-, Programm- oder Bug-Bounty-Zielhost kontaktiert. Alle
ausgeführten Netzwerk- und Browsertests waren auf lokale Loopback-Mocks
begrenzt. Ein später vom Menschen ausdrücklich gestarteter Produktionsrequest
liegt außerhalb dieses Entwicklungsnachweises und muss die oben beschriebenen
Gates vollständig passieren.

## Restrisiken und nächster Schritt

Die vollständige Liste steht in
`PILOT_READINESS_C_KNOWN_LIMITATIONS.md`. Der kleinste konservative nächste
Schritt ist kein breiterer Scanner, sondern zunächst eine zweite menschliche
Prüfung dieses Branches gegen Policy, Scope und Kill-Switch-Verhalten. Erst
danach darf eine manuell beaufsichtigte, organisatorisch freigegebene
Ein-Request-Abnahme einer einzigen Testklasse auf einem ausdrücklich
autorisierten Asset erwogen werden.

Zusätzlich bleibt ein lokales Verfügbarkeitsrisiko: Der native Core-Helper ist
nicht mit einer stabilen Developer-ID codesigniert. Ein Source-Update,
Cacheverlust oder Recompile kann deshalb eine neue macOS-Codeidentität
erzeugen, deren Keychain-Zugriff bis zu einem manuellen Upgrade-Schritt
fail-closed abgelehnt wird. Es gibt dafür bewusst keinen weniger sicheren
Secret-Fallback.

## Nachtrag 2026-07-16: Live-Kompatibilität des Read-only-Adapters

Ein ausdrücklich vom Benutzer ausgelöster HackerOne-Read-only-
Verbindungstest erhielt eine HTTP-Antwort, wurde aber wegen additiver
JSON:API-Felder als `malformed_response` abgelehnt. Gleichzeitig behandelte
die lokale Dashboardroute jedes fachliche Testergebnis als HTTP 200, wodurch
das Frontend fälschlich eine grüne Erfolgsmeldung zeigte.

Der Adapter projiziert Antworten nun vor der weiterhin strikten
Schema-Validierung auf die explizit konsumierten Felder. Additive Felder
werden weder normalisiert noch persistiert. Bekannte Pflichtfelder, Typen,
Längen, Zeitstempel, Seitenlimits und Resource-Typen bleiben unverändert
fail-closed. Proxies, Accessors, unsichere Namen, ungewöhnliche Prototypen,
Sparse Arrays und übergroße Objekte werden vor der Projektion blockiert. Die
lokale Verbindungstestroute liefert nur für `connected` plus
`schemaValid=true` HTTP 200; alle fachlichen Fehlschläge liefern HTTP 502 mit
dem bereits redigierten Fehlercode.

Der Nachtrag wurde mit 128/128 Vitest-Dateien und 1101/1101 Tests, 21/21
Property-Dateien mit 58/58 Property-Tests, 5/5 Security-Tests sowie 2/2 lokalen
Browser-Tests verifiziert. Die vollständige Coverage beträgt 85,03 %
Statements, 82,38 % Branches, 92,27 % Funktionen und 86,05 % Zeilen. Während
Implementierung und automatisierten Tests dieses Nachtrags wurde kein
HackerOne-, Plattform- oder Bug-Bounty-Zielhost kontaktiert. Der oben genannte
einmalige reale Read-only-Kontakt wurde zuvor ausschließlich durch den
Benutzer im Dashboard ausgelöst; Codex löste keinen weiteren Live-Test aus.

## Nachtrag 2026-07-16: Katalog-Zusammenfassungen

Der reale, vom Benutzer ausgelöste Verbindungstest war nach dem ersten
Kompatibilitätsfix erfolgreich. Der anschließend ebenfalls ausdrücklich vom
Benutzer ausgelöste Programmkatalog-Sync scheiterte jedoch atomar mit
`HACKERONE_RESPONSE_SCHEMA_INVALID`, weil nicht jeder Katalogeintrag alle
Detailattribute enthält beziehungsweise einzelne optionale Attribute `null`
sein können.

Die API-Grenze verlangt für einen Katalogeintrag weiterhin zwingend eine
kanonische JSON:API-ID, den festen Resource-Typ `program`, ein
Plain-Object-Attributobjekt und einen kanonischen Handle. Fehlende oder
explizit `null` gesetzte Zusammenfassungsattribute werden konservativ
normalisiert: Status wird `unknown`, Policy leer, Bounty/Open-Scope/
Safe-Harbor/Bookmark `false`, persönliche Zähler `0`, Währung `UNKNOWN` und
der Anzeigename fällt auf den Handle zurück. Falsche Typen, ungültige Werte,
unsichere Strukturen und Größenüberschreitungen bleiben blockiert. Diese
Defaults können weder eine offene Einreichung noch Bounty-, Policy-, Scope-
oder Automationsfreigabe erzeugen; für aktive Tests bleibt ein vollständiger,
ausdrücklich synchronisierter Detailsnapshot erforderlich.

Der optimierte Abschlusslauf kombinierte Vollsuite und Coverage: 128/128
Dateien und 1104/1104 Tests waren erfolgreich. Coverage: 85,04 % Statements,
82,43 % Branches, 92,27 % Funktionen und 86,05 % Zeilen. Während
Implementierung und Tests wurde kein realer HackerOne-, Plattform- oder
Zielhost kontaktiert; alle Netzwerkprüfungen verwendeten lokale
Loopback-Mocks.

## Nachtrag 2026-07-16: Semantisch kanonische Pagination

Nach erfolgreicher Schema-Validierung blockierte der nächste ausdrücklich vom
Benutzer ausgelöste Katalog-Sync den von HackerOne gelieferten Next-Link mit
`HACKERONE_PAGINATION_BLOCKED`. Die API kann die beiden fest erlaubten
JSON:API-Seitenparameter percent-encodiert oder in anderer Reihenfolge
serialisieren.

Die Pagination validiert nun semantisch genau ein `page[number]` und genau ein
`page[size]`. Seitennummer muss exakt um eins steigen und Seitengröße
unverändert bleiben. HTTPS, fester Host, Port 443, identischer Pfad, leere
Userinfo, kein Fragment sowie die Obergrenzen bleiben zwingend. Relative
Links, fremde Hosts, zusätzliche oder doppelte Parameter und Seitensprünge
blockieren weiterhin. Der gelieferte Link wird nie direkt ausgeführt; nach
erfolgreicher Prüfung erzeugt die Anwendung selbst wieder den kanonischen
festen Requestplan.

Gezielt waren 84/84 Policy-/Property-Tests und 20/20 Loopbacktests
erfolgreich. Der einzige kombinierte Vollsuite-/Coverage-Lauf bestand 128/128
Dateien und 1106/1106 Tests. Coverage: 85,05 % Statements, 82,45 % Branches,
92,27 % Funktionen und 86,07 % Zeilen. Codex kontaktierte keinen externen
Host; alle Netzwerkprüfungen liefen ausschließlich gegen Loopback-Mocks.

## Nachtrag 2026-07-16: Explizite Programmauswahl

Das HackerOne-Programm-Dropdown behält eine noch nicht übernommene Auswahl
über lokale Zustandsaktualisierungen hinweg. Ohne gültigen Draft wird kein
Katalogeintrag implizit ausgewählt; stattdessen erscheint ein ausdrücklicher
Platzhalter. Nur `Auswahl übernehmen` darf den Draft persistieren.

Detailsynchronisierung und Kampagnenbindung verwenden ausschließlich die
persistierte Auswahl und bleiben deaktiviert, solange sie nicht exakt mit der
sichtbaren Auswahl übereinstimmt. Die Detailsynchronisierungsroute erzwingt
diese Übereinstimmung zusätzlich serverseitig vor einem Adapter- oder
Transportaufruf. Damit kann weder ein Hintergrundrefresh noch ein alter oder
zweiter Browser-Tab unbemerkt den ersten Katalogeintrag autorisieren.

Die gezielte Regression bestand 23/23 Tests. Der abschließende kombinierte
Vollsuite-/Coverage-Lauf bestand 128/128 Dateien und 1108/1108 Tests.
Coverage: 85,04 % Statements, 82,43 % Branches, 92,27 % Funktionen und
86,06 % Zeilen. Der Phase-1-Sicherheitskern wurde nicht verändert.

Codex und alle automatisierten Tests kontaktierten keinen HackerOne-,
Plattform- oder Bug-Bounty-Zielhost; alle Netzwerkanteile liefen gegen lokale
Loopback-Mocks. Vor diesem Fix hatte der Benutzer im Dashboard ausdrücklich
einen HackerOne-Read-only-Detailsync ausgelöst, der aufgrund der fehlerhaft
persistierten Auswahl nur die HackerOne-Metadaten-API für `1password`
ansprach und mit Schemafehler blockierte. Es wurde dabei kein 1Password- oder
anderer Programmzielhost kontaktiert und keine aktive Testaktion ausgeführt.

## Nachtrag 2026-07-16: Numerische Detail-ID

Der Benutzer löste nach korrekter Auswahl von `1win_com` ausdrücklich einen
Read-only-Detailsync aus. Das lokale append-only Request-Audit belegte, dass
der HTTP-200-Programmdetaildatensatz am Antwortschema blockierte, bevor
Structured-Scopes- oder Scope-Exclusion-Endpunkte angefragt wurden. Der
aktuelle offizielle `Get Program`-Antwortvertrag zeigt die Programm-ID als
JSON-Zahl; der lokale Parser verlangte bislang ausschließlich einen String.

Programmressourcen akzeptieren nun weiterhin begrenzte nichtleere String-IDs
oder positive sichere Ganzzahlen. Zahlen werden unmittelbar verlustfrei als
kanonische Dezimalstrings normalisiert. Null, negative Werte, Brüche,
unsichere Ganzzahlen und andere Typen blockieren unverändert. Unbekannte
Felder einschließlich `relationships` werden nicht persistiert oder als
Scope verwendet. Der Phase-1-Sicherheitskern und alle Egress-, Policy-,
Scope-, Budget-, Approval- und Kill-Switch-Gates bleiben unverändert.

Gezielt bestanden 80/80 Unit-/Loopbacktests und 2/2 Property-Tests. Der
einzige vollständige kombinierte Regressionstest-/Coverage-Lauf bestand
128/128 Dateien und 1110/1110 Tests. Coverage: 85,06 % Statements, 82,47 %
Branches, 92,27 % Funktionen und 86,07 % Zeilen.

Codex führte keinen authentifizierten HackerOne-Request aus und kontaktierte
keinen Plattform- oder Bug-Bounty-Zielhost. Der Benutzerrequest vor dem Fix
kontaktierte ausschließlich den HackerOne-Programmdetail-Metadatenendpunkt;
kein `1win_com`-Asset und keine aktive Testfunktion wurden angefragt.
