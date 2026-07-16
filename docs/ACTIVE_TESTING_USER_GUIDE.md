# Aktive Tests – Benutzerhandbuch für Pilot Readiness C

## Was dieser Modus kann

Der aktive Pilotmodus kann nach vollständiger manueller Freigabe genau eine
der folgenden Prüfungen auf genau einem unterstützten HackerOne-API-Scope
ausführen:

- `HEAD` auf dem exakten Scope-Pfad zur Klassifikation ausgewählter
  HTTP-Sicherheitsheader;
- `OPTIONS` auf dem exakten Scope-Pfad mit einem festen CORS-Probe-Origin;
- `GET /.well-known/security.txt` für einen Root-URL-Scope.

Jeder Plan erlaubt einen Request, keinen Retry und keinen Redirect. Der Modus
ist kein Scanner, Crawler, Browserrunner oder Exploitframework. Er erstellt
keine Accounts und reicht keinen Report ein.

## Verbindliche Voraussetzungen

Starte keinen aktiven Test, bevor alle Punkte erfüllt sind:

1. Du bist für das konkrete Programm und Asset organisatorisch und rechtlich
   autorisiert.
2. Du hast vollständigen aktuellen Policytext, Scope-Anweisung,
   Ausschlüsse, Rate Limits und Automationsregeln selbst gelesen.
3. Das Programm erlaubt die konkrete niedrig-riskante Automation. Bei
   Unklarheit gilt: nicht starten.
4. Der sichere lokale Core und Operator-Signer sind vollständig eingerichtet.
5. HackerOne-Read-only ist mit einem vollständigen API-Identifier-/Token-Paar
   eingerichtet. Das Produkt sendet diese Werte nur an die feste
   HackerOne-API und niemals an ein Programmasset.
6. Programmkatalog, Programmdetail, Structured Scopes und Scope Exclusions
   wurden unmittelbar vorher bewusst synchronisiert.
7. Der aktuelle API-Snapshot wurde nach menschlicher Prüfung lokal signiert
   akzeptiert.

Der letzte erfolgreiche Detailsync darf beim aktiven Schritt höchstens 15
Minuten alt sein und muss nach der aktuell signierten Adapteraktivierung
liegen. Nach Credential-, Account- oder Adaptergenerationwechsel löscht die
Control Plane Auswahl und Sync-Zustand; Katalog, Auswahl, Details und Annahme
müssen dann bewusst neu durchlaufen werden.

Die lokale Snapshot-Annahme ist keine Annahme von HackerOne-
Nutzungsbedingungen, Programmregeln oder rechtlichen Erklärungen. Sie ersetzt
keine Berechtigung.

## Installation ohne globales pnpm

Wenn `pnpm` nicht global verfügbar ist, verwende die gepinnte Version über
`npx`:

```sh
cd /Users/julian/Downloads/bugbounty-copilot-codex-starter
npx --yes pnpm@11.7.0 install --frozen-lockfile
```

Node.js 24 oder neuer ist erforderlich. Produktive Keychain- und
App-Integration sind macOS-spezifisch.

## Sicheren Core einmalig einrichten

Ist im Dashboard `local_setup_shell` beziehungsweise „Core Setup
erforderlich“ sichtbar:

1. Starte die lokale Anwendung zunächst ohne aktive Integration:

   ```sh
   npx --yes pnpm@11.7.0 app
   ```

2. Öffne ausschließlich die ausgegebene URL mit
   `http://127.0.0.1:<port>`.
3. Prüfe, dass der globale Kill Switch aktiv ist.
4. Wähle die einmalige lokale Core-Provisionierung. Es gibt und braucht keine
   Secretfelder. Der Server wählt selbst `fresh_bundle` oder den eng
   begrenzten `legacy_complete`-Modus.
5. Beende die App nach der Erfolgsmeldung. Die laufende Instanz übernimmt die
   neuen Schlüssel absichtlich nicht.

Bei Konflikt-, Teil- oder Keychain-Fehlern nicht wiederholt klicken und keine
Einträge manuell löschen. Der Zustand muss offline untersucht werden.

## Finder-App ausdrücklich für aktive Tests installieren

Der Installerstandard bleibt `local-only`. Für den aktiven Pilotmodus muss die
Finder-App einmal ausdrücklich neu installiert werden:

```sh
cd /Users/julian/Downloads/bugbounty-copilot-codex-starter
BUGBOUNTY_EVENT_KEY_MIN_VERSION=1 \
  npx --yes pnpm@11.7.0 app:install-macos -- \
  --enable-hackerone-active-testing
```

Für eine getrennt verwaltete Legacy-Operator-Konfiguration müssen zusätzlich
nur die nicht geheimen Metadaten
`BUGBOUNTY_OPERATOR_KEY_REFERENCE`, `BUGBOUNTY_OPERATOR_ID` und
`BUGBOUNTY_OPERATOR_KEY_REVISION` beim Installer vollständig gesetzt sein.
Private Schlüssel, API-Tokens oder Passwörter gehören niemals in
Umgebungsvariablen.

Danach kann die Anwendung ohne Terminal über
`~/Applications/Bug Bounty Copilot.app` geöffnet werden. Der Launcher setzt
intern exakt:

```text
BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED=true
BUGBOUNTY_HACKERONE_READONLY_ENABLED=true
BUGBOUNTY_ACTIVE_TESTING_ENABLED=1
```

Das Installerflag führt noch keinen Netzwerkrequest aus. Es macht lediglich
die weiterhin durch Core, Kill Switch, Snapshot, Policy, Budget und Signatur
gesperrte Capability sichtbar.

### Alternative: kontrollierter Terminalstart

```sh
cd /Users/julian/Downloads/bugbounty-copilot-codex-starter
BUGBOUNTY_EVENT_KEY_MIN_VERSION=1 \
BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED=true \
BUGBOUNTY_HACKERONE_READONLY_ENABLED=true \
BUGBOUNTY_ACTIVE_TESTING_ENABLED=1 \
  npx --yes pnpm@11.7.0 app
```

Öffne nur die vom Prozess ausgegebene `127.0.0.1`-Dashboard-URL. Der
Standardport ist 4173; bei Belegung wird ein anderer Loopbackport ausgegeben.

## HackerOne-Metadaten vorbereiten

### Credentials lokal speichern

Öffne **Einstellungen → Integrationen → HackerOne** und verwende das lokale
Credentialformular. Der Adaptervertrag benötigt zwei Werte:

- API-Identifier;
- API-Token.

Beide werden als generation-gebundenes Paar unter festen Referenzen im
macOS-Schlüsselbund gespeichert. Die Browserfelder werden nach dem Vorgang
geleert; die Oberfläche zeigt anschließend nur Präsenz und einen kurzen
Fingerprint.

Wenn dein HackerOne-Zugang kein passendes Identifier-/Token-Paar bereitstellt,
erfinde keinen Identifier und kopiere den Token nicht in beide Felder. Der
Adapter muss in diesem Zustand deaktiviert bleiben. Gib Credentials niemals
in Codex, GitHub, Logs, Screenshots oder Supporttexte ein.

### Read-only-Integration aktivieren und synchronisieren

1. Gib den globalen Kill Switch über den vorhandenen signierten lokalen
   Operatorpfad frei.
2. Wähle **Read-only-Integration aktivieren**. Das ist eine eigene signierte
   Aktivierung und noch keine Zielrequestfreigabe.
3. Wähle **Verbindung testen**.
4. Wähle **Programmkatalog synchronisieren**.
5. Wähle exakt ein API-synchronisiertes Programm und übernimm die Auswahl.
6. Wähle **Programmdetails, Scopes und Ausschlüsse synchronisieren**.
7. Prüfe Programmstatus, Submission State, vollständige Policy, Structured
   Scopes, Eligibility, Instructions, Maximum Severity, CIA-Metadaten und
   Scope Exclusions.
8. Prüfe Snapshot- und Policydigest sowie jeden Driftindikator.
9. Akzeptiere nur den exakten aktuellen Snapshot über die separate signierte
   lokale Policy-Aktion.

Ein manueller JSON-Import ist für aktive Tests absichtlich unbrauchbar. Die
aktive Capability akzeptiert ausschließlich Quelle
`hackerone_api_authenticated`.

## Einen aktiven Einmaltest ausführen

Die Dashboardsektion **Aktive Tests** besitzt drei getrennte Schritte.

### Schritt 1: exakten Plan vorbereiten

1. Prüfe den Capability-Status. Er muss konfiguriert sein; Core und
   Operator-Signer müssen bereit sein; der Kill Switch muss freigegeben sein.
2. Prüfe, dass genau das gewünschte API-Programm und der aktuelle akzeptierte
   Snapshot angezeigt werden.
3. Wähle ein **serverseitig projiziertes** unterstütztes Asset. Der
   Asset-Identifier ist nur Text und kein Link. Es gibt kein freies URL-Feld.
4. Wähle genau eine geschlossene Testklasse:

   | Auswahl                | Tatsächlicher Request                     | Zusätzliche Grenze                                          |
   | ---------------------- | ----------------------------------------- | ----------------------------------------------------------- |
   | HTTP-Sicherheitsheader | ein `HEAD` auf dem exakten Scope-Pfad     | kein Responsebody zulässig                                  |
   | CORS-Preflight         | ein `OPTIONS` auf dem exakten Scope-Pfad  | fester Probe-Origin und feste gewünschte Methode            |
   | security.txt-Metadaten | ein `GET` auf `/.well-known/security.txt` | nur Root-Scope, erlaubter Text-Content-Type und Größenlimit |

5. Bestätige einzeln und wahrheitsgemäß:
   - Automationsregel der aktuellen Policy geprüft;
   - exakte Scope-Anweisung geprüft;
   - alle Scope-Ausschlüsse geprüft;
   - keine Seiteneffekte für diese Testklasse bestätigt.
6. Wähle **Exakten Plan vorbereiten**.

Dieser Schritt erzeugt und persistiert nur den digestgebundenen Plan und eine
offene Approval. Er führt weder DNS noch einen Zielrequest aus.

### Schritt 2: exakt diesen Plan signiert freigeben

Prüfe Plan-ID, Plandigest, Programm, Snapshotdigest, Scope, Assetdigest,
Testklasse und Status erneut. Wähle danach **Exakt diesen Plan freigeben**.

Die lokale Operator-Credential signiert eine frische, session-, nonce-,
Control-Plane- und kontextgebundene Entscheidung. Die Freigabe startet noch
keinen Request. Sie läuft spätestens nach fünf Minuten ab; der Plan spätestens
nach zehn Minuten. Bei Ablauf oder geänderter Projektion einen neuen Plan
vorbereiten, keine Sperre umgehen.

### Schritt 3: separat starten

Erst wenn die Oberfläche den aktuellen Plan als akzeptiert zeigt, wird der
rote Button **Exakt diesen freigegebenen Plan jetzt starten** verfügbar.

Vor dem Klick nochmals prüfen:

- exaktes Programm und Asset;
- Methode und Pfad;
- aktuelle Policy und Ausschlüsse;
- globaler Kill Switch freigegeben;
- genau ein gewünschter Live-Request.

Der Start reserviert das persistente Budget, prüft Registrydefinition,
Ownership, aktuelle Adaptergeneration und alle Planbindungen erneut,
löst den exakten Host auf, blockiert die gesamte Antwortmenge bei einer
gesperrten Adresse, pinnt die ausgewählte öffentliche IP an TLS und sendet
höchstens einen Request. Redirects und Retries sind deaktiviert.

Bei Kill Switch oder Deadline beginnt danach kein HTTP-Request. Eine bereits
an den Systemresolver übergebene DNS-Auflösung ist betriebssystembedingt nicht
abbrechbar und kann im Hintergrund enden; ihr Ergebnis wird verworfen.

## Ergebnis und lokaler Report

Nach Erfolg zeigt die Oberfläche nur redigierte Attempt- und
Reportzusammenfassungen. Persistiert werden unter anderem:

- Plan-, Snapshot-, Policy-, Asset-, Response- und Observation-Digests;
- Statuscode, Dauer, beobachtete Größe und erlaubter Content-Type;
- TLS-Protokoll und redigierte Cipherklassifikation;
- Transportart und DNS-Resolution-Digest;
- geschlossene deterministische Signale;
- `reviewStatus=local_draft_unsubmitted`;
- `externalSubmissionPerformed=false`.

Rohbody, Rohheader, Cookiewerte und Redirect-Ziele werden nicht gespeichert.
Die Anwendung besitzt keine Report-Submission-Route und keinen Submit-Button.
Ein Signal ist keine bestätigte Schwachstelle; es muss separat menschlich
bewertet werden.

## Budgetverhalten

- ein Plan: genau eine Reservation und höchstens ein Request;
- Runtime: maximal zehn Reservationen insgesamt;
- maximal zwei Reservationen innerhalb von 60 Sekunden;
- maximal eine Reservation beziehungsweise Ausführung gleichzeitig;
- keine Erstattung bei Fehler, Abbruch, Timeout oder Crash;
- keine Wiederholung derselben Kombination aus Snapshot, Scope, Asset und
  Testklasse.

Diese Grenzen dürfen nicht durch Datenbankänderung, neue IDs oder manuelle
Dateimanipulation umgangen werden.

## Sofort stoppen und aktiven Modus wieder deaktivieren

Für einen sofortigen Stopp:

1. Engagiere den globalen Kill Switch im Dashboard.
2. Warte nicht auf einen Retry; es gibt keinen.
3. Beende die Anwendung.

Ein bereits übertragener Request kann nicht zurückgerufen werden. Engagement
während des Laufs blockiert Completion und verbraucht die Reservation.

Um spätere Finder-Starts wieder vollständig lokal zu halten, installiere die
App ohne Integrationsflag neu:

```sh
cd /Users/julian/Downloads/bugbounty-copilot-codex-starter
BUGBOUNTY_EVENT_KEY_MIN_VERSION=1 \
  npx --yes pnpm@11.7.0 app:install-macos
```

Alternativ aktiviert `--enable-hackerone-readonly` nur den bestehenden
Metadatenpfad, nicht Active Testing.

## Häufige Blockiergründe

| Anzeige oder Reason Code                                                                    | Sichere Reaktion                                                                                                                         |
| ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `ACTIVE_TESTING_EXTERNAL_INTEGRATIONS_DISABLED`                                             | Finder-App mit dem ausdrücklichen Active-Testing-Installerflag neu installieren oder Terminalwerte exakt prüfen; keine Defaults annehmen |
| `ACTIVE_TESTING_CAPABILITY_DISABLED`                                                        | prüfen, dass Read-only exakt `true` und Active Testing exakt `1` gesetzt ist                                                             |
| `ACTIVE_TESTING_SECURE_CORE_REQUIRED`                                                       | Core in der Setup-Shell einrichten und danach mit expliziter Event-Key-Mindestversion neu starten                                        |
| `ACTIVE_TESTING_OPERATOR_SIGNER_REQUIRED`                                                   | lokale Keychain-/Operator-Metadaten prüfen; keinen Schlüsseldatei- oder Environmentfallback verwenden                                    |
| `ACTIVE_TESTING_KILL_SWITCH_ACTIVE`                                                         | Ursache prüfen; nur über den signierten lokalen Operatorpfad freigeben                                                                   |
| `ACTIVE_TESTING_API_PROGRAM_SELECTION_REQUIRED`                                             | ausschließlich ein synchronisiertes API-Programm auswählen; manueller Import zählt nicht                                                 |
| `ACTIVE_TESTING_PROGRAM_CATALOG_NOT_CURRENT`                                                | Katalog- und Detailsnapshot neu synchronisieren und Drift vollständig prüfen                                                             |
| `ACTIVE_TESTING_CURRENT_API_SNAPSHOT_REQUIRED`                                              | Programmdetail, Structured Scopes und Exclusions vollständig synchronisieren                                                             |
| `ACTIVE_TESTING_CURRENT_SNAPSHOT_ACCEPTANCE_REQUIRED`                                       | aktuellen Snapshot menschlich prüfen und separat signiert lokal akzeptieren                                                              |
| `ACTIVE_TESTING_NO_SUPPORTED_ASSET`                                                         | keine Scopegrenze umgehen; ein anderes ausdrücklich unterstütztes API-Scope wählen oder stoppen                                          |
| `ACTIVE_TEST_POLICY_AUTOMATION_FORBIDDEN`                                                   | stoppen; kein aktiver Test für dieses Programm                                                                                           |
| `ACTIVE_TEST_REQUEST_BUDGET_EXCEEDED`                                                       | nicht zurücksetzen; Attempts und mögliche Crash-Reservation offline prüfen                                                               |
| `ACTIVE_TEST_SNAPSHOT_NOT_CURRENT_ACCEPTED`                                                 | neuen aktuellen Snapshot synchronisieren, prüfen, akzeptieren und einen neuen Plan erstellen                                             |
| `ACTIVE_TEST_KILL_SWITCH`                                                                   | Vorgang als abgebrochen beziehungsweise fehlgeschlagen behandeln; keinen automatischen Wiederholungsversuch starten                      |
| `ACTIVE_TEST_DNS_RESOLUTION_FAILED` oder ein `ACTIVE_TEST_RESOLUTION_*_BLOCKED`             | keine IP manuell erzwingen; Ziel-/DNS-Situation und Scope offline prüfen                                                                 |
| `ACTIVE_TEST_TLS_*`, `ACTIVE_TEST_REDIRECT_BLOCKED` oder `ACTIVE_TEST_CONTENT_TYPE_BLOCKED` | nicht lockern und keinen allgemeinen Client verwenden; Ergebnis als blockiert behandeln                                                  |

## Ausdrücklich nicht tun

- keine Regeln, Bedingungen oder Rechtserklärungen automatisiert bestätigen;
- keine Tokens, Cookies, Passwörter oder Browser-Sessions an Zielhosts senden;
- keinen realen Login, Account, CAPTCHA, TOTP oder E-Mail-Flow automatisieren;
- keine freien Requests, Skripte, Scanner oder LLM-generierten HTTP-Aufrufe
  verwenden;
- keine Budget-, Schema-, Kill-Switch-, DNS-, TLS- oder Redaction-Prüfung
  deaktivieren;
- keinen lokalen Report automatisch oder ungeprüft einreichen.
