# HackerOne Read-only – Benutzerhandbuch

## Was diese Integration tut

Die Integration liest persönliche HackerOne-Programm-, Policy-, Structured-
Scope- und Scope-Exclusion-Metadaten über die offizielle Hacker API. Sie
sendet keine Requests an Programmassets und reicht keine Reports ein.

Auf der lokalen HackerOne-Ansicht müssen dauerhaft sichtbar sein:

- **HACKERONE READ-ONLY**
- **KEINE ZIELREQUESTS**
- **KEINE REPORT-EINREICHUNG**
- **EXTERNE METADATENINTEGRATION AKTIV/DEAKTIVIERT**

Wenn eine Grenze fehlt oder der Zustand unklar ist, stoppe die Bedienung,
deaktiviere die Integration und engagiere den globalen Kill Switch.

## Voraussetzungen

- macOS für den produktiven Keychain-Pfad;
- Node.js mindestens 24;
- installierte, gelockte Repository-Abhängigkeiten;
- sichere lokale Control-Plane-Einrichtung nach
  [FIRST_RUN_GUIDE.md](FIRST_RUN_GUIDE.md);
- gültiger Event-Key-Mindestversionsanker nach
  [PHASE5_EVENT_KEY_LIFECYCLE.md](PHASE5_EVENT_KEY_LIFECYCLE.md);
- eingerichteter lokaler Ed25519-Operator nach
  [PHASE4_SIGNED_OPERATOR_APPROVALS.md](PHASE4_SIGNED_OPERATOR_APPROVALS.md);
- persönlicher HackerOne-API-Identifier und Token nur für echte API-Nutzung;
  ein Token-only-Credential ist im aktuellen Basic-Auth-Adapter nicht
  kompatibel und darf nicht mit einem geratenen Identifier ergänzt werden.

Ohne sicheren Core kann nur die lokale Setup-Oberfläche starten. Jede
HackerOne-Aktion mit externer oder signierter Wirkung bleibt serverseitig
fail-closed blockiert. Nur Credential-Speicherung, Credential-Löschung und
Integrations-Deaktivierung bleiben als lokale Sicherheitsaktionen verfügbar;
sie aktivieren und kontaktieren nichts.

## Credentials lokal verwalten

Das Dashboard bietet ein einmaliges lokales Secretformular. Gib Identifier
und Token nur dort ein und wähle **Credentials lokal speichern**. Die Felder
werden sofort geleert; die Werte gehen ausschließlich als festes binäres
`H1CR`-v1-Frame mit maximal 3.000 druckbaren ASCII-Bytes je Wert an
`POST /api/hackerone/credentials/store` auf demselben Loopback-Origin. Die
Route verlangt `application/octet-stream`, exakten Origin, CSRF und eine
verpflichtende exakt passende `Content-Length`. Sie verwendet weder JSON noch
Browser-Storage oder Logs und reflektiert keine Secretwerte.

Alternativ kannst du selbst in einem interaktiven Terminal speichern:

```sh
pnpm hackerone:credentials store
```

Identifier und Token werden verborgen eingelesen. Sie erscheinen weder im
Terminal noch in argv oder Environment. Beide Speicherwege deaktivieren den
Adapter, erzeugen ein generation-gebundenes kanonisches Keychain-Paar und
verifizieren es durch sofortiges Zurücklesen. Erst danach zeigen sie den
kurzen Token-Fingerprint. Der lokal kompilierte native macOS-Helfer erhält die
Werte ausschließlich über stdin; der frühere interaktive
`/usr/bin/security -w`-Promptpfad wird nicht verwendet.

Beende das Dashboard vollständig, bevor du `store` oder `remove` ausführst.
Der separate TTY-Adminprozess kann keinen bereits laufenden Transport in
einem anderen Prozess aktiv abbrechen. `status` ist read-only, bleibt aber
ebenfalls TTY-gebunden.

Status prüfen:

```sh
pnpm hackerone:credentials status
```

Credentials entfernen:

```sh
pnpm hackerone:credentials remove
```

Nur diese drei alternativen CLI-Unterbefehle sind TTY-gebunden. Im Dashboard
stehen Speichern, Präsenzprüfung und Entfernen ebenfalls lokal zur Verfügung.
Ausführliche Rotation, Paarhüllen und Fehlerbehandlung stehen in
[HACKERONE_KEYCHAIN_SETUP.md](../HACKERONE_KEYCHAIN_SETUP.md).

## Anwendung starten

Für den normalen lokalen Start ohne Terminal kann einmalig die macOS-App
installiert werden:

```sh
npx --yes pnpm@11.7.0 app:install-macos
```

Danach startet `~/Applications/Bug Bounty Copilot.app` das Dashboard und
öffnet ausschließlich die validierte Loopback-URL. Der Launcher lädt nichts
nach. Der Standardmodus erzwingt beide Integrationsschalter als `false`. Für
die bewusst konfigurierte H1-Read-only-Sitzung installiere den Launcher
stattdessen einmalig mit:

```sh
npx --yes pnpm@11.7.0 app:install-macos -- --enable-hackerone-readonly
```

Das konfiguriert nur die beiden Startup-Schalter. Wenn die getrennte lokale
Event-/Operator-Einrichtung bereits abgeschlossen ist, müssen beim einmaligen
Installerlauf außerdem deren vier **nicht geheimen** Referenz- und
Versionswerte gesetzt werden; der Finder erbt keine Terminalvariablen. Der
Installer validiert und speichert ausschließlich diese Metadaten privat. Er
speichert keinen Event- oder Operator-Schlüssel. Adapteraktivierung,
Kill-Switch-Freigabe und jeder Request bleiben getrennte Frontendaktionen.
Der vollständige einmalige Beispielbefehl und die Fail-closed-Regeln stehen in
[MACOS_APP_LAUNCHER.md](MACOS_APP_LAUNCHER.md).

Beide separaten externen Schalter sind standardmäßig aus. Für eine bewusst
manuell gestartete API-Sitzung müssen sie exakt `true` sein:

```sh
BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED=true \
BUGBOUNTY_HACKERONE_READONLY_ENABLED=true \
pnpm app
```

Zusätzlich müssen die Werte deiner sicheren lokalen Installation korrekt
gesetzt sein, insbesondere `BUGBOUNTY_EVENT_KEY_MIN_VERSION`,
`BUGBOUNTY_OPERATOR_KEY_REFERENCE`, `BUGBOUNTY_OPERATOR_ID` und
`BUGBOUNTY_OPERATOR_KEY_REVISION`. Secretwerte gehören nicht in
Environmentvariablen.

Öffne ausschließlich die vom Prozess ausgegebene URL. Sie muss mit
`http://127.0.0.1:` beginnen. Der Standardport ist 4173; bei belegtem Port
kann ein anderer Loopbackport verwendet werden.

Behandle den globalen Kill Switch nach jedem Start zunächst als aktiv, bis
die Control Plane nachweislich einen gültigen signierten Clear-Zustand
anzeigt.

## Globalen Kill Switch freigeben

Die H1-Aktivierungsroute verlangt einen bereits freigegebenen globalen Kill
Switch. Verwende ausschließlich den bestehenden signierten lokalen
Operatorworkflow. Das Clear ist keine H1-Aktivierung und keine Policy-
Zustimmung.

Wenn der Kill Switch während eines Requests engagiert wird, abortiert der
Service den in-flight Request und blockiert neue Reservationen. Ein Abbruch
erstattet kein Budget.

**Integration deaktivieren**, **Credentials lokal speichern** und
**Credentials entfernen** abortieren eine laufende H1-Serviceoperation noch
vor dem ersten Storezugriff, persistieren danach die Deaktivierung und warten
auf Quieszenz. Erst danach wird eine Keychain-Mutation ausgeführt. Der Kill
Switch bleibt die übergeordnete
Sofort-Stopp-Grenze, ist aber keine Vorbedingung dafür, dass diese drei
Dashboardaktionen einen laufenden Request abbrechen.

## Read-only-Integration signiert aktivieren

1. Öffne **Einstellungen → Integrationen → HackerOne**.
2. Prüfe die sichtbare Liste aller fünf Aktivierungsvoraussetzungen:
   Security-Core, globaler External-Schalter, H1-Read-only-Schalter,
   vollständiges Credential-Paar und freigegebener Kill Switch.
3. Prüfe Präsenzanzeige und kurzen Fingerprint. Vollständige Secretwerte
   dürfen nirgendwo erscheinen.
4. Prüfe, dass **Globale externe Integrationen** und **Adapter konfiguriert**
   angezeigt werden und der Kill Switch freigegeben ist.
5. Wähle **Read-only-Integration aktivieren**.
6. Prüfe **EXTERNE METADATENINTEGRATION AKTIV**.

Der Klick erzeugt eine frische lokale Approval, die den vollständigen
64-stelligen SHA-256-Token-Digest, Runtime einschließlich Requestbudgets,
feste API-Zielklasse und Adaptergeneration bindet. Die UI zeigt davon nur das
zwölfstellige Präfix. Der konfigurierte lokale Operator signiert die
Entscheidung; Signatur, Replay-Schutz, Decision-Audit, Binding und
Adaptertransition werden atomar geprüft. Eine erst bei oder nach Ablauf der
fünfminütigen Entscheidungsfrist beobachtete Annahme rollt vollständig zurück.

Die Aktivierung betrifft ausschließlich `HACKERONE_METADATA_READ`. Sie
aktiviert weder allgemeine Zielaktionen noch Browserzugriffe oder Reports.
Credential-Rotation, Credential-Löschung oder **Integration deaktivieren**
invalidiert die alte Aktivierung über eine neue Adaptergeneration.

Jeder GET reserviert weiterhin eine persistente Budgeteinheit. Minuten-,
Per-Operation- und aktive Crash-Budgets überleben Deaktivierung und
Reaktivierung. Der vom Gate erzeugte Transportplan und die aus dem Keychain
geladene Credential-Lease sind jeweils nur einmal verwendbar.

## Verbindung testen

Wähle **Verbindung testen**. Der Vorgang darf genau einen Request senden:

```text
GET https://api.hackerone.com:443/v1/hackers/programs?page[number]=1&page[size]=1
```

Er lädt keine Folgeseite, wiederholt nicht und persistiert keine
Programmliste. Angezeigt werden nur Ergebnis, Anzahl, Schema-Gültigkeit,
Dauer und ein redigierter Status.

Mögliche Ergebnisse:

- `connected`
- `invalid_credentials`
- `unauthorized`
- `rate_limited`
- `unavailable`
- `malformed_response`
- `blocked_by_policy`
- `blocked_by_kill_switch`
- `secret_store_unavailable`

## Programmkatalog synchronisieren

1. Prüfe signierte Adapteraktivierung und freigegebenen Kill Switch.
2. Wähle **Programmkatalog synchronisieren**.
3. Prüfe Anzahl, Synchronisierungszeit und Ergebnis.
4. Wähle im Dropdown ein Programm mit Quelle
   **authentifizierte HackerOne API**.
5. Wähle **Auswahl übernehmen**.

Pagination beginnt bei Seite 1, läuft seriell und nutzt Seitengröße 100. Ein
fremder, nicht kanonischer oder manipulierter Next-Link beendet die gesamte
Synchronisierung. Maximal 20 Seiten und 1.000 Programme werden akzeptiert.
Bei einem Fehler bleibt der vorherige Katalog bestehen. Es gibt kein
Browser-Scraping oder freie URL als Fallback.

Katalogdaten und erfolgreicher Synchronisierungsstatus werden atomar
geschrieben. Erkennt der Katalog bei einem bereits detailliert
synchronisierten Programm geändertes Policy-Material oder fehlt das Programm,
setzt er sofort **Katalog-Drift ausstehend**, pausiert ausdrücklich gebundene
aktive Kampagnen und blockiert eine Policy-Annahme. Erst der exakte neue
Detailsnapshot hebt diesen Marker auf; ein späterer unveränderter oder
zurückgekehrter Katalogsync allein räumt ihn bewusst nicht ab.

Der Dashboardkatalog zeigt höchstens 1.000 Programmsummaries und kennzeichnet
Truncation. Summaries enthalten Score, Reason Codes, Katalog-/Driftstatus,
Bounty-, Open-Scope-, Safe-Harbor-, Bookmark- und persönliche Reportfelder,
aber keinen Policytext. Der vollständige Text wird nur für den ausgewählten
Review-Snapshot projiziert.

## Programmdetails, Scopes und Ausschlüsse synchronisieren

Wähle **Programmdetails, Scopes und Ausschlüsse synchronisieren**. Der Handle
wird ausschließlich aus dem aktiven API-synchronisierten Datensatz hinter
der opaque `h1a_`-Referenz gelesen.

Die Operation liest nacheinander:

1. `/v1/hackers/programs/{handle}`;
2. `/v1/hackers/programs/{handle}/structured_scopes`;
3. `/v1/hackers/programs/{handle}/scope_exclusions`.

Nach vollständiger In-Memory-Validierung werden append-only Snapshot,
Programmauswahl, erfolgreicher Synchronisierungsstatus, Drift/Pause/Audit und
das Zurücksetzen von `catalog_drift_pending` atomar geschrieben. Prüfe:

- Programmstatus und Submission State;
- vollständigen Policytext;
- Bounty-, Open-Scope- und Safe-Harbor-Indikatoren;
- persönliche Programmstatistiken;
- Structured Scopes einschließlich Eligibility, Instructions, Severity und
  CIA-Metadaten;
- Scope Exclusions;
- Policy- und Snapshot-Digest;
- Vorgängerversion und Driftkategorien;
- Suitability-Score und Reason Codes.

Asset-Identifier erscheinen nur als Plain Text mit expliziter Copy-Aktion.
Es gibt keine Links, Navigation, DNS-Auflösung oder HTTP-/Browseraktion.

## Programm an eine lokale Kampagne binden

Die H1-Sektion projiziert höchstens 100 lokale Kampagnensummaries. Um eine
Abhängigkeit ausdrücklich zu erfassen:

1. wähle das H1-Programm und übernimm die Auswahl;
2. wähle eine exakte lokale Kampagnen-ID;
3. wähle **Abhängige Kampagne binden**.

Die Route akzeptiert nur die aktuell ausgewählte opaque Programmreferenz und
eine streng begrenzte Kampagnen-ID. Bindungen sind append-only. Es gibt in
Pilot A kein Unbind.

Bei späterem Drift werden nur ausdrücklich gebundene Kampagnen in
`approved` oder `running_simulation` pausiert. Snapshot, aktueller Pointer,
Pause, Entfernen der bisherigen Kampagnenfreigabe und bodyfreies Drift-Audit
werden in einer lokalen Transaktion geschrieben.

## Policy Drift und signierte Annahme

Eine erfolgreiche Synchronisierung akzeptiert nichts. Jeder neue Snapshot
zeigt zunächst **ANNAHME AUSSTEHEND**.

Drift kann folgende Kategorien enthalten:

- Policytext geändert;
- Programmstatus geändert;
- Open Scope geändert;
- Safe Harbor geändert;
- Submission Eligibility geändert;
- Bounty Eligibility geändert;
- Instructions geändert;
- Maximum Severity geändert;
- Scopes/CIA-Metadaten geändert;
- Scope Exclusions geändert.

Das Dashboard zeigt den vollständigen aktuellen und unmittelbar vorherigen
Policytext sowie die letzten 20 Versionssummaries. Bei älteren Versionen
zeigt es den Truncation-Indikator. Für eine Annahme:

1. prüfe aktuellen und vorherigen Policytext, Scopes, Ausschlüsse und Diff;
2. prüfe opaque Programmreferenz, Snapshot- und Policy-Digest;
3. stelle sicher, dass der globale Kill Switch freigegeben ist;
4. setze die Checkbox zur exakten aktuellen Snapshotversion;
5. wähle **Aktuelle Policy explizit akzeptieren**.

Der Klick erzeugt eine Approval vom Typ `program_policy_acceptance`. Die
frische Operator-Signatur bindet Session, Nonce, Payload, Programm, Quelle,
aktuellen Snapshot, Policy, Vorgänger und Zeit. Nur eine atomar persistierte
Acceptance-Evidence lässt den sichtbaren Status auf akzeptiert wechseln.

Ein alter Digest, eine wiederverwendete Nonce, ein nicht aktueller Snapshot,
`catalog_drift_pending`, ein inaktives API-Programm, ein aktiver Kill Switch,
eine ungültige Signatur oder ein Auditfehler blockiert. Diese Prüfung läuft
bei Approval-Erzeugung, Decision und Evidence-Insert erneut. Diese lokale
Annahme ist keine Annahme von HackerOne-
Nutzungsbedingungen und keine Report- oder Zielrequestfreigabe.

## Manueller Offline-Fallback

Ohne Token kannst du **Manueller JSON-Import** verwenden. Der Import erzeugt
keine Netzwerkverbindung und wird als **manuell und ungeprüft** markiert.
Sicherer Core bleibt erforderlich; die beiden External-Integration-Schalter
und H1-Credentials sind für den Import nicht nötig.

Das exakte Schema und ein synthetisches Beispiel stehen in
[HACKERONE_MANUAL_IMPORT.md](../HACKERONE_MANUAL_IMPORT.md). Die eigentliche
Importquelle darf höchstens 1 MiB groß sein.

Ein manueller Datensatz kann lokal geprüft, an eine lokale Kampagne gebunden
und über dieselbe signierte Snapshot-Acceptance angenommen werden. Er kann
nicht als API-synchronisierter Handle dienen. Falls der Detailsync-Button
noch sichtbar ist, blockiert das Backend die `h1m_`-Referenz fail-closed.
Programmzeile und initialer Snapshot werden atomar importiert; ein Fehler
hinterlässt keines von beiden partiell.

## Dashboard-HTTP-Oberfläche

Die einzige Binärroute ist:

- `POST /api/hackerone/credentials/store` mit exakt
  `application/octet-stream` und `H1CR`-v1-Frame

Die übrige H1-Sektion verwendet nur diese festen JSON-Mutationsrouten:

- `POST /api/hackerone/credentials/remove`
- `POST /api/hackerone/integration/enable`
- `POST /api/hackerone/integration/disable`
- `POST /api/hackerone/connection-test`
- `POST /api/hackerone/programs/synchronize`
- `POST /api/hackerone/program/select`
- `POST /api/hackerone/program/synchronize`
- `POST /api/hackerone/campaign/bind`
- `POST /api/hackerone/policy/accept`
- `POST /api/hackerone/manual-import`

Status kommt aus `GET /api/state`. Alle Routen sind Same-Origin/CSRF-
geschützt und verlangen exakte Bodys. Die Binärroute besitzt zusätzlich eine
verpflichtende exakte `Content-Length`, ein Limit von 6.009 Bytes und
serverseitiges Buffer-Zeroing. Sie ist kein allgemeiner HTTP- oder
Secret-Upload-Endpunkt.

## Credentials rotieren oder entfernen

- Das lokale Dashboardformular oder alternativ
  `pnpm hackerone:credentials store` rotiert das generation-gebundene Paar
  und deaktiviert den Adapter zuerst.
- `pnpm hackerone:credentials remove` deaktiviert und löscht beide festen
  Einträge.
- Der Dashboardbutton **Credentials entfernen** abortiert vor dem ersten
  Storezugriff, deaktiviert persistent, wartet auf Quieszenz und löscht danach;
  er nimmt selbst keine Secretwerte entgegen.
- Lokale Programme, Snapshots und Evidence bleiben nach Secretlöschung
  offline lesbar.
- Nach Rotation sind ein signierter Kill-Switch-Clear, eine neue signierte
  Adapteraktivierung und ein bewusster Verbindungstest erforderlich.

Gib Token oder Identifier niemals in Codex, GitHub, Logs, Screenshots oder
Supporttickets ein.

## Manueller Terminal-Verbindungstest

`pnpm hackerone:connection-test` ist ein ausdrücklich manueller Live-Smoke.
Er darf niemals von Tests, Build, CI oder Codex gestartet werden. Wenn der
Benutzer ihn selbst startet, kontaktiert er den echten offiziellen API-Host.

Voraussetzungen:

- interaktives stdin und stdout;
- beide Environment-Schalter exakt `true`;
- vollständiges generation-gebundenes Keychain-Paar;
- persistenter Adapter bereits über aktuelle signierte Evidence aktiviert;
- globaler Kill Switch freigegeben;
- Action-Gate-Schema, Budget und Audit verfügbar.

Dann lautet der manuelle Befehl:

```sh
BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED=true \
BUGBOUNTY_HACKERONE_READONLY_ENABLED=true \
pnpm hackerone:connection-test
```

Der Befehl aktiviert oder entsperrt nichts selbst. Er führt nur den festen
Ein-Datensatz-GET aus und gibt keine Responseinhalte aus.

## Fehlerbehebung

| Anzeige/Code                                     | Sichere Reaktion                                                               |
| ------------------------------------------------ | ------------------------------------------------------------------------------ |
| `HACKERONE_METADATA_CAPABILITY_DISABLED`         | beide expliziten Runtime-Schalter prüfen; nicht umgehen                        |
| `EXTERNAL_INTEGRATIONS_DISABLED`                 | Konfiguration bleibt fail-closed; nur bewusst und exakt aktivieren             |
| `HACKERONE_ADAPTER_DISABLED`                     | Credentials/Fingerprint prüfen und neue signierte Aktivierung auslösen         |
| `HACKERONE_SIGNED_ACTIVATION_REQUIRED`           | keine direkte Boolean-Aktivierung versuchen; Dashboard-Approval verwenden      |
| `HACKERONE_KILL_SWITCH`                          | Ursache prüfen; nur über signierten Operatorpfad freigeben                     |
| `HACKERONE_SECRET_STORE_UNAVAILABLE`             | Keychain-Paar lokal im Dashboard oder mit TTY-Adminbefehl prüfen/neu schreiben |
| `HACKERONE_CREDENTIAL_FRAME_INVALID`             | Eingaben neu erfassen; Binärrahmen nicht manuell konstruieren                  |
| `HACKERONE_CREDENTIAL_PAIR_CHANGED`              | Operation stoppen; Adapter deaktivieren und Credentials kontrolliert rotieren  |
| `HACKERONE_INVALID_CREDENTIALS`                  | Token außerhalb des Produkts rotieren und erneut sicher speichern              |
| `HACKERONE_RATE_LIMITED`                         | stoppen und später manuell erneut versuchen; kein erzwungener Retry            |
| `HACKERONE_REQUEST_BUDGET_EXCEEDED`              | keine Limits umgehen; aktive/crashed Reservation und Aktivierung prüfen        |
| `HACKERONE_PAGINATION_BLOCKED`                   | keine URL korrigieren; Adapter/API-Vertrag untersuchen                         |
| `HACKERONE_RESPONSE_SCHEMA_INVALID`              | bestehende Daten offline verwenden; Schemaänderung untersuchen                 |
| `HACKERONE_STORE_SCHEMA_MISMATCH`                | nicht reparieren/adoptieren; lokale DDL-Ursache offline untersuchen            |
| `HACKERONE_ACTION_SCHEMA_MISMATCH`               | Adapter deaktiviert lassen; lokale DDL-Ursache offline untersuchen             |
| `HACKERONE_SNAPSHOT_ACCEPTANCE_REQUIRES_CURRENT` | aktuelle Version/Digests neu prüfen                                            |
| `HACKERONE_CAMPAIGN_BINDING_POLICY_DRIFT`        | Detailsnapshot synchronisieren und Drift menschlich prüfen                     |
| `HACKERONE_POLICY_ACCEPTANCE_KILL_SWITCH`        | Annahme stoppen; Kill Switch nur nach Prüfung signiert freigeben               |

Bei Keychain-, Schema-, Netzwerk-, Budget- oder Policyfehlern gibt es keinen
Fallback auf Browser, freie HTTP-Requests, alte Credentials oder Zielassets.

## Beenden

Beende die lokale Anwendung mit `Ctrl-C`. Verlasse dich beim nächsten Start
nicht auf einen alten UI-Status. Prüfe Runtime, Credential-Paar,
Adaptergeneration, signierte Aktivierung und globalen Kill Switch erneut.
