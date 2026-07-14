# HackerOne Read-only – Sicherheitsmodell

## Sicherheitsziel

`HACKERONE_METADATA_READ` darf ausschließlich persönliche Programm-, Policy-
und Scope-Metadaten über die offizielle HackerOne Hacker API lesen. Die
Capability ist keine Bug-Bounty-Zielaktion und kann keine Berechtigung für
Programmassets, aktive Tests, Browserautomation oder Reports erzeugen.

Der gesamte Pfad arbeitet deny-by-default und fail-closed. Fehlende oder
fehlerhafte Konfiguration, ein aktiver oder unlesbarer Kill Switch, fehlende
signierte Evidence, ein Keychain-Fehler, ein Budgetkonflikt, eine unbekannte
Antwortform, ein Schemakonflikt oder ein Auditfehler blockiert.

## Vertrauensgrenzen

| Grenze          | Untrusted Eingabe                       | Freigabemechanismus                                                                                |
| --------------- | --------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Runtime         | Environment-/Konfigurationswerte        | exaktes Datenobjekt, echte Boolean-Semantik, intern gebrandeter Zustand, Nullbudget bei Fehler     |
| Operator        | Browserklick und Approval-Entscheidung  | Ed25519-Signatur, Session, Nonce, Frische, Context-/Payload-Digest und atomare Decision-Evidence   |
| Dashboard       | lokaler HTTP-Request                    | `127.0.0.1`, exakter Host/Origin, CSRF, feste Routen, exakte JSON- beziehungsweise Binärschemata   |
| Request         | Operation, Handle und Pagination        | geschlossenes Intent, gebrandeter Plan und kanonischer Request-Target                              |
| External Action | Proposal, Activation und Budget         | Registry, store-gebundene Control Plane, persistente Reservation und atomare Auditzeile            |
| Egress          | vollständige Ziel-URL                   | fester H1-Targettyp, Phase-1-Egress-Guard und spezialisierter HTTPS-Transport                      |
| Credentials     | lokales Einmalformular/TTY und Keychain | feste Binärgrenze, kanonische Paarhülle, vollständiger Binding-Digest, Einmal-Lease und Zeroing    |
| Response        | Header und Body                         | 1-MiB-Limit, absolute Deadline, UTF-8, genau ein JSON-Medientyp, eindeutiges JSON und Ajv-Schema   |
| Persistenz      | normalisierte Datensätze                | `STRICT`-Tabellen, Digests, Foreign Keys, Transaktionen, Trigger und tatsächliche DDL-Verifikation |

## Erzwungene External-Action-Kette

Für jeden externen GET gilt diese Kette:

```text
geschlossenes Request-Intent
→ Schema- und Semantikvalidierung
→ Registry-/Policy-Entscheidung
→ feste Scope-/Target-Prüfung
→ Ownership = not_applicable, exakt aus Registry
→ persistente Budgetprüfung und Reservation
→ signierte Aktivierungsevidence
→ Kill-Switch-Recheck
→ gebrandeter deterministischer HTTPS-Runner
→ Responsevalidierung
→ Settlement und Audit
```

Konkret müssen vor dem Transport alle folgenden Bedingungen gelten:

1. `BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED` ist exakt `true`.
2. `BUGBOUNTY_HACKERONE_READONLY_ENABLED` ist exakt `true`.
3. Der daraus abgeleitete Runtime-Zustand ist intern vertrauenswürdig.
4. Die tatsächlichen H1-Store- und Action-Gate-DDLs entsprechen exakt der
   erwarteten Tabellen-, Index- und Triggerstruktur.
5. Der globale Kill Switch ist nachweislich nicht aktiv.
6. Der Adapter ist durch eine aktuelle akzeptierte Operatorentscheidung
   aktiviert. Diese bindet den vollständigen 64-stelligen Token-Digest,
   Runtime einschließlich aller Requestbudgets, feste Zielklasse,
   Adaptergeneration und eine fünfminütige Entscheidungsfrist.
7. Das Request-Intent besteht das exakte Schema. Der Handle stammt bei einem
   Detailabruf aus einem aktiven API-synchronisierten Datensatz.
8. Das Action Gate bindet eine eindeutige Proposal-ID an Operation,
   Plan-Digest, vollständigen Credential-Binding-Digest und
   Aktivierungsevidence.
9. Das persistente Per-Operation-, Minuten- und Parallelitätsbudget erlaubt
   die Reservation. Es wird nicht durch Deaktivierung oder Reaktivierung
   zurückgesetzt; maximal eine Reservation darf gleichzeitig aktiv sein.
10. Der Action-Gate-Start prüft Runtime, Kill Switch, Aktivierung und
    Reservation erneut und erzeugt erst dann einen nicht strukturell
    fälschbaren, genau einmal konsumierbaren Transportplan.
11. Der Phase-1-Egress-Guard und die Transport-Policy erlauben exakt denselben
    kanonischen GET.
12. Das Credential-Paar wird erst nach der Reservation als genau einmal
    konsumierbare Vault-Lease geladen. Objektidentität, beide Secret-Digests
    und der vollständige Token-Binding-Digest müssen Plan, Aktivierung und
    Reservation entsprechen.
13. Nur eine vollständig validierte Antwort darf normalisiert persistiert
    werden.
14. Ein erfolgreiches Settlement prüft Runtime, Kill Switch, Adaptergeneration
    und Aktivierung nochmals. Fehler und Abbruch werden ebenfalls persistent
    abgeschlossen und erstatten kein Budget.

Crash-Reservationen bleiben nach Neustart `reserved` oder `running` und damit
fail-closed blockierend. Ein Prozessneustart darf verbrauchtes Budget nicht
zurücksetzen. Kein LLM, Browsertext oder allgemeiner HTTP-Client kann einen
gebrandeten Transportplan erzeugen.

## Signierte Aktivierung

Die Dashboard-Aktivierung ist keine freie Boolean-Transition. Sie erzeugt
eine Approval vom Typ `privacy_alert` mit:

- fester Aktionsklasse und Registry-ID;
- `https://api.hackerone.com:443`, Methode `GET`;
- vollständigem 64-stelligen SHA-256-Token-Binding-Digest; nur die UI zeigt
  dessen zwölfstelliges Präfix;
- Runtime-Digest und aktueller Adaptergeneration;
- Erstell- und Ablaufzeit;
- kanonischem Binding-Digest und Approval-Payload-Hash.

Die Entscheidung muss durch den eingerichteten Ed25519-Operator signiert,
session-/nonce-/zeit-/control-plane-/payloadgebunden und frisch sein. Signed
Statement, Replay-Schutz, Approval-Transition, Audit, Activation-Binding und
Erhöhung der Adaptergeneration werden in derselben
`BEGIN IMMEDIATE`-Transaktion geprüft und geschrieben. Wird die Annahme bei
oder nach Ende der fünfminütigen Entscheidungsfrist beobachtet, rollt die
gesamte Approval-, Audit-, Binding- und Adapteränderung zurück. Ablehnung oder
jeder Fehler lässt den Adapter deaktiviert. Eine rechtzeitig angenommene
Aktivierung erhält dadurch keine automatische Fünf-Minuten-Laufzeit.

Credential-Rotation oder -Löschung deaktiviert einen aktiven Adapter und
erhöht bei diesem Übergang seine Generation. Eine alte Aktivierung kann
dadurch nicht wiederverwendet werden.

## Erlaubter Netzwerkraum

- Schema: `https`
- Host: `api.hackerone.com`
- Port: `443`
- Methode: `GET`
- TLS-Zertifikatsprüfung: `rejectUnauthorized: true`
- Redirect-Following: deaktiviert
- Kompression: nur `identity`
- absolute Requestdeadline: 10 Sekunden
- maximale Response: 1.048.576 Bytes

Erlaubte Request-Targets:

- `/v1/hackers/programs?page[number]=N&page[size]=S`
- `/v1/hackers/programs/{handle}`
- `/v1/hackers/programs/{handle}/structured_scopes?page[number]=N&page[size]=S`
- `/v1/hackers/programs/{handle}/scope_exclusions?page[number]=N&page[size]=S`

Pagination beginnt bei Seite 1, schreitet exakt um eins fort und nutzt eine
Seitengröße von höchstens 100. Ein Next-Link darf Host, Port, Pfad,
Operation, Handle, Seitengröße oder Queryreihenfolge nicht verändern.
Userinfo, Fragment, nicht kanonische Authority und unbekannte Parameter
blockieren.

Der Verbindungstest ist enger: genau
`/v1/hackers/programs?page[number]=1&page[size]=1`, keine Folgeseite, kein
Retry und keine Programmpersistierung.

## Explizit ausgeschlossener Netzwerkraum

Nicht erreichbar sind:

- alle anderen Hosts und Ports;
- HTTP und alle nicht-GET-Methoden;
- `weaknesses`;
- Reports, Report Intents, Anhänge, Kommentare und Triage-Antworten;
- Bounty-, Zahlungs- und Customer-API-Endpunkte;
- HackerOne-Webseiten, Loginseiten und Scraping;
- DNS-, HTTP-, Browser-, Ping- oder Crawl-Zugriffe auf Asset-Identifier;
- Redirect-Ziele, auch wenn sie wieder auf HackerOne zeigen;
- benutzerdefinierte Hosts, Pfade, Methoden oder Header.

Ein 3xx-Status oder bereits ein `Location`-Header blockiert. Der Transport
isoliert die einzige Verwendung von Node HTTPS; alle anderen Dateien des
Pakets enthalten keine Netzwerkprimitive.

## Credential-Schutz

Credentials können einmalig im loopbackgebundenen Dashboard oder alternativ
über `pnpm hackerone:credentials store` in einem interaktiven TTY eingegeben
werden. Der Dashboardpfad sendet ausschließlich
`application/octet-stream`: Magic `H1CR`, Version 1, zwei Big-Endian-
`uint16`-Längen und danach die beiden druckbaren ASCII-Werte. Jeder Wert ist
auf 3.000 Bytes, das Frame auf 6.009 Bytes begrenzt. Exakter Origin, CSRF,
Content-Type und eine verpflichtende, exakt passende `Content-Length` werden
vor der Verarbeitung geprüft. DOM-Felder werden sofort geleert; kontrollierte
Browser- und Serverbuffer werden anschließend genullt. Der Pfad verwendet
weder JSON noch `localStorage`, `sessionStorage`, Logs oder Response-
Reflexionen. Die TTY-Variante bleibt der alternative lokale Adminweg.

Die festen Keychain-Referenzen enthalten je eine kanonische druckbare Hülle
der Form `BBC-H1-CRED-V1.<Rolle>.<Generation>.<Secret>`. Rolle `i`/`t`, die
zufällige 16-Byte-Generation und das Secret sind strikt kanonisch Base64url-
kodiert; Padding und nicht kanonische Restbits blockieren. Nur Identifier und
Token derselben Generation gelten als Paar. Partielle oder durch parallele
Prozesse gemischte Writes werden beim Probe/Load nicht als Credentials
akzeptiert. Bei einem Schreibfehler versucht der Vault beide Einträge zu
löschen.

Intern bindet SHA-256 den Token mit allen 64 Hexzeichen an Aktivierung,
Proposal, Reservation, den einmaligen Transportplan und die einmalige
Credential-Lease. Die Lease prüft zusätzlich Identifierdigest und
Objektidentität. Die UI und der Statusbefehl erhalten ausschließlich das erste
zwölfstellige Präfix. Es ist nur ein Änderungsindikator, kein Secretersatz und
kein Authentisierungsnachweis.

Basic Auth entsteht unmittelbar vor Node HTTPS aus zwei `Uint8Array`-Werten.
Temporäre Kombination, geladene Keychain-Hüllen, Identifier-/Token-Buffer und
Ausgabe-/Fehlerbuffer der `security`-CLI werden anschließend genullt.
Authorization wird nie auditiert.

Details stehen in `HACKERONE_KEYCHAIN_SETUP.md`.

## Budgets, Retries und Abbruch

Die Dashboard-Runtime konfiguriert:

- höchstens 100 Attempts je Top-Level-Operation;
- höchstens 60 Attempts im gleitenden persistenten Minutenfenster;
- maximale Parallelität 1.

Jeder Retry erhält eine neue persistente Proposal-ID, Reservation und
Budgeteinheit. Gescheiterte oder abgebrochene Attempts werden nicht
erstattet. Minutenverbrauch, Attempt-Index derselben Operation und aktive
`reserved`-/`running`-Zeilen gelten über Deaktivierung, Reaktivierung und
Prozessneustart hinweg. Zusätzlich serialisiert der Client Top-Level-
Operationen und hält standardmäßig mindestens 100 ms Abstand zwischen
Requeststarts.

401, 403 und 429 werden nie wiederholt. Nur 502, 503 und 504 dürfen bei
normalen Synchronisierungsoperationen höchstens zweimal mit kurzem Backoff
wiederholt werden. Der Verbindungstest wiederholt nie.

Kill-Switch-Engagement bricht den laufenden Service-Request über ein
`AbortSignal` ab. `disable`, Dashboard-`store` und Dashboard-`remove`
abortieren noch vor dem ersten Storezugriff die laufende Operation,
persistieren anschließend die Deaktivierung, warten auf deren Quieszenz und
führen erst danach eine Credential-Mutation aus. Auch ein Store-Lese- oder
Schreibfehler kann den unmittelbaren In-Process-Abort daher nicht überspringen.
So kann kein neuer Request zwischen Deaktivierung und Keychain-Mutation
beginnen. Der separate TTY-Credentialprozess besitzt keinen In-Process-
Abortkanal zu einem anderen Dashboardprozess und bleibt daher ein bewusst
getrennter lokaler Adminweg. Der persistente Settlementzustand bleibt
maßgeblich; ein Abbruch stellt kein Budget wieder her.

## Response-Schutz

Der Client akzeptiert genau einen `Content-Type` mit `application/json` oder
`application/vnd.api+json`, optional exakt `charset=utf-8`. Mehrdeutige
Header, unbekanntes Content-Encoding, ungültiges UTF-8, BOM, ungültiges oder
mehrdeutiges JSON, doppelte Schlüssel, fehlende Pflichtfelder und unbekannte
Felder blockieren.

Rohe Bodys leben nur im Speicher. Response-Chunks und zusammengesetzte Bodys
werden nach Verarbeitung oder Fehler genullt. Persistiert werden nur die
explizit normalisierten Felder.

## SQLite-Schema und Persistenz

Metadaten-Store und Action Gate besitzen getrennte feste
Schemaerwartungen. Beim ersten Anlegen muss der jeweilige Namespace leer
sein. Nach dem Anlegen und bei jedem Wiederöffnen werden die tatsächlichen
`sqlite_schema`-Objekte einschließlich DDL, Tabellen, Indizes und Trigger
kanonisch verglichen. Ein gültig wirkender Markerdigest allein reicht nicht.
Zusätzliche Spalten/Indizes, ersetzte Trigger oder partielle Namespaces
blockieren mit `HACKERONE_STORE_SCHEMA_MISMATCH` beziehungsweise
`HACKERONE_ACTION_SCHEMA_MISMATCH`.

API- und manuelle Quellen liegen in getrennten Tabellen und erhalten
unterschiedliche opaque Referenzpräfixe. Snapshots, Request-Audit,
Action-Attempts, Aktivierungs-/Acceptance-Bindings und Acceptance-Evidence
sind per Trigger unveränderlich oder auf exakt definierte Zustandsübergänge
beschränkt.

Request-Auditereignisse enthalten ausschließlich:

- zufällige Request-ID;
- Aktionsklasse und Endpoint-Klasse;
- redigierten Outcome-Code;
- HTTP-Status oder `null`;
- Dauer.

Sie enthalten keinen Body, Handle, Pfad, Query, Header, Asset-Identifier und
kein Credential. Das Action Gate schreibt zusätzlich bodyfreie
Authorization- und Settlement-Audits. Schlägt der konfigurierte
Request-Audit-Sink fehl, schlägt die Operation fail-closed fehl.

## Markierte Security-Core-Änderungen

Pilot A verändert zwei bestehende Security-Core-Grenzen zwingend und eng
begrenzt:

- `packages/control-plane/store.ts` beweist die gemeinsame vertrauenswürdige
  Datenbankbindung und erweitert die vorhandene signierte Approval-
  Transaktion um H1-Aktivierung beziehungsweise H1-Snapshot-Annahme. Die
  Erweiterung schreibt keine Evidence außerhalb von `BEGIN IMMEDIATE` und
  rollt bei abgelaufener Aktivierungsentscheidung, Katalog-Drift,
  Signatur-, Audit- oder Revisionsfehler vollständig zurück.
- `packages/secret-store/store.ts` liest Keychainwerte und CLI-Fehlerausgaben
  ausschließlich in begrenzte Bytebuffer, gibt eine kontrollierte Kopie aus
  und nullt alle eigenen Backing-Buffer auf Erfolgs- und Fehlerpfaden.

Beide Änderungen besitzen direkte Regressionstests. Bestehende
Signatur-, Replay-, Keychain- und Fail-closed-Prüfungen wurden nicht
gelockert.

## Snapshots, Drift und signierte Annahme

Der Policy-Digest bindet Policytext, Programmstatus, Submission State,
Bounty-Status, Open Scope, Safe Harbor, sortierte Structured Scopes und Scope
Exclusions. Der Snapshot bindet zusätzlich alle normalisierten
Programmdaten, Abrufzeit, Quelle, Adapter-/Schema-Version und Vorgänger.

Drift umfasst:

- Policytext;
- Programmstatus;
- Open Scope;
- Safe Harbor;
- Submission-/Bounty-Eligibility;
- Instructions und Maximum Severity;
- Scope-Identität und CIA-Metadaten;
- Scope Exclusions.

Schon der Katalogsync vergleicht katalogseitiges Policy-Material mit dem
aktuellen Detailsnapshot. Bei Änderung oder Entfernung setzt er
`catalog_drift_pending`, pausiert ausdrücklich gebundene Kampagnen sofort und
schreibt ein bodyfreies Katalog-Drift-Audit. Solange der Marker gesetzt oder
das API-Programm inaktiv ist, blockieren neue Kampagnenbindungen und alle
Policy-Acceptance-Grenzen. Der Marker bleibt auch dann sticky, wenn ein
späterer Katalogsync wieder zum alten Material zurückkehrt. Erst ein exakt
gebundener Detailsnapshot entfernt ihn.

Katalogersetzung und Syncstatus, Detailsnapshot und Auswahl/Syncstatus sowie
manueller Datensatz und initialer Snapshot werden jeweils in einer einzigen
Transaktion geschrieben. Bei Snapshot-Drift werden neuer Snapshot,
Pointerupdate, bodyfreies Drift-Audit und Pause ausdrücklich gebundener
Kampagnen ebenfalls gemeinsam geschrieben. Betroffene Kampagnen wechseln von
`approved` oder `running_simulation` auf `paused`, verlieren ihre bisherige
menschliche Freigabe und erhalten `kill_switch_status = engaged`. Ein Audit-
oder Persistenzfehler rollt die jeweilige gesamte lokale Wirkung zurück.

Synchronisierung ist keine Zustimmung. Jede Snapshotzeile wird technisch mit
`acceptance_pending = 1` unveränderlich angelegt. Der sichtbare
Annahmestatus wird ausschließlich aus einer separaten append-only
`hackerone_policy_acceptances`-Evidence abgeleitet.

Eine Annahme ist nur für den aktuell gebundenen Snapshot möglich. Die
Approval bindet opaque Programmreferenz, Quelle, aktuellen Snapshot-Digest,
Policy-Digest, Vorgänger-Digest, Operator, Zeit und Payload. Checkbox und
Same-Origin-Request sind lediglich der menschliche Auslöser; erst eine
frische Ed25519-signierte Operatorentscheidung erzeugt in derselben
Transaktion Decision-Audit, unveränderliche Acceptance-Evidence und
Statement-Referenz. Sie ist keine Annahme von HackerOne-Nutzungsbedingungen
und keine Freigabe für Ziel- oder Reportaktionen.

## Dashboard-Grenze

Der Dashboardserver bindet ausschließlich an `127.0.0.1`. Alle H1-Mutationen
benötigen einen sicheren Core, exakten Origin, CSRF-Token und eine kanonische
Route. Fachmutationen verlangen `application/json` und ein exaktes
Body-Schema. Die einzige Credential-Store-Route verlangt stattdessen exakt
`application/octet-stream`, den versionierten Binärrahmen und die strengere
verpflichtende `Content-Length`. Die Setup-Shell blockiert jede H1-Mutation
vor dem ersten Effekt.

`POST /api/hackerone/credentials/store` ist ausschließlich dieser lokale,
einmalige und begrenzte Secretpfad. Sicherheitsheader blockieren fremde
Origins, Frames, Formziele und Worker; die Anwendung persistiert Credentials
nicht in Browser-Speichern und reflektiert sie nicht. Credential-Löschung ist
eine separate fail-closed Mutation; Store und Remove deaktivieren und
abortieren vor der Keychain-Mutation.

Die H1-Projektion begrenzt den Katalog auf 1.000 Programme, die sichtbare
Versionshistorie auf die letzten 20 Versionen und Kampagnen auf 100. Gesamt-
und Truncation-Zähler machen die Begrenzung sichtbar; die aktuelle Auswahl
wird im begrenzten Programmkatalog erhalten. Katalogsummaries enthalten
keinen Policytext, Versionssummaries keinen Snapshotbody und
Kampagnensummaries keinen Contract oder Accountreferenzen. Programmsummaries
enthalten Score, Reason Codes, Status-, Bounty-/Safe-Harbor-/Bookmark- und
persönliche Reportfelder, aber keinen Policytext. Nur der aktuell ausgewählte
Snapshot und der unmittelbar vorherige Policytext werden für die explizite
Review projiziert. Bei mehr als 1.000 Programmen oder 20 Versionen zeigt die
UI den jeweiligen Truncation-Indikator.

Asset-Identifier werden mit `textContent` als Plain Text und expliziter
Copy-Aktion dargestellt. Es entstehen keine Links und keine Navigation.

## Test- und Entwicklungsgrenze

Automatisierte Tests verwenden ausschließlich In-Process-Fakes,
synthetische Credentials und Loopback-Mockserver. Sie rufen weder
`api.hackerone.com` noch einen Plattform- oder Zielhost auf. Der
Produktions-Transport wird durch Policy-, Fälschungs-, Timeout-, Header-,
Größen-, Schema-, Egress- und lokale Integrationstests qualifiziert.

Der manuelle CLI-Smoke ist TTY-, Konfigurations-, signierter Aktivierungs-,
Credential- und Kill-Switch-gebunden. Er wird weder von Tests noch vom Build
gestartet und wurde während der Entwicklung nicht ausgeführt.
