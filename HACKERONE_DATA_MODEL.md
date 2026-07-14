# HackerOne Read-only – lokales Datenmodell

## Grundsätze

- API- und manuell importierte Daten bleiben sichtbar und physisch getrennt.
- Nur strikt validierte, normalisierte Felder werden gespeichert.
- Rohe API-Antworten, Authorization-Header und Secrets außerhalb der beiden
  festen Keychain-Hüllen werden nicht gespeichert.
- Snapshots, Aktivierungsbindungen, Acceptance-Evidence, Action-Attempts und
  Audits sind append-only oder besitzen nur exakt definierte Transitionen.
- Synchronisierung ist keine Zustimmung.
- Opaque lokale Referenzen sind Identifikatoren, keine Credentials und keine
  Autorisierung.
- Positive externe Aktionen entstehen nur aus der store-gebundenen
  Control-Plane- und Action-Gate-Evidence.

Die Tabellen liegen in der privaten lokalen Control-Plane-SQLite-Datei,
standardmäßig `.local/dashboard/control-plane.sqlite`. Die Härtung von
`ControlPlaneDatabase` gilt unverändert. HackerOne-Metadaten sind normale
SQLite-Inhalte und nicht zusätzlich als AES-256-GCM-Event-Hüllen
verschlüsselt; das ist bei privaten Programmdaten ein dokumentiertes lokales
Restrisiko.

## Quellen und opaque Referenzen

| Quelle                        | Bedeutung                                                          | Referenzpräfix |
| ----------------------------- | ------------------------------------------------------------------ | -------------- |
| `hackerone_api_authenticated` | über persönliche Credentials validierte HackerOne-API-Antwort      | `h1a_`         |
| `manual_unverified`           | lokal bereitgestelltes, nicht von HackerOne verifiziertes Dokument | `h1m_`         |

Die opaque Referenz bindet Präfix, Quelle und externe Identität über SHA-256.
Ein manueller Datensatz kann dadurch nicht als API-synchronisiert verwendet
werden. Detailrequests akzeptieren nur aktive `h1a_`-Datensätze und lesen den
Handle aus dem Store, niemals aus Freitext.

## Credential-Hüllen und Bindungsprojektion

Die beiden Keychain-Einträge sind keine rohen Passwortwerte. Sie enthalten
je eine kanonische druckbare Hülle
`BBC-H1-CRED-V1.<Rolle>.<Generation>.<Secret>` mit Rolle `i`/`t`, gemeinsamer
zufälliger 16-Byte-Generation und ungepaddeter Base64url-Kodierung. Nicht
kanonische Hüllen oder unterschiedliche Generationen ergeben kein gültiges
Paar.

Der vollständige SHA-256-Token-Digest mit 64 Hexzeichen wird nur intern an
Aktivierung, Proposal, Attempt, One-shot-Transportplan und One-shot-
Credential-Lease gebunden. Die Dashboard- und CLI-Projektion schneidet ihn
auf zwölf Zeichen ab. Weder der vollständige Digest noch die Hüllen werden
über `/api/state` ausgegeben.

## Tatsächliche Schema-Verifikation

Der Metadaten-Store und das Action Gate verwalten getrennte feste
SQLite-Namespaces. Je Namespace wird eine kanonische Erwartung aus allen
Tabellen-, Index- und Trigger-DDLs gebaut.

Beim ersten Start muss der Namespace vollständig leer sein. Nach dem Anlegen
und bei jedem Wiederöffnen vergleicht die Anwendung die tatsächlichen
`sqlite_schema`-Objekte mit der Erwartung. Zusätzlich werden Komponentenname,
Version und Digest im Marker geprüft. Der Marker allein gilt ausdrücklich
nicht als Beweis.

Folgende Manipulationen blockieren unter anderem:

- zusätzliche oder fehlende Spalten;
- zusätzliche oder fehlende Indizes;
- geänderte oder fehlende Trigger;
- unerwartete gleichnamige Objekte;
- partielle, vorab angelegte Namespaces;
- ein falscher Markerdigest oder eine falsche Version.

Fehlercodes sind `HACKERONE_STORE_SCHEMA_MISMATCH` beziehungsweise
`HACKERONE_ACTION_SCHEMA_MISMATCH`. Es gibt keine automatische Adoption oder
Reparatur unbekannter DDL.

## Metadaten-Store

### `hackerone_readonly_schema`

Marker für Komponentenname `metadata_store`, Schema-Version 1 und den Digest
der vollständigen erwarteten Store-DDL.

### `hackerone_integration_state`

Singleton-Zustand mit:

- persistentem Adapter-Schalter, standardmäßig `0`;
- monotoner `adapter_generation`;
- letztem Verbindungstest und letztem erfolgreichen Verbindungstest;
- redigiertem Verbindungsergebnis;
- letzter Synchronisierung und Ergebnis;
- letztem erlaubten Fehlercode;
- ausgewählter opaque Programmreferenz und expliziter Quelle;
- monotoner Revision für konfliktgeprüfte Updates.

Identifier oder Tokenwerte gehören nicht in diese Tabelle. Ein direkter
positiver `setAdapterEnabled`-Pfad ist verboten. Aktivierung erfolgt nur über
den signierten Action-Gate-/Control-Plane-Übergang. Deaktivierung setzt den
Schalter auf `0` und erhöht Adaptergeneration und Revision.

### `hackerone_api_programs`

Normalisierte API-authentifizierte Programmdatensätze:

- HackerOne-ID, Handle, Name und Currency;
- Policytext, Submission State und Program State;
- Offers Bounties, Open Scope, Gold Standard Safe Harbor und Bookmark;
- persönliche Reportanzahl und persönliche gültige Reportanzahl;
- optionale Start-/Create-/Update-Zeitstempel;
- lokale Synchronisierungszeit;
- aktiver Katalogstatus;
- `catalog_drift_pending` als sofortige Sperre zwischen erkanntem
  katalogseitigem Policywechsel und exaktem Detailsnapshot;
- Record-Digest und Pointer auf den aktuellen Snapshot.

Katalogtausch und erfolgreicher Synchronisierungsstatus sind atomar. Die
vollständig validierte neue Menge wird upserted; fehlende Programme bleiben
historisch vorhanden, aber inaktiv. Weicht katalogseitiges Policy-Material
vom aktuellen Detailsnapshot ab oder verschwindet das Programm, wird
`catalog_drift_pending = 1` gesetzt. In derselben Transaktion werden
ausdrücklich gebundene aktive Kampagnen pausiert und ein bodyfreies
Katalog-Drift-Audit geschrieben. Jeder Fehler rollt alle diese Wirkungen
zurück. Der Marker bleibt über weitere Katalogsyncs sticky und wird nur vom
Commit eines exakten Detailsnapshots zurückgesetzt. Manuelle Datensätze werden
nicht berührt.

### `hackerone_manual_programs`

Enthält dieselben normalisierten Spalten ausschließlich für
`manual_unverified`. Die Tabelle ist separat; API- und manuelle Identitäten
werden nicht zusammengeführt. Programmzeile und initialer append-only
Snapshot werden in einer gemeinsamen Transaktion importiert. Pilot A besitzt
keinen In-place-Updateflow. Eine ID-/Handle-Kollision bei erneutem Import
blockiert und hinterlässt keinen partiellen Datensatz.

### `hackerone_policy_snapshots`

Jede Zeile enthält:

- Snapshot-Digest als Primärschlüssel;
- opaque Programmreferenz und Quelle;
- Policy-Digest;
- optionalen Vorgänger-Snapshot-Digest;
- Abruf-/Importzeit;
- kanonisches Snapshot-JSON, höchstens 4 MiB;
- physisches `acceptance_pending = 1`.

Das kanonische JSON enthält Programmdaten, vollständigen Policytext, sortierte
Structured Scopes, Scope Exclusions, Suitability, Adapter-/Schema-Version,
Quelle, Abrufzeit und Digestkette. Asset-Identifier werden als Metadaten im
Klartext gespeichert; ihr zusätzlicher Digest ersetzt den Wert nicht.

Trigger verbieten jedes Update und Delete. Neue Snapshots müssen mit
`acceptance_pending = 1` entstehen. Der sichtbare logische Annahmestatus wird
nicht durch Mutation dieser Zeile erzeugt, sondern aus einer passenden
append-only `hackerone_policy_acceptances`-Zeile abgeleitet. Dadurch bleibt
die ursprüngliche Snapshotzeile vollständig unveränderlich.

### `hackerone_request_audit`

Append-only und bodyfrei:

- lokale Sequenz;
- zufällige 32-stellige Hex-Request-ID;
- feste Aktionsklasse `HACKERONE_METADATA_READ`;
- eine der vier Endpoint-Klassen;
- redigierter Outcome-Code;
- HTTP-Status oder `null`;
- Dauer in Millisekunden.

Nicht enthalten sind URL, Handle, Query, Header, Body, Credential,
Asset-Identifier oder Policytext. Trigger verbieten Update und Delete.

### `hackerone_campaign_bindings`

Append-only-Verknüpfung aus exakter opaque HackerOne-Programmreferenz,
bestehender lokaler Kampagnen-ID und Bindungszeit. Der Insert prüft, dass das
Programm in genau einer H1-Quelltabelle existiert. Update und Delete sind
gesperrt.

Bei späterem Policy Drift werden nur ausdrücklich gebundene Kampagnen in
`approved` oder `running_simulation` pausiert. Ihre bisherige menschliche
Freigabe wird entfernt und `kill_switch_status` auf `engaged` gesetzt.

## External-Action- und Approval-Evidence

### `hackerone_metadata_action_schema`

Marker für Komponentenname `metadata_action_gate`, Schema-Version 1 und den
Digest der vollständigen Action-Gate-DDL.

### `hackerone_metadata_activation_bindings`

Unveränderliche Bindung einer lokalen Approval an:

- Approval-Payload-Hash und Operator;
- vollständigen 64-stelligen SHA-256-Token-Binding-Digest; das zwölfstellige
  Präfix ist ausschließlich UI-/Statusprojektion;
- Runtime-Digest;
- Adaptergeneration vor Aktivierung;
- Erstell- und Ablaufzeit;
- kanonischen Binding-Digest;
- Decision-Audit-ID und bei Annahme die aktivierte Generation.

Insert- und Transition-Trigger verlangen eine passende offene
`privacy_alert`-Approval und anschließend die vollständige signierte
Decision-/Statement-/Audit-Evidence. Bei Annahme muss die aktivierte
Generation exakt der Vorgängergeneration plus eins entsprechen. Eine
abgelehnte Approval erhält Evidence, aktiviert aber nichts. Wird eine
Annahme bei oder nach Ablauf ihrer fünfminütigen Entscheidungsfrist
beobachtet, rollt die gesamte Decision-Transaktion zurück.

### `hackerone_policy_acceptance_bindings`

Unveränderliche Bindung einer Approval vom Typ
`program_policy_acceptance` an:

- Approval-Payload-Hash und Operator;
- opaque Programmreferenz und Quelle;
- aktuellen Snapshot- und Policy-Digest;
- Vorgänger-Snapshot-Digest;
- Erstellzeit und Binding-Digest;
- Decision-Audit-ID.

Vor dem Insert wird geprüft, dass der Snapshot aktuell für exakt dieses
Programm ist und noch keine Acceptance-Evidence besitzt. Bei API-Daten muss
das Programm zusätzlich katalogaktiv und frei von
`catalog_drift_pending` sein. Dieselbe Prüfung läuft erneut bei Decision und
Evidence-Insert. Trigger binden die spätere Entscheidung an signiertes
Statement, Approvalrevision und Audit.

### `hackerone_policy_acceptances`

Append-only Evidence einer akzeptierten aktuellen Snapshotversion:

- Snapshot-Digest als Primärschlüssel;
- opaque Programmreferenz;
- eindeutige Approval-ID;
- Operator und Annahmezeit;
- eindeutige Decision-Audit-ID;
- eindeutiger Digest des signierten Statements.

Insert-Trigger prüfen die vollständige Binding-/Approval-/Decision-/Statement-
Kette. Update und Delete sind verboten. Eine Ablehnung erzeugt keine Zeile.

### `hackerone_metadata_action_attempts`

Persistente Reservation und Settlement-Evidence pro tatsächlichem GET:

- Authorization-, Operation- und eindeutige Proposal-ID;
- Proposal- und Plan-Digest;
- feste Action-ID/-Klasse;
- Endpoint-Klasse sowie feste Methode, Scheme, Host und Port;
- kanonischer Request-Target;
- Aktivierungs-Approval und Binding-Digest;
- vollständiger 64-stelliger Credential-Binding-Digest;
- Attempt-Index und eine Budgeteinheit;
- Status, Zeitstempel, Revision;
- Reservation- und Settlement-Audit-ID.

Erlaubte Zustände sind:

```text
reserved@0 → running@1 → succeeded|failed|aborted@2
reserved@0 → aborted@1
```

Identitäts-, Proposal-, Plan-, Target-, Aktivierungs-, Credential-, Budget-
und Reservationfelder sind unveränderlich. Zeilen können nicht gelöscht
werden. Abbruch und Fehler erstatten keine Einheit. Eine nach Prozesscrash
verbliebene `reserved`-/`running`-Zeile bleibt als aktive Reservation
blockierend. Per-Operation-Zähler, gleitendes Minutenfenster und aktive
Reservationen werden aus allen persistenten Attempts abgeleitet und nicht
durch Adapterreaktivierung zurückgesetzt.

Die bestehenden Control-Plane-Tabellen `approvals`,
`signed_approval_decisions`, `operator_signed_statements` und
`control_plane_audit` halten die referenzierte Phase-4-/Phase-6-Evidence.
Signaturprüfung, Replay-Schutz, Approval-Transition, Audit und H1-Bindung
laufen in derselben `BEGIN IMMEDIATE`-Transaktion.

Der signierte Runtime-Digest bindet alle drei Requestbudgetwerte sowie
Transportversion, Capture-Modus, Redirectverbot, Responsegrenze, Deadline und
festes Ziel. Eine Runtime-Budgetänderung invalidiert deshalb vorhandene
Aktivierungsevidence, statt still mit anderen Grenzen weiterzulaufen.

## Snapshot-Digests und Drift

Der Policy-Digest bindet:

- Policytext;
- Program State und Submission State;
- Offers Bounties und Open Scope;
- Gold Standard Safe Harbor;
- vollständig sortierte Structured Scopes;
- vollständig sortierte Scope Exclusions.

Der Snapshot-Digest bindet darüber hinaus den vollständigen normalisierten
Programmdatensatz, Abrufzeit, Adapter-/Schema-Version, Quelle und
Vorgänger-Digest. Deshalb kann sich ein Snapshot auch ändern, wenn der
Policy-Digest stabil bleibt.

Drift-Codes:

- `POLICY_TEXT_CHANGED`
- `PROGRAM_STATE_CHANGED`
- `OPEN_SCOPE_CHANGED`
- `SAFE_HARBOR_CHANGED`
- `SUBMISSION_ELIGIBILITY_CHANGED`
- `BOUNTY_ELIGIBILITY_CHANGED`
- `INSTRUCTIONS_CHANGED`
- `MAXIMUM_SEVERITY_CHANGED`
- `SCOPES_CHANGED`
- `SCOPE_EXCLUSIONS_CHANGED`

Neuer Snapshot, aktueller Pointer, Kampagnenpause und bodyfreie
`hackerone_policy_drift`-Auditzeile werden atomar geschrieben. Beim
authentifizierten Detailsync gehören zusätzlich Programmauswahl,
Synchronisierungsstatus und das Zurücksetzen von `catalog_drift_pending` zu
derselben Transaktion. Ein Fehler rollt alle diese lokalen Wirkungen zurück.

## Suitability

Die lokale Heuristik speichert einen Score von 0 bis 100 und deterministische
Reason Codes. Sie berücksichtigt Submission State, Bounties,
Policyvorhandensein, Structured Scopes, Web-/API-Assettypen,
Scope-Ausschlüsse und Safe Harbor.

Feste Grenzen:

- `accountWorkflows = manual_review_required`
- `legalDecisionMade = false`
- Automationsstatus nur `allowed`, `forbidden` oder
  `unknown_requires_human_review`

Ohne ausdrücklich erkannte Erlaubnis bleibt Automation unklar. Der Score ist
keine rechtliche, Policy- oder operative Freigabe.

## Begrenzte Dashboard-Projektion

`/api/state` liefert für die H1-Sektion:

- höchstens 1.000 Programmsummaries ohne Policytext, aber mit Score,
  Reason Codes, Katalog-/Driftstatus, Bounty-, Open-Scope-, Safe-Harbor-,
  Bookmark- und persönlichen Reportfeldern;
- höchstens die letzten 20 Versionssummaries ohne Snapshotbody;
- höchstens 100 Kampagnensummaries ohne Contract, Assets oder Accounts;
- Gesamt- und Truncation-Zähler;
- den aktuell ausgewählten Review-Snapshot;
- den unmittelbar vorherigen vollständigen Policytext für die Review.

Die Projektion ist eine Darstellungsgrenze, keine Autorisierungsquelle. Der
Store bleibt maßgeblich. Bei mehr als 1.000 Programmen oder 20 Versionen
liefert die Projektion Gesamtzahl und Truncation-Indikator; die UI zeigt die
Begrenzung sichtbar an.

## Nie persistierte Daten

- vollständiger API-Identifier und API-Token außerhalb der beiden
  Keychain-Einträge
- Basic-Authorization-Header oder Base64-Kombination
- rohe API-Responses und Response-Bodys
- unbekannte JSON-Felder
- Cookies, Browser-Sessions oder Storage State
- HARs, Screenshots, Traces oder Videos
- Zielrequest-, DNS-, Ping-, Crawl- oder Scan-Ergebnisse
- Report-Submissions, Attachments, Triage- oder Zahlungsdaten

## Retention

Pilot Readiness A besitzt keinen UI-Purge- oder Retentionworkflow für
Programme, Snapshots, Action-Attempts, Approval-Evidence und Auditzeilen. Das
Löschen der Keychain-Credentials entfernt diese Metadaten nicht. Eine spätere
Löschfunktion muss als separate, signierte lokale Offline-Adminoperation mit
Referenz-, Snapshot- und Auditkonsistenz entworfen werden. Direkte
SQL-Manipulation ist kein unterstützter Betriebsweg.
