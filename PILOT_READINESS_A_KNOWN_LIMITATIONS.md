# Pilot Readiness A – bekannte Einschränkungen

## Freigabegrenze

Pilot Readiness A ist ausschließlich eine lesende Plattformmetadaten-
Integration. Sie ist kein GO für Bug-Bounty-Zielzugriffe, aktive Tests,
Account-Automation, HackerOne-Browserzugriffe oder Reports. Ein importierter
Scope bleibt Datenbestand und erzeugt niemals Egress-Autorisierung.

## Bekannte Einschränkungen

### Kein automatisierter Live-Nachweis

Automatisierte Tests verwenden nur In-Process-Fakes, synthetische
Credentials und lokale Loopback-Mockserver. Sie prüfen weder Erreichbarkeit
noch aktuelles Produktionsschema von `api.hackerone.com`.

Der TTY-gebundene Ein-Request-Smoke ist bewusst getrennt und wurde während
Entwicklung und automatisierten Tests nicht ausgeführt. Transport- und
Vertragsgrenzen werden ohne realen Host durch statische Tests, gebrandete
Pläne, In-Process-Transporte und Loopback-Harnesses geprüft. Ein echter
TLS-/API-Vertragsnachweis bleibt ausschließlich einem später vom Benutzer
selbst gestarteten Smoke vorbehalten.

### Striktes API-Schema kann bei legitimen Änderungen blockieren

Unbekannte Felder und abweichende Responseformen werden fail-closed
abgewiesen. Das schützt vor stiller Semantikänderung, kann aber nach einer
legitimen HackerOne-Schemaerweiterung eine Adapteraktualisierung erfordern.
Es gibt kein tolerant-decoding oder Browser-Scraping als Fallback.

### Striktes lokales DDL-Schema besitzt noch keinen Migrationspfad

Metadaten-Store und Action Gate prüfen die tatsächlichen Tabellen, Indizes
und Trigger exakt. Das erkennt Manipulation zuverlässig, bedeutet aber auch,
dass eine zukünftige legitime Schemaänderung eine explizite, getestete
Migration braucht. Pilot A adoptiert oder repariert keinen partiellen oder
abweichenden Namespace automatisch.

### macOS-gebundener Credentialpfad

Der produktive Vault verwendet `/usr/bin/security` und den
macOS-Schlüsselbund. Andere Plattformen bleiben deaktiviert. Die lokale
Dashboardroute kann das Paar einmalig als fest begrenztes Binärframe
speichern; alternativ benötigen die CLI-Unterbefehle `store`, `status` und
`remove` ein interaktives Terminal. Es gibt keinen Produktionsfallback auf
Datei, Environment, SQLite oder In-Memory-Secrets.

Die Keychain-Einträge enthalten kanonische, printable Base64url-Hüllen mit
Rolle und gemeinsamer Generation. Manuelles Anlegen roher Passwortwerte über
die Schlüsselbundverwaltung ist nicht kompatibel.

### Best-effort Nullsetzen innerhalb einer Garbage-Collected Runtime

Bytebuffer für Dashboardframe, TTY, Keychain, Credentials, Basic-Auth-
Zusammensetzung, Response-Chunks und rohe Bodys werden explizit genullt.
JavaScript-Strings wie die kurzlebigen Password-Input-Werte, der
Authorization-Headerwert oder der dekodierte JSON-Text können jedoch von der
Runtime kopiert worden sein und lassen sich nicht garantiert aus dem Heap
löschen. Sie werden weder in Browser-Storage noch in Produktpersistenz,
Audit oder Fehlerantwort übernommen. Ein kompromittierter lokaler Prozess,
Browserprozess oder Speicherdump bleibt außerhalb des Schutzmodells.

### Lokale Metadaten sind nicht zusätzlich event-verschlüsselt

Programme, Policytexte, Asset-Identifier, Scopes und Ausschlüsse liegen in
der privaten Control-Plane-SQLite-Datei. Datei-/Verzeichnisrechte und
SQLite-Härtung schützen den lokalen Pfad; die Werte sind aber keine
AES-GCM-Event-Hüllen. Private Programmmetadaten erfordern einen geschützten
Einzelbenutzer-Arbeitsplatz und geeigneten Datenträgerschutz.

### Keine Retention-, Export- oder Purge-Oberfläche

Credential-Löschung entfernt keine Programme, Snapshots, Action-Attempts,
Acceptance-Evidence oder Auditereignisse. Append-only Daten besitzen noch
keinen signierten Offline-Export- oder Retentionworkflow. Direkte
SQL-Manipulation ist nicht unterstützt.

### Crash-Reservationen bleiben blockierend

Proposal, Attempt, Budgeteinheit und Reservation sind persistent. Ein
Prozesscrash nach Reservation oder Runnerstart kann eine Zeile in `reserved`
oder `running` hinterlassen. Sie bleibt absichtlich aktiv und wird nicht
erstattet; Pilot A besitzt keine signierte In-place-Recovery-Oberfläche.

Der konservative Betriebsweg ist Adapter deaktiviert lassen, Ursache und
Attempt-Evidence offline prüfen und keine neue External Action starten. Eine
Reaktivierung räumt die aktive Reservation ausdrücklich nicht ab. Pilot A
bietet daher keinen unterstützten Resume-/Recovery-Pfad; direkte SQL-
Manipulation ist verboten. Eine spätere Recovery müsste offline,
prozessabwesenheitsgeprüft, signiert und ohne Budgeterstattung entworfen
werden.

### Kein absolutes Gesamtbudget über alle Operationen

`max_requests_total` begrenzt Attempts je Top-Level-Operation. Das
Minutenbudget, das Per-Operation-Budget und aktive Crash-Reservationen bleiben
über Deaktivierung und Reaktivierung hinweg persistent. Pilot A besitzt aber
kein zusätzliches absolutes Lifetime-Limit über alle unterschiedlichen
Operationen. Der Dashboardstandard beträgt 100 Attempts je Operation, 60 pro
Minute und Parallelität 1. Jeder Retry verbraucht eine eigene Einheit. Die
Budgetwerte selbst sind Teil des signierten Runtime-Digests; eine Änderung
invalidiert alte Aktivierungsevidence.

### Einzelprozess-/Einzelbenutzerannahme im Dashboard

Service-Orchestrierung serialisiert Operationen innerhalb eines Prozesses;
die SQLite-Reservationen sichern die relevante Budget-/Parallelitätsgrenze
prozessübergreifend ab. Dashboard und Bedienmodell sind trotzdem nicht als
Multi-User-, Remote- oder verteiltes System qualifiziert. Der lokale
Dashboardtransport ist Loopback-HTTP mit Host-/Origin-/CSRF-Schutz, nicht
TLS.

Dashboard-`disable`, Dashboard-`store` und Dashboard-`remove` abortieren die
laufende In-Process-Operation noch vor dem ersten Storezugriff, persistieren
danach die Deaktivierung und warten auf Quieszenz, bevor eine Credential-
Mutation beginnt. Der alternative TTY-
Credential-Admin läuft jedoch als separater Prozess. Er kann Adapterzustand
und Keychain ändern, aber keinen bereits laufenden HTTPS-Request im
Dashboardprozess per `AbortSignal` unterbrechen. Deshalb bleibt ein beendetes
Dashboard die konservative Betriebsbedingung für TTY-`store` und
TTY-`remove`. Diese Prozessabwesenheit wird in Pilot A noch nicht technisch
mit einer eigenen Admin-Lease nachgewiesen.

### Der Dashboardklick ist kein Hardware-Präsenznachweis

Aktivierung und Policy-Annahme sind Ed25519-signiert und an Session, Nonce,
Frische, Payload sowie Control Plane gebunden. Der lokale Klick ist dennoch
kein Hardwareattest oder rechtlicher Anwesenheitsnachweis. Das initiale
Operator-Enrollment bleibt lokales TOFU gemäß Phase 4.

Für die Adapteraktivierung wird der bestehende Approval-Typ `privacy_alert`
mit einer zusätzlichen exakten H1-Bindung verwendet. Ein eigener semantischer
Approval-Typ wäre eine mögliche spätere Modellverbesserung; die aktuelle
Trigger-/Payloadbindung verhindert strukturelle Wiederverwendung.

### System-Trust statt Certificate Pinning

TLS-Zertifikate werden über die Node-/OS-Vertrauenskette geprüft. Es gibt
kein separates Zertifikat- oder Public-Key-Pinning. Redirects bleiben
unabhängig davon deaktiviert.

### Begrenzte Pagination und Datenmengen

- maximal 20 Seiten je paginierter Operation;
- maximal 1.000 Programme;
- maximal 2.000 Structured Scopes;
- maximal 2.000 Scope Exclusions;
- maximal 1 MiB je HTTP-Response;
- maximal 1 MiB je manuelle Importquelle;
- maximal 4 MiB je kanonischem Snapshot-JSON.

Größere Ergebnisse werden blockiert und nicht teilweise übernommen.

### Begrenzte Dashboard-Projektion

Die H1-Projektion zeigt höchstens 1.000 Programmsummaries, die letzten 20
Versionssummaries und 100 Kampagnensummaries. Gesamt- und
Truncation-Indikatoren sind vorhanden und die aktuelle Auswahl bleibt
sichtbar. Programmsummaries enthalten Score, Reason Codes und persönliche
Reportfelder, aber keinen Policytext. Es gibt noch keine Pagination für
ältere oder darüberliegende Einträge.

Der aktuelle Review-Snapshot kann bis zu den Storegrenzen reichen. Für den
ausgehenden `/api/state`-Body existiert kein separates kleineres
Response-Limit; seine Größe wird indirekt durch Snapshot-, Scope- und
Policygrenzen beschränkt.

### Katalogseitenzahl ist abgeleitet

Das Serviceergebnis berechnet `pages` aus der Anzahl gespeicherter Programme
und der festen Seitengröße 100. Es ist kein persistierter Zähler der
tatsächlich empfangenen API-Seiten.

### Kategorischer statt zeilenweiser Diff

Das Dashboard zeigt deterministische Änderungskategorien sowie vollständigen
aktuellen und unmittelbar vorherigen Policytext. Es erzeugt keinen
zeilenweisen Rich-Text-Diff. Ältere Versionen erscheinen nur als begrenzte
Digest-/Zeit-/Quellsummaries.

### Kampagnenbindung ist append-only

Das Dashboard kann das aktuell ausgewählte H1-Programm an eine exakte lokale
Kampagnen-ID binden. Nur solche Bindungen führen bei späterem Drift zur
atomaren Pause. Die Bindung ist append-only; Pilot A bietet kein Unbind oder
Delete.

Snapshot-Commit, Kampagnenpause und Drift-Audit sind atomar. Der externe
Metadatenrequest ist zu diesem Zeitpunkt jedoch bereits erfolgt; schlägt die
lokale Commit-Transaktion fehl, bleibt der alte Snapshot bestehen und die
Operation wird als fehlgeschlagen markiert.

### Manueller Import ist kein Updateflow

Ein manueller Datensatz kann nicht in-place aktualisiert oder mit API-Daten
zusammengeführt werden. Kollisionen blockieren. Der Detailsync-Button kann
bei einem manuellen Datensatz sichtbar bleiben; der Backend-Store weist den
Request anhand des `h1m_`-Präfixes fail-closed zurück.

### `weaknesses` ist deaktiviert

Request-Planer, Action Gate, Transport und Client registrieren keinen
Weaknesses-Abruf. Die Funktion ist weder über Dashboard noch CLI erreichbar.

### Suitability bleibt Heuristik

Der Score erkennt nur eine kleine deterministische Menge englischer
Policyformulierungen. Das Fehlen eines Verbots bedeutet nie „erlaubt“.
Unklare Texte bleiben `unknown_requires_human_review`. Der Score ersetzt
keine juristische oder programmverantwortliche Prüfung.

### Keine Ziel- oder Submission-Funktion

Nicht vorhanden sind unter anderem:

- DNS-/HTTP-/Browserzugriffe auf Scope-Assets;
- Scanner und aktive Testklassen;
- Account-Erstellung oder Login-Automation;
- Report-, Attachment- oder Triage-Übertragung;
- Bounty-/Payment-Funktionen;
- LLM-gesteuerte Requests;
- HackerOne-Web-Scraping.

Diese Punkte sind nicht nur UI-versteckt, sondern außerhalb der Registry und
der gebrandeten Requestoperationen.

## Betriebsregel

Bei jeder Unklarheit Integration deaktivieren, Kill Switch engagieren und nur
bereits gespeicherte lokale Snapshots prüfen. Es gibt keinen allgemeinen
Browser-, JSON-Secret- oder ungeschützten HTTP-Fallback; die einzige
Credentialroute ist das feste lokale Binärprotokoll. Der manuelle Live-Smoke
darf ausschließlich vom Benutzer selbst und nie durch Tests, Build, CI oder
Codex gestartet werden.
