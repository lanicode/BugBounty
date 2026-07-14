# Phase 3: Store-gebundener External-Action-Evaluator

## Umfang und Sicherheitsziel

Phase 3 ersetzt die caller-gelieferten positiven Gate-Entscheidungen aus Phase
2 durch einen Evaluator, der eine Freigabe ausschließlich aus aktueller,
persistierter Control-Plane-Evidence ableitet. Der Schritt bleibt vollständig
lokal: Es gibt keinen realen Plattformadapter, keinen externen Runner, keine
aktive Sicherheitsprüfung, keine Kontoerstellung, keine Report-Einreichung und
keinen LLM-gesteuerten Request.

Der einzige ausführbare Runner ist `DeterministicMockActionRunner`. Er liefert
vorab konfigurierte In-Process-Antworten und führt selbst keinen HTTP-, Browser-,
DNS- oder Socket-Zugriff aus. Das Registry-Ziel ausführbarer
Simulationsaktionen ist unveränderlich als `http://127.0.0.1` modelliert;
`report_submit` und `triage_response_send` besitzen überhaupt kein
Simulationsziel.

## Erzwungene Entscheidungskette

```text
Proposal v2
-> exakte Schema- und Objektvalidierung
-> geschlossene Registry
-> Simulation-only und Loopback-Zielklasse
-> aktueller Policy-/Kampagnen-Snapshot
-> Scope-/Account-/Ownership-Evidence
-> proposal- und operatorgebundene Human Approval
-> Replay-, Gesamt-, Kampagnen-, Rate- und Concurrency-Budget
-> atomare Reservation plus Audit-Evidence
-> erneute Evidence-Prüfung vor Runner-Start
-> gebrandeter deterministischer Mock-Runner
-> Kill-Switch-Prüfung während und nach dem Runner
-> erneute Evidence-Prüfung vor erfolgreichem Settlement
```

Fehlt eine Stufe, ist sie inkonsistent oder kann sie nicht gelesen werden,
blockiert der Ablauf. Ohne expliziten `StoreBoundExternalActionEvaluator` nutzt
die Pipeline einen gebrandeten Deny-All-Evaluator und antwortet mit
`ACTION_STORE_EVIDENCE_REQUIRED`.

## Proposal v2

`ExternalActionProposalV2` bindet folgende Werte:

- `version: 2`, `proposal_id`, `action_id` und `mode`;
- Programm- und Kampagnenreferenz;
- Kampagnenrevision und vollständigen Kampagnendigest;
- Policy-Version und Policy-SHA-256;
- deterministische `scope_ref`;
- Accountreferenz und Accountrolle oder konsistent `null`;
- Objektreferenz oder `null`;
- `payload_ref`, die in Phase 3 zwingend `null` bleibt;
- Approval- und Operatorreferenz.

Das JSON-Schema ist geschlossen (`additionalProperties: false`) und begrenzt
Formate, Längen, Revisionen und SHA-256-Werte. Die Laufzeitvalidierung akzeptiert
nur gewöhnliche, nicht geproxte Objekte mit exakt den erwarteten eigenen,
enumerierbaren Datenfeldern. Accessors, Symbole, Zusatzfelder, Proxies und
abweichende Prototypen werden vor einer fachlichen Auswertung abgelehnt. Der
Validator kopiert die Daten in ein neues, verschachtelt eingefrorenes Objekt.

`action_id` wird nach der Schema-Prüfung zusätzlich gegen die geschlossene
Registry geprüft. Das Schema kennt zwar `mode: "external"` und eine optionale
nichtleere Payload-Referenz als Datenform; die Pipeline blockiert externen Modus
immer mit `EXTERNAL_INTEGRATIONS_DISABLED` und jede nicht-null Payload mit
`ACTION_PAYLOAD_REFERENCE_BLOCKED`.

Der Proposal-Digest ist SHA-256 über die kanonische JSON-Darstellung des
vollständig validierten Proposal-v2-Objekts. Jede fachliche Mutation erzeugt
damit einen anderen Digest oder scheitert bereits an der Validierung.

## Ableitung der aktuellen Evidence

`prepareStoreBoundExternalActionProposal` akzeptiert nur einen gebrandeten
`ControlPlaneStore` und eine simulationsfähige Registry-Aktion. Der Store liest
den Kontext in einer synchronen SQLite-Transaktion. Eine positive Evidence
erfordert gleichzeitig:

- einen aktiven, verfügbaren `local_mock`-Simulationsdatensatz mit erlaubter
  Automation und bereits angenommener Regelversion;
- eine Kampagne im Zustand `running_simulation`, lokalen und globalen Kill
  Switch auf `clear`, gültiges Zeitfenster und eine zeitlich gültige
  menschliche Kampagnenfreigabe;
- exakte Übereinstimmung zwischen aktuellem Programm, Kampagnen-Policy-Stand
  und akzeptierter Policy-Version;
- keine unklaren Regeln, `offline_simulation` ausdrücklich erlaubt und nicht
  verboten;
- ausschließlich Programm-Assets, die erlaubt und nicht ausgeschlossen sind;
- die zur Registry-Aktion passende Account-/Objekt-Evidence.

Für `ownershipCheck: "not_applicable"` müssen Account und Objekt fehlen. Für
`"account"` muss eine zur Kampagne gehörende, verifizierte, bereite Identität
ohne offenen Human-Schritt und mit Organisationsreferenz vorliegen. Für
`"object"` gelten dieselben Identitätsregeln; zusätzlich muss das Objekt aktiv,
researcher-controlled, unverfallen und exakt an Programm, Kampagne, Account,
Policy und die erlaubte Aktion `offline_inspect` gebunden sein.

Der Kampagnendigest bindet ID, Programm, Revision, Zustand, den Digest des
vollständigen genehmigten Kampagnenvertrags, Freigabeoperator und -zeit,
letzten Policy-Check, Kampagnen-Kill-Status und Erstellzeit. Identität und
Owned-Object erhalten jeweils eigene kanonische Digests. `scope_ref` ist kein
caller-interpretierter Text, sondern `scope-` plus SHA-256 über Registry-Aktion,
Zielklasse, Programm, Kampagne, Revision, Kampagnendigest, Policy, erlaubte und
ausgeschlossene Assets, Methoden, Risikoklassen, Aktionsklassen sowie die
relevante Account-, Organisations- und Ownership-Evidence.

## Persistierte, operatorgebundene Approval

Eine External-Action-Approval wird in einer Transaktion als `external_action`
mit Status `open` und Revision `0` angelegt. Gleichzeitig entsteht genau eine
fachlich immutable Binding-Zeile für Proposal-ID und -Digest, Aktion, Programm,
Kampagne, Policy, Scope, Account, Objekt, Payload, Operator und Gültigkeitszeit.
Nur `decision_audit_id` darf später genau einmal von `null` auf die exakt
validierte Accepted-Decision-Audit-ID wechseln. Der Convenience-Pfad setzt fünf
Minuten Gültigkeit; der Store akzeptiert grundsätzlich höchstens 15 Minuten.

Die spätere Entscheidung läuft in einer eigenen `BEGIN IMMEDIATE`-Transaktion.
Eine akzeptierte Approval ist nur verwendbar, wenn:

- Status `accepted` und Revision `1` vorliegen;
- `decided_by` exakt dem gebundenen `operator_ref` entspricht;
- `user_action` exakt `approve_store_bound_external_action` lautet;
- Policy-Version und -Hash unverändert sind;
- Erzeugung, Entscheidung und Ausführung innerhalb des Bindungszeitfensters
  liegen;
- der verknüpfte bodyfreie Auditdatensatz exakt Entscheidung, Zeitpunkt,
  Approval-ID und Payload-Hash bindet;
- derselbe Operatorstring auch die aktuelle Policy-Annahme und
  Kampagnenfreigabe bezeichnet.

Das Operatorlabel wird damit konsistent gebunden, ist in Phase 3 aber noch
weder lokal authentifiziert noch kryptografisch signiert. Diese Grenze ist in
`PHASE3_KNOWN_RISKS.md` festgehalten und ist ein zusätzlicher Grund, reale
Runner deaktiviert zu lassen.

## Atomare Autorisierung und Reservation

`authorizeAndReserve` führt die erneute Kontextableitung, Proposal-/Approval-
Prüfung, alle Budgetprüfungen sowie Audit- und Attempt-Insert in genau einer
`BEGIN IMMEDIATE`-Transaktion aus. Die Reservation wird nur sichtbar, wenn alle
Prüfungen und beide Inserts erfolgreich committen. Die Datenbankabstraktion
lehnt ein Promise oder beliebiges Thenable als Transaktionsergebnis ab und
rollt mit `CONTROL_PLANE_TRANSACTION_ASYNC` zurück; dadurch kann kein
asynchroner Callback die atomare Grenze unbemerkt verlassen.

Die Reservation bindet die vollständige Approval-Evidence erneut in
`external_action_attempts`. `evidence_digest` umfasst den immutable
Binding-Digest, den Approval-Payload-Hash, Approval-Revision `1` und die
Decision-Audit-ID. Eine zugehörige bodyfreie Auditzeile bindet
Authorization-ID, Reservierungszeit und Evidence-Digest.

SQLite-Migration v4 verwendet `STRICT`-Tabellen, exakte Foreign Keys,
Eindeutigkeitsregeln und Trigger. Proposal-ID, Proposal-Digest, Approval,
Evidence-Digest und Auditreferenzen sind single-use. Binding-Felder können
nicht aktualisiert und Bindings oder Attempts nicht gelöscht werden.
`control_plane_audit` ist ab Migration v4 gegen Update und Delete geschützt;
neue Auditzeilen bleiben als vorgesehener Append-Pfad möglich.

Beim Upgrade engagiert Migration v4 den globalen Kill Switch und pausiert
aktive beziehungsweise genehmigte Kampagnen. Ein Altzustand wird daher nicht
stillschweigend unter den neuen Regeln weiter ausgeführt.

## Persistente Budgets, Concurrency, Rate und Zeit

Alle Prüfungen lesen und reservieren innerhalb derselben
`BEGIN IMMEDIATE`-Transaktion:

- Replay: Eine bereits bekannte Proposal-ID **oder** ein bereits bekannter
  Proposal-Digest blockiert dauerhaft.
- Globales Gesamtbudget: Die Zahl aller persistierten Attempts wird gegen
  `runtime.config.budgets.max_actions_total` geprüft. Der Laufzeitwert muss eine
  sichere Ganzzahl zwischen 1 und 1.000 sein.
- Kampagnenbudget: Alle Attempts der Kampagne zählen gegen
  `campaign.contract.maxRequests`.
- Globale Concurrency: `reserved` und `running` zählen gegen das Laufzeitlimit,
  das in Phase 3 exakt `1` sein muss.
- Kampagnen-Concurrency: `reserved` und `running` zählen gegen
  `campaign.contract.maxConcurrency`, ebenfalls exakt `1`.
- Rolling Rate: Alle Kampagnen-Reservations mit `reserved_at >= now - 60s`
  zählen gegen `requestsPerMinute`. Der Grenzzeitpunkt ist inklusive.
- Clock Rollback: Liegt die neu angeforderte Zeit vor dem global höchsten
  persistierten `reserved_at`, blockiert `ACTION_CLOCK_ROLLBACK`. Start und
  Settlement dürfen außerdem nicht vor ihrer jeweiligen vorherigen
  Attempt-Zeit liegen.

Abgebrochene, fehlgeschlagene und erfolgreiche Attempts bleiben Teil von
Replay-, Gesamt-, Kampagnen- und Rate-Budget. Ein sauber behandelter Abbruch
vor dem Runner gibt lediglich den aktiven Concurrency-Slot frei; es gibt keine
Budgeterstattung.

## Attempt-Zustandsmaschine und Revalidierung

Die persistierte Zustandsmaschine erlaubt nur:

```text
reserved (Revision 0)
  -> running (Revision 1)
    -> succeeded | failed | aborted (Revision 2)

reserved (Revision 0)
  -> aborted (Revision 1, Runner nie gestartet)
```

Vor `reserved -> running` werden Attempt, Reservation-Audit, Proposal,
Approval und aktuelle Store-Evidence erneut geprüft. Drift an Policy,
Kampagne, Scope, Identität, Objekt oder Approval blockiert den Runner. Fängt die
Pipeline einen Fehler nach erfolgreicher Reservation, aber vor einem
erfolgreichen Start im selben Prozess ab, schreibt sie `aborted` Revision `1`
und ein Settlement-Audit mit
`STORE_BOUND_ACTION_ABORTED_BEFORE_START`.

Nach einem gestarteten Runner wird ein Runnerfehler als `failed`, ein
Kill-Switch-Abbruch als `aborted` persistiert. Vor einem erfolgreichen
Settlement prüft der Store die komplette Evidence noch einmal. Drift wandelt
den Abschluss in `aborted` um, persistiert den konkreten Reason Code und gibt
den Fehler an den Caller zurück.

Ein Prozessabbruch nach Commit der Reservation, aber bevor der normale
Catch-Pfad ausgeführt wird, hinterlässt dagegen absichtlich `reserved`.
Entsprechend bleibt ein Crash nach dem Start als `running` sichtbar. Beide
Zustände blockieren Replay und Concurrency fail-closed. Eine Recovery- oder
Lease-Logik ist noch nicht implementiert.

## Globaler Kill Switch

Die Pipeline prüft den gebrandeten Kill Switch vor der Proposal-Auswertung,
vor der Reservation, nach der Reservation, nach dem Start, im laufenden Runner
alle fünf Millisekunden und nach dessen Rückkehr. Der Store prüft den
persistierten Zustand zusätzlich bei jeder Evidence-Ableitung. Fehlender
Reader, Reader-Ausnahme, nicht-boolescher Rückgabewert, geschlossene Datenbank,
fehlende oder inkonsistente Audit-Evidence und jeder Zustand außer einem exakt
validierten `clear` gelten als aktiv.

Ein Kill vor der Reservation erzeugt keinen Attempt. Ein im selben Prozess
erkannter Kill nach der Reservation, aber vor dem Runner, erzeugt einen
abgebrochenen Pre-Start-Attempt. Ein Kill während des Runners abortiert das
Signal und persistiert `aborted` Revision `2`. Das persistente Engagement wird
zuerst geschrieben und pausiert aktive Kampagnen, bevor seine Auditfortsetzung
versucht wird.

## Branding, Freeze und Spoofing-Grenzen

Folgende produktive Objekte werden bei echter Konstruktion in privaten
`WeakSet`s gebrandet und zusätzlich gegen ihren exakten Prototyp geprüft:

- `ControlPlaneDatabase`;
- `ControlPlaneStore`;
- `StoreBoundExternalActionEvaluator` und der interne Deny-All-Evaluator;
- `Phase2KillSwitch`;
- `DeterministicMockActionRunner` und `DisabledExternalActionRunner`.

Der Store akzeptiert nur eine gültig gebrandete Datenbank; der Evaluator nur
einen gültig gebrandeten Store. Pipeline, Evaluator, Runner und Kill Switch sind
eingefroren; ebenso ihre Konstruktoren und Prototypen. Dadurch können
Caller-Objekte, Prototype-Spoofs, Proxy-Wrapper und nachträgliches
Method-Shadowing die Vertrauenskette nicht ersetzen. Der Kill-Switch-Reader
wird als eigener Datenwert aus einem gewöhnlichen Objekt erfasst, ohne
Accessor aufzurufen.

Branding ist eine In-Process-Integritätsmaßnahme, keine Identitäts- oder
Sandboxgrenze. Insbesondere bleibt Code mit einem echten rohen
`ControlPlaneDatabase`-Handle Teil der Trusted Computing Base.

## Datenminimierung und lokale Grenze

Die neuen Tabellen speichern ausschließlich Referenzen, Statuswerte,
Zeitpunkte, Revisionen und Digests. `payload_ref` bleibt `null`; Secretwerte,
Tokens, Cookies, Sessions, Rohbodys, HARs, E-Mail-Inhalte und Eventdaten werden
weder angefordert noch in den neuen Tabellen persistiert.

`external_integrations_enabled` muss effektiv `false` sein. Selbst ein formal
auf extern konfigurierter Phase-2-Runtime-State wird vom Runtime-Resolver und
von der Pipeline geschlossen deaktiviert. `DisabledExternalActionRunner`
besitzt keinen Transport und kann keine Simulation ausführen. Während
Entwicklung und Tests dieses Schritts ist deshalb kein realer Plattform- oder
Bug-Bounty-Host Teil eines ausführbaren Pfads.
