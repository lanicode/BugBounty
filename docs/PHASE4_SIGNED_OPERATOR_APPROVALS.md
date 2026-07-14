# Phase 4: signierte lokale Operator-Freigaben

## Status und Umfang

Phase 4 ergänzt die lokale Control Plane um eine einzelne persistente
Operator-Credential und kryptografisch authentisierte Entscheidungen. Der
Schutz gilt für:

- Enrollment und erneute Authentisierung einer lokalen Operator-Session;
- akzeptierte und abgelehnte Approval-Entscheidungen;
- das Löschen des globalen Kill Switches;
- die Revalidierung solcher Entscheidungen durch Policy-, Campaign- und
  External-Action-Konsumenten.

Die Implementierung aktiviert keine reale Plattformintegration und keinen
externen Runner. Dashboard, Demo-SaaS, Simulation und Mock-Aktionen bleiben
lokal; `external_integrations_enabled` bleibt effektiv `false`. Eine Signatur
ist eine technische lokale Autorisierung, keine automatische Annahme von
Regeln, Bedingungen oder rechtlichen Erklärungen.

## Trust Boundary

Die Grenze besteht aus fünf Schichten:

1. Der macOS Keychain ist im Produktpfad die einzige Quelle des privaten
   Operator-Schlüssels. Umgebungsvariablen enthalten nur Keychain-Referenz,
   Operator-ID und Key-Revision, niemals das Schlüsselmaterial.
2. `packages/operator-auth` importiert den Schlüssel, erzeugt geschlossene
   signierte Envelopes und prüft Ed25519-Signaturen. Nur intern erzeugte,
   über `WeakSet` gebrandete Signer mit dem exakten eingefrorenen Prototyp
   gelten als vertrauenswürdig.
3. `ControlPlaneStore` ist die einzige fachliche Schreibgrenze. Auch Store und
   Datenbank sind über interne Brands und exakte Prototypen gebunden. Der Store
   validiert Signatur, Session, Zeit, aktuellen Zustand und Kontext vor einer
   positiven Mutation.
4. SQLite erzwingt zusätzlich referenzielle Bindungen, Single-use-Nonces,
   Immutability und das Verbot unsignierter Zustandsübergänge.
5. Policy-, Campaign- und External-Action-Pfade lesen persistierte Evidence
   nicht als bloßes Boolean, sondern rekonstruieren und verifizieren sie erneut.

Untrusted sind insbesondere alle Signierinputs, eingehenden Envelopes,
Dashboard-Requests, Zeitwerte außerhalb der Store-Clock und direkt gelesene
SQLite-Zeilen. Envelopes müssen echte Plain Objects mit exakt den erwarteten,
enumerierbaren Datenfeldern sein. Zusatzfelder, Accessors, Arrays, Proxies und
fremde Prototypen werden abgewiesen.

## Keychain und Ed25519

Der Produktpfad verwendet `MacOSKeychainSecretStore` und eine Referenz der Form
`keychain://<service>/<account>`. Der Adapter ist außerhalb von macOS
fail-closed und liest über `/usr/bin/security`. Es gibt weder Schlüsseldatei
noch Klartext- oder Environment-Fallback.

`createKeychainOperatorSigner` erwartet einen binären PKCS#8-DER-Schlüssel:

1. Secret-Store- und Konfigurationsfehler blockieren die Erstellung.
2. Leere Werte, Werte über 4096 Byte, ungültiges DER und andere Schlüsseltypen
   als Ed25519 werden abgewiesen.
3. Aus dem privaten Schlüssel wird der öffentliche SPKI-DER-Schlüssel
   abgeleitet. Die Credential bindet `operator_id`, den kanonischen
   Base64url-SPKI-Wert, dessen SHA-256-Fingerprint und `key_revision`.
4. Der gelesene Secret-Puffer und die temporäre DER-Kopie werden überschrieben.
   Schlägt das Überschreiben fehl, wird kein Signer zurückgegeben.
5. Der private `KeyObject` bleibt nur im lokalen Prozess. Persistiert werden
   ausschließlich Public Key, Fingerprint, Revision, signierte Statements und
   deren Digests.

Signiert wird die UTF-8-Darstellung eines kanonischen JSON-Dokuments ohne das
Signaturfeld. Die Ed25519-Signatur ist exakt 64 Byte lang und wird kanonisch als
Base64url gespeichert. Der Statement-Digest ist SHA-256 über dasselbe
kanonische, unsignierte Dokument. Bei der Verifikation werden Public-Key-DER,
Fingerprint, Ed25519-Typ, kanonische DER-Repräsentation und Signatur erneut
geprüft.

Das Dashboard darf ohne vollständig konfigurierte Signer-Metadaten starten,
bleibt dann aber für alle positiven signaturpflichtigen Operationen gesperrt.
Eine teilweise oder fehlerhafte Konfiguration bricht ab. Die interaktive CLI
verlangt immer eine vollständige Signer-Konfiguration und bricht bei fehlendem
Keychain-Zugriff ab.

## Signierte Envelopes

Alle drei Envelope-Typen verwenden `version: 1`, eine typspezifische Domain,
die persistente `control_plane_id`, eine 32-Byte-Session-ID, eine global
eindeutige 32-Byte-Nonce sowie kanonische `issued_at`- und `expires_at`-Werte.
Session und Nonce sind kanonisches Base64url. Das Gültigkeitsfenster muss
positiv und höchstens fünf Minuten lang sein; die Prüfung verlangt
`issued_at <= observed_at < expires_at`.

### Enrollment-Proof

Domain:
`bugbounty-copilot:control-plane:operator-enrollment:v1`

Gebundene Felder:

- `control_plane_id`
- `operator_id`
- `public_key_spki_base64url`
- `key_fingerprint_sha256`
- `key_revision`
- `session_id`, `nonce`, `issued_at`, `expires_at`
- `signature_base64url`

### Approval-Entscheidung

Domain:
`bugbounty-copilot:control-plane:approval-decision:v1`

Zusätzlich gebunden werden:

- `approval_id` und `approval_kind`
- `approval_payload_hash_sha256`
- `expected_revision`
- `decision` (`accepted` oder `rejected`)
- die explizite `user_action`
- `operator_id`, Key-Fingerprint und Key-Revision
- `context_digest_sha256`

Für jede Approval-Art außer `external_action` muss der Kontextdigest exakt dem
Approval-Payload-Hash entsprechen. Für `external_action` ist er der immutable
External-Action-Approval-Binding-Digest. Damit kann eine gültige Signatur weder
auf ein anderes Approval noch auf eine andere Revision, Payload oder
External-Action-Evidence übertragen werden.

### Kill-Switch-Clear

Domain:
`bugbounty-copilot:control-plane:kill-switch-clear:v1`

Das Envelope bindet `command: "clear"`, die erwartete aktuelle
Kill-Switch-Revision, eine explizite `user_action`, Operator und Schlüssel,
Session, Nonce, Zeitfenster und einen Kontextdigest. Dieser Digest umfasst die
Control-Plane-ID, den Schlüssel `global_kill_switch`, den Zustand `engaged` und
die erwartete Revision.

## Control-Plane-ID, TOFU und Sessions

Migration v5 erzeugt pro Datenbank einmalig eine zufällige 32-Byte-
`control_plane_id`. SQLite-Trigger verhindern anschließend Insert, Update und
Delete. Dadurch sind Signaturen an genau einen Store gebunden und nicht auf
eine unabhängig erzeugte Control Plane übertragbar.

Das erste Enrollment ist bewusst Trust On First Use:

- der globale Kill Switch muss effektiv aktiv sein;
- der Credential-Store muss leer sein;
- der neue Schlüssel muss per Ed25519 einen Proof-of-Possession über seine
  eigene Credential, Control-Plane-ID, Session, Nonce und Zeit liefern;
- Statement und Singleton-Credential werden atomar gespeichert.

Nach dem Enrollment ist die Credential immutable. Eine neue lokale Session
liefert einen weiteren signierten Enrollment-Proof mit derselben Credential.
Bei einer Approval- oder Kill-Clear-Entscheidung muss eine noch gültige
Enrollment-Evidence für exakt dieselbe Control Plane, Operator-Credential und
`session_id` vorhanden sein. Diese Evidence wird samt Signatur und Digest
erneut geprüft.

Die Nonce ist in `operator_signed_statements` global `UNIQUE`, also auch über
Statement-Typen und Prozessneustarts hinweg nur einmal verwendbar. Ein
Nonce-Konflikt bricht die umgebende Transaktion ab. Eine abgelaufene Session
löscht die Credential nicht; sie erfordert einen neuen authentisierten
Session-Proof.

TOFU authentisiert lokalen Schlüsselbesitz, aber keine bürgerliche Identität,
keinen bestimmten macOS-Benutzer und keine rechtliche Zustimmung.

## Store-eigene monotone Uhr

Sensitive Store-Methoden akzeptieren keinen vom Aufrufer gelieferten
`observedAt`-Parameter. `ControlPlaneStore` besitzt stattdessen eine private
Clock-Abhängigkeit; ohne Injektion wird die Systemzeit verwendet.

Vor Enrollment, Session-Authentisierung, Approval-Entscheidung und Kill-Clear:

- wird genau im Store eine neue Beobachtungszeit gelesen;
- werden Clock-Ausnahmen zu `OPERATOR_CLOCK_UNAVAILABLE`;
- werden Proxies, Nicht-`Date`-Objekte, fremde Prototypen und ungültige Werte
  mit `OPERATOR_CLOCK_INVALID` abgewiesen;
- wird der Wert kanonisch in UTC serialisiert;
- darf er nicht vor dem höchsten bereits persistierten `verified_at` liegen.

Der Store prüft diese High-Water-Mark vor dem Insert; der SQLite-Trigger
`operator_signed_statements_clock_guard` wiederholt die Prüfung innerhalb der
Schreibtransaktion. Gleichstand ist erlaubt, Rücklauf blockiert mit
`OPERATOR_CLOCK_ROLLBACK`. Persistierte Signaturen werden zur historischen
Revalidierung gegen ihr gespeichertes `verified_at` geprüft; aktuelle
Policy-, Scope-, Approval-Lifetime- und Action-Zustände werden davon getrennt
erneut bewertet.

Diese Uhr ist fail-closed, aber keine hardwaregesicherte monotone Uhr. Die
Systemzeit und eine ausdrücklich injizierte Clock bleiben Teil der Trusted
Computing Base.

## Atomare Entscheidungen

`ControlPlaneDatabase.transaction` verwendet synchrones `BEGIN IMMEDIATE`.
Thenables sind verboten. Jeder Fehler führt zu `ROLLBACK`; auch ein
Rollback-Fehler ersetzt nicht den ursprünglichen Fehler.

Eine Approval-Entscheidung erfolgt in einer solchen Transaktion:

1. Store-Zeit beobachten und Clock-Rollback ausschließen.
2. Effektiven Kill Switch, offenes Approval und Revision prüfen.
3. Persistente Credential vollständig revalidieren.
4. Envelope-Bindungen, Zeitfenster und Ed25519-Signatur prüfen.
5. Passende, noch gültige Session-Evidence prüfen.
6. allgemeines signiertes Statement und Approval-Evidence einfügen;
7. Approval mit optimistischem Revision-/Payload-Guard aktualisieren;
8. Audit-Eintrag mit dem Statement-Digest erzeugen;
9. bei einem akzeptierten External-Action-Approval dessen Auditbindung setzen.

Signaturprüfung, Replay-Schutz, Evidence, Approval-Mutation, Audit und optionale
External-Action-Auditbindung werden daher gemeinsam committed oder gemeinsam
zurückgerollt.

Kill-Clear ist ebenfalls atomar: Signatur- und Session-Prüfung, allgemeines
Statement, Kill-Clear-Evidence, Audit und der konditionale Wechsel von
`engaged` auf `clear` bilden eine Transaktion. Nach dem Update revalidiert
`isKillSwitchActive()` die vollständige Evidence; eine inkonsistente Freigabe
führt zum Rollback.

Kill-Engagement ist absichtlich asymmetrisch. `setKillSwitch(false, ...)` ist
verboten; nur das signierte Clear-Verfahren darf freigeben. Ein Engagement
schreibt dagegen zuerst den blockierenden Zustand und pausiert aktive
Kampagnen. Schlägt danach das Audit fehl, wird ein Fehler gemeldet, der bereits
engagierte Zustand aber nicht in einen unsicheren Zustand zurückgerollt.

## SQLite-Migration v5 und Trigger

Migration v5 führt folgende persistente Strukturen ein:

- `control_plane_identity`: immutable Singleton-ID;
- `operator_signed_statements`: gemeinsame append-only Evidence mit Purpose,
  Bindungen, Nonce, Zeit und Signatur;
- `local_operator_credentials`: eine immutable Einzeloperator-Credential;
- `signed_approval_decisions`: 1:1-Bindung zwischen Approval und signiertem
  Statement;
- `signed_kill_switch_clears`: Evidence für einen konkreten
  Kill-Switch-Revisionswechsel.

Die wichtigsten Trigger erzwingen:

- keine rückläufigen `verified_at`-Werte;
- kein Update oder Delete signierter Statements, Credentials,
  Approval-Evidence oder Kill-Clear-Evidence;
- Credential-Insert nur mit passender Enrollment-Evidence und nur bei leerer
  Credential-Tabelle;
- Approval-Evidence nur für ein offenes Approval mit passender Art, Payload
  und Revision;
- kein bereits entschiedenes Approval per Insert und kein Approval-Update auf
  `accepted` oder `rejected` ohne exakt passende signierte Evidence;
- keine External-Action-Decision-Auditbindung ohne akzeptierte signierte
  Entscheidung und passendes Audit;
- kein Wechsel des globalen Kill Switches auf `clear` ohne Revision `+1`,
  passende signierte Evidence und exakt gebundenes Clear-Audit.

Zusätzlich löscht die Migration vorhandene Policy-Acceptances, setzt Programme
auf `pending`, engagiert den globalen Kill Switch und pausiert zuvor genehmigte
oder laufende Simulationskampagnen. Dabei werden deren Human-Approval-Felder
entfernt. Historische Approval-Zeilen werden nicht als neue signierte Evidence
übernommen. Fehlt die neue Evidence, blockieren die Store-Konsumenten diese
Datensätze als Autorisierung.

Migrationen selbst laufen in `BEGIN IMMEDIATE`, besitzen gespeicherte
Checksummen und blockieren bei Versions- oder Checksum-Abweichung. SQLite läuft
mit Foreign Keys, `trusted_schema=OFF` und `synchronous=FULL`.

## Revalidierung durch Policy und Campaign

Eine Policy-Acceptance benötigt ein passendes akzeptiertes
`program_policy_acceptance`-Approval. `acceptPolicy`, `getPolicy` und
`listPolicies` revalidieren dessen signierte Decision-Evidence. Eine laufende
oder genehmigte Kampagne benötigt zusätzlich ein passendes signiertes
`campaign_contract`-Approval, den aktuellen Policy-Hash und einen effektiven
clearen Kill Switch. Campaign-Lese- und Schreibpfade prüfen diese Bindungen
erneut.

Damit wird ein historisches Operatorlabel in `decided_by` nicht als
Authentisierung behandelt. Entscheidend sind Envelope, Credential, Session,
Statement-Digest und die persistente Evidence-Kette.

## External-Action-Revalidierung

Phase 4 erweitert den bestehenden store-gebundenen Phase-3-Evaluator, ohne
einen realen Transport zu aktivieren.

Für ein `external_action`-Approval wird ein Binding-Digest über Proposal,
Action, Operator, Programm, Campaign-Revision und -Digest, Policy, Scope,
Accountrolle, Identity, Ownership, Payload-Referenz und Gültigkeitsfenster
gebildet. Genau dieser Digest wird signiert. Bei einer akzeptierten
Entscheidung bindet ein SQLite-Trigger das Approval-Audit an die
External-Action-Evidence.

Vor der atomaren Reservation prüft `readAcceptedBinding` unter anderem:

- Proposal- und Binding-Digest sowie alle Policy-, Campaign-, Scope-, Account-
  und Ownership-Bindungen;
- Approval-Art, Status `accepted`, Revision 1, Operator, feste User-Action,
  Policy und Gültigkeitsfenster;
- deterministische Audit-ID und sämtliche relevanten Auditfelder;
- die vollständige kryptografische Approval- und Session-Evidence;
- denselben Operator für External-Action-, Campaign- und Policy-Acceptance.

Der resultierende Evidence-Digest enthält zusätzlich Approval-Payload-Hash,
Approval-Revision, Decision-Statement-Digest, Key-Fingerprint und Key-Revision.
Reservation und Budgetverbrauch werden gemeinsam mit diesem Digest
persistiert.

Vor Runner-Start wird der aktuelle Kontext samt signierter Entscheidung erneut
aufgebaut und mit dem reservierten Evidence-Digest verglichen. Vor einem
erfolgreichen Settlement geschieht dieselbe vollständige Revalidierung erneut.
Bei Drift kann der Versuch nicht als erfolgreich gespeichert werden; er wird
als abgebrochen protokolliert und der Reason Code wird an den Aufrufer
zurückgegeben. Explizite Fehler- oder Abbruch-Settlements benötigen keine neue
positive Autorisierung, müssen aber weiterhin exakt zum persistierten Attempt
passen.

Diese Kette bleibt auf den deterministischen lokalen Mock-Runner beschränkt.
Sie ist kein Nachweis einer vorhandenen oder freigegebenen realen
Bug-Bounty-Integration.

## Dashboard und Simulation

Dashboard und `SimulationOrchestrator` akzeptieren einen `OperatorSigner` nur
als explizite Dependency. Ein vorhandener, aber ungebrandeter Signer blockiert
bereits die Konstruktion. Fehlt der Signer, liefern Simulation, Approval und
Kill-Clear `OPERATOR_SIGNER_REQUIRED`, ohne Credential oder signierte Evidence
anzulegen. Kill-Engagement bleibt weiterhin ohne Signer möglich.

Das Dashboard:

- bindet ausschließlich an `127.0.0.1`;
- prüft Remote-Adresse, Host, Same-Origin, CSRF und JSON-Grenzen;
- zeigt nur an, ob ein vertrauenswürdiger Signer konfiguriert ist, sowie dessen
  Operator-ID;
- prüft vor einer Approval-Entscheidung zusätzlich die erwartete Revision und
  den erwarteten Payload-Hash;
- erzeugt pro Serverinstanz eine zufällige lokale Operator-Session.

Die Simulation erzeugt ebenfalls pro Orchestrator eine zufällige Session. Sie
prüft Review-Digest, explizite Bestätigungen und Signer-Operator, authentisiert
die Session, löscht den Kill Switch signiert und signiert danach jede positive
Policy- und Campaign-Entscheidung. Fehlt der Signer, blockiert sie vor der
ersten Control-Plane-Mutation. Tritt nach einem erfolgreichen Clear ein Fehler
auf, versucht der Orchestrator den Kill Switch wieder zu engagieren.

Alle hier beschriebenen HTTP- und Browserpfade sind lokale Loopback-Pfade. Es
werden keine Plattform-Credentials, realen Accounts oder externen
Bug-Bounty-Ziele angesprochen.

## Fail-closed Reason Codes

Die wichtigsten Fehlerklassen sind:

| Grenze                            | Beispiele                                                                                                                                                                                                                                 |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Signer-Konfiguration und Keychain | `OPERATOR_SIGNER_CONFIG_INVALID`, `OPERATOR_SECRET_STORE_INVALID`, `OPERATOR_KEY_UNAVAILABLE`, `OPERATOR_KEY_INVALID`, `OPERATOR_KEY_ZEROIZATION_FAILED`                                                                                  |
| Signer-Brand und Signieren        | `OPERATOR_SIGNER_REQUIRED`, `OPERATOR_SIGNER_UNTRUSTED`, `OPERATOR_SIGNING_INPUT_INVALID`, `OPERATOR_SIGNING_FAILED`                                                                                                                      |
| Envelope und Kryptografie         | `OPERATOR_ENROLLMENT_INVALID`, `OPERATOR_APPROVAL_DECISION_INVALID`, `OPERATOR_KILL_CLEAR_INVALID`, `OPERATOR_CREDENTIAL_INVALID`, `OPERATOR_STATEMENT_BINDING_INVALID`, `OPERATOR_SIGNATURE_INVALID`                                     |
| Zeit und Replay                   | `OPERATOR_STATEMENT_TIME_INVALID`, `OPERATOR_CLOCK_UNAVAILABLE`, `OPERATOR_CLOCK_INVALID`, `OPERATOR_CLOCK_ROLLBACK`; Nonce-`UNIQUE`-Verletzung                                                                                           |
| Enrollment und Session            | `OPERATOR_ENROLLMENT_KILL_SWITCH_REQUIRED`, `OPERATOR_CREDENTIAL_ALREADY_ENROLLED`, `OPERATOR_CREDENTIAL_REQUIRED`, `OPERATOR_CREDENTIAL_MISMATCH`, `OPERATOR_SESSION_AUTHENTICATION_REQUIRED`, `OPERATOR_SESSION_AUTHENTICATION_INVALID` |
| Approval                          | `APPROVAL_KILL_SWITCH`, `APPROVAL_ALREADY_PROCESSED`, `APPROVAL_PERSISTENCE_CONFLICT`, `SIGNED_APPROVAL_DECISION_REQUIRED`, `SIGNED_APPROVAL_DECISION_INVALID`                                                                            |
| Kill Switch                       | `SIGNED_KILL_SWITCH_CLEAR_REQUIRED`, `SIGNED_KILL_SWITCH_CLEAR_INVALID`, `KILL_SWITCH_NOT_ENGAGED`, `KILL_SWITCH_STATE_UNAVAILABLE`                                                                                                       |
| External Action                   | `ACTION_HUMAN_CHECKPOINT_REQUIRED`, `ACTION_EVIDENCE_CHANGED`, `ACTION_AUTHORIZATION_STATE_INVALID`, `ACTION_KILL_SWITCH`                                                                                                                 |

Fehler werden nicht auf einen freien Actor-Pfad oder eine unsignierte Mutation
zurückgestuft. `isKillSwitchActive()` interpretiert fehlende, unlesbare oder
inkonsistente Clear-Evidence als aktiv. Das gilt auch bei Datenbank-, Audit-
oder Verifikationsfehlern.

## Bewusste Grenzen

- Der Code erzeugt und provisioniert keinen Operator-Schlüssel. Ein bereits
  vorhandener Ed25519-PKCS#8-DER-Wert muss außerhalb dieses Workflows sicher im
  Keychain hinterlegt werden.
- Es gibt genau eine immutable lokale Credential. Rotation, Recovery,
  Revocation, Quorum und Mehrbenutzerfreigaben sind nicht implementiert.
- TOFU und Keychain-Zugriff beweisen lokalen Schlüsselbesitz, nicht
  Benutzeranwesenheit, Secure-Enclave-Bindung, Biometrie oder eine externe
  Identität.
- Temporäre Bytepuffer werden überschrieben; für den vom Node-Runtime
  verwalteten privaten `KeyObject` gibt es jedoch keine Zusage sofortiger oder
  hardwaregestützter Löschung.
- System-Clock, lokaler Prozess, OS-Account, Keychain-Zugriffsregeln und das
  rohe Datenbank-Handle gehören zur Trusted Computing Base.
- Trigger und kryptografische Revalidierung ersetzen keine OS-seitige
  Dateiintegrität gegen einen privilegierten lokalen Angreifer.
- Signaturen dokumentieren eine technische Aktion. Sie ersetzen keine
  automatische Zustimmung zu Programmregeln, Nutzungsbedingungen oder
  rechtlichen Erklärungen.
- Reale Plattformadapter, Account-Automation, CAPTCHA-/Anti-Bot-Umgehung,
  aktive Sicherheitstests, Report-Einreichung, Triage-Versand und
  LLM-gesteuerte Requests bleiben deaktiviert oder außerhalb des Scopes.

## Implementierungsorte

- `packages/operator-auth`: Envelopes, Keychain-Signer und Ed25519-Verifikation
- `packages/control-plane/store.ts`: TOFU, Sessions, Store-Clock,
  Entscheidungen und Revalidierung
- `packages/control-plane/database.ts`: Migration v5, Trigger und atomare
  Transaktionen
- `packages/control-plane/external-action-store.ts`: store-gebundene
  External-Action-Revalidierung
- `packages/dashboard/server.ts`: lokaler signierter Dashboard-Pfad
- `packages/simulation/orchestrator.ts`: lokale signierte Simulation
