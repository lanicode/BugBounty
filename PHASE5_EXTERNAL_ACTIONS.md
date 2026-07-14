# Phase-5-Register externer Aktionen

## Unveränderter External-Action-Umfang

Phase 5 erweitert keine External-Action-Funktion. Der neue Event-Key-Lifecycle
ist ausschließlich eine lokale Persistenz- und Adminfunktion. Initialisierung,
Legacy-Adoption, Status, Rotation und explizite Recovery können weder einen
External-Action-Vorschlag erzeugen noch einen Runner, HTTP-Client, Browser oder
Plattformadapter auslösen. Event-Keys werden niemals als Secret einer externen
Action verwendet oder an die External-Action-Pipeline übergeben.

`external_integrations_enabled` ist effektiv und standardmäßig `false`.
Fehlende oder fehlerhafte Konfiguration, Secret-Store- oder Keychain-Fehler,
ein formal aktivierter externer Modus, unbekannte Actions, untrusted Runner
oder nicht verifizierbare Store-Evidence blockieren fail-closed. Es gibt
weiterhin keinen realen Adapter und keinen External-Action-Transport.

Jede simulationsfähige Action erzwingt unverändert die vollständige Kette:

```text
strukturierter Vorschlag
-> exakte Schema- und Descriptorvalidierung
-> Registry-/Policy-Entscheidung
-> Scope-/Ownership-Prüfung
-> persistente Budgetprüfung und Reservation
-> kryptografisch signierte Human-Approval
-> deterministischer In-Process-Mock-Runner
```

Die signierte `external_action`-Entscheidung bindet exakt den unveränderlichen
Approval-Binding-Digest. Credential, Signatur, Nonce, Session, Revision,
Control-Plane-ID und Kontext werden beim Entscheiden sowie erneut vor
Reservation, Runner-Start und erfolgreichem Settlement geprüft.

Die Registry-Secret-Art ist ausschließlich ein Typmetadatum für eine mögliche
zukünftige Implementierung. In Phase 5 wird kein externes Secret angefordert,
aufgelöst, gespeichert oder an den Mock-Runner übergeben. Weder der lokale
Ed25519-Operator-Key noch ein Event-Key ist ein Secret einer externen Action.

## Vollständige Registry

| Action-ID                 | Auslösende Komponente       | Erforderliches Secret                                                     | Zielhost                                                                             | Policy-Prüfung                                                                                                                                                    | Menschlicher Kontrollpunkt                                                                                                                 | Default-Zustand                                                                            | Kill-Switch-Verhalten                                                                                                      |
| ------------------------- | --------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `platform_api_read`       | `platform_adapter`          | Zukünftig `platform_api_token`; in Phase 5 nur Typmetadatum, kein Token   | Festes Registry-Metadatum `http://127.0.0.1`; der Runner öffnet keine Verbindung     | aktuelle Policy, laufende freigegebene Simulationskampagne, Scope, leere Account-/Objektbindung, signierter exakter Action-Binding-Digest und persistente Budgets | Registry `not_required`, aber zwingend frische signierte `external_action`-Entscheidung sowie bestehende Policy-/Kampagnenfreigabe         | `blocked`; ausschließlich gebrandeter lokaler In-Process-Mock                              | Block vor/nach jeder Stufe und Polling während Runner; Pre-Start-Kill wird `aborted` Revision 1, laufender Kill Revision 2 |
| `test_account_register`   | `account_lifecycle`         | Zukünftig `test_identity_credentials`; in Phase 5 keine Zugangsdaten      | Festes Registry-Metadatum `http://127.0.0.1`; keine reale Registrierung              | aktuelle Policy/Kampagne/Scope, Registry-Ownership `not_applicable`, Account und Objekt `null`, signierte Action-Evidence und Budgets                             | Registry `manual_account_registration` plus signierte `external_action`-Entscheidung; der manuelle Checkpoint wird nie automatisch erfüllt | `blocked`; nur deterministische lokale Simulation, keine Kontoerstellung                   | Block vor/nach jeder Stufe und während Runner; kein automatisches Fortsetzen                                               |
| `email_verification_open` | `account_lifecycle`         | Zukünftig `email_verification_capability`; in Phase 5 kein Mailboxzugriff | Festes Registry-Metadatum `http://127.0.0.1`; keine Mailboxverbindung                | aktuelle Policy/Kampagne/Scope, bereite verifizierte kampagnengebundene Account-Evidence, Objekt `null`, signierte Action-Evidence und Budgets                    | Registry `email_verification` plus signierte `external_action`-Entscheidung; keine automatische Verifikation                               | `blocked`; nur lokaler In-Process-Mock                                                     | Block vor/nach jeder Stufe und während Runner; Checkpoint bleibt menschlich                                                |
| `browser_journey_start`   | `browser_orchestrator`      | Zukünftig `browser_profile`; in Phase 5 kein Profil-/Sessionwert          | Festes Registry-Metadatum `http://127.0.0.1`; kein Browsertransport                  | aktuelle Policy/Kampagne/Scope, bereite verifizierte kampagnengebundene Account-Evidence, Objekt `null`, signierte Action-Evidence und Budgets                    | Registry `campaign_approval` plus signierte `external_action`-Entscheidung                                                                 | `blocked`; nur lokaler In-Process-Mock, kein externer Browser                              | Block vor/nach jeder Stufe und während Runner; laufende Simulation erhält Abort-Signal                                     |
| `target_request`          | `deterministic_test_runner` | Zukünftig `test_identity_session`; in Phase 5 keine Session               | Festes Registry-Metadatum `http://127.0.0.1`; der Mock führt keinen HTTP-Request aus | aktuelle Policy/Kampagne/Scope, exakte Account- und aktive Owned-Object-Evidence, ausschließlich `offline_inspect`, signierte Action-Evidence und Budgets         | Registry `not_required`, aber zwingend signierte `external_action`-Entscheidung sowie Policy-/Kampagnenfreigabe                            | `blocked`; ungefährliche deterministische In-Process-Antwort, kein aktiver Sicherheitstest | Block vor/nach jeder Stufe und während Runner; Evidence vor Start und Erfolg erneut geprüft                                |
| `report_submit`           | `reporting`                 | Zukünftig `platform_api_token`; in Phase 5 kein Token                     | `external_disabled`; Host und Scheme `null`                                          | immer vor dem Runner durch `simulationSupported: false` beziehungsweise deaktivierte externe Integrationen blockiert; eine Signatur hebt das nicht auf            | Registry `report_collective_approval`; lokale Approval ist niemals eine Einreichung                                                        | `blocked`; kein Runner und keine Einreichung                                               | Am Pipeline-Eingang zusätzlich blockiert; Kill kann niemals umgangen werden                                                |
| `triage_response_send`    | `triage_workspace`          | Zukünftig `platform_api_token`; in Phase 5 kein Token                     | `external_disabled`; Host und Scheme `null`                                          | immer vor dem Runner durch `simulationSupported: false` beziehungsweise deaktivierte externe Integrationen blockiert; eine Signatur hebt das nicht auf            | Registry `triage_response_approval`; lokale Approval versendet keine Nachricht                                                             | `blocked`; kein Runner und kein Versand                                                    | Am Pipeline-Eingang zusätzlich blockiert; Kill kann niemals umgangen werden                                                |

## Tatsächlich ausführbarer Simulationspfad

Nur `platform_api_read`, `test_account_register`,
`email_verification_open`, `browser_journey_start` und `target_request` können
nach vollständiger, signierter und revalidierter Store-Evidence den
`DeterministicMockActionRunner` erreichen. Er liest eine defensive Kopie einer
vorab registrierten In-Process-Antwort. Die Loopback-Adresse ist
unveränderliches Registry-Metadatum und kein vom Runner ausgeführter Request.

Die Action-Namen erweitern den Funktionsumfang nicht: Es findet kein Plattform-
API-Zugriff, keine Registrierung, E-Mail-Verifikation, Browserreise oder
Zielanfrage statt. `target_request` bleibt fachlich auf die lokale Ownership-
Action `offline_inspect` beschränkt. `report_submit` und
`triage_response_send` besitzen auch im Simulationsmodus keinen Runner.

## Reale Integrationen und Entwicklung

HackerOne-, Bugcrowd- und sonstige reale Plattformintegrationen existieren
nicht. Es werden keine echten Tokens, Cookies, Passwörter, TOTP-Secrets,
E-Mail-Zugangsdaten oder Browser-Sessions benötigt. Ein Proposal im Modus
`external` wird unabhängig von Konfiguration, Signatur, Event-Key-State oder
vorhandener Evidence abgelehnt. Report- und Triage-Approvals bleiben lokale
Datensätze ohne externe Wirkung.

Während Entwicklung und Tests von Phase 5 wurde kein realer Plattform- oder
Bug-Bounty-Host kontaktiert. Netzwerk- und Browsertests blieben auf
Loopback-Adressen beziehungsweise vollständig in-process beschränkt.
