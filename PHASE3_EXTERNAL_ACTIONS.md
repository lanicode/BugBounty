# Phase-3-Register externer Aktionen

## Globale Invarianten

`external_integrations_enabled` ist effektiv `false`. Fehlende oder fehlerhafte
Konfiguration, Secret-Store-Fehler, ein formal aktivierter externer Modus,
unbekannte Aktionen, nicht gebrandete Runner/Evaluatoren und nicht lesbare
Store-Evidence blockieren. `DisabledExternalActionRunner` enthält keinen
Transport; es gibt keinen realen Adapter.

Der Proposal enthält weder Host noch Scheme, Secret-Art oder Runnerauswahl.
Diese Metadaten stammen ausschließlich aus der eingefrorenen Registry. Die dort
genannte Secret-Art ist in Phase 3 nur eine zukünftige Capability-Klasse: Es
wird kein Secretwert aufgelöst, angefordert, persistiert oder an den
In-Process-Mock-Runner übergeben.

Jede der fünf simulationsfähigen Aktionen erzwingt zusätzlich zum
Registry-Human-Checkpoint eine akzeptierte `external_action`-Approval, die
exakt an Proposal, Operator, Policy, Kampagnenrevision, Scope, Account, Objekt
und Payload gebunden ist. Auch ein Registry-Wert `not_required` hebt diese
store-gebundene Phase-3-Approval nicht auf.

## Gemeinsame Policy- und Kill-Switch-Regeln

Eine erreichbare Simulationsaktion benötigt eine aktuelle, akzeptierte Policy,
eine laufende und menschlich freigegebene lokale Simulationskampagne, einen
gültigen Scope, das zur Registry passende Ownership-Modell, persistente Budgets
und die gebundene Human Approval. Drift oder Lesefehler blockieren.

Die Registry setzt für jede Aktion
`killSwitchBehavior: "block_before_and_after_runner"`. Konkret prüft die
Pipeline vor und nach jeder wirkungsrelevanten Stufe sowie während eines
laufenden Runners. Vor der Reservation entsteht bei Kill kein Attempt. Ein im
selben Prozess erkannter Kill nach Reservation, aber vor Start, persistiert
`aborted` Revision `1`; während des Runners persistiert er `aborted` Revision
`2`. Ein Crash hinterlässt dagegen fail-closed `reserved` oder `running`.

## Vollständige Registry

| Action-ID                 | Auslösende Komponente       | Registry-Secret-Art                                                    | Zielhost/-policy                                                                                 | Policy-/Scope-/Ownership-Prüfung                                                                                                                                      | Menschlicher Kontrollpunkt                                                                                                               | Default-Zustand                                                                                | Kill-Switch-Verhalten                                                                                                    |
| ------------------------- | --------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `platform_api_read`       | `platform_adapter`          | `platform_api_token`; nur Typmetadatum, kein Token                     | Registry-Metadatum `http://127.0.0.1`, Klasse `platform_api`; Runner bleibt In-Process           | aktuelle Policy und Scope erforderlich; Account und Objekt müssen `null` sein                                                                                         | Registry: `not_required`; Phase 3: proposal-/operatorgebundene `external_action`-Approval sowie bestehende Policy- und Kampagnenfreigabe | `blocked`; nur gebrandeter lokaler Mock kann nach vollständiger Evidence laufen                | Block vor/nach Stufen und Polling während Runner; Pre-Start-Kill -> `aborted` Rev. 1, laufender Kill -> `aborted` Rev. 2 |
| `test_account_register`   | `account_lifecycle`         | `test_identity_credentials`; nur Typmetadatum, keine Zugangsdaten      | Registry-Metadatum `http://127.0.0.1`, Klasse `test_application`; keine reale Registrierung      | aktuelle Policy und Scope erforderlich; Registry-Ownership `not_applicable`, daher Account und Objekt `null`                                                          | Registry: `manual_account_registration`; zusätzlich proposal-/operatorgebundene `external_action`-Approval                               | `blocked`; ausschließlich deterministische lokale Simulation, keine Kontoerstellung            | Block vor/nach Stufen und Polling während Runner; kein automatisches Fortsetzen oder Erfüllen des manuellen Checkpoints  |
| `email_verification_open` | `account_lifecycle`         | `email_verification_capability`; nur Typmetadatum, kein E-Mail-Zugriff | Registry-Metadatum `http://127.0.0.1`, Klasse `email_verification`; keine Mailboxverbindung      | aktuelle Policy und Scope; bereite, verifizierte, kampagnengebundene Account-Evidence; Objekt muss `null` sein                                                        | Registry: `email_verification`; zusätzlich proposal-/operatorgebundene `external_action`-Approval; keine automatische Verifikation       | `blocked`; ausschließlich lokaler In-Process-Mock                                              | Block vor/nach Stufen und Polling während Runner; Checkpoint wird niemals automatisch bestätigt                          |
| `browser_journey_start`   | `browser_orchestrator`      | `browser_profile`; nur Typmetadatum, kein Profil oder Sessionwert      | Registry-Metadatum `http://127.0.0.1`, Klasse `browser_journey`; kein Browsertransport           | aktuelle Policy und Scope; bereite, verifizierte, kampagnengebundene Account-Evidence; Objekt muss `null` sein                                                        | Registry: `campaign_approval`; zusätzlich proposal-/operatorgebundene `external_action`-Approval                                         | `blocked`; ausschließlich lokaler In-Process-Mock, kein externer Browser                       | Block vor/nach Stufen und Polling während Runner; laufende Simulation erhält Abort-Signal                                |
| `target_request`          | `deterministic_test_runner` | `test_identity_session`; nur Typmetadatum, keine Session               | Registry-Metadatum `http://127.0.0.1`, Klasse `program_target`; kein HTTP-Request durch den Mock | aktuelle Policy und Scope; exakte Account- und aktive Owned-Object-Evidence; nur `offline_inspect`                                                                    | Registry: `not_required`; Phase 3: proposal-/operatorgebundene `external_action`-Approval sowie Policy- und Kampagnenfreigabe            | `blocked`; nur ungefährliche deterministische In-Process-Antwort, kein aktiver Sicherheitstest | Block vor/nach Stufen und Polling während Runner; Evidence wird vor Start und vor Erfolg erneut geprüft                  |
| `report_submit`           | `reporting`                 | `platform_api_token`; nur Typmetadatum, kein Token                     | `external_disabled`, Host und Scheme `null`, Klasse `report_submission`                          | Registry verlangt Policy, Scope und Objekt-Ownership; Phase 3 blockiert vorher mit `ACTION_SIMULATION_NOT_SUPPORTED` beziehungsweise `EXTERNAL_INTEGRATIONS_DISABLED` | Registry: `report_collective_approval`; eine lokale Freigabe ist niemals eine Einreichung                                                | `blocked`; `simulationSupported: false`, kein Runner, keine Einreichung                        | Unabhängig von Evidence blockiert; Kill-Prüfung am Pipeline-Eingang bleibt zusätzlich aktiv                              |
| `triage_response_send`    | `triage_workspace`          | `platform_api_token`; nur Typmetadatum, kein Token                     | `external_disabled`, Host und Scheme `null`, Klasse `triage_response`                            | Registry verlangt Policy, Scope und Objekt-Ownership; Phase 3 blockiert vorher mit `ACTION_SIMULATION_NOT_SUPPORTED` beziehungsweise `EXTERNAL_INTEGRATIONS_DISABLED` | Registry: `triage_response_approval`; eine lokale Freigabe versendet keine Nachricht                                                     | `blocked`; `simulationSupported: false`, kein Runner, kein Versand                             | Unabhängig von Evidence blockiert; Kill-Prüfung am Pipeline-Eingang bleibt zusätzlich aktiv                              |

## Tatsächlich ausführbarer Simulationspfad

`platform_api_read`, `test_account_register`, `email_verification_open`,
`browser_journey_start` und `target_request` können nach vollständiger
Store-Evidence ausschließlich den gebrandeten `DeterministicMockActionRunner`
erreichen. Dieser liest eine defensive Kopie einer vorab registrierten
In-Process-Antwort. Die Loopback-Adresse ist Zielmetadatum der Registry, nicht
ein durch diesen Runner ausgeführter Netzwerkrequest.

Die Aktionsnamen erweitern den Funktionsumfang nicht: Es findet weder ein
Plattform-API-Zugriff noch eine Registrierung, E-Mail-Verifikation,
Browserreise oder Zielanfrage statt. `target_request` ist fachlich auf die
lokale Ownership-Aktion `offline_inspect` beschränkt.

## Reale Integrationen

Es gibt keine HackerOne-, Bugcrowd- oder sonstige Plattformintegration. Es
werden keine echten Tokens, Cookies, Passwörter, TOTP-Secrets,
E-Mail-Zugangsdaten oder Browser-Sessions benötigt. Ein Proposal im Modus
`external` wird unabhängig von Runtime-Konfiguration und vorhandener Evidence
abgelehnt. Report- und Triage-Approvals bleiben lokale Datensätze ohne externe
Wirkung.

Während Entwicklung und Tests von Phase 3 wurde kein realer Plattform- oder
Bug-Bounty-Host kontaktiert.
