# Phase-6-Register externer Aktionen

## Unveränderter External-Action-Umfang

Phase 6 ergänzt oder verändert keine Registry-Action, keinen Adapter, keinen
Runner und keinen Transport. Control-Plane-Recovery, Kill-Switch-Versöhnung,
Audit-Append und Audit-Stale-Recovery sind ausschließlich lokale
Persistenzfunktionen. Sie können weder einen External-Action-Vorschlag
erzeugen noch HTTP, Browser, Plattform-API oder E-Mail auslösen.

`external_integrations_enabled` ist standardmäßig und effektiv `false`.
Fehlende oder fehlerhafte Konfiguration, Secret-Store-Fehler, ein formal
aktivierter externer Modus, unbekannte Actions, untrusted Runner oder nicht
verifizierbare Store-Evidence blockieren fail-closed. Es gibt weiterhin keinen
realen Adapter und keinen External-Action-Transport.

Jede simulationsfähige Action erzwingt unverändert:

```text
strukturierter Vorschlag
-> exakte Schema- und Descriptorvalidierung
-> Registry-/Policy-Entscheidung
-> Scope-/Ownership-Prüfung
-> persistente Budgetprüfung und Reservation
-> kryptografisch signierte Human-Approval
-> deterministischer In-Process-Mock-Runner
```

Die in der Registry benannten Secrets sind ausschließlich Typmetadaten für
eine mögliche spätere Implementierung. Phase 6 fordert keine Tokens, Cookies,
Passwörter, TOTP-Secrets, E-Mail-Zugangsdaten oder Browser-Sessions an, löst
sie nicht auf und übergibt sie nicht an einen Runner.

## Vollständige Registry

| Action-ID                 | Auslösende Komponente       | Erforderliches Secret                                                  | Zielhost                                                            | Policy-Prüfung                                                                                                                                                             | Menschlicher Kontrollpunkt                                                                                                       | Default-Zustand                                                | Kill-Switch-Verhalten                                                         |
| ------------------------- | --------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `platform_api_read`       | `platform_adapter`          | zukünftig `platform_api_token`; derzeit nur Typmetadatum               | festes Registry-Metadatum `http://127.0.0.1`; kein Transport        | aktuelle Policy, freigegebene laufende Simulationskampagne, Scope, Ownership `not_applicable`, signierte Action-Bindung, persistentes Budget und erneute Store-Validierung | Registry `not_required`, aber signierte `external_action`-Entscheidung und bestehende Policy-/Kampagnenfreigabe bleiben zwingend | `blocked`; nur gebrandeter In-Process-Mock                     | Block vor und nach jeder Stufe sowie Polling während des Runners; kein Refund |
| `test_account_register`   | `account_lifecycle`         | zukünftig `test_identity_credentials`; derzeit keine Zugangsdaten      | festes Registry-Metadatum `http://127.0.0.1`; keine Registrierung   | aktuelle Policy/Kampagne/Scope, Ownership `not_applicable`, signierte Action-Bindung, persistentes Budget und Revalidierung                                                | `manual_account_registration` plus signierte `external_action`-Entscheidung; nie automatisch erfüllt                             | `blocked`; lokale Simulation ohne Kontoerstellung              | Block vor/nach jeder Stufe und während Runner; kein automatisches Fortsetzen  |
| `email_verification_open` | `account_lifecycle`         | zukünftig `email_verification_capability`; derzeit kein Mailboxzugriff | festes Registry-Metadatum `http://127.0.0.1`; keine Mailverbindung  | aktuelle Policy/Kampagne/Scope, bereite kampagnengebundene Account-Evidence, signierte Action-Bindung, Budget und Revalidierung                                            | `email_verification` plus signierte `external_action`-Entscheidung; keine automatische Verifikation                              | `blocked`; nur In-Process-Mock                                 | Block vor/nach jeder Stufe und während Runner; Checkpoint bleibt menschlich   |
| `browser_journey_start`   | `browser_orchestrator`      | zukünftig `browser_profile`; derzeit kein Profil/Sessionwert           | festes Registry-Metadatum `http://127.0.0.1`; kein Browsertransport | aktuelle Policy/Kampagne/Scope, bereite kampagnengebundene Account-Evidence, signierte Action-Bindung, Budget und Revalidierung                                            | `campaign_approval` plus signierte `external_action`-Entscheidung                                                                | `blocked`; nur In-Process-Mock                                 | Block vor/nach jeder Stufe und Runner-Abbruchsignal bei Engagement            |
| `target_request`          | `deterministic_test_runner` | zukünftig `test_identity_session`; derzeit keine Session               | festes Registry-Metadatum `http://127.0.0.1`; kein HTTP-Request     | aktuelle Policy/Kampagne/Scope, exakte Account- und aktive Owned-Object-Evidence, ausschließlich `offline_inspect`, signierte Bindung, Budget und Revalidierung            | Registry `not_required`, aber signierte `external_action`-Entscheidung und Policy-/Kampagnenfreigabe bleiben zwingend            | `blocked`; ungefährliche In-Process-Antwort, kein aktiver Test | Block vor/nach jeder Stufe; Evidence vor Start und Settlement erneut geprüft  |
| `report_submit`           | `reporting`                 | zukünftig `platform_api_token`; derzeit kein Token                     | `external_disabled`; Host und Scheme `null`                         | vor Runner stets durch `simulationSupported: false` und deaktivierte externe Integration blockiert; Signatur hebt dies nicht auf                                           | `report_collective_approval`; lokale Approval ist keine Einreichung                                                              | `blocked`; kein Runner, keine Einreichung                      | bereits am Pipeline-Eingang blockiert; Kill Switch kann nie umgangen werden   |
| `triage_response_send`    | `triage_workspace`          | zukünftig `platform_api_token`; derzeit kein Token                     | `external_disabled`; Host und Scheme `null`                         | vor Runner stets durch `simulationSupported: false` und deaktivierte externe Integration blockiert; Signatur hebt dies nicht auf                                           | `triage_response_approval`; lokale Approval versendet nichts                                                                     | `blocked`; kein Runner, kein Versand                           | bereits am Pipeline-Eingang blockiert; Kill Switch kann nie umgangen werden   |

## Tatsächlich ausführbarer Simulationspfad

Nur `platform_api_read`, `test_account_register`,
`email_verification_open`, `browser_journey_start` und `target_request` können
nach vollständiger, signierter und erneut validierter Store-Evidence den
`DeterministicMockActionRunner` erreichen. Er liest nur eine defensive Kopie
einer vorab registrierten In-Process-Antwort. Das Loopbackziel ist festes
Registry-Metadatum und wird vom Runner nicht kontaktiert.

`report_submit` und `triage_response_send` sind auch im Simulationsmodus nicht
ausführbar. Ein `external`-Proposal wird unabhängig von Konfiguration,
Signatur, Approval-, Audit- oder Event-Key-Evidence abgelehnt. Kill-Switch-
Engagement blockiert vor Reservation, vor Start, während des Mock-Runners und
vor Settlement. Reservierungen werden bei Abbruch oder Crash nicht erstattet.

## Reale Integrationen und Entwicklung

HackerOne-, Bugcrowd- und andere reale Plattformintegrationen existieren
nicht. Phase 6 fügt keine Kontoautomation, Regel- oder Bedingungsannahme,
CAPTCHA-Umgehung, Report-Einreichung, Triage-Antwort oder LLM-gesteuerte
Requestfähigkeit hinzu.

Während Entwicklung und Tests wurde kein realer Plattform-, HackerOne-,
Bugcrowd-, Beispiel- oder Bug-Bounty-Zielhost kontaktiert. Produkt-Netzwerk-
und Browsertests blieben vollständig in-process oder auf `127.0.0.1`
beschränkt.
