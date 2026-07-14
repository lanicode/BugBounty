# Phase-7-Register externer Aktionen

## Unveränderter External-Action-Umfang

Phase 7 ergänzt oder verändert keine Registry-Action, keinen Adapter, keinen
produktiven Runner und keinen Transport. Der neue Playwright-Harness ist
ausschließlich Testinfrastruktur und wird nicht als
`browser_journey_start`-Runner registriert. Er startet seine eigene lokale
Demo-SaaS auf `127.0.0.1:0` und kann weder einen External-Action-Vorschlag noch
eine Plattform-, Ziel-, E-Mail- oder Reportaktion auslösen.

`external_integrations_enabled` ist standardmäßig und effektiv `false`.
Fehlende oder fehlerhafte Konfiguration, Secret-Store-Fehler, unbekannte
Actions, untrusted Runner oder nicht verifizierbare Store-Evidence blockieren
fail-closed. Es gibt weiterhin keinen realen Adapter und keinen
External-Action-Transport.

Jede simulationsfähige Registry-Action erzwingt unverändert:

```text
strukturierter Vorschlag
-> exakte Schema- und Descriptorvalidierung
-> Registry-/Policy-Entscheidung
-> Scope-/Ownership-Prüfung
-> persistente Budgetprüfung und Reservation
-> kryptografisch signierte Human-Approval
-> deterministischer In-Process-Mock-Runner
```

## Vollständige Registry

| Action-ID                 | Auslösende Komponente       | Erforderliches Secret                                                  | Zielhost                                                            | Policy-Prüfung                                                                                                                               | Menschlicher Kontrollpunkt                                                                           | Default-Zustand                                                       | Kill-Switch-Verhalten                                                        |
| ------------------------- | --------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `platform_api_read`       | `platform_adapter`          | zukünftig `platform_api_token`; derzeit nur Typmetadatum               | festes Registry-Metadatum `http://127.0.0.1`; kein Transport        | aktuelle Policy, laufende Simulationskampagne, Scope, signierte Action-Bindung, persistentes Budget und Store-Revalidierung                  | signierte `external_action`-Entscheidung und bestehende Policy-/Kampagnenfreigabe                    | `blocked`; nur gebrandeter In-Process-Mock                            | Block vor/nach jeder Stufe und Polling im Runner; kein Refund                |
| `test_account_register`   | `account_lifecycle`         | zukünftig `test_identity_credentials`; derzeit keine Zugangsdaten      | festes Registry-Metadatum `http://127.0.0.1`; keine Registrierung   | aktuelle Policy/Kampagne/Scope, signierte Action-Bindung, Budget und Store-Revalidierung                                                     | `manual_account_registration` plus signierte `external_action`-Entscheidung; nie automatisch erfüllt | `blocked`; lokale Simulation ohne Kontoerstellung                     | Block vor/nach jeder Stufe und während Runner; kein automatisches Fortsetzen |
| `email_verification_open` | `account_lifecycle`         | zukünftig `email_verification_capability`; derzeit kein Mailboxzugriff | festes Registry-Metadatum `http://127.0.0.1`; keine Mailverbindung  | aktuelle Policy/Kampagne/Scope, bereite Account-Evidence, signierte Bindung, Budget und Store-Revalidierung                                  | `email_verification` plus signierte `external_action`-Entscheidung                                   | `blocked`; nur In-Process-Mock                                        | Block vor/nach jeder Stufe und während Runner; Checkpoint bleibt menschlich  |
| `browser_journey_start`   | `browser_orchestrator`      | zukünftig `browser_profile`; derzeit kein Profil oder Sessionwert      | festes Registry-Metadatum `http://127.0.0.1`; kein Browsertransport | aktuelle Policy/Kampagne/Scope, bereite Account-Evidence, signierte Bindung, Budget und Store-Revalidierung                                  | `campaign_approval` plus signierte `external_action`-Entscheidung                                    | `blocked`; nur In-Process-Mock; Phase-7-Harness ist nicht registriert | Block vor/nach jeder Stufe und Runner-Abbruchsignal bei Engagement           |
| `target_request`          | `deterministic_test_runner` | zukünftig `test_identity_session`; derzeit keine Session               | festes Registry-Metadatum `http://127.0.0.1`; kein HTTP-Request     | aktuelle Policy/Kampagne/Scope, exakte Account-/Ownership-Evidence, nur `offline_inspect`, signierte Bindung, Budget und Store-Revalidierung | signierte `external_action`-Entscheidung und Policy-/Kampagnenfreigabe                               | `blocked`; ungefährliche In-Process-Antwort, kein aktiver Test        | Block vor/nach jeder Stufe; Evidence vor Start und Settlement erneut geprüft |
| `report_submit`           | `reporting`                 | zukünftig `platform_api_token`; derzeit kein Token                     | `external_disabled`; Host und Scheme `null`                         | vor Runner durch `simulationSupported: false` und deaktivierte externe Integration blockiert                                                 | `report_collective_approval`; lokale Approval ist keine Einreichung                                  | `blocked`; kein Runner, keine Einreichung                             | am Pipeline-Eingang blockiert; Kill Switch kann nie umgangen werden          |
| `triage_response_send`    | `triage_workspace`          | zukünftig `platform_api_token`; derzeit kein Token                     | `external_disabled`; Host und Scheme `null`                         | vor Runner durch `simulationSupported: false` und deaktivierte externe Integration blockiert                                                 | `triage_response_approval`; lokale Approval versendet nichts                                         | `blocked`; kein Runner, kein Versand                                  | am Pipeline-Eingang blockiert; Kill Switch kann nie umgangen werden          |

## Tatsächlich ausführbare lokale Browseraktion

Der Phase-7-Harness ist absichtlich keine Registry-Action. Seine auslösende
Komponente ist ausschließlich Playwright Test; er benötigt kein Secret, wählt
keinen Zielhost und startet selbst einen kurzlebigen Server auf
`127.0.0.1:0`. Die Policygrenze besteht aus festem Testgraph, Phase-1-Egress-
Guard, exaktem Schritt-Guard und unveränderlicher Demo-SaaS. Es gibt keinen
menschlichen Kontrollpunkt, weil keine externe oder produktive Aktion
stattfindet. Der Default außerhalb des expliziten Testkommandos ist
`nicht gestartet`; eine Integration in den Kill Switch oder die produktive
Runner-Registry existiert nicht und wird daher auch nicht behauptet.

## Reale Integrationen und Entwicklung

HackerOne-, Bugcrowd- und andere reale Plattformintegrationen existieren
nicht. Phase 7 fügt keine Kontoautomation, Regel- oder Bedingungsannahme,
CAPTCHA-Umgehung, Report-Einreichung, Triage-Antwort oder LLM-gesteuerte
Requestfähigkeit hinzu.

Während Entwicklung und Tests wurde kein realer Plattform-, HackerOne-,
Bugcrowd-, Beispiel- oder Bug-Bounty-Zielhost kontaktiert. Produkt-Netzwerk-
und Browsertests blieben vollständig in-process oder auf `127.0.0.1`
beschränkt.
