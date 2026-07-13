# Phase-3-Acceptance-Criteria: Store-gebundener Action-Evaluator

## Verbindlicher Umfang

Phase 3 implementiert ausschließlich den persistenzgebundenen
External-Action-Evaluator aus `docs/PHASE3_RECOMMENDATION.md`. Reale
Plattformadapter, echte Accounts, E-Mail-/TOTP-/CAPTCHA-Automation, aktive
Sicherheitstests, Report-Einreichung, Triage-Nachrichten, LLM-gesteuerte
Requests und Verbindungen zu realen Zielen bleiben außerhalb des Scopes.

`external_integrations_enabled` bleibt unabhängig von Konfiguration und
Secrets effektiv `false`. Der einzige ausführbare Runner bleibt der
deterministische Loopback-Mock-Runner.

## Funktionale Sicherheitskriterien

1. Die Phase-2-Baseline ist in `docs/PHASE2_BASELINE.md` exakt fixiert; der
   geschützte Phase-1-Pfaddiff bleibt leer.
2. Schema-Validierung, geschlossene Registry, externer Modus und
   Runner-Branding werden geprüft, bevor persistierte Evidence eine Wirkung
   haben kann.
3. Caller-konstruierte Booleans, Callback-Gates, Proxies und
   Prototype-Spoofs können keinen Runner freigeben.
4. Eine positive Entscheidung entsteht ausschließlich in genau einer
   `BEGIN IMMEDIATE`-Transaktion aus einem aktuellen `ControlPlaneStore`-
   Snapshot.
5. Der Snapshot bindet den vollständigen kanonischen Vorschlag an Programm,
   aktuelle akzeptierte Policy und Hash, Kampagnen-ID und Revision,
   vollständigen Kampagnendigest, erlaubte und ausgeschlossene Assets,
   Account-Rolle, Ownership-Objekt, Payload-Referenz, Registry-Zielklasse und
   Operatorlabel.
6. `scope_ref` ist ein deterministischer Digest der aktuellen fachlichen
   Evidence und kein frei interpretierter String.
7. Eine strukturierte, akzeptierte Approval-Evidence ist exakt an Proposal,
   Operator, Policy, Kampagnenrevision, Scope, Account, Objekt und Payload
   gebunden. Freitextsuche gilt nicht als Autorisierung.
8. Proposal-IDs sind persistent single-use. Budget und aktive Reservationen
   gelten über Prozess- und Store-Neustarts hinweg; fehlgeschlagene oder
   abgebrochene Runner-Starts werden nicht automatisch erstattet.
9. Vor Runner-Start und nach Runner-Rückkehr werden Store-Evidence und Kill
   Switch erneut fail-closed validiert. Ein Crash hinterlässt eine blockierende
   Reservation statt einer stillen Freigabe.
10. Fehlende, alte, manipulierte, abgelaufene oder nicht atomar lesbare
    Evidence blockiert. Datenbank- und Secret-Fehler blockieren ebenfalls.
11. `report_submit`, `triage_response_send`, externer Modus, unbekannte
    Aktionen und nicht gebrandete Runner bleiben unabhängig von vorhandener
    Evidence blockiert.
12. Es werden keine Secrets, Rohbodys, Cookies, Tokens oder Eventdaten in den
    neuen Evidence- und Attempt-Tabellen gespeichert.

## Nachweiskriterien

- Unit-Tests decken jede Evidence-Dimension, Replay, Budget, Zustandswechsel,
  Approval-Audit und alle Registry-Aktionen ab.
- Property-Tests mutieren Proposal- und Evidence-Bindungen; jede Abweichung
  blockiert vor dem Runner.
- Lokale SQLite-Integrationstests beweisen Migration, Reopen, persistentes
  Budget, Replay-Schutz, Drift und Kill-Abbruch.
- Statische Import-Boundary-Tests beweisen, dass kein HTTP-, Browser-, DNS-,
  Socket-, Child-Process- oder LLM-Transport ergänzt wurde.
- Typprüfung, ESLint ohne Warnungen, Formatprüfung, Build, Gesamtsuite,
  Coverage, Phase-1-Egress und Platform-Source-Regression bestehen ohne
  deaktivierte Tests.
- Netzwerk- und Browsertests verwenden ausschließlich In-Process-Mocks oder
  `127.0.0.1`.

## Bewusst verbleibende Grenze

Das persistierte Operatorlabel ist in diesem Schritt noch keine lokal
authentifizierte oder kryptografisch signierte Identität. Deshalb bleiben reale
Runner auch nach Erfüllung dieser Kriterien deaktiviert.
