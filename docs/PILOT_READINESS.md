# Pilot Readiness

## Aktuelle Entscheidung: Pilot Readiness C

**Technisches GO für einen eng begrenzten, menschlich kontrollierten
Active-Testing-Pilot – kein GO für allgemeines oder autonomes Scanning.**

Die einzige neue Zielrequest-Capability besteht aus den drei fest verdrahteten
Klassen `http_headers` (`HEAD`), `cors_preflight` (`OPTIONS`) und
`security_txt` (`GET /.well-known/security.txt`). Sie ist standardmäßig aus,
verwendet nur exakte HTTPS-URL-Assets aus einem aktuellen authentifizierten
HackerOne-API-Snapshot und benötigt lokale Snapshotannahme, vier manuelle
Regelbestätigungen, einen serverseitigen Plan, eine frische signierte
Planfreigabe und einen separaten Startklick. Jeder Plan erlaubt einen Request,
keinen Redirect und keinen Retry. DNS, TLS, Scope, Policy, Budget und Kill
Switch werden fail-closed geprüft. Evidence bleibt redigiert; Reports bleiben
lokale Entwürfe.

Dieses technische GO ersetzt keine Programmregeln oder rechtliche Prüfung.
Der Operator darf es nur für ein Programm und ein Asset verwenden, für das er
selbst die aktuelle Automationsberechtigung geprüft hat. Account-, Login-,
Credential-, Schreib-, Exploit-, CAPTCHA-/Anti-Bot-, LLM- und Submission-
Automation bleiben **NO-GO**. Details und Stopkriterien stehen in
`docs/ACTIVE_TESTING_USER_GUIDE.md`.

## Historische Entscheidung: Phase-8-Fixture-Pilot

Der folgende Abschnitt dokumentiert weiterhin das frühere technische GO für
den rein lokalen Fixture-only-Usability-Pilot. Aussagen über fehlende
Zielrequests beziehen sich auf diesen Phase-8-Ablauf, nicht auf die getrennte
Pilot-C-Capability.

### Qualifizierter Phase-8-Umfang

Der Pilot darf ausschließlich:

- einen lokalen Checkout des Phase-8-Branches verwenden;
- `pnpm app` starten;
- die ausgegebenen `127.0.0.1`-URLs öffnen;
- den 21-Schritt-Guided-Flow mit den eingebauten Fixtures bedienen;
- Managementaktionen und fail-closed Abbruchzustände prüfen;
- lokale Evidence- und Reportvorschauen ansehen;
- den Prozess mit `Ctrl-C` beenden.

Es dürfen keine echten Secrets, Accounts, Sessions, URLs, Objekt-IDs,
Policies, Reports oder Zielinformationen eingegeben werden.

### Nachgewiesene Phase-8-Gates

| Gate                                     | Status             |
| ---------------------------------------- | ------------------ |
| Typecheck / Lint / Format / Build        | GO                 |
| 518/518 Gesamttests                      | GO                 |
| 40/40 Property-Tests                     | GO                 |
| 79/79 Integrationstests                  | GO                 |
| 15/15 Egress-Regressionen                | GO                 |
| 12/12 Platform-Source-Tests              | GO                 |
| 2/2 Phase-7-Playwright-Replays           | GO                 |
| Coverage 88,64/84,01/96,69/89,84 %       | GO                 |
| Keine bekannte Dependency-Schwachstelle  | GO                 |
| Loopback-App-Smoke und sauberer Shutdown | GO                 |
| Phase-1-Security-Core-Diff leer          | GO                 |
| Unabhängiges Security-Re-Review          | GO / keine Blocker |

### Phase-8-Pilot-Szenario

1. Branch und sauberen Repositoryzustand prüfen.
2. `pnpm install --frozen-lockfile` und `pnpm app` ausführen.
3. Startausgabe auf Loopback, Runtime-Modus, External/AI deaktiviert und Kill
   Switch aktiv prüfen.
4. Drei permanente Sicherheitsbanner prüfen.
5. Sieben Onboarding-Schritte durchführen.
6. sichere UI-Auswahl testen; Teilrollenauswahl muss blockieren.
7. Policy-Quelle, Inhalt, Hash und vollständigen Diff prüfen.
8. alle ausdrücklichen Kontrollpunkte einzeln auslösen.
9. 20 Journey-Katalogschritte und Ergebnis-Button prüfen.
10. Inventory, Ownership, Canary-Digest und Kandidatenbudget 0/X prüfen.
11. Evidence-Bindungen und Markdown-/HTML-/JSON-Vorschau prüfen.
12. lokale Review Queue und lokale Freigabe abschließen.
13. bestätigen, dass Core-Zähler durch den Guided-Flow unverändert bleiben.
14. optional einen lokalen Demo-Drift-Test ausführen; UI muss `stale_blocked`
    und die Neustart-Anweisung zeigen.
15. `Ctrl-C` und geschlossene Ports prüfen.

### Phase-8-Sofortige Stopkriterien

Pilot abbrechen, wenn:

- eine ausgegebene oder angefragte URL nicht `127.0.0.1` ist;
- eine der drei Sicherheitskennzeichnungen fehlt;
- External Integrations oder AI nicht deaktiviert erscheinen;
- der Guided-Flow eine freie URL, ID, Locator, Script oder Credential annimmt;
- ein Kontrollpunkt automatisch bestätigt wird;
- bei Demo-Drift Aktionen, Evidence oder Report weiter nutzbar bleiben;
- der Produktpfad einen Browser, Request oder externe Submission startet;
- eine Sicherheitsprüfung deaktiviert, gelockert oder übersprungen werden
  müsste.

### Für den Phase-8-Pfad weiterhin NO-GO

- reale Bug-Bounty-Programme, Plattformen und Zielhosts außerhalb der
  getrennten Pilot-C-Grenze;
- aktive Tests, Scanner oder Tier-1+-Runner außerhalb der drei geschlossenen
  Pilot-C-Einmaltestklassen;
- reale Registrierung, Login oder Account-Automation;
- CAPTCHA-, Anti-Bot-, E-Mail-, TOTP- oder rechtliche Automation;
- AI-/LLM-Verarbeitung;
- externe Report-Einreichung oder Kommunikation;
- Multi-User-, Netzwerkdateisystem- oder Remote-Betrieb;
- dauerhafte Verwendung des Guided-State als produktive Datenbank.

### Freigabeverantwortung

Der technische Nachweis bestätigt nur Reproduzierbarkeit und lokale
Sicherheitsgrenzen. Datenschutz, interne Richtlinien, Pilotteilnehmende,
Arbeitsplatzschutz und Abnahmeprotokoll bleiben organisatorische Aufgaben.
