# Phase 8 – erster lokaler Start

## 1. Installieren und starten

Im Repository sind nur zwei Terminalbefehle nötig:

```sh
pnpm install --frozen-lockfile
pnpm app
```

Die Anwendung startet Control Plane, Dashboard und Demo-SaaS ausschließlich
auf `127.0.0.1`. Das Terminal zeigt:

- Dashboard-URL;
- Demo-SaaS-URL;
- `local_setup_shell` oder `local_simulation`;
- External-Integration-Status `disabled`;
- AIProvider-Status `disabled_not_implemented`;
- Kill-Switch-Status `active`;
- Hinweis, dass keine reale Einreichung möglich ist.

Bevorzugte Dashboard-URL ist
[http://127.0.0.1:4173](http://127.0.0.1:4173). Ist Port 4173 belegt, gilt
die im Terminal ausgegebene ephemere Loopback-URL.

## 2. Erwarteter Erstzustand

Ohne zuvor eingerichtete Keychain-Credentials ist `local_setup_shell` der
erwartete sichere Zustand. Der Event Store wird nicht konstruiert, positive
persistierende Core-Routen sind blockiert und der Kill Switch bleibt aktiv.
Der flüchtige Guided-Flow ist verfügbar, solange System, Datenbank und
Demo-SaaS `ready` und der Secret Store nur `setup_required`, nicht `blocked`,
sind. Es gibt keinen Klartext- oder In-Memory-Secret-Fallback.

Eine vollständig validierte macOS-Keychain-/Operator-Konfiguration schaltet
den Modus `local_simulation` frei. Der verschlüsselte Event Store wird dann
nur bei Bedarf sicher geöffnet. Phase 8 fordert keine echten Tokens,
Passwörter, Cookies, TOTP-, E-Mail- oder Browser-Sessions an.

## 3. Guided-Flow starten

Im Dashboard zunächst die drei permanenten Banner prüfen:

- `SIMULATIONSMODUS`;
- `EXTERNE INTEGRATIONEN DEAKTIVIERT`;
- `KEINE REALE REPORT-EINREICHUNG`.

Danach den jeweils angezeigten Hauptbutton verwenden. Der Ablauf umfasst:

1. sieben Onboarding-Schritte;
2. Programm und lokale Policy-Fixture;
3. ausdrückliche Policy-Annahme;
4. Kampagnenvertrag und ausdrückliche Freigabe;
5. drei Demo-Identitäten und optionale lokale Fixture-Sessions;
6. geschlossene 20-Schritt-Journey-Projektion;
7. Inventory, Ownership, Canary und Kandidat;
8. lokale Verifikation, Evidence und Report;
9. lokale Review Queue und ausdrückliche lokale Freigabe.

Die sichere UI erlaubt zwei Testmail-Schemas, zwei Programmnamen, eine
optionale Admin-Asset-Exclusion, lesbare oder strukturierte Policy-Fixture,
Budgets 0/4/8 und RPM 0/1/2. Policy v1, Tier 0 und Parallelität 1 sind fest.
Der Evidence-Fall benötigt alle Rollen Owner, Member und External; Teilmengen
werden fail-closed blockiert.

## 4. Journey und Ergebnis

Die einzige Journey heißt `phase7-local-demo-role-boundary`. Das Produkt
projiziert den gemeinsamen gepinnten Katalog mit 8 Owner-, 7 Member- und 5
External-Schritten. Es startet keinen Browser und sendet keine Requests.
Nach Abschluss der Inventur öffnet „Journey-Ergebnis öffnen“ die lokale
Zusammenfassung.

## 5. Evidence und Report

Evidence bindet die validierte Demo-SaaS-Projektion, drei Rollen, Journey-ID
und -Digest, Ownership, Canary-Digest, lokale Policy, Demo-Policy und
Auditreferenz. Markdown, HTML und JSON lassen sich lokal als Text öffnen. Der
Report wird nur in eine flüchtige lokale Review Queue gelegt.

Ändert sich die Demo-SaaS während des Ablaufs, zeigt das Dashboard
`blocked_demo_drift`, sperrt Aktionen und Vorschauen und markiert Evidence
und Report als `stale_blocked`. In diesem Fall App mit `Ctrl-C` beenden und
`pnpm app` erneut starten.

## 6. Beenden

Im startenden Terminal `Ctrl-C` drücken. Dashboard und Demo-SaaS werden
gemeinsam geschlossen. Ein Neustart setzt den Guided-State zurück und
aktiviert den Kill Switch erneut.
