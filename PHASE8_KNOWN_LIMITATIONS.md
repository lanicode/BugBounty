# Phase 8 – bekannte Einschränkungen

## Produktumfang

Phase 8 ist ein nutzbarer lokaler Fixture-Pilot, aber kein Live-Scanner. Der
21-Schritt-Guided-Flow bleibt bewusst ein flüchtiger In-Memory-
Präsentationszustand. Er erzeugt keine persistenten Programme, Kampagnen,
Approvals oder Reports im Security Core und erteilt diesem keine
Autorisierung. Der vorhandene signierte 18-Schritte-Core-Simulator ist ein
getrennter fortgeschrittener Pfad.

Programm-, Asset-, Policy- und Kampagnenverwaltung sind whitelistgebundene
lokale Fixtures, kein allgemeines CRUD. „Policy importieren“ bedeutet Import
einer eingebauten lesbaren oder strukturierten Seed-Fixture; freie Texte,
Dateien und entfernte Quellen sind nicht vorgesehen. Der feste
Baseline/Test/Kontrolltest-Fall benötigt alle drei Rollen Owner, Member und
External.

## Runtime und Persistenz

- `local_setup_shell` benötigt keine Secrets, konstruiert keinen Event Store
  und sperrt alle positiven persistenten Core-Routen.
- `local_simulation` setzt eine vollständig validierte macOS-Keychain- und
  Operator-Konfiguration voraus; der verschlüsselte Event Store wird erst bei
  Bedarf geöffnet.
- Guided-State geht beim Neustart verloren. Die SQLite-Control-Plane bleibt
  lokal persistent; der Start aktiviert den Kill Switch erneut.
- Der bevorzugte Dashboard-Port 4173 kann belegt sein. Dann wird ein
  ausgegebener ephemerer Loopback-Port verwendet.
- Die Statusseite pollt alle zwei Sekunden, ist aber kein allgemeines
  Prozess-Supervisionssystem. Ein Datenbankfehler lässt den State-Request
  fail-closed scheitern; Demo-Inhaltsdrift wird explizit erkannt.

## Journey und Browser

Das Produkt startet keinen Browser. Es projiziert die 20 Schritte des
gepinnten Owner-/Member-/External-Katalogs nur als Metadaten. Die getrennte
Phase-7-Testsuite beweist den tatsächlichen Loopback-Replay; dieses Ergebnis
ist keine Aussage über reale Authentisierung oder serverseitige
Autorisierung.

Freie URLs, Locators, Scripts, Browserbefehle, unbekannte IDs, Redirects und
freie HTTP-Requests sind nicht verfügbar. Der Request-Budgetwert des
Kandidaten ist Vertragsmetadatum; `consumed` bleibt 0, weil das Produkt keine
Requests ausführt.

## Evidence und Reporting

Evidence besteht aus redigierten Fixture-Metadaten, nicht aus realem
Schwachstellennachweis. Keine Rohbodys, HARs, Auth-State-Dateien oder
Screenshotbytes werden persistiert. Der Bundle-Digest schützt Konsistenz,
ersetzt aber weder unabhängige Reproduktion noch menschliche Bewertung.

Demo-SaaS-Drift nach Erzeugung entwertet Evidence und Report als
`stale_blocked`; ein Neustart ist erforderlich. Markdown, HTML und JSON sind
lokale Vorschauen. Die HTML-Fassung wird als Text angezeigt und nicht als
aktiver Browserinhalt gerendert.

## Bewusst deaktiviert

- reale Bug-Bounty- und Plattformadapter;
- externe Integrationen und External-Action-Runner;
- aktive Sicherheitstests und neue Scan-Engine;
- echte Registrierung, Anmeldung und Account-Automation;
- CAPTCHA-, Anti-Bot-, E-Mail-, TOTP- oder rechtliche Automation;
- AI-/LLM-Provider und LLM-gesteuerte Requests;
- automatische Zustimmung zu Policies, Regeln oder Bedingungen;
- externe Report-Einreichung;
- allgemeiner HTTP- oder Browserclient im Produkt.

## Betriebsrisiken

Der Keychain-basierte sichere Core-Pfad ist macOS-spezifisch. Phase 8 liefert
bewusst keine automatische Key-Provisionierung und keinen Secret-tragenden
Shell-Einzeiler. Lokale Benutzer mit Zugriff auf Rechner, Browser oder
Laufzeitverzeichnis liegen außerhalb des Produkt-Sandboxmodells. Vor einem
internen Pilot müssen Repositoryzustand, ausgegebene URLs, Kill-Switch-Status
und die drei dauerhaften Sicherheitsbanner geprüft werden.

## Verifizierter Abschlussstand

Der finale Lauf bestand 518/518 Gesamttests, 40/40 Property-Tests, 79/79
Integrationstests, 15/15 Egress-Regressionen, 12/12 Platform-Source-Tests und
2/2 Playwright-Replays. Die Abdeckung beträgt 88,64 % Statements, 84,01 %
Branches, 96,69 % Functions und 89,84 % Lines. Der Dependency-Audit fand
keine bekannte Schwachstelle. Diese Werte qualifizieren ausschließlich den
lokalen Fixture-Umfang.
