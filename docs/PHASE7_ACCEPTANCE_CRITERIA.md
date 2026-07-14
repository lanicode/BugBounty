# Phase-7-Acceptance-Criteria: lokale Browserjourneys

Stand: 14. Juli 2026

Baseline: `baaa8a8d4b7b332cc2d6ddf84a259fa0366f9e28`

## Geschlossener Umfang

Phase 7 qualifiziert genau einen deterministischen, read-only
Playwright-Testablauf gegen frische Instanzen der vorhandenen Demo-SaaS. Der
Ablauf ist Testinfrastruktur und wird nicht als produktiver
`browser_journey_start`-Runner registriert. Reale Plattformen, Konten,
Zielhosts, Berichte und externe Browserprofile bleiben deaktiviert.

## Netzwerk- und Browsergrenze

1. Jeder Server bindet ausschließlich und explizit an `127.0.0.1` mit einem
   vom Betriebssystem vergebenen Port.
2. Der Browserkontext wird vor der ersten Seite durch den bestehenden
   Phase-1-Egress-Guard geschützt.
3. Zusätzlich erlaubt der Journey-Harness nur den exakten Demo-Origin, `GET`
   und die fest einkompilierten kanonischen Routen des jeweiligen
   Rollengraphen.
4. Beliebige Caller-URLs, `localhost`, IPv6, Userinfo, Query, Fragment,
   Redirect, WebSocket, Service Worker, Download, Popup, fremde Ports und
   nicht gelistete Pfade blockieren fail-closed.
5. Die Tests müssen anhand der tatsächlich beobachteten Requests beweisen,
   dass kein anderer Origin und keine andere Methode verwendet wurde.
6. Der Port stammt ausschließlich von der soeben gestarteten Demo-Instanz.
   Die ungeschützten Playwright-`page`- und `context`-Fixtures sind im
   Phase-7-Testcode verboten.
7. Neue Seiten, Popups, Dialoge, Downloads, Frames, unerwartete Fetches,
   Console-Fehler und Page-Errors brechen den Lauf ab. Request-, Seiten-,
   Laufzeit- und Screenshotgrößen sind hart begrenzt.

## Geschlossener Rollen- und Zustandsgraph

1. Zulässige Rollen sind ausschließlich `Owner`, `Member` und `External` aus
   den lokalen Demo-Fixtures.
2. Der Harness wählt für jede Rolle eine unveränderliche, azyklische und
   endliche Routefolge; Caller können weder Schritte noch Locators oder URLs
   ergänzen.
3. Die Rollenansicht ist ausdrücklich ein lokales Replay-Profil und kein
   Authentifizierungs- oder Autorisierungsnachweis des anonymen read-only
   Demo-HTTP-Servers.
4. Zwei vollständig isolierte Läufe derselben Rolle müssen nach Entfernung
   des ephemeren Ports dieselbe kanonische Evidence und denselben Digest
   erzeugen.
5. Rollenübergreifende Unterschiede müssen der dokumentierten lokalen
   Capability-Matrix entsprechen. Es werden keine mutierenden Requests
   ausgeführt.
6. Start- und Endzustand müssen `mode: simulation`,
   `externalIntegrationsEnabled: false` und dieselbe Demo-Revision beweisen.
   Cookies, Local Storage und Session Storage müssen leer bleiben.

## Evidence- und Screenshotgrenze

1. Rohantworten werden nur im Speicher validiert und weder geloggt noch
   persistiert.
2. Evidence enthält ausschließlich geschlossene Enumwerte, Statuscodes,
   Anzahlen, Inhaltsdigests und eine kanonische Gesamtsumme; keine Titel,
   Anzeigenamen, Identitätsreferenzen, Canaries, Cookies, Header oder Bodys.
3. Automatische Playwright-Screenshots, Traces, Videos, HARs, Attachments und
   Storage-State-Dateien sind deaktiviert.
4. Ein Screenshot darf nur im Speicher entstehen, nachdem ein opaker,
   vollständig viewportfüllender Redaktions-Layer aus ausschließlich
   statischen, validierten Labels erfolgreich verifiziert wurde.
5. Vom Screenshot verlassen ausschließlich SHA-256 und Byteanzahl die
   Redaktionsfunktion. Die PNG-Bytes werden nie mit einem Pfad erzeugt,
   anschließend überschrieben und nicht an den Testreporter angehängt.
6. Zwei Seiten mit unterschiedlichem darunterliegendem Inhalt müssen bei
   identischem sicheren Label denselben redigierten Screenshot-Digest
   erzeugen.
7. PNG-Signatur, feste Abmessungen und ein enges Byte-Limit werden vor der
   Digestfreigabe geprüft. Text-, EXIF- und unbekannte PNG-Metadaten-Chunks
   blockieren; die Bytes werden auch im Fehlerfall nicht ausgegeben.
8. `toHaveScreenshot()` ist verboten, weil es rohe Actual-/Diff-Artefakte
   erzeugen kann.

## Test- und Qualitätskriterien

1. Playwright Test läuft headless, seriell, ohne Retries und ohne bei Fehlern
   erzeugte Browserartefakte.
2. Der Test importiert ausschließlich eine eigene lokale Fixture, die intern
   den Browser-Fixture nutzt und Server, Guard, Context und Page vollständig
   kapselt. Produktive `apps/` und `packages/` erhalten keinen Browserstart.
3. Direkte Unit-Tests decken Origin-, Rollen-, Pfad-, Graph- und
   Evidenceschema-Validierung ab.
4. Property-Tests beweisen, dass beliebige nicht exakt gelistete Rollen,
   Origins, Methoden und Routen keinen zulässigen Schritt erzeugen.
5. Lokale Browserintegration beweist A/B-Determinismus, alle drei
   Rollenprofile, Redaktionsinvarianz und die unveränderte Demo-Revision.
6. Lokale Browserintegration beweist außerdem, dass ein zweiter
   Loopback-Server auf einem nicht freigegebenen Port exakt null Requests
   erhält.
7. Typprüfung, Linting, Formatprüfung, Build, Unit-, Property-, Integrations-,
   Egress-, Browser- und vollständige Phase-1-Regressionssuite laufen grün.
8. Keine Tests werden deaktiviert, übersprungen, gelockert oder durch Retries
   grün gemacht.
9. Coverage unterschreitet keine vorhandene Schwelle.
10. Der geschützte Phase-1-Pfaddiff bleibt leer. Jede Abweichung würde einen
    eigenen Security-Core-Commit, Regressionstests und Dokumentation
    erfordern.

## Nicht Teil von Phase 7

- produktiver Browserorchestrator oder allgemeiner URL-/HTTP-Client;
- LLM-gesteuerte Navigation, Locator-Healing oder neue Berechtigungen;
- echte Anmeldung, Cookies, Auth-State, Browserprofile oder Account-Automation;
- mutierende Demo-SaaS-HTTP-Routen oder aktive Sicherheitstests;
- Plattformadapter, HackerOne, Bugcrowd, Zielhosts oder Report-Einreichung;
- automatische Regel-, Bedingungs-, Rechts- oder Reportzustimmung;
- persistierte Screenshots oder unverschlüsselte Eventdaten;
- externe Aktion außerhalb der bestehenden Proposal-zu-Runner-Kette.
