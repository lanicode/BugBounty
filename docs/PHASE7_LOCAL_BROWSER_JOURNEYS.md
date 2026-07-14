# Phase 7: geschlossene lokale Browserjourneys

## Zweck und Grenze

Phase 7 qualifiziert einen einzigen, deterministischen Browser-Referenzablauf
gegen die vorhandene read-only Demo-SaaS. Der gesamte Lauf liegt unter
`tests/browser`. Er ist weder Produktfunktion noch Implementierung der
registrierten zukünftigen External Action `browser_journey_start`.

Der Harness nimmt keine URL, keinen Port, keinen Locator und keinen freien
Schritt vom Caller entgegen. Er startet selbst eine frische Demo-SaaS auf
`127.0.0.1:0`, übernimmt den tatsächlich gebundenen ephemeren Port und baut
danach den Browserkontext. Reale Plattformen, Ziele, Konten, Secrets und
Browserprofile sind nicht beteiligt.

## Zweistufige Request-Grenze

```text
fester Rollen-/Schrittgraph
  -> exakte URL = http://127.0.0.1:<gestarteter Port><aktueller Pfad>
  -> Methode exakt GET
  -> Phase-1-Egress-Guard
  -> Demo-SaaS Host-/Peer-/Route-Prüfung
  -> feste JSON-Response
```

Der Schritt-Guard ist vor der ersten Page installiert und reicht eine exakt
erlaubte Anfrage mit `fallback` an den Phase-1-Egress-Guard weiter. Jeder
andere Origin, Port, Pfad, Query, Fragment, Userinfo oder jede andere Methode
wird abgebrochen. Redirects, WebSockets, Service Worker und Downloads werden
zusätzlich durch den bestehenden Guard blockiert. Unerwartete Pages, Frames,
Dialoge, Console-Fehler oder Page-Errors beenden den Lauf.

## Rollen- und Replaymodell

Die drei Profile sind geschlossene lokale Sichtfolgen:

- Owner: Service, Organisation, Projekte, Dokumente, Einladungen,
  Testobjekte, Policy, State.
- Member: Service, Organisation, Projekte, Dokumente, Testobjekte, Policy,
  State.
- External: Service, Organisation, Projekte, Policy, State.

Diese Auswahl modelliert ausschließlich einen deterministischen Replay-Plan.
Der Demo-HTTP-Server ist anonym und read-only; Phase 7 beansprucht deshalb
ausdrücklich keinen Authentisierungs- oder Autorisierungsnachweis. Jeder Plan
läuft in einem frischen Server und Context. Ein erster Durchgang Owner ->
Member -> External und ein zweiter External -> Member -> Owner müssen jeweils
identische Evidence-Digests ergeben.

## Responseprojektion

Jede Response muss Status 200, exakten Content-Type, exakte Security-Header,
kanonisches UTF-8-JSON, eine korrekte Content-Length und ein enges
Größenlimit erfüllen. Pro Route gilt ein exaktes Schema ohne Zusatzfelder.
Die Start- und Endresponse beweisen `mode: simulation` und
`externalIntegrationsEnabled: false`; die Demo-Revision und der kanonische
In-Process-Snapshot dürfen sich nicht verändern.

Rohbodys bleiben nur im Speicher und werden nach der Projektion genullt. Die
freigegebene Evidence enthält ausschließlich Rolle, Status, geplante und
beobachtete Counts, Statuscodes, Record-Counts, Response-Digests,
Screenshot-Digests und Byteanzahlen. Origin, Port, Header, Bodywerte,
Identitätsreferenzen, Titel und Canaries fehlen.

## Visuelle Redaktionsgrenze

Automatische Playwright-Screenshots, Traces, Videos und Page-Snapshots sind in
der Config deaktiviert. Für jeden Zustand wird genau ein Screenshot ohne
Dateipfad erzeugt:

1. Rolle und Zustand werden gegen geschlossene Enums und die Rollenmatrix
   geprüft.
2. Ein einzelnes, exakt viewportfüllendes 1280×720-Maskenelement wird
   verifiziert.
3. Playwright übermalt dieses Element mit einer ausschließlich aus Rolle und
   Zustand abgeleiteten opaken Farbe.
4. Der PNG-Container muss Größe, Signatur, Dimensionen, CRCs und die
   Chunk-Allowlist `IHDR`/`IDAT`/`IEND` erfüllen. Text-, EXIF- und unbekannte
   Chunks blockieren.
5. Nur SHA-256 und Byteanzahl werden freigegeben; der Buffer wird bei Erfolg
   und Fehler genullt.

Eine zusätzliche Probe ersetzt den darunterliegenden DOM-Inhalt durch einen
bekannten Secret-Marker. Der Digest muss bei identischer Rolle und identischem
Zustand unverändert bleiben. Die Farbe macht den Screenshot-Digest
zustandsgebunden, enthält aber bewusst keine Roh-UI. Das ist ein
Redaktionsnachweis, keine visuelle Produktaufnahme.

## Ausführung

```sh
pnpm test:browser
```

Der Runner arbeitet seriell mit einem Worker, ohne Retries. `trace`,
`screenshot` und `video` stehen auf `off`; `preserveOutput` steht auf `never`.
Die Config setzt die Playwright-Page-Snapshot-Sperre selbst und blockiert einen
widersprechenden Umgebungswert vor Browserstart. Nach einem erfolgreichen Lauf
bleibt unter `.local/phase7-playwright` ausschließlich `.last-run.json` mit
nicht sensitiven Runner-Metadaten.

## Bewusst nicht implementiert

- produktiver Browser- oder External-Action-Runner;
- freie Ziele, URLs, Schritte, Scripts oder Locator-Healing;
- Anmeldung, Cookies, Local-/Session-Storage oder Storage-State;
- Account-Erstellung, Regeln, Bedingungen, CAPTCHA oder rechtliche Schritte;
- aktive Tests, Mutationen, Crawling, Replay realer Requests oder Reports;
- persistierte PNG-Evidence oder Pixelinterpretation der komprimierten IDAT-
  Daten;
- serverseitiger Rollen-/Mandanten-Autorisierungsnachweis.
