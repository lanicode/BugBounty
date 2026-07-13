# Phase-1-Betrieb

## Installation und Prüfung

```bash
pnpm install --frozen-lockfile
npm run doctor
npm run validate -- --config config/program.example.yaml
npm run policy:hash -- --config config/program.example.yaml
npm run typecheck
npm run lint
npm test
```

Die Beispielkonfiguration ist absichtlich nicht startfähig: `REPLACE_ME`, `example.com` und nicht akzeptierte Policy-Werte erzeugen einen harten Stopp. Validierung kann Strukturfehler melden, gibt aber keine Secrets oder Rohwerte aus.

## Lokale Mock-Tests

`npm run test:egress` startet kurzlebige HTTP-Server ausschließlich auf `127.0.0.1` mit vom Betriebssystem vergebenem Port. HTTP wird nur in expliziten Testkonfigurationen für Loopback akzeptiert. Es gibt keinen Recorder-Befehl für Live-Ziele.

## Schlüssel und Events

Der Produktionsadapter nutzt macOS Keychain über `/usr/bin/security`. Wenn Keychain nicht verfügbar ist, schlägt der Betrieb geschlossen fehl. Tests verwenden ausschließlich `InMemorySecretStore`. Eventdateien enthalten AES-256-GCM-Hüllen; Klartextbetrieb existiert nicht.

## Bewusst deaktiviert

Aktive Sicherheitstests, Crawling, Replay, Mutation, Login-/Account-Automation, HackerOne-/Plattformzugriff, Reporting, LLM-Requests, Service Worker, WebSockets, Redirect-Following, Multipart-/Form-Body-Persistierung und externe Recorder-Starts.

## Migration vom Demo-MVP

- Die nachträgliche Request-Beobachtung ist durch eine synchrone Pre-Request-Entscheidung und einen kontextweiten Playwright-Route-Guard ersetzt.
- Vollständige HAR-Aufzeichnung ist entfernt; der selektive Recorder persistiert ausschließlich redigierte, größenbegrenzte Events oder Hash-Metadaten.
- Die lose Hostliste ist durch Scheme-, Exact-Host-, Port-, Pfad-, Methoden-, Hostklassen- und Capture-Regeln ersetzt.
- Unverschlüsselte Profile/Eventdaten sind durch Keychain-Schlüssel und AES-256-GCM-Hüllen ersetzt. Browser-Auth-State selbst ist in Phase 1 nicht implementiert.
- Heuristische Kandidaten- und Reportfunktionen des MVP werden nicht übernommen; Phase 1 endet bewusst vor Analyse und Reporting.

## Betriebsgrenzen

Audit- und Event-Schreibzugriffe sind für genau einen lokalen Prozess ausgelegt. Eine prozessübergreifende Sperre, DNS-/Netzwerk-Namespace-Isolation, Ownership Ledger und signierte Vertragsverifikation gehören nicht zu Phase 1. Ohne diese Schichten gibt es keine Live-Freigabe.
