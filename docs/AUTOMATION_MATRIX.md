# Automatisierungsmatrix

## 1. Programm auswählen und Regeln akzeptieren

Automatisierbar:

- Programme über offizielle Plattform-APIs synchronisieren.
- Policy, strukturierte Scopes, Ausschlüsse und Änderungen abrufen.
- Programme nach erwarteter Erfolgswahrscheinlichkeit, Duplikatrisiko, Technik-Fit und Aufwand bewerten.
- Policy in maschinenlesbare Regeln kompilieren.
- Policy-Version hashen, archivieren und bei Änderungen Kampagnen automatisch stoppen.
- Annahmeseite vorbereiten und nur die geänderten Klauseln anzeigen.

Verbleibender Mensch:

- Ein ausdrücklicher Klick für neue oder geänderte Regeln.

## 2. Zwei eigene Konten erstellen

Automatisierbar:

- Eigene E-Mail-Aliase erzeugen.
- Passwörter im lokalen Secret Store erzeugen und einsetzen.
- Registrierungsformulare ausfüllen.
- Verifikationslinks aus einem eigenen Postfach lesen und auf Host-Allowlist prüfen.
- TOTP lokal erzeugen, wenn der Dienst dies zulässt.
- Getrennte Browserzustände erzeugen und erneuern.
- Testorganisationen, Rollen und markierte Testobjekte anlegen.
- Konten und Daten nach Kampagnenende aufräumen.

Verbleibender Mensch:

- CAPTCHA, Identitätsprüfung oder ausdrückliche Nutzungsbedingungen.

## 3. Anwendung normal bedienen

Automatisierbar:

- Einen Referenzablauf aufzeichnen und für alle eigenen Konten wiederholen.
- Playwright-Testpläne automatisch generieren und bei UI-Änderungen heilen.
- Einen sicheren UI-Zustandsgraphen erzeugen.
- Nur Navigation und vorab klassifizierte reversible Aktionen ausführen.
- Testdaten mit eindeutigen Canaries anlegen.
- JavaScript, OpenAPI und GraphQL-Artefakte passiv inventarisieren.

Verbleibender Mensch:

- Nur unbekannte, mehrdeutige oder sensible UI-Aktionen klassifizieren.

## 4. HTTP-Verkehr lokal aufzeichnen

Automatisierbar:

- Requests vor dem Versand durch einen Egress Guard prüfen.
- Out-of-Scope-Verkehr technisch abbrechen.
- Notwendige Drittanbieter nur als unterstützende Hosts zulassen.
- Daten vor der Persistierung pseudonymisieren.
- Binärinhalte nur hashen und große Antworten abschneiden.
- Zielbezogene WebSocket-Frames redigiert erfassen.
- Ereignisse in ein lokales, verschlüsseltes Event-Format schreiben.

Verbleibender Mensch:

- Keiner im Normalfall.

## 5. Kandidaten prüfen

Automatisierbar:

- Endpunkte, Parameter und Datenflüsse normalisieren.
- IDs und Eigentumsbeziehungen aus Testobjekten lernen.
- Konto-, Rollen- und Tenant-Unterschiede vergleichen.
- Response-Schemas statt bloßer Längen vergleichen.
- Kandidaten durch deterministische Regeln vorfiltern.
- KI nur für Hypothesen, Priorisierung und Erklärung einsetzen.
- Einen Minimaltest aus einem beobachteten Baseline-Request erzeugen.
- Nur eine Variable zwischen zwei eigenen Objekten ändern.
- Positiv-, Negativ- und Rollback-Kontrollen automatisch ausführen.

Verbleibender Mensch:

- Nur Tier-3-Fälle oder uneindeutige Eigentumsnachweise.

## 6. Pro Kandidat freigeben

Automatisierbar:

- Per-Kandidat-Klick durch einen einmalig signierten Kampagnenvertrag ersetzen.
- Niedrig riskante Tests automatisch zulassen, sofern Host, Pfad, Methode, Konto, Objekt, Budget und Policy-Hash passen.
- Jede Entscheidung unveränderlich protokollieren.
- Bei Policy-Drift, 429/503, fremden Daten oder Budgetüberschreitung automatisch stoppen.

Verbleibender Mensch:

- Eine Kampagnenfreigabe sowie Einzelfreigaben für sensible Tier-3-Tests.

## 7. Fremde Daten ausschließen

Automatisierbar:

- Jedes eigene Testobjekt mit einer eindeutigen Canary markieren.
- Vor dem Request alle Objekt-IDs gegen ein Ownership Ledger prüfen.
- Antworten auf unbekannte Nutzer-, Tenant-, E-Mail-, Zahlungs- und Identitätsdaten prüfen.
- Nur Diffs und Canary-Nachweise an die KI weitergeben.
- Verdächtige Antworten lokal verschlüsselt quarantänisieren.
- Gesamte Kampagne beim ersten Datenschutzsignal stoppen.

Verbleibender Mensch:

- Nur Quarantänefälle bewerten.

## 8. Bericht einreichen

Automatisierbar:

- Evidenz, Zeitstempel, Hashes, Reproduktionsschritte und Impact zusammenführen.
- CWE/VRT/Severity konservativ vorschlagen.
- Eigene Datenbank und öffentliche Meldungen auf mögliche Duplikate prüfen.
- Plattformfelder und Anhänge über offizielle APIs vorbereiten.
- Report-Entwürfe automatisch anlegen.
- Bei HackerOne kann ein Adapter offizielle Hacker-API-Endpunkte für Reports oder Report Intents verwenden.
- Neue Triage-Aktivität überwachen und Antwortentwürfe erstellen.

Verbleibender Mensch:

- Empfohlen: eine tägliche oder wöchentliche Sammelfreigabe. Vollautomatische Einreichung ist technisch möglich, aber reputations- und qualitätskritisch.
