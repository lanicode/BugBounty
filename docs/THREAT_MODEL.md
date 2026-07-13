# Threat Model – Phase 1

## Schutzgüter

Scope-Grenzen, akzeptierter Policy-Hash, Kampagnenvertrag, lokale Schlüssel, pseudonymisierte Eventdaten, Audit-Integrität und der Nachweis, dass kein Request vor einer Freigabeentscheidung versendet wird.

## Angreifer und Fehlerquellen

- Manipulierte oder missverständliche YAML-/JSON-Konfiguration.
- URL-Tricks mit Userinfo, DNS-Suffixen, IDN, abschließenden Punkten, IPv6, Ports und mehrfacher Kodierung.
- Browser-Unterkanäle wie Frames, Popups, Fetch/XHR, Formulare, Redirects, Service Worker und WebSockets.
- Secret- und PII-Lecks über Header, Query, JSON, Freitext, Fehler oder Debug-Ausgaben.
- Dateimanipulation, Nonce-Wiederverwendung, Teilwrites und zu offene Dateirechte.
- Policy-Drift, abgelaufene Verträge, Budget-Rennen und ein nicht reagierender Worker.

## Kontrollen

Strikte JSON-Schemas ohne Zusatzfelder, semantische Platzhalter-/Secret-Prüfung, kanonisches SHA-256, synchrone Egress-Entscheidung, exact-match Scope, Pre-Disk-Redaktion, HMAC-Pseudonyme, AES-256-GCM mit eindeutigen Zufallsnonces, atomare Dateien mit Modus `0600`, Audit-Hashkette, serielle Budgets, Kill Switch und AbortSignal.

## Verbleibende Grenzen

DNS-Rebinding und Prozessisolation sind nicht Teil des reinen Entscheidungsmoduls. Der Keychain-Adapter hängt von der Sicherheit des Betriebssystems und dessen CLI ab. Browser-Binärdateien und Playwright selbst gehören zur Supply Chain. Phase 1 besitzt weder Ownership Ledger noch Plattform-Policy-Synchronisierung und ist nicht für Live-Verkehr freigegeben.
