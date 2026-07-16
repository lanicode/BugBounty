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

## Pilot Readiness C – zusätzliche Live-Grenze

Phase 1 selbst bleibt unverändert nicht für Live-Verkehr freigegeben. Der
getrennte Pilot-C-Pfad kombiniert ihn mit einem geschlossenen,
snapshotgebundenen Active-Testing-Gate. Für diesen Pfad werden zusätzliche
Angriffe betrachtet:

- Caller-gesteuerte oder normalisierungsmehrdeutige Hosts und Pfade;
- DNS-Suchdomains, private oder gemischte Antworten und DNS-Rebinding;
- TLS-Downgrade, Zertifikatsfehler, Remote-IP-Abweichung und unerwartetes ALPN;
- Approval-, Plan-, Snapshot-, Katalog-, Clock- und Budget-Replay;
- gefälschte erfolgreiche Response-Evidence ohne ausgeführten Transport;
- Rohbody-, Header-, Cookie- oder Redirect-Leaks in Observation und Report;
- Crashs zwischen Reservation, Request und Settlement.

Kontrollen sind exakte kanonische HTTPS-URL-Syntax und Pfadgleichheit vor DNS,
vollständige Prüfung und Digestbindung aller DNS-Antworten, deterministische
IP-Auswahl und Verbindungs-Pinning, TLS 1.2/1.3 mit Hostprüfung, private
Transport-Evidence-Issuance, frische signierte Planfreigabe, separate
Startaktion, persistente nicht erstattbare Budgets, Kill-Switch-Polling über
DNS und Request sowie geschlossene redigierte Evidence-Schemas. Redirects,
Retries, Upgrades, freie Requestbestandteile und Report-Einreichung fehlen.

Nicht gelöst sind ein allgemeiner Netzwerk-Namespace beziehungsweise
separater Sandbox-Prozess, verteilte/multi-user Ausführung, automatische
semantische Interpretation beliebiger Programmregeln und Rückruf eines bereits
übertragenen Requests. Der lokal enthaltene Loopback-Testharness ist kein
App-Runner und wird von der Produktionskomposition nicht injiziert. Seine
HTTP-Engine liegt ausschließlich unter `tests/support`, wird nur in den zwei
expliziten Vitest-Loopback-Suites als vollständiger Modulersatz geladen und ist
durch `tsconfig.build.json` aus den Produktionsartefakten ausgeschlossen. Ein
lokaler Source-Checkout bleibt wie jeder Testcode Teil der
Supply-Chain-/Local-Code-Execution-Grenze, stellt aber keinen produktiven
Transportexport bereit.
