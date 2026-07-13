# Security Policy

## Entwicklungs- und Testmodell

Dieses Repository ist kein Live-Scanner. Phase 1 darf nur Konfigurationen validieren, Offline-/Capture-Entscheidungen treffen und lokale Loopback-Mocks ansprechen. Ein externer Host ist in Tests und Beispielen verboten.

Melde Schwachstellen privat an die Repository-Eigentümer und veröffentliche weder Secrets noch Eventdateien. Testartefakte müssen frei von bekannten Secret-Markern und HAR-Dateien bleiben.

## Fail-closed-Invarianten

Unvalidierte Konfiguration, Policy-Drift, fehlender Keychain-Zugriff, unbekannte Inhalte, Redirects, Service Worker, WebSockets, Parallelität über eins und erschöpfte Budgets führen zu einer Blockentscheidung. Es existiert kein Force-Schalter und kein Klartext-Fallback.

## Produktionsstatus

Phase 1 ist eine Sicherheitsgrundlage, keine Freigabe zur Nutzung gegen Live-Ziele. Aktive Tests, Plattformkonten, Ownership-Verifikation und Report-Flows fehlen absichtlich.
