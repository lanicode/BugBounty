# Security Policy

## Entwicklungs- und Testmodell

Dieses Repository ist kein Live-Scanner. Produktcode validiert
Konfigurationen, trifft Offline-/Capture-Entscheidungen und spricht in
Entwicklung und Tests ausschließlich lokale Loopback-Mocks an. Ein externer
Plattform-, Beispiel- oder Zielhost ist in Tests verboten.

Melde Schwachstellen privat an die Repository-Eigentümer und veröffentliche weder Secrets noch Eventdateien. Testartefakte müssen frei von bekannten Secret-Markern und HAR-Dateien bleiben.

## Fail-closed-Invarianten

Unvalidierte Konfiguration, Policy-Drift, fehlender Keychain-Zugriff, unbekannte Inhalte, Redirects, Service Worker, WebSockets, Parallelität über eins und erschöpfte Budgets führen zu einer Blockentscheidung. Es existiert kein Force-Schalter und kein Klartext-Fallback.

Der Phase-7-Browserstart existiert ausschließlich unter `tests/browser` und
ist kein External-Action-Runner. Vor der ersten Page sind Phase-1-Egress-Guard
und exakter Schritt-Guard aktiv. Browserartefakte sind deaktiviert;
Screenshotbytes entstehen ausschließlich hinter einer vollständig opaken
rollen-/zustandsgebundenen Maske, werden nur als validierter Digest
freigegeben und anschließend genullt.

## Produktionsstatus

Die abgeschlossenen lokalen Phasen sind keine Freigabe zur Nutzung gegen
Live-Ziele. Aktive Tests, reale Plattformkonten, reale Browser-Sessions und
Report-Einreichung fehlen absichtlich. Rollen-Replays beweisen keine reale
Authentisierung oder Autorisierung.
