# Phase 2 – sicherer ProgramSource-Einstieg

## Implementierter Umfang

Der erste Phase-2-Baustein liest ausschließlich lokale JSON-Fixtures unter einer fest vorgegebenen Root-Grenze. Die Snapshots werden ohne Zusatzfelder validiert, auf Secret-Feldnamen geprüft, kanonisch serialisiert und mit SHA-256 gehasht. Das Scope-Mapping normalisiert Hosts, Ports und Pfade deterministisch und trennt Targets, Supporting Hosts und blockierte Hosts strikt.

Eine separat gehaltene `SourceAcceptance` bindet Source-Revision, Snapshot-Hash und Upstream-Policy-Hash. Jede Änderung führt zu einem deterministischen Drift-Stopp.

## Sicherheitsgrenzen

- Kein HTTP-Client und keine Browsernutzung im `platform-source`-Paket.
- Keine Zugangsdaten, Tokens, Cookies oder vollständigen Policy-Texte in Snapshots.
- Nur relative `.json`-Referenzen innerhalb der Fixture-Root; Symlinks, Pfadtraversal, übergroße und ungültige Dateien werden blockiert.
- Supporting Hosts bleiben read-only (`GET`, `HEAD`, `OPTIONS`).
- Kompilierte Policies sind ausdrücklich `productionEligible: false`.
- Es existiert noch kein HackerOne-Live-Adapter und keine Authentifizierung.

## Nächste Freigabestufe

Vor einem echten API-Abruf benötigt der Adapter einen separaten, reviewbaren Transport mit Keychain-Credentials, Host-Pinning auf den dokumentierten offiziellen API-Host, Response-Größenlimits, verschlüsseltem Snapshot-Store und ausschließlich read-only Endpunkten. Dieser Transport ist noch nicht implementiert.
