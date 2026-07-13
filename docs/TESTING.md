# Phase-1-Testnachweis

Stand: 13. Juli 2026. Alle Netzwerk-Integrationstests liefen ausschließlich gegen kurzlebige Server auf `127.0.0.1`.

## Ergebnis

- Vollständige Suite: 11 Testdateien, 35 Tests, 35 bestanden.
- Egress-Suite: 3 Testdateien, 10 Tests, 10 bestanden.
- Coverage: 86,13 % Statements, 79,72 % Branches, 90,58 % Funktionen, 87,87 % Zeilen.
- TypeScript-Typprüfung, ESLint ohne Warnungen, Prettier-Check und Build: bestanden.
- Dependency-Audit: keine bekannten Schwachstellen.

## Abgedeckte Sicherheitsinvarianten

Exact-Host/Userinfo/Port/HTTP/IDN/Case/Trailing-Dot/IPv6- und Pfadtraversalentscheidungen; Target-/Supporting-Trennung; Capture-Modi; Redirects; Browser-Ressourcen und WebSocket-/Service-Worker-Sperren; Header-/Query-/JSON-/Textredaktion; Größen-/Binär-/Content-Type-Verhalten; Quarantäne; HMAC-Stabilität; Schema-/Placeholder-/Policy-Drift; Vertragslaufzeit, Asset, Konto, Risk-Tier, Budget, Parallelität, Kill Switch und AbortSignal; Eventverschlüsselung/Manipulation/kein Überschreiben; Audit-Hashkette; Secret-Marker-Abwesenheit in persistierten Events; Loopback-Pre-Request-Entscheidung.

Property-Tests erzeugen 300 Hostvarianten sowie generierte Traversal-, Header- und rekursive JSON-Fälle.
