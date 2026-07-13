# Phase-1-Testnachweis

Stand: 13. Juli 2026. Alle Netzwerk-Integrationstests liefen ausschließlich gegen kurzlebige Server auf `127.0.0.1`.

## Ergebnis

- Vollständige Suite: 12 Testdateien, 36 Tests, 36 bestanden.
- Egress-Suite: echte Chromium- sowie Unit- und HTTP-Loopback-Tests; alle bestanden.
- Coverage: 86,18 % Statements, 79,90 % Branches, 90,58 % Funktionen, 87,92 % Zeilen.
- TypeScript-Typprüfung, ESLint ohne Warnungen, Prettier-Check und Build: bestanden.
- Dependency-Audit: keine bekannten Schwachstellen.

## Abgedeckte Sicherheitsinvarianten

Exact-Host/Userinfo/Port/HTTP/IDN/Case/Trailing-Dot/IPv6- und Pfadtraversalentscheidungen; Target-/Supporting-Trennung; Capture-Modi; Redirects; echte Chromium-Popups, neue Seiten, Frames, Fetch, Formulare sowie WebSocket-/Service-Worker-Sperren; Header-/Query-/JSON-/Textredaktion; Größen-/Binär-/Content-Type-Verhalten; Quarantäne; HMAC-Stabilität; Schema-/Placeholder-/Policy-Drift; Vertragslaufzeit, Asset, Konto, Risk-Tier, Budget, Parallelität, Kill Switch und AbortSignal; Eventverschlüsselung/Manipulation/kein Überschreiben; Audit-Hashkette; Secret-Marker-Abwesenheit in persistierten Events; Loopback-Pre-Request-Entscheidung.

Property-Tests erzeugen 300 Hostvarianten sowie generierte Traversal-, Header- und rekursive JSON-Fälle.
