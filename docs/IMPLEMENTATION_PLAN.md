# Implementierungsplan Phase 1

1. Reproduzierbares, striktes TypeScript-Tooling und sichere Repository-Regeln etablieren.
2. Program YAML und Kampagnenvertrag zuerst strukturell, danach semantisch validieren; kanonisieren und hashen.
3. URL-Normalisierung und Egress-Entscheidung als synchrone, deterministische Pure Functions implementieren; anschließend vor der ersten Seite an Playwright anbinden.
4. Request-/Response-Daten vor jeder Persistierung minimieren, rekursiv redigieren und sensible Identität quarantänisieren.
5. Keychain-Interface, Test-In-Memory-Store, AES-256-GCM-Eventhüllen und hashverkettetes Audit-Log implementieren.
6. Policy-Drift, Vertrag, Budget, Parallelität, Kill Switch und Abbruchsignal deterministisch erzwingen.
7. CLI für Diagnose, Validierung und Verifier ergänzen.
8. Unit-, Property- und ausschließlich lokale Loopback-Integrationstests sowie Coverage- und Artefaktprüfung ausführen.

## Konservative Architekturentscheidungen

- Supporting Hosts benötigen einen exakt passenden Capture-Modus und eine explizite Methodenliste.
- Userinfo, URL-Fragmente, nicht-kanonische Hosts, IPv6-Zonen, mehrfach kodierte Pfade und jede Traversalform werden blockiert.
- HTTP ist nur für Loopback und nur bei expliziter Testfreigabe möglich.
- Multipart, Form-Data, komprimierte und unbekannte Inhalte werden nicht als Body gespeichert.
- Phase 1 erlaubt nur `tier_0_offline` und den rein passiven `capture`-Action-Typ; aktive Risk-Tiers bleiben selbst bei Vertragsfreigabe blockiert.
