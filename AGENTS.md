# Sicherheitsregeln für Repository-Agenten

## Geltungsbereich

Der produktive Code in `apps/` und `packages/` enthält den Phase-1-Sicherheitskern und den rein lokalen, read-only Phase-2-`ProgramSource`. `legacy/mvp/` ist eine unsichere, nicht produktive Audit-Referenz.

## Nicht verhandelbare Regeln

- Netzwerk- und Browsertests laufen ausschließlich gegen Loopback-Adressen. Beispielhosts werden nie aufgelöst oder kontaktiert.
- Jede Netzwerkentscheidung erfolgt vor dem Request, deny-by-default und fail-closed.
- Keine aktiven Sicherheitstests, Kontoerstellung, Live-Plattformintegration, Report-Einreichung oder LLM-gesteuerten Requests ergänzen. Der Phase-2-`ProgramSource` darf ausschließlich lokale, eingecheckte Offline-Fixtures lesen.
- Keine Roh-HARs, Rohbodys, Tokens, Cookies, Zugangsdaten oder Identitätsdaten persistieren oder loggen.
- Persistierung erfolgt erst nach Redaktion und Größenprüfung. Eventdaten werden ausschließlich authentifiziert verschlüsselt gespeichert.
- Produktionsschlüssel stammen ausschließlich aus dem OS-Keychain-Adapter. Es gibt keinen Klartext-Fallback.
- Policy-Drift, Redirects, Service Worker, WebSockets, unbekannte Content-Types und Budgetfehler blockieren.
- Sicherheitsgrenzen benötigen direkte Unit- und Property-Tests. Tests dürfen nicht zur Fehlerbehebung gelockert werden.
- Neue Abhängigkeiten werden exakt gepinnt und in `docs/DEPENDENCIES.md` begründet.

## Architekturgrenzen

- `packages/config`: untrusted YAML/JSON bis zur Schema- und Semantikvalidierung.
- `packages/egress-guard`: einzige Freigabestelle für HTTP-/Browser-Egress.
- `packages/redaction`: einzige Transformation vor Eventpersistierung.
- `packages/secret-store`: Keychain-Produktion und In-Memory nur für Tests.
- `packages/event-store`: AES-256-GCM-Hüllen und atomare, restriktive Dateien.
- `packages/policy`: Vertrag, Budgets, Kill Switch und deterministische Reason Codes.
- `packages/audit-log`: bodyfreies append-only JSONL mit Hash-Verkettung.
- `packages/platform-source`: lokale, strikt validierte Plattform-Snapshots; kein HTTP-Client, keine Tokens und keine Live-API.

Konservative Entscheidungen und bewusst deaktivierte Funktionen sind in der Betriebsdokumentation festzuhalten.
