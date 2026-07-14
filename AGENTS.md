# Sicherheitsregeln für Repository-Agenten

## Geltungsbereich

Der produktive Code in `apps/` und `packages/` enthält den unveränderten Phase-1-Sicherheitskern, die lokale Phase-2-Control-Plane, den store-gebundenen Phase-3-External-Action-Evaluator und die lokale signierte Phase-4-Operatorgrenze. `legacy/mvp/` ist ausschließlich eine unsichere, nicht produktive Audit-Referenz.

## Nicht verhandelbare Regeln

- Netzwerk- und Browsertests laufen ausschließlich gegen Loopback-Adressen. Beispielhosts werden nie aufgelöst oder kontaktiert.
- Jede Netzwerkentscheidung erfolgt vor dem Request, deny-by-default und fail-closed.
- Keine aktiven Sicherheitstests, reale Kontoerstellung, Live-Plattformintegration, Report-Einreichung oder LLM-gesteuerten Requests ergänzen.
- Phase-2-Quellen, Mock-Adapter, Demo-SaaS, Simulation und Dashboard bleiben vollständig lokal. Externe Adapter sind deaktivierte Platzhalter ohne Transport.
- Keine Roh-HARs, Rohbodys, Tokens, Cookies, Zugangsdaten oder Identitätsdaten persistieren oder loggen.
- Persistierung erfolgt erst nach Redaktion und Größenprüfung. Eventdaten werden ausschließlich authentifiziert verschlüsselt gespeichert.
- Produktionsschlüssel stammen ausschließlich aus dem OS-Keychain-Adapter. Es gibt keinen Klartext-Fallback.
- Private Operator-Schlüssel werden ausschließlich als Ed25519-PKCS#8 über eine `keychain://`-Referenz geladen. Schlüsseldateien, Schlüsselmaterial in Umgebungsvariablen, automatische Provisionierung und Klartext-Fallbacks sind verboten.
- Jede neue persistierte Approval-Entscheidung sowie jeder Kill-Switch-Clear benötigt eine gültige, frische, session-, nonce-, control-plane- und kontextgebundene Operator-Signatur. Freie Actor-Strings sind keine Credential.
- Signaturprüfung, Replay-Schutz, Decision-Evidence, Approval-Transition, Audit und External-Action-Binding bleiben atomar in `BEGIN IMMEDIATE`. Die store-eigene Uhr und ihr persistenter High-Water-Mark dürfen nicht umgangen werden.
- Policy-Drift, Redirects, Service Worker, WebSockets, unbekannte Content-Types und Budgetfehler blockieren.
- Regelannahmen, Kampagnenfreigaben, Account-Schritte, rechtliche Erklärungen und Reportfreigaben dürfen niemals automatisch bestätigt werden.
- Checkpoint-freie Demoidentitäten sind ausschließlich vorautorisierte In-Process-Fixtures. Sobald ein Mock-Account-Plan CAPTCHA, E-Mail, TOTP, Regeln, Bedingungen oder Rechtserklärungen enthält, muss der Workflow pausieren; kein Checkpoint darf automatisch erfüllt werden.
- Externe Aktionen müssen über Registry, Schema, Policy, Scope, Ownership, Budget, menschlichen Kontrollpunkt und deterministischen Runner laufen.
- Positive External-Action-Entscheidungen dürfen ausschließlich aus einem atomaren, aktuellen `ControlPlaneStore`-Snapshot entstehen. Caller-Booleans, Callback-Gates und Freitextsuche sind keine Autorisierung.
- Proposal, Policy, Kampagnenrevision/-digest, Scope, Accountrolle, Ownership, Payload, Approval, Operator, Budget und Audit müssen exakt gebunden und vor Start sowie Settlement erneut geprüft werden.
- Proposal-IDs, Attempts und Budgets sind persistent. Abbruch und Fehler erstatten kein Budget; Crash-Reservationen bleiben fail-closed blockierend.
- Das initiale Operator-Enrollment ist lokales TOFU bei aktivem Kill Switch. Es ist keine rechtliche Zustimmung, keine Hardwarebindung und kein Beweis menschlicher Anwesenheit. Reale Runner bleiben unabhängig von vorhandener Evidence deaktiviert.
- `external_integrations_enabled` bleibt standardmäßig sowie bei fehlender oder fehlerhafter Konfiguration effektiv `false`.
- Der globale Kill Switch ist fail-closed; Lesefehler, fehlende Audit-Referenzen, Revisionsfehler und inkonsistente Clear-Zustände gelten als aktiv. Engagement pausiert aktive Kampagnen vor der Audit-Fortsetzung.
- Sicherheitsgrenzen benötigen direkte Unit-, Property- und Integrationstests. Tests dürfen nicht zur Fehlerbehebung gelockert werden.
- Neue Abhängigkeiten werden exakt gepinnt und in `docs/DEPENDENCIES.md` begründet.

## Architekturgrenzen

- `packages/config`: untrusted YAML/JSON bis zur Schema- und Semantikvalidierung.
- `packages/egress-guard`: einzige Freigabestelle des Phase-1-Kerns für HTTP-/Browser-Egress.
- `packages/redaction`: einzige Transformation vor Eventpersistierung.
- `packages/secret-store`: Keychain-Produktion und In-Memory nur für Tests.
- `packages/event-store`: AES-256-GCM-Hüllen und atomare, restriktive Dateien.
- `packages/policy`: Phase-1-Vertrag, Budgets, Kill Switch und deterministische Reason Codes.
- `packages/audit-log`: bodyfreies append-only JSONL mit Hash-Verkettung.
- `packages/platform-source`: lokale, strikt validierte Plattform-Snapshots ohne HTTP-Client.
- `packages/control-plane`: lokale SQLite-Datenmodelle, Migrationen und Zustandsmaschinen.
- `packages/external-actions`: einzige Registry und Gate-Pipeline für künftige externe Wirkungen.
- `packages/operator-auth`: einzige lokale Ed25519-Signaturgrenze für Enrollment, Approval-Entscheidungen und Kill-Switch-Clear.
- `packages/dashboard` und `packages/demo-saas`: ausschließlich `127.0.0.1`, feste Routen und lokale Mocks.

Konservative Entscheidungen, bewusst deaktivierte Funktionen und jede zwingende Änderung am Phase-1-Kern sind in den Abschlussdokumenten festzuhalten.
