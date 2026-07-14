# Phase-4-Änderungen am Sicherheitskern

## Baselines

Phase-3-Baseline:

```text
46c98815bb6e99ce19b7f348886191c467cb84bc
```

Phase-1-Baseline:

```text
0f0f508765ebec663c2d09dc22fa408c1de46a4f
```

Die Phase-3-Baseline ist zusätzlich in `docs/PHASE3_BASELINE.md` fixiert.

## Phase-1-Pfaddiff

Der kontrollierte Pfaddiff von der Phase-1-Baseline bis zum Phase-4-Stand ist
für alle geschützten Phase-1-Pfade leer:

```text
packages/config
packages/egress-guard
packages/redaction
packages/secret-store
packages/event-store
packages/policy
packages/audit-log
packages/recorder
packages/shared
apps/cli
```

Verwendete Prüfung:

```sh
git diff --name-only 0f0f508765ebec663c2d09dc22fa408c1de46a4f..HEAD -- packages/config packages/egress-guard packages/redaction packages/secret-store packages/event-store packages/policy packages/audit-log packages/recorder packages/shared apps/cli
```

Die Ausgabe ist leer. Phase 4 verändert den Phase-1-Sicherheitskern nicht.

## Ausdrücklich markierte Phase-4-Security-Core-Änderungen

Die folgenden Änderungen härten die Phase-2-/Phase-3-Control-Plane und ihre
einzige lokale External-Action-Pipeline. Sie sind ausdrücklich
**Phase-4-Security-Core-Änderungen**.

### Lokale Operator-Credential und signierte Statements

`packages/operator-auth/` ergänzt eine geschlossene Signaturgrenze:

- ausschließlich Ed25519 und PKCS#8;
- privates Schlüsselmaterial nur über eine `keychain://`-Referenz des
  bestehenden `SecretStore`-Interfaces;
- keine Schlüsseldatei, Umgebungsvariable mit Schlüsselmaterial,
  automatische Bereitstellung oder Klartextalternative;
- Entfernung temporärer Schlüsselbytes nach dem Import;
- private, nicht reflektierbare Signierfähigkeit ohne generische
  `sign(data)`-Methode;
- getrennte Signaturdomänen für Enrollment, Approval und Kill-Clear;
- kanonische Digests und exakte Plain-Object-/Descriptorprüfung ohne
  Zusatzfelder, Accessors, Proxies oder fremde Prototypen;
- Bindung an Control-Plane-ID, Operator, Fingerprint, Key-Revision, Session,
  Nonce, Zeitfenster und den exakten Entscheidungs- beziehungsweise
  Kontextdigest.

Die Produktkomposition verwendet ausschließlich `MacOSKeychainSecretStore`.
Die abstrakte `SecretStore`-Naht bleibt nur als vorhandene Capability-Grenze
und für isolierte Tests bestehen.

### Persistierte, fail-closed Control-Plane-Prüfung

`packages/control-plane/database.ts`, `store.ts`,
`external-action-evidence.ts` und `external-action-store.ts` erhalten
Migration v5 und die Laufzeitprüfung:

- zufällige persistente, gegen Update/Delete geschützte Control-Plane-ID;
- append-only Enrollment-, Approval-Decision- und Kill-Clear-Evidence;
- global eindeutige Nonces und persistente maximale Verifikationszeit;
- SQLite-Trigger gegen unsigned Approval-Transitions, nachträgliche Evidence-
  Änderungen, falsche Action-Bindings und Clock Rollback;
- TOFU-Enrollment nur bei aktivem Kill Switch und leerem Credential-Store;
- Signatur-, Session-, Nonce-, Kontext-, Revision- und Credential-Prüfung in
  einer `BEGIN IMMEDIATE`-Transaktion mit Decision, Approval-Transition,
  Audit und Action-Binding;
- Migration v5 aktiviert den Kill Switch, pausiert genehmigte/laufende
  Kampagnen und verwirft aktuelle Policy-Annahmen;
- historische unsigned Approvals bleiben Auditdaten, autorisieren aber keinen
  neuen Consumer;
- Kill-Engagement bleibt jederzeit möglich; Kill-Clear benötigt eine frische,
  replay-sichere Signatur;
- Policy-, Campaign- und External-Action-Consumer revalidieren die
  kryptografische Evidence;
- External Actions revalidieren vor Reservation, Runner-Start und Settlement.

Der Store besitzt eine interne vertrauenswürdige Clock-Capability. Öffentliche
Operationspfade akzeptieren keinen caller-gelieferten Beobachtungszeitpunkt.
Eine ungültige, rückläufige oder werfende Clock blockiert.

### Dashboard- und Simulationskomposition

`packages/dashboard/`, `packages/simulation/`, `apps/dashboard/` und
`apps/phase2-cli/` wurden auf die signierte Control-Plane-API umgestellt:

- ohne vollständig konfigurierte lokale Signierfähigkeit sind Simulation,
  Approval und Kill-Clear gesperrt;
- fehlende oder teilweise Konfiguration führt nicht zu einem Fallback;
- das Dashboard zeigt nur nicht geheime Operator-Metadaten;
- der Operator wird aus der konfigurierten Credential abgeleitet und nicht
  aus einem freien UI-Label;
- lange menschliche Reviews erhalten vor jeder Entscheidung eine neue kurze
  signierte Session, ohne das maximale Fünf-Minuten-Fenster zu lockern;
- die menschlichen Bestätigungszeitpunkte bleiben separat in der
  Approval-Payload gebunden;
- Dashboard, Store und Simulation teilen in der Produktkomposition dieselbe
  Clock-Capability.

## Zugehörige Regressionstests

Die Security-Core-Änderungen besitzen eigene Regressionen:

- `tests/unit/operator-auth.test.ts` prüft Import, Zeroisierung,
  Signaturdomänen, Branding, Schema, Zeitfenster und Fehlerpfade.
- `tests/unit/operator-auth-boundary.test.ts` prüft statisch das Fehlen von
  HTTP-, Browser-, DNS-, Socket-, Child-Process- und LLM-Transporten.
- `tests/property/operator-auth.property.test.ts` mutiert jedes signierte Feld
  der drei Statement-Arten; jede Abweichung blockiert.
- `tests/integration/operator-auth-persistence.test.ts` prüft Enrollment,
  Nonce-Single-use, Clock-Grenze, Immutability, Reopen, Cross-Store-Trennung
  und die fail-closed Migration.
- `tests/integration/operator-auth-external-action-tamper.test.ts` prüft
  Manipulation vor Reservation, Start und Settlement sowie unsigned Fakes.
- bestehende Database-, Store-, External-Action-, Simulation- und Dashboard-
  Tests wurden auf signierte Entscheidungen migriert und um signerlose
  Deny-All-Pfade ergänzt.
- die vollständigen Phase-1-Egress- und Phase-3-Regressionen bleiben aktiv.

Keine bestehende Sicherheitsprüfung wurde deaktiviert oder gelockert. Phase 4
ergänzt keine neue Laufzeitabhängigkeit.

## Bewusst unveränderte oder zurückgestellte Grenzen

- Der Phase-1-Egress-, Redaction-, Secret-Store-, Event-Store-, Policy- und
  Audit-Log-Code bleibt unverändert.
- `external_integrations_enabled` bleibt effektiv `false`.
- Reale Adapter und alle externen Transporte bleiben deaktiviert.
- Rotation, Revocation, Recovery, Quorum und Hardwarebindung der Operator-
  Credential bleiben zurückgestellt.
- Event-Key-Rotation, Crash-Recovery und qualifizierter Mehrprozessbetrieb
  bleiben zurückgestellt.

Während der Implementierung und Prüfung wurde kein realer Plattform- oder
Bug-Bounty-Host als Testziel verwendet.
