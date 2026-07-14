# Phase-3-Abschlussbericht

Stand: 14. Juli 2026

Branch: `codex/phase-3-store-bound-evaluator`

Phase-2-Baseline: `307344353ec3a0bcfc04a3f409c6dc4815df349b`

Getesteter Implementierungsstand: `5d3a283` zuzüglich dieses reinen
Dokumentations-Abschlusscommits

## Ergebnis

Phase 3 ersetzt die caller-gesteuerten positiven Simulations-Gates durch einen
store-gebundenen External-Action-Evaluator. Eine Runner-Freigabe entsteht nur
noch aus einem aktuellen, atomaren und persistierten Snapshot von Programm,
Policy, Kampagne, Scope, Account, Ownership, Budget, Human Approval und Audit.
Proposal-IDs, Attempts, Budgets und aktive Reservationen überleben Store- und
Prozessneustarts.

Der einzige ausführbare Runner bleibt ein deterministischer In-Process-Mock.
Es wurde kein realer Plattform-, HackerOne-, Bugcrowd-, Beispiel- oder
Bug-Bounty-Zielhost kontaktiert. Netzwerk- und Browsertests verwendeten
ausschließlich kurzlebige Server auf `127.0.0.1`. Die offizielle npm-Registry
wurde nur für den erlaubten Dependency-Audit kontaktiert; GitHub wird
ausschließlich für den vom Benutzer verlangten Source-Control-Push verwendet.

## Architekturzusammenfassung

```text
ExternalActionProposal v2
  -> exakte Schema-/Descriptor-Validierung und kanonischer Digest
  -> geschlossene, immutable Registry
  -> simulation-only / external integrations disabled
  -> atomarer ControlPlaneStore-Snapshot
       |-- aktuelle akzeptierte Policy
       |-- laufende freigegebene Kampagne + vollständiger Digest
       |-- deterministischer Scope
       |-- Account-/Ownership-Evidence
       |-- strukturierte operatorgebundene Approval + Audit
       `-- Replay-, Gesamt-, Campaign-, Rate-, Concurrency- und Clock-Budget
  -> persistierte Reservation + append-only Audit
  -> Revalidierung vor Start
  -> gebrandeter In-Process-Mock-Runner
  -> Kill-Switch-Monitoring
  -> Revalidierung vor erfolgreichem Settlement
```

SQLite-Migration v4 ergänzt immutable Approval-Bindings und single-use
Attempts. `BEGIN IMMEDIATE` serialisiert die fachliche Entscheidung und die
Budgetreservation. Foreign Keys, `STRICT`-Tabellen, Checks und Trigger
erzwingen die Bindungen zusätzlich in der Datenbank. Auditzeilen und Approval-
Bindings können nicht nachträglich aktualisiert oder gelöscht werden. Attempt-
Bindings sind unveränderlich; ausschließlich die eng definierten Status-,
Revisions- und Zeitübergänge der Zustandsmaschine sind zulässig, und Attempts
können nicht gelöscht werden.

## Liste aller Änderungen

1. Phase-2-Baseline und Phase-3-Acceptance-Criteria fixiert.
2. Geschlossenen Proposal-v2-Vertrag mit exakter Plain-Object-, Accessor-,
   Proxy-, Längen-, Format- und Zusatzfeldprüfung implementiert.
3. Kanonische Digests für Proposal, Kampagne, Identität, Ownership, Scope,
   Approval-Binding und vollständige Authorization-Evidence ergänzt.
4. SQLite-Migration v4 mit `external_action`-Approval, immutable Bindings,
   persistenten Attempts, append-only Control-Plane-Audits und fail-closed
   Upgrade-Kill-Switch implementiert.
5. Atomaren Store-Evaluator für Policy, Scope, Ownership, Operator, Approval,
   Audit, Replay und Budgets implementiert.
6. Globales Runtime-Gesamtbudget, globale Concurrency und globalen
   Clock-High-Water-Mark sowie Campaign-, Rate- und Vertragsbudgets erzwungen.
7. Attempt-Zustände `reserved -> running -> terminal` und
   `reserved -> aborted` mit monotonen Zeitpunkten implementiert.
8. Pre-Start-Fehler räumen Concurrency fail-closed auf, ohne Budget zu
   erstatten; ein echter Crash hinterlässt absichtlich eine blockierende
   Reservation.
9. Alte caller-gelieferte Boolean-Gates entfernt; ohne gebrandeten
   Store-Evaluator gilt Deny-All.
10. Datenbank, Store, Evidence-Store, Evaluator, Kill Switch, Pipeline und
    Runner gegen Fakes, Proxies, Prototype-Spoofs und Method-Shadowing gehärtet.
11. Statische Importgrenze auf alle Phase-3-Runtime-Dateien erweitert.
12. Unit-, Property-, SQLite-Reopen-, Drift-, Kill-, Crash-, Rate-, Clock- und
    lokale Integrationstests ergänzt.
13. Architektur-, Security-Core-, External-Actions-, Risiko-, Test- und
    Bedienungsdokumentation aktualisiert.

Der exakte Dateisatz steht in `PHASE3_FILE_MANIFEST.txt`. Details zur
Entscheidungskette stehen in `docs/PHASE3_STORE_BOUND_EVALUATOR.md`.

## Tatsächlich ausgeführte Befehle

Die pnpm-Kommandos liefen mit Node.js `v24.14.0`, pnpm `11.7.0` und dem
gebündelten Runtime-Pfad. Die wesentlichen finalen Befehle waren:

```sh
pnpm typecheck
pnpm lint
pnpm format:check
pnpm build
pnpm test
pnpm test:coverage
pnpm exec vitest run tests/property
pnpm exec vitest run tests/integration
pnpm exec vitest run tests/unit/control-plane/database.test.ts tests/unit/external-action-proposal.test.ts tests/unit/external-actions-import-boundary.test.ts tests/unit/external-actions.test.ts tests/unit/store-bound-external-actions.test.ts tests/property/store-bound-evaluator.property.test.ts tests/integration/external-action-kill-switch.test.ts tests/integration/store-bound-external-action.test.ts
pnpm test:egress
pnpm test:platform-source
pnpm audit --audit-level high
git diff --check
git diff --name-only 0f0f508765ebec663c2d09dc22fa408c1de46a4f..HEAD -- packages/config packages/egress-guard packages/redaction packages/secret-store packages/event-store packages/policy packages/audit-log packages/recorder packages/shared apps/cli
git log --oneline 307344353ec3a0bcfc04a3f409c6dc4815df349b..HEAD
git status --short
```

Zusätzlich liefen während der Implementierung wiederholt fokussierte Vitest-,
TypeScript-, ESLint-, Prettier- und Diff-Checks. Der erste Gesamtlauf in der
Socket-Sandbox bestand 234 Tests und scheiterte ausschließlich zehnmal an
`listen EPERM` für lokale `127.0.0.1`-Server. Derselbe Lauf mit expliziter
Loopback-Freigabe bestand vollständig; es wurde kein Test deaktiviert.

## Vollständige Testergebnisse

- Typprüfung `tsc --noEmit`: bestanden.
- ESLint `--max-warnings 0`: bestanden, keine Warnungen.
- Prettier `--check .`: bestanden.
- Build `tsc -p tsconfig.build.json`: bestanden.
- Gesamtsuite/Coverage-Lauf: **49/49 Dateien, 247/247 Tests bestanden**.
- Phase-3-Fokussuite: **8/8 Dateien, 65/65 Tests bestanden**.
- Property-Suite: **7/7 Dateien, 12/12 Tests bestanden**.
- Integrationssuite: **9/9 Dateien, 36/36 Tests bestanden**.
- Phase-1-Egress: **4/4 Dateien, 11/11 Tests bestanden**.
- Platform Source: **4/4 Dateien, 12/12 Tests bestanden**.
- Dependency-Audit: `No known vulnerabilities found`.
- Diff-, geschützter Phase-1-Pfad- und statische Importgrenzen: bestanden.
- Node meldet für `node:sqlite` weiterhin die dokumentierte
  `ExperimentalWarning`; sie beeinflusst das Testergebnis nicht.

Die vollständige Befehls-/Ergebnismatrix steht in
`PHASE3_TEST_RESULTS.txt`.

## Testabdeckung

| Metrik     | Abdeckung | Treffer / Gesamt |
| ---------- | --------: | ---------------: |
| Statements |   87,73 % |      3127 / 3564 |
| Branches   |   82,76 % |      2161 / 2611 |
| Functions  |   94,90 % |        670 / 706 |
| Lines      |   88,88 % |      3016 / 3393 |

Alle konfigurierten Schwellen wurden überschritten: Statements, Funktionen
und Zeilen mindestens 80 %, Branches mindestens 75 %.

## Acceptance Criteria

Alle realistisch ausführbaren Kriterien aus
`docs/PHASE3_ACCEPTANCE_CRITERIA.md` sind erfüllt:

- positiver Runnerpfad nur aus atomarer Store-Evidence;
- exakte Proposal-, Policy-, Campaign-, Scope-, Account-, Ownership-,
  Operator-, Approval-, Audit- und Budgetbindung;
- persistenter Replay-, Restart-, Rate-, Clock- und Concurrency-Schutz;
- Revalidierung vor Start und Settlement;
- Report, Triage, externer Modus, unbekannte Actions und untrusted Runner
  blockiert;
- keine Secrets, Rohbodys, Cookies, Tokens oder Eventdaten in neuen Tabellen;
- keine Änderung am geschützten Phase-1-Sicherheitskern;
- vollständige Unit-, Property-, Integration-, Egress- und
  Import-Boundary-Regression.

## Logische Commits

1. `75dc34d` — `docs: pin phase 2 baseline and phase 3 scope`
2. `d9463fd` — `feat(control-plane): persist phase 3 action evidence and reservations`
3. `8acaadd` — `feat(external-actions): require store-bound action decisions`
4. `5d3a283` — `test: verify phase 3 fail-closed action evaluation`
5. dieses Abschlussartefakt — `docs: add phase 3 completion package`

## Bekannte Restrisiken

1. Das Operatorlabel ist exakt gebunden, aber noch nicht lokal authentifiziert
   oder kryptografisch signiert.
2. Ein echtes rohes `ControlPlaneDatabase`-Handle bleibt Teil der Trusted
   Computing Base.
3. `node:sqlite` ist experimentell; qualifiziert ist der lokale
   Single-Process-Betrieb.
4. Crash-Reservationen benötigen einen künftig menschlich kontrollierten
   Recovery-Pfad und blockieren bis dahin Concurrency.
5. Das Runtime-Gesamtlimit ist geprüft, aber noch nicht als versionierter,
   operatorgebundener Budgetvertrag persistiert.
6. Wall-Clock, lokaler OS-Account und lokales Dateisystem bleiben
   Vertrauensannahmen.
7. Kill-Switch-Reader und Evidence-Store sind noch nicht über eine gemeinsame
   Capability-ID untrennbar gleichgesetzt.
8. Keychain-Rotation, Re-Keying und Wiederherstellung alter Eventhüllen sind
   zurückgestellt.

Die vollständige Bewertung steht in `PHASE3_KNOWN_RISKS.md`.

## Deaktivierte oder zurückgestellte Funktionen

- reale HackerOne-, Bugcrowd- oder andere Plattformadapter;
- echte Tokens, Cookies, Passwörter, TOTP-, E-Mail- oder Browser-Sessions;
- reale Account-Erstellung und automatische Checkpoint-/Rechtszustimmung;
- CAPTCHA- oder Anti-Bot-Umgehung;
- aktive Sicherheitstests und beliebige Zielrequests;
- Report-Einreichung und Triage-Versand;
- LLM-gesteuerte HTTP-/Browserrequests;
- nicht-null External-Action-Payloads;
- lokal authentifizierte Operatoridentität und signierte Approvals;
- automatische Crash-Recovery, Budgeterstattung und Mehrprozessbetrieb;
- Event-Key-Rotation und Re-Keying.

## Bestätigung der externen Grenze

Während Entwicklung und Tests von Phase 3 wurde **kein realer Plattform-,
HackerOne-, Bugcrowd-, Beispiel- oder Bug-Bounty-Host kontaktiert**. Alle
Produkt-, Netzwerk- und Browsertests liefen gegen In-Process-Mocks oder
`127.0.0.1`. `.invalid`-Namen wurden ausschließlich als nicht aufgelöste
Metadaten verwendet.

## Kleinster empfohlener nächster Schritt

Der kleinste sichere nächste Schritt ist eine lokal authentifizierte
Operatoridentität mit kryptografisch signierten, nonce- und
proposal-gebundenen Approvals. Sie muss weiterhin ausschließlich lokale
Simulationen autorisieren; reale Adapter bleiben deaktiviert. Erst danach
sollten Key-Rotation und kontrollierte Recovery-Capabilities folgen.
