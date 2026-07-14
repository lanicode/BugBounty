# Phase-4-Abschlussbericht

Stand: 14. Juli 2026

Branch: `codex/phase-4-signed-operator-approvals`

Phase-3-Baseline: `46c98815bb6e99ce19b7f348886191c467cb84bc`

Getesteter Implementierungsstand:
`c58f3d545e7e576f316e3aad0f1a20fa15d292fd` zuzüglich dieses reinen
Dokumentations-Abschlusscommits

## Ergebnis

Phase 4 ersetzt freie Operatorlabels als positive Autorisierung durch eine
lokale, Keychain-referenzierte Ed25519-Credential und kryptografisch signierte,
replay-sichere Control-Plane-Entscheidungen. Enrollment, Approval-Entscheidung
und Kill-Clear sind getrennte Signaturdomänen. Signaturprüfung, persistente
Evidence, Zustandsmutation, Audit und External-Action-Bindung werden atomar
geschrieben und von den Konsumenten erneut geprüft.

Der einzige ausführbare Runner bleibt ein deterministischer In-Process-Mock.
Es wurde kein realer Plattform-, HackerOne-, Bugcrowd-, Beispiel- oder Bug-
Bounty-Zielhost kontaktiert. Netzwerk- und Browsertests verwendeten
ausschließlich kurzlebige Server auf `127.0.0.1`. Die offizielle npm-Registry
wurde nur für den erlaubten Dependency-Audit kontaktiert; GitHub wird
ausschließlich für den vom Benutzer verlangten Source-Control-Push verwendet.

## 1. Architekturzusammenfassung

```text
macOS Keychain (private Ed25519 PKCS#8, nur per keychain:// Referenz)
  -> gebrandeter lokaler OperatorSigner
  -> kurzes, signiertes Session-/Enrollment-Proof
  -> strukturierte Approval- oder Kill-Clear-Entscheidung
  -> exakte Schema-/Descriptor-/Digestprüfung
  -> persistente Credential-, Nonce-, Clock- und Signaturprüfung
  -> BEGIN IMMEDIATE
       |-- append-only Signed Statement
       |-- immutable Decision Evidence
       |-- Approval/Kill-Switch-Zustandswechsel
       |-- bodyfreier Control-Plane-Audit
       `-- External-Action-Auditbindung
  -> kryptografische Consumer-Revalidierung
  -> Policy / Campaign / Scope / Ownership / Budget
  -> Reservation
  -> erneute Revalidierung vor Start
  -> deterministischer In-Process-Mock-Runner
  -> erneute Revalidierung vor erfolgreichem Settlement
```

Eine zufällige, persistente und immutable Control-Plane-ID trennt Signaturen
zwischen Datenbanken. Jede Session und Entscheidung bindet Operator,
Public-Key-Fingerprint, Key-Revision, 32-Byte-Session, global eindeutige
32-Byte-Nonce, Ausgabe-/Ablaufzeit und exakten Kontext. Das maximale Zeitfenster
beträgt fünf Minuten. Eine persistente Clock-High-Water-Mark blockiert
Rücksprünge.

Migration v5 aktiviert fail-closed den Kill Switch, pausiert genehmigte oder
laufende Kampagnen und entfernt aktuelle Policy-Annahmen. Historische
unsignierte Approvals bleiben Auditdaten, autorisieren aber keinen Consumer.
Dashboard und Simulation können ohne explizit konfigurierte lokale
Signierfähigkeit keine positive Entscheidung durchführen. Kill-Engagement
bleibt jederzeit möglich.

Details stehen in `docs/PHASE4_SIGNED_OPERATOR_APPROVALS.md`.

## 2. Liste aller Änderungen

1. Phase-3-Baseline und geschlossene Phase-4-Acceptance-Criteria fixiert.
2. Neues transportfreies `packages/operator-auth` mit Ed25519-only PKCS#8-
   Import, Keychain-Referenzpflicht, temporärer Byte-Zeroisierung und privater
   Signierfähigkeit implementiert.
3. Exakte, kanonische Envelopes für Enrollment, Approval und Kill-Clear mit
   Abwehr von Zusatzfeldern, Accessors, Proxies und fremden Prototypen ergänzt.
4. SQLite-Migration v5 mit immutable Control-Plane-ID, Credential,
   Signed-Statement-, Approval-Decision- und Kill-Clear-Evidence ergänzt.
5. Globale Nonce-Single-use- und persistente Clock-Rollback-Guards in Store
   und SQLite implementiert.
6. TOFU-Enrollment auf aktiven Kill Switch, leeren Credential-Store und
   signierten Proof-of-Possession begrenzt.
7. Frühere actor-basierte Approval-Mutation durch eine atomare signierte
   Decision-API ersetzt; akzeptierte wie abgelehnte Entscheidungen benötigen
   Evidence.
8. Kill-Clear auf eine frische signierte, revisionsgebundene Entscheidung
   begrenzt; Kill-Engagement bleibt asymmetrisch jederzeit verfügbar.
9. Policy-, Campaign- und External-Action-Konsumenten auf vollständige
   kryptografische Evidence-Revalidierung umgestellt.
10. External Actions revalidieren Signatur und reservierten Evidence-Digest
    vor Reservation, Runner-Start und erfolgreichem Settlement.
11. Dashboard und Simulation auf explizite Signer-Injektion umgestellt;
    fehlende, teilweise oder fehlerhafte Konfiguration blockiert ohne
    Fallback.
12. Produktkomposition auf `MacOSKeychainSecretStore`, nicht geheime
    Operator-Metadaten und eine gemeinsame Clock-Capability beschränkt.
13. Unit-, Property-, SQLite-Reopen-, Migration-, Immutability-, Replay-,
    Clock-, Cross-Store-, Tamper-, Dashboard- und Simulationsregressionen
    ergänzt.
14. Dokumentation für Architektur, Bedienung, Security-Core-Änderungen,
    externe Actions, Risiken, Tests und Roadmap aktualisiert.

Der exakte Dateisatz steht in `PHASE4_FILE_MANIFEST.txt`.

## 3. Tatsächlich ausgeführte Befehle

Die finalen Projektkommandos liefen mit Node.js `v24.14.0`, pnpm `11.7.0` und
dem gebündelten Workspace-Runtime-Pfad:

```sh
pnpm typecheck
pnpm lint
pnpm format:check
pnpm build
pnpm test
pnpm test:coverage
pnpm exec vitest run tests/property
pnpm exec vitest run tests/integration
pnpm test:egress
pnpm test:platform-source
pnpm audit --audit-level high
pnpm exec prettier --write PHASE4_EXTERNAL_ACTIONS.md
git diff --check
git diff --name-only 0f0f508765ebec663c2d09dc22fa408c1de46a4f -- packages/config packages/egress-guard packages/redaction packages/secret-store packages/event-store packages/policy packages/audit-log packages/recorder packages/shared apps/cli
git diff --name-status 46c98815bb6e99ce19b7f348886191c467cb84bc..HEAD
git log --oneline 46c98815bb6e99ce19b7f348886191c467cb84bc..HEAD
git status --short --branch
```

Zusätzlich liefen wiederholt fokussierte Vitest-, TypeScript-, ESLint-,
Prettier- und Diff-Checks. Der neue Pre-Start-Tamper-Test bestand fokussiert
mit 5/5 Tests. Die tatsächlich verwendete Shell setzte für die Projektbefehle
den absoluten gebündelten Node-/pnpm-Pfad über `env PATH=...`.

Ein erster Aufruf der vier Basisgates ohne diesen Runtime-Pfad scheiterte mit
`pnpm: command not found`; nach Setzen des dokumentierten Workspace-Pfads
bestanden dieselben Kommandos. Ein Zwischenstand der neuen External-Actions-
Dokumentation benötigte einmal Prettier; die finale Formatprüfung ist grün.
Diese beiden Diagnosen waren keine Produkt- oder Testfehler.

## 4. Vollständige Testergebnisse

- Typprüfung `tsc --noEmit`: bestanden.
- ESLint `--max-warnings 0`: bestanden, 0 Warnungen und 0 Fehler.
- Prettier `--check .`: bestanden.
- Build `tsc -p tsconfig.build.json`: bestanden.
- Gesamtsuite: **54/54 Dateien, 276/276 Tests bestanden**.
- Coverage-Lauf: **54/54 Dateien, 276/276 Tests bestanden**.
- Property-Suite: **8/8 Dateien, 19/19 Tests bestanden**.
- Integrationssuite: **11/11 Dateien, 48/48 Tests bestanden**.
- Phase-1-Egress: **4/4 Dateien, 11/11 Tests bestanden**.
- Platform Source: **4/4 Dateien, 12/12 Tests bestanden**.
- Dependency-Audit: `No known vulnerabilities found`.
- `git diff --check`: bestanden.
- Geschützter Phase-1-Pfaddiff: leer.
- Statische Operator-Auth- und External-Action-Importgrenzen: bestanden.
- Keine Tests wurden deaktiviert, übersprungen oder gelockert.
- Node meldet für `node:sqlite` weiterhin die dokumentierte
  `ExperimentalWarning`; sie beeinflusst das Ergebnis nicht.

Die vollständige Befehls-/Ergebnismatrix steht in
`PHASE4_TEST_RESULTS.txt`.

## 5. Testabdeckung

| Metrik     | Abdeckung | Treffer / Gesamt |
| ---------- | --------: | ---------------: |
| Statements |   87,64 % |      3595 / 4102 |
| Branches   |   82,37 % |      2454 / 2979 |
| Functions  |   95,36 % |        762 / 799 |
| Lines      |   88,85 % |      3477 / 3913 |

Alle konfigurierten Schwellen wurden überschritten: Statements, Funktionen
und Zeilen mindestens 80 %, Branches mindestens 75 %. Der neue
`operator-auth`-Bereich erreicht 90,36 % Statements, 85,16 % Branches, 100 %
Functions und 91,80 % Lines.

## Acceptance Criteria

Alle realistisch ausführbaren Kriterien aus
`docs/PHASE4_ACCEPTANCE_CRITERIA.md` sind erfüllt:

- Ed25519-only, Keychain-referenzierter Produktpfad ohne Klartext-Fallback;
- persistente Control-Plane-ID und Cross-Store-Domaintrennung;
- TOFU nur bei engagiertem Kill Switch und leerer Credential-Tabelle;
- exakte signierte Enrollment-, Approval- und Kill-Clear-Envelopes;
- atomare Signatur-, Nonce-, State-, Audit- und Action-Bindung;
- unsigned Entscheidungen und Kill-Clear auf Store- und SQLite-Ebene
  blockiert;
- fail-closed Migration v4 zu v5;
- Consumer-Revalidierung vor Reservation, Start und Settlement;
- signerlose Dashboard-/Simulationspfade bleiben ohne positive Mutation;
- vollständige Unit-, Property-, Persistence-, Tamper-, Egress- und
  Import-Boundary-Regression;
- keine Änderung am geschützten Phase-1-Sicherheitskern.

## Logische Commits

1. `f87487e` — `docs: pin phase 3 baseline and phase 4 scope`
2. `e661f9b` — `feat(operator-auth): add keychain-backed signed statements`
3. `4444652` — `feat(control-plane): require signed operator decisions`
4. `c58f3d5` — `feat(local-ui): sign dashboard and simulation decisions`
5. dieses Abschlussartefakt — `docs: add phase 4 completion package`

## 6. Bekannte Restrisiken

1. Lokales TOFU beweist Schlüsselbesitz, aber weder reale Identität,
   Benutzeranwesenheit, Hardwarebindung noch rechtliche Zustimmung.
2. Rotation, Widerruf, Recovery, Multi-Operator und Quorum fehlen.
3. OS-Account, lokaler Prozess, Systemuhr, Dateisystem, Keychain-Berechtigung
   und rohes Datenbank-Handle bleiben Teil der Trusted Computing Base.
4. Der dokumentierte CLI-Provisioning-Befehl macht Schlüsselmaterial
   kurzzeitig als lokales Prozessargument sichtbar; eine interaktive
   Provisioning-Hilfe ohne Argumentmaterial fehlt.
5. `node:sqlite` ist experimentell; qualifiziert ist der lokale synchrone
   Single-Process-Betrieb, nicht konkurrierender Mehrprozessbetrieb.
6. Crash-Reservationen blockieren absichtlich Budgets und Concurrency, bis ein
   künftig signierter Recovery-Pfad existiert.
7. Das globale Runtime-Budget ist noch kein versionierter signierter Vertrag.
8. Kill-Reader und Evidence-Store sind noch nicht formal durch dieselbe
   unverfälschbare Capability-ID gekoppelt.
9. Event-Key-Rotation, Re-Keying und Recovery fehlen weiterhin.

Die vollständige Bewertung steht in `PHASE4_KNOWN_RISKS.md`.

## 7. Deaktivierte oder zurückgestellte Funktionen

- reale HackerOne-, Bugcrowd- oder andere Plattformadapter;
- echte API-Tokens, Cookies, Passwörter, TOTP-, E-Mail- oder Browser-Sessions;
- Account-Erstellung außerhalb lokaler Testanwendungen;
- automatische Zustimmung zu Regeln, Bedingungen, rechtlichen Erklärungen
  oder menschlichen Checkpoints;
- CAPTCHA- oder Anti-Bot-Umgehung;
- aktive Sicherheitstests und beliebige Zielrequests;
- Report-Einreichung und Triage-Versand;
- LLM-gesteuerte HTTP-/Browserrequests;
- externer Modus und nicht deterministische Runner;
- automatische Operator-Key-Bereitstellung, Rotation, Widerruf und Recovery;
- Event-Key-Rotation und Re-Keying;
- automatische Crash-Recovery, Budgeterstattung und Mehrprozessbetrieb.

`external_integrations_enabled` bleibt standardmäßig und effektiv `false`.
Fehlende Konfiguration, Konfigurationsfehler oder Secret-Store-Fehler
blockieren.

## 8. Bestätigung der externen Grenze

Während Entwicklung und Tests von Phase 4 wurde **kein realer Plattform-,
HackerOne-, Bugcrowd-, Beispiel- oder Bug-Bounty-Host kontaktiert**. Alle
Produkt-, Netzwerk- und Browsertests liefen gegen In-Process-Mocks oder
Loopback-Adressen unter `127.0.0.1`. `.invalid`-Namen wurden ausschließlich als
nicht aufgelöste Metadaten verwendet.

Die einzige sonstige Netzwerkverwendung war der erlaubte Dependency-Audit
gegen die offizielle npm-Paketquelle. Der GitHub-Zugriff dient ausschließlich
dem ausdrücklich verlangten Push des Quellcode-Branches.

## 9. Kleinster empfohlener nächster Schritt für Phase 5

Der kleinste sichere nächste Schritt ist die lokale, versionierte Event-Key-
Rotation: zunächst eine geschlossene Phase-5-Acceptance-Criteria und danach
Key-ID-/Envelope-Versionierung mit dem Grundsatz **write new, read explicitly
versioned old**, ausschließlich über Keychain-Referenzen. Rotation und Re-Key
müssen atomar, restart-sicher, auditierbar und bei fehlendem alten oder neuen
Key fail-closed sein. Noch kein externer Adapter, Browserjourney oder aktiver
Test wird dabei aktiviert.
