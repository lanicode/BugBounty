# Phase-6-Abschlussbericht

Stand: 14. Juli 2026

Branch: `codex/phase-6-control-plane-recovery`

Phase-5-Baseline:
`872e9fe4766dbfd11f46c5b15c71afe7c92d6e60`

Getesteter Implementierungsstand:
`7b2240f` zuzüglich dieses reinen Dokumentations-Abschlusscommits

## Ergebnis

Phase 6 qualifiziert die lokale Control Plane, den globalen Kill Switch und
das Phase-1-Audit-Log für kontrollierte Prozessneustarts, `SIGKILL` an
definierten Commitgrenzen und konkurrierende lokale Prozesse. Die Grenzen
bleiben deny-by-default und fail-closed; Phase 6 beansprucht ausdrücklich
keinen allgemeinen Active-active-, Cluster- oder Netzwerkdateisystembetrieb.

Es wurde kein realer Plattform-, HackerOne-, Bugcrowd-, Beispiel- oder
Bug-Bounty-Zielhost kontaktiert. Produkt-Netzwerk- und Browsertests liefen nur
in-process oder gegen kurzlebige Mock-Server auf `127.0.0.1`. Die offizielle
npm-Quelle wurde ausschließlich für den erlaubten Dependency-Audit verwendet;
GitHub wird ausschließlich für den verlangten Source-Control-Push verwendet.

## 1. Architekturzusammenfassung

```text
lokaler absoluter SQLite-Pfad
  -> kanonisches privates Verzeichnis (0700)
  -> privates reguläres DB- und Sidecar-File (0600, kein Symlink/Hardlink)
  -> SQLite DELETE journal + FULL/fullfsync + Foreign Keys
  -> Migration-Checksummen + integrity_check + foreign_key_check
  -> BEGIN IMMEDIATE / verschachtelte Savepoints / CONTROL_PLANE_BUSY
  -> ControlPlaneStore
       |-- Engagement zuerst dauerhaft auf engaged
       |-- aktive Kampagnen separat dauerhaft pausieren
       |-- Audit anschließend binden
       |-- Reopen versöhnt Teilzustände nur zu engaged/paused
       `-- Clear bleibt signiert und atomar

privater lokaler Audit-Pfad
  -> prozessübergreifende exklusive Mutation-Lease
  -> vollständige Head-Verifikation vor jedem Append
  -> exaktes kanonisches JSONL-Schema + SHA-256-Vorgängerkette
  -> begrenzter O_APPEND-Write + Datei-fsync + Verzeichnis-fsync
  `-- Teilzeilen, Manipulation und unklare Locks blockieren
```

Die SQLite-Grenze akzeptiert nur einen lokalen, absoluten und konservativ
kanonischen Pfad. Sie prüft Eigentümer, Typ, Rechte, Linkanzahl, Sidecars,
Pragmas, Migrationen und relationale Integrität bei jedem Open. Unabhängige
Writer werden auf einen begrenzten Busy-Zeitraum serialisiert; Busy/Locked wird
deterministisch zu `CONTROL_PLANE_BUSY`. Ein durch `SIGKILL` abgebrochener
offener Write wird von SQLite zurückgerollt, ein vorheriger Commit bleibt nach
Reopen erhalten.

Kill-Switch-Engagement bleibt bewusst asymmetrisch: Der Switch wird zuerst
dauerhaft aktiviert. Pause und Audit dürfen diesen sicheren Commit bei einem
späteren Fehler nicht zurückrollen. Beim Aufbau eines `ControlPlaneStore`
werden freigegebene oder laufende Kampagnen unter einem aktiven oder nicht
vollständig beweisbaren Clear in einer `BEGIN IMMEDIATE`-Transaktion pausiert.
Ein Clear erfordert weiterhin die vorhandene frische, kontextgebundene
Operator-Signatur.

Das Audit-Log besitzt keinen flüchtigen Head mehr. Append und Verify erwerben
eine private prozessübergreifende Lease, lesen und verifizieren den gesamten
persistierten Head und setzen Sequenz und Hash nach Objekt- oder
Prozessneustart fort. Nicht kanonische Records, Zusatzfelder, Accessors,
fremde Prototypen, ungültige UTF-8-Daten, Leer- und Teilzeilen, Symlinks,
Hardlinks, falsche Rechte und Größenüberschreitungen blockieren.

## 2. Liste aller Änderungen

1. Letzten vollständigen Phase-5-Commit in `docs/PHASE5_BASELINE.md` fixiert
   und den geschlossenen Phase-6-Umfang dokumentiert.
2. File-backed SQLite auf absolute, kanonische, eigentümergebundene Pfade,
   private Verzeichnisse und private reguläre DB-/Sidecar-Dateien gehärtet.
3. `O_NOFOLLOW`, Linkanzahl- und Inode-Prüfungen sowie konservative
   Sidecar-Validierung ergänzt.
4. Journalmodus `DELETE`, `synchronous=FULL`, `fullfsync=ON`, normales
   Locking, Foreign Keys, deaktiviertes Trusted Schema, In-Memory-Tempstore und
   ein Busy-Limit von 1.000 ms erzwungen und zurückgelesen.
5. Migration-Checksummen durch `integrity_check(1)` und
   `foreign_key_check` vor beziehungsweise nach Migrationen ergänzt.
6. SQLite-Busy/Locked deterministisch auf `CONTROL_PLANE_BUSY` abgebildet;
   fehlgeschlagene Rollbacks vergiften die Instanz fail-closed.
7. Verschachtelte synchrone Transaktionen mit eindeutigen Savepoints
   abgesichert; asynchrone Callback-Ergebnisse bleiben verboten.
8. Kill-Switch-Engagement in dauerhafte Sicherheitsgrenzen für Engagement,
   Kampagnenpause und Auditbindung getrennt, ohne Clear-Rollback.
9. Sichere Reopen-Versöhnung im `ControlPlaneStore` ergänzt: unvollständige
   Clear-Evidence gilt als engaged und aktive Kampagnen werden pausiert.
10. Das Phase-1-Audit-Log restart-sicher gemacht: persistierter Head wird vor
    jedem Append vollständig neu geladen und validiert.
11. Private prozessübergreifende Audit-Mutation-Lease mit exaktem Lockrecord,
    begrenztem Wait und ausdrücklicher Offline-Stale-Recovery ergänzt.
12. Auditpfad, Datei, Elternverzeichnis und Lock auf Kanonizität, Typ,
    Eigentümer, Rechte, Linkanzahl, Inode und Symlinkfreiheit begrenzt.
13. Auditpayload und -record auf exakte Daten-Deskriptoren, kanonisches JSON,
    enge Wertformate sowie Datei-, Record- und Eintragslimits gehärtet.
14. Audit-Appends vor Erfolg auf Datei und Verzeichnis synchronisiert;
    Teilzeilen und unklare Mutationen werden nicht still repariert.
15. Unit-, Property-, Prozess-, Konkurrenz-, Reopen-, `SIGKILL`- und
    vollständige Regressionstests ergänzt.
16. Coverage-Instrumentierung mit `--maxWorkers=1` serialisiert, damit der
    offizielle Gesamtlauf reproduzierbar bleibt, ohne einen Test zu ändern.

Der exakte Dateisatz steht in `PHASE6_FILE_MANIFEST.txt`.

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
pnpm exec vitest run tests/unit/control-plane/database-hardening.test.ts tests/integration/control-plane-database-crash.test.ts tests/unit/audit-log.test.ts tests/property/audit-log.property.test.ts tests/integration/audit-log-process.test.ts tests/unit/control-plane/store.test.ts tests/integration/kill-switch-recovery.test.ts
pnpm audit --audit-level high
git diff --check
git diff --name-only 872e9fe4766dbfd11f46c5b15c71afe7c92d6e60..HEAD -- packages/config packages/egress-guard packages/redaction packages/secret-store packages/event-store packages/policy packages/audit-log packages/recorder packages/shared apps/cli
git diff --name-status 872e9fe4766dbfd11f46c5b15c71afe7c92d6e60..HEAD
git log --oneline 872e9fe4766dbfd11f46c5b15c71afe7c92d6e60..HEAD
git status --short --branch
```

Zusätzlich liefen fokussierte Test-, TypeScript-, ESLint-, Prettier- und
Diff-Prüfungen während der Komponentenimplementierung. Die tatsächlich
verwendete Shell setzte den absoluten gebündelten Node-/pnpm-Pfad vor die
Projektkommandos.

## 4. Vollständige Testergebnisse

- Typprüfung `tsc --noEmit`: bestanden.
- ESLint `--max-warnings 0`: bestanden, 0 Warnungen und 0 Fehler.
- Prettier `--check .`: bestanden.
- Build `tsc -p tsconfig.build.json`: bestanden.
- Gesamtsuite: **73/73 Dateien, 383/383 Tests bestanden**.
- Coverage-Lauf: **73/73 Dateien, 383/383 Tests bestanden**.
- Property-Suite: **12/12 Dateien, 27/27 Tests bestanden**.
- Integrationssuite: **18/18 Dateien, 69/69 Tests bestanden**.
- Phase-1-Egress: **4/4 Dateien, 11/11 Tests bestanden**.
- Platform Source: **4/4 Dateien, 12/12 Tests bestanden**.
- Fokussierte Phase-6-Suite: **7/7 Dateien, 50/50 Tests bestanden**.
- Dependency-Audit: `No known vulnerabilities found`.
- `git diff --check`: bestanden.
- Geschützter Phase-1-Pfaddiff: ausschließlich die dokumentierte Änderung
  `packages/audit-log/audit.ts`.
- Keine Tests wurden deaktiviert, übersprungen oder gelockert.

Die ersten DB-Child-Testläufe werteten die dokumentierte
`node:sqlite`-Experimentalwarnung im Child-stderr als unerwartete Ausgabe. Die
Child-Fixtures starten seitdem mit `--no-warnings`; dies unterdrückt nur die
Runtime-Warnung und verändert weder Produktcode noch Sicherheitsassertionen.

Frühe Coverage-Läufe überlappten, weil länger laufende Exec-Sessions nicht
rechtzeitig gepollt wurden; unter dieser Ressourcenlast trat einmal ein
Dashboard-Testtimeout auf. Der offizielle Coverage-Lauf wurde anschließend
über das Projektskript mit `--maxWorkers=1` vollständig serialisiert und lief
grün. Kein Test wurde dafür inhaltlich abgeschwächt.

Die vollständige Ergebnismatrix steht in `PHASE6_TEST_RESULTS.txt`.

## 5. Testabdeckung

| Metrik     | Abdeckung | Treffer / Gesamt |
| ---------- | --------: | ---------------: |
| Statements |   88,00 % |      4657 / 5292 |
| Branches   |   82,65 % |      3064 / 3707 |
| Functions  |   96,23 % |        921 / 957 |
| Lines      |   89,18 % |      4495 / 5040 |

Alle konfigurierten Schwellen wurden überschritten: Statements, Funktionen
und Zeilen mindestens 80 %, Branches mindestens 75 %.

| Bereich                     | Statements | Branches | Functions |   Lines |
| --------------------------- | ---------: | -------: | --------: | ------: |
| `packages/audit-log`        |    86,64 % |  81,17 % |     100 % | 87,39 % |
| `packages/control-plane`    |    86,69 % |  82,17 % |   99,10 % | 88,25 % |
| `control-plane/database.ts` |    88,08 % |  76,02 % |     100 % | 91,33 % |
| `control-plane/store.ts`    |    84,49 % |  79,25 % |   99,22 % | 86,64 % |

## Acceptance Criteria

Alle realistisch ausführbaren Kriterien aus
`docs/PHASE6_ACCEPTANCE_CRITERIA.md` sind erfüllt:

- private, geschlossene und bei Open vollständig geprüfte SQLite-Pfade;
- erzwungene und verifizierte lokale Durability-Pragmas;
- Migration-, SQLite- und Foreign-Key-Integritätsprüfung;
- deterministische Busy-Grenze und echte `SIGKILL`-Rollbacknachweise;
- fail-safe Kill-Switch-Engagement und sichere Reopen-Versöhnung;
- signierter, atomarer Kill-Switch-Clear bleibt unverändert erforderlich;
- restart-sicheres, serialisiertes und kanonisches Audit-Append;
- strikte Audit-Größen-, Pfad-, Format- und Durability-Grenzen;
- Unit-, Property-, Prozess-, Restart- und vollständige Regressionstests;
- ausschließlich dokumentierte Änderung am Phase-1-Audit-Log.

## Logische Commits

1. `f50af63` — `docs: pin phase 5 baseline and phase 6 scope`
2. `f14ce1a` — `security(control-plane): harden durable sqlite recovery`
3. `a6fccff` — `security(audit-log): add restart-safe durable appends`
4. `fe021b8` — `security(kill-switch): reconcile crash-safe campaign pauses`
5. `7b2240f` — `test: serialize coverage instrumentation`
6. dieses Abschlussartefakt — `docs: add phase 6 completion package`

## 6. Bekannte Restrisiken

1. Eine konsistente vollständige Audit-Dateirücksetzung oder Tail-Truncation
   ist ohne separat erhaltenen Head oder Transparenzanker nicht erkennbar.
2. PID-Wiederverwendung oder unklare Prozesssicht kann eine stale Audit-Lease
   konservativ dauerhaft blockieren.
3. Eine durch Crash erzeugte Audit-Teilzeile wird nicht automatisch entfernt;
   es existiert noch kein sicherer Partial-Line-Recovery-Befehl.
4. Lokaler OS-Account, Prozessintegrität, SQLite, Dateisystem- und
   `fsync`-Semantik bleiben Teil der TCB; macOS-Root-Aliase `/var` und `/tmp`
   werden als OS-TCB akzeptiert.
5. Der qualifizierte SQLite-`DELETE`-Journalpfad gilt nicht für allgemeine
   Netzwerk- oder ungewöhnliche Dateisysteme.
6. Die sichere Kill-Switch-Versöhnung im Store-Konstruktor erzeugt keinen
   eigenen neuen forensischen Recovery-Auditeintrag.
7. Die lokale Serialisierung ist kein allgemeiner Active-active-Betrieb.
8. Generische Approval-Decision-Audits sind nicht für jede Approval-Art über
   eine eigene relationale Foreign-Key-Bindung modelliert.
9. Reservierte oder laufende External-Action-Attempts werden nach Crash weder
   automatisch wiederholt noch erstattet.
10. `node:sqlite` ist in Node.js weiterhin als experimentell markiert.

Die vollständige Bewertung steht in `PHASE6_KNOWN_RISKS.md`.

## 7. Deaktivierte oder zurückgestellte Funktionen

- reale HackerOne-, Bugcrowd- oder andere Plattformadapter;
- echte API-Tokens, Cookies, Passwörter, TOTP-, E-Mail- oder Browser-Sessions;
- Account-Erstellung außerhalb lokaler Testanwendungen;
- automatische Zustimmung zu Regeln, Bedingungen, rechtlichen Erklärungen
  oder menschlichen Checkpoints;
- CAPTCHA- und Anti-Bot-Umgehung;
- aktive Sicherheitstests und beliebige Zielrequests;
- Report-Einreichung und Triage-Versand;
- LLM-gesteuerte HTTP- oder Browserrequests;
- reale oder generische externe Runner;
- automatische Audit-Teilzeilenreparatur und externer Audit-Head;
- allgemeiner Active-active-, Cluster- oder Netzwerkdateisystembetrieb.

`external_integrations_enabled` bleibt standardmäßig und bei fehlender oder
fehlerhafter Konfiguration effektiv `false`. Die fünf simulationsfähigen
Registry-Actions erreichen weiterhin nur den deterministischen
In-Process-Mock; `report_submit` und `triage_response_send` besitzen keinen
Runner.

## 8. Bestätigung der Netzwerkgrenze

Während Entwicklung und Tests wurde **kein realer Plattform-, HackerOne-,
Bugcrowd-, Beispiel- oder Bug-Bounty-Zielhost kontaktiert**. Produktverkehr
blieb vollständig in-process oder auf `127.0.0.1` beschränkt. Nur der erlaubte
Dependency-Audit gegen die offizielle npm-Quelle und der ausdrücklich
verlangte Source-Control-Push zu GitHub liegen außerhalb dieser Produktgrenze.

## 9. Kleinster empfohlener nächster Schritt für Phase 7

Als kleinster konservativer Schritt sollte Phase 7 zunächst geschlossene
Acceptance Criteria definieren und genau eine deterministische Playwright-Test-
Referenzjourney gegen die vorhandene Demo-SaaS auf `127.0.0.1` implementieren.
Persistierte Screenshots oder andere UI-Evidence müssen dabei vor dem
Schreiben lokal redigiert werden. Externe Adapter, Konten, Zielhosts und reale
Transporte bleiben unverändert deaktiviert.
