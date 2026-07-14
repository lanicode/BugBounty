# Phase-5-Abschlussbericht

Stand: 14. Juli 2026

Branch: `codex/phase-5-event-key-rotation`

Phase-4-Baseline: `a3312cd65c5e64d36a281a7a195bfc862378eac1`

Getesteter Implementierungsstand:
`4d1e3bb` zuzüglich dieses reinen Dokumentations-Abschlusscommits

## Ergebnis

Phase 5 implementiert den lokalen, restart-sicheren Event-Key-Lifecycle nach
dem Grundsatz **write new -> read explicitly activated old**. Eine Rotation
aktiviert ausschließlich `current + 1` für neue Writes. Alte Hüllen werden
nicht automatisch umgeschrieben und alte Keys nicht automatisch gelöscht.

Der State ist append-only, HMAC-authentifiziert, digest-verkettet und durch
einen verpflichtenden separat zu erhaltenden Mindestversionsanker gegen ein
versehentlich akzeptiertes Tail-Rollback begrenzt. Eine directory-weite
Mutation-Lease schließt Write-/Rotate-Races. Echte `SIGKILL`-Tests beweisen den
Wiederanlauf vor und nach der atomaren Commitgrenze. Unklare Zustände bleiben
blockiert, bis ein expliziter lokaler Offline-Recovery-Befehl ausgeführt wird.

Der einzige ausführbare External-Action-Runner bleibt ein deterministischer
In-Process-Mock. Es wurde kein realer Plattform-, HackerOne-, Bugcrowd-,
Beispiel- oder Bug-Bounty-Zielhost kontaktiert. Netzwerk- und Browsertests
verwendeten ausschließlich kurzlebige Mock-Server auf `127.0.0.1`. Die
offizielle npm-Registry wurde nur für den erlaubten Dependency-Audit
kontaktiert; GitHub wird ausschließlich für den ausdrücklich verlangten
Source-Control-Push verwendet.

## 1. Architekturzusammenfassung

```text
verpflichtende nicht geheime Konfiguration
BUGBOUNTY_EVENT_KEY_MIN_VERSION
  -> MacOSKeychainSecretStore
       keychain://bugbounty-copilot/event-store-vN
  -> EventKeyLifecycle
       |-- exakte private Mutation-Lease im Eventverzeichnis
       |-- append-only state-NNNNNNNNNN.json
       |-- zufällige Store-ID
       |-- SHA-256-Vorgängerkette
       |-- HKDF-SHA-256 -> HMAC-SHA-256 pro Record
       |-- activeKeyVersion = revision
       `-- readableKeyVersions = [1..active]
  -> EncryptedEventStore
       |-- neue Writes nur mit activeKeyVersion
       |-- Reads nur mit explizit aktivierten Versionen
       |-- AES-256-GCM und exakte Envelope-Grenzen
       |-- write-once Temp + fsync + Hardlink + Directory-fsync
       `-- Key-Kopien werden auf allen Pfaden überschrieben
```

Rotation hält die Mutation-Lease über vollständige State-Verifikation,
Keyprüfung, Record-Commit und erneutes Reload. Ein Crash vor dem finalen Link
lässt den alten Head aktiv; ein gelinkter und authentifizierbarer Record wird
nach Restart zum neuen Head. Ein lebender Lock-Inhaber kann nicht durch
Recovery verdrängt werden. Nur `ESRCH` gilt als stale; `EPERM`, PID-Reuse und
unklare Lockdaten blockieren.

Die Produktkomposition besitzt keinen Default für die Mindestversion. Nach
erfolgreicher Rotation wird der ausgegebene neue Wert separat übernommen,
bevor Dashboard oder Simulation neu starten. Ein gemeinsames vollständiges
Rollback von State, Eventdateien, Keychain und dieser Konfiguration bleibt
ausdrücklich Teil der lokalen Trusted Computing Base.

Details stehen in `docs/PHASE5_EVENT_KEY_LIFECYCLE.md`.

## 2. Liste aller Änderungen

1. Letzten reinen Phase-4-Commit fixiert und geschlossene Phase-5-Acceptance-
   Criteria dokumentiert.
2. `packages/event-store` als zwingende Phase-5-Security-Core-Änderung auf
   aktive Schreib- und explizit lesbare Key-Versionen erweitert.
3. Eventhüllen auf exaktes Schema, kanonisches Base64, feste Nonce-/Taggrößen,
   sichere Versionsgrenzen, `O_NOFOLLOW` und maximal 4 MiB gehärtet.
4. Oversize-Writes vor jeder Dateierzeugung blockiert; Elternverzeichnis nach
   Publish und Temp-Cleanup mit `fsync` gesichert.
5. Event-Key-Kopien und abgeleitete MAC-Bytes indexbasiert auf Erfolgs- und
   Fehlerpfaden überschrieben; kein Klartext- oder `fill()`-Fallback.
6. Neues `packages/event-key-lifecycle` mit kanonischer append-only
   State-Chain, Store-Domainbindung, HKDF und HMAC implementiert.
7. Monotone Rotation mit Expected-Version, `current + 1`, Keylängen-,
   Vollständigkeits- und Duplikatsprüfung implementiert.
8. `minimumActiveKeyVersion` in API, Dashboard, Simulation und Admin-CLI
   verpflichtend gemacht; fehlende oder ungültige Konfiguration blockiert.
9. Directory-weite Mutation-Lease für Initialisierung, Legacy-Adoption,
   `refresh + write` und Rotation ergänzt.
10. Explizite stale Recovery mit PID-Liveness-Prüfung, exaktem Bestätigungsflag
    und eng begrenzter Event-Temp-Bereinigung ergänzt.
11. Explizite, vollständig authentifizierende Legacy-v1-Adoption ergänzt;
    stilles Übernehmen vorhandener Events bleibt verboten.
12. Dashboard- und CLI-Simulation vor fachlicher Mutation an den persistierten
    Lifecycle-Head gebunden.
13. Unit-, Property-, Fault-, Child-Process-, `SIGKILL`-, Restart-, CLI-,
    Dashboard- und Simulationsregressionen ergänzt.
14. Sicherheitskern-, External-Action-, Risiko-, Test-, Betriebs- und
    Roadmap-Dokumentation auf Phase 5 aktualisiert.

Der exakte Dateisatz steht in `PHASE5_FILE_MANIFEST.txt`.

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
git diff --check
git diff --name-only a3312cd65c5e64d36a281a7a195bfc862378eac1..HEAD -- packages/config packages/egress-guard packages/redaction packages/secret-store packages/event-store packages/policy packages/audit-log packages/recorder packages/shared apps/cli
git diff --name-status a3312cd65c5e64d36a281a7a195bfc862378eac1..HEAD
git log --oneline a3312cd65c5e64d36a281a7a195bfc862378eac1..HEAD
git status --short --branch
```

Zusätzlich liefen wiederholt fokussierte Vitest-Suites für Event Store,
Lifecycle, Property-, Fault-, Restart-, CLI- und Child-Process-Grenzen sowie
Prettier-, TypeScript-, ESLint- und Diff-Checks. Der zentrale fokussierte Lauf
bestand mit 13/13 Dateien und 82/82 Tests. Die tatsächlich verwendete Shell
setzte den absoluten gebündelten Node-/pnpm-Pfad vor jedes Projektkommando.

Ein erster kurzer `pnpm typecheck`-Aufruf vor dem Laden dieses Runtime-Pfads
endete mit `command not found`. Ein unprivilegierter Gesamtlauf traf danach
erwartungsgemäß auf Socket-`EPERM` für lokale Loopback-Server und deckte
zusätzlich eine fehlende Event-Loop-Halterung im absichtlich blockierten
Pre-Link-Test-Child auf. Der Test-Holder wurde ohne Änderung einer
Produktprüfung an seinen vorhandenen stdin-Gate gebunden. Der finale
Gesamtlauf bestand anschließend vollständig mit expliziter Loopback-
Berechtigung.

## 4. Vollständige Testergebnisse

- Typprüfung `tsc --noEmit`: bestanden.
- ESLint `--max-warnings 0`: bestanden, 0 Warnungen und 0 Fehler.
- Prettier `--check .`: bestanden.
- Build `tsc -p tsconfig.build.json`: bestanden.
- Gesamtsuite: **67/67 Dateien, 356/356 Tests bestanden**.
- Coverage-Lauf: **67/67 Dateien, 356/356 Tests bestanden**.
- Property-Suite: **11/11 Dateien, 24/24 Tests bestanden**.
- Integrationssuite: **15/15 Dateien, 63/63 Tests bestanden**.
- Phase-1-Egress: **4/4 Dateien, 11/11 Tests bestanden**.
- Platform Source: **4/4 Dateien, 12/12 Tests bestanden**.
- Dependency-Audit: `No known vulnerabilities found`.
- `git diff --check`: bestanden.
- Geschützter Phase-1-Pfaddiff: ausschließlich die dokumentierte Änderung
  `packages/event-store/store.ts`.
- Keine Tests wurden deaktiviert, übersprungen oder gelockert.
- Node meldet für `node:sqlite` weiterhin die dokumentierte
  `ExperimentalWarning`; sie beeinflusst das Ergebnis nicht.

Die vollständige Befehls-/Ergebnismatrix steht in
`PHASE5_TEST_RESULTS.txt`.

## 5. Testabdeckung

| Metrik     | Abdeckung | Treffer / Gesamt |
| ---------- | --------: | ---------------: |
| Statements |   88,17 % |      4197 / 4760 |
| Branches   |   83,14 % |      2817 / 3388 |
| Functions  |   95,95 % |        855 / 891 |
| Lines      |   89,27 % |      4052 / 4539 |

Alle konfigurierten Schwellen wurden überschritten: Statements, Funktionen
und Zeilen mindestens 80 %, Branches mindestens 75 %. Der neue Bereich
`event-key-lifecycle` erreicht 91,12 % Statements, 87,95 % Branches, 100 %
Functions und 91,79 % Lines. Der geänderte `event-store` erreicht 91,66 %
Statements, 87,82 % Branches, 100 % Functions und 93,54 % Lines.

## Acceptance Criteria

Alle realistisch ausführbaren Kriterien aus
`docs/PHASE5_ACCEPTANCE_CRITERIA.md` sind erfüllt:

- versionierter Keychain-referenzierter Produktpfad ohne Secret-Fallback;
- `write new -> read explicitly activated old` technisch erzwungen;
- exakt monotone Rotation mit vollständigem Key-Preflight;
- authentifizierte append-only State-Chain mit HKDF/HMAC und Store-Bindung;
- verpflichtender separater Minimum-Versionsanker;
- private, durable und prozessübergreifend wirksame Mutation-Lease;
- kontrollierte Commit-Faults vor und nach dem finalen Link;
- echte `SIGKILL`- und Child-Process-Recovery-Nachweise;
- explizite, eng begrenzte Offline-Recovery ohne automatische Übernahme;
- explizite authentifizierte Legacy-v1-Adoption;
- vollständige Unit-, Property-, Persistence-, Egress- und
  Phase-1-/Phase-4-Regression;
- ausschließlich dokumentierte Änderung am Phase-1-Event-Store.

## Logische Commits

1. `6e7350f` — `docs: pin phase 4 baseline and phase 5 scope`
2. `f28f6c5` — `security(event-store): harden versioned durable envelopes`
3. `64e5de9` — `feat(event-keys): add restart-safe local key lifecycle`
4. `4d1e3bb` — `feat(local-runtime): activate managed event key heads`
5. dieses Abschlussartefakt — `docs: add phase 5 completion package`

## 6. Bekannte Restrisiken

1. Ein vollständiges gemeinsames Rollback von Eventverzeichnis, State-Chain,
   Keychain und separat erhaltener Minimum-Konfiguration bleibt Teil der TCB.
2. OS-Account, lokaler Prozess, Keychain-ACLs, Dateisystem-, Hardlink- und
   `fsync`-Semantik bleiben Vertrauensannahmen.
3. PID-Reuse oder nicht entscheidbare Liveness führt konservativ zu einem
   dauerhaften Recovery-Block.
4. Recovery ist ein Offline-Adminvorgang mit Bestätigungsflag, aber keine
   Operator-Signatur oder Garantie menschlicher Anwesenheit.
5. Historische Keys bleiben für Chain-Verifikation und alte Events zwingend;
   ihr Verlust blockiert den ganzen Store.
6. Automatisches Re-Keying, Retirement, Löschen, Escrow und Restore alter Keys
   fehlen.
7. Gültig benannte State-Temps werden nie Head, benötigen bei dauerhafter
   Ansammlung aber forensische manuelle Bereinigung.
8. Die Lease qualifiziert gezielte lokale Write-/Rotate-Races, keinen
   allgemeinen Active-active-, Container- oder Netzwerkdateisystembetrieb.
9. Approval Queue, Kill Switch, Control Plane und Audit Log besitzen noch
   keine gemeinsame Crash-/Mehrprozessqualifikation.
10. Die Restrisiken der signierten Phase-4-Operator- und External-Action-
    Grenzen bleiben bestehen.

Die vollständige Bewertung steht in `PHASE5_KNOWN_RISKS.md`.

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
- automatische Event-Key-Erzeugung oder -Provisionierung;
- automatisches Re-Keying oder Umschreiben alter Hüllen;
- automatische Löschung, Retirement oder Recovery alter Keys;
- automatische Übernahme unbekannter Locks oder Tempdateien;
- allgemeiner Active-active-Mehrprozessbetrieb.

`external_integrations_enabled` bleibt standardmäßig und effektiv `false`.
Fehlende Konfiguration, Konfigurationsfehler oder Secret-Store-Fehler
blockieren.

## 8. Bestätigung der externen Grenze

Während Entwicklung und Tests von Phase 5 wurde **kein realer Plattform-,
HackerOne-, Bugcrowd-, Beispiel- oder Bug-Bounty-Host kontaktiert**. Alle
Produkt-, Netzwerk- und Browsertests liefen gegen In-Process-Mocks oder
Loopback-Adressen unter `127.0.0.1`. `.invalid`-Namen wurden ausschließlich als
nicht aufgelöste Metadaten verwendet.

Die einzige sonstige Netzwerkverwendung war der erlaubte Dependency-Audit
gegen die offizielle npm-Paketquelle. Der GitHub-Zugriff dient ausschließlich
dem ausdrücklich verlangten Push des Quellcode-Branches.

## 9. Kleinster empfohlener nächster Schritt für Phase 6

Der kleinste sichere nächste Schritt ist eine geschlossene Phase-6-Acceptance-
Criteria für Crash-/Restart- und Mehrprozesshärtung der bereits lokalen
Approval Queue, des Kill Switches, der Control Plane und des Audit Logs. Als
erste Implementierung sollte genau ein file-backed `SIGKILL`-Szenario beweisen,
dass ein bestätigtes Kill-Switch-Engagement nach Prozessabbruch und Reopen
weiterhin fail-closed aktiv ist. Noch keine Browserjourney, kein externer
Adapter und kein aktiver Test wird dabei aktiviert.
