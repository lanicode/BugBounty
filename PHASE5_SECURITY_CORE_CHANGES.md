# Phase-5-Änderungen am Sicherheitskern

## Baselines

Phase-4-Baseline:

```text
a3312cd65c5e64d36a281a7a195bfc862378eac1
```

Phase-1-Baseline:

```text
0f0f508765ebec663c2d09dc22fa408c1de46a4f
```

Die Phase-4-Baseline ist zusätzlich in `docs/PHASE4_BASELINE.md` fixiert.

## Kontrollierter Phase-1-Pfaddiff

Der geprüfte Diff der geschützten Phase-1-Pfade gegen Phase 4 enthält genau
eine Produktdatei:

```text
packages/event-store/store.ts
```

Verwendete Prüfung:

```sh
git diff --name-only a3312cd65c5e64d36a281a7a195bfc862378eac1..HEAD -- packages/config packages/egress-guard packages/redaction packages/secret-store packages/event-store packages/policy packages/audit-log packages/recorder packages/shared apps/cli
```

`packages/config`, `packages/egress-guard`, `packages/redaction`,
`packages/secret-store`, `packages/policy`, `packages/audit-log`,
`packages/recorder`, `packages/shared` und `apps/cli` bleiben gegenüber dem
letzten reinen Phase-4-Commit unverändert.

## Ausdrücklich markierte Phase-5-Security-Core-Änderung

Die Änderung an `packages/event-store/store.ts` ist ausdrücklich eine
**zwingende Phase-5-Security-Core-Änderung**. Ohne sie könnte der Event-Key-
Lifecycle weder die aktive Schreibversion noch die authentisiert aktivierten
historischen Leseversionen technisch durchsetzen.

### Versionierte, geschlossene Eventhüllen

- Die aktive Schreibversion und eine strikt aufsteigende, descriptor-sicher
  gelesene Menge aktivierter Leseversionen werden beim Aufbau des Stores
  validiert.
- Eine zukünftige, ungültige oder nicht aktivierte Hüllenversion blockiert vor
  Key-Referenz- und Secret-Store-Zugriff.
- Eventhüllen besitzen ein exaktes Feldschema ohne Zusatzfelder, Accessors,
  Symbole oder fremde Prototypen.
- Envelope-Version, Key-Version, kanonisches Base64, 12-Byte-Nonce,
  16-Byte-GCM-Tag und nicht leerer Ciphertext werden strikt geprüft.
- Eventpfade müssen direkt im aufgelösten Store liegen und dem geschlossenen
  Dateinamenschema entsprechen. Reads verwenden `O_NOFOLLOW` und akzeptieren
  ausschließlich reguläre Dateien.
- `inspect()` gibt nur Envelope- und Key-Version zurück und entschlüsselt keine
  Eventdaten. Dieser Pfad ermöglicht die explizite, authentifizierende
  Legacy-v1-Adoption im Lifecycle.

### Größen-, Persistenz- und Key-Härtung

- Der maximale serialisierte Envelope beträgt 4 MiB. Ein zu großer Write wird
  vollständig im Speicher verworfen, bevor Verzeichnis, Ziel- oder Tempdatei
  erzeugt werden.
- Eventdateien bleiben write-once: private `wx`-Tempdatei, Datei-`fsync`,
  exklusiver Hardlink und kein Überschreiben eines vorhandenen Ziels.
- Das Elternverzeichnis wird sowohl nach dem Publish als auch nach dem
  Entfernen des Tempnamens mit `fsync` gesichert.
- Temp-Cleanup-Fehler werden nicht unterdrückt. Sie bleiben sichtbar und
  hinterlassen einen Zustand, den der Lifecycle bis zu expliziter Recovery
  blockiert.
- Geladene Schlüssel müssen exakt gewöhnliche 32-Byte-`Uint8Array`-Werte sein.
  Lifecycle- und Event-Store-Kopien sowie abgeleitete MAC-Bytes werden auf
  Erfolgs- und Fehlerpfaden indexbasiert überschrieben; es gibt keinen
  überschreibbaren `fill()`-Fallback.
- Dateien besitzen exakt Modus `0600`, Lifecycle-Verzeichnisse exakt `0700`.

## Neuer Phase-5-Sicherheitsbereich

`packages/event-key-lifecycle` ist neu und erweitert keinen externen
Aktionspfad. Es bildet die lokale Sicherheitsgrenze zwischen Keychain-
Referenzen, authentifiziertem Lifecycle-State und dem Phase-1-Event-Store:

- append-only, kanonische und lückenlose State-Records;
- zufällige Store-ID, SHA-256-Vorgängerkette und HKDF-separierte
  HMAC-SHA-256-Authentisierung;
- monotone Rotation ausschließlich `current + 1` mit Prüfung aller alten und
  neuen Schlüssel auf Vorhandensein, Länge und Verschiedenheit;
- verpflichtender, separat zu erhaltender `minimumActiveKeyVersion`-Anker;
- directory-weite, private und kanonische Mutation-Lease über vollständiges
  `refresh -> write` sowie Rotation, Initialisierung und Legacy-Adoption;
- Blockierung fremder, ungültiger, lebender und verwaister Locks;
- explizite Offline-Recovery nur bei nachweislich nicht existierender
  Owner-PID und nur für exakt benannte private Event-Tempdateien;
- bei Recovery-, Unlink- oder `fsync`-Fehlern bleibt die Lease fail-closed
  bestehen;
- keine automatische Schlüsselbereitstellung, kein Re-Key, keine Löschung
  alter Keys und kein Klartext-/Datei-/Environment-Key-Fallback.

Dashboard, Simulations-CLI und Event-Key-Admin verwenden weiterhin
`MacOSKeychainSecretStore`. Die Umgebungsvariable
`BUGBOUNTY_EVENT_KEY_MIN_VERSION` enthält nur nicht geheime Versionsmetadaten,
ist verpflichtend und besitzt keinen Default.

## Direkte Regressionstests

Die Security-Core-Änderungen besitzen eigene Regressionen:

- `tests/unit/storage.test.ts`: write-once, strikte lesbare Versionen,
  Envelope-Schema, kanonisches Base64, Größenlimit vor Dateierzeugung,
  `O_NOFOLLOW`, Key-Zeroisierung, Elternverzeichnis-`fsync` und
  Cleanup-Fehler.
- `tests/property/event-envelope.property.test.ts`: generierte ungültige
  Envelope-Felder vor Secret-Zugriff und authentifizierte
  Ciphertext-Manipulationen.
- `tests/unit/event-key-lifecycle.test.ts`: State-Schema, HMAC, Chain,
  Rotation, Keyfehler, Rechte, Symlinks, Accessors, Legacy-Adoption und
  Zeroisierung.
- `tests/property/event-key-lifecycle.property.test.ts` und
  `tests/property/event-key-rotation-invalid.property.test.ts`: Mutationen
  aller State-Felder, monotone gültige Folgen sowie stale, übersprungene,
  rückwärts gerichtete und ungültige Rotationen.
- `tests/unit/event-key-mutation-lease.test.ts`: exakte Lease, konkurrierende
  Writer/Rotationen, aktive und stale PIDs, strikte Recovery und
  Tempdateigrenzen.
- `tests/unit/event-key-state-commit-faults.test.ts`: Fehler vor dem finalen
  Link behalten v1; ein bereits gelinkter v2-Record wird nach einem gemeldeten
  `fsync`-Fehler beim Restart als v2 authentifiziert.
- `tests/unit/event-key-recovery-faults.test.ts`: Unlink- und
  Verzeichnis-`fsync`-Fehler bleiben mit Lock fail-closed.
- `tests/integration/event-key-mutation-crash.test.ts`: echte Child-Prozesse
  werden vor und nach dem Commit per `SIGKILL` beendet; aktive Locks sind
  nicht übernehmbar, stale Locks nur explizit.
- `tests/integration/event-key-restart.test.ts`: Reopen, alte und neue
  Ciphertexte, fehlende historische Keys, Cross-Store-Manipulation,
  Chain-Lücken und abgeschnittener Head gegen verpflichtenden Minimum-Anker.
- `tests/integration/event-key-admin-cli.test.ts`: fehlende oder ungültige
  Minimum-Konfiguration blockiert vor `.local`- und Keychain-Zugriff; Recovery
  verlangt das exakte lokale Bestätigungsflag.
- bestehende Dashboard-, Simulation-, Egress-, Platform-Source-, Phase-4- und
  vollständige Phase-1-Regressionen bleiben aktiv.

Keine Sicherheitsprüfung wurde deaktiviert, gelockert oder übersprungen. Phase
5 ergänzt keine neue Laufzeitabhängigkeit.

## Bewusst unveränderte oder zurückgestellte Grenzen

- `external_integrations_enabled` bleibt effektiv `false`.
- Reale Adapter, Plattformzugriffe, aktive Tests, Account-Erstellung,
  Report-Einreichung und LLM-gesteuerte Requests bleiben deaktiviert.
- Alte Eventhüllen werden nicht automatisch neu verschlüsselt.
- Alte Keychain-Einträge werden nicht automatisch gelöscht oder stillgelegt.
- Ein vollständiges gemeinsames Rollback von State, Eventdateien und separat
  erhaltener Minimum-Konfiguration bleibt eine lokale TCB-Grenze.
- PID-Reuse, lokaler OS-Account, Prozess, Keychain und Dateisystem bleiben
  Vertrauensannahmen.
- Ein allgemeiner Active-active-Mehrprozessbetrieb der Control Plane,
  Approval Queue, des Kill Switches und Audit Logs ist nicht Teil von Phase 5.

Während Implementierung und Prüfung wurde kein realer Plattform-, HackerOne-,
Bugcrowd-, Beispiel- oder Bug-Bounty-Zielhost kontaktiert.
