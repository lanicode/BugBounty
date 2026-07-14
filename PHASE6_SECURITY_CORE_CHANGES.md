# Phase-6-Änderungen am Sicherheitskern

## Baselines

Phase-5-Baseline:

```text
872e9fe4766dbfd11f46c5b15c71afe7c92d6e60
```

Phase-1-Baseline:

```text
0f0f508765ebec663c2d09dc22fa408c1de46a4f
```

Die Phase-5-Baseline ist zusätzlich in `docs/PHASE5_BASELINE.md` fixiert.

## Kontrollierter Phase-1-Pfaddiff

Der geprüfte Diff der geschützten Phase-1-Pfade gegen Phase 5 enthält genau
eine Produktdatei:

```text
packages/audit-log/audit.ts
```

Verwendete Prüfung:

```sh
git diff --name-only 872e9fe4766dbfd11f46c5b15c71afe7c92d6e60..HEAD -- packages/config packages/egress-guard packages/redaction packages/secret-store packages/event-store packages/policy packages/audit-log packages/recorder packages/shared apps/cli
```

`packages/config`, `packages/egress-guard`, `packages/redaction`,
`packages/secret-store`, `packages/event-store`, `packages/policy`,
`packages/recorder`, `packages/shared` und `apps/cli` bleiben gegenüber dem
vollständigen Phase-5-Commit unverändert.

Änderungen an `packages/control-plane/database.ts` und
`packages/control-plane/store.ts` härten die lokale Phase-2-Control-Plane;
sie sind keine Änderungen an den oben fixierten Phase-1-Pfaden.

## Ausdrücklich markierte Phase-6-Security-Core-Änderung

Die Änderung an `packages/audit-log/audit.ts` ist ausdrücklich eine
**zwingende Phase-6-Security-Core-Änderung**. Der frühere flüchtige
Objekt-Head begann nach jedem Objekt- oder Prozessneustart wieder bei Genesis.
Unabhängige Instanzen konnten deshalb keine sichere gemeinsame lineare Kette
garantieren. Eine Restart- und Mehrprozessqualifikation von Control Plane und
Kill Switch wäre ohne einen restart-sicheren Auditpfad unvollständig.

### Persistierter Head und geschlossenes Recordformat

- `append()` lädt und verifiziert die vollständige persistierte Kette unter
  der Mutation-Lease, bevor Sequenz und Vorgängerhash bestimmt werden.
- `verifyAuditLog()` verwendet dieselbe Pfad-, Lease- und vollständige
  Chain-Verifikation wie Append.
- Der leere Store beginnt bei einem festen Genesis-Hash; ein Reopen setzt
  exakt am letzten verifizierten Record fort.
- Payloads und Records müssen gewöhnliche Objekte mit exakten eigenen,
  enumerierbaren Daten-Deskriptoren sein. Proxies, Accessors, Symbole,
  Zusatzfelder, fehlende Felder und fremde Prototypen blockieren.
- Zeitstempel, Actions, Entscheidungen, Reason Codes, Policy-Hashes und
  optionale Referenzen besitzen geschlossene Formate und Längen.
- Jede Zeile muss die kanonische JSON-Repräsentation des normalisierten
  Records sein. Ungültiges UTF-8, CRLF, Leerzeilen, nicht kanonische Zahlen,
  fehlender finaler Newline und Teilzeilen blockieren.
- Sequenz, Vorgängerhash und SHA-256-Recordhash werden lückenlos neu geprüft.

### Private Pfad- und Mehrprozessgrenze

- Der Auditpfad muss absolut und lexikalisch kanonisch sein. Sein reales
  Elternverzeichnis muss vorab existieren, exakt `0700`, dem aktuellen
  OS-Benutzer gehören und darf kein Symlink sein.
- Auditdatei und Mutation-Lock müssen private reguläre Einzel-Link-Dateien im
  Modus `0600` sein. Öffnen erfolgt mit `O_NOFOLLOW`; Inode/Device und der
  unveränderte Elternpfad werden vor sicherheitsrelevanten Schritten geprüft.
- Append und Verify werden durch `<audit>.mutation.lock` zwischen Objekten und
  lokalen Prozessen serialisiert. Lock-Erstellung ist exklusiv und der
  kanonische Lockrecord bindet Schema-Version, PID und Zufallstoken.
- Konkurrenz wartet höchstens fünf Sekunden und blockiert danach
  deterministisch mit `AUDIT_MUTATION_LOCKED`; ein fremdes Lock wird nie
  automatisch übernommen.
- `recoverStaleAuditMutation()` verlangt die exakte Bestätigung
  `confirm-local-offline-audit-recovery` und akzeptiert nur `ESRCH` als Beweis
  einer stale Owner-PID. Lebende PIDs, `EPERM`, PID-Reuse und unklare Daten
  blockieren.
- Recovery verifiziert das Audit-Log vollständig, bevor die stale Lease
  entfernt wird. Eine Teilzeile oder unbekannte Beschädigung wird nicht
  automatisch bereinigt.

### Größen- und Durability-Grenzen

- Ein einzelner kanonischer Record ist auf 4 KiB begrenzt.
- Die vollständige Datei ist auf 16 MiB und 50.000 Records begrenzt.
- Reads vergleichen Dateigröße und Metadaten vor und nach dem vollständigen
  Lesen; parallele oder ausgetauschte Dateien blockieren.
- Append verwendet `O_APPEND`, schreibt vollständig, synchronisiert die Datei,
  prüft die exakte neue Größe und synchronisiert das Elternverzeichnis vor
  Erfolg.
- Lock-Erstellung und -Entfernung werden ebenfalls auf Datei beziehungsweise
  Verzeichnis synchronisiert. Release-Fehler werden fail-closed gemeldet.
- Das Audit-Log bleibt bodyfrei. Es werden keine Rohbodys, Tokens, Cookies,
  Secrets oder Identitätsdaten ergänzt und es gibt keinen Klartext-Fallback
  für Event- oder Secretdaten.

## Direkte Regressionstests

Die Security-Core-Änderung besitzt eigene direkte Regressionen:

- `tests/unit/audit-log.test.ts`: Restart-Head, geschlossene Payload- und
  Record-Schemas, Kanonizität, Hashkette, UTF-8, Newline, Größenlimits,
  Rechte, Eigentümer, Symlink/Hardlink, Inode-Wechsel, Locks, `fsync` und
  explizite stale Recovery.
- `tests/property/audit-log.property.test.ts`: generierte gültige Ketten und
  Manipulationen von Sequenz, Vorgängerhash, Recordhash und Payloadfeldern.
- `tests/integration/audit-log-process.test.ts`: unabhängige lokale
  Child-Prozesse erzeugen eine einzige verifizierbare lineare Kette; eine
  lebende Child-Lease bleibt blockierend und wird erst nach `SIGKILL` und
  ausdrücklicher Recovery entfernt.
- `tests/fixtures/audit-log-appender.ts` und
  `tests/fixtures/audit-log-lock-holder.ts`: echte Prozessgrenzen für Append,
  Lock-Liveness und Reopen.
- `tests/unit/storage.test.ts` und `tests/fixtures/audit.valid.jsonl`:
  bestehende Audit-Verifikation bleibt mit der nun verpflichtenden
  kanonischen JSONL-Repräsentation kompatibel.
- Die vollständigen Phase-1-, Phase-2-, Phase-3-, Phase-4- und
  Phase-5-Regressionen sowie Egress-, Platform-Source-, Property- und
  Integrationstests bleiben aktiv.

Keine Sicherheitsprüfung wurde deaktiviert, gelockert oder übersprungen. Das
Serialisieren des Coverage-Laufs über `--maxWorkers=1` verändert weder
Produktcode noch Testassertionen. Phase 6 ergänzt keine Laufzeitabhängigkeit.

## Bewusst unveränderte oder zurückgestellte Grenzen

- `external_integrations_enabled` bleibt effektiv `false`.
- Reale Adapter, Plattformzugriffe, aktive Tests, Account-Erstellung,
  Report-Einreichung und LLM-gesteuerte Requests bleiben deaktiviert.
- Audit-Hashes besitzen noch keinen separat erhaltenen authentisierten Head;
  vollständiges Rollback oder Tail-Truncation bleibt daher lokal unerkannt.
- Eine Crash-Teilzeile wird blockiert, aber nicht automatisch repariert.
- Die PID-basierte Lease ist kein verteiltes Lock und qualifiziert keine
  Netzwerkdateisysteme oder allgemeine Active-active-Ausführung.
- Event-Store, Event-Key-Lifecycle, Egress, Redaction, Policy und Secret Store
  bleiben unverändert und ihre bisherigen Grenzen gelten fort.

Während Implementierung und Prüfung wurde kein realer Plattform-, HackerOne-,
Bugcrowd-, Beispiel- oder Bug-Bounty-Zielhost kontaktiert.
