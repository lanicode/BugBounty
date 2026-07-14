# Phase 6 – lokale Control-Plane- und Audit-Recovery

## Umfang

Phase 6 qualifiziert ausschließlich lokale Persistenz auf einem vom aktuellen
OS-Benutzer kontrollierten Dateisystem. Sie aktiviert keine externen
Integrationen, Plattformadapter, Accounts, aktiven Sicherheitstests,
Reporteinreichungen oder LLM-gesteuerten Requests. Produkt-Netzwerk- und
Browsertests bleiben auf `127.0.0.1` beschränkt.

## SQLite-Betriebsvertrag

`ControlPlaneDatabase.file()` verlangt einen absoluten normalisierten Pfad.
Das unmittelbare Elternverzeichnis muss regulär, vom aktuellen Benutzer
besessen und exakt `0700` sein. Die Datenbank muss regulär, single-link,
benutzereigen und exakt `0600` sein. User-owned Symlink-Ahnen, ein Symlink oder
Hardlink als Datenbank, unerwartete Dateitypen sowie `-wal` und `-shm`
blockieren. Die root-owned macOS-Kompatibilitätsaliase `/var` und `/tmp`
gehören ausdrücklich zur lokalen OS-TCB; andere kanonische Abweichungen werden
abgelehnt.

Neue Dateien werden exklusiv mit `O_EXCL | O_NOFOLLOW` angelegt, vor dem
SQLite-Open geprüft und auf Datei- sowie Verzeichnisebene synchronisiert. Ein
privates reguläres `-journal` ist für die qualifizierte Rollback-Recovery
zulässig. Konfiguriert und zurückgelesen werden:

```text
foreign_keys = ON
trusted_schema = OFF
journal_mode = DELETE
synchronous = FULL
fullfsync = ON
locking_mode = NORMAL
busy_timeout = 1000 ms
temp_store = MEMORY
```

Bei einem bestehenden File laufen `integrity_check(1)` und
`foreign_key_check` vor Migrationen; nach Migrationen laufen beide erneut.
Migrationen sind checksum-gebunden und teilen eine `BEGIN IMMEDIATE`-Grenze.
Busy/Locked wird ohne unbeschränkten Retry als `CONTROL_PLANE_BUSY` gemeldet.

## Transaktionen und Prozessabbruch

Die äußere Transaktion verwendet `BEGIN IMMEDIATE`. Verschachtelte
Store-Operationen verwenden Savepoints; ein innerer Fehler rollt nur seinen
Savepoint zurück und behält den ursprünglichen Fehler. Kann ein Rollback oder
Savepoint-Cleanup nicht bewiesen werden, wird die Datenbankinstanz vergiftet
und blockiert weitere Verwendung.

Ein echter Child-Test hält eine uncommittete Mutation im Rollback-Journal und
wird per `SIGKILL` beendet. Reopen erhält den vorherigen Commit und verwirft
die uncommittete Zeile. Ein separater Child-Commit bleibt nach Exit und Reopen
erhalten. Ein zweiter Writer blockiert nach dem begrenzten Timeout
deterministisch.

## Kill-Switch-Recovery

Engagement folgt drei geordneten lokalen Commitgrenzen:

```text
1. global state = engaged, neue Revision, audit_reference = NULL
2. approved/running campaigns = paused + engaged
3. immutable engagement audit + revisionsgebundener State-Link
```

Ein Fehler in Schritt 3 rollt weder Schritt 1 noch Schritt 2 zurück. Ein Crash
zwischen Schritt 1 und 2 hinterlässt einen effektiv aktiven Kill Switch;
`ControlPlaneStore` pausiert beim nächsten Aufbau alle noch als
`approved`/`running_simulation` persistierten Kampagnen. Diese Reconciliation
gibt niemals frei und erzeugt keine Zustimmung. Sie schreibt bewusst keinen
neuen forensischen Recovery-Auditeintrag; der fehlende aktuelle Audit-Link
bleibt selbst fail-closed.

Ein signierter Clear pausiert innerhalb seiner eigenen atomaren Transaktion
noch einmal jeden gefährlichen Kampagnenzustand, bevor die signierte
Clear-Evidence den State ändern darf. Policy-Akzeptanz, Kampagnenupdate und
Owned-Object-Insert halten Kill-, Evidence- und Write-Prüfung in derselben
SQLite-Transaktion. Engagement-Audit-IDs binden die Revision, sodass derselbe
Actor und Zeitstempel keine Kollision zwischen zwei Revisionen erzeugen.

## Audit-Log-Vertrag

Das dateibasierte Audit-Log akzeptiert nur einen absoluten kanonischen Pfad in
einem benutzereigenen Verzeichnis mit exakt `0700`. Log und Lease sind
reguläre single-link-Dateien mit exakt `0600`. Symlinks, Accessors, Proxies,
Zusatzfelder, ungültiges UTF-8, Leerzeilen, nicht kanonisches JSON, fehlender
finaler Newline und Teilzeilen blockieren.

Vor jedem Append wird die vollständige Hashkette vom Datenträger geladen und
verifiziert. Grenzen sind 4 KiB pro Record, 16 MiB pro Log und 50.000 Records.
Unabhängige Instanzen und Prozesse serialisieren über
`<audit>.mutation.lock`; erfolgreicher Append synchronisiert Datei und
Elternverzeichnis.

## Explizite Audit-Lease-Recovery

Ein `SIGKILL` lässt die Lease absichtlich bestehen. Normale Verifikation und
Append blockieren. Recovery ist nur offline bei gestoppten Schreibern erlaubt
und benötigt exakt:

```text
AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION
= "confirm-local-offline-audit-recovery"
```

`recoverStaleAuditMutation(path, confirmation)` akzeptiert ausschließlich
einen kanonischen, höchstens 512 Byte langen Lock mit Schema-Version, PID und
zufälligem Token. Die PID wird vor und nach vollständiger Logverifikation
geprüft. Nur `ESRCH` gilt als stale; lebende PID, `EPERM`, PID-Reuse,
unbekannte Fehler oder geänderte Inode-/Pfadbindung blockieren. Erst danach
wird die Lease entfernt und das Verzeichnis synchronisiert.

Eine Teilzeile oder beschädigte Hashkette wird niemals gekürzt oder repariert;
die Lease bleibt erhalten. Forensische Untersuchung und ein künftig separat
zu entwerfender authentisierter Repair-Prozess sind dann erforderlich.

## Nicht qualifiziert

- Netzwerkdateisysteme, Cluster- oder allgemeiner Active-active-Betrieb;
- automatische Audit-Reparatur oder Tail-Truncation;
- automatische Erstattung, Wiederholung oder Erfolgsmeldung unklarer
  External-Action-Reservations;
- reale Plattform- oder Zielverbindungen;
- automatische menschliche, rechtliche oder Report-Zustimmung.
