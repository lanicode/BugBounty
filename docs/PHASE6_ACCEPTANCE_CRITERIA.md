# Phase-6-Acceptance-Criteria: lokaler Control-Plane-Wiederanlauf

## Verbindlicher Umfang

Phase 6 härtet ausschließlich die lokale Persistenz von Control Plane, Kill
Switch und Audit Log gegen Prozessneustart, kontrollierte Prozessabbrüche und
konkurrierende lokale Prozesse. Es entstehen keine neuen externen Aktionen,
keine realen Plattformadapter, keine Account-Automation und keine aktiven
Sicherheitstests.

Alle Produkt-Netzwerktests bleiben auf Loopback-Adressen beschränkt. Der
globale Schalter `external_integrations_enabled` bleibt standardmäßig `false`
und fail-closed. Phase 6 qualifiziert keinen allgemeinen verteilten oder
Active-active-Betrieb.

## Baseline und Security Core

1. `docs/PHASE5_BASELINE.md` fixiert den exakten letzten Phase-5-Commit.
2. Der Phase-1-Sicherheitskern wird nur dort verändert, wo Restart-Sicherheit
   technisch zwingend ist. Jede Änderung wird in
   `PHASE6_SECURITY_CORE_CHANGES.md` markiert und direkt regressionsgetestet.
3. Es gibt keinen Klartext-, Best-effort- oder ungeschützten Fallback für
   Event-, Audit- oder Secretdaten.

## Control-Plane-Datenbank

1. File-backed SQLite akzeptiert nur einen lokalen absoluten kanonischen Pfad,
   ein privates reguläres Datenbankfile und einen privaten realen Elternpfad;
   Symlinks und unerwartete Sidecar-Dateitypen blockieren.
2. Die Datenbank erzwingt und verifiziert Foreign Keys, deaktiviertes Trusted
   Schema, `synchronous=FULL`, eine explizite lokale Journalstrategie und ein
   begrenztes Busy-Timeout.
3. Bei jedem Reopen laufen Schema-Checksum-Prüfung, `integrity_check` und
   `foreign_key_check`. Fehler schließen die Datenbank und blockieren.
4. Busy/Locked-Konflikte werden deterministisch als Security-Fehler gemeldet;
   Schutzprüfungen oder Zeitgrenzen werden nicht gelockert.
5. Ein per SIGKILL beendeter Prozess hinterlässt keine uncommittete Mutation.
   Vor dem Abbruch commitierte Daten bleiben nach Reopen erhalten.

## Kill Switch und fachliche Mutationen

1. Engagement bleibt asymmetrisch fail-safe: kein Fehler darf einen aktiven
   Kill Switch auf `clear` zurückrollen.
2. State-Engagement, Kampagnenpause und Auditbindung sind gegenüber parallelen
   lokalen Schreibern serialisiert. Teilzustände werden beim Reopen nur in die
   sichere Richtung (`engaged`/`paused`) versöhnt, niemals automatisch
   freigegeben.
3. Ein Clear benötigt weiterhin den vorhandenen signierten menschlichen
   Kontrollpunkt. Reopen oder Recovery erzeugen keine Zustimmung.
4. Kill-Switch-Prüfung und sicherheitsrelevante Read-validate-write-Mutationen
   verwenden eine konsistente SQLite-Transaktionsgrenze, sodass Engagement
   nicht durch einen zeitgleichen Write überholt wird.

## Audit Log

1. Das Phase-1-Audit-Log lädt und verifiziert seinen persistierten Head vor
   jedem Append und setzt Sequenz und Hash nach Objekt- oder Prozessneustart
   korrekt fort.
2. Append ist innerhalb eines und zwischen lokalen Prozessen serialisiert.
   Lock-, Datei- und Elternpfade sind geschlossen, größenbegrenzt, regulär,
   ohne Symlinks und mit `0600`/`0700` geschützt.
3. Records haben ein exaktes Schema, validierte eigene Datenfelder und eine
   kanonische JSON-Repräsentation. Extra-Felder, Accessors, fremde Prototypen,
   Leerzeilen, fehlender finaler Newline und Teilzeilen blockieren.
4. Ein erfolgreicher Append wird vor Erfolg auf Datei und Verzeichnis
   synchronisiert. Eine Crash-Teilzeile wird nicht still entfernt oder
   übergangen; explizite sichere Recovery bleibt ein späterer Adminvorgang.
5. Vollständige Datei- und Recordgrößenlimits verhindern unbeschränktes Lesen
   oder Schreiben.

## Nachweise

- Unit- und Property-Tests decken strikte Formate, Manipulation, Rechte,
  Symlinks, Sequenzen, Reopen und Parallelität ab.
- Lokale Child-Prozess-Integrationstests decken SQLite- und Audit-Log-Restart,
  Konkurrenz sowie SIGKILL vor und nach Commit ab.
- Nach jeder größeren Komponente laufen die vollständigen Phase-1- und
  bisherigen Phasenregressionen erneut.
- Typprüfung, ESLint ohne Warnungen, Formatprüfung, Build, Gesamtsuite,
  Coverage, Property-, Integrations-, Egress-, Platform-Source- und
  Dependency-Gates bestehen.

## Bewusste Grenzen

Ein privilegierter lokaler Angreifer, der Dateien, Verzeichnisse und
Konfiguration konsistent ersetzt oder zurückrollt, bleibt Teil der lokalen
Trusted Computing Base. Phase 6 implementiert weder automatische Reparatur
beschädigter Auditdaten noch eine Netzwerk- oder Cluster-Koordination.
