# Testnachweis

Stand: 14. Juli 2026. Der vollständige Phase-5-Lauf steht in `PHASE5_TEST_RESULTS.txt`.

Alle Netzwerk- und Browser-Integrationstests liefen ausschließlich gegen kurzlebige Server auf `127.0.0.1`. Beispiel- und `.invalid`-Hosts wurden nur als nicht aufgelöste Testdaten verwendet.

## Aktuelles Ergebnis

- Vollständige Suite: 67 Testdateien, 356 Tests, alle bestanden.
- Property-Suite: 11 Testdateien, 24 Tests, alle bestanden.
- Integrationssuite: 15 Testdateien, 63 Tests, alle bestanden.
- Phase-1-Egress-Regression: 4 Testdateien, 11 Tests, alle bestanden.
- Lokale ProgramSource-Suite: 4 Testdateien, 12 Tests, alle bestanden.
- Statements: 88,17 % (4197/4760).
- Branches: 83,14 % (2817/3388).
- Funktionen: 95,95 % (855/891).
- Zeilen: 89,27 % (4052/4539).
- `packages/event-key-lifecycle`: 91,12 % Statements, 87,95 % Branches,
  100 % Funktionen und 91,79 % Zeilen.
- `packages/event-store`: 91,66 % Statements, 87,82 % Branches, 100 %
  Funktionen und 93,54 % Zeilen.
- TypeScript-Typprüfung, ESLint ohne Warnungen, Prettier-Check und Build: bestanden.
- Dependency-Audit: keine bekannten Schwachstellen.

## Ergänzte Phase-5-Invarianten

Verpflichtende Mindestversionskonfiguration ohne Default; authentifizierte,
kanonische und lückenlose State-Chain mit HKDF-separiertem HMAC;
Cross-Store-Bindung; monotone Rotation exakt um eins; fehlende, ungültige,
wiederverwendete oder historische Keys blockieren; neue Writes verwenden nur
den authentifizierten Head, alte Hüllen nur explizit aktivierte Versionen;
keine automatische Neuverschlüsselung oder Key-Löschung; explizite
Legacy-v1-Adoption; Pre-write-Hüllengrößenprüfung; kanonisches Base64;
Nonce-, Tag-, Pfad-, Symlink-, Rechte- und Dateitypgrenzen; Key-Zeroization;
Datei- und Verzeichnis-`fsync`.

Eine private verzeichnisweite Mutation-Lease umfasst den gesamten
Refresh-/Commit-Bereich von Init, Adoption, Event-Write und Rotation. Unbekannte
oder fremde Locks, verwaiste Event-Temporärdateien und Lease-Verlust blockieren
fail-closed. Die explizite Recovery akzeptiert nur ein enges Dateischema,
verweigert eine lebende Eigentümer-PID und bereinigt niemals automatisch.
Echte Kindprozess-Tests beweisen Prozesskonkurrenz sowie `SIGKILL` vor und nach
dem finalen State-Hardlink: pre-link bleibt der alte Head aktiv, post-link wird
nach bestätigter Recovery der neue Head. Zusätzliche Fault-Injection deckt
State-Commit, Temp-Cleanup, Lock- und Directory-`fsync`-Fehler ab.

## Ergänzte Phase-3-Invarianten

Geschlossener Proposal-v2-Vertrag; kanonischer Digest über alle Evidence-Felder; atomare Store-Autorisierung mit `BEGIN IMMEDIATE`; strukturierte operatorgebundene Approval- und Audit-Evidence; persistenter Single-use-Replay-Schutz; globale und kampagnenbezogene Gesamt-, Concurrency-, Rate- und Clock-Rollback-Grenzen; Reopen- und Crash-Reservation; Pre-Start-Abbruch ohne Budgeterstattung; Drift vor Start und Settlement; immutable Audit- und Approval-Binding-Zeilen sowie immutable Attempt-Bindings mit trigger-erzwungenen Zustandsübergängen; Deny-All ohne Store-Evaluator; WeakSet-/Prototyp-/Proxy-/Accessor-/Method-Shadowing-Abwehr; ausschließlich gebrandeter In-Process-Mock; statische Abwesenheit neuer HTTP-, Browser-, DNS-, Socket-, Child-Process- und LLM-Transporte.

## Ergänzte Phase-4-Invarianten

Ed25519-Key-Import ausschließlich über `keychain://`; Zeroization temporärer
Schlüsselbytes und nicht reflektierbares privates `KeyObject`; geschlossene und
kanonische Enrollment-, Approval- und Kill-Clear-Envelopes; persistente
Control-Plane-Domäne; TOFU nur bei aktivem Kill Switch; frische
Session-Attestation; store-eigene validierte Uhr plus persistenter
Clock-High-Water-Mark; globale Nonce-Single-use-Grenze; atomare Signatur-,
Decision-, Audit- und External-Action-Bindung; immutable Credential- und
Signature-Evidence; file-backed Reopen; Cross-Store-Trennung; vollständige
Feldmutations-Properties; signerlose Dashboard-/Simulationspfade fail-closed;
Signatur-Revalidierung vor Reservation, Runner-Start und Settlement.

## Weiterhin abgedeckte Phase-2-Invarianten

Strikte JSON-/YAML-Importe; immutable Policy-Versionen und Diffs; Policy Drift; Kampagnenfreigaben und vollständige Vertragsdigests; Identitäts-Lifecycle und unveränderliche Account-Rollen-Scope-Snapshots; kryptografisch gebundene Ownership-Receipts; unbekannte, fremde, abgelaufene und policy-fremde Objekte; Approval-Tampering und doppelte Verarbeitung; SQLite-Migrationen einschließlich Cross-Program-Acceptance-Schutz; revisions- und auditgebundener fail-closed Kill Switch; Revalidierung aktiver Kampagnen beim Lesen; geschlossene Adapterregistrierung; deaktivierte externe Integrationen; vollständige Simulations-Gate-Kette; Demo-SaaS; interaktive CLI; 18-Schritte-Simulation; verschlüsselte Events; Dashboard-Host-/Origin-/CSRF-/Content-Type-/Größen-/UTF-8-Grenzen; echte Chromium-Navigation ausschließlich auf Loopback.

Die Phase-1-Invarianten für Egress, Redaktion, Secret Store, Policy, Audit und Browserkontrolle bleiben unverändert und vollständig in der Gesamtsuite enthalten. Die für Phase 5 zwingend geänderten Event-Store-Grenzen besitzen eigene Unit-, Property-, Fault- und Integrationstests; sie lockern keine bestehende Schutzprüfung.
