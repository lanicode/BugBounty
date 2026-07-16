# Pilot Readiness C – Security-Core-Änderungen

## Bewertungsbasis

Ausgangsstand für Pilot Readiness C ist Commit
`4dcc9f322e6b03ac04af06bd466e60948136766d`. Gegenüber diesem Stand waren vier
eng begrenzte Änderungen innerhalb des bestehenden Sicherheitskerns zwingend:

1. eine atomare, signierte Active-Testing-Approval-Bindung in der Control
   Plane;
2. eine einmalige, secretfreie lokale Core-Provisionierung über den
   produktiven macOS-Keychain-Adapter;
3. erzwungene rekursive SQLite-Trigger für unveränderliche Security-Evidence;
4. das atomare Verwerfen von Auswahl-, Verbindungs- und Sync-Zustand bei jeder
   neuen signierten HackerOne-Adaptergeneration.

Alle übrigen Active-Testing-Komponenten sind neue, getrennte Produktgrenzen.
Keine bestehende Prüfung wurde deaktiviert oder gelockert.

## Änderung 1: `packages/control-plane/store.ts`

### Trusted-Clock-Hook

Die neue öffentliche Methode `observeExternalActionTime()` gibt keine frei
gelieferte Zeit weiter. Sie ruft ausschließlich die bestehende private
Store-Uhr mit dem persistenten Operator-Statement-High-Water-Mark auf. Das
store-gebundene Active-Testing-Gate verwendet diese Uhr für:

- Plan- und Approval-Vorbereitung;
- Budgetreservation;
- Übergang `reserved -> running`;
- Abbruch, Fehler- und Erfolg-Settlement;
- Zeitbodenprüfung gegen Reservation und Start.

Damit kann ein angrenzendes Gate die nach einer signierten Entscheidung
verwendete Zeit nicht über eine zweite Prozessuhr, einen Caller-Timestamp oder
eine rückwärts gesetzte Testuhr umgehen. Rollback unter den High-Water-Mark
oder unter einen bereits persistierten Zustandszeitpunkt blockiert
fail-closed.

### Atomare Approval-Bindung

Die bestehende signierte Approval-Decision-Transaktion wurde um einen
Active-Testing-Integrationspunkt ergänzt:

- Für ein Approval mit Datensatz in `active_test_approval_bindings` wird der
  vollständige Binding-Digest als Signaturkontext verwendet.
- Der Digest bindet Approval-Payload und Operator, Plan und Plandigest,
  Snapshot, Policy, Scope und Asset, Runtime- und Katalogdigest sowie
  Erzeugungs- und Ablaufzeit.
- Die verifizierte Operator-ID, der Payloadhash und der signierte
  Kontextdigest müssen exakt zum persistierten Binding passen.
- Eine akzeptierende Entscheidung muss sowohl beim Ausstellungszeitpunkt als
  auch bei lokaler Beobachtung vor Ablauf liegen.
- Decision-Evidence, allgemeines Approval, bodyfreies Audit und
  `decision_audit_id` des Active-Testing-Bindings werden innerhalb derselben
  `BEGIN IMMEDIATE`-Transaktion geschrieben. Jeder Fehler rollt den gesamten
  Vorgang zurück.
- Die Verknüpfung ist einmalig. Ein fehlendes, bereits verknüpftes,
  widersprüchliches oder manipuliertes Binding blockiert.

Das Active-Testing-Gate verifiziert vor Reservation, Start und Abschluss
erneut die authentifizierte signierte Entscheidung und alle aktuellen
Bindungen. Caller-Booleans oder freie Actor-Strings erzeugen keine
Autorisierung.

### Direkte Regressionen

Die relevanten Regressionen liegen insbesondere in:

- `tests/unit/active-testing/gate.test.ts`
  - signierte, planbezogene Freigabe;
  - Trennung von Freigabe und Start;
  - Ablehnung syntaktisch gefälschter Transport-Evidence;
  - Snapshot-/Policy-Drift zwischen Approval und Start;
  - persistente Budgets ohne Erstattung;
  - Runtime- und Kill-Switch-Sperren;
  - Store-Uhr und Rollback vor Reservation und Settlement;
  - direkte unzulässige SQLite-Zustandsübergänge und ungebundene Evidence.
- `tests/property/active-testing.property.test.ts`
  - Schema-, Plan-, Bindungs- und Zustandsinvarianten über generierte Werte.
- die bestehenden Control-Plane-, Operator-Auth- und
  External-Action-Regressionen, die unverändert weiterlaufen müssen.

Die finalen Anzahlen und Ergebnisse werden ausschließlich aus dem
abschließenden Testlauf in `PILOT_READINESS_C_TEST_RESULTS.txt` und den
Abschlussbericht übernommen; dieses Dokument erfindet keine Testzahlen.

## Änderung 2: `packages/secret-store`

### Nativer atomarer Core-Provisioningpfad

`packages/secret-store/core-keychain.ts` und der feste native Helper
`packages/secret-store/native/macos-core-keychain-helper.c` ergänzen den
produktiven macOS-Keychain-Pfad. Die Mutation ist bewusst kleiner als eine
allgemeine Schlüsselverwaltung:

- `fresh_bundle`: nur wenn Core-Keychain-Einträge, Event-Store-Verzeichnis und
  lokale Operator-Credential nachweislich fehlen. Der Helper erzeugt mit
  `SecRandomCopyBytes` einen 32-Byte-Event-Key, einen 32-Byte-Ed25519-Seed,
  eine feste PKCS#8-Hülle und eine Generation und schreibt genau einen neuen,
  atomaren Bundle-Eintrag.
- `legacy_complete`: nur im exakt erkannten `legacy_ready`-Zustand. Der
  vorhandene 32-Byte-Event-Key wird gelesen und verifiziert, aber weder
  ersetzt noch erneut gespeichert. Der Helper erzeugt ausschließlich die
  fehlende Operator-Hülle als neuen Eintrag.
- Vorhandene Einträge werden nie geändert oder überschrieben. Es gibt keine
  Delete-, Rotation-, Recovery- oder Rollback-Löschung.
- Teilzustände, unerwartete Einträge, nicht kanonische Hüllen, ein vorhandener
  Event Store, eine vorhandene Operator-Credential, ein freigegebener oder
  veränderter Kill Switch sowie Lese-, ACL- oder Keychain-Fehler blockieren.
- Der native Prozess deaktiviert Core-Dumps und interaktive Keychain-Prompts,
  begrenzt Ein- und Ausgabe und nullt geheime Arbeitsbereiche.
- Der Provisioning-Request enthält nur feste Version, Bestätigung, Nonce und
  Kontextdigest. Er akzeptiert keinen Event-Key, privaten Operator-Key, Modus,
  Host oder Pfad.
- Secretbytes erscheinen nicht in Browserantworten, argv, Environment, Logs,
  Dateien oder Repository. Der native Provisioningpfad gibt nur eine
  validierte nicht geheime Receipt-Projektion zurück.
- Die laufende Setup-Shell übernimmt neu erzeugte Schlüssel nicht. Erst ein
  Neustart mit explizitem `BUGBOUNTY_EVENT_KEY_MIN_VERSION` darf ein
  vollständiges, gültiges Receipt auf die festen logischen
  `keychain://`-Referenzen abbilden.

### Fail-closed Laufzeitkomposition und Phase-4/5-Kompatibilität

Die Provisionierung speichert im `fresh_bundle` den logischen Event-Key v1
und den Operator-Key gemeinsam, während Phase 5 rotierte Event-Keys v2 und
higher weiterhin als feste Generic-Keychain-Einträge erwartet. Deshalb
verwendet `packages/secret-store/core-aware-store.ts` eine explizite
Komposition statt eines Fallbacks:

- Event-Key v1 und Operator-Key v1 werden im Bundle-/Envelope-Modus nur über
  den validierenden nativen Core-Helper gelesen.
- Ausschließlich feste Event-Key-Referenzen v2 bis v10000 werden an den
  Generic-Keychain-Adapter delegiert.
- Vor und nach jedem Secret-Read müssen Status, Modus, Operator-ID und
  Generation desselben vollständigen Core-Receipts unverändert sein. Bei
  Fehler, Drift, falscher Länge oder Zeroing-Fehler wird niemals der jeweils
  andere Adapter versucht.
- `apps/event-key-cli` löst den Store erst nach Syntax- und
  Mindestversionsprüfung auf. Dadurch funktionieren `status`, `rotate` und
  `recover-stale-mutation` nach Fresh-Provisioning; Rotation bleibt ein
  ausdrücklich bestätigter lokaler Offline-Adminbefehl. Es wurde keine
  Dashboard-, HTTP- oder automatische Rotationsroute ergänzt.
- `apps/phase2-cli` und die Dashboard-Runtime verwenden dieselbe
  Core-aware-Grenze. Ein Bundle-Receipt darf die fehlende Operator-ID auf die
  feste v1-Referenz ableiten; vorhandene Umgebungsmetadaten müssen exakt zum
  Receipt passen.

Vor Pilot C war ein vollständiger gültiger Phase-4/5-Zustand als direkter
32-Byte-Event-Key plus rohes, kanonisches 48-Byte-Ed25519-PKCS#8 gespeichert.
Der native Inspector erkennt ihn nun separat als
`legacy_direct_complete`. Dieser Zustand:

- besitzt absichtlich kein neues Bundle-Receipt und ist nicht
  provisionierbar;
- verlangt für Runtime und Phase-2-CLI weiterhin die vollständige exakte
  Operator-Konfiguration und verwendet statusgebunden den bestehenden
  Generic-Keychain-Pfad;
- bleibt vor und nach jedem Secret-Read auf denselben Zustand geprüft;
- wird niemals automatisch migriert, überschrieben oder gelöscht.

`legacy_ready` bleibt ausschließlich für den Event-Key-Adminpfad lesbar und
für den eng begrenzten manuellen Provisionierungsabschluss geeignet; es kann
keinen Operator-Signer oder Produkt-Runtime aktivieren. `absent`, `conflict`,
malforme PKCS#8-/Envelope-Daten, Inspektionsfehler und Zustandswechsel
blockieren ohne Generic-/Bundle-Fallback.

Die Dashboard- und Runtime-Integration ist in
`docs/CORE_PROVISIONING_SECURITY_CORE_CHANGES.md` zusätzlich beschrieben.

### Direkte Regressionen

- `tests/unit/core-keychain.test.ts`
  - Fresh- und Legacy-Modus;
  - State-Probe vor und nach der Mutation;
  - keine Event-Key-Übergabe beim Legacy-Abschluss;
  - Buffer-Zeroing, Größen-, Timeout- und Fehlerpfade;
  - keine kompensierende Löschung nach einem Post-Commit-Fehler.
- `tests/unit/core-aware-secret-store.test.ts`
  - exaktes v1-/v2-Dispatching ohne Fehler-Fallback;
  - stabile Receipt- und Legacy-Statusbindung vor und nach jedem Read;
  - Zeroing bei Drift, Größenfehlern und unzulässigen Zuständen.
- `tests/integration/event-key-admin-core-bundle.test.ts`
  - Fresh-Bundle-`initialize`, `status` und Rotation auf Generic-v2;
  - explizite Phase-5-Kompatibilität für `legacy_ready` und
    `legacy_direct_complete`;
  - kein Commit bei fehlendem v2-Key sowie keine State-Anlage bei
    `absent`/`conflict`.
- `tests/unit/phase2-cli-core-secrets.test.ts` und
  `tests/unit/core-startup-resolution.test.ts`
  - Receipt-gebundene Operatorableitung für Fresh-Bundles;
  - vollständig konfigurierte Legacy-Direct-Runtime über Generic Keychain;
  - Blockade bei Teilkonfiguration, Receipt-Mismatch oder Partial-State.
- `tests/unit/core-provisioning.test.ts`
  - serverseitige Moduswahl;
  - Nonce-/Kontextbindung und Replay-Sperre;
  - Kill-Switch-, Operator- und Event-Store-Vorbedingungen;
  - Ablehnung zusätzlicher Secretfelder und Zustandsdrift.
- `tests/integration/core-provisioning-dashboard.test.ts`
  - Loopback-, Host-, Origin-, CSRF- und geschlossener Bodyvertrag;
  - secretfreie Projektion und zwingende Neustartgrenze.
- `tests/native/macos-core-keychain-helper-contract.sh`
  - fester CLI-Vertrag;
  - genau ein Fresh-Bundle-Schreibpfad;
  - Legacy-Abschluss ohne Event-Key-Schreibpfad;
  - keine Modify-/Delete-Operation.

## Änderung 3: `packages/control-plane/database.ts`

### Rekursive SQLite-Trigger

Die gemeinsame Control-Plane-Datenbank setzt nun beim Öffnen zwingend
`PRAGMA recursive_triggers=ON` und prüft den gelesenen Wert fail-closed. Damit
kann ein `INSERT OR REPLACE` die bestehenden Append-only- und
Unveränderlichkeitstrigger nicht durch den impliziten Delete-Schritt umgehen.
Die Änderung erweitert keine Berechtigung und lockert kein Schema.

Die direkte Regression in
`tests/unit/control-plane/database-hardening.test.ts` prüft sowohl das
erzwungene Pragma als auch, dass ein `INSERT OR REPLACE` weiterhin am
Delete-Trigger einer append-only Tabelle scheitert. Alle In-Process-Besitzer
des internen `ControlPlaneDatabase`-Handles bleiben Teil der vertrauenswürdigen
Produkt-Codegrenze; die öffentliche Produktoberfläche gibt dieses Handle nicht
an Browser-, LLM- oder Adaptereingaben weiter.

## Änderung 4: `packages/control-plane/store.ts`

### Credential-Generation erzwingt neuen API-Sync

Beim atomaren Aktivieren einer neuen signierten HackerOne-Adaptergeneration
werden in derselben Transaktion alle zuvor credential- beziehungsweise
accountbezogenen Integrationsprojektionen gelöscht:

- letzter Verbindungs- und Erfolgszustand;
- letzter Synchronisationszeitpunkt, Ergebnis und Fehlercode;
- ausgewählte Programmreferenz und deren Quelle.

Dadurch kann ein unter Credential-Generation A synchronisierter und
akzeptierter Scope nach einer Aktivierung von Generation B nicht als aktuell
weiterverwendet werden. Active Testing verlangt einen erfolgreichen, zeitlich
nach der aktuellen signierten Aktivierung liegenden Detailsync, die neue
serverseitige Programmauswahl und die exakte lokale Annahme des daraus
entstehenden Snapshots. Die Regression in
`tests/unit/active-testing/gate.test.ts` deaktiviert und reaktiviert den
Adapter, prüft die atomar geleerten Felder und belegt, dass der alte Plan ohne
neuen Sync keine Reservation erzeugt.

## Bewusst unverändert

- `packages/config`, `packages/egress-guard`, `packages/redaction`,
  `packages/event-store`, `packages/event-key-lifecycle`, `packages/policy`,
  `packages/audit-log` und `packages/operator-auth` wurden für die Capability
  nicht gelockert.
- Event-Key-Adoption, Rotation und Recovery bleiben ausdrückliche lokale
  Offline-Adminoperationen bei beendetem Dashboard.
- Die Core-Provisionierung aktiviert weder HackerOne Read-only noch aktive
  Tests und gilt nicht als Programmregel-, Rechts- oder Reportzustimmung.
- Es wurde kein Klartext-, Datei-, Environment- oder In-Memory-Fallback für
  Produktionssecrets hinzugefügt.
- Es wurde kein HTTP-, Browser- oder LLM-Pfad zur Schlüsselverwaltung
  geschaffen; die einzige HTTP-Ausnahme ist die eng geschlossene lokale
  Loopback-Bestätigung ohne Secretdaten.

### Verbleibendes Verfügbarkeitsrisiko

Der native Core-Eintrag beschränkt den Zugriff auf die lokale Codeidentität
des kompilierten Helpers. Der Helper ist lokal aus verifiziertem
Repository-Source gebaut, aber nicht mit einer stabilen Developer-ID
codesigniert. Nach Source-Update, Cacheverlust oder Neuübersetzung kann macOS
die neue Binäridentität ablehnen. Das verliert keine Secretvertraulichkeit und
erzeugt keinen Fallback, kann aber einen manuellen Keychain-/Upgrade-Schritt
erfordern; der Produktstart blockiert in diesem Fall fail-closed.

## Sicherheitsbewertung

Diese vier Änderungen sind notwendige Integrationspunkte, keine generelle
Erweiterung von Autorität. Fehlende Tabellen, fehlende Receipts, fehlerhafte
Konfiguration, inkonsistente Persistenz oder nicht verfügbare Keychain-Dienste
erzeugen keine positive Capability. Der konservative Fehlerzustand bleibt
jeweils blockiert.
