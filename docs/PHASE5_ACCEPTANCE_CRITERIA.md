# Phase-5-Acceptance-Criteria: Event-Key-Rotation und Wiederanlauf

## Verbindlicher Umfang

Phase 5 implementiert ausschließlich den lokalen Lifecycle des bereits
Keychain-referenzierten Event-Schlüssels. Die sichere Strategie lautet:

```text
write new -> read explicitly activated old
```

Eine Rotation aktiviert monoton eine neue Version für zukünftige Writes. Alte
Eventhüllen werden nicht automatisch umgeschrieben und alte Schlüssel werden
nicht automatisch gelöscht. Ein explizites Re-Keying, allgemeiner
Mehrprozessbetrieb, Operator-Key-Rotation, Browserjourneys und reale
Integrationen bleiben außerhalb des Scopes.

Alle Schlüsselwerte stammen im Produktpfad ausschließlich aus dem macOS
Keychain über `SecretStore`. State-Records dürfen weder Schlüsselmaterial noch
Secret-Referenzen, Eventdaten oder sonstige sensible Laufzeitdaten enthalten.

## Baseline- und Security-Core-Kriterien

1. Die vollständige Phase-4-Baseline ist in `docs/PHASE4_BASELINE.md` exakt
   fixiert.
2. Änderungen an `packages/event-store` sind ausdrücklich als notwendige
   **Phase-5-Security-Core-Änderungen** markiert, erhalten direkte
   Regressionstests und werden in `PHASE5_SECURITY_CORE_CHANGES.md`
   dokumentiert.
3. Andere geschützte Phase-1-Komponenten bleiben unverändert, sofern keine
   zwingende, separat dokumentierte Notwendigkeit entsteht.
4. Es gibt keinen Klartext-, Datei-, Environment-Key- oder Best-effort-
   Fallback.

## Key-Lifecycle-Kriterien

1. Ein neues eigenes Lifecycle-Modul verwaltet den aktiven Schreibschlüssel
   und die explizit lesbaren historischen Versionen. Der Produktpfad verwendet
   nicht länger hart Version 1.
2. Frische Stores beginnen ausschließlich mit Version 1. Versionen sind
   positive Safe Integers innerhalb einer festen Obergrenze.
3. Jede Rotation benötigt die erwartete aktuelle Version und erlaubt exakt
   `current + 1`. Sprünge, Rückschritte, Wiederverwendung und Overflow
   blockieren.
4. Der neue Schlüssel muss vorhanden, exakt 32 Byte lang und von allen bisher
   aktivierten Schlüsselwerten verschieden sein. Fehlende alte oder neue
   Schlüssel blockieren vor dem Commit.
5. Temporäre Schlüsselkopien und abgeleitete HMAC-Schlüssel werden in allen
   Erfolgs- und Fehlerpfaden explizit überschrieben.
6. Ein konfigurierter `minimumActiveKeyVersion` bildet eine zusätzliche
   lokale Rollback-Grenze. Ein älterer persistierter Head blockiert.
7. `read()` akzeptiert nur eine in der authentisierten State-Chain aktivierte
   Hüllenversion. Eine nicht aktivierte, ungültige oder zukünftige Version
   erreicht den Secret Store nicht.

## Persistenz- und Authentisierungskriterien

1. Der Lifecycle persistiert eine append-only Folge immutable State-Records
   unter einem eigenen Verzeichnis mit Modus `0700`; Recorddateien besitzen
   Modus `0600`.
2. Recordnamen und Revisionen sind lückenlos, eindeutig und monoton.
3. Jeder Record enthält exakt Schema-Version, zufällige Store-ID, Revision,
   Operation, aktive Version, streng aufsteigende lesbare Versionen,
   Vorgängerdigest und Authentisierungstag.
4. Der Authentisierungstag ist HMAC-SHA-256 über das kanonische unsigned
   Record. Der MAC-Key wird mit HKDF-SHA-256, Store-ID und fester
   Domain-Separation aus dem jeweiligen Event-Key abgeleitet.
5. Der vollständige Vorgängerrecord einschließlich Tag wird per SHA-256 an den
   Nachfolger gebunden. Genesis verwendet einen festen Null-Digest.
6. Extra-Felder, Accessors, fremde Prototypen, nicht kanonisches JSON,
   ungültiges Base64/Hex, unbekannte Schema-/Future-Versionen, Recordlücken,
   Duplikate, vertauschte Records, falsche Store-ID, falscher HMAC,
   Nicht-Regulärdateien und Symlinks blockieren.
7. State-Commits verwenden eine neue `wx`-Temporärdatei, Datei-`fsync`, einen
   atomaren exklusiven Hardlink auf den revisionsgebundenen finalen Namen und
   Verzeichnis-`fsync`.
8. Ein Crash vor dem finalen Link lässt den alten Head aktiv. Ein erfolgreich
   verlinkter Record ist nach einem Restart der neue Head. Temporärdateien sind
   niemals Head.
9. Zwei konkurrierende Rotationen auf dieselbe Revision können höchstens einen
   neuen Record erzeugen; der Verlierer blockiert mit einem deterministischen
   Konfliktcode.
10. Nach jedem Commit wird die vollständige Chain erneut vom Datenträger
    geladen und verifiziert, bevor Erfolg gemeldet wird.

## Event-Envelope-Härtung

1. Aktive und lesbare Key-Versionen werden vor jedem Secret-Zugriff als
   positive, sichere und explizit erlaubte Werte geprüft.
2. Die Envelope bleibt geschlossen und größenbegrenzt. Base64 muss kanonisch
   sein; Nonce ist exakt 12 Byte und GCM-Tag exakt 16 Byte.
3. Ungültige Hüllen blockieren ohne Secret-Aufruf. Manipulierte Ciphertexts
   blockieren als Integritätsfehler.
4. Vom Secret Store geladene Key-Bytes werden nach Initialisierung des AES-
   GCM-Kontexts auch auf Fehlerpfaden überschrieben.
5. Existing write-once-, Atomizitäts-, `0700`-/`0600`- und AES-256-GCM-
   Invarianten bleiben erhalten.

## Legacy-, Restart- und Produktkriterien

1. Ein leeres neues Verzeichnis darf nach erfolgreichem v1-Key-Preflight einen
   Genesis-Record erzeugen.
2. Ein bestehender Phase-4-Store ohne State-Chain wird nicht still übernommen.
   `adoptLegacyV1()` benötigt einen expliziten lokalen Adminpfad, akzeptiert
   ausschließlich reguläre v1-Hüllen mit Key-Version 1 und authentifiziert
   jedes Event vor dem Genesis-Commit.
3. Eine einzige unbekannte, manipulierte, nicht lesbare oder gemischt
   versionierte Legacy-Datei blockiert die Adoption vollständig.
4. Nach v1→v2 und vollständigem Objekt-/Prozessneustart bleibt v2 der aktive
   Schreibschlüssel; alte v1-Events bleiben nur mit aktiviertem v1-Key lesbar.
5. Fehlt beim Restart ein aktivierter historischer Key, öffnet der Lifecycle
   nicht teilweise.
6. Dashboard-, CLI- und Simulationskomposition preflighten den Lifecycle vor
   nicht sicherheitsgerichteter Control-Plane-Fachmutation.
7. Rotation ist ausschließlich ein expliziter lokaler Adminvorgang. Kein
   Dashboard-, HTTP-, Modell- oder External-Action-Pfad löst sie automatisch
   aus.
8. Der aktive Head und die lesbaren Versionen dürfen im lokalen Systemstatus
   erscheinen; Secret-Werte und -Referenzen niemals.

## Nachweiskriterien

- Unit-Tests decken Initialisierung, Open, strikte Chain, Rotation, Konflikt,
  Keyfehler, Gleichheit, Envelope-Härtung, Rechte, Symlinks und Zeroization ab.
- Property-Tests mutieren Record- und Envelope-Felder und erzeugen gültige
  sowie ungültige monotone Versionsfolgen.
- File-backed Integrationstests beweisen Rotation, Reopen, alte/neue Events,
  Minimum-Version, fehlende Keys, Cross-Store-Manipulation und explizite
  Legacy-Adoption.
- Kontrollierte Fault-Tests beweisen die Commitgrenze vor und nach dem finalen
  Link, ohne Tests zu deaktivieren oder Schutzprüfungen zu lockern.
- Recorder-, Ownership-, Simulation-, Dashboard-, Phase-4- und vollständige
  Phase-1-Regressionen bestehen.
- Typprüfung, ESLint ohne Warnungen, Formatprüfung, Build, Gesamtsuite,
  Coverage, Property-, Integrations-, Egress-, Platform-Source- und
  Dependency-Gates bestehen.

## Bewusst verbleibende Grenzen

Die State-Chain schützt Integrität, Reihenfolge und selektive Manipulation. Ein
privilegierter Angreifer, der das vollständige lokale Dateisystem einschließlich
aller State-Records und Konfiguration konsistent zurückrollt, bleibt Teil der
lokalen Trusted Computing Base. `minimumActiveKeyVersion` reduziert dieses
Risiko nur, wenn die lokale Konfiguration separat erhalten bleibt.

Phase 5 qualifiziert keinen allgemeinen Active-active-Mehrprozessbetrieb und
löscht keine alten Keys. Crash-/Restart- und Mehrprozesshärtung von Approval
Queue, Kill Switch, Audit Log und Control Plane bleibt der nächste getrennte
Roadmap-Schnitt.
