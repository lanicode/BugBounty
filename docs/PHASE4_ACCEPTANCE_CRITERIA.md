# Phase-4-Acceptance-Criteria: lokal authentifizierte Freigaben

## Verbindlicher Umfang

Phase 4 implementiert ausschließlich eine lokale Operator-Credential und
kryptografisch signierte Control-Plane-Entscheidungen. Private
Operator-Schlüssel dürfen im Produktpfad nur über eine bestehende
`SecretStore`-Referenz aus dem macOS Keychain geladen werden. Es gibt keine
Schlüsseldatei, keine Umgebungsvariable mit Schlüsselmaterial, keinen
Klartext-Fallback und keine automatische Schlüsselbereitstellung.

Reale Plattformadapter, externe Accounts, E-Mail-/TOTP-/CAPTCHA-Automation,
aktive Sicherheitstests, Report-Einreichung, Triage-Versand und
LLM-gesteuerte Requests bleiben außerhalb des Scopes.
`external_integrations_enabled` bleibt effektiv `false`.

## Authentifizierungs- und Signaturkriterien

1. Die Phase-3-Baseline ist in `docs/PHASE3_BASELINE.md` exakt fixiert; der
   geschützte Phase-1-Pfaddiff bleibt leer.
2. Eine persistente zufällige Control-Plane-ID trennt Signaturdomänen zwischen
   unabhängig erzeugten Stores.
3. Die lokale Einzeloperator-Credential verwendet ausschließlich Ed25519. Der
   private PKCS#8-Schlüssel wird nur über den Secret Store importiert, nach dem
   Import aus temporären Bytepuffern entfernt und niemals persistiert,
   protokolliert oder serialisiert.
4. Das initiale TOFU-Enrollment ist nur bei aktivem Kill Switch und leerem
   Credential-Store möglich. Es benötigt einen signierten
   Proof-of-Possession über Control-Plane-ID, Operator-ID, Public-Key-
   Fingerprint, Session, Nonce und Enrollment-Zeit.
5. Decision Envelopes sind geschlossene, exakt validierte Plain Objects ohne
   Zusatzfelder, Accessors, Proxies oder fremde Prototypen. Sie binden Domain,
   Control-Plane-ID, Approval-ID/-Art, Payload-Hash, erwartete Revision,
   Entscheidung, Benutzeraktion, Operator, Key-Fingerprint, Kontextdigest,
   Session, eindeutige Nonce, Ausgabe- und Ablaufzeit.
6. Jede neue persistierte Approval-Entscheidung – akzeptiert oder abgelehnt –
   benötigt eine gültige Signatur der aktuell eingeschriebenen Credential.
   Der frühere freie `actor`-Pfad darf keine Entscheidung mehr persistieren.
7. Für `external_action` ist der Signatur-Kontextdigest exakt der immutable
   Approval-Binding-Digest. Für andere Approval-Arten ist er exakt der
   Approval-Payload-Hash.
8. Signaturprüfung, Nonce-/Replay-Prüfung, Approval-Update, Signature-Evidence,
   Audit und External-Action-Auditbindung erfolgen atomar in einer
   `BEGIN IMMEDIATE`-Transaktion.
9. Eine Kill-Switch-Aktivierung bleibt jederzeit möglich. Das Löschen des Kill
   Switches benötigt dagegen eine eigene, gültige, frische und replay-sichere
   signierte Operator-Entscheidung.
10. Fehlende Credential, Secret-Store-Fehler, falscher Schlüssel, ungültiges
    DER/Base64url, falsche Control-Plane-ID, falscher Kontext, falsche Revision,
    abgelaufene oder zukünftige Session, Clock Rollback, Nonce-Replay und
    ungültige Signaturen blockieren.
11. SQLite-Trigger blockieren neue unsigned Approval-Transitions sowie Update
    oder Delete an Credential-, Enrollment-, Decision- und Kill-Clear-
    Signatur-Evidence.
12. Policy-, Campaign- und External-Action-Konsumenten revalidieren die
    kryptografische Decision-Evidence. External Actions revalidieren sie vor
    Reservation, Runner-Start und Settlement.

## Migrationskriterien

- Migration v5 engagiert den globalen Kill Switch, pausiert genehmigte oder
  laufende Kampagnen und setzt aktuelle Policy-Annahmen zurück.
- Bereits vorhandene unsignierte Entscheidungen bleiben historische
  Datensätze, gelten aber niemals automatisch als neue Autorisierung.
- Es gibt keine automatische Re-Attestation und keine Übernahme eines
  frei gelieferten Operatorlabels als Credential.
- Ein Migrations-, Datenbank-, Keychain- oder Verifikationsfehler blockiert.

## Nachweiskriterien

- Unit-Tests decken Key-Import, Byte-Löschung, Enrollment, Envelope-Schema,
  Ed25519-Verifikation, Signaturbindung, Zeitfenster und Branding ab.
- Property-Tests mutieren jedes signierte Feld; jede Abweichung blockiert.
- SQLite-Tests beweisen Trigger, Immutability, Nonce-Single-use, Restart,
  Cross-Store-Trennung und die fail-closed v4-zu-v5-Migration.
- Store-/External-Action-Tests beweisen, dass unsigned, alte oder manipulierte
  Policy-, Campaign- und Action-Approvals keinen Runner erreichen.
- Dashboard- und Simulationspfade können ohne explizit injizierte lokale
  Signierfähigkeit keine positive Entscheidung durchführen.
- Statische Importgrenzen beweisen, dass keine HTTP-, Browser-, DNS-, Socket-,
  Child-Process- oder LLM-Transporte in die neue Authentifizierungsgrenze
  gelangen.
- Typprüfung, ESLint ohne Warnungen, Formatprüfung, Build, Gesamtsuite,
  Coverage, Phase-1-Egress, Platform-Source und die vollständige Phase-3-
  Regression bestehen ohne deaktivierte Tests.

## Bewusst verbleibende Grenze

Das initiale Enrollment ist lokales TOFU. Der macOS-Keychain-Zugriff beweist
Schlüsselbesitz des lokalen Prozesses, aber weder Hardwarebindung noch
Benutzeranwesenheit pro Signatur und keine rechtliche Zustimmung. OS-Account,
lokaler Prozess und rohes Datenbank-Handle bleiben Teil der Trusted Computing
Base. Rotation, Recovery, Quorum und reale Integrationen bleiben deaktiviert.
