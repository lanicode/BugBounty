# Lokales Core-Provisioning – Security-Core-Diff

## Zwingende Änderung

`packages/secret-store` gehört zum Phase-1-Sicherheitskern. Das neue lokale
Core-Provisioning ergänzt diese Grenze bewusst und eng begrenzt:

- Der macOS-native Helper erzeugt ein Fresh-Bundle als genau einen neuen
  Keychain-Eintrag oder ergänzt bei `legacy_ready` ausschließlich eine
  fehlende Operator-Hülle.
- Die TypeScript-Grenze stellt zusätzlich eine rein lesende Prüfung derselben
  Event-Verzeichnis- und Operator-Credential-Vorbedingungen bereit. Mutation,
  Modify und Delete bleiben ausgeschlossen.
- Event-Key und privater Operator-Key werden nie in HTTP-Antworten, Logs,
  Dateien, Umgebungsvariablen oder Prozessargumente projiziert.

## Dashboard- und Runtime-Grenzen

Die Dashboard-Route `/api/core/provision` ist nur auf dem bestehenden
Loopback-Server erreichbar und verwendet dessen exakte Host-, Origin-, JSON-
und CSRF-Prüfung. Ihr geschlossener Body enthält ausschließlich Version, eine
feste Bestätigung, Nonce und Kontextdigest. Der Digest bindet Session,
Operator-ID, Keychain-Status, Control-Plane-ID, Kill-Switch-Revision und
-Kontext sowie die geforderte Abwesenheit von Event Store und Operator-
Credential. Die Nonce wird vor der Mutation verbraucht; der Keychain-Zustand
macht Wiederholungen auch nach einem Prozessneustart fail-closed.

Der Server wählt `fresh_bundle` oder `legacy_complete`. Caller können weder
den Modus noch Secretmaterial liefern. Die laufende Setup-Shell übernimmt die
neuen Schlüssel nicht. Erst ein Neustart mit explizitem
`BUGBOUNTY_EVENT_KEY_MIN_VERSION` darf bei einem vollständig validierten
Receipt die festen logischen v1-Referenzen und Operator-Metadaten verwenden.
`legacy_ready`, Konflikte, Receipt-/Metadatenabweichungen und Lesefehler
erzeugen keine Runtime-Capability.

Davon getrennt erkennt der native Inspector den vor Pilot C gültigen,
vollständigen Phase-4/5-Direktzustand als `legacy_direct_complete`: exakt ein
32-Byte-Event-Key und ein kanonischer roher 48-Byte-Ed25519-PKCS#8-Key. Dieser
receiptlose Zustand ist nicht provisionierbar und wird nicht automatisch
migriert. Nur eine vollständige, exakte bestehende Operator-Konfiguration darf
ihn statusgebunden über den Generic-Keychain-Pfad weiterverwenden. Im
Bundle-/Envelope-Modus liest die gemeinsame Core-aware-Komposition v1 dagegen
ausschließlich über den nativen Helper; rotierte Event-Keys v2+ bleiben auf
festen Generic-Keychain-Referenzen. Fehler oder Zustandsdrift lösen keinen
Fallback aus.

## Bewusst unverändert

- Keine Egress-, Browser-, External-Action- oder Active-Testing-Grenze wurde
  erweitert.
- Event-Key-Adoption, -Rotation und -Recovery bleiben lokale Offline-
  Adminoperationen ohne Dashboard-Pfad.
- Es wurde keine Abhängigkeit ergänzt und keine bestehende Schutzprüfung
  gelockert.

## Direkte Regressionen

Contract-, Unit- und Loopback-Integrationstests decken Native-Helper-Vertrag,
StateProbe, Fresh-/Legacy-Modewahl, Kill-Switch-/Credential-/Event-Grenzen,
Nonce-/Digest-Tampering, Replay, CSRF/Origin, secretfreie Projektion,
Neustartpflicht sowie Runtime-Auflösung und fail-closed Teil-/Konfliktzustände
ab.
