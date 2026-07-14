# Lokales Phase-2-Dashboard

## Voraussetzungen

- macOS mit lokalem Schlüsselbund
- Node.js 24 oder neuer
- pnpm 11
- lokal installierte, im Lockfile exakt aufgelöste Abhängigkeiten

## Event-Schlüssel lokal einrichten

Dashboard und Phase-2-CLI verwenden ausschließlich `MacOSKeychainSecretStore`. Es gibt keinen Klartext- oder In-Memory-Fallback im Produktpfad. Vor dem ersten Simulationslauf einmal lokal ausführen:

```sh
security add-generic-password -U -s bugbounty-copilot -a event-store-v1 -w "$(openssl rand -base64 24)"
export BUGBOUNTY_EVENT_KEY_MIN_VERSION=1
```

Die 24 zufälligen Binärbytes werden durch Base64 zu exakt 32 ASCII-Bytes und unter der Referenz `keychain://bugbounty-copilot/event-store-v1` gespeichert. Den Wert weder anzeigen noch in Shell-Historien, Skripte, Logs oder das Repository kopieren. Fehlt der Eintrag, ist er unlesbar oder nicht exakt 32 Byte lang, endet der Lauf mit `SIMULATION_EVENT_SECRET_UNAVAILABLE`, bevor der Kill Switch freigegeben oder Control-Plane-Zustand verändert wird. Auf anderen Betriebssystemen bleibt dieser Produktpfad fail-closed deaktiviert.

`BUGBOUNTY_EVENT_KEY_MIN_VERSION` ist für jeden Start verpflichtend und
besitzt keinen Default. Der Wert ist ein positiver, store-spezifischer
Rollback-Anker. Fehlende oder ungültige Konfiguration blockiert mit
`EVENT_KEY_MIN_VERSION_CONFIG_INVALID`; ein persistierter Head unter dem Wert
blockiert ebenfalls. Ein wirklich frischer Store beginnt ausschließlich mit
Version 1.

## Lokale Operator-Credential einrichten

Phase 4 verlangt für Simulation, Approval-Entscheidungen und Kill-Clear einen
Ed25519-PKCS#8-Schlüssel aus demselben macOS-Schlüsselbund. Die Bereitstellung
ist bewusst ein manueller lokaler Administrationsschritt und erfolgt nicht
durch die Anwendung:

```sh
security add-generic-password -U -s bugbounty-copilot -a operator-ed25519-v1 -T /usr/bin/security -X "$(openssl genpkey -algorithm ED25519 -outform DER 2>/dev/null | xxd -p -c 256)"
```

Danach ausschließlich die nicht geheimen Metadaten setzen:

```sh
export BUGBOUNTY_OPERATOR_KEY_REFERENCE=keychain://bugbounty-copilot/operator-ed25519-v1
export BUGBOUNTY_OPERATOR_ID=local-reviewer
export BUGBOUNTY_OPERATOR_KEY_REVISION=1
```

Der private Schlüssel darf niemals als Datei, Umgebungsvariablenwert, Log oder
Repositoryinhalt abgelegt werden. Fehlende Metadaten deaktivieren die lokale
Signierfähigkeit. Partielle/ungültige Metadaten, Keychain-Lesefehler oder ein
ungültiger Schlüssel lassen den Start fail-closed abbrechen. Eine bereits
eingeschriebene andere Credential wird nicht automatisch ersetzt.

## Start

Im Repository ausführen:

```sh
pnpm install --frozen-lockfile
pnpm dashboard
```

Der Start benötigt weiterhin die im selben Terminal gesetzte Mindestversion.
Nach einer Rotation beispielsweise auf v2 lautet sie
`BUGBOUNTY_EVENT_KEY_MIN_VERSION=2`.

Die Control Plane bindet ausschließlich an:

```text
http://127.0.0.1:4173
```

Die separate Demo-SaaS erhält einen zufälligen freien Loopback-Port. Beide Adressen werden beim Start ausgegeben. Eine Bindung an `0.0.0.0`, `::` oder einen externen Host ist nicht vorgesehen.

## Sicherheitsstatus

Jede Seite zeigt sichtbar:

- `SIMULATIONSMODUS`
- `EXTERNE INTEGRATIONEN DEAKTIVIERT`

Eine neue lokale Datenbank und jeder Dashboard-Start aktiviert den globalen Kill Switch. Clear-Zustände sind an Control-Plane-ID, Credential, Schlüsselrevision, Session, Nonce, Revision, Zeitfenster, Signatur, Audit-ID und Kontextdigest gebunden. Fehlende, unlesbare oder inkonsistente Zustände werden als aktiv behandelt. Engagement pausiert aktive Kampagnen. Die Oberfläche schützt mutierende Requests mit exakter Host-/Origin-Prüfung und einem zufälligen CSRF-Token; Skripte und Styles werden nur als eigene statische Ressourcen unter einer restriktiven Content Security Policy ausgeliefert.

## Simulation ausführen

1. Dashboard unter `http://127.0.0.1:4173` öffnen.
2. Im Bereich „Vollständige lokale Simulation“ alle sechs menschlichen Bestätigungen einzeln setzen.
3. Simulation starten.
4. Die 18 Schritte, Policy-Diff, Kampagnenstatus, Testidentitäten, Ownership Ledger, Freigaben und Report-Entwurf prüfen.
5. Den globalen Kill Switch jederzeit über „Sofort stoppen“ aktivieren.

Das Dashboard übernimmt die konfigurierte Operator-ID schreibgeschützt. Ohne
injizierte lokale Signierfähigkeit blockieren Simulation, Approval und
Kill-Clear mit `OPERATOR_SIGNER_REQUIRED`; die jederzeit sichere Aktivierung
des Kill Switches bleibt verfügbar.

Die sechs Bestätigungen sind exakt:

1. Kill Switch nur für diesen lokalen Lauf freigeben.
2. Policy v1 samt Hash akzeptieren.
3. Kampagnenvertrag v1 samt vollständigem Digest freigeben.
4. Policy v2 nach Prüfung des Diffs akzeptieren.
5. Kampagnenvertrag v2 samt vollständigem Digest freigeben.
6. Report-Entwurf nur zur lokalen menschlichen Review einreihen.

Owner, Member und External sind vorautorisierte, checkpoint-freie In-Process-Demo-Fixtures; der Ablauf repräsentiert keine Registrierung und akzeptiert keine Bedingungen. Konfigurierte Account-Challenges wie CAPTCHA, E-Mail-Verifikation, TOTP, Programmregeln, Bedingungen oder rechtliche Erklärungen pausieren immer und werden niemals automatisch erfüllt.

## Event-Key lokal administrieren

Der Adminpfad arbeitet ausschließlich auf
`.local/dashboard/event-store`. Dashboard vor Adoption, Rotation oder Recovery
vollständig beenden. Status lesen:

```sh
pnpm event-key:admin status
```

Das Dashboard initialisiert nur einen nachweislich leeren Store automatisch
als v1. Derselbe Schritt kann bewusst separat ausgeführt werden:

```sh
pnpm event-key:admin initialize --confirm-local-event-key-initialize
```

Ein bestehender Phase-4-Store wird niemals automatisch übernommen. Nach
vollständiger lokaler Verifikation kann er explizit adoptiert werden:

```sh
pnpm event-key:admin adopt-legacy-v1 --confirm-local-legacy-adoption
```

Vor einer v1→v2-Rotation zuerst einen neuen, verschiedenen 32-Byte-Schlüssel
als `event-store-v2` im Keychain bereitstellen. Die Rotation läuft noch mit dem
bisherigen Mindestanker:

```sh
BUGBOUNTY_EVENT_KEY_MIN_VERSION=1 \
  pnpm event-key:admin rotate \
  --expected 1 \
  --next 2 \
  --confirm-local-event-key-rotation
```

Erst nach erfolgreichem Commit den Mindestanker für alle folgenden Starts
anheben und den Head prüfen:

```sh
export BUGBOUNTY_EVENT_KEY_MIN_VERSION=2
pnpm event-key:admin status
```

Neue Events verwenden jetzt v2; v1-Hüllen bleiben mit dem weiterhin
vorhandenen v1-Key lesbar. Es findet weder automatisches Re-Keying noch eine
automatische Löschung alter Keychain-Einträge statt.

Init, Adoption, Event-Writes und Rotation halten eine private
verzeichnisweite Mutation-Lease. Nach einem Prozessabbruch blockieren ein
verwaister Lock oder eine Event-Temporärdatei jeden weiteren Zugriff. Erst
nachdem sicher festgestellt wurde, dass kein Dashboard- oder Adminprozess mehr
läuft, ist die explizit bestätigte Recovery zulässig:

```sh
pnpm event-key:admin recover-stale-mutation \
  --confirm-local-stale-event-key-recovery
```

Die Recovery verdrängt keine lebende Eigentümer-PID, akzeptiert nur exakt
validierte private Lock-/Temp-Dateien und authentifiziert danach die komplette
State-Chain. Sie ist kein allgemeines Dateireparaturwerkzeug und wird niemals
automatisch ausgeführt.

## Lokale Laufzeitdaten

Das Dashboard schreibt ausschließlich nach `.local/dashboard/`; die
SQLite-Datei erhält Modus `0600`, das Verzeichnis `0700`. Bereits vorhandene
breitere Rechte, user-owned Symlink-Ahnen, Hardlinks, WAL/SHM oder unbekannte
Sidecars blockieren und werden nicht automatisch repariert. Beim Reopen werden
Migration-Checksums, SQLite-Integrität und Foreign Keys geprüft. Ein nach
Engagement-Crash noch als laufend persistierter Kampagnenzustand wird nur in
Richtung `paused` versöhnt; ein Clear bleibt signaturpflichtig. Details stehen
in `PHASE6_CONTROL_PLANE_RECOVERY.md`.

Der Pfad ist per `.gitignore` ausgeschlossen. Simulationsevents werden nur als
versionierte AES-256-GCM-Hüllen gespeichert; die authentifizierte State-Chain
enthält ausschließlich nicht geheime Metadaten. Schlüssel verbleiben im
macOS-Schlüsselbund. Roh-HARs, Klartext-Secrets und unredigierte Responses
werden nicht erzeugt.

Zum Zurücksetzen zuerst den Server beenden und anschließend nur die lokalen Demo-Daten entfernen:

```sh
rm -rf .local/dashboard .local/phase2-simulation
```

## Beenden

Im startenden Terminal `Ctrl-C` drücken. Dashboard und Demo-SaaS werden gemeinsam beendet.
