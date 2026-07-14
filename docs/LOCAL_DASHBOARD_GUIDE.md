# Lokale Phase-8-Anwendung

## Voraussetzungen

- macOS mit lokalem Schlüsselbund
- Node.js 24 oder neuer
- pnpm 11
- lokal installierte, im Lockfile exakt aufgelöste Abhängigkeiten

Für den normalen geführten Demoablauf werden keine Tokens, Konten,
Keychain-Einträge oder Terminalparameter benötigt:

```sh
pnpm install --frozen-lockfile
pnpm app
```

Dashboard, Control Plane und Demo-SaaS starten dabei gemeinsam. Fehlende
Kryptografie-Voraussetzungen werden im Dashboard als Setupzustand angezeigt;
der globale Kill Switch bleibt aktiv. Die folgenden Keychain-Schritte sind nur
für den separaten signierten 18-Schritte-Control-Plane-Lauf erforderlich.

## Event-Schlüssel lokal einrichten

Der normale Phase-8-Guided-Flow benötigt keinen Event-Schlüssel. Ohne
vollständige Kryptografie-Konfiguration startet `pnpm app` als
`local_setup_shell`: Der Event Store wird nicht konstruiert, positive
persistierende Core-Routen bleiben gesperrt und der Kill Switch bleibt aktiv.

Nur der getrennte signierte 18-Schritte-Control-Plane-Pfad und die
Event-Key-Administration verwenden `MacOSKeychainSecretStore`. Dafür muss ein
exakt 32 Byte langer Schlüssel separat, offline und nach einer geprüften
Keychain-Betriebsanweisung bereitgestellt werden. Dieses Dokument enthält
keinen Secret-tragenden Shell-Einzeiler. Schlüsselmaterial darf nicht als
Prozessargument, Shell-Historie, Skript, Log, Datei, Umgebungsvariable oder
Repositoryinhalt erscheinen. Danach wird ausschließlich der nicht geheime,
positive Rollback-Anker gesetzt, zum Beispiel
`BUGBOUNTY_EVENT_KEY_MIN_VERSION=1`. Fehlende, ungültige oder unter dem
authentifizierten Head liegende Konfiguration blockiert den sicheren Core
fail-closed.

## Lokale Operator-Credential einrichten

Phase 4 verlangt für den signierten Simulator, positive Approval-
Entscheidungen und Kill-Clear eine Ed25519-PKCS#8-Credential aus demselben
macOS-Schlüsselbund. Die Bereitstellung ist ein separater, geprüfter lokaler
Offline-Administrationsschritt und erfolgt niemals durch die Anwendung oder
über Secret-tragende Kommandozeilenargumente.

Danach ausschließlich die nicht geheimen Metadaten setzen:

```sh
export BUGBOUNTY_OPERATOR_KEY_REFERENCE=keychain://bugbounty-copilot/operator-ed25519-v1
export BUGBOUNTY_OPERATOR_ID=local-reviewer
export BUGBOUNTY_OPERATOR_KEY_REVISION=1
```

Der private Schlüssel darf niemals als Datei, Umgebungsvariablenwert, Log oder
Repositoryinhalt abgelegt werden. Fehlende, partielle oder ungültige
Metadaten, Keychain-Lesefehler und ungültige Schlüssel halten den sicheren
Core gesperrt; die Loopback-Setup-Shell bleibt verfügbar und zeigt den
blockierten Zustand. Eine bereits eingeschriebene andere Credential wird
nicht automatisch ersetzt.

## Start

Im Repository ausführen:

```sh
pnpm install --frozen-lockfile
pnpm app
```

Der UI-Start benötigt keine Mindestversion. Nur signierte und verschlüsselte
Control-Plane-Aktionen werden ohne passenden Anker deaktiviert. Nach einer
Rotation beispielsweise auf v2 lautet dieser für solche Aktionen
`BUGBOUNTY_EVENT_KEY_MIN_VERSION=2`.

Die Control Plane bindet bevorzugt an:

```text
http://127.0.0.1:4173
```

Ist Port `4173` bereits lokal belegt, wird ein ephemerer Loopback-Port
verwendet und ausdrücklich ausgegeben. Die separate Demo-SaaS erhält immer
einen zufälligen freien Loopback-Port. Eine Bindung an `0.0.0.0`, `::` oder
einen externen Host ist nicht vorgesehen.

## Sicherheitsstatus

Jede Seite zeigt sichtbar:

- `SIMULATIONSMODUS`
- `EXTERNE INTEGRATIONEN DEAKTIVIERT`
- `KEINE REALE REPORT-EINREICHUNG`

Eine neue lokale Datenbank und jeder Dashboard-Start aktiviert den globalen Kill Switch. Clear-Zustände sind an Control-Plane-ID, Credential, Schlüsselrevision, Session, Nonce, Revision, Zeitfenster, Signatur, Audit-ID und Kontextdigest gebunden. Fehlende, unlesbare oder inkonsistente Zustände werden als aktiv behandelt. Engagement pausiert aktive Kampagnen. Die Oberfläche schützt mutierende Requests mit exakter Host-/Origin-Prüfung und einem zufälligen CSRF-Token; Skripte und Styles werden nur als eigene statische Ressourcen unter einer restriktiven Content Security Policy ausgeliefert.

## Geführten Phase-8-Demoablauf ausführen

Die beim Start ausgegebene Dashboard-URL öffnen und den 21 festen Schritten
folgen. Testmail-Schema, zwei lokale Programmnamen, optionale
Admin-Asset-Exclusion, lesbare oder strukturierte Policy-Fixture sowie die
Budgets `0|4|8` und `0|1|2` sind über sichere UI-Controls wählbar. Für den
festen Baseline/Test/Kontrolltest-Rollengrenzfall sind Owner, Member und
External gemeinsam erforderlich. Die Policy wird aus einer lokalen Fixture
importiert und zeigt Quelle, Inhalt, Hash und vollständigen Diff; jeder
rechtlich oder wirkungsbezogen relevante Kontrollpunkt benötigt einen
ausdrücklichen Klick.

Die Journey verwendet Katalog-ID `phase7-local-demo-role-boundary` und den
gepinnten Digest
`f93fda8ba5203f1de6c7c4e2983c78c62d0767597a837d530324e6dc740673e5`.
Das Produkt projiziert 20 Katalogschritte, startet keinen Browser und erzeugt
keinen Request. Ein eigener Button öffnet das lokale Ergebnis. Identitäten,
Objekt, Canary-Digest und Demo-Policy stammen aus der validierten
Demo-SaaS-Projektion; Drift blockiert weitere Aktionen und markiert Evidence
und Report als ungültig.

## Signierte 18-Schritte-Control-Plane-Simulation ausführen

1. Die beim Start ausgegebene Dashboard-URL öffnen.
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

## Geschlossene lokale Browserjourney testen

Phase 7 besitzt einen getrennten test-only Browserpfad auf demselben
produktneutralen Journey-Katalog. Er benötigt keine Keychain-Credential und
darf nicht aus dem Dashboard gestartet werden:

```sh
pnpm test:browser
```

Der Test startet pro Replay eine neue Demo-SaaS auf einem ephemeren
`127.0.0.1`-Port. Owner, Member und External durchlaufen feste read-only
GET-Graphen zweimal in umgekehrter Reihenfolge. Die Profile sind keine
Anmeldung und kein Nachweis serverseitiger Autorisierung. Ein zweiter
Loopback-Server beweist, dass ein fremder Port vor dem Request blockiert wird.

Playwright schreibt keine Screenshots, Traces, Videos, HARs oder
Storage-State-Dateien. Die einzige visuelle Evidence ist ein sofort
verworfener, vollständig opak maskierter In-Memory-Puffer; nur sein
rollen-/zustandsgebundener Digest und seine Byteanzahl gelangen in die
minimierte Test-Evidence. Weitere Betriebsdetails stehen in
`PHASE7_LOCAL_BROWSER_JOURNEYS.md`.

## Event-Key lokal administrieren

Der Adminpfad arbeitet ausschließlich auf
`.local/dashboard/event-store`. Dashboard vor Adoption, Rotation oder Recovery
vollständig beenden. Status lesen:

```sh
pnpm event-key:admin status
```

Der Phase-8-App-Start konstruiert den Event Store nicht. Erst der vollständig
konfigurierte signierte Simulator öffnet einen nachweislich leeren Store bei
Bedarf sicher als v1. Derselbe Schritt kann bewusst separat ausgeführt werden:

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
