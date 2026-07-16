# Phase 5 – versionierter Event-Key-Lifecycle

## Zweck und Umfang

Phase 5 ergänzt den verschlüsselten Phase-1-Event-Store um einen lokalen,
restart-sicheren Schlüssel-Lifecycle. Neue Events werden mit der aktuell
aktivierten Schlüsselversion geschrieben; vorhandene Events bleiben über ihre
explizit aktivierte historische Version lesbar. Der Grundsatz lautet:

```text
write new -> read explicitly activated old
```

Die Implementierung erzeugt keine Schlüssel, übernimmt keine Secrets aus
Dateien oder Umgebungsvariablen und besitzt keinen Klartext-Fallback. Im
Produktpfad werden die 32 Byte langen Event-Schlüssel ausschließlich über die
Core-aware-Keychain-Komposition und Referenzen der Form
`keychain://bugbounty-copilot/event-store-vN` geladen. Nach
Fresh-Provisioning stammt v1 nur aus dem validierten Core-Bundle; rotierte
Versionen v2+ bleiben feste Generic-Keychain-Einträge. Der explizit erkannte,
nicht provisionierbare Phase-4/5-Direktzustand verwendet weiterhin
statusgebunden den Generic-Keychain-Adapter. Fehler lösen keinen Adapter-
Fallback aus.

Phase 5 implementiert bewusst weder automatische Neuverschlüsselung alter
Hüllen noch automatische Löschung, Archivierung oder Wiederherstellung alter
Schlüssel. Es gibt keinen Netzwerktransport und keinen Dashboard-Endpunkt für
Rotation.

`external_integrations_enabled` bleibt effektiv `false`. Entwicklung und Tests
verwenden ausschließlich In-Process-Komponenten, lokale Dateien und
Loopback-Adressen; kein realer Plattform-, Beispiel- oder Bug-Bounty-Zielhost
wird aufgelöst oder kontaktiert.

## Trust Boundary

Die Sicherheitsgrenze besteht aus drei getrennten Komponenten:

- `packages/event-key-lifecycle` besitzt den nicht geheimen, authentifizierten
  Lifecycle-Zustand, bestimmt aktive und lesbare Versionen und delegiert Reads
  und Writes ausschließlich mit diesem Zustand an den Event Store.
- `packages/event-store` besitzt Hüllenvalidierung, AES-256-GCM,
  Pfadbeschränkung, Event-Dateiatomizität und die technische Durchsetzung der
  aktiven beziehungsweise lesbaren Schlüsselversionen.
- `packages/secret-store` löst im Produkt nur `keychain://`-Referenzen über den
  macOS-Schlüsselbund auf. `InMemorySecretStore` ist eine reine Testgrenze.

Vertrauenswürdig bleiben der lokale OS-Account, die Prozess-ID-Anzeige des
Betriebssystems, der macOS-Schlüsselbund, der feste
`keyReference(version)`-Callback und das nur vom lokalen Benutzer beschreibbare
Dateisystem. Der State-Chain-Schutz erkennt Manipulationen innerhalb des
vorgefundenen Zustands, kann aber kein vollständiges Rollback des gesamten
vertrauenswürdigen Dateisystems auf einen früheren konsistenten Snapshot
beweisen. Der verpflichtende `minimumActiveKeyVersion` reduziert dieses Risiko
nur, wenn der Wert getrennt vom zurückgerollten Store erhalten bleibt.

Weder State-Records noch Statusausgaben enthalten Schlüsselmaterial,
Keychain-Referenzen, Eventdaten oder Klartext. Temporäre, vom Lifecycle geladene
Schlüsselkopien werden bei Erfolg und Fehler gelöscht. Alte Schlüssel müssen
dennoch im Keychain verbleiben, solange eine lesbare Hülle auf sie verweist.

## Event-Store-Härtung

`EncryptedEventStore` akzeptiert zusätzlich zur aktiven Schreibversion eine
streng aufsteigende Liste `readableKeyVersions`. Eine Hüllenversion außerhalb
dieser Liste wird vor dem Zugriff auf den `SecretStore` blockiert.

Für Eventhüllen gelten folgende Grenzen:

- Envelope-Version genau `1`;
- Schlüsselversion als positiver Safe Integer von `1` bis `10_000`;
- exaktes Objekt ohne Zusatzfelder, Accessors, Symbole oder Prototype-Spoofing;
- kanonisches Base64;
- Nonce genau 12 Byte;
- GCM-Tag genau 16 Byte;
- maximale Hüllengröße 4 MiB;
- Dateiname exakt `<event-id>.events.enc`, wobei die Event-ID höchstens 80
  alphanumerische Zeichen, `_` oder `-` enthält;
- nur Dateien direkt im konfigurierten Event-Verzeichnis;
- Öffnen mit `O_NOFOLLOW`, sodass symbolische Links nicht gelesen werden;
- AES-256-GCM-AAD `event-store:v1:key:<keyVersion>`;
- genau 32 Byte lange, unverfälschte `Uint8Array`-Schlüssel;
- indexweises Überschreiben der geladenen Schlüsselkopie in `finally`.

Die serialisierte Hüllengröße wird vor Verzeichnis- oder Dateianlage geprüft.
Neue Eventdateien werden weiterhin write-once über eine private temporäre
Datei, Datei-`fsync` und einen atomaren Hardlink auf den endgültigen Namen
angelegt. Nach Link und nach Temp-Unlink wird das Eventverzeichnis mit `fsync`
gesichert. Ein bestehendes Event wird nicht überschrieben; fehlgeschlagene
Temp-Bereinigung wird nicht unterdrückt, sondern erzwingt die explizite
Lifecycle-Recovery.

## State-Verzeichnis und Record-Schema

Der Lifecycle speichert ausschließlich nicht geheime Metadaten unter:

```text
<event-directory>/.event-key-state/
  state-0000000001.json
  state-0000000002.json
  ...
```

Event- und State-Verzeichnis müssen privat sein. Verzeichnisse erhalten Modus
`0700`, State-Records Modus `0600`. Ein State-Record ist höchstens 16 KiB groß,
ist kanonisches JSON ohne abweichende Leerzeichen oder Zusatzfelder und besitzt
exakt dieses Schema:

```json
{
  "activeKeyVersion": 2,
  "authenticationTag": "<64 lowercase hex>",
  "operation": "rotate",
  "previousRecordDigest": "<64 lowercase hex>",
  "readableKeyVersions": [1, 2],
  "revision": 2,
  "schemaVersion": 1,
  "storeId": "<64 lowercase hex>"
}
```

Die Feldbedeutung ist:

- `schemaVersion`: derzeit ausschließlich `1`;
- `storeId`: einmalig zufällig erzeugte 32-Byte-Store-ID in Hex und
  Cross-Store-Bindung;
- `revision`: lückenloser positiver Zähler ab `1`;
- `operation`: beim ersten Record `initialize` oder `adopt_legacy_v1`, danach
  ausschließlich `rotate`;
- `activeKeyVersion`: aktive Schreibversion; im aktuellen monotonen Modell
  identisch zur Revision;
- `readableKeyVersions`: exakt die lückenlose Folge `1..activeKeyVersion`;
- `previousRecordDigest`: SHA-256 des vollständigen kanonischen vorherigen
  Records; beim Genesis-Record 64 Nullen;
- `authenticationTag`: Authentisierung des Records mit dem aktiven Event-Key.

Dateiname, Revision, aktive Version, Vorgängerdigest, `storeId`, Operation und
lesbare Versionsfolge werden gemeinsam geprüft. Fehlende, doppelte,
vertauschte oder unbekannte Revisionen blockieren den gesamten Store.

## HKDF, HMAC und Chain

Der Event-Key wird nicht unmittelbar gleichzeitig als AES- und State-HMAC-Key
verwendet. Für jeden Record wird ein separater 32-Byte-Key abgeleitet:

```text
HKDF-SHA-256(
  input key = Event-Key der activeKeyVersion,
  salt      = binäre storeId,
  info      = "event-key-state:v1",
  length    = 32 Byte
)
```

`authenticationTag` ist HMAC-SHA-256 über das kanonische JSON aller übrigen
Record-Felder. Beim Öffnen werden alle Records strukturell geprüft, alle
referenzierten Schlüssel geladen, paarweise konstantzeitlich auf
Wiederverwendung geprüft und danach sämtliche HMACs verifiziert. Zwei
Versionen dürfen nicht dieselben Schlüsselbytes besitzen.

Der SHA-256-Digest des vollständigen, authentifizierten Records wird als
`previousRecordDigest` des Nachfolgers gebunden. Ein fehlender alter Schlüssel
blockiert deshalb auch dann den Restart, wenn nur neue Events geschrieben
werden sollen. Es gibt keinen partiellen oder nur-schreibenden Fallback.

## Atomarer State-Commit

Ein neuer State-Record wird innerhalb einer gehaltenen verzeichnisweiten
Mutation-Lease append-only geschrieben:

1. kanonischen Record vollständig im Speicher erzeugen;
2. private temporäre Datei mit `wx` und Modus `0600` öffnen;
3. Record schreiben und Datei mit `fsync` sichern;
4. temporären Modus erneut auf `0600` setzen;
5. per Hardlink atomar auf den revisionsgebundenen endgültigen Namen committen;
6. State-Verzeichnis mit `fsync` sichern;
7. temporären Namen entfernen und das State-Verzeichnis erneut mit `fsync`
   sichern;
8. Lease-Eigentum erneut prüfen;
9. die vollständige Chain erneut vom Datenträger laden und verifizieren.

Der endgültige Name existiert höchstens einmal. Zwei konkurrierende
Rotationsversuche können daher nicht zwei verschiedene Records derselben
Revision committen. `EEXIST` wird fail-closed als
`EVENT_KEY_ROTATION_CONFLICT` behandelt.

Temporäre Namen werden nur im engen Format
`.tmp-state-<pid>-<16 lowercase hex>` toleriert. Sie müssen regulär, privat und
höchstens 16 KiB groß sein. Andere Dateien, Verzeichnisse oder Symlinks im
State-Verzeichnis blockieren. Ein tolerierter Temp-Record ist niemals Teil der
Chain, wird nicht automatisch als gültiger Zustand übernommen und kann keinen
finalen Record ersetzen.

## Verzeichnisweite Mutation-Lease

Init, Legacy-Adoption, jeder Event-Write und jede Rotation erwerben exklusiv:

```text
<event-directory>/.event-key-mutation.lock
```

Die private Datei besitzt Modus `0600` und ein kanonisches, geschlossenes
Record aus `schemaVersion`, `ownerPid` und einem zufälligen 128-Bit-Token. Sie
enthält weder Secret-Referenzen noch Schlüssel- oder Eventdaten. Anlage erfolgt
mit `wx`, danach werden Lockdatei und Eventverzeichnis per `fsync` gesichert.

Die Lease umfasst den gesamten sicherheitsrelevanten Bereich: State und
Eventverzeichnis neu laden und authentifizieren, Operation ausführen,
endgültigen Commit sichern und Lease-Eigentum erneut prüfen. Erst danach wird
der Lock entfernt und das Verzeichnis erneut synchronisiert. Damit kann ein
zweiter Lifecycle-Prozess nicht zwischen Refresh und Event-Write oder Rotation
treten. Ein vorhandener fremder Lock, ein geänderter Token, ein Symlink,
abweichende Rechte, nicht kanonisches JSON oder ein I/O-Fehler blockiert
fail-closed. Reads und Open blockieren ebenfalls, solange eine Mutation aktiv
oder ungeklärt ist.

Nach einem harten Prozessabbruch bleibt die Lockdatei absichtlich bestehen.
Eine Event-Temporärdatei im exakten Format
`.tmp-<pid>-<16 lowercase hex>` führt auch ohne Lock zu
`EVENT_KEY_MUTATION_RECOVERY_REQUIRED`; sie wird niemals beim normalen Start
automatisch entfernt. Die Recovery ist ein ausdrücklicher Offline-Adminschritt:

1. Dashboard und alle Event-Key-Adminprozesse beenden;
2. Lock strukturell prüfen und eine noch lebende `ownerPid` ablehnen;
3. nur exakt benannte, reguläre, private und größenbegrenzte Event-Temps
   vorvalidieren und entfernen;
4. Eventverzeichnis mit `fsync` sichern;
5. die vollständige State-Chain und alle aktivierten Keys authentifizieren;
6. erst nach vollständigem Erfolg die Lease entfernen und erneut `fsync`
   ausführen.

Unbekannte Dateien, ungültige Temps oder jeder Recovery-Fehler lassen den
Store blockiert. Es gibt keinen Timeout, keine automatische Stale-Erkennung
und keine Best-effort-Bereinigung.

## Lifecycle-Operationen

### Fresh Init

`initializeFresh()` erstellt ausschließlich Genesis v1. Es verlangt:

- den verpflichtenden `minimumActiveKeyVersion = 1`;
- keine vorhandenen State-Records;
- keine vorhandenen Eventdateien;
- einen lesbaren, exakt 32 Byte langen Schlüssel v1.

Existierende Events ohne Lifecycle-State führen zu
`EVENT_KEY_LEGACY_ADOPTION_REQUIRED`. Fehlender oder ungültiger v1-Key erzeugt
keinen Genesis-Record.

`openOrInitializeFresh()` ist der Produktpfad. Er öffnet einen vorhandenen
State strikt. Nur bei tatsächlich fehlendem Root/State oder einem vollständig
leeren State-Verzeichnis ohne Events wird Fresh Init versucht. Dadurch kann ein
nach fehlendem Key verbliebenes leeres Verzeichnis sicher erneut initialisiert
werden. Ein existierender nichtleerer, aber ungültiger State wird niemals
überschrieben oder neu initialisiert. Ein Initialisierungsrennen endet entweder
im einzigen erfolgreichen Genesis-Commit oder in einem strikten Reload des
Gewinnerzustands.

### Strict Open und Restart

`open()` initialisiert nichts. Es verlangt vorhandene private Verzeichnisse,
eine lückenlose kanonische Chain und alle Schlüssel von v1 bis zur aktiven
Version. Jeder Record und jede HMAC werden neu geprüft. Der Head muss mindestens
der verpflichtend konfigurierten Mindestversion entsprechen. Ein vorhandener
Mutation-Lock oder ein verwaistes Event-Temp blockiert bereits vor Nutzung des
Stores.

Nach Rotation und Prozessneustart wird die aktive Version ausschließlich aus
dem authentifizierten Head geladen. Reads und Writes aktualisieren den
Lifecycle-Zustand vor jeder Operation erneut. Der Event Store schreibt mit der
Head-Version und darf nur die im Head aufgelisteten historischen Versionen
lesen.

### Explizite Legacy-v1-Adoption

`adoptLegacyV1()` ist die einzige Migration für Eventverzeichnisse aus den
Phasen 1 bis 4. Sie ist niemals automatisch. Sie verlangt:

- keinen vorhandenen State-Record;
- mindestens eine Eventdatei;
- ausschließlich private reguläre Dateien mit gültigem Eventnamen;
- Envelope-Version 1 und Key-Version 1 für jede Datei;
- erfolgreiche AES-GCM-Authentisierung und JSON-Validierung jedes Events;
- eine unveränderte Dateiliste zwischen Beginn und Ende der Prüfung;
- einen lesbaren, exakt 32 Byte langen v1-Key.

Erst danach wird Genesis mit `operation: "adopt_legacy_v1"` committed.
Gemischte Versionen, manipulierte Events, unbekannte Dateien oder Änderungen
während der Prüfung blockieren vollständig.

### Rotation

`rotate({ expectedActiveKeyVersion, nextKeyVersion })` akzeptiert ein exaktes
Datenobjekt ohne Zusatzfelder, Symbole oder Accessors. Die Operation:

1. erwirbt die verzeichnisweite Mutation-Lease;
2. lädt und authentifiziert den aktuellen State vollständig;
3. verlangt, dass `expectedActiveKeyVersion` exakt dem Head entspricht;
4. erlaubt ausschließlich `nextKeyVersion = current + 1` bis maximal `10_000`;
5. lädt alle alten und den neuen Key;
6. blockiert fehlende, falsch lange oder wiederverwendete Schlüssel;
7. erzeugt den nächsten authentifizierten Record;
8. committed ihn atomar;
9. lädt und prüft den neuen Head erneut;
10. löscht alle temporären Schlüsselkopien und gibt die Lease erst danach
    frei.

Es findet kein Re-Key alter Hüllen statt. Der neue Record erweitert
`readableKeyVersions`; er entfernt keine alte Version.

## Mindestversion und Rollback-Anker

`minimumActiveKeyVersion` ist ein positiver Safe Integer von `1` bis `10_000`.
Er ist verpflichtend und besitzt keinen Standardwert. Liegt der
authentifizierte Head darunter, blockiert Open mit
`EVENT_KEY_ACTIVE_VERSION_BELOW_MINIMUM`.

Dashboard, Simulations-CLI und Event-Key-Admin lesen den Wert aus:

```text
BUGBOUNTY_EVENT_KEY_MIN_VERSION
```

Fehlende oder ungültige Konfiguration blockiert mit
`EVENT_KEY_MIN_VERSION_CONFIG_INVALID`. Die Mindestversion muss erst nach
erfolgreicher Rotation angehoben werden. Würde sie schon vor der Rotation auf
die nächste Version gesetzt, könnte der Adminpfad den aktuellen Head nicht
öffnen.

Die Konfiguration ist kein Ersatz für sichere Backups oder einen
hardwaregestützten monotonen Zähler. Sie verhindert jedoch, dass ein Prozess
versehentlich einen formal gültigen Head unterhalb der betrieblich erwarteten
Version akzeptiert.

## Produktkomposition

Dashboard, Phase-2-Simulations-CLI und Event-Key-Admin-CLI injizieren:

- das jeweilige lokale Eventverzeichnis;
- die fail-closed Core-aware-Keychain-Komposition beziehungsweise den explizit
  erkannten statusgebundenen Phase-4/5-Direktadapter;
- den festen Callback
  `keychain://bugbounty-copilot/event-store-v<version>`;
- `BUGBOUNTY_EVENT_KEY_MIN_VERSION`.

Der letzte Wert muss in jedem Produktprozess ausdrücklich vorhanden und gültig
sein. Ein fehlender Wert wird nicht als v1 interpretiert.

`SimulationOrchestrator` führt `openOrInitializeFresh()` vor der ersten
fachlichen Simulationsmutation aus. Jeder Lifecycle-, State- oder
Secret-Store-Fehler wird an dieser Produktgrenze konservativ als
`SIMULATION_EVENT_SECRET_UNAVAILABLE` behandelt. Die Simulation bleibt damit
vor Control-Plane-Zustandsänderungen blockiert.

Der persistente Dashboardpfad lautet `.local/dashboard/event-store`. Der
separate Simulations-CLI-Lauf verwendet ein neues lokales Laufverzeichnis. Es
gibt keinen HTTP-, Browser- oder External-Action-Pfad zur Event-Key-Rotation.

## Lokale Admin-CLI

Der Adminpfad arbeitet ausschließlich auf `.local/dashboard/event-store` und
verwendet den macOS-Keychain-Adapter. Er akzeptiert keine Schlüsselwerte als
Argument oder Umgebungsvariable. Der benötigte Keychain-Eintrag muss vor einer
Rotation bereits lokal und außerhalb dieses Workflows bereitgestellt sein.

Status anzeigen:

```sh
pnpm event-key:admin status
```

Jeder Befehl benötigt `BUGBOUNTY_EVENT_KEY_MIN_VERSION` passend zum erwarteten
Store-Head. Die folgenden v1-Beispiele setzen daher eine zuvor exportierte `1`
voraus.

Einen wirklich leeren Store explizit als v1 initialisieren:

```sh
pnpm event-key:admin initialize --confirm-local-event-key-initialize
```

Vorhandene, vollständig verifizierte Legacy-v1-Events explizit übernehmen:

```sh
pnpm event-key:admin adopt-legacy-v1 --confirm-local-legacy-adoption
```

Offline von v1 auf v2 rotieren:

```sh
BUGBOUNTY_EVENT_KEY_MIN_VERSION=1 \
  pnpm event-key:admin rotate \
  --expected 1 \
  --next 2 \
  --confirm-local-event-key-rotation
```

Nach erfolgreicher Rotation wird die ausgegebene
`requiredMinimumVersionAfterRestart` betrieblich übernommen und der neue Head
erneut geprüft:

```sh
export BUGBOUNTY_EVENT_KEY_MIN_VERSION=2
pnpm event-key:admin status
```

Nach einem bestätigten Prozessabbruch und nur bei sicher beendetem Dashboard
eine verwaiste Mutation explizit untersuchen und recovern:

```sh
pnpm event-key:admin recover-stale-mutation \
  --confirm-local-stale-event-key-recovery
```

Eine noch lebende Eigentümer-PID, ein ungültiger Lock, unbekannte Dateien oder
nicht exakt validierbare Event-Temps blockieren. Ein fehlgeschlagener
Recovery-Versuch gibt den Store nicht frei.

Der Dashboardprozess muss während Adoption oder Rotation beendet sein. Die
Bestätigungsflags sind absichtliche lokale Kontrollpunkte; sie ersetzen keine
Schlüsselbereitstellung und keine automatische Zustimmung zu Regeln,
Nutzungsbedingungen oder rechtlichen Erklärungen.

## Mehrprozess- und Recovery-Grenzen

Die Lifecycle-Instanz serialisiert ihre eigenen Operationen. Zusätzlich
serialisiert die verzeichnisweite Mutation-Lease Init, Legacy-Adoption, Writes
und Rotation über unabhängige Prozesse. Der append-only Hardlink-Commit
verhindert doppelte Records derselben Revision, und jede Operation aktualisiert
den Head innerhalb der Lease vor der Delegation. Konkurrierende Prozesse
warten nicht unbeschränkt, sondern blockieren deterministisch.

Rotation und Legacy-Adoption bleiben trotz Lease bewusst Offline-Operationen
bei beendetem Dashboard. Die Recovery ist ebenfalls offline und ausdrücklich;
sie ist keine automatische Mehrprozesskoordination und kein allgemeines
Reparaturwerkzeug. Automatische Key-Retirement-, State-Temp-Cleanup-, Re-Key-
oder Restore-Funktionen sind nicht implementiert.

Ein verlorener alter Schlüssel blockiert den gesamten Store. Das ist
beabsichtigt: Es gibt keinen Klartextbetrieb, kein Überspringen alter Records
und keine automatische Löschung nicht mehr entschlüsselbarer Events.

## Crash-, Restart- und Prozessnachweis

Die Tests verwenden echte lokale Kindprozesse, aber keinen Netzwerktransport.
Ein Kindprozess hält die Mutation-Lease im vollständigen Refresh-/Write-
Bereich; ein unabhängiger Prozess kann den Store in dieser Zeit weder öffnen
noch rotieren. Weitere Kindprozesse werden kontrolliert mit `SIGKILL` beendet:

- **pre-link:** Abbruch vor dem finalen State-Hardlink lässt v1 als einzigen
  Head aktiv;
- **post-link:** Abbruch nach erfolgreichem State-Hardlink lässt v2 als
  persistierten Head zurück.

Beide Fälle bleiben wegen der haltbaren Lease zunächst blockiert, verweigern
Recovery solange die Eigentümer-PID lebt und öffnen erst nach expliziter
Recovery mit dem jeweils erwarteten Mindestanker. Separate Fault-Injection
erzwingt Fehler vor dem Link, nach dem Link beim State-Verzeichnis-`fsync`, bei
Event-Temp-Unlink und bei Directory-`fsync`; jeder Pfad bleibt fail-closed.

## Reason Codes

### Lifecycle-Konfiguration und Keys

| Reason Code                              | Bedeutung                                                                                 |
| ---------------------------------------- | ----------------------------------------------------------------------------------------- |
| `EVENT_KEY_LIFECYCLE_OPTIONS_INVALID`    | Lifecycle-Optionen oder Mindestversion sind strukturell ungültig.                         |
| `EVENT_KEY_ACTIVE_VERSION_BELOW_MINIMUM` | Der authentifizierte Head liegt unter der konfigurierten Mindestversion.                  |
| `EVENT_KEY_REFERENCE_INVALID`            | Der versionsabhängige Referenz-Callback schlägt fehl oder liefert keine sichere Referenz. |
| `EVENT_KEY_UNAVAILABLE`                  | Ein erforderlicher historischer oder aktiver Key kann nicht geladen werden.               |
| `EVENT_KEY_INVALID`                      | Ein geladener Key ist nicht als exakt 32 Byte langer zulässiger `Uint8Array` verwendbar.  |
| `EVENT_KEY_DUPLICATE`                    | Zwei aktivierte Versionen besitzen identische Schlüsselbytes.                             |

### Verzeichnis und State-Chain

| Reason Code                             | Bedeutung                                                                           |
| --------------------------------------- | ----------------------------------------------------------------------------------- |
| `EVENT_KEY_DIRECTORY_INVALID`           | Root oder State-Pfad ist kein reguläres Verzeichnis oder ist ein Symlink.           |
| `EVENT_KEY_DIRECTORY_PERMISSIONS`       | Ein Lifecycle-Verzeichnis ist nicht privat genug.                                   |
| `EVENT_KEY_DIRECTORY_UNKNOWN_FILE`      | Fresh Init oder Legacy-Adoption findet eine unbekannte Root-Datei.                  |
| `EVENT_KEY_STATE_MISSING`               | State-Verzeichnis oder mindestens ein erforderlicher State-Record fehlt.            |
| `EVENT_KEY_STATE_EXISTS`                | Initialisierung oder Adoption trifft bereits vorhandenen State.                     |
| `EVENT_KEY_STATE_IO_FAILED`             | State-I/O oder die erforderliche Verzeichnis-Durability kann nicht bewiesen werden. |
| `EVENT_KEY_STATE_FILE_INVALID`          | Name, Typ, Größe oder Rechte eines State-Records sind ungültig.                     |
| `EVENT_KEY_STATE_JSON_INVALID`          | Ein State-Record ist kein gültiges JSON.                                            |
| `EVENT_KEY_STATE_RECORD_INVALID`        | Schema, Kanonisierung oder Feldwerte eines Records sind ungültig.                   |
| `EVENT_KEY_STATE_CHAIN_INVALID`         | Revision, Version, Vorgängerdigest, Operation oder Store-Bindung ist inkonsistent.  |
| `EVENT_KEY_STATE_AUTHENTICATION_FAILED` | Ein Record-HMAC stimmt nicht.                                                       |
| `EVENT_KEY_STATE_SYMLINK`               | Ein Eintrag im State-Verzeichnis ist ein symbolischer Link.                         |
| `EVENT_KEY_STATE_TEMP_INVALID`          | Eine temporäre Datei verletzt Name, Typ, Größe oder Rechte.                         |
| `EVENT_KEY_STATE_TEMP_CLEANUP_FAILED`   | State-Temp-Unlink oder anschließendes Verzeichnis-`fsync` schlägt fehl.             |
| `EVENT_KEY_STATE_UNKNOWN_FILE`          | Das State-Verzeichnis enthält einen unbekannten Eintrag.                            |

### Mutation-Lease und Recovery

| Reason Code                            | Bedeutung                                                                      |
| -------------------------------------- | ------------------------------------------------------------------------------ |
| `EVENT_KEY_MUTATION_LOCKED`            | Eine andere oder verwaiste Mutation-Lease blockiert den Store.                 |
| `EVENT_KEY_MUTATION_LOCK_INVALID`      | Locktyp, Rechte, Größe, Schema, Kanonisierung oder Symlinkgrenze ist ungültig. |
| `EVENT_KEY_MUTATION_LOCK_IO_FAILED`    | Anlage oder Durability der Mutation-Lease kann nicht bewiesen werden.          |
| `EVENT_KEY_MUTATION_LOCK_ACTIVE`       | Explizite Recovery trifft eine noch lebende Eigentümer-PID.                    |
| `EVENT_KEY_MUTATION_LEASE_LOST`        | Der gehaltene Lock fehlt oder sein Token stimmt nicht mehr.                    |
| `EVENT_KEY_MUTATION_RECOVERY_REQUIRED` | Eine eng benannte Event-Temporärdatei verlangt explizite Offline-Recovery.     |
| `EVENT_KEY_MUTATION_RECOVERY_FAILED`   | Temp-Bereinigung oder anschließende Directory-Durability schlägt fehl.         |
| `EVENT_KEY_EVENT_TEMP_INVALID`         | Eine Event-Temporärdatei verletzt Name, Typ, Rechte oder Größengrenze.         |

### Legacy-Adoption und Rotation

| Reason Code                          | Bedeutung                                                                            |
| ------------------------------------ | ------------------------------------------------------------------------------------ |
| `EVENT_KEY_LEGACY_ADOPTION_REQUIRED` | Events ohne State dürfen nicht automatisch als Fresh Store übernommen werden.        |
| `EVENT_KEY_LEGACY_EVENTS_REQUIRED`   | Explizite Adoption wurde ohne vorhandene Legacy-Events aufgerufen.                   |
| `EVENT_KEY_LEGACY_INVALID`           | Mindestens eine Legacy-Datei, Hülle, Version oder Authentisierung ist ungültig.      |
| `EVENT_KEY_LEGACY_CHANGED`           | Die Legacy-Dateiliste änderte sich während der Adoption.                             |
| `EVENT_KEY_ROTATION_INPUT_INVALID`   | Das Rotationsobjekt enthält ungültige Versionen, Extras, Symbole oder Accessors.     |
| `EVENT_KEY_ROTATION_STALE`           | `--expected` beziehungsweise die erwartete aktive Version entspricht nicht dem Head. |
| `EVENT_KEY_ROTATION_NON_MONOTONIC`   | Die nächste Version ist nicht exakt die aktuelle Version plus eins.                  |
| `EVENT_KEY_ROTATION_CONFLICT`        | Eine andere Operation hat den endgültigen Revisionsnamen zuerst committed.           |
| `EVENT_KEY_ROTATION_COMMIT_INVALID`  | Der nach dem Commit erneut geladene Head entspricht nicht dem erwarteten Record.     |

### Event Store und Produktgrenzen

| Reason Code                            | Bedeutung                                                                                       |
| -------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `EVENT_DIRECTORY_INVALID`              | Das Eventverzeichnis ist ungültig.                                                              |
| `EVENT_ID_INVALID`                     | Eine Event-ID verletzt das geschlossene Dateinamenschema.                                       |
| `EVENT_PATH_INVALID`                   | Ein Read-Pfad liegt außerhalb des Stores oder besitzt keinen gültigen Eventnamen.               |
| `EVENT_ENVELOPE_INVALID`               | Datei, Größe, Schema, Base64, Nonce, Tag oder Version der Hülle ist ungültig.                   |
| `EVENT_ENVELOPE_TOO_LARGE`             | Eine neue serialisierte Hülle überschreitet 4 MiB und wird vor Dateianlage blockiert.           |
| `EVENT_KEY_VERSION_INVALID`            | Eine Version liegt außerhalb `1..10_000` oder ist kein positiver Safe Integer.                  |
| `EVENT_READABLE_KEY_VERSIONS_INVALID`  | Die Liste lesbarer Versionen ist nicht streng, eindeutig oder enthält die aktive Version nicht. |
| `EVENT_KEY_VERSION_NOT_READABLE`       | Eine formal gültige Hüllenversion wurde im Lifecycle nicht aktiviert.                           |
| `EVENT_INTEGRITY_FAILED`               | AES-GCM-Authentisierung oder Entschlüsselung schlägt fehl.                                      |
| `EVENT_PLAINTEXT_INVALID`              | Entschlüsselter Inhalt ist kein zulässiger JSON-Wert.                                           |
| `EVENT_KEY_ADMIN_USAGE_INVALID`        | Admin-Befehl oder explizites Bestätigungsflag ist ungültig.                                     |
| `EVENT_KEY_MIN_VERSION_CONFIG_INVALID` | Die Produktkonfiguration der Mindestversion ist ungültig.                                       |
| `SIMULATION_EVENT_SECRET_UNAVAILABLE`  | Die Simulation fasst Lifecycle- und Secret-Fehler vor Fachmutation fail-closed zusammen.        |

Unerwartete interne Fehler werden an den App-Grenzen nicht mit möglicherweise
sensitiven Details ausgegeben, sondern als `INTERNAL_SECURITY_ERROR`
zusammengefasst.

## Bewusst nicht implementiert

- automatische Erzeugung oder Provisionierung von Event-Keys;
- Klartext-, Datei- oder Umgebungsvariablen-Fallback für Schlüsselmaterial;
- Re-Key oder Umschreiben bestehender Eventhüllen;
- automatische Löschung oder Retirement alter Keychain-Einträge;
- automatisches Überspringen fehlender historischer Schlüssel;
- automatische Bereinigung oder Recovery beliebiger temporärer Artefakte;
- allgemeiner Active-active-Mehrprozessbetrieb außerhalb der geschützten
  Event-Mutationen und Online-Rotation bei laufendem Dashboard;
- externe Plattformadapter, reale Zielhosts, Report-Einreichung oder
  LLM-gesteuerte Requests.
