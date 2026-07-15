# HackerOne – macOS-Keychain-Setup

## Zweck und feste Referenzen

Der aktuell implementierte HackerOne-Read-only-Adapter verwendet ein
API-Identifier-/API-Token-Paar für Basic Auth. Bug Bounty Copilot verwaltet
beide ausschließlich im macOS-Schlüsselbund. Gibt das Plattformkonto nur ein
einzelnes Token ohne separaten Identifier aus, ist dieses Credentialformat
mit dem aktuellen Adapter nicht kompatibel und bleibt fail-closed; niemals
einen Identifier raten oder einen Platzhalter speichern.

| Wert           | Referenz                                                | Keychain Service    | Account                    |
| -------------- | ------------------------------------------------------- | ------------------- | -------------------------- |
| API-Identifier | `keychain://bugbounty-copilot/hackerone-api-identifier` | `bugbounty-copilot` | `hackerone-api-identifier` |
| API-Token      | `keychain://bugbounty-copilot/hackerone-api-token`      | `bugbounty-copilot` | `hackerone-api-token`      |

Die Einträge enthalten kanonische, versionierte, rollen- und
generation-gebundene Credential-Hüllen. Sie dürfen nicht manuell als rohe
Passwortwerte angelegt oder bearbeitet werden. Nur zwei Hüllen derselben
zufälligen Generation gelten als vollständiges Paar.

Credentials gehören niemals in `.env`-Dateien, Shell-History,
Prozessargumente, Git, Codex-Nachrichten, GitHub, Tickets, Logs oder
Screenshots. Das Dashboard nimmt sie nur über das dafür bestimmte lokale
Einmalformular und die feste Binärroute entgegen; JSON, Browser-Storage und
Logpersistenz sind dafür verboten.

## Voraussetzungen

- macOS mit Apple Command Line Tools (`/usr/bin/xcrun` und `clang`);
- Repository-Abhängigkeiten installiert;
- private lokale Control-Plane unter
  `.local/dashboard/control-plane.sqlite` eingerichtet;
- sicher gestartetes, ausschließlich an `127.0.0.1` gebundenes Dashboard für
  den UI-Weg;
- für den alternativen TTY-Weg ein interaktives lokales Terminal; bei TTY-
  `store` oder TTY-`remove` sollte der getrennte Dashboardprozess beendet
  sein, weil der CLI-Prozess keinen fremden In-Process-Request signalisieren
  kann.

Die drei alternativen CLI-Unterbefehle `store`, `status` und `remove` sind
TTY-gebunden.
Weiterleitung aus einer Datei, Pipe, CI, Hintergrundjob oder nicht
interaktivem Codex-Prozess wird mit `HACKERONE_MANUAL_TTY_REQUIRED`
abgewiesen.

Der feste native Keychain-Helfer wird beim ersten Credentialzugriff aus der
versionierten C-Quelldatei lokal kompiliert. Das Binärprogramm und sein
Quell- und Binärdigest liegen nur im privaten Verzeichnis `.local/native`
(Modus `0700`/`0600`). Vor jeder Operation werden Eigentümer, Modus,
Hardlinkzahl, Quelldigest und tatsächlicher Binärdigest erneut geprüft. Die
Kompilierung verwendet eine private Kopie der zuvor gehashten Quelle und eine
minimale Umgebung. Es gibt keinen Download und keinen
`/usr/bin/security -w`-Promptfallback. Fehlende Toolchain, falsche
Dateirechte, Symlinks, Digestabweichungen, Kompilierfehler oder eine nicht
interaktiv erlaubte Keychainoperation blockieren fail-closed.

## Credentials über das lokale Dashboard speichern

Das Formular **Credentials lokal speichern** ist der einmalige lokale
UI-Pfad. Beide Felder sind Password-Inputs mit deaktivierter Browser-
Autovervollständigung. Nach dem Klick werden ihre DOM-Werte sofort geleert.
Der Client kodiert jeden Wert als 1 bis 3.000 druckbare ASCII-Bytes und baut
dieses Frame:

```text
H1CR | Version 1 | Identifier-Länge uint16 BE | Token-Länge uint16 BE
| Identifierbytes | Tokenbytes
```

Die maximal 6.009 Bytes gehen ausschließlich als
`application/octet-stream` an
`POST /api/hackerone/credentials/store` auf demselben Loopback-Origin. Die
Route verlangt vor dem Lesen exakten Origin, CSRF, Content-Type und eine
vorhandene, kanonische, exakt passende `Content-Length`. Falsche Magic,
Version, Länge, Zeichenklasse oder Übergröße blockiert. Erfolgs- und
Fehlerantworten reflektieren keine Credentialwerte.

Client und Server nullen alle kontrollierten Identifier-, Token-, Frame-,
Chunk- und Payloadbuffer nach Abschluss. Es gibt keinen JSON-Body, kein
`localStorage`, kein `sessionStorage` und keine Logausgabe. Browserstrings
können in einer Garbage-Collected Runtime dennoch nicht garantiert physisch
aus dem Heap gelöscht werden; verwende deshalb nur den privaten lokalen
Arbeitsplatz und schließe den Tab nach der Ablage.

Der Service abortiert eine laufende Operation noch vor dem ersten Storezugriff,
deaktiviert einen aktiven Adapter danach persistent und wartet auf Quieszenz,
bevor der Keychain-Write beginnt. Speichern aktiviert die Integration nie
automatisch.

Die rein lokale Credential-Ablage und -Löschung sind auch in der
`local_setup_shell` verfügbar. Das richtet noch keine externe Capability ein:
Aktivierung, Verbindungstest, Synchronisierung, Auswahl, Bindung und
Policy-Annahme bleiben bis zu einem vollständig bereiten Security-Core
serverseitig blockiert.

## Alternative: Credentials im TTY speichern

Starte im Repository:

```sh
pnpm hackerone:credentials store
```

Der Befehl fragt nacheinander verborgen ab:

```text
HackerOne API-Identifier:
HackerOne API-Token:
```

Bei der Eingabe erscheinen weder Klartext noch Maskierungszeichen. Die Werte
werden nicht über argv oder Environment übergeben. Steuerzeichen,
nicht druckbare Bytes, leere Werte und Werte oberhalb der festen Grenze
werden blockiert.

Vor dem Schreiben wird ein aktivierter persistenter HackerOne-Adapter
deaktiviert; dieser Übergang erhöht seine Generation. Anschließend:

1. liest der TTY-Pfad Identifier und Token in begrenzte Bytebuffer;
2. der Vault erzeugt eine gemeinsame zufällige 16-Byte-Generation;
3. jede Secretseite erhält die kanonische, vollständig druckbare Hülle
   `BBC-H1-CRED-V1.<Rolle>.<Generation>.<Secret>`; Rolle `i`/`t`, 16-Byte-
   Generation und Secret sind ungepaddet Base64url-kodiert;
4. der feste native Helfer erhält die Hülle einmal über eine begrenzte
   stdin-Pipe, niemals als Prozessargument oder Environmentwert;
5. der Helfer deaktiviert Core Dumps und Keychain-UI, sperrt Secretbuffer im
   Speicher und akzeptiert nur `read|store|delete` für die zwei festen Rollen
   sowie bei `store` ausschließlich eine kanonische rollenpassende Hülle;
6. der Vault liest beide gespeicherten Hüllen über denselben Helfer zurück und
   prüft Rolle, gemeinsame neue Generation sowie die vollständigen Identifier-
   und Token-Digests;
7. temporäre TTY-, Hüllen-, stdin-, stdout- und Keychainbuffer werden genullt;
8. erst nach erfolgreichem Readback wird das zwölfstellige SHA-256-
   Fingerprint-Präfix des persistierten Tokens ausgegeben.

Schlägt ein Schreibvorgang fehl, versucht der Vault beide festen Einträge zu
löschen und meldet nur `HACKERONE_KEYCHAIN_WRITE_FAILED`. Es gibt keinen
Klartext-, Datei-, SQLite-, Environment- oder In-Memory-Produktionsfallback.

Padding, fremde Zeichen, nicht kanonische Restbits, falsche Rolle oder Magic
blockieren. Eine durch parallele Prozesse gemischte oder partielle
Paarversion wird bei `probe` und `load` nicht akzeptiert. Das ist absichtlich
fail-closed; führe `remove` und anschließend `store` erneut aus.

## Status ohne Secret-Ausgabe prüfen

```sh
pnpm hackerone:credentials status
```

Die Ausgabe enthält ausschließlich:

- `Identifier vorhanden: ja/nein`
- `Token vorhanden: ja/nein`
- `Token-Fingerprint: <12 Hexzeichen>/nicht verfügbar`

Der Status gibt nie Identifier, Token, Keychain-Hülle oder vollständigen
Digest aus. Eine partielle, beschädigte, rollenfalsche oder
generationsgemischte Paarung erscheint nicht als vorhandenes Credential-Paar.
Gelesene Keychain-Buffer werden nach der Prüfung genullt.

Das Dashboard zeigt dieselben Paar-Präsenzindikatoren, den kurzen
Fingerprint und den letzten erfolgreichen Verbindungstest. Vollständige
Secretwerte werden nur beim bewussten einmaligen Binär-Write vom lokalen
Formular zum Loopbackprozess übertragen; Status, State-Projektion und Logs
enthalten sie nie. Intern wird für Aktivierung und Requestbindung der volle
64-stellige SHA-256-Token-Digest verwendet, niemals das zwölfstellige
Anzeigepräfix.

## Integration nach dem Speichern aktivieren

Credential-Speicherung ist keine Aktivierung. Nach jedem `store`:

1. starte beziehungsweise aktualisiere die sichere lokale Anwendung;
2. prüfe, dass beide externen Runtime-Schalter exakt `true` sind;
3. gib den globalen Kill Switch über den bestehenden signierten
   Operatorworkflow frei;
4. wähle im Dashboard **Read-only-Integration aktivieren**;
5. prüfe, dass eine neue signierte Aktivierung für den aktuellen intern
   vollständigen Token-Binding-Digest und die aktuelle Adaptergeneration
   akzeptiert wurde;
6. starte erst dann bewusst den Verbindungstest.

Eine alte Aktivierung gilt nach Credential-Mutation nicht mehr. Die
Aktivierung erlaubt ausschließlich `HACKERONE_METADATA_READ` zur festen
offiziellen API und niemals Zielrequests oder Report-Einreichungen.

## Rotation

1. Erzeuge den Ersatz-Token außerhalb dieses Produkts in deinem persönlichen
   HackerOne-Konto.
2. Speichere Identifier und neuen Token über das lokale Einmalformular. Wenn
   du stattdessen den TTY-Befehl verwendest, beende vorher den Dashboardprozess
   und führe `pnpm hackerone:credentials store` aus. Beide Wege deaktivieren
   vor der Mutation.
3. Prüfe im Dashboard oder mit `pnpm hackerone:credentials status`, dass ein
   vollständiges Paar
   vorhanden ist und der Fingerprint sich wie erwartet geändert hat.
4. Gib den globalen Kill Switch
   signiert frei und erzeuge eine neue signierte Read-only-Aktivierung.
5. Führe den eng begrenzten Verbindungstest aus.
6. Prüfe den redigierten Status und den Zeitpunkt der letzten erfolgreichen
   Prüfung.
7. Widerrufe den alten Token über HackerOne erst nach deiner eigenen
   Betriebsprüfung.

Die festen Keychain-Einträge werden ausschließlich über den lokal kompilierten
Helfer aktualisiert. Es gibt keine lokale Liste alter Tokens und keine
automatische Rückkehr zum vorherigen Secret. Ein fehlgeschlagener Write oder
Readback kann beide Einträge entfernen.

Bei einem bereits vorhandenen alten Eintrag setzt der Helfer vor jeder
Inhaltsänderung seine explizite Ein-Helfer-ACL. Kann macOS diese ACL ohne
Interaktion nicht sicher setzen, bleibt der neue Inhalt ungeschrieben und der
Vorgang schlägt fail-closed fehl. Alte, manuell oder mit anderen Werkzeugen
angelegte rohe Einträge sind kein unterstützter Fallback; entferne sie über
den festen `remove`-Pfad und speichere das Paar anschließend neu.

Kann auch `remove` den fremden Alt-ACL-Eintrag nicht ohne macOS-Interaktion
löschen, beende zuerst Dashboard und Credential-CLI. Lösche dann in der
lokalen **Schlüsselbundverwaltung** ausschließlich die beiden Einträge des
Dienstes `bugbounty-copilot` mit den Accounts `hackerone-api-identifier` und
`hackerone-api-token`. Alternativ ist dieser feste Delete-only-Recoveryweg
möglich:

```sh
/usr/bin/security delete-generic-password \
  -s bugbounty-copilot -a hackerone-api-identifier
/usr/bin/security delete-generic-password \
  -s bugbounty-copilot -a hackerone-api-token
```

Die Befehle enthalten bewusst weder `-w` noch einen Read-Schritt: Werte werden
nicht gelesen, kopiert oder ausgegeben. Bestätige gegebenenfalls nur den
lokalen macOS-Löschdialog und speichere anschließend das vollständige Paar
neu. Verwende diesen Recoveryweg nicht für Event- oder Operator-Key-Einträge.

Die lokale native Regression lässt sich ohne Plattform- oder Zielkontakt mit
ausschließlich zufällig benannten synthetischen Keychain-Einträgen ausführen:

```sh
pnpm test:native
```

Sie prüft Contractgrenzen sowie Store, Read, Delete, ACL-Migration oder
unverändertes Fail-closed-Verhalten und die Grenzen 4.095/4.096 Bytes. Die
synthetischen Einträge werden am Ende wieder entfernt.

## Credentials entfernen

Im Loopback-Dashboard kann **Credentials entfernen** verwendet werden. Der
Service abortiert vor dem ersten Storezugriff, persistiert danach die
Deaktivierung, wartet auf Quieszenz und löscht dann beide festen
Keychain-Einträge. Die Route nimmt selbst keine Secretwerte entgegen.

Alternativer TTY-Adminweg:

```sh
pnpm hackerone:credentials remove
```

Beende das Dashboard vor diesem TTY-Weg. Der separate Adminprozess kann einen
bereits gestarteten Transport in einem anderen Prozess nicht aktiv
signalisieren.

Der TTY-Befehl deaktiviert zuerst einen noch aktiven Adapter; dieser Übergang
erhöht dessen Generation. Anschließend versucht er beide festen
Keychain-Einträge zu löschen.

Prüfe danach mit:

```sh
pnpm hackerone:credentials status
```

Wenn nur einer der Löschvorgänge gelingt, lautet das Ergebnis
`HACKERONE_KEYCHAIN_DELETE_FAILED`. Das teilweise Paar bleibt unbrauchbar und
die Capability deaktiviert. Wiederhole `remove`; gib niemals Keychainwerte
zur Diagnose auf stdout aus.

Das Entfernen löscht keine lokal normalisierten Programme, Policies,
Snapshots, Acceptance-Evidence oder Auditereignisse. Diese bleiben offline
lesbar. Pilot Readiness A besitzt bewusst keinen Purge-/Retentionworkflow.

## Fehlercodes

| Code                                   | Bedeutung und sichere Reaktion                                              |
| -------------------------------------- | --------------------------------------------------------------------------- |
| `HACKERONE_CREDENTIAL_COMMAND_INVALID` | nur exakt `store`, `status` oder `remove` verwenden                         |
| `HACKERONE_MANUAL_TTY_REQUIRED`        | ausschließlich selbst in einem interaktiven lokalen Terminal starten        |
| `HACKERONE_CREDENTIAL_INPUT_INVALID`   | Eingabe leer, zu groß oder enthält unzulässige Bytes; neu beginnen          |
| `HACKERONE_TTY_INPUT_INVALID`          | uneindeutiger oder zusätzlicher TTY-Frame; neu beginnen                     |
| `HACKERONE_TTY_INPUT_ABORTED`          | Eingabe mit `Ctrl-C` abgebrochen                                            |
| `HACKERONE_SECRET_STORE_UNAVAILABLE`   | macOS-Keychain fehlt, ist unlesbar oder das Paar ist ungültig/gemischt      |
| `HACKERONE_KEYCHAIN_WRITE_FAILED`      | mindestens ein Write fehlgeschlagen; Cleanup beider Einträge wurde versucht |
| `HACKERONE_KEYCHAIN_DELETE_FAILED`     | mindestens ein Delete fehlgeschlagen; Paar bleibt unbrauchbar               |
| `HACKERONE_KEYCHAIN_HELPER_FAILED`     | nativer Helfer fehlt, ist untrusted oder lehnt die feste Operation ab       |
| `HACKERONE_KEYCHAIN_HELPER_TIMEOUT`    | nativer Helfer antwortete nicht innerhalb der festen Deadline               |

## Plattformgrenze

Der produktive Credentialpfad ist macOS-spezifisch. Auf anderen Plattformen
bleibt die Integration mit `HACKERONE_SECRET_STORE_UNAVAILABLE` deaktiviert.
In-Memory-Backends und synthetische Credential-Paare existieren
ausschließlich in Tests und sind kein Produktionsfallback.
