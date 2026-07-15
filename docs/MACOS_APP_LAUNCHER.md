# macOS-App-Launcher

Der lokale Launcher installiert **Bug Bounty Copilot.app** standardmäßig in
`~/Applications`. Danach startet ein Doppelklick die vorhandene lokale
Anwendung ohne sichtbares Terminal und öffnet ausschließlich ihre validierte
Loopback-Dashboard-URL.

## Einmalige Installation

Im Repository müssen Node.js 24 oder neuer und die bereits installierten
Projektabhängigkeiten vorhanden sein. Der Installer lädt nichts aus dem
Internet nach:

```bash
npx --yes pnpm@11.7.0 install --frozen-lockfile
npx --yes pnpm@11.7.0 app:install-macos
```

Anschließend liegt die App unter:

```text
~/Applications/Bug Bounty Copilot.app
```

Sie kann im Finder geöffnet und bei Bedarf in das Dock gezogen werden. Nach
einem Verschieben oder erneuten Klonen des Repositorys muss der Installer im
neuen Repository noch einmal ausgeführt werden.

Der Standardlauncher setzt beide externen Integrationsschalter bei jedem
Start ausdrücklich auf `false`. Für die weiterhin manuell zu aktivierende,
ausschließlich lesende HackerOne-Metadatenintegration kann stattdessen beim
Installieren einmalig der explizite Modus gewählt werden:

```bash
npx --yes pnpm@11.7.0 app:install-macos -- --enable-hackerone-readonly
```

Dieser Modus setzt ausschließlich
`BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED=true` und
`BUGBOUNTY_HACKERONE_READONLY_ENABLED=true`. Er aktiviert den Adapter nicht,
gibt den Kill Switch nicht frei und startet keinen Netzwerkrequest. Die
anschließende signierte Aktivierung und jeder Verbindungstest bleiben
getrennte ausdrückliche Frontendaktionen. Ein erneuter Installerlauf ohne den
Schalter setzt die App wieder auf `local-only`.

Damit ein Finder-Start nach der getrennten lokalen Event-Key- und
Operator-Einrichtung nicht von einer zufällig geerbten Terminalumgebung
abhängt, übernimmt der Installer die vier **nicht geheimen** Core-Metadaten
einmalig in private App-Konfigurationsdateien:

```bash
BUGBOUNTY_EVENT_KEY_MIN_VERSION=1 \
BUGBOUNTY_OPERATOR_KEY_REFERENCE='keychain://bugbounty-copilot/operator-ed25519-v1' \
BUGBOUNTY_OPERATOR_ID='local.admin' \
BUGBOUNTY_OPERATOR_KEY_REVISION=1 \
  npx --yes pnpm@11.7.0 app:install-macos -- --enable-hackerone-readonly
```

Das Beispiel setzt keine Schlüssel. Die Referenz bezeichnet lediglich einen
bereits separat provisionierten Schlüsselbund-Eintrag. Event-Key-Version und
Operator-Revision müssen positive kanonische Dezimalzahlen sein; die
Operator-Referenz, ID und Revision sind nur gemeinsam zulässig. Fehlt die
Event-Key-Angabe, wird sie ausdrücklich als `unset` gespeichert. Fehlt die
gesamte Operator-Dreiergruppe, werden alle drei Werte als `unset` gespeichert
und die Anwendung bleibt im sicheren Setup-Modus. Teilweise oder ungültige
Angaben blockieren bereits den Installer; das reservierte Literal `unset` ist
deshalb kein zulässiger konfigurierter Wert. Echte Event- oder
Operator-Schlüssel werden niemals in der App gespeichert.

Ein anderes absolutes Zielverzeichnis kann als Argument oder über die
Installationsvariable angegeben werden:

```bash
npx --yes pnpm@11.7.0 app:install-macos -- "$HOME/Applications"
BUGBOUNTY_COPILOT_APP_DIR="$HOME/Applications" \
  npx --yes pnpm@11.7.0 app:install-macos
```

## Sicherheitsverhalten

- Die `.app` speichert nur den kanonischen Repository-Pfad, den beim
  Installieren aus `process.execPath` ermittelten kanonischen, ausführbaren
  und nicht symbolisch verlinkten Node-Pfad, den nicht geheimen Modus
  `local-only`/`hackerone-readonly` und die vier oben beschriebenen
  nicht geheimen Referenz-/Versionswerte. Alle Dateien sind nur für den
  aktuellen Benutzer lesbar und werden nie als Shellcode ausgewertet.
- Vor jedem Start werden alle Konfigurationsdateien erneut auf Eigentümer,
  Modus, Einzeiligkeit und kanonisches Format geprüft. Die Anwendung erhält
  eine neu konstruierte Minimalumgebung; geerbte Werte wie `NODE_OPTIONS`,
  `DYLD_*` oder fremde Integrationsschalter werden entfernt. Die beiden
  Integrationsschalter werden immer ausdrücklich aus dem installierten Modus
  gesetzt.
- Der Launcher verwendet ausschließlich das bereits installierte lokale
  `tsx` und den bestehenden Einstieg `apps/dashboard/index.ts`. Er führt beim
  Start weder `npm`, `npx`, `pnpm install` noch einen anderen Download aus.
- Der Browser wird erst geöffnet, nachdem der gestartete Prozess exakt eine
  kanonische URL der Form `http://127.0.0.1:<Port>` gemeldet hat. Hostnamen,
  HTTPS, Benutzerinformationen, Pfade, Querys, Fragmente und privilegierte
  Ports werden blockiert.
- Startausgaben werden nur begrenzt im Arbeitsspeicher bis zur lokalen
  URL-Erkennung verarbeitet, nicht angezeigt und nicht persistiert. Tokens,
  Credentials oder Eventdaten werden vom Launcher weder gelesen noch
  protokolliert.
- Meldet das Dashboard nicht innerhalb von zehn Sekunden seine validierte
  Loopback-URL, wird der Prozess beendet. Eine ausschließlich auf
  `127.0.0.1:43917` gehaltene lokale Lease verhindert parallele Starts; ein
  belegter oder nicht bindbarer Lease-Port blockiert fail-closed.
- Beim Beenden erhält der Dashboard-Kindprozess zunächst `SIGTERM`. Reagiert
  er nicht innerhalb der begrenzten Schonfrist, folgt `SIGKILL`; der Launcher
  wartet auf das Reaping, bevor er die Single-Instance-Lease freigibt.
- Fehlen Repository, Node, `tsx` oder der Dashboard-Einstieg, endet der Start
  fail-closed mit einem generischen lokalen Hinweis. Es gibt keinen
  Klartext-, Download- oder alternativen Netzwerk-Fallback.
- Die bestehende Readiness-, Keychain-, Kill-Switch- und
  External-Integrations-Policy der Anwendung wird nicht verändert. Der
  Launcher verschafft keine zusätzliche Capability.

Der Launcher ist bewusst kein signiertes/distributables macOS-Produktpaket.
Er wird lokal aus dem geprüften Repository installiert und enthält weder
Auto-Updater noch Hintergrunddienst. Solange die App läuft, bleibt der lokale
Node-Prozess aktiv. Das Schließen des Browserfensters beendet ihn nicht und ein
erneuter Doppelklick öffnet die URL bei einer bereits laufenden unsichtbaren
Instanz nicht zuverlässig erneut. Zum vollständigen Beenden in der macOS-
Aktivitätsanzeige den Prozess **BugBountyCopilotLauncher** auswählen und
**Beenden** wählen; der Launcher beendet dann Dashboard und Lease kontrolliert.
Beim Abmelden wird er ebenfalls mit beendet. Ein eigener Menüleisten-/Reopen-
Controller ist in dieser lokalen Alpha noch nicht implementiert.
