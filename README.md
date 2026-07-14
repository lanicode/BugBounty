# Bug Bounty Copilot – lokale Phase-7-Browserqualifizierung

Bug Bounty Copilot ist ein eigenes, lokal betriebenes Produkt für die sichere Vorbereitung künftiger Bug-Bounty-Workflows. Phase 3 bindet die External-Action-Pipeline an atomare, aktuelle und persistierte Policy-, Kampagnen-, Scope-, Ownership-, Budget- und Approval-Evidence.

Phase 4 ersetzt freie Operatorlabels durch eine lokal eingeschriebene
Ed25519-Credential. Approval-Entscheidungen und Kill-Switch-Clears benötigen
eine frische, nonce- und sessiongebundene Signatur; Policy-, Kampagnen- und
External-Action-Konsumenten verifizieren diese Evidence erneut. Der
Phase-1-Sicherheitskern bleibt unverändert.

Phase 5 ergänzt einen restart-sicheren, versionierten Event-Key-Lifecycle:
Neue Events verwenden ausschließlich den authentifiziert aktivierten Head,
während alte Hüllen nur mit ausdrücklich aktivierten historischen Versionen
lesbar bleiben. Eine verzeichnisweite Mutation-Lease serialisiert Init,
Legacy-Adoption, Writes und Rotation auch über Prozesse hinweg. Dafür wurde
`packages/event-store` als zwingende **Security-Core-Änderung** gehärtet; die
anderen Phase-1-Komponenten bleiben unverändert.

Phase 6 qualifiziert die lokale SQLite-Control-Plane, den globalen Kill Switch
und das Phase-1-Audit-Log für kontrollierte Prozessabbrüche, Restart und
konkurrierende lokale Prozesse. SQLite prüft Pfad, Rechte, Sidecars,
Durability-Pragmas und Integrität beim Reopen. Kill-Switch-Engagement,
Kampagnenpause und Audit-Fortsetzung besitzen geordnete Commitgrenzen. Das
Audit-Log rehydriert seinen Hashketten-Head unter einer privaten
prozessübergreifenden Lease; verwaiste Leases werden ausschließlich durch
einen expliziten lokalen Offline-Recovery-Schritt entfernt.

Phase 7 ergänzt einen ausschließlich testseitigen Playwright-Testharness gegen
frische Demo-SaaS-Instanzen auf `127.0.0.1`. Owner-, Member- und
External-Profile durchlaufen feste, read-only GET-Graphen zweimal in
umgekehrter Reihenfolge. Jede Navigation passiert vor der ersten Seite den
Phase-1-Egress-Guard und einen zusätzlichen exakten Schritt-Guard. Responses
werden streng projiziert; Screenshot-Evidence verlässt den Prozess nur als
Digest eines vollständig opaken, rollen- und zustandsgebundenen
In-Memory-PNGs. Es existiert weiterhin kein produktiver Browser-Runner.

Die Anwendung ist weiterhin **kein Live-Scanner**. Sie führt keine aktiven Sicherheitstests aus, erstellt keine realen Konten, besitzt keine funktionsfähige Plattformintegration und reicht keine Reports ein. Sämtliche Demonstrationen laufen deterministisch gegen In-Process-Mocks oder Loopback-Server. Externe Integrationen sind standardmäßig, bei fehlender oder fehlerhafter Konfiguration und bei Laufzeitfehlern deaktiviert.

## Lokal starten

Voraussetzungen sind macOS, Node.js 24 oder neuer und pnpm 11. Der produktive Dashboard- und CLI-Pfad besitzt keinen In-Memory- oder Klartext-Fallback. Vor dem ersten 18-Schritte-Lauf muss deshalb ein zufälliger, exakt 32 Byte langer Event-Schlüssel im macOS-Schlüsselbund liegen:

```sh
security add-generic-password -U -s bugbounty-copilot -a event-store-v1 -w "$(openssl rand -base64 24)"
export BUGBOUNTY_EVENT_KEY_MIN_VERSION=1
```

Dieser Befehl gehört zur lokalen Einrichtung und darf nicht in Skripte, Logs oder das Repository übernommen werden. Ein fehlender, nicht lesbarer oder falsch langer Eintrag blockiert die Simulation vor jeder Zustandsänderung.

`BUGBOUNTY_EVENT_KEY_MIN_VERSION` ist ein verpflichtender, store-spezifischer
Rollback-Anker ohne Default. Fehlende oder ungültige Konfiguration blockiert
Dashboard, Simulations-CLI und Event-Key-Admin fail-closed. Ein frischer Store
beginnt mit `1`; nach erfolgreicher Rotation muss der Wert vor dem nächsten
Produktstart auf den ausgegebenen neuen Head angehoben werden.

Zusätzlich wird einmalig ein Ed25519-PKCS#8-Schlüssel direkt im macOS-
Schlüsselbund angelegt. Der folgende Befehl setzt voraus, dass das lokale
`openssl` Ed25519 unterstützt; die erzeugten Schlüsselbytes werden weder
ausgegeben noch in eine Datei geschrieben:

```sh
security add-generic-password -U -s bugbounty-copilot -a operator-ed25519-v1 -T /usr/bin/security -X "$(openssl genpkey -algorithm ED25519 -outform DER 2>/dev/null | xxd -p -c 256)"
```

Nur nicht geheime Metadaten werden der Anwendung übergeben:

```sh
export BUGBOUNTY_OPERATOR_KEY_REFERENCE=keychain://bugbounty-copilot/operator-ed25519-v1
export BUGBOUNTY_OPERATOR_ID=local-reviewer
export BUGBOUNTY_OPERATOR_KEY_REVISION=1
```

Es gibt keine automatische Schlüsselbereitstellung, Schlüsseldatei oder
Klartext-/Umgebungsvariablen-Fallback für das private Schlüsselmaterial. Ohne
vollständige Konfiguration kann das Dashboard nur blockierte Zustände anzeigen
und den Kill Switch aktivieren; Simulation, positive Approval-Entscheidungen
und Kill-Clear bleiben gesperrt. Die CLI bricht vollständig ab.

```sh
pnpm install --frozen-lockfile
pnpm dashboard
```

Danach ist das Dashboard ausschließlich unter [http://127.0.0.1:4173](http://127.0.0.1:4173) erreichbar. Es zeigt dauerhaft **SIMULATIONSMODUS** und **EXTERNE INTEGRATIONEN DEAKTIVIERT** an. Die Simulation verlangt sechs einzeln zeitgestempelte lokale Bestätigungen; der globale Kill Switch ist bei einer neuen Datenbank und bei jedem Dashboard-Start aktiv.

Der vollständige CLI-Ablauf kann separat ausgeführt werden:

```sh
pnpm phase2:simulate --confirm-local-simulation
```

Die CLI benötigt ein interaktives TTY, zeigt zuerst das vollständige digest-gebundene Review-Paket an und akzeptiert an jedem Kontrollpunkt ausschließlich die exakte Eingabe `yes`. Ein Sammel- oder Non-TTY-Fallback existiert nicht.

Die geschlossene Phase-7-Browserqualifizierung läuft separat und benötigt
weder Keychain-Einträge noch Konten oder Browserprofile:

```sh
pnpm test:browser
```

Der Befehl startet nur kurzlebige Server auf `127.0.0.1`, läuft seriell ohne
Retries und deaktiviert automatische Screenshots, Traces, Videos und
Page-Snapshots. Die Details stehen in
`docs/PHASE7_LOCAL_BROWSER_JOURNEYS.md`.

Die rein lokale Event-Key-Administration besitzt einen getrennten CLI-Pfad.
Status, explizite Legacy-v1-Adoption, monotone Rotation und die manuell
bestätigte Recovery einer nach Prozessabbruch verbliebenen Mutation-Lease sind
in `docs/PHASE5_EVENT_KEY_LIFECYCLE.md` beschrieben. Rotation und Recovery
erfolgen nur bei beendetem Dashboard. Weder alte Hüllen noch alte Keychain-
Einträge werden automatisch umgeschrieben oder gelöscht.

Die Control-Plane-Datenbank und das Audit-Log akzeptieren ausschließlich
private lokale Verzeichnisse. Neu angelegte Laufzeitverzeichnisse besitzen
`0700`, Dateien `0600`. Ein bereits vorhandenes Verzeichnis oder eine Datei
mit breiteren Rechten wird nicht automatisch repariert, sondern blockiert bis
zur lokalen Offline-Prüfung. Die Phase-6-Recovery- und Betriebssemantik steht
in `docs/PHASE6_CONTROL_PLANE_RECOVERY.md`.

## Sicherheitsmodell

Jede künftig extern wirksame Aktion muss die folgende technisch erzwungene Kette durchlaufen:

```text
strukturierter Vorschlag
  -> Schema-Validierung
  -> Policy-Entscheidung
  -> Scope-Prüfung
  -> Ownership-Prüfung
  -> Budget-Prüfung
  -> menschlicher Kontrollpunkt
  -> deterministischer Runner
```

Vorschläge können weder Zielhost noch Secret-Art oder Runner bestimmen. Die zentrale Registry setzt diese Werte. Proposal v2 bindet zusätzlich Kampagnenrevision und -digest, Policy, Scope, Accountrolle, Objekt, Approval und Operator. Positive Entscheidungen entstehen ausschließlich in einer `BEGIN IMMEDIATE`-Transaktion aus aktueller Store-Evidence und einer gültigen signierten Operatorentscheidung. Nonces, Credential, Signatur-Evidence, Proposal-IDs, Budgets und aktive Reservationen bleiben über Neustarts erhalten. Caller-Booleans, freie Actor-Strings, Callback-Gates, Proxies und Prototype-Spoofs können keinen Runner freigeben.

Externe Runner sind nicht implementiert; `external_integrations_enabled` ist immer effektiv `false`. Der gebrandete Kill Switch und der Store blockieren vor, während und nach Runner-Aufrufen sowie bei unlesbarem oder inkonsistentem Zustand. Der einzige ausführbare Runner ist ein deterministischer In-Process-Mock ohne HTTP- oder Browsertransport. Der Event-Key-Admin ist ebenfalls rein lokal und weder aus dem Dashboard noch aus einem Modell- oder External-Action-Pfad erreichbar.

## Hauptkomponenten

- `packages/control-plane`: SQLite-Persistenz, Program Registry, unveränderliche Policies, Kampagnen-, Identitäts- und Freigabe-Zustandsmaschinen.
- `packages/platform-source` und `packages/platform`: strikt lokale Fixtures sowie Mock-Adapter hinter einem eigenen Interface.
- `packages/external-actions`: geschlossene Action Registry, Proposal-v2-Vertrag und store-gebundene deterministische Pipeline.
- `packages/operator-auth`: Keychain-geladener Ed25519-Signer, geschlossene
  Enrollment-/Decision-/Kill-Clear-Envelopes und kryptografische Verifikation.
- `packages/event-key-lifecycle`: authentifizierte append-only State-Chain,
  verpflichtender Mindestversionsanker, verzeichnisweite Mutation-Lease und
  explizite lokale Crash-Recovery.
- `packages/account-simulation` und `packages/ownership-ledger`: rein lokale Account-Lifecycle-Simulation und kryptografisch gebundene Eigentumsnachweise.
- `packages/demo-saas` und `packages/simulation`: lokale Demo-Domäne und reproduzierbarer 18-Schritte-Ablauf.
- `packages/dashboard`: loopback-only HTTP-Control-Plane und Browseroberfläche.
- `tests/browser`: ausschließlich testseitiger Playwright-Testharness mit
  geschlossenem Rollen-/Routengraph, exakter Loopback-Policy und minimierter
  Digest-Evidence; kein Produkt- oder External-Action-Runner.
- `packages/event-store`: zwingend geänderter Phase-1-Sicherheitskern mit
  versionierten AES-256-GCM-Hüllen, expliziten Leseversionen,
  Hüllengrößenprüfung vor Dateianlage sowie Datei- und Verzeichnis-`fsync`.
- `packages/audit-log`: zwingend geänderter Phase-1-Sicherheitskern mit
  strikter kanonischer Hashkette, Restart-Rehydration, privater
  Mutation-Lease und expliziter stale-Lease-Recovery.
- `packages/config`, `packages/egress-guard`, `packages/redaction`,
  `packages/secret-store` und `packages/policy`: in Phase 6 unveränderte
  Phase-1-Komponenten.

Bedienung und Grenzen stehen in `docs/LOCAL_DASHBOARD_GUIDE.md` und
`docs/SIMULATION_GUIDE.md`. Die signierte Operatorgrenze ist in
`docs/PHASE4_SIGNED_OPERATOR_APPROVALS.md`, der Event-Key-Lifecycle in
`docs/PHASE5_EVENT_KEY_LIFECYCLE.md`, die lokale Recovery-Semantik in
`docs/PHASE6_CONTROL_PLANE_RECOVERY.md` und der geschlossene Browserharness in
`docs/PHASE7_LOCAL_BROWSER_JOURNEYS.md` beschrieben. Der vollständige
Phase-7-Nachweis steht in `PHASE7_COMPLETION_REPORT.md`.
