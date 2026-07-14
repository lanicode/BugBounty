# Bug Bounty Copilot – lokal nutzbares Phase-8-Produkt

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

Phase 8 verbindet Control Plane, Dashboard und Demo-SaaS zu einer gemeinsam
startbaren lokalen Anwendung. Ein geschlossener 21-Schritte-Assistent führt
ohne manuelle YAML-, JSON-, SQLite- oder Quellcodebearbeitung von der
Einrichtung bis zur ausschließlich lokalen Reportprüfung. Programme, Policies,
Kampagnen, Identitäten, Journey, Inventory, Kandidat und Evidence werden dabei
ehrlich als flüchtige, deterministische Demo-Projektionen gekennzeichnet. Der
produktneutrale Katalog `packages/local-journey-catalog` ist mit ID und Digest
gepinnt; ausschließlich der getrennte Phase-7-Browserharness führt ihn mit
Playwright aus. Das Produkt projiziert nur Katalogmetadaten und startet keinen
Browser. Identitäten, kontrolliertes Objekt, Canary-Digest und Demo-Policy
werden aus einer exakt validierten, digestgebundenen Demo-SaaS-Projektion
übernommen. Laufzeitdrift entwertet Evidence und Report fail-closed.

Die Anwendung ist weiterhin **kein Live-Scanner**. Sie führt keine aktiven Sicherheitstests aus, erstellt keine realen Konten, besitzt keine funktionsfähige Plattformintegration und reicht keine Reports ein. Sämtliche Demonstrationen laufen deterministisch gegen In-Process-Mocks oder Loopback-Server. Externe Integrationen sind standardmäßig, bei fehlender oder fehlerhafter Konfiguration und bei Laufzeitfehlern deaktiviert.

## Lokal starten

Für den normalen lokalen Demoablauf sind nur Installation und Start nötig:

```sh
pnpm install --frozen-lockfile
pnpm app
```

Danach ist das Dashboard standardmäßig unter
[http://127.0.0.1:4173](http://127.0.0.1:4173) erreichbar. Ist dieser lokale
Port belegt, verwendet die Anwendung einen ausgegebenen ephemeren
Loopback-Port. Die Demo-SaaS bindet ebenfalls an einen beim Start ausgegebenen
ephemeren Loopback-Port. Fehlende
Kryptografie-Konfiguration verhindert den UI-Start nicht: Die Anwendung läuft
dann als `local_setup_shell`; der Event Store wird nicht konstruiert, der Kill
Switch bleibt aktiv und alle positiven persistenten Core-Routen sind
serverseitig gesperrt. Bei vollständig validierter Keychain- und
Operator-Konfiguration lautet der Modus `local_simulation`; der verschlüsselte
Event Store wird erst bei Bedarf sicher geöffnet. Es existiert kein In-Memory-
oder Klartext-Secret-Fallback.

### Optional: signierten 18-Schritte-Control-Plane-Lauf freischalten

Voraussetzungen sind macOS, Node.js 24 oder neuer und pnpm 11. Dieser
fortgeschrittene Pfad ist nicht für den Phase-8-Guided-Flow erforderlich. Er
benötigt einen separat und offline bereitgestellten, exakt 32 Byte langen
Event-Schlüssel im macOS-Schlüsselbund. Dieses Repository dokumentiert
bewusst keinen Secret-tragenden Shell-Einzeiler: Schlüsselmaterial darf weder
als expandiertes Prozessargument noch in Shell-Historie, Skript, Log,
Umgebungsvariable oder Repository erscheinen. Die Provisionierung muss einer
separat geprüften lokalen Keychain-Betriebsanweisung folgen.

`BUGBOUNTY_EVENT_KEY_MIN_VERSION` ist ein verpflichtender, store-spezifischer
Rollback-Anker ohne Default für verschlüsselte Eventaktionen. Fehlende oder
ungültige Konfiguration blockiert diese Aktionen, Simulations-CLI und
Event-Key-Admin fail-closed; die read-only Oberfläche und der flüchtige
Phase-8-Demoablauf bleiben verfügbar. Ein frischer Store beginnt mit `1`.

Zusätzlich wird einmalig eine Ed25519-PKCS#8-Credential direkt im
macOS-Schlüsselbund bereitgestellt. Auch hierfür gilt die separat geprüfte
Offline-Provisionierung ohne Secret-tragende Kommandozeilenargumente.

Nur nicht geheime Metadaten werden der Anwendung übergeben:

```sh
export BUGBOUNTY_EVENT_KEY_MIN_VERSION=1
export BUGBOUNTY_OPERATOR_KEY_REFERENCE=keychain://bugbounty-copilot/operator-ed25519-v1
export BUGBOUNTY_OPERATOR_ID=local-reviewer
export BUGBOUNTY_OPERATOR_KEY_REVISION=1
```

Es gibt keine automatische Schlüsselbereitstellung, Schlüsseldatei oder
Klartext-/Umgebungsvariablen-Fallback für das private Schlüsselmaterial. Ohne
vollständige Konfiguration bleiben signierte Simulation, positive
Approval-Entscheidungen und Kill-Clear gesperrt. Die CLI bricht vollständig
ab; das Dashboard zeigt den Setupzustand und den sicheren lokalen Demoablauf.

```sh
pnpm app
```

Danach die im Terminal ausgegebene Dashboard-URL öffnen. Sie zeigt dauerhaft
**SIMULATIONSMODUS**, **EXTERNE INTEGRATIONEN DEAKTIVIERT** und **KEINE REALE
REPORT-EINREICHUNG** an. Die
Simulation verlangt sechs einzeln zeitgestempelte lokale Bestätigungen; der
globale Kill Switch ist bei einer neuen Datenbank und bei jedem
Dashboard-Start aktiv.

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
- `packages/local-runtime`: redigierte, fail-closed Runtime-Readiness ohne I/O.
- `packages/local-product`: deterministischer, flüchtiger 21-Schritte-
  Präsentationsworkflow ohne Netzwerk-, Browser- oder Secretzugriff.
- `packages/local-journey-catalog`: produktneutrale, I/O-freie Quelle des
  gepinnten Journey-Profils für Produktprojektion und Phase-7-Testharness.
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

Bedienung und Grenzen stehen in `docs/FIRST_RUN_GUIDE.md`,
`docs/USER_GUIDE.md`, `docs/PILOT_READINESS.md` und
`docs/LOCAL_DASHBOARD_GUIDE.md`. Die signierte Operatorgrenze ist in
`docs/PHASE4_SIGNED_OPERATOR_APPROVALS.md`, der Event-Key-Lifecycle in
`docs/PHASE5_EVENT_KEY_LIFECYCLE.md`, die lokale Recovery-Semantik in
`docs/PHASE6_CONTROL_PLANE_RECOVERY.md` und der geschlossene Browserharness in
`docs/PHASE7_LOCAL_BROWSER_JOURNEYS.md` beschrieben. Der vollständige
Phase-7-Nachweis steht in `PHASE7_COMPLETION_REPORT.md`.
