# Bug Bounty Copilot – lokale Phase-3-Control-Plane

Bug Bounty Copilot ist ein eigenes, lokal betriebenes Produkt für die sichere Vorbereitung künftiger Bug-Bounty-Workflows. Phase 3 bindet die External-Action-Pipeline zusätzlich an atomare, aktuelle und persistierte Policy-, Kampagnen-, Scope-, Ownership-, Budget- und Approval-Evidence. Der Phase-1-Sicherheitskern bleibt unverändert.

Die Anwendung ist weiterhin **kein Live-Scanner**. Sie führt keine aktiven Sicherheitstests aus, erstellt keine realen Konten, besitzt keine funktionsfähige Plattformintegration und reicht keine Reports ein. Sämtliche Demonstrationen laufen deterministisch gegen In-Process-Mocks oder Loopback-Server. Externe Integrationen sind standardmäßig und bei Fehlern deaktiviert.

## Lokal starten

Voraussetzungen sind macOS, Node.js 24 oder neuer und pnpm 11. Der produktive Dashboard- und CLI-Pfad besitzt keinen In-Memory- oder Klartext-Fallback. Vor dem ersten 18-Schritte-Lauf muss deshalb ein zufälliger, exakt 32 Byte langer Event-Schlüssel im macOS-Schlüsselbund liegen:

```sh
security add-generic-password -U -s bugbounty-copilot -a event-store-v1 -w "$(openssl rand -base64 24)"
```

Dieser Befehl gehört zur lokalen Einrichtung und darf nicht in Skripte, Logs oder das Repository übernommen werden. Ein fehlender, nicht lesbarer oder falsch langer Eintrag blockiert die Simulation vor jeder Zustandsänderung.

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

Vorschläge können weder Zielhost noch Secret-Art oder Runner bestimmen. Die zentrale Registry setzt diese Werte. Proposal v2 bindet zusätzlich Kampagnenrevision und -digest, Policy, Scope, Accountrolle, Objekt, Approval und Operator. Positive Entscheidungen entstehen ausschließlich in einer `BEGIN IMMEDIATE`-Transaktion aus aktueller Store-Evidence; Proposal-IDs, Budgets und aktive Reservationen bleiben über Neustarts erhalten. Caller-Booleans, Callback-Gates, Proxies und Prototype-Spoofs können keinen Runner freigeben.

Externe Runner sind nicht implementiert; `external_integrations_enabled` ist immer effektiv `false`. Der gebrandete Kill Switch und der Store blockieren vor, während und nach Runner-Aufrufen sowie bei unlesbarem oder inkonsistentem Zustand. Der einzige ausführbare Runner ist ein deterministischer In-Process-Mock ohne HTTP- oder Browsertransport.

## Hauptkomponenten

- `packages/control-plane`: SQLite-Persistenz, Program Registry, unveränderliche Policies, Kampagnen-, Identitäts- und Freigabe-Zustandsmaschinen.
- `packages/platform-source` und `packages/platform`: strikt lokale Fixtures sowie Mock-Adapter hinter einem eigenen Interface.
- `packages/external-actions`: geschlossene Action Registry, Proposal-v2-Vertrag und store-gebundene deterministische Pipeline.
- `packages/account-simulation` und `packages/ownership-ledger`: rein lokale Account-Lifecycle-Simulation und kryptografisch gebundene Eigentumsnachweise.
- `packages/demo-saas` und `packages/simulation`: lokale Demo-Domäne und reproduzierbarer 18-Schritte-Ablauf.
- `packages/dashboard`: loopback-only HTTP-Control-Plane und Browseroberfläche.
- `packages/config`, `packages/egress-guard`, `packages/redaction`, `packages/secret-store`, `packages/event-store`, `packages/policy` und `packages/audit-log`: unveränderter Phase-1-Sicherheitskern.

Bedienung und Grenzen stehen in `docs/LOCAL_DASHBOARD_GUIDE.md` und `docs/SIMULATION_GUIDE.md`. Die Phase-3-Architektur ist in `docs/PHASE3_STORE_BOUND_EVALUATOR.md` beschrieben; der vollständige Nachweis steht in `PHASE3_COMPLETION_REPORT.md`.
