# Phase-3-Änderungen am Sicherheitskern

## Baselines

Phase-2-Baseline:

```text
307344353ec3a0bcfc04a3f409c6dc4815df349b
```

Phase-1-Baseline:

```text
0f0f508765ebec663c2d09dc22fa408c1de46a4f
```

Die Phase-2-Baseline ist zusätzlich in `docs/PHASE2_BASELINE.md` fixiert.

## Phase-1-Pfaddiff

Der kontrollierte Pfaddiff von der Phase-1-Baseline bis zum aktuellen
Phase-3-Stand ist für alle geschützten Phase-1-Pfade leer:

```text
packages/config
packages/egress-guard
packages/redaction
packages/secret-store
packages/event-store
packages/policy
packages/audit-log
packages/recorder
packages/shared
apps/cli
```

Verwendete Prüfung:

```text
git diff --name-only 0f0f508765ebec663c2d09dc22fa408c1de46a4f..HEAD -- packages/config packages/egress-guard packages/redaction packages/secret-store packages/event-store packages/policy packages/audit-log packages/recorder packages/shared apps/cli
```

Die Ausgabe ist leer. Phase 3 verändert den Phase-1-Sicherheitskern nicht.

## Ausdrücklich als Phase-3-Security-Core markierte Änderungen

Die folgenden Änderungen betreffen die Sicherheitsgrenze der Phase-2-Control-
Plane beziehungsweise die einzige External-Action-Pipeline und sind deshalb
ausdrücklich **Phase-3-Security-Core-Änderungen**.

### Persistierte Control-Plane-Evidence und Reservationen

Commit `d9463fd` (`feat(control-plane): persist phase 3 action evidence and
reservations`):

- `packages/control-plane/database.ts`
  - Migration v4 ergänzt `external_action` als Approval-Art.
  - Neue `STRICT`-Tabellen speichern immutable Approval-Bindings und
    single-use Attempts.
  - Exakte Foreign Keys, Null-Konsistenz, Digestformate, Eindeutigkeit und
    Zustandsübergänge werden in SQLite erzwungen.
  - Control-Plane-Auditzeilen sind gegen Update und Delete geschützt.
  - Die Migration engagiert den globalen Kill Switch und pausiert aktive oder
    genehmigte Kampagnen.
  - Datenbankinstanzen erhalten eine private `WeakSet`-Marke und eine exakte
    Prototypprüfung.
  - Synchrone Transaktionen verwenden `BEGIN IMMEDIATE`; Promise- und
    Thenable-Ergebnisse lösen Rollback aus.
- `packages/control-plane/external-action-evidence.ts`
  - Kanonische Digests für Kampagne, Identität, Ownership, Scope, Approval-
    Binding und vollständige Authorization-Evidence.
  - Exakter Proposal-zu-Store-Kontextvergleich.
- `packages/control-plane/external-action-store.ts`
  - Aktuelle Policy-, Scope-, Account-, Objekt-, Operator- und Auditprüfung.
  - Atomare Approval-Erzeugung, Autorisierung und Reservation.
  - Persistenter Replay-, Gesamt-, Kampagnen-, Rate-, Concurrency- und
    Clock-Rollback-Schutz.
  - Revalidierung vor Runner-Start und vor erfolgreichem Settlement.
  - Fail-closed Attempt-Zustandsmaschine und bodyfreie Settlement-Audits.
- `packages/control-plane/store.ts`
  - Einbindung des Evidence-Stores in den bestehenden Control-Plane-Store.
  - Atomare Verknüpfung akzeptierter External-Action-Approvals mit ihrer
    Decision-Audit-ID.
  - Store-Branding und exakte Datenbank-Vertrauensprüfung.
- `packages/control-plane/types.ts` und `packages/control-plane/index.ts`
  - `external_action` sowie die typisierten Binding-/Attempt-Datensätze werden
    ergänzt und exportiert.

Diese Änderungen waren zwingend erforderlich, weil der Phase-2-Evaluator
positive Gate-Booleans noch nicht aus persistierter, aktueller und
operatorgebundener Evidence ableitete.

### Proposal v2 und store-gebundene Runner-Freigabe

Commits `d9463fd` und `8acaadd` (`feat(external-actions): require store-bound
action decisions`):

- `packages/external-actions/proposal.schema.json` und
  `packages/external-actions/proposal.ts`
  - Geschlossener Proposal-v2-Vertrag mit Kampagnenrevision/-digest, Policy,
    Scope, Accountrolle, Objekt, Approval und Operator.
  - Exakte Plain-Object-/Descriptor-Prüfung, Proxy-Abwehr, defensive Kopie,
    Freeze und kanonischer Proposal-Digest.
- `packages/external-actions/pipeline.ts` und
  `packages/external-actions/index.ts`
  - Positive Entscheidungen können nur noch über einen gebrandeten
    `StoreBoundExternalActionEvaluator` entstehen.
  - Ohne Evaluator gilt Deny-All; Callback-, Proxy- und Prototype-Spoofs
    blockieren vor dem Runner.
  - Runtime-Budget, externer Modus, Registry-Ziel, Ownership-Referenzen,
    Payload, Runner und Kill Switch werden fail-closed geprüft.
  - Reservation, Start, Runner, Abbruch und Settlement sind an die persistierte
    Evidence gebunden.
  - Runner, Evaluator, Kill Switch, Pipeline, Konstruktoren und Prototypen sind
    eingefroren beziehungsweise privat gebrandet.

Der frühere Phase-2-Simulations-Evaluator mit caller-gelieferten positiven
Booleans ist kein Freigabepfad mehr.

## Zugehörige Regressionstests

Commit `5d3a283` (`test: verify phase 3 fail-closed action evaluation`) und die
direkten Tests aus `d9463fd` decken die Security-Core-Änderungen ab:

- `tests/unit/control-plane/database.test.ts`
  - Migration, exakte Tabellenspalten, Foreign Keys, Approval-/Attempt-
    Immutability, Audit-Immutability, Zustandsübergänge, Datenbank-Branding und
    Rollback asynchroner Transaktionen.
- `tests/unit/external-action-proposal.test.ts`
  - alle Proposal-v2-Felder, Digestbindung, Zusatzfelder, Accessors, Proxies,
    Prototypen und Freeze.
- `tests/unit/store-bound-external-actions.test.ts`
  - aktuelle Persistenz-Evidence, Operatorbindung, Deny-All, Branding,
    Replay, Budget und deaktivierte reale Aktionen.
- `tests/unit/external-actions.test.ts`
  - Registry, Reihenfolge, unbekannte/gesperrte Aktionen, Runner-/Authorizer-
    Spoofing, externe Modi und Kill-Switch-Regressionen.
- `tests/property/store-bound-evaluator.property.test.ts`
  - generierte Proposal-Mutationen und Schreibversuche auf immutable
    Approval-Bindings.
- `tests/integration/store-bound-external-action.test.ts`
  - SQLite-Reopen, persistentes Replay/Gesamtbudget, globale Concurrency,
    Rolling Rate, Clock Rollback, Drift und Crash-Reservation.
- `tests/integration/external-action-kill-switch.test.ts`
  - Kill vor Reservation, Pre-Start-Abbruch, laufender Abort, Audit-
    Manipulationsversuch und Datenbank-Lesefehler.
- `tests/unit/external-actions-import-boundary.test.ts`
  - statische Abwesenheit von HTTP-, Browser-, DNS-, Socket-, Child-Process-
    und LLM-Transportimports im External-Action-Pfad.

Es wurde keine bestehende Sicherheitsprüfung deaktiviert oder gelockert. Phase
3 ergänzt keine neue Abhängigkeit.

## Bewusst unveränderte Grenzen

- Der Phase-1-Egress-, Redaction-, Secret-Store-, Event-Store-, Policy- und
  Audit-Log-Code bleibt unverändert.
- Reale Adapter bleiben deaktiviert und ohne Transport.
- `external_integrations_enabled` bleibt effektiv `false`.
- Das persistierte Operatorlabel ist noch nicht authentifiziert oder signiert.
- Crash-Recovery, Mehrprozessfreigabe und Key-Rotation sind zurückgestellt und
  in `PHASE3_KNOWN_RISKS.md` dokumentiert.

Während der Implementierung dieser Änderungen wurde kein realer Plattform-
oder Bug-Bounty-Host als Testziel verwendet.
