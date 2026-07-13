# Bug-Bounty-Copilot v2 – Phase-1-Sicherheitskern

Der deterministische Phase-1-Kern ist unter `packages/` implementiert. Er validiert und hasht Programmpolicies, blockiert Egress vor dem Request, redigiert vor jeder Persistierung, verschlüsselt lokale Events und verifiziert Audit-Hashketten. Er enthält absichtlich keinen Live-Recorder, keine aktiven Sicherheitstests und keine Plattform- oder LLM-Integration.

Dieser Blueprint ersetzt den bisherigen Demo-MVP als Zielarchitektur. Er ist absichtlich noch kein autonomer Live-Scanner. Das Ziel ist maximale Automatisierung innerhalb schriftlich autorisierter Programme, eigener Testkonten, eigener Testobjekte und deterministisch erzwungener Grenzen.

## Zielbild

Der Mensch erledigt im Normalbetrieb nur noch:

1. die ausdrückliche Annahme neuer oder geänderter Programmregeln,
2. CAPTCHA/Identitätsprüfungen, wenn eine Plattform sie verlangt,
3. die Freigabe eines Kampagnenvertrags,
4. die Kontrolle eines Datenschutzalarms,
5. optional die finale Sammelfreigabe für Reports.

Alles dazwischen wird automatisiert: Programmsynchronisierung, Policy-Kompilierung, Account-Provisionierung, normale Browserabläufe, datensparsame Aufzeichnung, A/B-Analyse, sichere Verifikation, Beweispaket, Report-Entwurf und Triage-Monitoring.

## Zentrale Sicherheitsarchitektur

```text
Plattform-Adapter -> Policy-Compiler -> Program Registry
                                       |
                                       v
                              Campaign Contract
                                       |
                                       v
Scheduler -> Isolierter Worker -> Egress Guard -> Zielprogramm
                    |                 |
                    |                 +-> Policy Decision Log
                    v
       Redacted Event Store -> Analyzer -> AI Candidate Planner
                                          |
                                          v
                              Schema Validation
                                          |
                                          v
                              Deterministic Verifier
                                          |
                                          v
                              Evidence + Report Adapter
```

Die KI darf Hypothesen und streng strukturierte Testvorschläge erzeugen. Sie erhält weder beliebige Netzwerkrechte noch die Befugnis, Scope, Budgets oder Eigentumsnachweise zu überschreiben.

## Ordner

- `config/program.example.yaml`: Trennung von Testzielen, notwendigen Drittanbietern und blockierten Zielen.
- `config/approval-profile.example.yaml`: Automatisierungsstufen und Risikoklassen.
- `schemas/candidate.schema.json`: Format für KI-Kandidaten.
- `schemas/test-contract.schema.json`: einmalig freizugebender Kampagnenvertrag.
- `policies/scope.rego`: Beispiel für deterministische Freigabeentscheidungen.
- `docs/MVP_AUDIT.md`: Audit des bisherigen MVP.
- `docs/AUTOMATION_MATRIX.md`: Automatisierung aller manuellen Schritte.
- `docs/ROADMAP.md`: sinnvolle Bau-Reihenfolge.
- `docs/PLATFORM_STRATEGY.md`: Plattformstrategie mit HackerOne als erstem Adapter.

## Wichtiger Status

Phase 1 ist eine getestete Sicherheitsgrundlage, aber weiterhin keine Freigabe für reale Ziele. Ownership Ledger, Plattform-Synchronisierung, Accounts und aktive Test-Tiers fehlen bewusst. Bedienung und Grenzen stehen in `docs/PHASE1_OPERATIONS.md`; das Threat Model steht in `docs/THREAT_MODEL.md`.
