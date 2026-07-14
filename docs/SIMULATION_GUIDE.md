# Phase-2-Simulationsleitfaden

Die Simulation ist ein reproduzierbarer, rein lokaler Produktdurchstich. Sie benutzt In-Process-Mocks und optionale Loopback-Server, aber weder reale Plattformen noch externe Ziele.

## Einmalige Keychain-Voraussetzung

Produktive Dashboard- und CLI-Läufe benötigen den exakt 32 Byte langen Schlüssel unter `keychain://bugbounty-copilot/event-store-v1`:

```sh
security add-generic-password -U -s bugbounty-copilot -a event-store-v1 -w "$(openssl rand -base64 24)"
export BUGBOUNTY_EVENT_KEY_MIN_VERSION=1
```

Der Wert wird nicht in der Control Plane gespeichert. Fehlen, Lesefehler oder falsche Länge blockieren vor jeder Simulationsfachdaten-Mutation; vorbereitende Verzeichnis- und Schema-Erstellung kann bereits erfolgt sein. Tests injizieren ausschließlich einen In-Memory-Testschlüssel und beweisen diesen fail-closed Preflight; der Produktpfad besitzt keinen Fallback.

`BUGBOUNTY_EVENT_KEY_MIN_VERSION` ist verpflichtend und besitzt keinen
Default. Die Phase-2-CLI verwendet pro Lauf ein neues, zufälliges lokales
Eventverzeichnis und kann deshalb ausschließlich mit Mindestversion `1`
initialisieren. Das persistente Dashboard verwendet dagegen den zu seinem
authentifizierten Head passenden, nach erfolgreicher Rotation angehobenen
Wert. Fehlende oder ungültige Konfiguration blockiert fail-closed.

Zusätzlich ist eine manuell bereitgestellte Ed25519-Operator-Credential nötig:

```sh
security add-generic-password -U -s bugbounty-copilot -a operator-ed25519-v1 -T /usr/bin/security -X "$(openssl genpkey -algorithm ED25519 -outform DER 2>/dev/null | xxd -p -c 256)"
export BUGBOUNTY_OPERATOR_KEY_REFERENCE=keychain://bugbounty-copilot/operator-ed25519-v1
export BUGBOUNTY_OPERATOR_ID=local-reviewer
export BUGBOUNTY_OPERATOR_KEY_REVISION=1
```

Die drei Umgebungsvariablen enthalten nur Referenz, Operator-ID und Revision,
niemals Schlüsselmaterial. Die CLI verlangt alle drei Werte und einen lesbaren
PKCS#8-Schlüssel; Dashboard und CLI besitzen keinen Klartext-Fallback.

## CLI

```sh
pnpm phase2:simulate --confirm-local-simulation
```

Ohne `--confirm-local-simulation` wird der Lauf abgelehnt. Zusätzlich ist ein echtes interaktives TTY erforderlich; ein Non-TTY-Aufruf endet vor Anlage von `.local`. Die CLI zeigt zuerst Policy v1/v2, Diff, vollständige Kampagnenverträge, Approval-Digests und den Review-Digest. Danach fragt sie Actor und alle sechs Kontrollpunkte nacheinander ab. Nur die exakte Eingabe `yes` wird angenommen; jede andere Eingabe bricht sofort ab. Das Flag ist ausdrücklich keine Sammelfreigabe und keine rechtliche oder Plattformzustimmung.

## Dashboard

```sh
pnpm dashboard
```

Danach `http://127.0.0.1:4173` öffnen, die sechs Kontrollpunkte einzeln bestätigen und „Simulation starten“ wählen.

## Event-Key-Verhalten

Der Orchestrator authentifiziert oder initialisiert den Event-Key-Lifecycle
vor der ersten nicht sicherheitsgerichteten Control-Plane-Mutation. Neue
Events werden ausschließlich mit dem aktivierten Head geschrieben; alte
Hüllen sind nur über die in der authentifizierten State-Chain aktivierten
historischen Versionen lesbar. Alle historischen Schlüssel müssen deshalb im
Keychain verfügbar bleiben.

Init und Event-Writes halten für den vollständigen Refresh-/Commit-Bereich
eine verzeichnisweite Mutation-Lease. Eine fremde oder nach Abbruch
verbliebene Lease sowie Event-Temporärdateien blockieren. Recovery und Rotation
sind ausschließlich explizite lokale Offline-Adminschritte für den persistenten
Dashboard-Store; die Simulation löst sie nicht aus. Es gibt kein automatisches
Re-Keying, keine automatische Löschung alter Keys und keinen Dashboard-,
HTTP-, Browser-, Modell- oder External-Action-Pfad zur Rotation.

## Reproduzierbare 18 Schritte

1. Mock-Programm importieren.
2. Policy v1 anzeigen.
3. Policy v1 ausdrücklich lokal akzeptieren.
4. Kampagnenvertrag erstellen.
5. Kampagne ausdrücklich freigeben.
6. Owner-, Member- und External-Testidentitäten erzeugen.
7. Mock-Testorganisation erzeugen.
8. eigene Mock-Testobjekte mit Canaries erzeugen.
9. Ownership Ledger aktualisieren und Bindungen prüfen.
10. drei AES-256-GCM-verschlüsselte lokale Ereignisse erfassen.
11. Policy Drift simulieren.
12. laufende Kampagne automatisch pausieren.
13. Policy-Diff v1 zu v2 anzeigen.
14. Policy v2 ausdrücklich akzeptieren.
15. Kampagne erneut freigeben und Simulation fortsetzen.
16. lokalen Report-Entwurf erzeugen.
17. Report-Sammelfreigabe in die Approval Queue stellen.
18. bestätigen, dass keine externe Einreichung ausgeführt wurde.

Schritt 6 materialisiert ausschließlich vorautorisierte, checkpoint-freie Owner-/Member-/External-Fixtures in der lokalen Demo. Es wird keine Registrierung, E-Mail-Aktion, CAPTCHA-, TOTP-, Regel-, Bedingungs- oder Rechtserklärung dargestellt oder automatisch erfüllt. Sobald ein Account-Plan einen solchen Checkpoint enthält, bleibt der separate Account-Workflow pausiert.

## Erwartetes Ergebnis

Der Abschluss meldet `mode: simulation`, `externalIntegrationsEnabled: false`, `networkConnections: 0`, `externalSubmissions: 0`, zwei Policy-Versionen, drei Identitäten, ein kontrolliertes Objekt, drei versioniert verschlüsselte Events, einen offenen Report-Kontrollpunkt und genau 18 Schritte.

Ein während des Ablaufs aktivierter, unlesbarer oder audit-/revisionsinkonsistenter Kill Switch bricht vor dem nächsten Schritt geschlossen ab und pausiert aktive Kampagnen. Er verhindert außerdem Kampagnenstart, Resume, Freigabeverarbeitung und Runner-Aufrufe. Jede lokale Policy-/Kampagnenentscheidung wird zum tatsächlichen Laufzeitpunkt frisch signiert; die zuvor erfassten menschlichen Bestätigungszeiten bleiben separat im hashgebundenen Approval-Payload erhalten. Der External-Action-Evaluator revalidiert persistierte Signatur-Evidence vor Reservation, Start und Settlement. Der einzige Runner bleibt ein deterministischer In-Process-Mock ohne Netzwerktransport.
