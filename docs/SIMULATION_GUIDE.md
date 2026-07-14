# Phase-2-Simulationsleitfaden

Die Simulation ist ein reproduzierbarer, rein lokaler Produktdurchstich. Sie benutzt In-Process-Mocks und optionale Loopback-Server, aber weder reale Plattformen noch externe Ziele.

## Keychain-Voraussetzung nur für den signierten Core-Pfad

Der normale Phase-8-Guided-Flow benötigt keine Credential. `pnpm app` startet
ohne vollständige Kryptografie-Konfiguration als Loopback-
`local_setup_shell`; der Event Store wird nicht konstruiert und positive
persistierende Core-Routen bleiben gesperrt.

Nur CLI und signierter 18-Schritte-Dashboardpfad benötigen einen separat und
offline bereitgestellten, exakt 32 Byte langen Schlüssel unter
`keychain://bugbounty-copilot/event-store-v1`. Dieses Dokument gibt bewusst
keinen Secret-tragenden Shell-Einzeiler vor. Schlüsselmaterial darf nicht als
expandiertes Prozessargument, Shell-Historie, Datei, Log, Skript,
Umgebungsvariable oder Repositoryinhalt erscheinen. Tests injizieren
ausschließlich einen In-Memory-Testschlüssel; der Produktpfad besitzt keinen
Fallback.

`BUGBOUNTY_EVENT_KEY_MIN_VERSION` ist verpflichtend und besitzt keinen
Default. Die Phase-2-CLI verwendet pro Lauf ein neues, zufälliges lokales
Eventverzeichnis und kann deshalb ausschließlich mit Mindestversion `1`
initialisieren. Das persistente Dashboard verwendet dagegen den zu seinem
authentifizierten Head passenden, nach erfolgreicher Rotation angehobenen
Wert. Fehlende oder ungültige Konfiguration blockiert fail-closed.

Zusätzlich ist eine nach derselben geprüften Offline-Betriebsanweisung
bereitgestellte Ed25519-Operator-Credential nötig. Nur nicht geheime Metadaten
werden exportiert:

```sh
export BUGBOUNTY_EVENT_KEY_MIN_VERSION=1
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

Danach die beim Start ausgegebene Dashboard-URL öffnen, die sechs
Kontrollpunkte einzeln bestätigen und „Simulation starten“ wählen.

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
