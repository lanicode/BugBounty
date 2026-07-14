# Phase 3: Bekannte Restrisiken und bewusste Grenzen

## Operatorlabel ist nicht authentifiziert oder signiert

Phase 3 bindet `operator_ref`, Approval-Entscheider, Policy-Annehmer und
Kampagnenfreigeber durch exakte Stringgleichheit. Das verhindert versehentliche
oder inkonsistente Freigabekombinationen, beweist aber nicht, welche reale
Person den String gesetzt hat. Es gibt noch keine lokale Operator-
Authentifizierung, OS-gebundene Session, Signatur, Hardwarebindung oder
Nichtabstreitbarkeit.

Ein Prozess mit ausreichendem Control-Plane-Zugriff kann daher ein syntaktisch
gültiges Operatorlabel verwenden. Vor jedem realen Adapter sind eine lokal
authentifizierte Operatoridentität und kryptografisch signierte Approvals
zwingend. Reale Adapter bleiben bis dahin deaktiviert.

## Rohes Datenbank-Handle gehört zur Trusted Computing Base

WeakSet-Branding und exakte Prototypprüfung verhindern, dass ein Caller einen
Store oder Evaluator mit einem strukturellen Fake, Proxy oder Prototype-Spoof
freigibt. Ein echtes `ControlPlaneDatabase`-Objekt stellt seinen Besitzern aber
weiterhin die generischen Methoden `run`, `get`, `all` und `transaction` zur
Verfügung. Code mit diesem Handle gehört damit ausdrücklich zur Trusted
Computing Base.

SQLite-Constraints und Trigger blockieren viele direkte Manipulationen,
insbesondere Updates/Deletes an Auditzeilen, Approval-Bindings und Attempts.
Sie bilden jedoch keine Prozess-Sandbox: Der Append-Pfad für Auditzeilen muss
offen bleiben, und andere zulässige SQL-Mutationen sind mit dem rohen Handle
möglich. Vor realen Wirkungen sollte die Datenbankfähigkeit in schmalere Read-,
Decision- und Reservation-Capabilities geteilt und aus untrusted
Kompositionspfaden entfernt werden.

## SQLite-Laufzeit und Mehrprozessbetrieb

Die Control Plane nutzt das in Node.js 24 enthaltene `node:sqlite`, das von
Node weiterhin als experimentell gekennzeichnet wird. `BEGIN IMMEDIATE`,
Foreign Keys, `STRICT`-Tabellen, `trusted_schema=OFF`, `synchronous=FULL`,
defensive Optionen und deaktiviertes Extension Loading bilden eine
konservative lokale Grenze.

Getestet ist der synchrone Single-Process-Betrieb einschließlich Schließen und
Wiederöffnen einer Datei. Mehrere Prozesse, konkurrierende unabhängige
Node-Laufzeiten, Lock-Starvation, Netzwerkdateisysteme und Crash-Konsistenz auf
ungewöhnlichen Dateisystemen sind nicht qualifiziert. Die Datenbank sollte nur
in einem vom lokalen Benutzer kontrollierten Verzeichnis und nicht über ein
Netzlaufwerk betrieben werden.

## Crash-Reservation benötigt Recovery

Ein normal abgefangener Fehler zwischen Reservation und Runner-Start wird als
`aborted` Revision `1` persistiert. Stürzt der Prozess nach dem atomaren
Reservation-Commit ab, bevor dieser Catch-Pfad läuft, bleibt der Attempt
absichtlich `reserved`; ein Crash nach Start bleibt `running`. Beide Zustände
zählen weiterhin gegen Replay, Gesamtbudget, Kampagnenbudget, Rolling Rate und
aktive Concurrency.

Dieses Verhalten ist fail-closed, kann aber weitere lokale Simulationen
dauerhaft blockieren. Es gibt noch keine signierte Recovery-Entscheidung,
Lease, Heartbeat, Reaper-Logik oder menschlich kontrollierte Auflösung einer
verwaisten Reservation. Ein künftiger Recovery-Pfad darf niemals automatisch
Budget erstatten oder Replay freigeben.

## Audit ist immutable, aber noch nicht authentifiziert

Migration v4 blockiert Update und Delete für `control_plane_audit`; Binding-,
Reservation- und Settlement-Datensätze referenzieren bodyfreie Audit-Evidence
über IDs und Digests. Die SQLite-Audit-Tabelle ist jedoch weder signiert noch
hashverkettet und teilt dieselbe lokale Vertrauensdomäne wie das rohe
Datenbank-Handle. Ihre Immutability schützt gegen nachträgliche SQL-Änderung,
nicht gegen einen bereits privilegierten Writer, der neue, formal passende
Zeilen einfügt.

Das hashverkettete Phase-1-Audit-Log ist davon getrennt und wurde in Phase 3
nicht verändert. Vor realen Actions müssen Operatorentscheidung und relevante
Control-Plane-Audits kryptografisch authentifiziert werden.

## Laufzeitbudget-Grenze ist nicht selbst persistiert

Attempts und damit Nutzung, Replay und aktive Reservationen bleiben über
Store- und Prozessneustarts erhalten. Das globale Limit
`max_actions_total` wird jedoch beim Bau jeder Pipeline aus dem aktuellen
Phase-2-Runtime-State geliefert und nicht als versionierter Budgetvertrag in
SQLite gebunden. Der Wert wird zwar fail-closed auf eine sichere Ganzzahl von 1
bis 1.000 geprüft und `max_concurrency` muss exakt `1` sein; ein privilegierter
Kompositionspfad könnte später dennoch ein höheres gültiges Gesamtlimit
bereitstellen.

Der Kampagnenvertrag begrenzt parallel `maxRequests`, `requestsPerMinute` und
Concurrency. Vor realen Adaptern sollte auch der globale Budgetvertrag
persistiert, versioniert, operatorgebunden und in den Evidence-Digest
aufgenommen werden.

## Systemuhr ist eine lokale Vertrauensannahme

Der Evaluator verwendet normalisierte UTC-Zeitstempel aus `Date.now()`. Ein
Rücksprung vor den global jüngsten `reserved_at` wird blockiert; Start und
Settlement werden ebenfalls monoton zu ihren Attempt-Zeitpunkten erzwungen.
Approval-Ablauf, Kampagnenfenster und Rolling-Rate-Fenster hängen trotzdem von
der lokalen Wall Clock ab. Ein privilegierter Vorwärtssprung kann Fristen
vorzeitig auslaufen lassen und ein später korrigierter Rücksprung den Betrieb
blockieren.

Es gibt noch keine vertrauenswürdige monotone Uhr oder signierte Zeitquelle.
Das aktuelle Verhalten ist auf Blockieren statt automatische Reparatur
ausgelegt.

## Kill-Switch-Reader und Evidence-Store sind nicht capability-gleichgesetzt

`Phase2KillSwitch` ist echt gebrandet, eingefroren und erfasst seinen Reader
descriptor-sicher. Die vorgesehene Komposition liest denselben
`ControlPlaneStore`, den auch der `StoreBoundExternalActionEvaluator` nutzt.
Die Pipeline beweist aber noch nicht über eine gemeinsame Capability-ID, dass
beide Objekte tatsächlich an dieselbe Store-Instanz gebunden wurden.

Der Evidence-Store prüft den persistierten Kill Switch vor Reservation, Start
und erfolgreichem Settlement erneut. Eine absichtlich falsch komponierte
Reader-Funktion könnte einen bereits laufenden lokalen Mock trotzdem erst beim
Settlement stoppen, statt dessen Abort-Signal sofort auszulösen. Reale Runner
bleiben deaktiviert; vor ihrer Einführung muss der Kill-Switch-Reader
untrennbar an dieselbe gebrandete Store-Capability gebunden werden.

## Key-Rotation und Wiederherstellung sind zurückgestellt

Phase 3 speichert keine Secrets oder Eventdaten und verändert den Phase-1-
Secret-/Event-Store nicht. Der Produktionsschlüssel für verschlüsselte
Eventhüllen stammt weiterhin ausschließlich aus dem macOS-Keychain-Adapter; es
gibt keinen Klartext-Fallback.

Ein Verfahren für Schlüsselrotation, Wiederherstellung, Re-Keying vorhandener
Hüllen und kontrollierten Wiederanlauf fehlt weiterhin. Diese Arbeit ist vor
einem langlebigen produktiven Betrieb erforderlich, aber nicht Teil des
store-gebundenen Evaluators.

## Branding ist keine Sandbox

Gefrorene Instanzen, Konstruktoren und Prototypen sowie private WeakSet-Marken
schützen die vorgesehene JavaScript-Komposition gegen Caller-Booleans,
Callback-Fakes, Proxies und Prototype-Spoofs. Sie schützen nicht gegen
beliebigen Code, der bereits im selben Prozess mit Modul-, Datenbank- oder
Dateisystemprivilegien läuft. Neue Plugins oder dynamisch geladener Code dürfen
daher nicht in die Trusted Computing Base aufgenommen werden, ohne die Grenze
neu zu prüfen.

## Bewusst deaktivierte Funktionen

- Externer Modus und alle realen Plattformadapter;
- HackerOne-, Bugcrowd- oder andere Bug-Bounty-Plattformverbindungen;
- echte Accounts, E-Mail-, TOTP-, CAPTCHA- oder Browser-Session-Automation;
- aktive Sicherheitstests und beliebige Zielrequests;
- Report-Einreichung und Triage-Nachrichten;
- LLM-gesteuerte HTTP- oder Browserrequests;
- nicht-null Payload-Referenzen für External Actions;
- automatische Zustimmung zu Regeln, Bedingungen, rechtlichen Erklärungen
  oder menschlichen Checkpoints;
- automatische Crash-Recovery oder Budgeterstattung.

Die fünf simulationsfähigen Registry-Aktionen erreichen nur den
deterministischen In-Process-Mock. `report_submit` und
`triage_response_send` bleiben selbst im Simulationsmodus nicht ausführbar.

## Lokale Sicherheitsgrenze

Die Registry enthält für simulationsfähige Aktionen ausschließlich das feste
Loopback-Metadatum `http://127.0.0.1`; der aktuelle Mock-Runner öffnet jedoch
keine Netzwerkverbindung. Der lokale Einzeloperator, sein OS-Account, die
Repository- und Datenbankdateien sowie die Systemuhr bleiben Teil der
Vertrauensannahme. Ein kompromittierter lokaler Rechner wird durch Phase 3
nicht abgesichert.

Während Entwicklung und Tests von Phase 3 wurde kein realer Plattform- oder
Bug-Bounty-Host kontaktiert.
