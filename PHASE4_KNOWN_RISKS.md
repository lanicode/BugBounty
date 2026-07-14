# Phase 4: Bekannte Restrisiken und bewusste Grenzen

## TOFU beweist Schlüsselbesitz, nicht die reale Person

Das initiale Enrollment ist bewusst lokales Trust On First Use. Die signierte
Enrollment-Probe beweist Besitz des privaten Ed25519-Schlüssels und bindet ihn
an die zufällige Control-Plane-ID. Sie beweist weder Benutzeranwesenheit bei
jeder Signatur noch Hardwarebindung, rechtliche Identität oder
Nichtabstreitbarkeit.

Enrollment ist nur bei aktivem Kill Switch und leerem Credential-Store
möglich. Der lokale OS-Account, der erste Prozess und die macOS-Keychain-
Berechtigung bleiben Teil der Trusted Computing Base.

## Rotation, Widerruf, Recovery und Quorum fehlen

Phase 4 unterstützt genau eine lokale Operator-Credential mit monotoner
Key-Revision. Ein ausformulierter, signierter Ablauf für Rotation, Widerruf,
Verlust, Recovery, Emergency-Reenrollment, Mehrpersonenfreigabe oder Quorum ist
noch nicht implementiert. Es gibt keinen automatischen Ersatzschlüssel.

Ein verlorener oder nicht lesbarer Schlüssel blockiert positive
Entscheidungen und Kill-Clear fail-closed. Kill-Engagement bleibt möglich.

## Rohes Datenbank-Handle und gleicher Prozess gehören zur TCB

SQLite-Constraints und Trigger blockieren unsigned Zustandsübergänge und
nachträgliche Änderungen an Credential- und Signatur-Evidence. Ein Besitzer
des echten rohen `ControlPlaneDatabase`-Handles kann jedoch weiterhin
generische SQL-Operationen ausführen. Er gehört ausdrücklich zur Trusted
Computing Base.

Private Felder, exakte Prototypen, Brands, gefrorene Instanzen und
descriptor-sichere Validierung schützen die vorgesehene JavaScript-
Komposition, aber nicht gegen beliebigen privilegierten Code im selben
Prozess. Dynamische Plugins oder untrusted Module dürfen diese Fähigkeiten
nicht erhalten.

## Lokale Uhr ist eine Vertrauensannahme

Der Store bezieht Zeit aus einer intern gehaltenen Clock-Capability und
persistiert den höchsten verifizierten Zeitpunkt. Rücksprünge, ungültige
Zeitwerte und Clock-Ausnahmen blockieren. Im Produktpfad ist die System-Wall-
Clock dennoch eine lokale Vertrauensannahme. Ein privilegierter Vorwärtssprung
kann Sessions und Freigaben vorzeitig ablaufen lassen; eine spätere Korrektur
blockiert dann fail-closed.

Die optionale Clock-Injektion ist ausschließlich eine Kompositions- und
Testnaht. Code, der sie kontrolliert, gehört zur Trusted Computing Base.

## macOS-Keychain- und Provisioning-Grenze

Der Produktpfad lädt den privaten PKCS#8-Schlüssel ausschließlich über
`MacOSKeychainSecretStore` und eine `keychain://`-Referenz. Der Secret-Store-
Interfacepfad bleibt für isolierte Tests injizierbar; die Produkt-Apps
akzeptieren keinen Datei-, Klartext- oder Environment-Key-Fallback.

Der dokumentierte manuelle Provisioning-Befehl übergibt die kurzlebige
hexadezimale PKCS#8-Repräsentation an das lokale `security`-Werkzeug. Auf einem
kompromittierten Rechner können Prozessargumente, Shellverlauf, Terminal,
Zwischenablage oder Keychain-Berechtigungen offengelegt werden. Das lokale OS,
die Shell und `/usr/bin/security` gehören daher zur TCB. Für langlebige
Produktnutzung sollte eine interaktive Provisioning-Hilfe ohne
Schlüsselmaterial in Argumentlisten folgen.

## SQLite-Laufzeit und Mehrprozessbetrieb

`node:sqlite` ist in Node.js 24 weiterhin experimentell. Qualifiziert ist der
synchrone lokale Single-Process-Betrieb einschließlich Schließen und
Wiederöffnen einer Datei. Mehrere unabhängige Prozesse, Lock-Starvation,
Netzwerkdateisysteme und Crash-Konsistenz auf ungewöhnlichen Dateisystemen sind
nicht qualifiziert.

Die persistierte Clock-Grenze und `BEGIN IMMEDIATE` reduzieren lokale Races,
ersetzen aber keine Mehrprozess-Lease oder Capability-Isolation.

## Crash-Reservationen bleiben absichtlich blockierend

Ein Prozesscrash nach Reservation oder Runner-Start kann weiterhin einen
Attempt in `reserved` oder `running` hinterlassen. Diese Zustände zählen gegen
Replay, Budgets und Concurrency. Es gibt noch keinen signierten Recovery-
Entscheid, Heartbeat, Reaper oder eine automatische Budgeterstattung.

Das Verhalten ist fail-closed, kann aber weitere lokale Simulationen
dauerhaft blockieren. Recovery darf später weder Signaturbindung noch Replay-
Schutz umgehen.

## Budget- und Capability-Grenzen aus Phase 3 bleiben

Das globale Runtime-Gesamtlimit ist validiert, aber noch nicht als
versionierter und operator-signierter Budgetvertrag persistiert. Campaign-
Budgets, Attempts und Nutzung sind persistent. Ein privilegierter
Kompositionspfad könnte aber einen anderen gültigen globalen Grenzwert liefern.

Kill-Switch-Reader und Evidence-Store verwenden in der vorgesehenen
Komposition denselben Store, sind jedoch noch nicht durch eine gemeinsame
unverfälschbare Capability-ID formell gleichgesetzt.

## Event-Key-Rotation fehlt weiterhin

Phase 4 verändert den Phase-1-Secret-/Event-Store nicht. Der Event-Schlüssel
bleibt Keychain-referenziert und ohne Klartext-Fallback. Ein Verfahren für
Rotation, Wiederherstellung, Re-Keying vorhandener Eventhüllen und
kontrollierten Wiederanlauf fehlt weiterhin.

## Bewusst deaktivierte Funktionen

- Externer Modus und alle realen Plattformadapter;
- HackerOne-, Bugcrowd- oder andere Bug-Bounty-Plattformverbindungen;
- echte Tokens, Cookies, Passwörter, TOTP-, E-Mail- oder Browser-Sessions;
- Account-Erstellung außerhalb lokaler Testanwendungen;
- automatische Zustimmung zu Regeln, Bedingungen, rechtlichen Erklärungen
  oder menschlichen Checkpoints;
- CAPTCHA- und Anti-Bot-Umgehung;
- aktive Sicherheitstests und beliebige Zielrequests;
- Report-Einreichung und Triage-Versand;
- LLM-gesteuerte HTTP- oder Browserrequests;
- reale oder generische externe Runner;
- automatische Schlüsselbereitstellung, Klartext-Fallback und generisches
  Signieren beliebiger Daten;
- automatische Crash-Recovery, Budgeterstattung und Mehrprozessbetrieb.

Die fünf simulationsfähigen Registry-Actions erreichen nur den
deterministischen In-Process-Mock. `report_submit` und
`triage_response_send` bleiben auch im Simulationsmodus nicht ausführbar.

## Lokale Sicherheitsgrenze

Produkt-, Netzwerk- und Browsertests verwenden ausschließlich In-Process-
Mocks oder `127.0.0.1`. Ein kompromittierter lokaler Rechner wird durch Phase
4 nicht abgesichert. Während Entwicklung und Tests wurde kein realer
Plattform- oder Bug-Bounty-Host kontaktiert.
