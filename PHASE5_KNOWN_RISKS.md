# Phase 5: Bekannte Restrisiken und bewusste Grenzen

## Die Mindestversion ist ein separat zu erhaltender Rollback-Anker

`minimumActiveKeyVersion` ist in allen Produktkompositionen verpflichtend und
besitzt keinen Default. Ein fehlender oder ungültiger Wert sowie ein
authentisierter Head unterhalb dieser Mindestversion blockieren fail-closed.
Nach einer erfolgreichen Rotation muss der Betreiber den Wert auf die neue
aktive Version anheben und getrennt vom Event-Store erhalten.

Die HMAC-verketteten State-Records erkennen Löschung oder Manipulation nur
relativ zum vorgefundenen Head und zur separat erhaltenen Mindestversion. Ein
privilegierter Angreifer, der Eventverzeichnis, vollständige State-Chain,
Keychain-Zustand und Mindestversionskonfiguration gemeinsam auf einen früheren
konsistenten Snapshot zurücksetzt, kann nicht erkannt werden. Das vollständige
Dateisystem- und Konfigurationsrollback bleibt Teil der Trusted Computing
Base. Phase 5 implementiert keinen hardwaregestützten monotonen Zähler und
keinen externen Transparenzanker.

## Lokaler OS-Account, Dateisystem und Keychain bleiben vertrauenswürdig

Der Produktpfad bezieht Event-Keys ausschließlich über
`MacOSKeychainSecretStore`. Es gibt keinen Klartext-, Datei- oder Environment-
Key-Fallback. Trotzdem bleiben der lokale OS-Account, Keychain-ACLs, der feste
`keyReference(version)`-Callback, Prozessintegrität, Verzeichnisrechte sowie
die Hardlink- und `fsync`-Semantik des lokalen Dateisystems Teil der TCB.

Ein privilegierter lokaler Angreifer kann Prozesse, Konfiguration oder
Keychainzugriffe beeinflussen. Netzwerkdateisysteme, ungewöhnliche
Dateisystemsemantik, Backups mit abweichenden Rechten und kompromittierte
lokale Administratoren sind nicht qualifiziert.

## Mutation-Lease und PID-Erkennung sind lokale Fail-Closed-Grenzen

Initialisierung, Adoption, Event-Write und Rotation werden durch die private
Datei `.event-key-mutation.lock` pro Eventverzeichnis serialisiert. Ein Crash
kann diese Lease absichtlich stehen lassen; weitere Operationen blockieren
dann, statt sie automatisch zu übernehmen. Das ist kein allgemeines
Distributed-Lock-Protokoll.

Die explizite Recovery prüft die im Lock gespeicherte PID mit der lokalen
OS-Prozesssicht. PID-Wiederverwendung, PID-Namespaces oder fehlende
Berechtigung zur Liveness-Prüfung können eine tatsächlich verwaiste Lease als
aktiv erscheinen lassen. Das führt konservativ zu einem dauerhaften Block und
erfordert lokale Untersuchung; eine fremde oder laufende Lease wird nicht
automatisch gelöscht.

## Recovery ist ausdrücklich, offline und kein Authentisierungsbeweis

`recover-stale-mutation --confirm-local-stale-event-key-recovery` darf nur bei
beendetem Dashboard und gestoppten Schreibern ausgeführt werden. Der
Bestätigungsparameter verhindert versehentliche Aufrufe, ist aber weder eine
Operator-Signatur noch ein Nachweis menschlicher Anwesenheit oder rechtlicher
Zustimmung. Wer den lokalen OS-Account und den Prozess kontrolliert, gehört zur
TCB.

Die Recovery entfernt nur streng benannte, private, reguläre und
größenbegrenzte Event-Temporärdateien unter der geprüften Lease. Sie
rekonstruiert keine Events, errät keinen Commitstatus und repariert keine
State-Chain. Unklare Artefakte und aktive PIDs blockieren. Eine gleichzeitige
manuelle Recovery und ein noch laufender, aber falsch als beendet bewerteter
Writer bleiben eine lokale Betriebsgefahr.

## State- und Event-Temporärdateien können Eingriffe erfordern

Ein Crash vor dem atomaren Link kann eine streng geformte State-Temporärdatei
zurücklassen. Sie wird niemals als Head aktiviert und nicht automatisch
gelöscht. Ein korrekt benanntes, reguläres, privates und größenbegrenztes
State-Temp wird ignoriert; abweichende State-Artefakte blockieren. Forensische
Prüfung und gegebenenfalls manuelle Offline-Bereinigung bleiben
Betreiberaufgabe.

Eine zurückgelassene Event-Temporärdatei blockiert Reads und Mutationen mit
Recovery-Bedarf. Nur die ausdrückliche Offline-Recovery darf das enge bekannte
Temp-Format entfernen. Unbekannte Dateien, Symlinks, falsche Rechte oder
übergroße Artefakte werden nicht bereinigt.

## Historische Schlüssel bleiben zwingend erforderlich

Die Strategie lautet `write new -> read explicitly activated old`. Beim Open
werden alle seit Genesis aktivierten Key-Versionen benötigt, um die State-
Chain zu authentisieren, Schlüsselwiederverwendung zu erkennen und alte Events
zu lesen. Ein fehlender, falsch langer oder doppelter historischer Key
blockiert den gesamten Lifecycle; es gibt keinen partiellen Read-, Write-only-
oder Klartextbetrieb.

Phase 5 verschlüsselt bestehende Hüllen nicht neu und löscht oder retired alte
Keychain-Einträge nicht. Dadurch wächst der zu erhaltende Schlüsselsatz mit
jeder Rotation. Sichere Backup-, Restore-, Escrow-, Retirement- und
kompromissbedingte Re-Key-Verfahren bleiben offen.

## Kein allgemeiner Active-active- oder Mehrprozessbetrieb

Die Mutation-Lease schließt lokale Write-/Rotate-Races auf einem qualifizierten
Dateisystem und derselben Prozesssicht. Reads blockieren während einer fremden
Mutation. Nicht qualifiziert sind jedoch allgemeiner Active-active-Betrieb,
Lock-Fairness und -Starvation, lange Hänger, Prozess- oder Containergrenzen,
Netzwerkdateisysteme sowie Crash-Konsistenz auf ungewöhnlichen Dateisystemen.

Phase 5 härtet nicht den Mehrprozessbetrieb von Approval Queue, Control Plane,
Kill Switch oder Audit Log. Die separate Crash-/Restart-Qualifikation dieser
Komponenten bleibt einer späteren Phase vorbehalten.

## Bewusst keine automatische Rotation, Wiederherstellung oder Migration

Event-Key-Initialisierung, Legacy-v1-Adoption, Rotation und Recovery sind
ausschließlich explizite lokale Adminvorgänge. Kein Dashboard-, HTTP-, Browser-,
Modell- oder External-Action-Pfad kann sie auslösen. Keys werden weder erzeugt
noch automatisch provisioniert. Legacy-Adoption akzeptiert nur vollständig
authentifizierte v1-Events; ein einzelner unbekannter oder manipulierter
Eintrag blockiert.

Es gibt keine automatische Rotation nach Zeit oder Nutzung, kein Überspringen
fehlender Schlüssel, kein automatisches Re-Key, keine automatische Key-Löschung
und keine universelle Repair-Funktion. Diese Grenzen vermeiden stille
Datenverluste, erzeugen aber bewussten Betriebsaufwand.

## Restrisiken aus Phase 4 bleiben bestehen

Phase 5 verändert die signierte Operator- und External-Action-Grenze nicht.
Insbesondere bleiben die in `PHASE4_KNOWN_RISKS.md` dokumentierten Grenzen:

- Operator-Enrollment ist lokales TOFU und beweist Schlüsselbesitz, nicht
  Identität, Hardwarebindung oder menschliche Anwesenheit;
- Operator-Key-Rotation, Widerruf, Recovery, Emergency-Reenrollment,
  Mehrpersonenfreigabe und Quorum fehlen;
- das rohe SQLite-Handle, privilegierter Code im selben Prozess und injizierte
  Clock-Capabilities gehören zur TCB;
- System-Wall-Clock, macOS-Keychain, lokales Provisioning und Shell bleiben
  Vertrauensannahmen;
- `node:sqlite` ist experimentell und allgemeiner Mehrprozessbetrieb der
  Control Plane ist nicht qualifiziert;
- Crash-Reservationen bleiben blockierend und werden weder automatisch
  erstattet noch geerntet;
- der globale Runtime-Grenzwert ist kein versionierter, operator-signierter
  Budgetvertrag, und Store-Capabilities sind noch nicht durch eine gemeinsame
  unverfälschbare Capability-ID formal gleichgesetzt.

Keine dieser Grenzen wird durch eine erfolgreiche Event-Key-Rotation,
Operator-Signatur oder lokale Approval aufgehoben.

## Bewusst deaktivierte oder zurückgestellte Funktionen

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
- automatische Event-Key-Erzeugung, Re-Keying, Löschung, Escrow und
  universelle Crash-Recovery;
- allgemeiner Active-active-Mehrprozessbetrieb.

Die fünf simulationsfähigen Registry-Actions erreichen ausschließlich den
deterministischen In-Process-Mock. `report_submit` und
`triage_response_send` bleiben auch im Simulationsmodus nicht ausführbar.

## Lokale Sicherheitsgrenze

Produkt-, Netzwerk- und Browsertests verwenden ausschließlich In-Process-
Mocks oder Loopback-Adressen. Ein kompromittierter lokaler Rechner wird durch
Phase 5 nicht abgesichert. Während Entwicklung und Tests wurde kein realer
Plattform- oder Bug-Bounty-Host kontaktiert.
