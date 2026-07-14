# Phase 6: Bekannte Restrisiken und bewusste Grenzen

## Audit-Hashkette besitzt noch keinen extern erhaltenen Head

Das Audit-Log verifiziert Format, Sequenz, Vorgängerkette und Recordhash vor
jeder Verwendung. Diese Prüfung erkennt interne Lücken oder Manipulationen nur
relativ zur aktuell vorgefundenen Datei. Eine privilegierte lokale Instanz, die
die vollständige Datei auf einen früheren konsistenten Stand zurücksetzt oder
einen vollständigen gültigen Tail entfernt, kann ohne separat erhaltenen
authentisierten Head nicht erkannt werden.

Auch SHA-256 ist hier Integritätsverkettung und keine Authentisierung gegen
einen lokalen Angreifer, der die Datei vollständig neu berechnen kann. Lokaler
OS-Account, Prozess und Dateisystem bleiben Teil der Trusted Computing Base.
Ein transparenter, separat erhaltener Audit-Head ist bewusst zurückgestellt.

## Audit-Mutation-Lease ist eine lokale PID-Grenze

Die exklusive `<audit>.mutation.lock`-Datei serialisiert Append und Verify auf
demselben lokalen Dateisystem und in derselben Prozesssicht. Nach fünf Sekunden
wird Konkurrenz fail-closed blockiert; Fairness und Starvation werden nicht
garantiert.

Explizite Recovery akzeptiert nur `ESRCH` als Beweis, dass die gespeicherte
Owner-PID nicht existiert. PID-Wiederverwendung, PID-Namespaces oder fehlende
Berechtigung zur Liveness-Prüfung können eine tatsächlich verwaiste Lease als
aktiv erscheinen lassen. Das verursacht konservativ einen dauerhaften Block.
Das Protokoll ist kein verteiltes Lock und nicht für Container- oder
Netzwerkdateisystemgrenzen qualifiziert.

## Audit-Teilzeilen werden nicht automatisch repariert

Ein Crash während des Append kann nach Betriebssystem- und Dateisystemsemantik
eine unvollständige letzte Zeile hinterlassen. Die nächste Verifikation
blockiert mit `AUDIT_PARTIAL_RECORD`; die stale Lock-Recovery verifiziert die
Datei ebenfalls und entfernt in diesem Zustand die Lease nicht.

Phase 6 entfernt oder schneidet niemals automatisch Daten ab, weil ohne
zusätzlichen Commitnachweis nicht sicher entschieden werden kann, welche Bytes
beabsichtigt waren. Ein eng spezifizierter Offline-Adminpfad für eine
nachweislich partielle letzte Zeile fehlt. Bis dahin sind forensische Prüfung
und Wiederherstellung aus einem vertrauenswürdigen Backup erforderlich.

## Vollständige Audit-Verifikation ist bewusst begrenzt, aber linear

Jeder Append liest und verifiziert den vollständigen persistierten Log. Das
schließt einen flüchtigen oder stale Head, kostet aber linear Zeit. Die Grenzen
von 16 MiB, 50.000 Records und fünf Sekunden Lock-Wartezeit verhindern
unbeschränkten Ressourcenverbrauch, können bei einem gefüllten Log aber einen
operativen Rotations- oder Archivierungsbedarf erzeugen. Sichere Rotation,
Archivierung und Head-Übernahme sind noch nicht implementiert.

## SQLite, OS und Dateisystem bleiben Teil der TCB

Die Control Plane prüft private Eigentümer-, Rechte-, Typ-, Link- und
Sidecargrenzen und verifiziert ihre Durability-Pragmas. Trotzdem bleiben
`node:sqlite`, die SQLite-Bibliothek, Prozessintegrität, Kernel,
Dateisystemcache, `fsync`-/`fullfsync`-Semantik und physischer Datenträger Teil
der TCB.

Auf macOS werden die root-eigenen Kompatibilitätsaliase `/var` und `/tmp` als
Teil der lokalen OS-TCB akzeptiert, damit kanonische temporäre Pfade
funktionieren. Benutzerkontrollierte oder andere Ancestor-Symlinks blockieren.
Ein kompromittierter Root-Kontext oder konsistenter Austausch aller geprüften
Artefakte wird nicht abgewehrt.

## DELETE-Journal qualifiziert kein Netzwerkdateisystem

File-backed SQLite erzwingt `journal_mode=DELETE`, `synchronous=FULL`,
`fullfsync=ON`, normales Locking und einen begrenzten Busy-Timeout. Die
Prozess- und `SIGKILL`-Tests qualifizieren diese Kombination ausschließlich auf
dem lokalen Testdateisystem. NFS, SMB, FUSE, verteilte Volumes, abweichende
Locksemantik und ungewöhnliche Crash-Persistenz sind nicht freigegeben.

Ein nach Recovery verbleibender nicht-hot `-journal` ist zulässig, muss aber
weiterhin eine private reguläre Einzel-Link-Datei sein. `-wal` und `-shm`
blockieren, da WAL-Betrieb nicht Teil dieser Phase ist.

## Kill-Switch-Versöhnung besitzt eine forensische Auditlücke

Der `ControlPlaneStore` pausiert bei Konstruktion jede noch freigegebene oder
laufende Kampagne, wenn der Kill Switch aktiv ist oder ein gültiger signierter
Clear nicht vollständig bewiesen werden kann. Diese Versöhnung läuft in einer
lokalen `BEGIN IMMEDIATE`-Transaktion und bewegt Zustand nur in Richtung
`engaged`/`paused`.

Der Recovery-Schritt erzeugt bewusst keinen neuen Auditdatensatz. Nach einem
Crash zwischen Engagement und Auditbindung ist der sichere Zustand damit
wiederhergestellt, die automatische Pause besitzt aber keinen eigenen
forensischen Recovery-Auditeintrag. Ein späterer signierter Clear bleibt
erforderlich und wird normal auditiert.

## Kein allgemeiner Active-active-Betrieb

SQLite serialisiert lokale Writer über `BEGIN IMMEDIATE` und einen Busy-
Timeout. Das belegt konkurrierende lokale Prozesse und definierte Crashgrenzen,
nicht beliebig viele aktive Instanzen, Lock-Fairness, automatische Leaderwahl,
Cluster-Failover oder verteilte Konsistenz. Lang laufende Transaktionen können
andere Writer blockieren; nach dem Timeout wird die Operation ohne Retry als
`CONTROL_PLANE_BUSY` abgelehnt.

## Nicht jede generische Approval-Art besitzt eine eigene FK-Auditbindung

External-Action-Evidence, signierte Statements und Kill-Switch-Clear besitzen
enge relationale Bindungen und Trigger. Der generische
Approval-Decision-Audit ist jedoch nicht für jede mögliche Approval-Art über
eine eigene spezialisierte Foreign-Key-Tabelle mit allen fachlichen Feldern
gebunden. Privilegierter Code mit direktem Datenbankzugriff bleibt Teil der TCB;
eine erfolgreiche generische Approval ist keine Autorisierung für einen
externen Runner.

## Crash-Reservationen bleiben absichtlich blockierend

External-Action-Attempts in `reserved` oder `running` werden nach Prozesscrash
nicht automatisch wiederholt, geerntet oder erstattet. Proposal-ID, Attempt
und Budget bleiben persistent verbraucht beziehungsweise blockierend. Dies
verhindert unbemerkte Doppelwirkung, erfordert aber manuelle forensische
Klärung und kann Budget dauerhaft binden.

## `node:sqlite` bleibt experimentell

Node.js kennzeichnet `node:sqlite` weiterhin mit einer
`ExperimentalWarning`. Phase 6 testet die verwendete Node-Version und die
benötigten Transaktions-, Pragma- und Recoverypfade, garantiert aber keine
zukünftige API- oder Verhaltensstabilität. Ein Runtime-Upgrade benötigt die
vollständige Regression und erneute lokale Crashqualifikation.

## Restrisiken früherer Phasen gelten fort

Phase 6 verändert weder Egress, Event-Verschlüsselung und Key-Lifecycle noch
Operator- oder External-Action-Autorisierung. Insbesondere bleiben bestehen:

- Operator-Enrollment ist lokales TOFU und kein Beweis menschlicher Anwesenheit;
- Key-Rotation, Widerruf, Mehrpersonenfreigabe und Quorum für Operatoren fehlen;
- Event-Key-Minimum, Keychain, historische Keys und vollständiges
  State-/Event-Rollback bleiben gemäß Phase 5 lokale TCB-Grenzen;
- reale Integrationen bleiben unabhängig von vorhandener Approval-Evidence
  deaktiviert;
- Budget- und Store-Capabilities bleiben lokale, privilegierte
  Prozessgrenzen.

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
- automatische Audit-Reparatur, -Rotation oder externer Head;
- allgemeiner Active-active-, Cluster- oder Netzwerkdateisystembetrieb.

Die fünf simulationsfähigen Registry-Actions erreichen ausschließlich den
deterministischen In-Process-Mock. `report_submit` und
`triage_response_send` bleiben auch im Simulationsmodus nicht ausführbar.

## Lokale Sicherheitsgrenze

Produkt-, Netzwerk- und Browsertests verwenden ausschließlich In-Process-
Mocks oder Loopback-Adressen. Ein kompromittierter lokaler Rechner wird durch
Phase 6 nicht abgesichert. Während Entwicklung und Tests wurde kein realer
Plattform-, HackerOne-, Bugcrowd-, Beispiel- oder Bug-Bounty-Zielhost
kontaktiert.
