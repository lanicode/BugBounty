# Pilot Readiness C – Bekannte Einschränkungen und Restrisiken

## Einordnung

Pilot Readiness C reduziert die technisch ausführbare Wirkung auf wenige,
planbezogene Einmalrequests. Die Capability ersetzt weder eine rechtliche
Freigabe noch eine menschliche Programmpolicy-Prüfung. „Niedrig-riskant“
bedeutet nicht „ohne Wirkung“.

## Autorisierung, Policy und Scope

### Lokaler Snapshot ist kein Live-Nachweis

„Aktuell“ bedeutet technisch: ausgewählter, lokal persistierter und akzeptierter
authentifizierter HackerOne-API-Snapshot aus der gegenwärtigen signierten
Adaptergeneration, dessen letzter erfolgreicher Detailsync höchstens 15 Minuten
zurückliegt und zeitlich nach der Aktivierung liegt. Ein Adapter-, Credential-
oder Accountwechsel verwirft Auswahl und Sync-Zustand. Zwischen letzter
Synchronisierung und Start kann HackerOne trotzdem eine Policy, einen Scope
oder eine Ausschlussregel geändert haben. Die Anwendung führt bewusst keinen
automatischen Vorab-Sync durch, weil externe Aktionen nie stillschweigend
ausgelöst werden dürfen.

Konservative Maßnahme: unmittelbar vor Planvorbereitung Programmkatalog,
Programmdetail, Structured Scopes und Scope Exclusions manuell
synchronisieren, Drift prüfen und nur den neuen Snapshot ausdrücklich lokal
akzeptieren.

### Policyerkennung ist keine Rechtsauslegung

Eine enge deterministische Erkennung blockiert klar formulierte englische
Verbote automatisierter Tests. Sie kann sprachliche, kontextabhängige oder
ungewöhnlich formulierte Verbote nicht vollständig interpretieren. Die vier
manuellen Bestätigungen sind deshalb eine echte Sicherheitsgrenze und keine
Formalität.

Konservative Maßnahme: vollständigen Policytext, Scope-Anweisung,
Ausschlüsse, Rate Limits, Safe-Harbor-Regeln und alle programmspezifischen
Vorgaben selbst lesen. Bei Unklarheit keinen aktiven Plan freigeben.

### API-Scope ist kein Besitz- oder Rechtsbeweis

Die Anwendung bindet technisch an einen authentifizierten API-Snapshot und
ein dort genanntes Asset. Sie kann nicht beweisen, dass der angemeldete Mensch
teilnahmeberechtigt ist, dass das Programm die konkrete Automationsform
erlaubt oder dass ein Drittanbieterasset organisatorisch freigegeben wurde.

### Unterstützte Scopeformen sind absichtlich eng

Nur kanonische `https://`-URL-Scopes auf Port 443 ohne Wildcard, IP-Literal,
Query, Fragment oder Benutzerinformationen werden unterstützt. Submission-
und Bounty-Eignung müssen beide positiv sein. Andere legitime Scopeformen wie
Domains, CIDRs, APIs mit erforderlicher Authentisierung, Mobile Apps oder
spezielle Ports bleiben blockiert.

`security_txt` ist nur für einen URL-Scope mit Rootpfad `/` verfügbar. Die
Anwendung versucht nicht, aus komplexen Scopeformulierungen zusätzliche Ziele
abzuleiten.

## Wirkung der aktiven Requests

### Auch ein Einmalrequest ist beobachtbar

Ein `GET`, `HEAD` oder `OPTIONS` kann Serverlogs, WAF-Regeln, Rate Limits,
Monitoring oder ungewöhnliche Anwendungslogik auslösen. Fehlerhaft
implementierte Server können selbst bei nominell lesenden Methoden
Seiteneffekte haben. Die Anwendung kann dieses Restrisiko nicht beseitigen.

### Kill Switch kann einen bereits übertragenen Request nicht zurückholen

Der Kill Switch wird vor und während DNS, TLS und Responseverarbeitung sowie
vor Completion geprüft. Wird er nach Übertragung eines Requests engagiert,
kann er die bereits beim Ziel eingetroffene Anfrage nicht rückgängig machen.
Er zerstört beziehungsweise entwertet den laufenden Vorgang fail-closed; das
Budget bleibt verbraucht.

### Kein Retry und keine automatische Verifikation

Temporäre Netzfehler, WAF-Antworten oder methodenspezifisches Serververhalten
können zu Fehl- oder Nichtbefunden führen. Die Anwendung wiederholt den
Request nicht und führt keine Exploitation zur Bestätigung durch. Ein
deterministisches Signal ist nur eine lokale Beobachtung, kein verifizierter
Bug und keine Einreichungsempfehlung.

### Testklassenspezifische Grenzen

- Headerchecks prüfen nur eine kleine feste Menge und bewerten keine
  vollständige Browser- oder Anwendungskonfiguration.
- Cookie-Werte werden nicht gespeichert; die Flag-Klassifikation kann
  semantische Kontexte wie Cookie-Zweck oder Pfad nicht beurteilen.
- Der CORS-Test verwendet genau einen festen `.invalid`-Probe-Origin und eine
  feste gewünschte Methode. Andere Origins, Methoden, Preflightvarianten oder
  tatsächliche Credentialflüsse werden nicht geprüft.
- `security.txt` prüft Verfügbarkeit und Metadaten, nicht die inhaltliche
  Richtigkeit, Aktualität oder Vertrauenswürdigkeit der Datei.

## DNS-, SSRF- und TLS-Grenzen

### Systemresolver und DNS-Vertraulichkeit

Die Produktion verwendet den lokalen Systemresolver. Die DNS-Abfrage kann dem
konfigurierten Resolver den ausgewählten Zielhost offenlegen. DNSSEC wird von
der Anwendung nicht selbst verifiziert.

Node.js stellt für den verwendeten System-`getaddrinfo`-Pfad kein
`AbortSignal` bereit. Deadline oder Kill Switch beenden deshalb den
Produktvorgang fail-closed und garantieren, dass danach kein HTTP-Request
beginnt; eine bereits an das Betriebssystem übergebene DNS-Auflösung kann im
Hintergrund dennoch zu Ende laufen.

Alle gelieferten A-/AAAA-Adressen werden geprüft und digestgebunden; eine
gesperrte Antwort blockiert die gesamte Menge. Die anschließend gewählte
Adresse wird an die TLS-Verbindung gepinnt. Das reduziert Rebinding-Risiken,
ersetzt aber keine Vertrauensbewertung des lokalen DNS- und Netzwerkpfads.
Der Resolver erhält den validierten Host als absoluten Namen mit terminalem
Punkt, damit lokale Search-Domains nicht stillschweigend angehängt werden;
SNI, Hostprüfung und Evidence bleiben an den kanonischen Scope-Host ohne Punkt
gebunden.

### Plattform-Trust-Store

TLS-Zertifikats- und Hostprüfung stützen sich auf Node.js und den verfügbaren
Trust-Store. Es gibt kein zusätzliches Certificate Pinning für wechselnde
Programmassets und keine anwendungseigene OCSP-/CRL-Auswertung. Nur TLS 1.2
und 1.3 sind erlaubt; die Cipherauswertung wird bewusst nur als
`modern` beziehungsweise `other_redacted` gespeichert.

### Kein Proxy- oder Unternehmensnetzwerkmodell

HTTP-Proxies, TLS-Inspection, PAC-Dateien, VPN-Sonderrouten und gespaltene DNS-
Umgebungen sind kein qualifizierter Betriebsmodus. Unerwartete Antworten oder
Adressklassen blockieren typischerweise fail-closed, können aber den
praktischen Einsatz in solchen Netzen verhindern.

## Evidence, Datenschutz und Persistenz

### Rohdaten werden transient verarbeitet

Der Transport muss Responseheader und beim `security.txt`-Check die begrenzten
Bodybytes im Prozess sehen, um Klassifikationen und Digests zu bilden.
Rohheader, Body und Cookies werden nicht persistiert, dennoch existieren sie
kurzzeitig im Prozessspeicher und gegebenenfalls in Betriebssystem-
Netzwerkpuffern.

### Lokale SQLite-Daten enthalten sensible Metadaten

Planzeilen enthalten den exakten Zielhost und Pfad. Persistierte Observations-
und Reportentwürfe enthalten Status, Timing, Größen, Digests und
deterministische Signale. Die private, gehärtete SQLite-Control-Plane ist
lokal zugriffsbeschränkt, diese Datensätze liegen jedoch nicht zusätzlich als
AES-GCM-Event-Store-Hüllen vor.

Konservative Maßnahme: den lokalen Benutzeraccount und Datenträger schützen,
keine Datenbank in Cloud-Sync-, Netzwerk- oder gemeinsam genutzte
Verzeichnisse legen und den Rechner nicht mit untrusted lokalen Prozessen
teilen.

### Keine Retention- oder Löschoberfläche

Active-Testing-Pläne, Attempts, Observations und Reportentwürfe sind
append-only beziehungsweise unveränderlich. Eine geprüfte Purge-, Export- oder
Retention-Oberfläche existiert nicht. Dateien oder Tabellen dürfen nicht
manuell während des Betriebs verändert werden; Schema- oder
Evidenceabweichungen blockieren den nächsten Start.

Der interne `ControlPlaneDatabase`-Handle und Produktcode mit direktem
SQL-Zugriff gehören zur vertrauenswürdigen lokalen Codegrenze. Browser- und
Adaptereingaben erhalten diesen Handle nicht. Ein bereits kompromittierter
lokaler Prozess mit Codeausführungsrechten könnte SQLite-Pragmas oder Dateien
außerhalb der vorgesehenen Produktoberfläche manipulieren; Reopen-Schema-,
Kanonizitäts- und Evidenceprüfungen reduzieren, aber beseitigen dieses lokale
Codeausführungsrisiko nicht.

### Lokaler Report ist nicht einreichungsfertig

Der Report enthält bewusst nur redigierte Klassifikationen und Digests. Er
kann zu wenig Reproduktionsdetail für eine Plattformmeldung enthalten. Es
gibt keine Submit-Funktion, keinen Anhangspfad und keine automatische
Übertragung. Jede spätere Meldung wäre ein separater, bislang nicht
implementierter und erneut zu prüfender Produktumfang.

## Budget, Crash und Betrieb

### Budgets sind absichtlich nicht rücksetzbar

Die Runtime erlaubt höchstens zehn Reservationen insgesamt, zwei pro Minute
und eine gleichzeitig. Ein Plan selbst erlaubt genau eine Anfrage. Fehler,
Abbruch und Crash erstatten nichts. Dieselbe Kombination aus Snapshot, Scope,
Asset und Testklasse kann nicht wiederholt werden.

Es existiert keine Dashboardfunktion zum Zurücksetzen oder Reparieren dieses
Budgets. Das verhindert stille Wiederholungen, kann aber nach einem
harmlosen Transportfehler weitere Arbeit blockieren.

### Crash-Reservationen bleiben blockierend

Ein Prozessabbruch zwischen Reservation, Start und Settlement kann einen
`reserved`- oder `running`-Attempt hinterlassen. Es gibt keine automatische
Recovery, weil eine unbekannte externe Wirkung nicht sicher erstattet oder
wiederholt werden kann. Eine zukünftige Recovery müsste ein eigener lokaler,
auditierter Offline-Adminpfad sein.

### Einzelbenutzer- und macOS-Grenze

Der produktive Secret- und Core-Provisioningpfad ist für einen lokalen
macOS-Einzelbenutzer ausgelegt. Multi-User-, Remote-, Container-, CI- und
Netzwerkdateisystembetrieb ist nicht qualifiziert. Node.js 24, pnpm 11 und für
Installer beziehungsweise nativen Helper die macOS-Entwicklungswerkzeuge
müssen verfügbar und lokal vertrauenswürdig sein.

### Core-Provisioning besitzt keinen automatischen Rollback

Fresh Provisioning schreibt ein atomisches Bundle. Beim konservativen
Legacy-Abschluss wird genau die fehlende Operator-Hülle ergänzt und der
bestehende Event-Key nicht verändert. Scheitert eine Nachprüfung nach einem
erfolgreichen Keychain-Write, löscht die Anwendung den neuen Eintrag bewusst
nicht automatisch. Der Zustand bleibt gesperrt und benötigt eine getrennte
manuelle Offline-Untersuchung.

### Native Keychain-Helper und Upgrade-Verfügbarkeit

Die neuen Core-Keychain-Einträge binden ihre macOS-ACL an den lokal
kompilierten Helper unter `.local/native/core-keychain-helper-v1`. Dieser
Pilot-Build ist noch kein dauerhaft signierter, versionierter
Distributionshelper. Eine Neuübersetzung nach Source-, Toolchain- oder
Cacheänderung kann von macOS als andere Codeidentität behandelt werden und bei
deaktivierter Keychain-Interaktion fail-closed nicht mehr lesen. Vor einer
dauerhaften Produktverteilung braucht der Helper deshalb einen signierten,
versionierten Upgrade- und Recoveryvertrag; manuelles ACL-Lockern oder ein
Klartext-Export ist kein zulässiger Workaround.

### Launcher-Modus ist Installationskonfiguration

`--enable-hackerone-active-testing` wird in das lokale App-Bundle übernommen.
Das Flag startet keinen Test, bleibt aber für spätere Finder-Starts aktiv, bis
die App erneut im `local-only`- oder Read-only-Modus installiert wird. Für
einen sofortigen Stopp ist zuerst der globale Kill Switch zu engagieren und
danach die App zu beenden.

### Dashboard-Readiness ist nur eine lokale Projektion

Das Dashboard kann aufgrund der vorhandenen lokalen Schalter und Metadaten
anzeigen, dass Active Testing grundsätzlich vorbereitet werden kann. Diese
Anzeige ist keine Vorabautorisierung und kann vor der serverseitigen
Planvorbereitung optimistischer wirken als das vollständige Gate. Erst die
serverseitige Plan-, Registry-, Credentialgeneration-, Snapshot-, Policy-,
Scope-, Budget- und Kill-Switch-Prüfung entscheidet. Ein abgelehnter Reason
Code darf nicht durch Wiederholen, Browserzustand oder manuelle
Datenbankänderung umgangen werden.

## Nicht qualifizierte Funktionen

Nicht implementiert beziehungsweise ausdrücklich verboten bleiben:

- schreibende Methoden, Auth- oder Accounttests, Session- und
  Credentialangriffe;
- Browserautomation gegen reale Ziele;
- Crawling, Fuzzing, Portscans, Bruteforce und Exploitation;
- CAPTCHA-, Anti-Bot-, E-Mail- und TOTP-Automation;
- automatische Zustimmung zu Regeln, Bedingungen oder Rechtserklärungen;
- automatische oder manuelle Einreichung aus der Anwendung;
- LLM-gesteuerte HTTP-Requests;
- weitere Plattformadapter.

## Testgrenze

Die automatisierten Tests führen den Produktions-Transport nicht gegen reale
HackerOne- oder Zielhosts aus. Sie qualifizieren Verträge, Gates und
Transportverhalten mit In-Process-Daten und Loopback-Mocks. Die
Loopback-HTTP-Engine liegt ausschließlich unter `tests/support`, wird aus dem
Produktionsbuild ausgeschlossen und ist kein Produkt- oder Runtimeexport.
Damit bleibt ein
Restrisiko für produktionsspezifische DNS-, TLS-, WAF- und Schemaunterschiede.
Ein späterer realer Ein-Request-Smoke darf nur nach vollständiger technischer
Abnahme, organisatorischer Freigabe und manueller Policy-/Scope-Prüfung
erfolgen.

## Additive API-Felder und Live-Abnahme

Der Read-only-Adapter verwirft additive JSON:API-Felder innerhalb fester
Struktur- und Größengrenzen, sofern alle konsumierten bekannten Felder das
strikte Schema erfüllen. Damit bleiben kompatible API-Erweiterungen ohne
stille Persistenz möglich. Das Verfahren kann jedoch nicht erkennen, ob ein
zukünftig neues Feld die Semantik eines bekannten Feldes grundlegend ändert.
Solche Änderungen erfordern weiterhin eine neue Code- und Policyprüfung.

Ein echter Verbindungstest darf nicht automatisiert durch Entwicklung oder
Tests wiederholt werden. Nach Installation dieses Fixes muss der Benutzer den
Read-only-Verbindungstest genau einmal bewusst auslösen und das Ergebnis im
Dashboard prüfen. Ein Fehlschlag erscheint nun als lokaler HTTP-Fehler statt
als grüne Erfolgsmeldung. Programm-Synchronisierung, aktive Tests und andere
externe Aktionen werden dadurch nicht automatisch gestartet.

### Katalogwerte können konservative Platzhalter enthalten

Katalog-Zusammenfassungen dürfen optionale Attribute auslassen oder `null`
liefern. Die lokale Liste zeigt dann bewusst `UNKNOWN`, `unknown`, leere
Policy, `false` oder `0`. Diese Werte sind keine Behauptung über das Programm,
sondern blockierende Platzhalter. Vor jeder Eignungsbewertung oder aktiven
Planung muss das ausgewählte Programm samt Policy, Structured Scopes und
Scope Exclusions separat synchronisiert und menschlich geprüft werden. Bleibt
ein sicherheitsrelevantes Detail auch dort unbekannt, kann kein aktiver Plan
freigegeben werden.

### Pagination bleibt absichtlich eng

Akzeptiert werden ausschließlich absolute HackerOne-API-Links mit den beiden
bekannten Seitenparametern. Andere zukünftige Paginationverfahren wie Cursor,
relative Links oder zusätzliche Filter bleiben fail-closed blockiert und
benötigen eine eigene Sicherheitsprüfung. Die Anwendung folgt dem gelieferten
Link nicht direkt, sondern rekonstruiert nach erfolgreicher Validierung ihren
festen kanonischen Requestplan.

### Mehrere offene Dashboard-Tabs

Jeder Browser-Tab besitzt weiterhin einen eigenen, flüchtigen Auswahl-Draft.
Der Draft wird nicht als Autorisierung verwendet und springt bei
Hintergrundaktualisierungen nicht mehr auf den ersten Katalogeintrag. Eine in
einem anderen Tab ausdrücklich übernommene Auswahl ersetzt jedoch die
serverseitig persistierte Auswahl und wird beim nächsten Refresh sichtbar.
Vor einer Detailsynchronisierung muss deshalb der im Metadatenbereich
angezeigte persistierte Handle geprüft werden. Alte Tabs sollten geschlossen
werden, um Bedienfehler zu vermeiden; die serverseitige Exaktprüfung bleibt
unabhängig davon fail-closed.

### API-ID-Repräsentation

Programmressourcen können ihre JSON:API-ID laut aktuellem HackerOne-
Antwortvertrag als positive Zahl oder als String darstellen. Die Anwendung
kanonisiert nur sichere positive Ganzzahlen; andere numerische Darstellungen
blockieren. Diese Kompatibilität sagt nichts über Policy, Scope, Eignung oder
Testfreigabe aus. Erst ein vollständig synchronisierter Snapshot mit
strukturierten Scopes und menschlicher Policy-Annahme kann die nachgelagerten
Gates erfüllen.
