# Empfehlung für Pilot Readiness B

## Entscheidung

Der kleinste verantwortbare nächste Schritt ist weiterhin **kein
Zielrequest**. Pilot Readiness A besitzt jetzt bereits:

- signierte Aktivierung mit Bindung an Runtime, Credential und Generation;
- signierte Annahme mit Bindung an aktuellen Snapshot, Policy, Quelle und
  Programm;
- persistente Proposal-, Attempt-, Budget-, Reservation- und
  Settlement-Evidence;
- tatsächliche SQLite-DDL-Verifikation;
- vollständige Credential-Bindung über 64 Digestzeichen, One-shot-
  Transportpläne und One-shot-Vault-Leases;
- budgetgebundene Runtime-Evidence und reaktivierungsübergreifende Minuten-,
  Per-Operation- und Crash-Budgets;
- atomare Katalog-/Sync-, Detailsnapshot-/Auswahl-/Sync-, Manual-/Snapshot-
  und Drift-/Kampagnenpause-/Audit-Commits;
- sofortige `catalog_drift_pending`-Sperre samt Kampagnenpause und
  Acceptance-Block;
- begrenzte lokale Binär-Credential-Ablage im Dashboard sowie den
  alternativen TTY-Adminweg, ohne JSON- oder Browser-Storage-Persistenz;
- eine begrenzte, quellenbewusste lokale Dashboardprojektion.

Die frühere Empfehlung, diese Grenzen erst in Pilot B einzuführen, ist damit
erledigt. Pilot B sollte die Integration read-only halten und als Nächstes die
operative Recovery für gestrandete Metadatenreservationen qualifizieren.

## Kleinster empfohlener Umfang

Pilot B sollte genau eine neue lokale Offline-Adminoperation liefern:

> Eine nach Prozesscrash gestrandete `reserved`- oder `running`-Reservation
> darf nach nachweislicher Prozessabwesenheit durch eine frische signierte
> Operatorentscheidung dauerhaft als `aborted` abgeschlossen werden, ohne
> irgendeine Budgeteinheit zu erstatten oder einen Transport zu starten.

Diese Operation ist weder Dashboardroute noch External-Action-Runner. Sie
muss bei beendetem Dashboard in einem interaktiven lokalen Terminal laufen,
den Adapter zunächst deaktivieren und alte Activation-Evidence niemals
reaktivieren.

## Vorgeschlagene Recovery-Kette

```text
TTY-only Offline-Adminstart
→ private Control-Plane-Datei und exakte DDL prüfen
→ Adapter deaktiviert und Dashboardprozess abwesend
→ exakte Authorization-/Attempt-ID auswählen
→ Status ist ausschließlich reserved oder running
→ Eigentümer-/Prozessabwesenheit zweimal prüfen
→ frische signierte Operator-Approval
→ Session/Nonce/Clock/Control-Plane-/Attempt-Digest prüfen
→ BEGIN IMMEDIATE
→ Status und Revision erneut prüfen
→ append-only Recovery-Evidence und bodyfreies Audit
→ Transition zu aborted
→ Budget bleibt verbraucht
→ Commit
```

Jede Abweichung, ein laufender Eigentümerprozess, Clock-Rollback, Replay,
Schemaabweichung, ungültige Signatur oder Auditfehler muss blockieren. Die
Operation darf keinen Requestplan oder Transport erzeugen.

## Weitere sinnvolle read-only Härtungen danach

Nach der kleinen Recovery-Grenze, aber weiterhin ohne Zielaktionen:

1. **Absolutes Gesamtbudget:** optionales persistentes Limit über alle
   Top-Level-Operationen ergänzen, das auch durch Reaktivierung nicht
   zurückgesetzt wird; bestehende Per-Operation-/Minuten-/Parallelitätsgrenzen
   nicht lockern.
2. **Versionierte API-Vertragsfixtures:** synthetische, versionierte Sätze für
   bekannte HackerOne-Schemaänderungen und explizite Adaptermigrationen
   pflegen.
3. **DDL-Migrationsdesign:** signierte, offline ausgeführte und vollständig
   getestete Migration statt automatischer Adoption bereitstellen.
4. **Dashboard-Pagination:** über 1.000 Programme, 20 Versionen und 100
   Kampagnen weiterhin mit festen lokalen Cursors und begrenzten Projektionen
   zugänglich machen.
5. **Quellenbewusste Controls:** API-Detailsync bei `manual_unverified`
   bereits in der UI deaktivieren und den Backend-Blockiergrund anzeigen.
6. **Signierter redigierter Export:** lokaler Snapshot-/Diff-Export ohne
   Credentials, Requestbodys, klickbare Assetlinks oder externe Übertragung.
7. **Retention-Entwurf:** separate signierte Offline-Adminoperation für
   Metadaten und Evidence; kein Dashboard-Schnelllöschen.

## Verbindliche Nicht-Ziele

Pilot B sollte weiterhin nicht implementieren:

- Requests an Scope-Assets;
- Scanner oder aktive Sicherheitstests;
- Browserautomation oder HackerOne-Web-Scraping;
- Account-Erstellung, Login, CAPTCHA, TOTP oder E-Mail-Automation;
- Report-Erstellung über Plattform-APIs oder Report-Einreichung;
- Attachments, Kommentare, Triage, Bounties oder Zahlungen;
- LLM-gesteuerte HTTP-Requests;
- `weaknesses` ohne separaten Produkt- und Security-Auftrag;
- automatische Zustimmung zu Programmregeln, Bedingungen oder rechtlichen
  Erklärungen;
- automatische Live-Smokes oder echte API-Requests in Tests, Build, CI oder
  durch Codex.

## Abnahmekriterien für die Recovery-Grenze

- ausschließlich als interaktiver lokaler Offline-Adminpfad bei beendetem
  Dashboard erreichbar;
- keine Dashboard-, HTTP-, Browser-, LLM- oder External-Action-Route;
- exakte private SQLite-Datei, sichere Dateihärtung und aktuelle tatsächliche
  DDL nachgewiesen;
- Adapter vor Recovery deaktiviert;
- nur ein exakter bestehender `reserved`-/`running`-Attempt auswählbar;
- Prozessabwesenheit konservativ und wiederholt geprüft;
- gültige frische Operator-Signatur mit Session, Nonce, Zeit,
  Control-Plane-Digest, Authorization-ID, Status, Revision, Proposal- und
  Plan-Digest;
- Replay, Clock-Rollback, parallele Transition, falsche Revision,
  Auditfehler und Schemaabweichung blockieren;
- Resultat ausschließlich `aborted`; keine Löschung und keine
  Budgeterstattung;
- Recovery-Evidence und Audit append-only und atomar;
- kein Netzwerkobjekt und kein Transport wird konstruiert;
- alle automatisierten Netzwerkprüfungen laufen ausschließlich gegen
  Loopback-Mocks;
- Phase-1- bis Pilot-A-Regressionen bleiben unverändert grün;
- kein realer Host wird durch Tests, Build oder Codex kontaktiert.

## Entscheidungstor vor jeder späteren Zielaktion

Auch nach Pilot B darf die H1-Metadatenaktivierung nicht als Freigabe für
Zielaktionen wiederverwendet werden. Ein späterer Auftrag müsste separat
Scope, Ownership, aktuelle Programmregeln, Kontobindung, Budgets, menschliche
Kontrollpunkte, deterministischen Runner, Kill Switch und Settlement-Evidence
definieren. Bis dahin bleiben Zielrequests, Browserautomation und
Report-Einreichung außerhalb der Registry-Freigabe.
