# Phase 7: Bekannte Restrisiken und bewusste Grenzen

## Rollenprofile sind kein Authentisierungs- oder Autorisierungsnachweis

Owner, Member und External bestimmen ausschließlich feste lokale
Replay-Routen. Die Demo-SaaS ist anonym und read-only. Es gibt keine Anmeldung,
Session, serverseitige Rollenprüfung oder Mandantengrenze. Die beobachteten
Routenunterschiede beweisen daher nur den geschlossenen Testplan, nicht, dass
ein Produktzugriff für eine reale Identität zulässig wäre.

## Redigierte Screenshots sind keine visuellen Produktaufnahmen

Der Harness verifiziert ein viewportfüllendes Maskenelement und lässt
Playwright dieses mit einer sicheren, rollen- und zustandsgebundenen opaken
Farbe übermalen. Eine Secret-Marker-Probe beweist, dass veränderter
darunterliegender DOM-Inhalt den Digest für dasselbe Label nicht verändert.
Der freigegebene Digest bindet damit den Testzustand, enthält aber bewusst
keine visuelle Produktinformation.

Diese Garantie gilt für den qualifizierten Chromium-/Playwright-Pfad und die
festen 1280×720-Einstellungen. Playwright, Chromium, CSS-Compositing,
Screenshot- und PNG-Encoder bleiben Teil der lokalen Trusted Computing Base.
Ein Browser- oder Runtime-Upgrade benötigt die vollständige Regression.

## PNG-Prüfung validiert Container und Metadaten, nicht einen Decoder

Der Validator prüft Signatur, Abmessungen, Größenlimit, Chunkreihenfolge,
CRC-Werte und die ausschließliche Allowlist `IHDR`, `IDAT`, `IEND`. Text-,
EXIF- und unbekannte Chunks blockieren. Er implementiert bewusst keinen
zweiten unabhängigen PNG-Pixeldecoder. Redaktionsgeometrie, Browsermaskierung
und Digestinvarianz liefern die ergänzenden Nachweise; ein Fehler in der
gemeinsamen Browser-/Codec-TCB wird dadurch nicht vollständig ausgeschlossen.

## Minimale Playwright-Runner-Metadaten bleiben lokal

Nach einem erfolgreichen Lauf bleibt
`.local/phase7-playwright/results/.last-run.json` zurück. Die Datei enthält
nur nicht sensitive Runner-Metadaten, keine URL, Ports, Responses,
Screenshots, Cookies oder Storage-States. Phase 7 löscht sie nicht, weil sie
vom Test Runner verwaltet wird; die Artefaktprüfung schließt alle sensibleren
Dateitypen und den Test-Secret-Marker aus.

## Der Harness ist kein produktiver External-Action-Runner

Der Browsercode lebt unter `tests/browser` und wird nur vom Testkommando
gestartet. Er durchläuft nicht die persistente Proposal-, Policy-, Scope-,
Budget-, Approval- und Kill-Switch-Pipeline. Das ist sicher, solange er
Testinfrastruktur bleibt, bedeutet aber auch, dass er nicht als produktive
Browserfähigkeit wiederverwendet werden darf. Eine spätere Produktintegration
benötigte einen eigenen geschlossenen Sicherheitsvertrag und darf nicht durch
Importieren des Testharness erfolgen.

## Ressourcen- und Laufzeitgrenzen sind absichtlich eng

Request-, Response-, Screenshot-, Frame-, Page- und Laufzeitgrenzen blockieren
unerwartete Änderungen konservativ. Legitimes Wachstum der Demo-Fixtures oder
Browserausgabe kann deshalb einen Testlauf stoppen. Phase 7 bevorzugt diesen
fail-closed Fehlalarm gegenüber stiller Erweiterung des zulässigen Umfangs.

## Lokale Browserinstallation und Sandbox bleiben Betriebsabhängigkeiten

Chromium muss lokal verfügbar und ausführbar sein; Socket- und Browserstart
können in restriktiven Sandboxes zusätzliche lokale Berechtigungen benötigen.
Der erste Gesamtlauf traf deshalb auf `listen EPERM 127.0.0.1`, während der
identische Lauf mit lokaler Socketberechtigung vollständig bestand. Diese
Berechtigung erlaubt keinen Produktverkehr außerhalb Loopback, muss aber in
CI explizit und eng eingerichtet werden.

## Restrisiken früherer Phasen gelten fort

Phase 7 verändert weder Egress, Event-Verschlüsselung und Key-Lifecycle noch
Operator-, Policy- oder External-Action-Autorisierung. Insbesondere bleiben
bestehen:

- lokaler OS-Account, Prozess, Browser, SQLite und Dateisystem sind Teil der
  Trusted Computing Base;
- Audit-Hashketten besitzen noch keinen separat erhaltenen authentisierten
  Head;
- Event-Key-Minimum, Keychain und historische Keys behalten ihre
  dokumentierten lokalen Grenzen;
- reservierte oder laufende External Actions werden nach Crash nicht
  automatisch wiederholt oder erstattet;
- reale Integrationen bleiben unabhängig von Approval-Evidence deaktiviert;
- allgemeiner Active-active-, Cluster- oder Netzwerkdateisystembetrieb ist
  nicht qualifiziert.

## Bewusst deaktivierte oder zurückgestellte Funktionen

- Produktiver Browserorchestrator und registrierter Browserrunner;
- freie URLs, Ziele, Schritte, Scripts, Locators und Locator-Healing;
- echte Anmeldung, Cookies, Storage-State, Profile und Account-Automation;
- mutierende Demo-SaaS-Routen, Crawling und aktive Sicherheitstests;
- externe Plattformadapter und Bug-Bounty-Zielverbindungen;
- echte Tokens, Passwörter, TOTP-, E-Mail- oder Browser-Secrets;
- automatische Zustimmung zu Regeln, Bedingungen, rechtlichen Erklärungen
  oder Reports;
- CAPTCHA- und Anti-Bot-Umgehung;
- Report-Einreichung, Triage-Versand und LLM-gesteuerte Requests;
- persistierte Rohscreenshots, Responses, Traces, Videos, HARs oder
  Storage-States.

## Lokale Sicherheitsgrenze

Produkt-, Netzwerk- und Browsertests verwenden ausschließlich In-Process-
Mocks oder Loopback-Adressen. Ein kompromittierter lokaler Rechner wird durch
Phase 7 nicht abgesichert. Während Entwicklung und Tests wurde kein realer
Plattform-, HackerOne-, Bugcrowd-, Beispiel- oder Bug-Bounty-Zielhost
kontaktiert.
