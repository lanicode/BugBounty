# Bekannte Restrisiken und bewusste Grenzen

## Lokaler Einzeloperator

Das Dashboard ist eine lokale Single-User-Control-Plane. Host-, Origin-, CSRF- und Loopback-Prüfungen schützen die lokale HTTP-Grenze, ersetzen aber keine Operator-Authentifizierung für einen gemeinsam genutzten oder kompromittierten Rechner. Der Server darf nicht über Portweiterleitung, Reverse Proxy oder geänderte Bindung veröffentlicht werden.

## SQLite und Dateisystem

Die Control Plane verwendet das in Node.js 24 enthaltene `node:sqlite`. Node gibt dafür derzeit eine `ExperimentalWarning` aus. Extension Loading ist deaktiviert, Migrationen sind gehasht, Foreign Keys und defensive Optionen sind aktiv. Die synchrone Single-Process-Nutzung ist für Phase 2 geeignet, aber nicht für Mehrprozessbetrieb.

Vor dem Öffnen wird ein symbolischer Link am Datenbankpfad abgelehnt. Zwischen Prüfung und Öffnen bleibt auf einem feindlich gemeinsam beschreibbaren Dateisystem theoretisch ein TOCTOU-Fenster. Deshalb muss `.local` in einem ausschließlich vom lokalen Benutzer kontrollierten Verzeichnis bleiben.

## Keychain-Abhängigkeit und Schlüssel-Lifecycle

Dashboard und CLI lesen den AES-256-GCM-Schlüssel ausschließlich über `MacOSKeychainSecretStore` aus `keychain://bugbounty-copilot/event-store-v1`. Es gibt keinen Klartext- oder In-Memory-Fallback im Produktpfad. Der Keychain-Eintrag muss manuell lokal bereitgestellt werden; Fehlen, Lesefehler, Nicht-macOS oder eine andere Länge als 32 Byte blockieren den Lauf vor jeder Simulationsfachdaten-Mutation. Vorbereitende Verzeichnis- und Datenbankschema-Erstellung kann bereits erfolgt sein. Rotation, Wiederherstellung und ein explizites Verfahren für alte Event-Hüllen sind noch nicht implementiert.

## Policy-Interpretation

JSON/YAML werden strikt geparst und normalisiert. Freier Policy-Text wird bewusst konservativ als potenziell unklar behandelt; das System ersetzt keine juristische oder programmseitige Auslegung. Jede Version und jeder Drift benötigt eine ausdrückliche lokale Annahme.

## Keine reale Integrationsvalidierung

Mock-Adapter und Interfaces beweisen die lokale Architektur, nicht das Verhalten realer Plattform-APIs. Es gibt keinen echten Adapter, keinen externen Host, kein Credential-Handling und keinen Auth-State. `.invalid`-Namen erscheinen ausschließlich als nicht aufgelöste Testmetadaten.

Der `DeterministicSimulationGateEvaluator` ist gebrandet und an den kanonischen Vorschlag gebunden, nimmt seine vier Entscheidungen aber noch als deterministische Simulationsdaten entgegen. Er löst Kampagnen-, Scope-, Account-, Objekt- und Approval-Referenzen nicht selbst gegen einen atomaren `ControlPlaneStore`-Snapshot auf. Wegen der ausschließlich lokalen Mock-Runner entsteht in Phase 2 keine externe Wirkung. Vor jedem realen Adapter ist ein persistenz- und operatorgebundener Evaluator zwingend.

## Keine aktiven Tests oder Einreichungen

`target_request` kann nur den fest verdrahteten lokalen Mock-Runner erreichen. Report- und Triage-Aktionen besitzen weder Simulations- noch externen Runner. Report-Datensätze sind Entwürfe; Freigaben lösen keine externe Wirkung aus.

## Persistenz- und Auditumfang

Die SQLite-Control-Plane besitzt ein minimiertes, bodyfreies Audit-Grundgerüst und optimistische Revisionen. Kill-Switch-Clear ist an Revision und Audit-Payload gebunden; aktive Kampagnen werden beim Lesen relational revalidiert. Vollständig signierte, authentifizierte Benutzerentscheidungen, Backups, Schlüsselrotation, Crash-Recovery über mehrere Prozesse und Langzeitaufbewahrung sind zurückgestellt. Der persistente Runner-Abort prüft den Kill Switch alle 5 ms; dies ist eine kleine, bewusste Polling-Latenz.

## Produkt- und UI-Umfang

Das Dashboard bietet Übersicht, lokalen JSON-/YAML-Programmimport, vollständige Simulationsfreigaben, Approval-Entscheidung, Kill Switch und Expertenansichten. Generisches CRUD für jede Policy-, Kampagnen- und Identity-Variante ist noch nicht als separate UI-Maske vorhanden; diese Modelle werden über die Control-Plane-APIs und den Demoablauf verwaltet.

`retired` plus `retiredAt` ist in Phase 2 der terminale Lösch-/Stilllegungsmarker des Account-Lifecycles; ein separates physisches `deletedAt` ist bewusst nicht vorhanden. Damit ist die Löschung ausschließlich logisch, nicht physisch. Die CLI ist absichtlich ausschließlich interaktiv und erzeugt pro Lauf ein eigenes lokales Event-Verzeichnis.

## Dependency- und Laufzeitrisiko

Abhängigkeiten sind exakt gepinnt und der Audit meldet keine bekannten Schwachstellen. Dies schließt unbekannte Schwachstellen nicht aus. Node.js 24 oder neuer ist erforderlich; ältere Laufzeiten werden nicht unterstützt.
