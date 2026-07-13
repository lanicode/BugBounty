# Lokales Phase-2-Dashboard

## Voraussetzungen

- macOS mit lokalem Schlüsselbund
- Node.js 24 oder neuer
- pnpm 11
- lokal installierte, im Lockfile exakt aufgelöste Abhängigkeiten

## Event-Schlüssel lokal einrichten

Dashboard und Phase-2-CLI verwenden ausschließlich `MacOSKeychainSecretStore`. Es gibt keinen Klartext- oder In-Memory-Fallback im Produktpfad. Vor dem ersten Simulationslauf einmal lokal ausführen:

```sh
security add-generic-password -U -s bugbounty-copilot -a event-store-v1 -w "$(openssl rand -base64 24)"
```

Die 24 zufälligen Binärbytes werden durch Base64 zu exakt 32 ASCII-Bytes und unter der Referenz `keychain://bugbounty-copilot/event-store-v1` gespeichert. Den Wert weder anzeigen noch in Shell-Historien, Skripte, Logs oder das Repository kopieren. Fehlt der Eintrag, ist er unlesbar oder nicht exakt 32 Byte lang, endet der Lauf mit `SIMULATION_EVENT_SECRET_UNAVAILABLE`, bevor der Kill Switch freigegeben oder Control-Plane-Zustand verändert wird. Auf anderen Betriebssystemen bleibt dieser Produktpfad fail-closed deaktiviert.

## Start

Im Repository ausführen:

```sh
pnpm install --frozen-lockfile
pnpm dashboard
```

Die Control Plane bindet ausschließlich an:

```text
http://127.0.0.1:4173
```

Die separate Demo-SaaS erhält einen zufälligen freien Loopback-Port. Beide Adressen werden beim Start ausgegeben. Eine Bindung an `0.0.0.0`, `::` oder einen externen Host ist nicht vorgesehen.

## Sicherheitsstatus

Jede Seite zeigt sichtbar:

- `SIMULATIONSMODUS`
- `EXTERNE INTEGRATIONEN DEAKTIVIERT`

Eine neue lokale Datenbank und jeder Dashboard-Start aktiviert den globalen Kill Switch. Clear-Zustände sind an Revision, Zeitstempel, Actor, Audit-ID und Payload-Hash gebunden. Fehlende, unlesbare oder inkonsistente Zustände werden als aktiv behandelt. Engagement pausiert aktive Kampagnen. Die Oberfläche schützt mutierende Requests mit exakter Host-/Origin-Prüfung und einem zufälligen CSRF-Token; Skripte und Styles werden nur als eigene statische Ressourcen unter einer restriktiven Content Security Policy ausgeliefert.

## Simulation ausführen

1. Dashboard unter `http://127.0.0.1:4173` öffnen.
2. Im Bereich „Vollständige lokale Simulation“ alle sechs menschlichen Bestätigungen einzeln setzen.
3. Simulation starten.
4. Die 18 Schritte, Policy-Diff, Kampagnenstatus, Testidentitäten, Ownership Ledger, Freigaben und Report-Entwurf prüfen.
5. Den globalen Kill Switch jederzeit über „Sofort stoppen“ aktivieren.

Die sechs Bestätigungen sind exakt:

1. Kill Switch nur für diesen lokalen Lauf freigeben.
2. Policy v1 samt Hash akzeptieren.
3. Kampagnenvertrag v1 samt vollständigem Digest freigeben.
4. Policy v2 nach Prüfung des Diffs akzeptieren.
5. Kampagnenvertrag v2 samt vollständigem Digest freigeben.
6. Report-Entwurf nur zur lokalen menschlichen Review einreihen.

Owner, Member und External sind vorautorisierte, checkpoint-freie In-Process-Demo-Fixtures; der Ablauf repräsentiert keine Registrierung und akzeptiert keine Bedingungen. Konfigurierte Account-Challenges wie CAPTCHA, E-Mail-Verifikation, TOTP, Programmregeln, Bedingungen oder rechtliche Erklärungen pausieren immer und werden niemals automatisch erfüllt.

## Lokale Laufzeitdaten

Das Dashboard schreibt ausschließlich nach `.local/dashboard/`; die SQLite-Datei erhält Modus `0600`, das Verzeichnis `0700`. Der Pfad ist per `.gitignore` ausgeschlossen. Simulationsevents werden nur als AES-256-GCM-Hüllen gespeichert; der Schlüssel verbleibt im macOS-Schlüsselbund. Roh-HARs, Klartext-Secrets und unredigierte Responses werden nicht erzeugt.

Zum Zurücksetzen zuerst den Server beenden und anschließend nur die lokalen Demo-Daten entfernen:

```sh
rm -rf .local/dashboard .local/phase2-simulation
```

## Beenden

Im startenden Terminal `Ctrl-C` drücken. Dashboard und Demo-SaaS werden gemeinsam beendet.
