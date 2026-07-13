# Bug Bounty Copilot MVP

Sicherer, passiver Startpunkt fuer autorisierte Bug-Bounty-Programme.

## Enthalten

- Zwei getrennte Playwright-Browserprofile
- HAR-Aufzeichnung fuer Konto A und Konto B
- Lokale Bereinigung sensibler Header und Werte
- Endpunktinventur
- A/B-Vergleich
- Berichtsentwurf
- Harte Scope-Allowlist
- Keine aktiven Sicherheitstests

## Voraussetzungen

- macOS
- Python 3.11 oder neuer
- Node.js 20 oder neuer

## Installation

```bash
cd bugbounty-copilot-mvp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
npm install
npx playwright install chromium
```

## 1. Scope konfigurieren

Bearbeite `config/scope.yaml` und trage nur die Hosts ein, die laut Programm-Policy erlaubt sind.

## 2. Je Konto einen normalen Ablauf aufzeichnen

```bash
npm run record:a
npm run record:b
```

Der Browser oeffnet sich. Melde dich nur mit deinen eigenen Testkonten an und bediene die Anwendung normal. Beende den Browser danach.

Die HAR-Dateien landen unter:

- `input/account-a/session.har`
- `input/account-b/session.har`

## 3. Analyse starten

```bash
source .venv/bin/activate
python tools/run_review.py
```

Ergebnisse:

- `output/redacted-account-a.har`
- `output/redacted-account-b.har`
- `output/endpoints.csv`
- `output/account-differences.csv`
- `reports/draft-report.md`

## Sicherheitsregeln

- Nur Programme mit ausdruecklicher Autorisierung verwenden.
- Nur eigene Konten und eigene Testdaten verwenden.
- Keine fremden IDs testen.
- Keine Lasttests, Brute-Force-, DoS- oder Massenscans.
- Auth-State-Dateien, Cookies und unbereinigte HAR-Dateien niemals teilen.
- Das Projekt sendet keine veraenderten oder zusaetzlichen Requests.
