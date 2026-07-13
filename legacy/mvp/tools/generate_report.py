from __future__ import annotations
from pathlib import Path
import csv


def generate(diff_csv: Path, destination: Path) -> None:
    rows = []
    if diff_csv.exists() and diff_csv.stat().st_size:
        with open(diff_csv, newline='', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))
    interesting = [r for r in rows if r.get('candidate_priority') == 'high'][:10]
    lines = [
        '# Bug-Bounty Review Draft', '',
        '> Noch kein bestaetigter Sicherheitsfund. Diese Datei enthaelt nur passive Analyse-Kandidaten.', '',
        '## Programm', '', '- Name: TODO', '- Policy-URL: TODO', '- Scope geprueft: TODO', '',
        '## Passive Kandidaten', ''
    ]
    if not interesting:
        lines.append('Keine auffaelligen A/B-Unterschiede erkannt.')
    for i, row in enumerate(interesting, 1):
        lines.extend([
            f'### Kandidat {i}', '',
            f"- Endpunkt: `{row.get('method')} https://{row.get('host')}{row.get('path_template')}`",
            f"- Beobachtung: `{row.get('presence')}`",
            f"- Status Konto A: `{row.get('status_a') or 'n/a'}`",
            f"- Status Konto B: `{row.get('status_b') or 'n/a'}`",
            '- Bewertung: Nur passiv beobachtet; noch nicht als Schwachstelle bestaetigt.',
            '- Naechster Schritt: Scope und Eigentum der Testobjekte manuell kontrollieren.', ''
        ])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text('\n'.join(lines), encoding='utf-8')
