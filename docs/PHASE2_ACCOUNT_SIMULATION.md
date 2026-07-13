# Phase 2 – Account-Workflow-Simulation

Die Account-Komponente ist bewusst keine Kontoerstellung. Sie modelliert den vollständigen Freigabe- und Pause-/Resume-Ablauf ausschließlich in-process gegen `MockLocalAccountApplication`.

## Erzwungene Grenzen

- Keine URL, kein HTTP-/Browser-Client, kein E-Mail-Postfach und kein Secretwert in Vorschlägen.
- Keine Passwörter, TOTP-Codes, CAPTCHA-Antworten, Cookies oder Browser-Sessions.
- Jeder Vorschlag durchläuft Schema, Policy, Anwendungs-Scope, serielles Budget und deterministischen Mock-Runner.
- CAPTCHA, 2FA, Programmregeln, AGB und rechtliche Erklärungen erzeugen ausschließlich einen Pause-Checkpoint.
- Resume akzeptiert keinen Code und keine Zustimmung. Im Test markiert ausschließlich die Mock-Anwendung den menschlich erledigten Checkpoint als erfüllt.
- Externe Account-Adapter sind als `DisabledExternalAccountAdapter` vorhanden und schlagen immer geschlossen fehl.
- Auth-State-Persistierung und echte Account-Provisionierung bleiben zurückgestellt; der Phase-1-Secret- und Egress-Kern wurde nicht erweitert.
