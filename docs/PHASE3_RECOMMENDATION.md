# Kleinster empfohlener Schritt für Phase 3

Der kleinste sinnvolle nächste Schritt ist ein **persistenzgebundener External-Action-Evaluator**, weiterhin ohne reale Plattformadapter oder externe Requests.

Konkret soll der Evaluator jede positive Policy-, Scope-, Ownership- und Human-Entscheidung aus einem atomaren, aktuellen `ControlPlaneStore`-Snapshot ableiten: Programm und Policy-Hash, Kampagnenrevision und vollständiger Vertragsdigest, erlaubte Assets, Account-Rolle, Ownership-Objekt, Budget sowie eine akzeptierte, proposal- und operatorgebundene Approval-Evidence. Caller-konstruierte Wahrheitswerte dürfen anschließend keinen Runner mehr freigeben.

Warum zuerst dieser Schritt: Phase 2 erzwingt Registry, Schema, Reihenfolge, Proposal-Bindung, Budget, Kill Switch und ausschließlich gebrandete Mock-Runner. Die Simulations-Gate-Entscheidungen selbst sind jedoch noch nicht an persistierte fachliche Evidence gekoppelt. Der Event-Schlüssel liegt bereits ausschließlich referenziert im macOS-Keychain; Phase 3 muss dafür Rotation und Wiederanlauf ergänzen, nicht erst einen Klartext-freien Speicher einführen. Danach folgen lokal authentifizierte Operator-Identität, signierte Approvals sowie Crash-/Mehrprozess-Tests.

Ausdrücklich nicht Teil dieses Schritts sind HackerOne/Bugcrowd, echte Accounts, E-Mail/TOTP/CAPTCHA-Automation, aktive Sicherheitstests, Report-Einreichung, LLM-gesteuerte Requests oder Verbindungen zu realen Zielen.
