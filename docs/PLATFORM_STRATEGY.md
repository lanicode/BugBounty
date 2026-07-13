# Plattformstrategie

## HackerOne zuerst

Für maximale Automatisierung eignet sich ein HackerOne-first-Ansatz, weil die offizielle Hacker API Programme, Programmdetails, strukturierte Scopes, Ausschlüsse, Reports und Report Intents abbildet. Ein Adapter kann daher Auswahl, Scope-Synchronisierung, Drafting, Anhänge, Submission und Monitoring ohne inoffizielle Browser-Endpunkte integrieren, sofern das eigene Konto API-Zugang besitzt.

Empfohlene Modi:

- `draft_only`: Reports und Anhänge vorbereiten, keine Einreichung.
- `batch_approval`: mehrere fertige Reports in einer lokalen Übersicht freigeben und danach über die offizielle API senden.
- `auto_submit`: nur nach stabiler Historie, sehr hohem Confidence-Threshold und ausdrücklicher Kampagnenfreigabe; standardmäßig deaktiviert.

## Bugcrowd und weitere Plattformen

Zuerst prüfen, welche offiziellen API-Schreibrechte das konkrete Forscherkonto erhält. Wo keine dokumentierte Researcher-Submission-API verfügbar ist, nur einen Entwurf oder ein vorausgefülltes Formular erzeugen. Keine undokumentierten internen Endpunkte automatisieren.

## Warum nicht sofort mehrere Plattformen

Jede Plattform hat andere Scope-Modelle, Pflichtfelder, Severity-Taxonomien, Limits und Authentifizierungsabläufe. Eine solide, messbar sichere Pipeline auf einer Plattform bringt mehr als mehrere fragile Browserbots.
