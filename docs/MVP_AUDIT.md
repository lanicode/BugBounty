# Audit des bisherigen MVP

## Gesamturteil

Der MVP ist ein brauchbarer Lernprototyp für passive Auswertung, aber keine belastbare Sicherheitsgrenze und keine geeignete Basis für parallelen Produktivbetrieb.

## Kritische Punkte

1. **Out-of-Scope-Verkehr wird nicht blockiert.** `playwright/record.mjs` registriert nur einen `request`-Listener und schreibt eine Meldung. Zu diesem Zeitpunkt wird der Request bereits ausgeführt. Die im README behauptete harte Allowlist wird daher nicht durchgesetzt.
2. **Unredigierte Daten werden zuerst vollständig gespeichert.** `recordHar.mode: full` und `content: embed` schreiben Cookies, Header und Inhalte in `input/.../session.har`. Die spätere Redaktion verhindert keine lokale Rohdatenspur.
3. **Der A/B-Vergleich filtert Scope nicht.** `endpoint_rows()` filtert erlaubte Hosts, `compare_rows()` dagegen nicht. Dadurch können Drittanbieter-Endpunkte in Kandidaten und Reports gelangen.
4. **Konfigurationsregeln sind deklarativ, aber wirkungslos.** `excluded_hosts`, `passive_only` und `max_pages_per_recording` werden nicht erzwungen.

## Hohe Risiken

- Profile und Sessions liegen unverschlüsselt im Dateisystem.
- Es gibt keine Rate-Limits, Request-Budgets oder globale Notabschaltung.
- Es gibt kein Register eigener Testobjekte und damit keinen maschinellen Eigentumsnachweis.
- Es gibt keine Trennung zwischen Testzielen und notwendigen Drittanbietern wie Login- oder CDN-Hosts.
- Redaktion deckt weder Form-Data, Multipart, Binärinhalte, WebSocket-Frames noch viele Token- und PII-Formate zuverlässig ab.
- Alle E-Mail-Adressen werden gleich ersetzt; dadurch gehen sichere Korrelationsinformationen verloren. Besser sind lokale HMAC-Pseudonyme.
- Es gibt keine Größen- oder Content-Type-Grenzen für Antwortkörper.

## Qualitätsprobleme

- Ein Statusunterschied oder nur in einem Konto beobachteter Endpunkt wird pauschal als hoch priorisiert. Das erzeugt viele normale, nicht sicherheitsrelevante Unterschiede.
- Pfadnormalisierung ist heuristisch und kennt keine Query-, JSON-, GraphQL- oder Sequenzsemantik.
- Response-Struktur, Eigentumsfluss, Rollen, Tenant-Zuordnung und Objektlebenszyklus werden nicht ausgewertet.
- Der Berichtsgenerator erzeugt Kandidaten, aber keine belastbare Evidenzkette.
- Abhängigkeiten sind nicht vollständig reproduzierbar gesperrt; Tests und Schema-Validierung fehlen.

## Konsequenz

Den alten MVP nicht als Schutzschicht für echte Programme skalieren. Zuerst Scope-Guard, datensparsame Erfassung, Ownership Ledger, Kampagnenvertrag und Policy-Tests implementieren.
