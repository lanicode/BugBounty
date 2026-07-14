# HackerOne – manueller JSON-Import

## Zweck und Vertrauensstatus

Der manuelle Import hält die lokale Review-Funktion ohne persönlichen
HackerOne-Token nutzbar. Er ist ein reiner Offline-Fallback und keine
Plattformverifikation.

Jeder erzeugte Datensatz erhält unveränderlich:

```text
source: manual_unverified
```

Er liegt in einer eigenen Tabelle und erhält ein `h1m_`-Präfix. Die
Anwendung mischt ihn nicht mit `hackerone_api_authenticated`. Ein manueller
Datensatz kann niemals Quelle eines API-Detailrequests sein.

Import bedeutet weder Policy-Annahme noch Automationsfreigabe. Der Snapshot
beginnt immer mit ausstehender lokaler Zustimmung. Eine spätere Annahme ist
nur für die exakt aktuelle Snapshotversion und nur über frische signierte
Operator-Evidence möglich.

## Eingabe- und Transportgrenzen

- Format: ausschließlich JSON
- Schema-Version: `1`
- maximale UTF-8-Quellgröße: 1.048.576 Bytes
- HTTP-JSON-Hülle der Dashboardroute: höchstens 2.098.176 Bytes
- keine BOM
- keine doppelten Schlüssel
- keine unbekannten Felder auf irgendeiner Ebene
- höchstens 2.000 Scopes und 2.000 Ausschlüsse
- eindeutige Scope-IDs und eindeutige Ausschluss-IDs
- Zeitstempel als gültige JSON-Schema-`date-time`-Werte oder `null`

Die größere HTTP-Hüllengrenze erlaubt JSON-Escaping, erweitert aber nicht die
1-MiB-Grenze der eigentlichen Importquelle. Die Route
`/api/hackerone/manual-import` benötigt sicheren Core, exakten Loopback-
Origin, CSRF, `application/json`, gültige `Content-Length` und exakt das Feld
`source`. Der Import selbst öffnet keine Netzwerkverbindung.

`source`, `synchronizedAt`, `importedAt` und `assetIdentifierDigest` dürfen
nicht im Importdokument stehen. Die Anwendung leitet sie lokal ab. Jedes
zusätzliche Feld führt zur Ablehnung.

## Vollständiges synthetisches Beispiel

Der reservierte `.invalid`-Name ist ausschließlich ein Metadatenwert. Die
Anwendung löst oder kontaktiert ihn nicht.

```json
{
  "version": 1,
  "program": {
    "hackerOneId": "manual-example-001",
    "handle": "manual_example",
    "name": "Manual Example Program",
    "currency": "USD",
    "policy": "Locally supplied policy text. Review against the authoritative source before acceptance.",
    "submissionState": "open",
    "programState": "public_mode",
    "offersBounties": false,
    "openScope": false,
    "goldStandardSafeHarbor": false,
    "bookmarked": false,
    "ownReportCount": 0,
    "ownValidReportCount": 0,
    "startedAcceptingAt": null,
    "createdAt": null,
    "updatedAt": "2026-07-01T12:00:00Z"
  },
  "structuredScopes": [
    {
      "id": "manual-scope-001",
      "assetType": "URL",
      "assetIdentifier": "https://manual-example.invalid/metadata-only",
      "eligibleForSubmission": true,
      "eligibleForBounty": false,
      "instruction": "Treat as metadata only. Do not request this identifier.",
      "maximumSeverity": "medium",
      "createdAt": null,
      "updatedAt": null,
      "confidentialityRequirement": "high",
      "integrityRequirement": null,
      "availabilityRequirement": null
    }
  ],
  "scopeExclusions": [
    {
      "id": "manual-exclusion-001",
      "category": "Synthetic excluded activity",
      "details": "No automated requests.",
      "createdAt": null,
      "updatedAt": null
    }
  ]
}
```

Alle Felder sind Pflichtfelder, auch wenn ihr Wert `null`, `0`, `false`, eine
leere Liste oder bei Policy, Instruction und Details ein leerer String sein
darf.

## Feldübersicht

### Programm

| Feld                                                                  | Typ / Grenze                      |
| --------------------------------------------------------------------- | --------------------------------- |
| `hackerOneId`                                                         | String, 1–128 Zeichen             |
| `handle`                                                              | `[A-Za-z0-9_-]`, 1–128 Zeichen    |
| `name`                                                                | String, 1–512 Zeichen             |
| `currency`                                                            | String, 1–16 Zeichen              |
| `policy`                                                              | String, höchstens 262.144 Zeichen |
| `submissionState`, `programState`                                     | String, 1–128 Zeichen             |
| `offersBounties`, `openScope`, `goldStandardSafeHarbor`, `bookmarked` | Boolean                           |
| `ownReportCount`, `ownValidReportCount`                               | nicht negative Integer            |
| `startedAcceptingAt`, `createdAt`, `updatedAt`                        | `date-time` oder `null`           |

NUL-Zeichen sind in Textfeldern verboten.

### Structured Scope

Jeder Scope benötigt:

- `id`: 1–128 Zeichen;
- `assetType`: 1–128 Zeichen;
- `assetIdentifier`: 1–4.096 Zeichen;
- `eligibleForSubmission` und `eligibleForBounty`: Boolean;
- `instruction`: höchstens 65.536 Zeichen;
- `maximumSeverity`: 1–64 Zeichen oder `null`;
- `createdAt`, `updatedAt`: `date-time` oder `null`;
- `confidentialityRequirement`, `integrityRequirement`,
  `availabilityRequirement`: 1–64 Zeichen oder `null`.

Der SHA-256-Digest des Asset-Identifier wird lokal berechnet. Asset-Identifier
werden gespeichert, als Plain Text angezeigt, kopiert und gehasht. Sie werden
nicht aufgelöst, geöffnet, angepingt, gecrawlt oder per Browser/HTTP
angefragt.

### Scope Exclusion

Jeder Ausschluss benötigt:

- `id`: 1–128 Zeichen;
- `category`: 1–256 Zeichen;
- `details`: höchstens 65.536 Zeichen;
- `createdAt`, `updatedAt`: `date-time` oder `null`.

ID und Kategorie dürfen nicht leer sein.

## Import über das Dashboard

1. Sicheren lokalen Core starten. Die Setup-Shell blockiert den Import.
2. Die HackerOne-Sektion öffnen.
3. Das vollständige JSON in **Manueller JSON-Import** einfügen.
4. **JSON lokal importieren** wählen.
5. Den Datensatz mit der Kennzeichnung **manuell und ungeprüft** auswählen.
6. Vollständigen Policytext, Scopes, Ausschlüsse, Digests, Suitability und
   Quelle prüfen.
7. Optional die ausgewählte lokale Referenz ausdrücklich an eine lokale
   Kampagne binden.
8. Für eine Annahme den globalen Kill Switch signiert freigeben, Checkbox und
   exakten aktuellen Snapshot prüfen und die separate signierte
   Policy-Acceptance auslösen.

Der globale External-Integration-Schalter und HackerOne-Credentials sind für
den rein lokalen Import nicht erforderlich. Die Policy-Annahme bleibt
trotzdem eine separate signierte Operatoraktion. Sie ist keine Annahme von
HackerOne-Nutzungsbedingungen und keine externe Freigabe.

Programmzeile und initialer append-only Snapshot werden in einer einzigen
lokalen SQLite-Transaktion geschrieben. Eine ID-/Handle-Kollision, ein
Snapshot-Bindingfehler oder ein Persistenzfehler rollt beides zurück; es gibt
weder ein Programm ohne Snapshot noch einen Snapshot ohne Programm.

Der UI-Detailsync kann bei einem manuellen Datensatz weiterhin sichtbar sein.
Der Backend-Store blockiert ihn mit
`HACKERONE_SYNCED_PROGRAM_SOURCE_INVALID`, weil ausschließlich aktive
`h1a_`-Referenzen synchronisierbar sind.

## Update- und Fehlerverhalten

Ein erneuter Import mit derselben manuellen ID oder demselben Handle ist kein
Update und wird abgewiesen. Pilot A besitzt keinen Editor und keine
automatische Zusammenführung. Ein Parse-, Schema-, Größen-, Duplicate- oder
Persistenzfehler erzeugt weder einen partiellen Datensatz noch einen
partiellen Snapshot.

| Code                                        | Ursache                                                   |
| ------------------------------------------- | --------------------------------------------------------- |
| `HACKERONE_DASHBOARD_MANUAL_IMPORT_INVALID` | HTTP-Hülle falsch, leer oder außerhalb ihrer Grenze       |
| `HACKERONE_MANUAL_IMPORT_SIZE_INVALID`      | Quelle leer oder größer als 1 MiB                         |
| `HACKERONE_MANUAL_IMPORT_JSON_INVALID`      | ungültiges/mehrdeutiges JSON, BOM oder doppelte Schlüssel |
| `HACKERONE_MANUAL_IMPORT_SCHEMA_INVALID`    | fehlendes, falsch typisiertes oder unbekanntes Feld       |
| `HACKERONE_MANUAL_SCOPE_DUPLICATE`          | doppelte Scope-ID                                         |
| `HACKERONE_MANUAL_EXCLUSION_DUPLICATE`      | doppelte Ausschluss-ID                                    |
| `HACKERONE_MANUAL_PROGRAM_WRITE_FAILED`     | lokale ID-/Handle-Kollision oder Persistenzfehler         |

Fehlerantworten enthalten weder den Importbody noch einzelne
potenziell sensitive Metadaten.
