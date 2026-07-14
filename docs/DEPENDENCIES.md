# Abhängigkeiten

Alle Versionen sind im Lockfile exakt aufgelöst.

- `ajv`, `ajv-formats`: Draft-2020-12-JSON-Schema- und RFC-3339-Validierung. Validierungsdetails werden vor Ausgabe reduziert.
- `yaml`: YAML-Parser; geparste Daten bleiben bis zur AJV-Validierung untrusted.
- `playwright`: Browser-Routing-API für den kontextweiten Guard und der im
  selben exakt gepinnten Paket enthaltene Playwright-Test-Runner. Phase 7
  startet Browser ausschließlich aus `tests/browser` gegen ephemere
  `127.0.0.1`-Server; es wurde keine neue Abhängigkeit ergänzt.
- `typescript`, `tsx`, `@types/node`: strikter Build und lokale CLI-Ausführung.
- `vitest`, `@vitest/coverage-v8`: isolierte Tests und V8-Coverage.
- `fast-check`: generative Tests für URL- und Redaktionsinvarianten.
- `eslint`, `@eslint/js`, `typescript-eslint`, `prettier`: statische Sicherheits- und Formatkontrollen.

Kryptografie, HMAC, Dateiatomizität und Keychain-Prozessaufruf verwenden ausschließlich Node-Standardbibliotheken. Produktionscode führt keine Shell aus; `security` wird mit fester Executable- und Argumentliste via `execFile` aufgerufen.
