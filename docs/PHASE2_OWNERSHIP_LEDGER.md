# Phase 2 – Ownership Ledger

Das Ownership Ledger akzeptiert ausschließlich lokal signierte Simulation-Receipts. Ein Caller kann Eigentum nicht durch ein beliebiges Objekt- oder Konto-Label behaupten.

## Invarianten

- Ein Objekt darf erst nach einem aktiven, signierten Account-Receipt registriert werden.
- Anwendung, Konto, Objekt und Policy-Hash werden exakt gebunden.
- Roh-Canaries werden sofort per HMAC ersetzt; Locator werden pseudonymisiert.
- Unbekannte, fremde, policy-abweichende oder pensionierte Objekte werden blockiert.
- Identische Receipts sind idempotent; widersprüchliche und Canary-kollidierende Receipts werden blockiert.
- Der optionale Produktionspfad journalisiert Events ausschließlich über den bestehenden AES-256-GCM-Eventstore. Tests verwenden nur den In-Memory-Secret-Store.
- Das Ledger führt keine externen Aktionen aus und importiert keinen HTTP- oder Browser-Client.
