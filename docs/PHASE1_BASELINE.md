# Phase-1-Baseline für Phase 2

Der letzte reine Phase-1-Commit ist:

```text
0f0f508765ebec663c2d09dc22fa408c1de46a4f
test: harden browser egress on real loopback chromium
```

Alle Phase-2-Diffs und Regressionen werden gegen diesen Commit bewertet. Der Commit enthält den vollständig getesteten Phase-1-Sicherheitskern einschließlich des echten Chromium-Loopback-Tests.

Phase-1-Sicherheitskern sind insbesondere `packages/config`, `packages/egress-guard`, `packages/redaction`, `packages/secret-store`, `packages/event-store`, `packages/policy`, `packages/audit-log`, `packages/recorder` und `apps/cli` in diesem Baseline-Stand.

Änderungen an diesen Pfaden sind nur erlaubt, wenn Phase 2 sie zwingend benötigt. Sie müssen in `PHASE2_SECURITY_CORE_CHANGES.md` markiert, begründet und durch eigene Regressionstests abgesichert werden.
