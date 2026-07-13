from pathlib import Path
from common import ROOT, load_har, load_scope
from redact_har import redact_har
from analyze import endpoint_rows, compare_rows, write_csv
from generate_report import generate


def main() -> None:
    scope = load_scope()
    hosts = scope.get('allowed_hosts', [])
    if not hosts or any('example.com' in h for h in hosts):
        raise SystemExit('Bitte zuerst config/scope.yaml mit echtem autorisiertem Scope ausfuellen.')

    source_a = ROOT / 'input' / 'account-a' / 'session.har'
    source_b = ROOT / 'input' / 'account-b' / 'session.har'
    if not source_a.exists() or not source_b.exists():
        raise SystemExit('Es fehlen session.har-Dateien fuer Konto A oder Konto B.')

    out = ROOT / 'output'
    red_a = out / 'redacted-account-a.har'
    red_b = out / 'redacted-account-b.har'
    redact_har(source_a, red_a)
    redact_har(source_b, red_b)

    har_a, har_b = load_har(red_a), load_har(red_b)
    write_csv(out / 'endpoints.csv', endpoint_rows([('account-a', har_a), ('account-b', har_b)]))
    write_csv(out / 'account-differences.csv', compare_rows(har_a, har_b))
    generate(out / 'account-differences.csv', ROOT / 'reports' / 'draft-report.md')

    print('Analyse abgeschlossen:')
    print(f'- {out / "endpoints.csv"}')
    print(f'- {out / "account-differences.csv"}')
    print(f'- {ROOT / "reports" / "draft-report.md"}')


if __name__ == '__main__':
    main()
