from __future__ import annotations
import csv
import json
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit
from common import load_har, load_scope, normalize_path


def entry_signature(entry: dict) -> tuple[str, str, str]:
    req = entry.get('request', {})
    parts = urlsplit(req.get('url', ''))
    return req.get('method', ''), parts.hostname or '', normalize_path(parts.path)


def endpoint_rows(hars: list[tuple[str, dict]]) -> list[dict]:
    scope = load_scope()
    allowed = set(scope.get('allowed_hosts', []))
    grouped = defaultdict(lambda: {'accounts': set(), 'statuses': set(), 'count': 0})
    for account, har in hars:
        for entry in har.get('log', {}).get('entries', []):
            method, host, path = entry_signature(entry)
            if host not in allowed:
                continue
            key = (method, host, path)
            grouped[key]['accounts'].add(account)
            grouped[key]['statuses'].add(str(entry.get('response', {}).get('status', '')))
            grouped[key]['count'] += 1
    rows = []
    for (method, host, path), data in sorted(grouped.items()):
        rows.append({
            'method': method,
            'host': host,
            'path_template': path,
            'accounts_seen': ','.join(sorted(data['accounts'])),
            'statuses': ','.join(sorted(data['statuses'])),
            'request_count': data['count']
        })
    return rows


def compare_rows(har_a: dict, har_b: dict) -> list[dict]:
    def index(har):
        idx = defaultdict(list)
        for entry in har.get('log', {}).get('entries', []):
            idx[entry_signature(entry)].append(entry)
        return idx
    a, b = index(har_a), index(har_b)
    rows = []
    for key in sorted(set(a) | set(b)):
        method, host, path = key
        statuses_a = sorted({str(x.get('response', {}).get('status', '')) for x in a.get(key, [])})
        statuses_b = sorted({str(x.get('response', {}).get('status', '')) for x in b.get(key, [])})
        only = 'both'
        if key not in a:
            only = 'account-b-only'
        elif key not in b:
            only = 'account-a-only'
        rows.append({
            'method': method,
            'host': host,
            'path_template': path,
            'presence': only,
            'status_a': ','.join(statuses_a),
            'status_b': ','.join(statuses_b),
            'candidate_priority': 'high' if only != 'both' or statuses_a != statuses_b else 'review'
        })
    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text('', encoding='utf-8')
        return
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
