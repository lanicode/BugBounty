from __future__ import annotations
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_scope() -> dict:
    with open(ROOT / 'config' / 'scope.yaml', 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def load_har(path: Path) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def normalize_path(path: str) -> str:
    segments = []
    for segment in path.split('/'):
        if not segment:
            continue
        if re.fullmatch(r'\d+', segment):
            segments.append('{id}')
        elif re.fullmatch(r'[0-9a-fA-F-]{16,}', segment):
            segments.append('{id}')
        elif re.fullmatch(r'[A-Za-z0-9_-]{24,}', segment):
            segments.append('{id}')
        else:
            segments.append(segment)
    return '/' + '/'.join(segments)


def sanitize_url(url: str, sensitive_params: set[str]) -> str:
    parts = urlsplit(url)
    pairs = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        pairs.append((key, '<REDACTED>' if key.lower() in sensitive_params else value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ''))
