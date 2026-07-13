from __future__ import annotations
import json
import re
from copy import deepcopy
from pathlib import Path
from common import load_har, load_scope, save_json, sanitize_url

RE_EMAIL = re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.I)
RE_BEARER = re.compile(r'Bearer\s+[A-Za-z0-9._~+/=-]+', re.I)


def redact_text(value: str) -> str:
    value = RE_BEARER.sub('Bearer <REDACTED>', value)
    value = RE_EMAIL.sub('<EMAIL>', value)
    return value


def redact_json(value, keys: set[str]):
    if isinstance(value, dict):
        return {k: ('<REDACTED>' if k.lower() in keys else redact_json(v, keys)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_json(v, keys) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_har(source: Path, destination: Path) -> None:
    scope = load_scope()
    privacy = scope.get('privacy', {})
    header_names = {x.lower() for x in privacy.get('redact_headers', [])}
    query_names = {x.lower() for x in privacy.get('redact_query_parameters', [])}
    json_keys = {x.lower() for x in privacy.get('redact_json_keys', [])}

    har = deepcopy(load_har(source))
    for entry in har.get('log', {}).get('entries', []):
        req = entry.get('request', {})
        req['url'] = sanitize_url(req.get('url', ''), query_names)
        for header in req.get('headers', []):
            if header.get('name', '').lower() in header_names:
                header['value'] = '<REDACTED>'
            else:
                header['value'] = redact_text(str(header.get('value', '')))
        post = req.get('postData')
        if isinstance(post, dict) and isinstance(post.get('text'), str):
            try:
                post['text'] = json.dumps(redact_json(json.loads(post['text']), json_keys), ensure_ascii=False)
            except Exception:
                post['text'] = redact_text(post['text'])

        resp = entry.get('response', {})
        for header in resp.get('headers', []):
            if header.get('name', '').lower() in header_names:
                header['value'] = '<REDACTED>'
            else:
                header['value'] = redact_text(str(header.get('value', '')))
        content = resp.get('content', {})
        if isinstance(content.get('text'), str):
            try:
                content['text'] = json.dumps(redact_json(json.loads(content['text']), json_keys), ensure_ascii=False)
            except Exception:
                content['text'] = redact_text(content['text'])

    save_json(destination, har)
