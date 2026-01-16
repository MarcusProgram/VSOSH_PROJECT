from __future__ import annotations

import urllib.parse
from typing import Dict, List, Tuple

from fastapi import Request

from .settings import settings


def percent_decode(value: str, rounds: int) -> str:
    decoded = value
    for _ in range(rounds):
        new_val = urllib.parse.unquote(decoded)
        if new_val == decoded:
            break
        decoded = new_val
    return decoded


def normalize_path(path: str) -> str:
    parts: List[str] = []
    for segment in path.split('/'):
        if segment in ('', '.'):
            continue
        if segment == '..':
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    return '/' + '/'.join(parts)


def canonical_query(query: str) -> Tuple[str, Dict[str, List[str]]]:
    parsed = urllib.parse.parse_qsl(query, keep_blank_values=True)
    decoded = [(percent_decode(k, settings.normalize_decode_rounds), percent_decode(v, settings.normalize_decode_rounds)) for k, v in parsed]
    decoded.sort(key=lambda kv: kv[0])
    canon = urllib.parse.urlencode(decoded, doseq=True)
    params: Dict[str, List[str]] = {}
    for k, v in decoded:
        params.setdefault(k, []).append(v)
    return canon, params


async def normalize_request(request: Request, body_bytes: bytes | None = None) -> dict:
    if body_bytes is None:
        body_bytes = await request.body()
    truncated_body = body_bytes[: settings.body_truncate]
    normalized_body = truncated_body.decode(errors="ignore") if truncated_body else ""
    path_decoded = percent_decode(request.url.path, settings.normalize_decode_rounds)
    norm_path = normalize_path(path_decoded)
    canon_query, params = canonical_query(request.url.query)
    headers = {k.lower(): v for k, v in request.headers.items()}
    return {
        "method": request.method.upper(),
        "path": norm_path,
        "query": canon_query,
        "params": params,
        "body": normalized_body,
        "body_bytes": body_bytes,
        "body_len": len(body_bytes),
        "headers": headers,
        "content_type": request.headers.get("content-type", ""),
    }
