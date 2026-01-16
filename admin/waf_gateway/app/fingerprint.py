from __future__ import annotations

import hashlib


def build_fingerprint(method: str, path: str, query: str, content_type: str, body: str) -> str:
    canonical = "|".join([method.upper(), path, query, content_type, body])
    return hashlib.sha256(canonical.encode()).hexdigest()
