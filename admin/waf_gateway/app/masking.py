from __future__ import annotations

from typing import Dict


SENSITIVE_HEADERS = {"authorization", "cookie"}


def mask_headers(headers: Dict[str, str]) -> Dict[str, str]:
    masked: Dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            masked[k] = "***"
        else:
            masked[k] = v
    return masked


def truncate_value(value: str, max_len: int = 256) -> str:
    if len(value) > max_len:
        return value[: max_len] + "..."
    return value
