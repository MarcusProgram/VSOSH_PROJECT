from __future__ import annotations

import hmac
import time
import uuid
import sys
from hashlib import sha256
from typing import Any

import httpx
import orjson

from .settings import settings


async def send_event(event: dict[str, Any]) -> None:
    print(f"[telegram_client] send_event called", file=sys.stderr)
    
    if not settings.telegram_backend_url:
        print("[telegram_client] ERROR: TELEGRAM_BACKEND_URL not set", file=sys.stderr)
        return
    
    if not settings.control_plane_hmac_secret:
        print("[telegram_client] ERROR: CONTROL_PLANE_HMAC_SECRET not set", file=sys.stderr)
        return
    
    if not settings.license_key_hash:
        print("[telegram_client] ERROR: LICENSE_KEY_HASH not set", file=sys.stderr)
        return
    
    print(f"[telegram_client] backend_url: {settings.telegram_backend_url}", file=sys.stderr)
    print(f"[telegram_client] license_hash: {settings.license_key_hash[:16]}...", file=sys.stderr)
    
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    event["license_key_hash"] = settings.license_key_hash
    body = orjson.dumps(event)
    
    signature = hmac.new(
        settings.control_plane_hmac_secret.encode(),
        f"{timestamp}\n{nonce}\n".encode() + body,
        sha256,
    ).hexdigest()
    
    headers = {
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
        "Content-Type": "application/json",
    }
    
    url = settings.telegram_backend_url.rstrip("/") + "/api/v1/event"
    print(f"[telegram_client] POST {url}", file=sys.stderr)
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, content=body, headers=headers)
            print(f"[telegram_client] response: {resp.status_code} {resp.text}", file=sys.stderr)
    except httpx.HTTPError as e:
        print(f"[telegram_client] HTTP ERROR: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[telegram_client] ERROR: {e}", file=sys.stderr)
