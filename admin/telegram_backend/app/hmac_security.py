from __future__ import annotations

import hmac
import time
from hashlib import sha256

from fastapi import HTTPException, Request

from .settings import settings
from .replay_protection import check_and_store_nonce


async def verify_hmac(request: Request, raw_body: bytes) -> None:
    timestamp = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    signature = request.headers.get("X-Signature")
    if not timestamp or not nonce or not signature:
        raise HTTPException(status_code=401, detail="missing hmac headers")
    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid timestamp")
    now = int(time.time())
    if abs(now - ts) > settings.timestamp_skew_sec:
        raise HTTPException(status_code=401, detail="timestamp skew")
    await check_and_store_nonce(nonce, ts)
    expected = hmac.new(
        settings.hmac_secret.encode(),
        f"{timestamp}\n{nonce}\n".encode() + raw_body,
        sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="invalid signature")
