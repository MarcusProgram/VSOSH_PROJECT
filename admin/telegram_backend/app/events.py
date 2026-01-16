from __future__ import annotations

import json
import time
import sys
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from .hmac_security import verify_hmac
from .licenses import get_chat_for_license
from .templates import format_event_message
from .db import get_db
from . import bot_runner

router = APIRouter()


async def log_audit(action: str, details: str) -> None:
    async for db in get_db():
        await db.execute(
            "INSERT INTO audit (action, details, created_at) VALUES (?, ?, ?)",
            (action, details[:500], time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        await db.commit()


@router.post("/api/v1/event")
async def ingest_event(request: Request) -> JSONResponse:
    print("[events] POST /api/v1/event", file=sys.stderr)
    
    raw = await request.body()
    
    try:
        await verify_hmac(request, raw)
    except HTTPException as e:
        print(f"[events] HMAC error: {e.detail}", file=sys.stderr)
        raise
    
    try:
        payload: dict[str, Any] = json.loads(raw.decode())
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="bad json")
    
    license_hash = payload.get("license_key_hash")
    print(f"[events] license_hash: {license_hash[:16] if license_hash else 'NONE'}...", file=sys.stderr)
    
    if not license_hash:
        raise HTTPException(status_code=400, detail="missing license")
    
    chat_id = await get_chat_for_license(license_hash)
    print(f"[events] chat_id for license: {chat_id}", file=sys.stderr)
    
    if chat_id is None:
        print("[events] license not activated - no chat_id", file=sys.stderr)
        raise HTTPException(status_code=401, detail="license not activated")
    
    await log_audit("event", json.dumps({
        "license_hash": license_hash[:16],
        "request_id": payload.get("request_id", ""),
        "decision": payload.get("decision", ""),
    }))
    
    text = format_event_message(payload)
    print(f"[events] sending to chat_id={chat_id}: {text[:100]}...", file=sys.stderr)
    
    await bot_runner.send_message(chat_id, text, payload)
    
    print("[events] message sent successfully", file=sys.stderr)
    return JSONResponse({"status": "ok"})
