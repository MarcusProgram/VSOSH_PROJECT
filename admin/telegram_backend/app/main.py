from __future__ import annotations

import asyncio
from fastapi import FastAPI, Depends
from fastapi.responses import JSONResponse

from .settings import settings
from .db import init_db
from .events import router as events_router
from .commands import pull_commands, ack_commands
from .licenses import hash_license
from . import bot_runner

app = FastAPI(title="Telegram Backend")
app.include_router(events_router)


@app.on_event("startup")
async def startup() -> None:
    await init_db()
    bot_runner.start_bot()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/commands/pull")
async def api_pull(license_key_hash: str, cursor: int | None = None) -> dict[str, object]:
    items, next_cursor = await pull_commands(license_key_hash, cursor)
    return {"commands": items, "cursor": next_cursor}


@app.post("/api/v1/commands/ack")
async def api_ack(body: dict[str, list[int]]) -> dict[str, str]:
    ids = body.get("ids", [])
    await ack_commands(ids)
    return {"status": "ok"}
