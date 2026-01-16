from __future__ import annotations

import time
import aiosqlite

from fastapi import HTTPException

from .settings import settings
from .db import get_db


async def check_and_store_nonce(nonce: str, timestamp: int) -> None:
    async for db in get_db():
        await db.execute("DELETE FROM nonces WHERE created_at < ?", (int(time.time()) - settings.max_nonce_age_sec,))
        cur = await db.execute("SELECT nonce FROM nonces WHERE nonce = ?", (nonce,))
        if await cur.fetchone():
            raise HTTPException(status_code=401, detail="replay detected")
        await db.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", (nonce, timestamp))
        await db.commit()
