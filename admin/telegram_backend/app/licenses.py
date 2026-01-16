from __future__ import annotations

import hashlib
import time
import aiosqlite

from fastapi import HTTPException

from .db import get_db


def hash_license(license_key: str) -> str:
    return hashlib.sha256(license_key.encode()).hexdigest()


async def insert_license(license_hash: str) -> None:
    async for db in get_db():
        await db.execute(
            "INSERT OR IGNORE INTO licenses (license_hash, activated_at) VALUES (?, ?)",
            (license_hash, None),
        )
        await db.commit()


async def activate_license(license_key: str, chat_id: int) -> str:
    license_hash = hash_license(license_key)
    async for db in get_db():
        cur = await db.execute(
            "SELECT chat_id FROM licenses WHERE license_hash = ?", (license_hash,)
        )
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="unknown license")
        if row["chat_id"] and row["chat_id"] != chat_id:
            raise HTTPException(status_code=401, detail="license already bound")
        await db.execute(
            "UPDATE licenses SET chat_id = ?, activated_at = ? WHERE license_hash = ?",
            (chat_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), license_hash),
        )
        await db.commit()
    return license_hash


async def check_access(chat_id: int) -> str:
    async for db in get_db():
        cur = await db.execute(
            "SELECT license_hash FROM licenses WHERE chat_id = ?", (chat_id,)
        )
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="chat not activated")
        return row["license_hash"]
    raise HTTPException(status_code=401, detail="chat not activated")


async def get_chat_for_license(license_hash: str) -> int | None:
    async for db in get_db():
        cur = await db.execute(
            "SELECT chat_id FROM licenses WHERE license_hash = ?", (license_hash,)
        )
        row = await cur.fetchone()
        if row:
            return row["chat_id"]
        return None
