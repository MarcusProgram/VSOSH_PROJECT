from __future__ import annotations

import json
import time
import aiosqlite

from typing import Any, List, Tuple

from .db import get_db


async def enqueue_command(license_hash: str, command_type: str, payload: dict[str, Any]) -> int:
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    async for db in get_db():
        cur = await db.execute(
            "INSERT INTO commands (license_hash, command_type, payload, created_at) VALUES (?, ?, ?, ?)",
            (license_hash, command_type, json.dumps(payload), created),
        )
        await db.commit()
        return cur.lastrowid
    return 0


async def pull_commands(license_hash: str, cursor: int | None) -> Tuple[list[dict[str, Any]], int]:
    async for db in get_db():
        if cursor is None:
            cur = await db.execute(
                "SELECT id, command_type, payload FROM commands WHERE license_hash = ? AND acked = 0 ORDER BY id ASC LIMIT 20",
                (license_hash,),
            )
        else:
            cur = await db.execute(
                "SELECT id, command_type, payload FROM commands WHERE license_hash = ? AND acked = 0 AND id > ? ORDER BY id ASC LIMIT 20",
                (license_hash, cursor),
            )
        rows = await cur.fetchall()
        next_cursor = cursor or 0
        items: list[dict[str, Any]] = []
        for row in rows:
            next_cursor = max(next_cursor, row["id"])
            items.append(
                {
                    "id": row["id"],
                    "command_type": row["command_type"],
                    "payload": json.loads(row["payload"]),
                }
            )
        return items, next_cursor
    return [], cursor or 0


async def ack_commands(ids: List[int]) -> None:
    if not ids:
        return
    async for db in get_db():
        await db.executemany("UPDATE commands SET acked = 1 WHERE id = ?", [(i,) for i in ids])
        await db.commit()
