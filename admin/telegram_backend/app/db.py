from __future__ import annotations

import aiosqlite
from pathlib import Path
from typing import AsyncIterator

from .settings import settings


async def get_db() -> AsyncIterator[aiosqlite.Connection]:
    db = await aiosqlite.connect(settings.db_path)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()


async def init_db() -> None:
    Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(settings.db_path)
    schema_path = Path(__file__).parent / "schema.sql"
    sql = schema_path.read_text(encoding="utf-8")
    await db.executescript(sql)
    await db.commit()
    await db.close()
