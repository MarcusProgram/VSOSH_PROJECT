from __future__ import annotations

import time
from typing import Dict

from .settings import settings


class IPBlocklist:
    def __init__(self) -> None:
        self.blocks: Dict[str, float] = {}

    def block(self, ip: str, ttl: int | None = None) -> None:
        expire = time.time() + (ttl or settings.block_ttl_sec)
        self.blocks[ip] = expire

    def unblock(self, ip: str) -> None:
        self.blocks.pop(ip, None)

    def is_blocked(self, ip: str) -> bool:
        now = time.time()
        to_remove = [addr for addr, exp in self.blocks.items() if exp < now]
        for addr in to_remove:
            self.blocks.pop(addr, None)
        exp = self.blocks.get(ip)
        return bool(exp and exp > now)
