from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple


class DecisionCache:
    def __init__(self, max_size: int = 512, ttl: int = 300) -> None:
        self.max_size = max_size
        self.ttl = ttl
        self.store: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        now = time.time()
        if key in self.store:
            ts, value = self.store[key]
            if now - ts <= self.ttl:
                return value
            del self.store[key]
        return None

    def set(self, key: str, value: Any) -> None:
        if len(self.store) >= self.max_size:
            oldest = sorted(self.store.items(), key=lambda kv: kv[1][0])[0][0]
            self.store.pop(oldest, None)
        self.store[key] = (time.time(), value)
