from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict

from .settings import settings


@dataclass
class Bucket:
    tokens: float
    last_ts: float


class RateLimiter:
    def __init__(self) -> None:
        self.buckets: Dict[str, Bucket] = {}

    def allow(self, ip: str, suspicious: bool = False) -> bool:
        burst = settings.rate_limit_burst_suspicious if suspicious else settings.rate_limit_burst
        refill = settings.rate_limit_refill_per_sec
        now = time.time()
        bucket = self.buckets.get(ip, Bucket(tokens=burst, last_ts=now))
        elapsed = now - bucket.last_ts
        bucket.tokens = min(burst, bucket.tokens + elapsed * refill)
        bucket.last_ts = now
        if bucket.tokens < 1:
            self.buckets[ip] = bucket
            return False
        bucket.tokens -= 1
        self.buckets[ip] = bucket
        return True
