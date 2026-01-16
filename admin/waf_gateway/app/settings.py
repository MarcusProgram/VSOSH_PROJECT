from __future__ import annotations

from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    upstream_url: str = "http://demo_upstream:8001"
    ai_url: str = Field(default="http://ai_analyzer:8002/analyze", alias="AI_URL")
    telegram_backend_url: str = Field(default="", alias="TELEGRAM_BACKEND_URL")
    control_plane_hmac_secret: str = Field(default="", alias="CONTROL_PLANE_HMAC_SECRET")
    license_key_hash: str = Field(default="", alias="LICENSE_KEY_HASH")
    request_timeout_ms: int = 150
    ml_timeout_ms: int = 150
    ml_queue_limit: int = 32
    ml_concurrency: int = 4
    circuit_failures: int = 5
    circuit_cooldown_sec: int = 30
    suspicion_threshold: int = 4  # Порог для вызова ML (если score >= 4)
    normalize_decode_rounds: int = 2
    body_truncate: int = 8192
    rate_limit_burst: int = 30
    rate_limit_refill_per_sec: float = 10.0
    rate_limit_burst_suspicious: int = 10
    block_ttl_sec: int = 600
    log_path: Path = Path("/data/logs/waf_events.jsonl")
    log_rotate_bytes: int = 10_000_000
    log_rotate_keep: int = 3
    hash_state_path: Path = Path("/data/logs/hash_state.json")
    ml_fail_closed: bool = False

    class Config:
        env_file = ".env"
        populate_by_name = True


settings = Settings()
