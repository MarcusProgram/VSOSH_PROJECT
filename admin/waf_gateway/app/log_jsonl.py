from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import orjson

from .integrity_chain import IntegrityChain
from .settings import settings


class JsonlLogger:
    def __init__(self) -> None:
        self.log_path = settings.log_path
        self.chain = IntegrityChain(settings.hash_state_path)

    def _rotate(self) -> None:
        if not self.log_path.exists():
            return
        if self.log_path.stat().st_size < settings.log_rotate_bytes:
            return
        for idx in reversed(range(1, settings.log_rotate_keep + 1)):
            src = self.log_path.with_name(self.log_path.name + f".{idx}")
            dst = self.log_path.with_name(self.log_path.name + f".{idx+1}")
            if src.exists():
                if idx == settings.log_rotate_keep:
                    src.unlink()
                else:
                    src.rename(dst)
        self.log_path.rename(self.log_path.with_name(self.log_path.name + ".1"))

    def write(self, event: dict[str, Any]) -> None:
        payload = orjson.dumps(event, option=orjson.OPT_SORT_KEYS)
        prev_hash, entry_hash = self.chain.append(payload)
        event["prev_hash"] = prev_hash
        event["entry_hash"] = entry_hash
        line = orjson.dumps(event, option=orjson.OPT_SORT_KEYS).decode()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        self._rotate()


def get_logger() -> JsonlLogger:
    return JsonlLogger()
