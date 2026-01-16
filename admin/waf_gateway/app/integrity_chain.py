from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Tuple


class IntegrityChain:
    def __init__(self, state_path: Path) -> None:
        self.state_path = state_path
        self.prev_hash = self._load_state()

    def _load_state(self) -> str:
        if self.state_path.exists():
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                return data.get("prev_hash", "0" * 64)
            except Exception:
                return "0" * 64
        return "0" * 64

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps({"prev_hash": self.prev_hash}), encoding="utf-8")

    def append(self, payload_bytes: bytes) -> Tuple[str, str]:
        entry_hash = hashlib.sha256(self.prev_hash.encode() + payload_bytes).hexdigest()
        prev = self.prev_hash
        self.prev_hash = entry_hash
        self._save_state()
        return prev, entry_hash
