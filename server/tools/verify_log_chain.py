#!/usr/bin/env python3
import json
import hashlib
import sys
from pathlib import Path


def compute_entry_hash(prev_hash: str, entry: dict) -> str:
    entry_copy = dict(entry)
    entry_copy.pop("prev_hash", None)
    entry_copy.pop("entry_hash", None)
    payload = json.dumps(entry_copy, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(prev_hash.encode() + payload).hexdigest()


def verify(path: Path) -> bool:
    if not path.exists():
        print(f"file not found: {path}")
        return False
    
    prev_hash = "0" * 64
    ok = True
    line_count = 0
    
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"line {line_no}: bad json: {e}")
                ok = False
                break
            
            expected = compute_entry_hash(prev_hash, entry)
            actual = entry.get("entry_hash", "")
            
            if actual != expected:
                print(f"line {line_no}: hash mismatch")
                ok = False
                break
            
            prev_hash = actual
            line_count += 1
    
    if ok:
        if line_count == 0:
            print("empty file")
        else:
            print(f"chain ok ({line_count} entries)")
    
    return ok


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python verify_log_chain.py <path>")
        sys.exit(1)
    
    path = Path(sys.argv[1])
    success = verify(path)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
