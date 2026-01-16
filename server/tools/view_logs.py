#!/usr/bin/env python3
import json
import sys
from pathlib import Path

COLORS = {
    "block": "\033[91m",
    "allow": "\033[92m",
    "rate_limit": "\033[93m",
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}

def c(text: str, color: str) -> str:
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

def fmt(e: dict) -> str:
    ts = e.get("timestamp_utc", "")[11:19]
    dec = e.get("decision", "?")
    ip = e.get("client_ip", "?")
    method = e.get("method", "?")
    path = e.get("path", "?")
    query = e.get("query", "")[:40]
    score = e.get("regex_score", 0)
    status = e.get("status_code", 0)
    ms = e.get("latency_ms", 0)
    
    hits = e.get("regex_hits", [])
    cats = ",".join(set(h.get("category", "") for h in hits)) or "-"
    
    dec_c = dec if dec in COLORS else "reset"
    dec_s = c(f"[{dec.upper():^6}]", dec_c)
    
    l1 = f"{c(ts,'dim')} {dec_s} {ip:>15} {method:>4} {path}"
    
    parts = []
    if query:
        parts.append(f"q={query}")
    if score:
        parts.append(f"score={score}")
    if cats != "-":
        parts.append(f"cat={cats}")
    parts.append(f"s={status}")
    parts.append(f"{ms}ms")
    
    l2 = "  " + " | ".join(parts)
    return f"{l1}\n{l2}"

def main():
    log_path = Path("data/logs/waf_events.jsonl")
    only_blocks = "--blocks" in sys.argv or "-b" in sys.argv
    limit = 100
    
    for arg in sys.argv[1:]:
        if arg.startswith("-n"):
            try:
                limit = int(arg[2:])
            except:
                pass
        elif not arg.startswith("-"):
            log_path = Path(arg)
    
    if not log_path.exists():
        print(f"Not found: {log_path}")
        return
    
    entries = []
    with open(log_path) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                e = json.loads(line)
                if only_blocks and e.get("decision") != "block":
                    continue
                entries.append(e)
            except:
                pass
    
    total = len(entries)
    blocks = sum(1 for e in entries if e.get("decision") == "block")
    
    for e in entries[-limit:]:
        print(fmt(e))
        print()
    
    print(c("=" * 50, "dim"))
    print(f"Showing {min(limit, len(entries))}/{total} | {c(str(blocks), 'block')} blocks")

if __name__ == "__main__":
    main()
