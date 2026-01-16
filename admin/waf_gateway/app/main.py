from __future__ import annotations

import asyncio
import sys
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .command_polling import CommandPoller
from .decision_engine import DecisionEngine
from .proxy import ProxyService

app = FastAPI(title="WAF Gateway")
engine = DecisionEngine()
proxy_service = ProxyService(engine)
poller = CommandPoller(engine.regex_engine, engine.blocklist)


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(poller.run_forever())


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/waf/blocklist")
async def get_blocklist() -> dict:
    """Показать заблокированные IP"""
    import time
    now = time.time()
    blocks = {ip: int(exp - now) for ip, exp in engine.blocklist.blocks.items() if exp > now}
    return {"blocked_ips": blocks}


@app.post("/waf/block/{ip}")
async def block_ip(ip: str, ttl: int = 3600) -> dict:
    """Заблокировать IP"""
    engine.blocklist.block(ip, ttl)
    print(f"[WAF] Blocked IP: {ip} for {ttl}s", file=sys.stderr)
    return {"status": "blocked", "ip": ip, "ttl": ttl}


@app.post("/waf/unblock/{ip}")
async def unblock_ip(ip: str) -> dict:
    """Разблокировать IP"""
    engine.blocklist.unblock(ip)
    print(f"[WAF] Unblocked IP: {ip}", file=sys.stderr)
    return {"status": "unblocked", "ip": ip}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy(path: str, request: Request):
    return await proxy_service.handle(request)
