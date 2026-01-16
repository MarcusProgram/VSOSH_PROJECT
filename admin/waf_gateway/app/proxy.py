from __future__ import annotations

import time
from typing import Any

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from .decision_engine import DecisionEngine
from .settings import settings


class ProxyService:
    def __init__(self, engine: DecisionEngine) -> None:
        self.engine = engine

    async def handle(self, request: Request) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        body = await request.body()
        start = time.time()
        decision, log_entry, extra = await self.engine.evaluate(request, client_ip, body)
        headers = {"X-Request-Id": log_entry["request_id"]}
        
        if decision == "block":
            log_entry["status_code"] = 403
            log_entry["latency_ms"] = int((time.time() - start) * 1000)
            self.engine.logger.write(log_entry)
            await self.engine.notify(decision, log_entry)
            return JSONResponse(
                status_code=403,
                content={"request_id": log_entry["request_id"], "decision": "block", "reason": extra.get("reason")},
                headers=headers,
            )
        
        if decision == "rate_limit":
            log_entry["status_code"] = 429
            log_entry["latency_ms"] = int((time.time() - start) * 1000)
            self.engine.logger.write(log_entry)
            await self.engine.notify(decision, log_entry)
            return JSONResponse(
                status_code=429,
                content={"request_id": log_entry["request_id"], "decision": "rate_limit"},
                headers=headers,
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                fwd_headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
                upstream_resp = await client.request(
                    request.method,
                    self._compose_upstream_url(request),
                    content=body,
                    headers=fwd_headers,
                )
        except httpx.HTTPError:
            log_entry["status_code"] = 502
            log_entry["latency_ms"] = int((time.time() - start) * 1000)
            self.engine.logger.write(log_entry)
            return JSONResponse(
                status_code=502,
                content={"request_id": log_entry["request_id"], "error": "upstream unavailable"},
                headers=headers,
            )

        log_entry["status_code"] = upstream_resp.status_code
        log_entry["latency_ms"] = int((time.time() - start) * 1000)
        self.engine.logger.write(log_entry)
        
        hop_by_hop = {"connection", "keep-alive", "transfer-encoding", "te", "trailers", "upgrade"}
        resp_headers = {k: v for k, v in upstream_resp.headers.items() if k.lower() not in hop_by_hop}
        resp_headers.update(headers)
        
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=upstream_resp.headers.get("content-type"),
        )

    def _compose_upstream_url(self, request: Request) -> str:
        base = settings.upstream_url.rstrip("/")
        path = request.url.path
        query = request.url.query
        if query:
            return f"{base}{path}?{query}"
        return f"{base}{path}"
