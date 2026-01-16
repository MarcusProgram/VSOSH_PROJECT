from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Tuple

import httpx

from .cache import DecisionCache
from .fingerprint import build_fingerprint
from .ip_blocklist import IPBlocklist
from .log_jsonl import get_logger
from .masking import mask_headers, truncate_value
from .normalization import normalize_request
from .rate_limit import RateLimiter
from .recommendations import map_recommendations
from .regex_engine import RegexEngine, load_engine
from .settings import settings
from .telegram_client import send_event


class MLUnavailable(Exception):
    pass


class DecisionEngine:
    def __init__(self) -> None:
        self.regex_engine: RegexEngine = load_engine()
        self.rate_limiter = RateLimiter()
        self.blocklist = IPBlocklist()
        self.cache = DecisionCache()
        self.logger = get_logger()
        self.sem = asyncio.Semaphore(settings.ml_concurrency)
        self.pending_waiters = 0
        self.failure_count = 0
        self.circuit_open_until = 0.0

    def _circuit_open(self) -> bool:
        return time.time() < self.circuit_open_until

    def _record_failure(self) -> None:
        self.failure_count += 1
        if self.failure_count >= settings.circuit_failures:
            self.circuit_open_until = time.time() + settings.circuit_cooldown_sec
            self.failure_count = 0

    def _record_success(self) -> None:
        self.failure_count = 0

    async def call_ml(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._circuit_open():
            raise MLUnavailable("circuit open")
        if self.sem.locked() and self.pending_waiters >= settings.ml_queue_limit:
            raise MLUnavailable("queue full")
        
        self.pending_waiters += 1
        try:
            async with self.sem:
                async with httpx.AsyncClient(timeout=settings.ml_timeout_ms / 1000) as client:
                    resp = await client.post(settings.ai_url, json=payload)
                if resp.status_code != 200:
                    self._record_failure()
                    raise MLUnavailable(f"status {resp.status_code}")
                self._record_success()
                return resp.json()
        except (httpx.HTTPError, asyncio.TimeoutError) as exc:
            self._record_failure()
            raise MLUnavailable(str(exc))
        finally:
            self.pending_waiters -= 1

    async def evaluate(self, request, client_ip: str, body_bytes: bytes) -> Tuple[str, dict[str, Any], dict[str, Any]]:
        request_id = uuid.uuid4().hex
        normalized = await normalize_request(request, body_bytes)
        headers_masked = mask_headers(normalized["headers"])

        if self.blocklist.is_blocked(client_ip):
            log_entry = self._build_log(
                request_id, client_ip, normalized, 0, [], "blocked", "ip block",
                "unknown", None, None, headers_masked, [], "block"
            )
            return "block", log_entry, {"reason": "ip blocked"}

        if not self.rate_limiter.allow(client_ip, suspicious=False):
            log_entry = self._build_log(
                request_id, client_ip, normalized, 0, [], "rate_limit", "rate limit",
                "unknown", None, None, headers_masked, [], "rate_limit"
            )
            return "rate_limit", log_entry, {}

        score, hits, suspected_param = self.regex_engine.analyze(normalized)
        categories = {h["category"] for h in hits}
        stage = "regex"
        ml_label: str | None = None
        ml_conf: float | None = None
        recommendation_ids = map_recommendations(categories)

        fingerprint = build_fingerprint(
            normalized["method"],
            normalized["path"],
            normalized["query"],
            normalized["content_type"],
            normalized.get("body", ""),
        )
        
        cached = self.cache.get(fingerprint)
        if cached:
            decision, ml_label, ml_conf, stage_cached = cached
            stage = "cache_hit"
            log_entry = self._build_log(
                request_id, client_ip, normalized, score, hits, stage, "cache",
                suspected_param, ml_label, ml_conf, headers_masked, recommendation_ids, decision
            )
            return decision, log_entry, {}

        # Двухэтапная фильтрация: regex -> ML
        # Если есть срабатывания regex (score > 0), вызываем ML и блокируем
        if score > 0 and len(hits) > 0:
            try:
                ml_payload = {
                    "method": normalized["method"],
                    "path": normalized["path"],
                    "query": normalized["query"],
                    "content_type": normalized["content_type"],
                    "body": normalized.get("body", "")[:2048],
                }
                ml_result = await self.call_ml(ml_payload)
                ml_label = ml_result.get("label")
                ml_conf = ml_result.get("confidence")
                stage = "regex+ml"
                
                # Если regex сработал - блокируем, ML дает дополнительную информацию
                decision = "block"
                if ml_label and ml_label != "BENIGN":
                    categories.add(ml_label)
                    recommendation_ids = map_recommendations(categories)
                    reason = f"🤖 ML: {ml_label} ({ml_conf:.0%}) + Regex: {categories}"
                else:
                    reason = f"🔍 Regex: {categories} (ML: {ml_label} {ml_conf:.0%})"
                
                log_entry = self._build_log(
                    request_id, client_ip, normalized, score, hits, stage, reason,
                    suspected_param, ml_label, ml_conf, headers_masked, recommendation_ids, decision
                )
                self.cache.set(fingerprint, (decision, ml_label, ml_conf, stage))
                return decision, log_entry, {"reason": reason}
                
            except MLUnavailable as exc:
                # Режим деградации: ML недоступен, блокируем по regex
                stage = "regex"
                decision = "block"
                reason = f"🔍 Regex: {categories}"
                log_entry = self._build_log(
                    request_id, client_ip, normalized, score, hits, stage, reason,
                    suspected_param, ml_label, ml_conf, headers_masked, recommendation_ids, decision
                )
                self.cache.set(fingerprint, (decision, ml_label, ml_conf, stage))
                return decision, log_entry, {"reason": reason}

        decision = "allow"
        log_entry = self._build_log(
            request_id, client_ip, normalized, score, hits, stage, "ok",
            suspected_param, ml_label, ml_conf, headers_masked, recommendation_ids, decision
        )
        self.cache.set(fingerprint, (decision, ml_label, ml_conf, stage))
        return decision, log_entry, {}

    def _build_log(
        self,
        request_id: str,
        client_ip: str,
        normalized: dict,
        regex_score: int,
        hits: list[dict[str, Any]],
        stage: str,
        reason: str,
        suspected_param: str,
        ml_label: str | None,
        ml_conf: float | None,
        headers: dict[str, str],
        recommendation_ids: list[str],
        decision: str,
    ) -> dict[str, Any]:
        endpoint = normalized.get("path", "")
        return {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_id": request_id,
            "client_ip": client_ip,
            "method": normalized.get("method"),
            "path": normalized.get("path"),
            "query": truncate_value(normalized.get("query", "")),
            "decision": decision,
            "status_code": 0,
            "latency_ms": 0,
            "stage": stage,
            "reason": reason,
            "regex_score": regex_score,
            "regex_hits": hits,
            "ml_label": ml_label,
            "ml_confidence": ml_conf,
            "suspected_param": suspected_param,
            "endpoint": endpoint,
            "recommendation_ids": recommendation_ids,
            "body_len": normalized.get("body_len", 0),
        }

    async def notify(self, decision: str, log_entry: dict[str, Any]) -> None:
        if decision != "block":
            return
        
        event = {
            "request_id": log_entry["request_id"],
            "decision": decision,
            "suspected_param": log_entry.get("suspected_param"),
            "category": None,
            "endpoint": log_entry.get("endpoint"),
            "client_ip": log_entry.get("client_ip"),
            "reason": log_entry.get("reason"),
            "recommendation_ids": log_entry.get("recommendation_ids"),
            "stage": log_entry.get("stage", "regex"),  # regex / ml / cache
            "ml_label": log_entry.get("ml_label"),
            "ml_confidence": log_entry.get("ml_confidence"),
        }
        if log_entry.get("regex_hits"):
            event["category"] = log_entry["regex_hits"][0].get("category")
        # Если ML определил категорию - используем её
        if log_entry.get("ml_label") and log_entry.get("ml_label") != "BENIGN":
            event["category"] = log_entry.get("ml_label")
        
        try:
            await send_event(event)
        except Exception:
            pass
