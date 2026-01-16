from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from .ip_blocklist import IPBlocklist
from .regex_engine import RegexEngine, RegexRule
from .settings import settings


class CommandPoller:
    def __init__(self, engine: RegexEngine, blocklist: IPBlocklist) -> None:
        self.engine = engine
        self.blocklist = blocklist
        self.running = False

    async def apply_command(self, cmd: dict[str, Any]) -> None:
        import sys
        cmd_type = cmd.get("command_type")
        payload = cmd.get("payload", {})
        print(f"[command_polling] Applying: {cmd_type} {payload}", file=sys.stderr)
        if cmd_type == "block_ip":
            ip = payload.get("ip")
            ttl = payload.get("ttl")
            if ip:
                self.blocklist.block(ip, ttl)
                print(f"[command_polling] BLOCKED IP: {ip} for {ttl}s", file=sys.stderr)
        elif cmd_type == "unblock_ip":
            ip = payload.get("ip")
            if ip:
                self.blocklist.unblock(ip)
                print(f"[command_polling] UNBLOCKED IP: {ip}", file=sys.stderr)
        elif cmd_type == "add_rule":
            try:
                rule = RegexRule(
                    {
                        "id": f"CMD_{payload.get('pattern','')}",
                        "category": payload.get("category", "XSS"),
                        "description": "добавлено из Telegram",
                        "target": payload.get("target", "query"),
                        "pattern": payload.get("pattern", ".*"),
                        "ignore_case": True,
                        "weight": int(payload.get("weight", 2)),
                    }
                )
                self.engine.rules.append(rule)
            except Exception:
                return

    async def poll_once(self) -> None:
        if not settings.license_key_hash:
            return
        url = (
            settings.telegram_backend_url.rstrip("/")
            + f"/api/v1/commands/pull?license_key_hash={settings.license_key_hash}"
        )
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return
        if resp.status_code != 200:
            return
        try:
            data = resp.json()
        except ValueError:
            return
        cmds = data.get("commands", [])
        if not cmds:
            return
        ids = []
        for cmd in cmds:
            await self.apply_command(cmd)
            ids.append(cmd.get("id"))
        ack_url = settings.telegram_backend_url.rstrip("/") + "/api/v1/commands/ack"
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                await client.post(ack_url, json={"ids": ids})
            except httpx.HTTPError:
                return

    async def run_forever(self) -> None:
        self.running = True
        while self.running:
            await self.poll_once()
            await asyncio.sleep(5)
