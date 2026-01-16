from __future__ import annotations

import regex
import yaml
from pathlib import Path
from typing import Any, Dict, List, Tuple

RULES_FILE = Path(__file__).parent / "rules.yaml"


class RegexRule:
    def __init__(self, data: dict) -> None:
        flags = regex.IGNORECASE if data.get("ignore_case") else 0
        self.id = data["id"]
        self.category = data["category"]
        self.description = data.get("description", "")
        self.target = data.get("target", "query")
        self.weight = int(data.get("weight", 1))
        self.pattern = regex.compile(data["pattern"], flags=flags)


class RegexEngine:
    def __init__(self) -> None:
        self.rules: List[RegexRule] = []
        self.load_rules()

    def load_rules(self) -> None:
        data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
        self.rules = [RegexRule(item) for item in data]

    def reload(self) -> None:
        self.load_rules()

    def analyze(self, req: dict) -> Tuple[int, List[dict], str]:
        hits: List[dict] = []
        categories: set[str] = set()
        suspected_param = "unknown"
        score = 0
        for rule in self.rules:
            target_data = self._select_target(rule.target, req)
            match, param = self._match_rule(rule, target_data, req)
            if match:
                categories.add(rule.category)
                hits.append(
                    {
                        "id": rule.id,
                        "category": rule.category,
                        "target": rule.target,
                        "description": rule.description,
                    }
                )
                if param:
                    suspected_param = param
                score += rule.weight
        if len(categories) > 1:
            score += 2
        if "%25" in req.get("query", ""):
            score += 1
        return score, hits, suspected_param

    def _select_target(self, target: str, req: dict) -> str:
        if target == "path":
            return req.get("path", "")
        if target == "body":
            return req.get("body", "")
        if target == "headers":
            return " ".join(f"{k}:{v}" for k, v in req.get("headers", {}).items())
        return req.get("query", "")

    def _match_rule(self, rule: RegexRule, data: str, req: dict) -> Tuple[bool, str | None]:
        try:
            if rule.target == "query":
                for key, values in req.get("params", {}).items():
                    for v in values:
                        if rule.pattern.search(f"{key}={v}", timeout=0.01):
                            return True, key
            if rule.pattern.search(data, timeout=0.01):
                return True, None
        except regex.TimeoutError:
            return False, None
        return False, None


def load_engine() -> RegexEngine:
    return RegexEngine()
