from __future__ import annotations
from typing import Any


CATEGORY_NAMES = {
    "SQLI": "SQL Injection",
    "XSS": "XSS",
    "TRAVERSAL": "Path Traversal",
    "CMD": "Command Injection",
    "SSRF": "SSRF",
}


def format_event_message(event: dict[str, Any]) -> str:
    """Форматирует событие атаки в сообщение для Telegram"""
    category = event.get("category", "unknown")
    endpoint = event.get("endpoint", "")
    client_ip = event.get("client_ip", "")
    reason = event.get("reason", "")
    suspected_param = event.get("suspected_param", "")
    stage = event.get("stage", "regex")
    ml_label = event.get("ml_label")
    ml_conf = event.get("ml_confidence")
    
    category_name = CATEGORY_NAMES.get(category, category)
    
    # Определяем метод детекции
    if ml_label and ml_conf:
        detection = f"🤖 ML: {ml_label} ({ml_conf:.0%}) + Regex"
    elif "ml" in stage.lower():
        detection = "🤖 ML-классификатор"
    else:
        detection = "🔍 Regex"
    
    lines = [
        "🚨 АТАКА ЗАБЛОКИРОВАНА",
        "",
        f"Тип: {category_name}",
        f"IP: {client_ip}",
        f"Endpoint: {endpoint}",
    ]
    
    if suspected_param and suspected_param != "unknown":
        lines.append(f"Параметр: {suspected_param}")
    
    lines.append(f"Детекция: {detection}")
    
    return "\n".join(lines)
