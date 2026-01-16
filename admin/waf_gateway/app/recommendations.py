from __future__ import annotations

# Рекомендации по защите согласно OWASP Cheat Sheet Series
CATEGORY_RECS = {
    "SQLI": ["REC_SQL_PARAM", "REC_SQL_ORM", "REC_SQL_WHITELIST"],
    "XSS": ["REC_XSS_ENCODE", "REC_CSP", "REC_XSS_SANITIZE"],
    "TRAVERSAL": ["REC_PATH_WHITELIST", "REC_PATH_CHROOT", "REC_PATH_CANONICALIZE"],
    "CMD": ["REC_CMD_AVOID_SHELL", "REC_CMD_WHITELIST", "REC_CMD_ESCAPE"],
    "SSRF": ["REC_SSRF_ALLOWLIST", "REC_SSRF_VALIDATE", "REC_SSRF_NETWORK_ISOLATION"],
}

# Полное описание рекомендаций
RECOMMENDATION_DETAILS = {
    "REC_SQL_PARAM": {
        "title": "Используйте параметризованные запросы",
        "description": "Используйте prepared statements с параметрами вместо конкатенации строк. "
                       "Например: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"
    },
    "REC_SQL_ORM": {
        "title": "Используйте ORM",
        "description": "Используйте ORM (SQLAlchemy, Django ORM) для безопасной работы с БД",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
    },
    "REC_SQL_WHITELIST": {
        "title": "Валидируйте входные данные",
        "description": "Применяйте whitelist валидацию для ожидаемых значений (числа, enum)",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
    },
    "REC_XSS_ENCODE": {
        "title": "Экранируйте вывод",
        "description": "Применяйте HTML-экранирование (html.escape) при выводе пользовательских данных",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
    },
    "REC_XSS_SANITIZE": {
        "title": "Санитизация HTML",
        "description": "Используйте библиотеки для очистки HTML (bleach, DOMPurify)",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
    },
    "REC_CSP": {
        "title": "Content Security Policy",
        "description": "Настройте заголовок Content-Security-Policy для защиты от inline-скриптов",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
    },
    "REC_PATH_WHITELIST": {
        "title": "Whitelist путей",
        "description": "Ограничьте доступ к файлам whitelist допустимых путей/имен",
        "owasp_link": "https://owasp.org/www-community/attacks/Path_Traversal"
    },
    "REC_PATH_CHROOT": {
        "title": "Ограничьте корневую директорию",
        "description": "Проверяйте, что итоговый путь находится в пределах разрешенной директории",
        "owasp_link": "https://owasp.org/www-community/attacks/Path_Traversal"
    },
    "REC_PATH_CANONICALIZE": {
        "title": "Канонизация пути",
        "description": "Используйте os.path.realpath() для получения канонического пути перед проверкой",
        "owasp_link": "https://owasp.org/www-community/attacks/Path_Traversal"
    },
    "REC_CMD_AVOID_SHELL": {
        "title": "Избегайте shell=True",
        "description": "Не используйте shell=True в subprocess. Передавайте команду как список аргументов",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
    },
    "REC_CMD_WHITELIST": {
        "title": "Whitelist команд",
        "description": "Ограничьте набор разрешенных команд и аргументов whitelist'ом",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
    },
    "REC_CMD_ESCAPE": {
        "title": "Экранирование аргументов",
        "description": "Используйте shlex.quote() для экранирования аргументов, если shell неизбежен",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
    },
    "REC_SSRF_ALLOWLIST": {
        "title": "Allowlist доменов",
        "description": "Ограничьте исходящие запросы allowlist разрешенных доменов/IP",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
    },
    "REC_SSRF_VALIDATE": {
        "title": "Валидация URL",
        "description": "Проверяйте и парсите URL до запроса. Блокируйте private IP диапазоны (10.x, 172.16-31.x, 192.168.x)",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
    },
    "REC_SSRF_NETWORK_ISOLATION": {
        "title": "Сетевая изоляция",
        "description": "Используйте сетевые политики для ограничения исходящего трафика из приложения",
        "owasp_link": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
    },
}


def map_recommendations(categories: set[str]) -> list[str]:
    """Возвращает список ID рекомендаций для заданных категорий атак"""
    recs: list[str] = []
    for cat in categories:
        recs.extend(CATEGORY_RECS.get(cat, []))
    return sorted(set(recs))


def get_recommendation_details(rec_ids: list[str]) -> list[dict]:
    """Возвращает полную информацию о рекомендациях"""
    result = []
    for rec_id in rec_ids:
        if rec_id in RECOMMENDATION_DETAILS:
            detail = RECOMMENDATION_DETAILS[rec_id].copy()
            detail["id"] = rec_id
            result.append(detail)
    return result
