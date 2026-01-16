#!/usr/bin/env python3
"""
Генератор лицензионных ключей для WAF.
Запускать на СВОЁМ сервере, ключи выдавать заказчикам.

Автоматически синхронизирует с базой данных телеграм-бота через Docker.
"""

import hashlib
import secrets
import json
import subprocess
from datetime import datetime
from pathlib import Path


SCRIPT_DIR = Path(__file__).parent
SYNC_SCRIPT = SCRIPT_DIR / "sync_to_bot.sh"


def generate_license() -> dict:
    """Генерирует новый лицензионный ключ."""
    license_key = secrets.token_hex(16)  # 32 символа hex
    license_hash = hashlib.sha256(license_key.encode()).hexdigest()
    
    return {
        "license_key": license_key,
        "license_hash": license_hash,
        "created_at": datetime.now().isoformat(),
    }


def sync_to_bot_via_docker() -> bool:
    """Синхронизирует лицензии с ботом через Docker."""
    if not SYNC_SCRIPT.exists():
        print(f"[WARN] Скрипт синхронизации не найден: {SYNC_SCRIPT}")
        return False
    
    try:
        result = subprocess.run(
            [str(SYNC_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            # Извлекаем сообщение об успехе
            for line in result.stdout.split('\n'):
                if '[OK]' in line:
                    print(line.strip())
            return True
        else:
            print(f"[WARN] Ошибка синхронизации: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("[WARN] Таймаут синхронизации с Docker")
        return False
    except Exception as e:
        print(f"[WARN] Не удалось синхронизировать: {e}")
        return False


def main():
    import sys
    
    # Режим синхронизации
    if len(sys.argv) > 1 and sys.argv[1] == "--sync":
        sync_to_bot_via_docker()
        return
    
    data = generate_license()
    
    print(f"key:  {data['license_key']}")
    print(f"hash: {data['license_hash']}")
    
    log_file = SCRIPT_DIR / "licenses_log.json"
    try:
        with open(log_file, "r") as f:
            licenses = json.load(f)
    except:
        licenses = []
    
    licenses.append(data)
    
    with open(log_file, "w") as f:
        json.dump(licenses, f, indent=2, ensure_ascii=False)
    
    print(f"\nsaved to {log_file}")
    
    # Автоматически синхронизируем с БД бота через Docker
    print("\nСинхронизация с ботом...")
    if not sync_to_bot_via_docker():
        print("[!] Запустите вручную: ./sync_to_bot.sh")


if __name__ == "__main__":
    main()
