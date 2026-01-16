#!/bin/bash
# Синхронизация лицензий с базой данных телеграм-бота через Docker

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ADMIN_DIR="$SCRIPT_DIR/../../admin"
LICENSES_FILE="$SCRIPT_DIR/licenses_log.json"

if [ ! -f "$LICENSES_FILE" ]; then
    echo "Файл лицензий не найден: $LICENSES_FILE"
    exit 1
fi

# Читаем хеши из JSON
HASHES=$(python3 -c "import json; print(' '.join([x['license_hash'] for x in json.load(open('$LICENSES_FILE'))]))")

# Формируем Python код для синхронизации
PYTHON_CODE="
import asyncio
import sys
sys.path.insert(0, '/app')
from app.db import init_db
from app.licenses import insert_license

HASHES = '$HASHES'.split()

async def main():
    await init_db()
    for h in HASHES:
        await insert_license(h)
    print(f'[OK] Синхронизировано {len(HASHES)} лицензий')

asyncio.run(main())
"

cd "$ADMIN_DIR"
echo "$PYTHON_CODE" | docker compose exec -T telegram_backend python3
