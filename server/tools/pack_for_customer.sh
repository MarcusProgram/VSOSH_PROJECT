#!/bin/bash
# Скрипт упаковки WAF для заказчика

OUT_DIR="/tmp/waf-customer-package"
ZIP_NAME="waf-gateway-$(date +%Y%m%d).zip"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Копируем нужные файлы
cp -r waf_gateway "$OUT_DIR/"
cp -r ai_analyzer "$OUT_DIR/"
mkdir -p "$OUT_DIR/data/logs"
mkdir -p "$OUT_DIR/data/ml_artifacts"

# Создаём docker-compose для заказчика
cat > "$OUT_DIR/docker-compose.yml" << 'EOF'
services:
  ai_analyzer:
    build:
      context: .
      dockerfile: ai_analyzer/Dockerfile
    volumes:
      - ./data/ml_artifacts:/data/ml_artifacts
    restart: always

  waf_gateway:
    build:
      context: .
      dockerfile: waf_gateway/Dockerfile
    environment:
      - UPSTREAM_URL=${UPSTREAM_URL}
      - TELEGRAM_BACKEND_URL=${TELEGRAM_BACKEND_URL}
      - CONTROL_PLANE_HMAC_SECRET=${CONTROL_PLANE_HMAC_SECRET}
      - LICENSE_KEY_HASH=${LICENSE_KEY_HASH}
    volumes:
      - ./data/logs:/data/logs
    ports:
      - "80:8080"
    depends_on:
      - ai_analyzer
    restart: always
EOF

# Создаём .env.example
cat > "$OUT_DIR/.env.example" << 'EOF'
# Адрес вашего сайта (который защищаем)
UPSTREAM_URL=http://your-app:3000

# Данные от поставщика WAF (заполнить)
TELEGRAM_BACKEND_URL=
CONTROL_PLANE_HMAC_SECRET=
LICENSE_KEY_HASH=
EOF

# Создаём README
cat > "$OUT_DIR/README.md" << 'EOF'
# WAF Gateway

## Установка

1. Распакуйте архив
2. Скопируйте .env.example в .env и заполните данными от поставщика
3. Запустите: `docker compose up -d`
4. Активируйте лицензию в Telegram боте: `/activate <ваш_ключ>`

## Настройка

В файле .env укажите:
- UPSTREAM_URL - адрес вашего сайта
- TELEGRAM_BACKEND_URL - адрес сервера управления (от поставщика)
- CONTROL_PLANE_HMAC_SECRET - секретный ключ (от поставщика)
- LICENSE_KEY_HASH - хеш лицензии (от поставщика)

## Логи

Логи атак: `data/logs/waf_events.jsonl`
EOF

# Упаковываем
cd /tmp
rm -f "$ZIP_NAME"
zip -r "$ZIP_NAME" "waf-customer-package"

echo ""
echo "Готово: /tmp/$ZIP_NAME"
echo ""
echo "Размер: $(du -h /tmp/$ZIP_NAME | cut -f1)"
