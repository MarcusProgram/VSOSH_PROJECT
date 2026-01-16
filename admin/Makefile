SHELL := /bin/bash

.PHONY: up down logs gen-license verify-logs test pack view-logs

# Запуск всех сервисов
up:
	mkdir -p data/logs data/telegram_db data/ml_artifacts
	docker compose up --build

# Запуск в фоне
up-d:
	mkdir -p data/logs data/telegram_db data/ml_artifacts
	docker compose up -d --build

# Остановка
down:
	docker compose down

# Логи в реальном времени
logs:
	docker compose logs -f

# Генерация лицензии для заказчика
gen-license:
	docker compose exec telegram_backend python /app/tools/generate_license.py

# Проверка целостности логов
verify-logs:
	python3 tools/verify_log_chain.py data/logs/waf_events.jsonl

# Просмотр логов атак
view-logs:
	python3 tools/view_logs.py

# Только блокировки
view-blocks:
	python3 tools/view_logs.py -b

# Упаковка для заказчика
pack:
	bash tools/pack_for_customer.sh

# Тесты
test:
	pytest tests/ -v

# Пересборка одного сервиса
rebuild-%:
	docker compose build --no-cache $*
	docker compose up -d $*
