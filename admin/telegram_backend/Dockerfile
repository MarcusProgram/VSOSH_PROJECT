FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] python-telegram-bot aiosqlite httpx pydantic pydantic-settings orjson
COPY telegram_backend/app /app/app
COPY telegram_backend/tools /app/tools
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
