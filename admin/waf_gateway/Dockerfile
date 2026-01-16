FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] httpx regex orjson pydantic pydantic-settings cachetools python-dotenv pyyaml
COPY waf_gateway/app /app/app
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
