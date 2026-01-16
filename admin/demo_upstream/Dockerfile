FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] jinja2 python-dotenv aiosqlite pydantic pydantic-settings httpx
COPY demo_upstream/app /app/app
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
