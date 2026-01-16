FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] scikit-learn joblib numpy scipy pydantic pydantic-settings orjson
COPY ai_analyzer/app /app/app
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
