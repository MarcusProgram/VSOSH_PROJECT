from __future__ import annotations

import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .settings import settings
from .schemas import AnalyzeRequest, AnalyzeResponse
from .train_on_startup import ensure_model

app = FastAPI(title="AI Analyzer")
model_holder = ensure_model()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/test")
async def test_model(text: str = "GET /api/users id=1 OR 1=1") -> dict:
    """Тестовый эндпоинт для демонстрации работы ML модели"""
    try:
        label, confidence = await asyncio.get_event_loop().run_in_executor(
            None, model_holder.predict, text
        )
        return {
            "input": text,
            "ml_prediction": label,
            "ml_confidence": f"{confidence:.1%}",
            "action": decide_action(label, confidence),
            "model_classes": list(model_holder.clf.classes_) if model_holder.clf else []
        }
    except Exception as e:
        return {"error": str(e)}


def decide_action(label: str, confidence: float) -> str:
    """
    Принятие решения на основе метки ML и уровня уверенности.
    Поддерживает все 5 типов атак: SQLI, XSS, TRAVERSAL, CMD, SSRF
    """
    attack_labels = {"SQLI", "XSS", "TRAVERSAL", "CMD", "SSRF"}
    if label in attack_labels:
        if confidence >= settings.threshold_block:
            return "block"
        if confidence >= settings.threshold_rate_limit:
            return "rate_limit"
    return "allow"


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    text = " ".join(
        [
            req.method.upper(),
            req.path,
            req.query or "",
            (req.content_type or ""),
            (req.body or ""),
        ]
    )
    try:
        label, confidence = await asyncio.get_event_loop().run_in_executor(
            None, model_holder.predict, text
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc))
    action = decide_action(label, confidence)
    explanation = f"label={label} conf={confidence:.2f}"
    return AnalyzeResponse(
        label=label,
        confidence=confidence,
        recommended_action=action,
        explanation=explanation,
        suspected_param=None,
    )


@app.exception_handler(HTTPException)
async def http_error(_, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
