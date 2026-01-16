from __future__ import annotations

from .model import AnalyzerModel
from .settings import settings


def ensure_model() -> AnalyzerModel:
    model = AnalyzerModel(settings.model_path)
    if model.exists():
        model.load()
    else:
        model.train()
    return model
