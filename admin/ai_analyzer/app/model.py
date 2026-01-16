from __future__ import annotations

import joblib
from pathlib import Path
from typing import Any, Tuple

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .dataset_synth import build_dataset


class AnalyzerModel:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.vectorizer: TfidfVectorizer | None = None
        self.clf: LogisticRegression | None = None

    def exists(self) -> bool:
        return self.path.exists()

    def train(self) -> None:
        texts, labels = build_dataset()
        vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=1)
        X = vectorizer.fit_transform(texts)
        clf = LogisticRegression(max_iter=200)
        clf.fit(X, labels)
        self.vectorizer = vectorizer
        self.clf = clf
        self.save()

    def save(self) -> None:
        if self.vectorizer is None or self.clf is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"vectorizer": self.vectorizer, "clf": self.clf}, self.path)

    def load(self) -> None:
        data: dict[str, Any] = joblib.load(self.path)
        self.vectorizer = data["vectorizer"]
        self.clf = data["clf"]

    def predict(self, text: str) -> Tuple[str, float]:
        if self.vectorizer is None or self.clf is None:
            raise RuntimeError("model not loaded")
        probs = self.clf.predict_proba(self.vectorizer.transform([text]))[0]
        idx = probs.argmax()
        label = self.clf.classes_[idx]
        return str(label), float(probs[idx])
