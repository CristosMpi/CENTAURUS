from __future__ import annotations

from pathlib import Path
from typing import Iterable

import joblib
import numpy as np

from app_audio_ml.features import extract_feature_vector


DEFAULT_MODEL_PATH = Path("models/audio_event_classifier.joblib")


class AudioEventClassifier:
    def __init__(self, model_path: str | Path = DEFAULT_MODEL_PATH):
        self.model_path = Path(model_path)
        self.pipeline = None
        self.labels: list[str] = []
        if self.model_path.exists():
            artifact = joblib.load(self.model_path)
            self.pipeline = artifact["pipeline"]
            self.labels = list(artifact["labels"])

    @property
    def ready(self) -> bool:
        return self.pipeline is not None

    def predict(self, samples: Iterable[float], sample_rate: int) -> dict:
        if not self.ready:
            raise RuntimeError("audio model not loaded")
        features = extract_feature_vector(samples, sample_rate).reshape(1, -1)
        probabilities = self.pipeline.predict_proba(features)[0]
        pred_idx = int(np.argmax(probabilities))
        return {
            "label": self.labels[pred_idx],
            "confidence": float(probabilities[pred_idx]),
            "probabilities": {
                label: float(prob)
                for label, prob in zip(self.labels, probabilities, strict=False)
            },
        }
