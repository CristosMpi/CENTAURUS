from __future__ import annotations

from fastapi import FastAPI, HTTPException

from app_audio_ml.model import AudioEventClassifier
from app_audio_ml.schemas import AudioClassifyRequest, AudioClassifyResponse

app = FastAPI(title="CENTAURUS Audio ML", version="0.1.0")
classifier = AudioEventClassifier()


@app.get("/health")
def health() -> dict:
    return {"ok": True, "model_loaded": classifier.ready}


@app.post("/audio/classify", response_model=AudioClassifyResponse)
def classify_audio(payload: AudioClassifyRequest) -> AudioClassifyResponse:
    if not classifier.ready:
        raise HTTPException(status_code=503, detail="audio model not available")
    result = classifier.predict(payload.samples, payload.sample_rate)
    return AudioClassifyResponse(**result)
