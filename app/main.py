from fastapi import FastAPI

from app.config import settings
from app.engine import assess_threat
from app.schemas import ThreatAssessmentRequest, ThreatAssessmentResponse

app = FastAPI(title="NEN CENTAURUS", version="3.0.0")


@app.get("/")
def root() -> dict:
    return {
        "name": "NEN CENTAURUS for ORIGIN",
        "version": "3.0.0",
        "status": "armed",
        "profile": settings.app_name,
    }


@app.get("/health")
def health() -> dict:
    return {"ok": True, "engine": "threat-fusion"}


@app.post("/v3/assess", response_model=ThreatAssessmentResponse)
def assess(payload: ThreatAssessmentRequest) -> ThreatAssessmentResponse:
    return assess_threat(payload)


@app.post("/v1/analyze", response_model=ThreatAssessmentResponse)
def compat_assess(payload: ThreatAssessmentRequest) -> ThreatAssessmentResponse:
    return assess_threat(payload)
