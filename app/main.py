from fastapi import FastAPI

from app.config import settings
from app.engine import analyze
from app.schemas import AnalyzeRequest, AnalyzeResponse

app = FastAPI(title=settings.app_name, version=settings.app_version)


@app.get("/")
def root() -> dict:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
    }


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/v1/analyze", response_model=AnalyzeResponse)
def analyze_event(payload: AnalyzeRequest) -> AnalyzeResponse:
    return analyze(payload)
