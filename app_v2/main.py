from fastapi import FastAPI, HTTPException

from app_v2.audit import append_audit
from app_v2.config import settings
from app_v2.engine import analyze
from app_v2.rate_limit import RateLimitMiddleware
from app_v2.schemas import AnalyzeRequest, AnalyzeResponse
from app_v2.security_utils import verify_signature

app = FastAPI(title=settings.app_name, version=settings.app_version)
app.add_middleware(RateLimitMiddleware)


@app.get("/")
def root() -> dict:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "features": [
            "profile-aware fusion",
            "event integrity checks",
            "rate limiting",
            "audit logging",
            "explainability",
        ],
    }


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/v2/analyze", response_model=AnalyzeResponse)
def analyze_event(payload: AnalyzeRequest) -> AnalyzeResponse:
    result = analyze(payload)
    append_audit(
        {
            "device_id": payload.device_id,
            "profile": payload.profile,
            "risk_level": result.risk_level,
            "confidence": result.confidence,
            "signature_valid": verify_signature(payload),
        }
    )
    return result


@app.post("/v2/verify")
def verify_event(payload: AnalyzeRequest) -> dict:
    valid = verify_signature(payload)
    if not valid:
        raise HTTPException(status_code=400, detail="invalid signature")
    return {"valid": True, "device_id": payload.device_id}
