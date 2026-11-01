from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app_v4 import VERSION
from app_v4.boundary import SecurityBoundary
from app_v4.config import Settings
from app_v4.engine import assess
from app_v4.schemas import AssessmentRequest, AssessmentResponse
from app_v4.state import StateStore


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings if settings is not None else Settings.from_env()

    @asynccontextmanager
    async def lifespan(app):
        app.state.store = StateStore(
            cfg.state_path, cfg.audit_key.get_secret_value(), cfg.max_audit_records
        )
        yield

    app = FastAPI(
        title="CENTAURUS V4 — ABYSSAL",
        version=VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
        redirect_slashes=False,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(cfg.allowed_hosts))
    app.add_middleware(SecurityBoundary, settings=cfg)

    @app.exception_handler(HTTPException)
    async def safe_error(request: Request, exc: HTTPException):
        return JSONResponse(
            {"detail": exc.detail, "request_id": request.state.request_id},
            status_code=exc.status_code,
        )

    @app.get("/")
    def root():
        return {
            "name": "CENTAURUS",
            "edition": "ABYSSAL",
            "version": VERSION,
            "assessment": "/v4/assess",
            "execution_mode": "recommendation_only",
        }

    @app.get("/health")
    def health():
        # Liveness only. Startup fails if the configuration or audit chain is invalid.
        return {"ok": True}

    @app.post("/v4/assess", response_model=AssessmentResponse)
    def assess_event(request: Request):
        try:
            body = request.state.signed_body
            # Reject ambiguous duplicate fields and non-standard JSON constants
            # before strict Pydantic validation in JSON mode.
            json.loads(
                body,
                object_pairs_hook=unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite number")),
            )
            payload = AssessmentRequest.model_validate_json(body)
        except (ValidationError, ValueError, UnicodeError, RecursionError):
            raise HTTPException(422, "Invalid assessment payload") from None
        if payload.identity.node_id != request.state.node_id:
            raise HTTPException(403, "Device identity is not authorized")
        age = (datetime.now(UTC) - payload.timestamp).total_seconds()
        if age > cfg.max_event_age_seconds or age < -5:
            raise HTTPException(422, "Telemetry timestamp is outside the allowed window")
        result = assess(payload, request.state.request_id)
        request.state.risk = result.overall_risk
        return result

    return app
