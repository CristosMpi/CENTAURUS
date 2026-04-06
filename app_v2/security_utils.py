from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from app_v2.config import settings
from app_v2.schemas import AnalyzeRequest


def canonical_message(payload: AnalyzeRequest) -> str:
    ts = payload.timestamp.astimezone(timezone.utc).isoformat()
    return f"{payload.device_id}|{ts}|{payload.profile}|{payload.sensors.vibration:.4f}|{payload.sensors.sound_db:.2f}|{int(payload.sensors.pir_triggered)}|{int(payload.sensors.thermal_presence)}"


def generate_signature(payload: AnalyzeRequest) -> str:
    message = canonical_message(payload).encode("utf-8")
    key = settings.shared_secret.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_signature(payload: AnalyzeRequest) -> bool:
    if not payload.event_signature:
        return False
    expected = generate_signature(payload)
    return hmac.compare_digest(expected, payload.event_signature)


def timestamp_is_fresh(payload: AnalyzeRequest, max_age_minutes: int = 10) -> bool:
    now = datetime.now(timezone.utc)
    ts = payload.timestamp.astimezone(timezone.utc)
    return now - timedelta(minutes=max_age_minutes) <= ts <= now + timedelta(minutes=1)
