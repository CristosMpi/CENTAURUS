from __future__ import annotations

from typing import List, Tuple

from app_v2.config import settings
from app_v2.profiles import DEFAULT_PROFILE, PROFILE_WEIGHTS
from app_v2.schemas import AnalyzeRequest, AnalyzeResponse, ScoreBreakdown
from app_v2.security_utils import timestamp_is_fresh, verify_signature

AUDIO_WEIGHTS = {
    "digging": 0.35,
    "metal_hit": 0.30,
    "drilling": 0.40,
    "footsteps": 0.15,
    "vehicle": 0.08,
    "wind": -0.08,
    "rain": -0.08,
    "animal": -0.05,
}


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def score_physical(req: AnalyzeRequest) -> Tuple[float, List[str]]:
    s = req.sensors
    score = 0.0
    reasons: List[str] = []
    if s.pir_triggered:
        score += 0.20
        reasons.append("PIR triggered")
    if s.vibration > 0.65:
        score += 0.30
        reasons.append(f"High vibration: {s.vibration:.2f}")
    elif s.vibration > 0.35:
        score += 0.12
        reasons.append(f"Moderate vibration: {s.vibration:.2f}")
    if s.sound_db > 78:
        score += 0.18
        reasons.append(f"High sound level: {s.sound_db:.1f} dB")
    elif s.sound_db > 62:
        score += 0.08
        reasons.append(f"Elevated sound level: {s.sound_db:.1f} dB")
    if s.thermal_presence:
        score += 0.20
        reasons.append("Thermal presence detected")
    if s.light_change > 0.4:
        score += 0.08
        reasons.append(f"Sudden light change: {s.light_change:.2f}")
    if s.battery_level is not None and s.battery_level < 10:
        score -= 0.02
        reasons.append("Low battery noted")
    return _clamp(score), reasons


def score_audio(audio_events: List[str]) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    for event in audio_events:
        weight = AUDIO_WEIGHTS.get(event, 0.05)
        score += weight
        reasons.append(f"Audio event: {event}")
    return _clamp(score), reasons


def score_cyber(req: AnalyzeRequest) -> Tuple[float, List[str]]:
    n = req.network
    score = 0.0
    reasons: List[str] = []
    if n.failed_logins >= 5:
        score += 0.25
        reasons.append(f"Failed logins spike: {n.failed_logins}")
    elif n.failed_logins >= 3:
        score += 0.12
        reasons.append(f"Elevated failed logins: {n.failed_logins}")
    if n.unknown_ip_hits >= 10:
        score += 0.25
        reasons.append(f"Unknown IP hits: {n.unknown_ip_hits}")
    elif n.unknown_ip_hits >= 5:
        score += 0.12
        reasons.append(f"Elevated unknown IP hits: {n.unknown_ip_hits}")
    if n.firmware_hash_mismatch:
        score += 0.40
        reasons.append("Firmware hash mismatch")
    if n.bandwidth_spike:
        score += 0.10
        reasons.append("Bandwidth spike detected")
    if n.repeated_port_scan_signals >= 3:
        score += 0.18
        reasons.append(f"Port scan pattern: {n.repeated_port_scan_signals}")
    if verify_signature(req):
        reasons.append("Valid event signature")
    else:
        score += 0.15
        reasons.append("Missing or invalid event signature")
    if not timestamp_is_fresh(req):
        score += 0.12
        reasons.append("Stale or suspicious timestamp")
    return _clamp(score), reasons


def score_context(req: AnalyzeRequest) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    if req.profile == "heritage" and ("digging" in req.audio_events or req.sensors.vibration > 0.6):
        score += 0.18
        reasons.append("Heritage profile amplified excavation-like pattern")
    if req.profile == "wildlife" and "animal" in req.audio_events:
        score -= 0.10
        reasons.append("Wildlife profile discounted animal event")
    if req.profile == "industrial" and req.network.firmware_hash_mismatch:
        score += 0.12
        reasons.append("Industrial profile amplified firmware anomaly")
    return _clamp(score), reasons


def fuse_scores(physical: float, audio: float, cyber: float, context: float, profile: str) -> float:
    weights = PROFILE_WEIGHTS.get(profile, PROFILE_WEIGHTS[DEFAULT_PROFILE])
    fused = (
        weights["physical"] * physical
        + weights["audio"] * audio
        + weights["cyber"] * cyber
        + weights["context"] * context
    )
    if physical > 0.6 and audio > 0.4:
        fused += 0.08
    if cyber > 0.45 and physical > 0.25:
        fused += 0.05
    return _clamp(fused)


def classify(score: float) -> str:
    if score >= settings.high_risk_threshold:
        return "high"
    if score >= settings.medium_risk_threshold:
        return "medium"
    return "low"


def recommended_actions(risk_level: str, cyber_score: float, profile: str) -> List[str]:
    actions = ["Log event to ORIGIN DUO"]
    if risk_level in {"medium", "high"}:
        actions.append("Notify operator")
    if risk_level == "high":
        actions.append("Trigger high-priority incident workflow")
        actions.append("Request visual confirmation if camera exists")
    if cyber_score >= 0.4:
        actions.append("Isolate suspicious network node")
        actions.append("Verify firmware integrity")
    if profile == "heritage":
        actions.append("Mark geospatial incident zone for review")
    return actions


def explainability(reasons: List[str], score_breakdown: ScoreBreakdown) -> List[str]:
    items = [
        f"Physical evidence score: {score_breakdown.physical_score:.2f}",
        f"Audio intelligence score: {score_breakdown.audio_score:.2f}",
        f"Cybersecurity score: {score_breakdown.cyber_score:.2f}",
        f"Context score: {score_breakdown.context_score:.2f}",
    ]
    items.extend(reasons[:4])
    return items


def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    physical_score, physical_reasons = score_physical(req)
    audio_score, audio_reasons = score_audio(req.audio_events)
    cyber_score, cyber_reasons = score_cyber(req)
    context_score, context_reasons = score_context(req)
    fused_score = fuse_scores(physical_score, audio_score, cyber_score, context_score, req.profile)
    risk_level = classify(fused_score)
    reasons = physical_reasons + audio_reasons + cyber_reasons + context_reasons
    breakdown = ScoreBreakdown(
        physical_score=round(physical_score, 3),
        audio_score=round(audio_score, 3),
        cyber_score=round(cyber_score, 3),
        context_score=round(context_score, 3),
        fused_score=round(fused_score, 3),
    )
    return AnalyzeResponse(
        device_id=req.device_id,
        risk_level=risk_level,
        confidence=round(fused_score, 3),
        score_breakdown=breakdown,
        reasons=reasons,
        recommended_actions=recommended_actions(risk_level, cyber_score, req.profile),
        explainability=explainability(reasons, breakdown),
        profile_used=req.profile,
        alert=risk_level in {"medium", "high"},
    )
