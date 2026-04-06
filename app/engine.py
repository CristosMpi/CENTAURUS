from __future__ import annotations

from typing import List, Tuple

from app.config import settings
from app.schemas import AnalyzeRequest, AnalyzeResponse, ScoreBreakdown

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
        score += 0.2
        reasons.append("PIR triggered")
    if s.vibration > 0.65:
        score += 0.3
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
        score += 0.2
        reasons.append("Thermal presence detected")

    if s.light_change > 0.4:
        score += 0.08
        reasons.append(f"Sudden light change: {s.light_change:.2f}")

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
        score += 0.4
        reasons.append("Firmware hash mismatch")

    if n.bandwidth_spike:
        score += 0.1
        reasons.append("Bandwidth spike detected")

    if n.repeated_port_scan_signals >= 3:
        score += 0.18
        reasons.append(f"Port scan pattern: {n.repeated_port_scan_signals}")

    return _clamp(score), reasons


def fuse_scores(physical: float, audio: float, cyber: float) -> float:
    fused = 0.45 * physical + 0.30 * audio + 0.25 * cyber
    if physical > 0.6 and audio > 0.4:
        fused += 0.1
    return _clamp(fused)


def classify(score: float) -> str:
    if score >= settings.high_risk_threshold:
        return "high"
    if score >= settings.medium_risk_threshold:
        return "medium"
    return "low"


def recommended_actions(risk_level: str, cyber_score: float) -> List[str]:
    actions = ["Log event to ORIGIN DUO"]
    if risk_level in {"medium", "high"}:
        actions.append("Notify operator")
    if risk_level == "high":
        actions.append("Trigger high-priority incident workflow")
        actions.append("Request visual confirmation if camera exists")
    if cyber_score >= 0.4:
        actions.append("Isolate suspicious network node")
        actions.append("Verify firmware integrity")
    return actions


def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    physical_score, physical_reasons = score_physical(req)
    audio_score, audio_reasons = score_audio(req.audio_events)
    cyber_score, cyber_reasons = score_cyber(req)
    fused_score = fuse_scores(physical_score, audio_score, cyber_score)
    risk_level = classify(fused_score)

    reasons = physical_reasons + audio_reasons + cyber_reasons
    response = AnalyzeResponse(
        device_id=req.device_id,
        risk_level=risk_level,
        confidence=round(fused_score, 3),
        score_breakdown=ScoreBreakdown(
            physical_score=round(physical_score, 3),
            audio_score=round(audio_score, 3),
            cyber_score=round(cyber_score, 3),
            fused_score=round(fused_score, 3),
        ),
        reasons=reasons,
        recommended_actions=recommended_actions(risk_level, cyber_score),
        alert=risk_level in {"medium", "high"},
    )
    return response
