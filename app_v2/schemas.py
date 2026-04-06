from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class SensorPayload(BaseModel):
    pir_triggered: bool = False
    vibration: float = Field(default=0.0, ge=0.0, le=1.0)
    sound_db: float = Field(default=0.0, ge=0.0, le=200.0)
    thermal_presence: bool = False
    light_change: float = Field(default=0.0, ge=0.0, le=1.0)
    humidity: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    temperature: Optional[float] = Field(default=None, ge=-50.0, le=100.0)
    battery_level: Optional[float] = Field(default=None, ge=0.0, le=100.0)


class NetworkPayload(BaseModel):
    failed_logins: int = Field(default=0, ge=0)
    unknown_ip_hits: int = Field(default=0, ge=0)
    firmware_hash_mismatch: bool = False
    bandwidth_spike: bool = False
    repeated_port_scan_signals: int = Field(default=0, ge=0)


class AnalyzeRequest(BaseModel):
    device_id: str
    timestamp: datetime
    profile: str = "heritage"
    sensors: SensorPayload
    audio_events: List[str] = []
    network: NetworkPayload
    event_signature: str | None = None


class ScoreBreakdown(BaseModel):
    physical_score: float
    audio_score: float
    cyber_score: float
    context_score: float
    fused_score: float


class AnalyzeResponse(BaseModel):
    device_id: str
    risk_level: str
    confidence: float
    score_breakdown: ScoreBreakdown
    reasons: List[str]
    recommended_actions: List[str]
    explainability: List[str]
    profile_used: str
    alert: bool
