from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
from typing import Dict, List, Literal

from pydantic import BaseModel, Field, field_validator


class IdentityContext(BaseModel):
    node_id: str = Field(min_length=3, max_length=64)
    operator_id: str = Field(min_length=3, max_length=64)
    mfa_verified: bool = True
    impossible_travel_flag: bool = False
    privilege_escalation_attempts: int = Field(default=0, ge=0)


class NetworkSignals(BaseModel):
    src_ip: str
    failed_logins_5m: int = Field(default=0, ge=0)
    unique_ports_scanned_5m: int = Field(default=0, ge=0)
    c2_beacon_score: float = Field(default=0.0, ge=0.0, le=1.0)
    tls_fingerprint_mismatch: bool = False
    egress_bytes_5m: int = Field(default=0, ge=0)

    @field_validator("src_ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        ip_address(value)
        return value


class RuntimeIntegrity(BaseModel):
    secure_boot_ok: bool = True
    firmware_hash_match: bool = True
    memory_tamper_alert: bool = False
    unsigned_processes: int = Field(default=0, ge=0)
    suspicious_syscalls_1m: int = Field(default=0, ge=0)


class PhysicalSignals(BaseModel):
    enclosure_opened: bool = False
    vibration: float = Field(default=0.0, ge=0.0, le=1.0)
    thermal_delta_c: float = Field(default=0.0, ge=-30.0, le=80.0)
    ultrasonic_motion_score: float = Field(default=0.0, ge=0.0, le=1.0)


class ThreatAssessmentRequest(BaseModel):
    timestamp: datetime
    mission_profile: Literal["critical_infra", "enterprise_edge", "remote_outpost"]
    identity: IdentityContext
    network: NetworkSignals
    runtime: RuntimeIntegrity
    physical: PhysicalSignals
    telemetry_tags: List[str] = []


class DomainScore(BaseModel):
    score: float
    reasons: List[str]
    prevented_attacks: List[str]


class ThreatAssessmentResponse(BaseModel):
    overall_risk: Literal["low", "guarded", "elevated", "critical"]
    confidence: float
    risk_score: float
    domain_scores: Dict[str, DomainScore]
    containment_plan: List[str]
    attack_kill_chain_stage: str
