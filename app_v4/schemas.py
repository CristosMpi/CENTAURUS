from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress

from app_v4.config import IDENTIFIER

Probability = Annotated[float, Field(ge=0, le=1)]
Count = Annotated[int, Field(ge=0, le=1_000_000_000)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Identity(StrictModel):
    node_id: str = Field(pattern=IDENTIFIER)
    operator_id: str = Field(pattern=IDENTIFIER)
    mfa_verified: bool | None = None
    impossible_travel_flag: bool = False
    privilege_escalation_attempts: Count = 0


class Network(StrictModel):
    src_ip: IPvAnyAddress
    failed_logins_5m: Count = 0
    unique_ports_scanned_5m: Count = 0
    c2_beacon_score: Probability = 0.0
    tls_fingerprint_mismatch: bool = False
    egress_bytes_5m: Annotated[int, Field(ge=0, le=10**15)] = 0
    threat_intel_reputation: Probability = 0.0
    lateral_movement_edges: Count = 0


class Runtime(StrictModel):
    secure_boot_ok: bool | None = None
    firmware_hash_match: bool | None = None
    memory_tamper_alert: bool = False
    unsigned_processes: Count = 0
    suspicious_syscalls_1m: Count = 0
    kernel_module_drift_score: Probability = 0.0


class Physical(StrictModel):
    enclosure_opened: bool = False
    vibration: Probability = 0.0
    thermal_delta_c: Annotated[float, Field(ge=-30, le=80)] = 0.0
    ultrasonic_motion_score: Probability = 0.0


class Deception(StrictModel):
    honeytoken_touched: bool = False
    decoy_service_touched: bool = False
    canary_credential_used: bool = False


class AssessmentRequest(StrictModel):
    timestamp: AwareDatetime
    mission_profile: Literal["critical_infra", "enterprise_edge", "remote_outpost"]
    identity: Identity
    network: Network
    runtime: Runtime
    physical: Physical
    deception: Deception = Field(default_factory=Deception)
    telemetry_tags: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=16
    )


class DomainResult(StrictModel):
    score: Probability
    reasons: list[str]
    related_attack_patterns: list[str]
    mitre_techniques: list[str]


class Action(StrictModel):
    action: str
    requires_operator_approval: bool = True


class AssessmentResponse(StrictModel):
    engine_version: str = "4.0.0"
    policy_version: str = "abyssal-1"
    request_id: str
    node_id: str
    overall_risk: Literal["low", "guarded", "elevated", "critical"]
    risk_score: Probability
    domain_scores: dict[str, DomainResult]
    policy_triggers: list[str]
    evidence_gaps: list[str]
    telemetry_trust: Literal["authenticated_source_only"] = "authenticated_source_only"
    execution_mode: Literal["recommendation_only"] = "recommendation_only"
    recommended_actions: list[Action]
