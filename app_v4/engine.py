"""Deterministic defensive policy; never executes containment commands."""

from app.engine import assess_threat
from app.schemas import ThreatAssessmentRequest
from app_v4.schemas import Action, AssessmentRequest, AssessmentResponse, DomainResult


def assess(payload: AssessmentRequest, request_id: str) -> AssessmentResponse:
    legacy = payload.model_dump(mode="json")
    # V3 needs booleans. Unknown integrity is scored conservatively and separately
    # disclosed as an evidence gap; it is never silently treated as healthy.
    gaps = []
    for section, field in (
        ("identity", "mfa_verified"),
        ("runtime", "secure_boot_ok"),
        ("runtime", "firmware_hash_match"),
    ):
        if legacy[section][field] is None:
            gaps.append(f"{section}.{field}")
            legacy[section][field] = False
    result = assess_threat(ThreatAssessmentRequest.model_validate(legacy))
    score = result.risk_score
    triggers = []

    def floor(value: float, reason: str):
        nonlocal score
        score = max(score, value)
        triggers.append(reason)

    if gaps:
        floor(0.35, "Missing identity or runtime integrity evidence")
    if payload.identity.mfa_verified is False:
        floor(0.35, "Operator MFA is not verified")
    if payload.runtime.secure_boot_ok is False:
        floor(0.65, "Secure boot failure")
    if payload.runtime.firmware_hash_match is False:
        floor(0.85, "Firmware integrity mismatch")
    if payload.runtime.memory_tamper_alert:
        floor(0.85, "Memory tampering reported")
    if payload.deception.canary_credential_used or payload.deception.honeytoken_touched:
        floor(0.85, "Credential deception tripwire triggered")
    elif payload.deception.decoy_service_touched:
        floor(0.65, "Decoy service touched")
    if payload.physical.enclosure_opened and payload.physical.vibration > 0.75:
        floor(0.80, "Enclosure breach corroborated by high vibration")
    if payload.network.c2_beacon_score > 0.8 and payload.network.threat_intel_reputation > 0.7:
        floor(0.80, "C2 activity corroborated by high-risk infrastructure")
    if payload.identity.impossible_travel_flag and payload.identity.privilege_escalation_attempts:
        floor(0.65, "Identity anomaly with privilege escalation")

    risk = (
        "critical"
        if score >= 0.8
        else "elevated"
        if score >= 0.6
        else "guarded"
        if score >= 0.35
        else "low"
    )
    actions = [Action(action="Preserve telemetry and review the signed assessment")]
    if gaps:
        actions.append(Action(action="Collect missing integrity evidence before restoring trust"))
    if risk in {"elevated", "critical"}:
        actions += [
            Action(action="Open an ORIGIN DUO incident and notify the operator"),
            Action(action="Review node isolation while preserving the safety and alert channel"),
            Action(action="Validate firmware against an independently trusted baseline"),
        ]
    if risk == "critical":
        actions += [
            Action(action="Revoke affected credentials and prepare a clean replacement node"),
            Action(action="Escalate to the incident lead before executing containment"),
        ]
    domains = {
        name: DomainResult(
            score=domain.score,
            reasons=domain.reasons,
            related_attack_patterns=domain.prevented_attacks,
            mitre_techniques=domain.mitre_techniques,
        )
        for name, domain in result.domain_scores.items()
    }
    for gap in gaps:
        section, field = gap.split(".")
        domains[section].reasons.append(f"Unknown evidence: {field}; conservative scoring applied")
    return AssessmentResponse(
        request_id=request_id,
        node_id=payload.identity.node_id,
        overall_risk=risk,
        risk_score=round(score, 3),
        domain_scores=domains,
        policy_triggers=triggers,
        evidence_gaps=gaps,
        recommended_actions=actions,
    )
