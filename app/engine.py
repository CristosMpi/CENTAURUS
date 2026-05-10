from __future__ import annotations

from app.schemas import DomainScore, ThreatAssessmentRequest, ThreatAssessmentResponse


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def _identity_score(req: ThreatAssessmentRequest) -> DomainScore:
    i = req.identity
    score = 0.0
    reasons = []
    attacks = []
    if not i.mfa_verified:
        score += 0.35
        reasons.append("MFA missing for operator action")
        attacks.append("Credential stuffing")
    if i.impossible_travel_flag:
        score += 0.30
        reasons.append("Impossible-travel login behavior")
        attacks.append("Session hijacking")
    if i.privilege_escalation_attempts > 0:
        score += min(0.35, i.privilege_escalation_attempts * 0.08)
        reasons.append(f"Privilege escalation attempts: {i.privilege_escalation_attempts}")
        attacks.append("Insider privilege abuse")
    return DomainScore(score=_clamp(score), reasons=reasons, prevented_attacks=sorted(set(attacks)))


def _network_score(req: ThreatAssessmentRequest) -> DomainScore:
    n = req.network
    score = 0.0
    reasons = []
    attacks = []
    if n.failed_logins_5m >= 20:
        score += 0.25
        reasons.append("Failed logins burst in 5m window")
        attacks.append("Brute-force authentication")
    if n.unique_ports_scanned_5m >= 15:
        score += 0.25
        reasons.append("Wide port-scan pattern detected")
        attacks.append("Reconnaissance and exploit staging")
    if n.c2_beacon_score > 0.5:
        score += 0.3
        reasons.append("High command-and-control beacon probability")
        attacks.append("Malware command-and-control")
    if n.tls_fingerprint_mismatch:
        score += 0.2
        reasons.append("TLS client fingerprint deviates from baseline")
        attacks.append("Evasion via custom tooling")
    if n.egress_bytes_5m > 150_000_000:
        score += 0.2
        reasons.append("Possible bulk exfiltration detected")
        attacks.append("Data exfiltration")
    return DomainScore(score=_clamp(score), reasons=reasons, prevented_attacks=sorted(set(attacks)))


def _runtime_score(req: ThreatAssessmentRequest) -> DomainScore:
    r = req.runtime
    score = 0.0
    reasons = []
    attacks = []
    if not r.secure_boot_ok:
        score += 0.35
        reasons.append("Secure boot validation failed")
        attacks.append("Boot-level rootkit persistence")
    if not r.firmware_hash_match:
        score += 0.35
        reasons.append("Firmware integrity mismatch")
        attacks.append("Firmware tampering")
    if r.memory_tamper_alert:
        score += 0.25
        reasons.append("Memory tamper alert raised")
        attacks.append("In-memory injection")
    if r.unsigned_processes > 2:
        score += 0.15
        reasons.append(f"Unsigned processes detected: {r.unsigned_processes}")
        attacks.append("Unauthorized binary execution")
    if r.suspicious_syscalls_1m > 100:
        score += 0.2
        reasons.append("Abnormal syscall activity spike")
        attacks.append("Kernel/userland exploit activity")
    return DomainScore(score=_clamp(score), reasons=reasons, prevented_attacks=sorted(set(attacks)))


def _physical_score(req: ThreatAssessmentRequest) -> DomainScore:
    p = req.physical
    score = 0.0
    reasons = []
    attacks = []
    if p.enclosure_opened:
        score += 0.35
        reasons.append("Enclosure opened event")
        attacks.append("Physical tampering")
    if p.vibration > 0.75:
        score += 0.2
        reasons.append("High vibration profile")
        attacks.append("Forced-entry manipulation")
    if p.thermal_delta_c > 18:
        score += 0.2
        reasons.append("Rapid thermal change near hardware")
        attacks.append("Thermal stress sabotage")
    if p.ultrasonic_motion_score > 0.7:
        score += 0.15
        reasons.append("Unusual close-range ultrasonic movement")
        attacks.append("Covert proximity intrusion")
    return DomainScore(score=_clamp(score), reasons=reasons, prevented_attacks=sorted(set(attacks)))


def assess_threat(req: ThreatAssessmentRequest) -> ThreatAssessmentResponse:
    identity = _identity_score(req)
    network = _network_score(req)
    runtime = _runtime_score(req)
    physical = _physical_score(req)

    weights = {"identity": 0.22, "network": 0.33, "runtime": 0.30, "physical": 0.15}
    risk_score = _clamp(
        identity.score * weights["identity"]
        + network.score * weights["network"]
        + runtime.score * weights["runtime"]
        + physical.score * weights["physical"]
        + (0.08 if (network.score > 0.55 and runtime.score > 0.55) else 0.0)
    )

    if risk_score >= 0.8:
        risk = "critical"
        chain_stage = "Actions on objectives"
    elif risk_score >= 0.6:
        risk = "elevated"
        chain_stage = "Lateral movement"
    elif risk_score >= 0.35:
        risk = "guarded"
        chain_stage = "Initial access"
    else:
        risk = "low"
        chain_stage = "Reconnaissance"

    containment = [
        "Bind operator actions to hardware-backed passkeys",
        "Enforce adaptive microsegmentation between node and control plane",
        "Rotate short-lived workload identities and invalidate active sessions",
    ]
    if risk in {"elevated", "critical"}:
        containment += [
            "Quarantine node network egress except signed update channel",
            "Trigger forensic memory snapshot and immutable evidence capture",
        ]
    if risk == "critical":
        containment += [
            "Cut over to clean standby node and revoke trust for compromised host",
        ]

    return ThreatAssessmentResponse(
        overall_risk=risk,
        confidence=round(0.72 + risk_score * 0.25, 3),
        risk_score=round(risk_score, 3),
        domain_scores={
            "identity": identity,
            "network": network,
            "runtime": runtime,
            "physical": physical,
        },
        containment_plan=containment,
        attack_kill_chain_stage=chain_stage,
    )
