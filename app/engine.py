from __future__ import annotations

from app.schemas import DomainScore, ThreatAssessmentRequest, ThreatAssessmentResponse


PROFILE_MULTIPLIER = {
    "critical_infra": 1.12,
    "enterprise_edge": 1.0,
    "remote_outpost": 1.05,
}


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def _mk(score: float, reasons: list[str], attacks: list[str], mitre: list[str]) -> DomainScore:
    return DomainScore(
        score=_clamp(score),
        reasons=reasons,
        prevented_attacks=sorted(set(attacks)),
        mitre_techniques=sorted(set(mitre)),
    )


def _identity_score(req: ThreatAssessmentRequest) -> DomainScore:
    i = req.identity
    score = 0.0
    reasons, attacks, mitre = [], [], []
    if not i.mfa_verified:
        score += 0.35
        reasons.append("MFA missing for operator action")
        attacks.append("Credential stuffing")
        mitre.append("T1110")
    if i.impossible_travel_flag:
        score += 0.30
        reasons.append("Impossible-travel login behavior")
        attacks.append("Session hijacking")
        mitre.append("T1078")
    if i.privilege_escalation_attempts > 0:
        score += min(0.35, i.privilege_escalation_attempts * 0.08)
        reasons.append(f"Privilege escalation attempts: {i.privilege_escalation_attempts}")
        attacks.append("Insider privilege abuse")
        mitre.append("T1068")
    return _mk(score, reasons, attacks, mitre)


def _network_score(req: ThreatAssessmentRequest) -> DomainScore:
    n = req.network
    score = 0.0
    reasons, attacks, mitre = [], [], []
    if n.failed_logins_5m >= 20:
        score += 0.20
        reasons.append("Failed logins burst in 5m window")
        attacks.append("Brute-force authentication")
        mitre.append("T1110")
    if n.unique_ports_scanned_5m >= 15:
        score += 0.20
        reasons.append("Wide port-scan pattern detected")
        attacks.append("Reconnaissance and exploit staging")
        mitre.append("T1046")
    if n.c2_beacon_score > 0.5:
        score += 0.25
        reasons.append("High command-and-control beacon probability")
        attacks.append("Malware command-and-control")
        mitre.append("T1071")
    if n.tls_fingerprint_mismatch:
        score += 0.14
        reasons.append("TLS client fingerprint deviates from baseline")
        attacks.append("Evasion via custom tooling")
        mitre.append("T1036")
    if n.egress_bytes_5m > 150_000_000:
        score += 0.14
        reasons.append("Possible bulk exfiltration detected")
        attacks.append("Data exfiltration")
        mitre.append("T1041")
    if n.threat_intel_reputation > 0.7:
        score += 0.20
        reasons.append("High-risk IP reputation from threat-intel feed")
        attacks.append("Known malicious infrastructure")
        mitre.append("T1583")
    if n.lateral_movement_edges > 5:
        score += 0.15
        reasons.append("Rapid lateral movement edge fanout")
        attacks.append("Lateral movement propagation")
        mitre.append("T1021")
    return _mk(score, reasons, attacks, mitre)


def _runtime_score(req: ThreatAssessmentRequest) -> DomainScore:
    r = req.runtime
    score = 0.0
    reasons, attacks, mitre = [], [], []
    if not r.secure_boot_ok:
        score += 0.30
        reasons.append("Secure boot validation failed")
        attacks.append("Boot-level rootkit persistence")
        mitre.append("T1542")
    if not r.firmware_hash_match:
        score += 0.30
        reasons.append("Firmware integrity mismatch")
        attacks.append("Firmware tampering")
        mitre.append("T1542")
    if r.memory_tamper_alert:
        score += 0.25
        reasons.append("Memory tamper alert raised")
        attacks.append("In-memory injection")
        mitre.append("T1055")
    if r.unsigned_processes > 2:
        score += 0.12
        reasons.append(f"Unsigned processes detected: {r.unsigned_processes}")
        attacks.append("Unauthorized binary execution")
        mitre.append("T1204")
    if r.suspicious_syscalls_1m > 100:
        score += 0.15
        reasons.append("Abnormal syscall activity spike")
        attacks.append("Kernel/userland exploit activity")
        mitre.append("T1068")
    if r.kernel_module_drift_score > 0.65:
        score += 0.2
        reasons.append("Kernel module drift from trusted baseline")
        attacks.append("Kernel persistence tampering")
        mitre.append("T1547")
    return _mk(score, reasons, attacks, mitre)


def _physical_score(req: ThreatAssessmentRequest) -> DomainScore:
    p = req.physical
    d = req.deception
    score = 0.0
    reasons, attacks, mitre = [], [], []
    if p.enclosure_opened:
        score += 0.30
        reasons.append("Enclosure opened event")
        attacks.append("Physical tampering")
        mitre.append("T1200")
    if p.vibration > 0.75:
        score += 0.18
        reasons.append("High vibration profile")
        attacks.append("Forced-entry manipulation")
    if p.thermal_delta_c > 18:
        score += 0.18
        reasons.append("Rapid thermal change near hardware")
        attacks.append("Thermal stress sabotage")
    if p.ultrasonic_motion_score > 0.7:
        score += 0.14
        reasons.append("Unusual close-range ultrasonic movement")
        attacks.append("Covert proximity intrusion")
    if d.honeytoken_touched or d.decoy_service_touched or d.canary_credential_used:
        score += 0.35
        reasons.append("Deception tripwire triggered")
        attacks.append("Interactive adversary behavior confirmed")
        mitre.append("T1654")
    return _mk(score, reasons, attacks, mitre)


def assess_threat(req: ThreatAssessmentRequest) -> ThreatAssessmentResponse:
    identity = _identity_score(req)
    network = _network_score(req)
    runtime = _runtime_score(req)
    physical = _physical_score(req)

    weights = {"identity": 0.20, "network": 0.35, "runtime": 0.30, "physical": 0.15}
    fused = (
        identity.score * weights["identity"]
        + network.score * weights["network"]
        + runtime.score * weights["runtime"]
        + physical.score * weights["physical"]
    )

    cross_domain_bonus = 0.0
    if network.score > 0.55 and runtime.score > 0.55:
        cross_domain_bonus += 0.10
    if req.deception.honeytoken_touched and req.runtime.memory_tamper_alert:
        cross_domain_bonus += 0.08

    risk_score = _clamp((fused + cross_domain_bonus) * PROFILE_MULTIPLIER[req.mission_profile])

    if risk_score >= 0.8:
        risk, chain_stage = "critical", "Actions on objectives"
    elif risk_score >= 0.6:
        risk, chain_stage = "elevated", "Lateral movement"
    elif risk_score >= 0.35:
        risk, chain_stage = "guarded", "Initial access"
    else:
        risk, chain_stage = "low", "Reconnaissance"

    containment = [
        "Bind operator actions to hardware-backed passkeys",
        "Enforce adaptive microsegmentation between node and control plane",
        "Rotate short-lived workload identities and invalidate active sessions",
    ]
    immediate_actions = ["Open SOC incident ticket", "Preserve relevant telemetry stream"]
    if risk in {"elevated", "critical"}:
        containment += [
            "Quarantine node network egress except signed update channel",
            "Trigger forensic memory snapshot and immutable evidence capture",
        ]
        immediate_actions += ["Block source IP and neighboring pivot IPs", "Rotate operator/API credentials"]
    if risk == "critical":
        containment += ["Cut over to clean standby node and revoke trust for compromised host"]
        immediate_actions += ["Activate crisis runbook and page incident commander"]

    return ThreatAssessmentResponse(
        overall_risk=risk,
        confidence=round(0.7 + risk_score * 0.28, 3),
        risk_score=round(risk_score, 3),
        domain_scores={"identity": identity, "network": network, "runtime": runtime, "physical": physical},
        containment_plan=containment,
        attack_kill_chain_stage=chain_stage,
        immediate_actions=immediate_actions,
    )
