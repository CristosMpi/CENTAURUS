from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_critical_risk_assessment_with_deception() -> None:
    payload = {
        "timestamp": "2026-05-10T00:00:00Z",
        "mission_profile": "critical_infra",
        "identity": {
            "node_id": "origin-node-17",
            "operator_id": "op-77",
            "mfa_verified": False,
            "impossible_travel_flag": True,
            "privilege_escalation_attempts": 4,
        },
        "network": {
            "src_ip": "203.0.113.77",
            "failed_logins_5m": 30,
            "unique_ports_scanned_5m": 24,
            "c2_beacon_score": 0.81,
            "tls_fingerprint_mismatch": True,
            "egress_bytes_5m": 220000000,
            "threat_intel_reputation": 0.95,
            "lateral_movement_edges": 9,
        },
        "runtime": {
            "secure_boot_ok": False,
            "firmware_hash_match": False,
            "memory_tamper_alert": True,
            "unsigned_processes": 6,
            "suspicious_syscalls_1m": 250,
            "kernel_module_drift_score": 0.9,
        },
        "physical": {
            "enclosure_opened": True,
            "vibration": 0.89,
            "thermal_delta_c": 24,
            "ultrasonic_motion_score": 0.82,
        },
        "deception": {
            "honeytoken_touched": True,
            "decoy_service_touched": True,
            "canary_credential_used": True,
        },
    }
    response = client.post("/v3/assess", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_risk"] == "critical"
    assert "immediate_actions" in data
    assert "network" in data["domain_scores"]
    assert len(data["domain_scores"]["network"]["mitre_techniques"]) > 0
