from fastapi.testclient import TestClient

from app_v2.main import app
from app_v2.security_utils import generate_signature
from app_v2.schemas import AnalyzeRequest, NetworkPayload, SensorPayload

client = TestClient(app)


def make_payload() -> dict:
    payload = {
        "device_id": "stake-01",
        "timestamp": "2026-04-06T11:00:00Z",
        "profile": "heritage",
        "sensors": {
            "pir_triggered": True,
            "vibration": 0.85,
            "sound_db": 84.0,
            "thermal_presence": True,
            "light_change": 0.55,
            "battery_level": 88.0,
        },
        "audio_events": ["digging", "metal_hit"],
        "network": {
            "failed_logins": 5,
            "unknown_ip_hits": 8,
            "firmware_hash_mismatch": False,
            "bandwidth_spike": True,
            "repeated_port_scan_signals": 4,
        },
    }
    req = AnalyzeRequest(
        device_id=payload["device_id"],
        timestamp=payload["timestamp"],
        profile=payload["profile"],
        sensors=SensorPayload(**payload["sensors"]),
        audio_events=payload["audio_events"],
        network=NetworkPayload(**payload["network"]),
    )
    payload["event_signature"] = generate_signature(req)
    return payload


def test_v2_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200


def test_v2_verify_and_analyze() -> None:
    payload = make_payload()
    verify = client.post("/v2/verify", json=payload)
    assert verify.status_code == 200
    response = client.post("/v2/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["profile_used"] == "heritage"
    assert "explainability" in data
    assert data["alert"] is True
