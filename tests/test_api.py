from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_high_risk_analysis() -> None:
    payload = {
        "device_id": "stake-01",
        "timestamp": "2026-04-06T11:00:00Z",
        "sensors": {
            "pir_triggered": True,
            "vibration": 0.85,
            "sound_db": 84.0,
            "thermal_presence": True,
            "light_change": 0.55,
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
    response = client.post("/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in {"medium", "high"}
    assert data["alert"] is True
    assert "Notify operator" in data["recommended_actions"]
