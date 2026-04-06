# CENTAURUS AI

Open-source MVP of the CENTAURUS AI layer for ORIGIN.

## Features
- FastAPI backend
- Sensor ingestion endpoint
- Rule-based + weighted anomaly scoring
- Sound intelligence event handling
- Cybersecurity anomaly checks
- Alert generation
- Health/status endpoints
- Simple test suite

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open docs at `http://127.0.0.1:8000/docs`

## Example request
```bash
curl -X POST http://127.0.0.1:8000/v1/analyze \\
  -H "Content-Type: application/json" \\
  -d '{
    "device_id": "stake-01",
    "timestamp": "2026-04-06T11:00:00Z",
    "sensors": {
      "pir_triggered": true,
      "vibration": 0.78,
      "sound_db": 81.0,
      "thermal_presence": true,
      "light_change": 0.21
    },
    "audio_events": ["digging", "metal_hit"],
    "network": {
      "failed_logins": 4,
      "unknown_ip_hits": 7,
      "firmware_hash_mismatch": false,
      "bandwidth_spike": true
    }
  }'
```

## License
MIT
