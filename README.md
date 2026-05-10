# NEN CENTAURUS for ORIGIN

NEN CENTAURUS is a cyber-defense decision engine for ORIGIN environments. It fuses identity, network, runtime integrity, and physical tamper telemetry into a unified threat assessment and containment plan.

## Core API
- `POST /v3/assess` — primary threat assessment endpoint
- `POST /v1/analyze` — compatibility route mapped to the same v3 engine
- `GET /health` — health + engine state

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Sample request
```bash
curl -X POST http://127.0.0.1:8000/v3/assess \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-05-10T00:00:00Z",
    "mission_profile": "critical_infra",
    "identity": {
      "node_id": "origin-node-17",
      "operator_id": "op-77",
      "mfa_verified": false,
      "impossible_travel_flag": true,
      "privilege_escalation_attempts": 4
    },
    "network": {
      "src_ip": "203.0.113.77",
      "failed_logins_5m": 30,
      "unique_ports_scanned_5m": 24,
      "c2_beacon_score": 0.81,
      "tls_fingerprint_mismatch": true,
      "egress_bytes_5m": 220000000
    },
    "runtime": {
      "secure_boot_ok": false,
      "firmware_hash_match": false,
      "memory_tamper_alert": true,
      "unsigned_processes": 6,
      "suspicious_syscalls_1m": 250
    },
    "physical": {
      "enclosure_opened": true,
      "vibration": 0.89,
      "thermal_delta_c": 24,
      "ultrasonic_motion_score": 0.82
    },
    "telemetry_tags": ["night-shift", "vip-asset"]
  }'
```

## Security map
See `docs/NEN_CENTAURUS_SECURITY_MAP.md` for a full map of each capability, where it is useful, and what attacks it helps prevent.
