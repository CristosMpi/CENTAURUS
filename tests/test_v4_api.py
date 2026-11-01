from __future__ import annotations

import asyncio
import base64
import json
import secrets
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app_v4.boundary import SecurityBoundary
from app_v4.config import Settings
from app_v4.main import create_app
from app_v4.security import sign_headers
from app_v4.state import StateStore, StateUnavailable


def payload():
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "mission_profile": "remote_outpost",
        "identity": {
            "node_id": "origin-node-17",
            "operator_id": "operator-01",
            "mfa_verified": True,
        },
        "network": {"src_ip": "192.0.2.17"},
        "runtime": {"secure_boot_ok": True, "firmware_hash_match": True},
        "physical": {},
    }


@pytest.fixture
def system(tmp_path):
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    cfg = Settings(
        keys={"device-key-01": {"node_id": "origin-node-17", "public_key": public}},
        audit_key=secrets.token_bytes(32),
        state_path=tmp_path / "state" / "abyssal.sqlite3",
        allowed_hosts=("testserver",),
    )
    with TestClient(create_app(cfg), base_url="https://testserver") as client:
        yield SimpleNamespace(client=client, private=private, cfg=cfg)


def signed(system, event=None, **kwargs):
    body = json.dumps(payload() if event is None else event).encode()
    return body, sign_headers(system.private, "device-key-01", body, **kwargs)


def post(system, event=None, **kwargs):
    body, headers = signed(system, event, **kwargs)
    return system.client.post("/v4/assess", content=body, headers=headers)


def test_authenticated_assessment_and_receipt(system):
    response = post(system)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["engine_version"] == "4.0.0"
    assert data["overall_risk"] == "low"
    assert data["telemetry_trust"] == "authenticated_source_only"
    assert data["execution_mode"] == "recommendation_only"
    assert "confidence" not in data
    assert "prevented_attacks" not in json.dumps(data)
    assert response.headers["x-audit-sequence"] == "1"
    assert len(response.headers["x-audit-digest"]) == 64
    assert all(action["requires_operator_approval"] for action in data["recommended_actions"])


def test_unsigned_rejected_before_assessment(system):
    assert system.client.post("/v4/assess", json=payload()).status_code == 401


@pytest.mark.parametrize(
    "section,field,value",
    [
        ("network", "egress_bytes_5m", 999999999),
        ("runtime", "firmware_hash_match", False),
        ("identity", "operator_id", "other-user"),
        ("physical", "enclosure_opened", True),
    ],
)
def test_signature_covers_all_telemetry(system, section, field, value):
    event = payload()
    _, headers = signed(system, event)
    event[section][field] = value
    response = system.client.post("/v4/assess", content=json.dumps(event).encode(), headers=headers)
    assert response.status_code == 401


def test_signature_binds_route_and_raw_bytes(system):
    assert post(system, path="/v3/assess").status_code == 401
    body, headers = signed(system)
    assert system.client.post("/v4/assess", content=body + b" ", headers=headers).status_code == 401


def test_forged_signature_does_not_consume_device_budget(system):
    # An attacker who learns a public key ID must not exhaust that device's quota.
    cfg = system.cfg.model_copy(update={"key_requests_per_minute": 1})
    with TestClient(create_app(cfg), base_url="https://testserver") as client:
        body, headers = signed(system)
        headers["X-Centaurus-Signature"] = "0" * 128
        assert client.post("/v4/assess", content=body, headers=headers).status_code == 401
        body, headers = signed(system)
        assert client.post("/v4/assess", content=body, headers=headers).status_code == 200


def test_key_cannot_impersonate_another_node(system):
    event = payload()
    event["identity"]["node_id"] = "origin-node-18"
    assert post(system, event).status_code == 403


@pytest.mark.parametrize("key_id", ["unknown-key", "device-key-01"])
def test_unknown_or_revoked_key(system, key_id):
    keys = {
        name: key.model_copy(update={"enabled": False}) for name, key in system.cfg.keys.items()
    }
    with TestClient(
        create_app(system.cfg.model_copy(update={"keys": keys})),
        base_url="https://testserver",
    ) as client:
        body, _ = signed(system)
        headers = sign_headers(system.private, key_id, body)
        assert client.post("/v4/assess", content=body, headers=headers).status_code == 401


@pytest.mark.parametrize("offset", [-61, 61, -100000])
def test_signature_timestamp_window(system, offset):
    assert post(system, timestamp=int(time.time()) + offset).status_code == 401


def test_replay_persists_across_app_instances(system):
    body, headers = signed(system)
    assert system.client.post("/v4/assess", content=body, headers=headers).status_code == 200
    with TestClient(create_app(system.cfg), base_url="https://testserver") as restarted:
        assert restarted.post("/v4/assess", content=body, headers=headers).status_code == 409


def test_concurrent_replay_is_atomic(system):
    body, headers = signed(system)

    def send(_):
        return system.client.post("/v4/assess", content=body, headers=headers).status_code

    with ThreadPoolExecutor(max_workers=6) as pool:
        codes = list(pool.map(send, range(6)))
    assert codes.count(200) == 1
    assert codes.count(409) == 5


@pytest.mark.parametrize("offset", [-301, 30])
def test_telemetry_freshness_separate_from_signature(system, offset):
    event = payload()
    event["timestamp"] = (datetime.now(UTC) + timedelta(seconds=offset)).isoformat()
    assert post(system, event).status_code == 422


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(unexpected="secret-value"),
        lambda p: p["runtime"].update(unexpected=True),
        lambda p: p["runtime"].update(secure_boot_ok="true"),
        lambda p: p["network"].update(failed_logins_5m=True),
        lambda p: p["network"].update(failed_logins_5m=-1),
        lambda p: p["network"].update(c2_beacon_score=float("nan")),
        lambda p: p["network"].update(c2_beacon_score=float("inf")),
        lambda p: p["network"].update(src_ip="not-an-ip"),
        lambda p: p.update(timestamp="2026-11-01T12:00:00"),
        lambda p: p.update(telemetry_tags=["x"] * 17),
        lambda p: p["identity"].update(node_id="../bad-node"),
    ],
)
def test_strict_validation_and_redacted_errors(system, mutate):
    event = payload()
    mutate(event)
    response = post(system, event)
    assert response.status_code == 422
    assert response.json()["detail"] == "Invalid assessment payload"
    assert "secret-value" not in response.text
    assert "input" not in response.json()


def test_duplicate_json_fields_are_rejected(system):
    body = (
        json.dumps(payload())
        .replace('"secure_boot_ok": true', '"secure_boot_ok": false, "secure_boot_ok": true')
        .encode()
    )
    headers = sign_headers(system.private, "device-key-01", body)
    assert system.client.post("/v4/assess", content=body, headers=headers).status_code == 422


@pytest.mark.parametrize(
    "section,field,value,expected",
    [
        ("runtime", "firmware_hash_match", False, "critical"),
        ("runtime", "memory_tamper_alert", True, "critical"),
        ("runtime", "secure_boot_ok", False, "elevated"),
        ("deception", "canary_credential_used", True, "critical"),
        ("deception", "honeytoken_touched", True, "critical"),
        ("deception", "decoy_service_touched", True, "elevated"),
        ("identity", "mfa_verified", False, "guarded"),
    ],
)
def test_critical_evidence_cannot_be_diluted(system, section, field, value, expected):
    event = payload()
    event.setdefault(section, {})[field] = value
    response = post(system, event)
    assert response.status_code == 200
    assert response.json()["overall_risk"] == expected
    assert response.json()["policy_triggers"]


def test_missing_integrity_never_defaults_to_healthy(system):
    event = payload()
    event["runtime"] = {}
    del event["identity"]["mfa_verified"]
    data = post(system, event).json()
    assert data["overall_risk"] == "guarded"
    assert len(data["evidence_gaps"]) == 3


def test_host_tls_and_proxy_spoofing(system):
    assert system.client.get("/health", headers={"host": "evil.example"}).status_code == 400
    assert (
        system.client.get(
            "http://testserver/health", headers={"X-Forwarded-Proto": "https"}
        ).status_code
        == 400
    )
    assert system.client.get("/health").status_code == 200


@pytest.mark.parametrize(
    "path", ["/docs", "/openapi.json", "/v3/assess", "/v2/analyze", "/v1/analyze"]
)
def test_legacy_and_debug_routes_not_exposed(system, path):
    assert system.client.get(path).status_code == 404
    assert system.client.post(path, json=payload()).status_code == 404


def test_security_headers_on_success_and_error(system):
    for response in (post(system), system.client.post("/v4/assess", json=payload())):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in response.headers["content-security-policy"]
        assert response.headers["strict-transport-security"]
        assert response.headers["x-request-id"] == response.json()["request_id"]


def test_query_encoding_and_duplicate_headers(system):
    body, headers = signed(system)
    assert (
        system.client.post("/v4/assess?debug=true", content=body, headers=headers).status_code
        == 400
    )
    assert (
        system.client.post(
            "/v4/assess", content=body, headers={**headers, "content-encoding": "gzip"}
        ).status_code
        == 415
    )
    duplicated = list(headers.items()) + [("X-Centaurus-Nonce", headers["X-Centaurus-Nonce"])]
    assert system.client.post("/v4/assess", content=body, headers=duplicated).status_code == 400


def test_body_size_and_content_type(system):
    body = b"x" * (system.cfg.max_body_bytes + 1)
    headers = sign_headers(system.private, "device-key-01", body)
    assert system.client.post("/v4/assess", content=body, headers=headers).status_code == 413
    # No Content-Length: enforce the limit while receiving too.
    assert (
        system.client.post("/v4/assess", content=iter([body]), headers=headers).status_code == 413
    )
    body, headers = signed(system)
    headers["Content-Type"] = "text/plain"
    assert system.client.post("/v4/assess", content=body, headers=headers).status_code == 415


def test_rate_limits_share_database(system):
    cfg = system.cfg.model_copy(update={"key_requests_per_minute": 1})
    with TestClient(create_app(cfg), base_url="https://testserver") as client:
        for expected in (200, 429):
            body, headers = signed(system)
            assert client.post("/v4/assess", content=body, headers=headers).status_code == expected
    with TestClient(create_app(cfg), base_url="https://testserver") as restarted:
        body, headers = signed(system)
        response = restarted.post("/v4/assess", content=body, headers=headers)
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "60"


def test_global_limit_bounds_unauthenticated_flood(system):
    cfg = system.cfg.model_copy(update={"global_requests_per_minute": 1})
    with TestClient(create_app(cfg), base_url="https://testserver") as client:
        assert client.post("/v4/assess", json={}).status_code == 401
        assert client.post("/v4/assess", json={}).status_code == 429


def test_nonce_capacity_fails_closed(system):
    cfg = system.cfg.model_copy(update={"max_pending_nonces": 1})
    with TestClient(create_app(cfg), base_url="https://testserver") as client:
        for expected in (200, 503):
            body, headers = signed(system)
            assert client.post("/v4/assess", content=body, headers=headers).status_code == expected


def test_audit_has_no_raw_payload_or_secret(system):
    event = payload()
    event["telemetry_tags"] = ["private-site-marker"]
    response = post(system, event)
    with sqlite3.connect(system.cfg.state_path) as db:
        encoded, digest = db.execute("SELECT event,digest FROM audit").fetchone()
    assert "private-site-marker" not in encoded
    assert "192.0.2.17" not in encoded
    assert "Signature" not in encoded
    assert json.loads(encoded)["authenticated"] is True
    assert digest == response.headers["x-audit-digest"]


def test_audit_tamper_detected_at_startup_and_tail_write(system):
    assert post(system).status_code == 200
    with sqlite3.connect(system.cfg.state_path) as db:
        db.execute("UPDATE audit SET event='{}' WHERE seq=1")
    assert post(system).status_code == 503
    with pytest.raises(StateUnavailable):
        StateStore(system.cfg.state_path, system.cfg.audit_key.get_secret_value())


def test_full_audit_verification_detects_middle_modification(system):
    for _ in range(3):
        assert post(system).status_code == 200
    with sqlite3.connect(system.cfg.state_path) as db:
        db.execute("UPDATE audit SET event='{}' WHERE seq=2")
    with pytest.raises(StateUnavailable):
        system.client.app.state.store.verify_audit()


def test_state_failure_never_returns_success(system, monkeypatch):
    def unavailable(*args, **kwargs):
        raise StateUnavailable

    monkeypatch.setattr(system.client.app.state.store, "append_audit", unavailable)
    assert post(system).status_code == 503


def test_startup_rejects_missing_or_weak_configuration(tmp_path, monkeypatch, system):
    monkeypatch.delenv("CENTAURUS_CONFIG_FILE", raising=False)
    with pytest.raises(KeyError):
        create_app()
    raw = system.cfg.model_dump()
    raw["audit_key"] = b"change-me"
    with pytest.raises(ValidationError):
        Settings.model_validate(raw)
    raw = system.cfg.model_dump()
    raw["allowed_hosts"] = ("*",)
    with pytest.raises(ValidationError):
        Settings.model_validate(raw)


def test_nonce_can_expire_but_old_signature_still_rejected(system):
    store = system.client.app.state.store
    now = int(time.time())
    store.consume_nonce("device-key-01", "expired", now - 10, now - 1, 100)
    store.consume_nonce("device-key-01", "new", now, now + 10, 100)
    with sqlite3.connect(system.cfg.state_path) as db:
        assert db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0] == 1


def test_audit_capacity_fails_closed(system):
    cfg = system.cfg.model_copy(update={"max_audit_records": 1})
    with TestClient(create_app(cfg), base_url="https://testserver") as client:
        for expected in (200, 503):
            body, headers = signed(system)
            assert client.post("/v4/assess", content=body, headers=headers).status_code == expected


def test_noncanonical_route_and_trailing_slash_rejected(system):
    body, headers = signed(system)
    assert system.client.post("/v4/%61ssess", content=body, headers=headers).status_code == 400
    assert system.client.post("/v4/assess/", content=body, headers=headers).status_code == 404


def test_thermal_boundary_is_consistent_with_underlying_engine(system):
    event = payload()
    event["physical"]["thermal_delta_c"] = 80
    assert post(system, event).status_code == 200
    event["physical"]["thermal_delta_c"] = 81
    assert post(system, event).status_code == 422


def test_slow_request_body_has_a_deadline(system):
    body, headers = signed(system)
    cfg = system.cfg.model_copy(update={"request_timeout_seconds": 0.1})

    async def inner(scope, receive, send):
        pytest.fail("Timed-out requests must not reach assessment")

    async def slow_receive():
        await asyncio.sleep(1)
        return {"type": "http.request", "body": body}

    messages = []

    async def collect(message):
        messages.append(message)

    scope = {
        "type": "http",
        "app": system.client.app,
        "scheme": "https",
        "method": "POST",
        "path": "/v4/assess",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    asyncio.run(SecurityBoundary(inner, cfg)(scope, slow_receive, collect))
    assert messages[0]["status"] == 408


def test_header_budget(system):
    body, headers = signed(system)
    headers["X-Oversized"] = "x" * 8192
    assert system.client.post("/v4/assess", content=body, headers=headers).status_code == 431


def test_deeply_nested_json_is_rejected(system):
    body = b"[" * 1100 + b"0" + b"]" * 1100
    headers = sign_headers(system.private, "device-key-01", body)
    assert system.client.post("/v4/assess", content=body, headers=headers).status_code == 422
