from __future__ import annotations

import argparse
import base64
import json
import os
import sqlite3

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient

from app_v4.config import Settings
from app_v4.main import create_app
from app_v4.security import sign_headers
from scripts.abyssal import provision, read_private, sample, send_assessment, verify


def provisioned(tmp_path, monkeypatch):
    directory = tmp_path / "credentials"
    args = argparse.Namespace(
        directory=directory,
        node="origin-node-17",
        key_id="device-key-01",
        development=True,
        host=["testserver"],
    )
    provision(args)
    path = directory / "server.json"
    monkeypatch.setenv("CENTAURUS_CONFIG_FILE", str(path))
    return directory, Settings.from_env()


def test_provision_sample_and_audit_round_trip(tmp_path, monkeypatch, capsys):
    directory, config = provisioned(tmp_path, monkeypatch)
    assert config.mode == "development"
    assert "private_key" not in json.dumps(read_private(directory / "server.json"))
    if os.name == "posix":
        assert (directory / "device.json").stat().st_mode & 0o777 == 0o600
    output = directory / "sample.json"
    sample(argparse.Namespace(node="origin-node-17", output=output))
    device = read_private(directory / "device.json")
    body = output.read_bytes()
    headers = sign_headers(base64.b64decode(device["private_key"]), device["key_id"], body)
    with TestClient(create_app(config), base_url="http://testserver") as client:
        response = client.post("/v4/assess", content=body, headers=headers)
    assert response.status_code == 200
    check = argparse.Namespace(
        config=directory / "server.json",
        expected_sequence=1,
        expected_digest=response.headers["x-audit-digest"],
    )
    verify(check)
    assert '"valid": true' in capsys.readouterr().out
    # A valid prefix still has a valid HMAC chain; an external receipt detects loss.
    with sqlite3.connect(config.state_path) as db:
        db.execute("DELETE FROM audit")
    with pytest.raises(ValueError, match="independently saved receipt"):
        verify(check)


def test_provision_does_not_overwrite(tmp_path, monkeypatch):
    directory, _ = provisioned(tmp_path, monkeypatch)
    with pytest.raises(FileExistsError):
        provision(
            argparse.Namespace(
                directory=directory,
                node="origin-node-17",
                key_id="device-key-01",
                development=True,
                host=[],
            )
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_configuration_permissions(tmp_path, monkeypatch):
    directory, _ = provisioned(tmp_path, monkeypatch)
    (directory / "server.json").chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        Settings.from_env()
    with pytest.raises(ValueError, match="permissions"):
        read_private(directory / "server.json")


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/v4/assess",
        "https://example.com/wrong",
        "https://user:pass@example.com/v4/assess",
        "https://example.com/v4/assess?x=1",
        "file:///v4/assess",
    ],
)
def test_client_rejects_unsafe_or_ambiguous_urls(url):
    with pytest.raises(ValueError):
        send_assessment(argparse.Namespace(url=url, allow_local_http=True))


def test_client_signs_exact_bytes_and_never_follows_redirects(tmp_path, monkeypatch):
    directory, _ = provisioned(tmp_path, monkeypatch)
    output = directory / "sample.json"
    sample(argparse.Namespace(node="origin-node-17", output=output))
    transport = httpx.MockTransport(
        lambda req: httpx.Response(307, headers={"location": "https://untrusted.example/v4/assess"})
    )
    original_client = httpx.Client

    def factory(**kwargs):
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        return original_client(transport=transport, **kwargs)

    monkeypatch.setattr("scripts.abyssal.httpx.Client", factory)
    with pytest.raises(SystemExit) as result:
        send_assessment(
            argparse.Namespace(
                url="https://origin.example/v4/assess",
                allow_local_http=False,
                device_file=directory / "device.json",
                payload=output,
            )
        )
    assert result.value.code == 1


def test_signer_rejects_bad_metadata():
    key = Ed25519PrivateKey.generate().private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    with pytest.raises(ValueError):
        sign_headers(key, "bad\nkey", b"{}")
    with pytest.raises(ValueError):
        sign_headers(key, "device-key-01", b"{}", nonce="short")
