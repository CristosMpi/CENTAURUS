"""Provision devices, sign local telemetry, and verify ABYSSAL audit receipts."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from app_v4.config import Settings
from app_v4.security import KEY_ID, sign_headers
from app_v4.state import StateStore


def write_private(path: Path, value: dict):
    with open(
        os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600),
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(value, file, indent=2)
        file.write("\n")


def read_private(path: Path) -> dict:
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError(f"Restrict {path.name} permissions to 600")
    return json.loads(path.read_text(encoding="utf-8"))


def provision(args):
    if not KEY_ID.fullmatch(args.node) or not KEY_ID.fullmatch(args.key_id):
        raise ValueError(
            "Node and key IDs must be 3–64 letters, digits, dots, underscores or hyphens"
        )
    args.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    config = {
        "mode": "development" if args.development else "production",
        "keys": {
            args.key_id: {
                "node_id": args.node,
                "public_key": base64.b64encode(public_bytes).decode(),
                "enabled": True,
            }
        },
        "audit_key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "state_path": str((args.directory / "state" / "abyssal.sqlite3").resolve()),
        "allowed_hosts": args.host or ["localhost", "127.0.0.1"],
    }
    write_private(args.directory / "server.json", config)
    write_private(
        args.directory / "device.json",
        {
            "node_id": args.node,
            "key_id": args.key_id,
            "private_key": base64.b64encode(private_bytes).decode(),
        },
    )
    print(f"Created {args.directory / 'server.json'} and {args.directory / 'device.json'}")
    print("Keep device.json on the device; the server needs only server.json.")


def sample(args):
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "mission_profile": "remote_outpost",
        "identity": {
            "node_id": args.node,
            "operator_id": "operator-01",
            "mfa_verified": True,
        },
        "network": {"src_ip": "192.0.2.17"},
        "runtime": {"secure_boot_ok": True, "firmware_hash_match": True},
        "physical": {},
        "telemetry_tags": ["sample-only"],
    }
    write_private(args.output, payload)
    print(f"Created sample telemetry at {args.output}")


def send_assessment(args):
    url = urlsplit(args.url)
    local_http = (
        args.allow_local_http
        and url.scheme == "http"
        and url.hostname in {"127.0.0.1", "localhost", "::1"}
    )
    if not ((url.scheme == "https" and url.hostname) or local_http):
        raise ValueError("Use HTTPS, or explicitly enable HTTP for a loopback development server")
    if url.username or url.password or url.query or url.fragment or url.path != "/v4/assess":
        raise ValueError("URL must end in /v4/assess without credentials, query or fragment")
    device = read_private(args.device_file)
    body = args.payload.read_bytes()
    if len(body) > 32768:
        raise ValueError("Payload exceeds the default server limit")
    private = base64.b64decode(device["private_key"], validate=True)
    headers = sign_headers(private, device["key_id"], body)
    with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
        response = client.post(args.url, content=body, headers=headers)
    print(response.text)
    if "x-audit-digest" in response.headers:
        print(
            f"Audit receipt: {response.headers['x-audit-sequence']} {response.headers['x-audit-digest']}",
            file=sys.stderr,
        )
    if response.status_code != 200:
        raise SystemExit(1)


def verify(args):
    raw = read_private(args.config)
    raw["audit_key"] = base64.b64decode(raw["audit_key"], validate=True)
    config = Settings.model_validate(raw)
    if not config.state_path.exists():
        raise ValueError("Audit database does not exist")
    store = StateStore(config.state_path, config.audit_key.get_secret_value())
    seq, digest = store.verify_audit()
    if (args.expected_sequence is None) != (args.expected_digest is None):
        raise ValueError("Supply both expected sequence and digest")
    if args.expected_sequence is not None and (seq, digest) != (
        args.expected_sequence,
        args.expected_digest,
    ):
        raise ValueError("Audit head does not match the independently saved receipt")
    print(json.dumps({"valid": True, "sequence": seq, "digest": digest}))


def main():
    parser = argparse.ArgumentParser(description="CENTAURUS V4 — ABYSSAL device toolkit")
    sub = parser.add_subparsers(required=True)
    setup = sub.add_parser("provision", help="Create a fresh device identity and server config")
    setup.add_argument("--directory", type=Path, default=Path(".abyssal"))
    setup.add_argument("--node", default="origin-node-17")
    setup.add_argument("--key-id", default="origin-node-17-key-01")
    setup.add_argument(
        "--host", action="append", help="Explicit allowed hostname; repeat as needed"
    )
    setup.add_argument("--development", action="store_true", help="Explicitly permit local HTTP")
    setup.set_defaults(run=provision)
    example = sub.add_parser("sample", help="Write fresh synthetic sample telemetry")
    example.add_argument("--node", default="origin-node-17")
    example.add_argument("--output", type=Path, default=Path(".abyssal/sample.json"))
    example.set_defaults(run=sample)
    send = sub.add_parser("assess", help="Sign exact payload bytes and send without redirects")
    send.add_argument("--device-file", type=Path, default=Path(".abyssal/device.json"))
    send.add_argument("--payload", type=Path, default=Path(".abyssal/sample.json"))
    send.add_argument("--url", required=True)
    send.add_argument("--allow-local-http", action="store_true")
    send.set_defaults(run=send_assessment)
    check = sub.add_parser("verify-audit", help="Verify the complete local HMAC chain")
    check.add_argument("--config", type=Path, default=Path(".abyssal/server.json"))
    check.add_argument("--expected-sequence", type=int)
    check.add_argument("--expected-digest")
    check.set_defaults(run=verify)
    args = parser.parse_args()
    try:
        args.run(args)
    except (ValueError, OSError, KeyError, httpx.HTTPError) as exc:
        parser.exit(1, f"ABYSSAL: {exc}\n")


if __name__ == "__main__":
    main()
