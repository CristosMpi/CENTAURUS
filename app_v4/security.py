"""Versioned signature protocol shared by the device client and ASGI boundary."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}\Z")
NONCE = re.compile(r"[a-zA-Z0-9_-]{22,64}\Z")
SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")
TIMESTAMP = re.compile(r"[0-9]{10}\Z")


def signature_message(
    key_id: str, timestamp: str, nonce: str, method: str, path: str, body: bytes
) -> bytes:
    return "\n".join(
        (
            "CENTAURUS-ABYSSAL-V4",
            key_id,
            timestamp,
            nonce,
            method,
            path,
            hashlib.sha256(body).hexdigest(),
        )
    ).encode("ascii")


def sign_headers(
    private_key: bytes,
    key_id: str,
    body: bytes,
    *,
    path: str = "/v4/assess",
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    nonce = secrets.token_urlsafe(24) if nonce is None else nonce
    if not KEY_ID.fullmatch(key_id) or not NONCE.fullmatch(nonce) or not TIMESTAMP.fullmatch(ts):
        raise ValueError("Invalid signature metadata")
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
        signature_message(key_id, ts, nonce, "POST", path, body)
    )
    return {
        "Content-Type": "application/json",
        "X-Centaurus-Key-Id": key_id,
        "X-Centaurus-Timestamp": ts,
        "X-Centaurus-Nonce": nonce,
        "X-Centaurus-Signature": signature.hex(),
    }


def decode_public_key(value: str) -> bytes:
    return base64.b64decode(value, validate=True)
