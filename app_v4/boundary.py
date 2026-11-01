"""Bounded ASGI security boundary, before JSON parsing or assessment."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from starlette.responses import JSONResponse

from app_v4.config import Settings
from app_v4.security import (
    KEY_ID,
    NONCE,
    SIGNATURE,
    TIMESTAMP,
    decode_public_key,
    signature_message,
)
from app_v4.state import CapacityExceeded, ReplayDetected, StateUnavailable


class Rejected(Exception):
    def __init__(self, status: int, detail: str):
        self.status, self.detail = status, detail


class SecurityBoundary:
    def __init__(self, app, settings: Settings):
        self.app, self.settings = app, settings
        self.public_keys = {
            key_id: Ed25519PublicKey.from_public_bytes(decode_public_key(key.public_key))
            for key_id, key in settings.keys.items()
        }

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cfg = self.settings
        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        store = scope["app"].state.store
        now = int(time.time())
        messages = []
        key_id = None
        digest = None
        audit = True
        authenticated = False

        async def capture(message):
            messages.append(message)

        try:
            if not store.allow("global", now, cfg.global_requests_per_minute):
                audit = False  # Floods cannot force unbounded audit writes.
                raise Rejected(429, "Request rate exceeded")
            if cfg.mode == "production" and scope.get("scheme") != "https":
                raise Rejected(400, "HTTPS is required")
            if scope.get("query_string"):
                raise Rejected(400, "Query parameters are not supported")
            raw_headers = scope.get("headers", [])
            if sum(len(k) + len(v) for k, v in raw_headers) > 8192:
                raise Rejected(431, "Request headers too large")
            seen = set()
            for name, _ in raw_headers:
                if name in seen and (
                    name.startswith(b"x-centaurus-")
                    or name
                    in {
                        b"host",
                        b"content-length",
                        b"content-type",
                        b"content-encoding",
                    }
                ):
                    raise Rejected(400, "Duplicate security header")
                seen.add(name)
            headers = dict(raw_headers)
            path = scope["path"]
            if scope["method"] == "POST" and path == "/v4/assess":
                if scope.get("raw_path", path.encode()) != b"/v4/assess":
                    raise Rejected(400, "Non-canonical request path")

                def header(name):
                    return headers.get(name.encode(), b"").decode("ascii")

                key_id = header("x-centaurus-key-id")
                ts = header("x-centaurus-timestamp")
                nonce = header("x-centaurus-nonce")
                signature = header("x-centaurus-signature")
                if not (
                    KEY_ID.fullmatch(key_id)
                    and TIMESTAMP.fullmatch(ts)
                    and NONCE.fullmatch(nonce)
                    and SIGNATURE.fullmatch(signature)
                ):
                    key_id = None
                    raise Rejected(401, "Request authentication failed")
                key = cfg.keys.get(key_id)
                if not key or not key.enabled or abs(now - int(ts)) > cfg.max_clock_skew_seconds:
                    key_id = None
                    raise Rejected(401, "Request authentication failed")
                if (
                    headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
                    != b"application/json"
                ):
                    raise Rejected(415, "Content-Type must be application/json")
                if b"content-encoding" in headers:
                    raise Rejected(415, "Encoded request bodies are not supported")
                length = headers.get(b"content-length")
                if length is not None and (not length.isdigit() or len(length) > 9):
                    raise Rejected(400, "Invalid Content-Length")
                if length is not None and int(length) > cfg.max_body_bytes:
                    raise Rejected(413, "Request body too large")
                chunks, size = [], 0
                try:
                    async with asyncio.timeout(cfg.request_timeout_seconds):
                        while True:
                            chunk = await receive()
                            if chunk["type"] == "http.disconnect":
                                raise Rejected(400, "Incomplete request")
                            body_chunk = chunk.get("body", b"")
                            size += len(body_chunk)
                            if size > cfg.max_body_bytes:
                                raise Rejected(413, "Request body too large")
                            chunks.append(body_chunk)
                            if not chunk.get("more_body", False):
                                break
                except TimeoutError:
                    raise Rejected(408, "Request body timeout") from None
                body = b"".join(chunks)
                if length is not None and len(body) != int(length):
                    raise Rejected(400, "Incomplete request")
                try:
                    self.public_keys[key_id].verify(
                        bytes.fromhex(signature),
                        signature_message(key_id, ts, nonce, scope["method"], path, body),
                    )
                except InvalidSignature:
                    raise Rejected(401, "Request authentication failed") from None
                authenticated = True
                now = int(time.time())
                if abs(now - int(ts)) > cfg.max_clock_skew_seconds:
                    raise Rejected(401, "Request authentication failed")
                if not store.allow(f"key:{key_id}", now, cfg.key_requests_per_minute):
                    raise Rejected(429, "Device request rate exceeded")
                # Signed metadata binds raw bytes, method, route, key ID and nonce.
                store.consume_nonce(
                    key_id,
                    nonce,
                    now,
                    int(ts) + cfg.max_clock_skew_seconds,
                    cfg.max_pending_nonces,
                )
                digest = hashlib.sha256(body).hexdigest()
                scope["state"]["node_id"] = key.node_id
                scope["state"]["signed_body"] = body

                async def buffered_receive():
                    return {"type": "http.request", "body": body, "more_body": False}

                await self.app(scope, buffered_receive, capture)
            else:
                await self.app(scope, receive, capture)
        except Rejected as exc:
            messages = []
            response = JSONResponse(
                {"detail": exc.detail, "request_id": request_id}, status_code=exc.status
            )
            if exc.status == 429:
                response.headers["Retry-After"] = "60"
            await response(scope, receive, capture)
        except ReplayDetected:
            messages = []
            await JSONResponse(
                {"detail": "Request replay rejected", "request_id": request_id},
                status_code=409,
            )(scope, receive, capture)
        except (StateUnavailable, CapacityExceeded):
            messages = []
            audit = False
            await JSONResponse(
                {"detail": "Security state unavailable", "request_id": request_id},
                status_code=503,
            )(scope, receive, capture)
        except (UnicodeError, ValueError):
            messages = []
            await JSONResponse(
                {"detail": "Malformed request", "request_id": request_id},
                status_code=400,
            )(scope, receive, capture)
        except Exception as exc:  # noqa: BLE001 — sanitize internal errors at the API boundary.
            logging.getLogger(__name__).error(
                "Internal request failure: id=%s type=%s", request_id, type(exc).__name__
            )
            messages = []
            await JSONResponse(
                {"detail": "Request could not be processed", "request_id": request_id},
                status_code=500,
            )(scope, receive, capture)

        receipt = None
        status = messages[0]["status"]
        # Health and metadata reads do not grow the audit table. All mutations
        # and rejected requests within the global budget leave a receipt.
        if audit and (scope["method"] != "GET" or status >= 400):
            try:
                receipt = store.append_audit(
                    {
                        "request_id": request_id,
                        "received_at": now,
                        "key_id": key_id if authenticated else None,
                        "authenticated": authenticated,
                        "body_sha256": digest,
                        "response_sha256": hashlib.sha256(
                            b"".join(
                                m.get("body", b"")
                                for m in messages
                                if m["type"] == "http.response.body"
                            )
                        ).hexdigest(),
                        "status": status,
                        "risk": scope["state"].get("risk"),
                        "policy_version": "abyssal-1",
                    }
                )
            except StateUnavailable:
                messages = []
                await JSONResponse(
                    {"detail": "Security state unavailable", "request_id": request_id},
                    status_code=503,
                )(scope, receive, capture)
        for message in messages:
            if message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers += [
                    (b"x-request-id", request_id.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                    (
                        b"content-security-policy",
                        b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
                    ),
                    (
                        b"permissions-policy",
                        b"camera=(), microphone=(), geolocation=()",
                    ),
                ]
                if cfg.mode == "production":
                    response_headers.append((b"strict-transport-security", b"max-age=31536000"))
                if receipt:
                    response_headers += [
                        (b"x-audit-sequence", str(receipt[0]).encode()),
                        (b"x-audit-digest", receipt[1].encode()),
                    ]
                message["headers"] = response_headers
            await send(message)
