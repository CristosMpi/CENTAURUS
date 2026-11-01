"""Fail-closed configuration; the server stores device PUBLIC keys only."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretBytes,
    field_validator,
    model_validator,
)

IDENTIFIER = r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$"


class DeviceKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    node_id: str = Field(pattern=IDENTIFIER)
    public_key: str
    enabled: bool = True

    @field_validator("public_key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError("Expected a base64 Ed25519 public key")
        return value


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    mode: Literal["production", "development"] = "production"
    keys: dict[str, DeviceKey] = Field(min_length=1, max_length=10000)
    audit_key: SecretBytes
    state_path: Path = Path("state/abyssal.sqlite3")
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1")
    max_body_bytes: int = Field(default=32768, ge=1024, le=262144)
    request_timeout_seconds: float = Field(default=5, ge=0.1, le=30)
    max_clock_skew_seconds: int = Field(default=60, ge=5, le=300)
    max_event_age_seconds: int = Field(default=300, ge=5, le=3600)
    key_requests_per_minute: int = Field(default=60, ge=1, le=10000)
    global_requests_per_minute: int = Field(default=600, ge=1, le=100000)
    max_pending_nonces: int = Field(default=100000, ge=1, le=1000000)
    max_audit_records: int = Field(default=1000000, ge=1, le=100000000)

    @model_validator(mode="after")
    def validate_security(self) -> Settings:
        if len(self.audit_key.get_secret_value()) < 32:
            raise ValueError("Audit key must contain at least 32 random bytes")
        if not self.allowed_hosts or any("*" in h or "/" in h for h in self.allowed_hosts):
            raise ValueError("Explicit allowed hosts are required; wildcards are forbidden")
        for key_id in self.keys:
            import re

            if not re.fullmatch(IDENTIFIER, key_id):
                raise ValueError("Invalid key ID")
        return self

    @classmethod
    def from_env(cls) -> Settings:
        # Missing configuration deliberately prevents startup. No demo keys exist.
        path = Path(os.environ["CENTAURUS_CONFIG_FILE"])
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ValueError("Configuration must be private (chmod 600)")
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["audit_key"] = base64.b64decode(raw["audit_key"], validate=True)
        return cls.model_validate(raw)
