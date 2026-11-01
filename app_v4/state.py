"""Single-host, multi-worker replay protection and serialized audit storage."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path


class StateUnavailable(Exception):
    pass


class ReplayDetected(Exception):
    pass


class CapacityExceeded(Exception):
    pass


class StateStore:
    def __init__(self, path: Path, audit_key: bytes, max_audit_records: int = 1000000):
        self.path = path
        self.audit_key = audit_key
        self.max_audit_records = max_audit_records
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("State storage must not be a symlink")
        if os.name == "posix" and stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
            raise ValueError("State directory must be private (chmod 700)")
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
        if not path.is_file():
            raise ValueError("State path must be a regular file")
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ValueError("State database must be private (chmod 600)")
        with self.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS nonces (key_id TEXT, nonce TEXT, expires INTEGER, PRIMARY KEY(key_id, nonce))"
            )
            db.execute("CREATE INDEX IF NOT EXISTS nonce_expiry ON nonces(expires)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS limits (bucket TEXT PRIMARY KEY, window INTEGER, count INTEGER)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, event TEXT NOT NULL, previous TEXT NOT NULL, digest TEXT NOT NULL)"
            )
        self.verify_audit()

    @contextmanager
    def transaction(self):
        try:
            db = sqlite3.connect(self.path, timeout=2, isolation_level=None)
            try:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.execute("COMMIT")
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()
        except sqlite3.Error as exc:
            raise StateUnavailable("Security state unavailable") from exc

    def allow(self, bucket: str, now: int, maximum: int) -> bool:
        # Only the global bucket and provisioned key IDs are used; attacker input
        # cannot allocate arbitrary rate-limit identities.
        window = now // 60
        with self.transaction() as db:
            db.execute("DELETE FROM limits WHERE window < ?", (window,))
            row = db.execute(
                "SELECT window, count FROM limits WHERE bucket=?", (bucket,)
            ).fetchone()
            count = row[1] + 1 if row and row[0] == window else 1
            db.execute(
                "INSERT OR REPLACE INTO limits VALUES (?, ?, ?)",
                (bucket, window, count),
            )
            return count <= maximum

    def consume_nonce(self, key_id: str, nonce: str, now: int, expires: int, maximum: int):
        with self.transaction() as db:
            db.execute("DELETE FROM nonces WHERE expires < ?", (now,))
            if db.execute(
                "SELECT 1 FROM nonces WHERE key_id=? AND nonce=?", (key_id, nonce)
            ).fetchone():
                raise ReplayDetected
            if db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0] >= maximum:
                raise CapacityExceeded
            db.execute("INSERT INTO nonces VALUES (?, ?, ?)", (key_id, nonce, expires))

    def _digest(self, seq: int, previous: str, event: str) -> str:
        return hmac.new(
            self.audit_key, f"{seq}\n{previous}\n{event}".encode(), hashlib.sha256
        ).hexdigest()

    def append_audit(self, event: dict) -> tuple[int, str]:
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self.transaction() as db:
            row = db.execute(
                "SELECT seq, event, previous, digest FROM audit ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if row and not hmac.compare_digest(row[3], self._digest(row[0], row[2], row[1])):
                raise StateUnavailable("Audit tail integrity failure")
            seq, previous = (row[0] + 1, row[3]) if row else (1, "0" * 64)
            if seq > self.max_audit_records:
                raise StateUnavailable(
                    "Audit capacity reached; archive and rotate under operator control"
                )
            digest = self._digest(seq, previous, encoded)
            db.execute(
                "INSERT INTO audit VALUES (?, ?, ?, ?)",
                (seq, encoded, previous, digest),
            )
            return seq, digest

    def verify_audit(self) -> tuple[int, str]:
        seq, previous = 0, "0" * 64
        with self.transaction() as db:
            for row in db.execute("SELECT seq, event, previous, digest FROM audit ORDER BY seq"):
                if (
                    row[0] != seq + 1
                    or row[2] != previous
                    or not hmac.compare_digest(row[3], self._digest(row[0], row[2], row[1]))
                ):
                    raise StateUnavailable("Audit chain integrity failure")
                seq, previous = row[0], row[3]
        return seq, previous
