from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

AUDIT_PATH = Path("audit_events.jsonl")


def append_audit(event: dict) -> None:
    payload = {
        "logged_at": datetime.now(timezone.utc).isoformat(),
        **event,
    }
    with AUDIT_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
