"""Append-only record of what was attempted, including what was refused."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional

STATE_DIR = ".kaliauto"
AUDIT_FILE = "audit.jsonl"
SECRETISH = re.compile(r"(token|secret|password|api[_-]?key)[=:]\S+", re.I)


def redact(text: str) -> str:
    return SECRETISH.sub(lambda m: m.group(0).split("=")[0].split(":")[0] + "=<redacted>", text)


class AuditLog:
    """One JSON object per line. Refusals are logged too: a refused action is evidence."""

    def __init__(self, state_dir: str = STATE_DIR, path: Optional[str] = None):
        self.path = Path(path) if path else Path(state_dir) / AUDIT_FILE

    def record(self, event: str, **fields: Any) -> Dict[str, Any]:
        entry = {"ts": round(time.time(), 3), "event": event,
                 "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        for key, value in fields.items():
            entry[key] = redact(value) if isinstance(value, str) else value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def entries(self):
        if not self.path.exists():
            return []
        out = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out
