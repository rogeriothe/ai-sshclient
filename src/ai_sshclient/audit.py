"""Append-only JSONL log of every action sent to a server (never command output)."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

ENV_AUDIT_VAR = "AI_SSHCLIENT_AUDIT"
DEFAULT_AUDIT_PATH = Path("~/.local/state/ai-sshclient/audit.log").expanduser()

_lock = threading.Lock()


def audit_path() -> Path | None:
    value = os.environ.get(ENV_AUDIT_VAR)
    if value is not None:
        # AI_SSHCLIENT_AUDIT=off (or empty) disables the log.
        return None if value.lower() in ("", "0", "off", "false", "no") else Path(value).expanduser()
    return DEFAULT_AUDIT_PATH


def record(**entry: object) -> None:
    path = audit_path()
    if path is None:
        return
    entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **entry}
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    try:
        with _lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as fh:
                fh.write(line)
    except OSError:
        # Auditing must never break the command itself.
        pass
