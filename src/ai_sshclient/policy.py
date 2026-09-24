"""Command checks applied before anything is sent to a server."""

from __future__ import annotations

import re

from .config import ServerConfig


class PolicyError(PermissionError):
    pass


# Commands that change state. Used by `read_only: true`. Deliberately broad: a false
# positive costs the agent a retry, a false negative can cost a server.
_WRITE_PATTERNS = [
    r"\b(rm|rmdir|mv|cp|dd|mkfs(\.\w+)?|shred|truncate|chmod|chown|chgrp|ln|touch|mkdir|tee|install)\b",
    r"\b(shutdown|reboot|halt|poweroff|kill|killall|pkill)\b",
    r"\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask|kill)\b",
    r"\bservice\s+\S+\s+(start|stop|restart|reload)\b",
    r"\bdocker\s+(rm|rmi|stop|kill|restart|start|run|exec|create|prune|compose\s+(down|up|rm|restart|stop))\b",
    r"\bdocker\s+\w+\s+(prune|rm)\b",
    r"\b(apt|apt-get|yum|dnf|pip|npm)\s+(install|remove|purge|upgrade|update)\b",
    r"\b(useradd|userdel|usermod|passwd|crontab\s+-[er])\b",
    r"\bsed\s+(-\w*i|--in-place)",
    r"\bgit\s+(push|reset|checkout|commit|merge|rebase|clean)\b",
    r"(^|[^<>&0-9])>>?\s*[^&\s]",  # output redirection to a file (not 2>&1)
]
_WRITE_RE = [re.compile(p) for p in _WRITE_PATTERNS]
_SUDO_RE = re.compile(r"(^|[;&|(`\s])sudo\b")


def check_command(server: ServerConfig, command: str, sudo: bool = False) -> None:
    """Raise PolicyError if `command` (or script text) is not allowed on `server`."""
    policy = server.policy
    if (sudo or _SUDO_RE.search(command)) and not policy.allow_sudo:
        raise PolicyError(f"server '{server.name}': sudo is not allowed by policy")
    for pattern in policy.deny:
        if re.search(pattern, command):
            raise PolicyError(f"server '{server.name}': command matches denied pattern {pattern!r}")
    if policy.allow and not any(re.search(p, command) for p in policy.allow):
        raise PolicyError(f"server '{server.name}': command matches no allowed pattern")
    if policy.read_only:
        for regex in _WRITE_RE:
            if match := regex.search(command):
                raise PolicyError(
                    f"server '{server.name}' is read_only: command looks like a write ({match.group(0).strip()!r})"
                )


def check_upload(server: ServerConfig) -> None:
    if server.policy.read_only:
        raise PolicyError(f"server '{server.name}' is read_only: uploads are not allowed")
