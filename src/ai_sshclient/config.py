"""Load server definitions from a YAML file."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ENV_CONFIG_VAR = "AI_SSHCLIENT_CONFIG"
DEFAULT_CONFIG_PATHS = (
    Path("servers.yaml"),
    Path("~/.config/ai-sshclient/servers.yaml").expanduser(),
)
HOST_KEY_POLICIES = ("tofu", "strict", "warn")

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Policy:
    """Guard rails for commands sent to a server. A safety net against mistakes, not a sandbox."""

    read_only: bool = False
    allow_sudo: bool = True
    deny: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict | None, server: str) -> Policy:
        data = dict(data or {})
        for key in ("deny", "allow"):
            patterns = tuple(data.get(key) or ())
            for pattern in patterns:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ConfigError(f"server '{server}': invalid policy.{key} regex {pattern!r}: {exc}") from None
            data[key] = patterns
        try:
            return cls(**data)
        except TypeError as exc:
            raise ConfigError(f"server '{server}': policy: {exc}") from None


@dataclass(frozen=True)
class Secrets:
    password: str | None = field(default=None, repr=False)
    key_passphrase: str | None = field(default=None, repr=False)

    def values(self) -> list[str]:
        return [v for v in (self.password, self.key_passphrase) if v]


@dataclass(frozen=True)
class ServerConfig:
    name: str
    host: str
    user: str
    port: int = 22
    # Secrets are kept unresolved (may contain ${VAR}) until a connection needs them.
    password: str | None = field(default=None, repr=False)
    password_command: str | None = field(default=None, repr=False)
    key_path: str | None = None
    key_passphrase: str | None = field(default=None, repr=False)
    passphrase_command: str | None = field(default=None, repr=False)
    proxy_jump: str | None = None
    host_key_policy: str = "tofu"
    timeout: float = 10.0
    max_output: int = 64000
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    policy: Policy = field(default_factory=Policy)
    description: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def auth_method(self) -> str:
        if self.key_path:
            return "key"
        if self.password or self.password_command:
            return "password"
        return "agent"

    def resolve_secrets(self) -> Secrets:
        """Expand ${VAR} and run *_command entries. Raises ConfigError naming this server."""
        try:
            password = _secret(self.password, self.password_command)
            passphrase = _secret(self.key_passphrase, self.passphrase_command)
        except ConfigError as exc:
            raise ConfigError(f"server '{self.name}': {exc}") from None
        return Secrets(password, passphrase)

    def public_info(self) -> dict:
        """Everything an agent may see: no secrets."""
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "auth": self.auth_method,
            "proxy_jump": self.proxy_jump,
            "description": self.description,
            "tags": list(self.tags),
            "cwd": self.cwd,
            "policy": {
                "read_only": self.policy.read_only,
                "allow_sudo": self.policy.allow_sudo,
                "deny": list(self.policy.deny),
                "allow": list(self.policy.allow),
            },
        }


def _expand_env(value: str) -> str:
    """Replace ${VAR} with the environment value so secrets stay out of the YAML."""

    def repl(match: re.Match[str]) -> str:
        var = match.group(1)
        if var not in os.environ:
            raise ConfigError(f"environment variable '{var}' is not set")
        return os.environ[var]

    return _ENV_PATTERN.sub(repl, value)


def _secret(value: str | None, command: str | None) -> str | None:
    if value is not None:
        return _expand_env(str(value))
    if command:
        try:
            proc = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ConfigError(f"secret command {command.split()[0]!r} failed: {exc}") from None
        if proc.returncode != 0:
            raise ConfigError(f"secret command {command.split()[0]!r} exited with {proc.returncode}")
        # Like `pass`, use only the first line.
        return proc.stdout.splitlines()[0] if proc.stdout else ""
    return None


def find_config_path(explicit: str | os.PathLike[str] | None = None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    if env := os.environ.get(ENV_CONFIG_VAR):
        return Path(env).expanduser()
    for candidate in DEFAULT_CONFIG_PATHS:
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(p) for p in DEFAULT_CONFIG_PATHS)
    raise ConfigError(f"no config file found (searched: {searched}; or set ${ENV_CONFIG_VAR})")


def load_config(path: str | os.PathLike[str] | None = None) -> dict[str, ServerConfig]:
    config_path = find_config_path(path)
    try:
        data = yaml.safe_load(config_path.read_text()) or {}
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {config_path}") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {config_path}: {exc}") from None

    defaults = data.get("defaults") or {}
    servers = data.get("servers") or {}
    if not isinstance(servers, dict):
        raise ConfigError("'servers' must be a mapping of name -> settings")

    result: dict[str, ServerConfig] = {}
    for name, settings in servers.items():
        merged = {**defaults, **(settings or {})}
        for required in ("host", "user"):
            if required not in merged:
                raise ConfigError(f"server '{name}': '{required}' is required")
        if key_path := merged.get("key_path"):
            merged["key_path"] = str(Path(_expand_env(key_path)).expanduser())
        if merged.get("host_key_policy", "tofu") not in HOST_KEY_POLICIES:
            raise ConfigError(f"server '{name}': host_key_policy must be one of {', '.join(HOST_KEY_POLICIES)}")
        merged["tags"] = tuple(merged.get("tags") or ())
        merged["env"] = {str(k): str(v) for k, v in (merged.get("env") or {}).items()}
        merged["policy"] = Policy.from_dict(merged.get("policy"), name)
        try:
            result[name] = ServerConfig(name=name, **merged)
        except TypeError as exc:
            raise ConfigError(f"server '{name}': {exc}") from None

    for server in result.values():
        if server.proxy_jump and server.proxy_jump not in result:
            raise ConfigError(f"server '{server.name}': proxy_jump '{server.proxy_jump}' is not a configured server")
    return result
