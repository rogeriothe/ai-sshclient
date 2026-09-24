"""Load server definitions from a YAML file."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ENV_CONFIG_VAR = "AI_SSHCLIENT_CONFIG"
DEFAULT_CONFIG_PATHS = (
    Path("servers.yaml"),
    Path("~/.config/ai-sshclient/servers.yaml").expanduser(),
)

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class ServerConfig:
    name: str
    host: str
    user: str
    port: int = 22
    password: str | None = None
    key_path: str | None = None
    key_passphrase: str | None = None
    timeout: float = 10.0
    description: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


def _expand_env(value: object) -> object:
    """Replace ${VAR} with the environment value so secrets stay out of the YAML."""
    if not isinstance(value, str):
        return value

    def repl(match: re.Match[str]) -> str:
        var = match.group(1)
        if var not in os.environ:
            raise ConfigError(f"environment variable '{var}' is not set")
        return os.environ[var]

    return _ENV_PATTERN.sub(repl, value)


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
        merged = {k: _expand_env(v) for k, v in merged.items()}
        if "host" not in merged:
            raise ConfigError(f"server '{name}': 'host' is required")
        if "user" not in merged:
            raise ConfigError(f"server '{name}': 'user' is required")
        if key_path := merged.get("key_path"):
            merged["key_path"] = str(Path(key_path).expanduser())
        merged["tags"] = tuple(merged.get("tags") or ())
        try:
            result[name] = ServerConfig(name=name, **merged)
        except TypeError as exc:
            raise ConfigError(f"server '{name}': {exc}") from None
    return result
