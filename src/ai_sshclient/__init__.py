from .client import CommandResult, SSHConnection, SSHManager
from .config import ConfigError, Policy, ServerConfig, load_config
from .policy import PolicyError

__all__ = [
    "CommandResult",
    "ConfigError",
    "Policy",
    "PolicyError",
    "SSHConnection",
    "SSHManager",
    "ServerConfig",
    "load_config",
    "main",
]


def main() -> None:
    from .cli import main as cli_main

    raise SystemExit(cli_main())
