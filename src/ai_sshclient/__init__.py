from .client import CommandResult, SSHConnection, SSHManager
from .config import ConfigError, ServerConfig, load_config

__all__ = ["CommandResult", "ConfigError", "SSHConnection", "SSHManager", "ServerConfig", "load_config", "main"]


def main() -> None:
    from .cli import main as cli_main

    raise SystemExit(cli_main())
