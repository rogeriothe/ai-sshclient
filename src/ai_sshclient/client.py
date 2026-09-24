"""Thin wrapper over paramiko that runs commands on configured servers."""

from __future__ import annotations

import os
from dataclasses import dataclass

import paramiko

from .config import ServerConfig, load_config


@dataclass(frozen=True)
class CommandResult:
    server: str
    command: str
    stdout: str
    stderr: str
    exit_code: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class SSHConnection:
    """A persistent connection to one server. Use as a context manager."""

    def __init__(self, server: ServerConfig) -> None:
        self.server = server
        self._client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        if self._client is not None:
            return
        s = self.server
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        # Load the key ourselves: paramiko's key_filename path tries every key type and
        # reports the last parse error, hiding the real cause (e.g. server rejected the key).
        pkey = (
            paramiko.PKey.from_path(s.key_path, password=s.key_passphrase.encode() if s.key_passphrase else None)
            if s.key_path
            else None
        )
        client.connect(
            hostname=s.host,
            port=s.port,
            username=s.user,
            password=s.password,
            pkey=pkey,
            timeout=s.timeout,
            # Only fall back to ssh-agent / ~/.ssh keys when no explicit credential is set.
            allow_agent=not (s.password or s.key_path),
            look_for_keys=not (s.password or s.key_path),
        )
        self._client = client

    def run(self, command: str, timeout: float | None = None, sudo: bool = False) -> CommandResult:
        self.connect()
        assert self._client is not None
        if sudo:
            command = f"sudo -S -p '' {command}"
        stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        if sudo and self.server.password:
            stdin.write(self.server.password + "\n")
            stdin.flush()
        stdin.channel.shutdown_write()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        code = stdout.channel.recv_exit_status()
        return CommandResult(self.server.name, command, out, err, code)

    def upload(self, local: str | os.PathLike[str], remote: str) -> None:
        self.connect()
        assert self._client is not None
        with self._client.open_sftp() as sftp:
            sftp.put(str(local), remote)

    def download(self, remote: str, local: str | os.PathLike[str]) -> None:
        self.connect()
        assert self._client is not None
        with self._client.open_sftp() as sftp:
            sftp.get(remote, str(local))

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> SSHConnection:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class SSHManager:
    """Entry point: resolves server names from the YAML config and runs commands."""

    def __init__(self, config_path: str | os.PathLike[str] | None = None) -> None:
        self.servers = load_config(config_path)

    def get(self, name: str) -> ServerConfig:
        try:
            return self.servers[name]
        except KeyError:
            available = ", ".join(sorted(self.servers)) or "(none)"
            raise KeyError(f"unknown server '{name}'. Available: {available}") from None

    def connect(self, name: str) -> SSHConnection:
        return SSHConnection(self.get(name))

    def run(self, name: str, command: str, timeout: float | None = None, sudo: bool = False) -> CommandResult:
        with self.connect(name) as conn:
            return conn.run(command, timeout=timeout, sudo=sudo)

    def by_tag(self, tag: str) -> list[ServerConfig]:
        return [s for s in self.servers.values() if tag in s.tags]
