"""Thin wrapper over paramiko that runs commands on configured servers."""

from __future__ import annotations

import os
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path

import paramiko

from . import audit
from .config import ConfigError, Secrets, ServerConfig, load_config
from .policy import PolicyError, check_command, check_upload

KNOWN_HOSTS_PATH = Path("~/.config/ai-sshclient/known_hosts").expanduser()
REDACTED = "***"


class CommandTimeout(TimeoutError):
    """The command outlived its timeout; the connection itself is still usable."""


@dataclass(frozen=True)
class CommandResult:
    server: str
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration_s: float = 0.0
    truncated: bool = False
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def failure(cls, server: str, command: str, exc: BaseException) -> CommandResult:
        message = f"{type(exc).__name__}: {exc}"
        return cls(server, command, "", message + "\n", 255, error=message)


def script_command(args: list[str] | None = None) -> str:
    """Remote command that runs a script sent over stdin; `args` become $1, $2..."""
    return "bash -s" + (" -- " + shlex.join(args) if args else "")


class _Capture:
    """Collects a stream keeping only its head and tail once it exceeds `limit` bytes."""

    def __init__(self, limit: int) -> None:
        self.half = limit // 2 if limit > 0 else 0
        self.head = bytearray()
        self.tail = bytearray()
        self.total = 0

    def add(self, data: bytes) -> None:
        self.total += len(data)
        if not self.half:
            self.head += data
            return
        room = self.half - len(self.head)
        if room > 0:
            self.head += data[:room]
            data = data[room:]
        if data:
            self.tail += data
            if len(self.tail) > self.half:
                del self.tail[: len(self.tail) - self.half]

    @property
    def dropped(self) -> int:
        return self.total - len(self.head) - len(self.tail)

    def text(self) -> str:
        head = self.head.decode(errors="replace")
        tail = self.tail.decode(errors="replace")
        if self.dropped:
            return f"{head}\n...[{self.dropped} bytes truncated]...\n{tail}"
        return head + tail


def _redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        # Very short values would redact random output; they are too weak to matter anyway.
        if len(secret) >= 4:
            text = text.replace(secret, REDACTED)
    return text


def _prepare_host_keys(client: paramiko.SSHClient, policy: str) -> None:
    client.load_system_host_keys()
    KNOWN_HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    KNOWN_HOSTS_PATH.touch(mode=0o600, exist_ok=True)
    # Our own file: keys learned on first use are saved here, never in ~/.ssh/known_hosts.
    # A key that changes later raises BadHostKeyException in every mode.
    client.load_host_keys(str(KNOWN_HOSTS_PATH))
    if policy == "tofu":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    elif policy == "strict":
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.WarningPolicy())


class SSHConnection:
    """A persistent connection to one server. Use as a context manager."""

    def __init__(self, server: ServerConfig, jump: SSHConnection | None = None, source: str = "api") -> None:
        self.server = server
        self.jump = jump
        self.source = source
        self._client: paramiko.SSHClient | None = None
        self._secrets: Secrets | None = None
        self._connect_lock = threading.Lock()

    @property
    def is_active(self) -> bool:
        transport = self._client.get_transport() if self._client else None
        return bool(transport and transport.is_active())

    def connect(self) -> None:
        # Pooled connections are shared by MCP tool calls running in parallel threads.
        with self._connect_lock:
            if self._client is None:
                self._open()

    def _open(self) -> None:
        s = self.server
        self._secrets = secrets = s.resolve_secrets()
        client = paramiko.SSHClient()
        _prepare_host_keys(client, s.host_key_policy)
        # Load the key ourselves: paramiko's key_filename path tries every key type and
        # reports the last parse error, hiding the real cause (e.g. server rejected the key).
        pkey = None
        if s.key_path:
            passphrase = secrets.key_passphrase.encode() if secrets.key_passphrase else None
            pkey = paramiko.PKey.from_path(s.key_path, password=passphrase)
        sock = None
        if self.jump is not None:
            self.jump.connect()
            transport = self.jump._client.get_transport()  # type: ignore[union-attr]
            sock = transport.open_channel("direct-tcpip", (s.host, s.port), ("127.0.0.1", 0), timeout=s.timeout)
        explicit = bool(secrets.password or s.key_path)
        client.connect(
            hostname=s.host,
            port=s.port,
            username=s.user,
            password=secrets.password,
            pkey=pkey,
            sock=sock,
            timeout=s.timeout,
            # Only fall back to ssh-agent / ~/.ssh keys when no explicit credential is set.
            allow_agent=not explicit,
            look_for_keys=not explicit,
        )
        self._client = client

    def _wrap(self, command: str, cwd: str | None, env: dict[str, str] | None) -> str:
        # Done in the shell instead of paramiko's environment=: sshd usually rejects
        # variables that are not in AcceptEnv.
        prefix = ""
        merged_env = {**self.server.env, **(env or {})}
        if merged_env:
            prefix += "".join(f"export {k}={shlex.quote(v)}; " for k, v in merged_env.items())
        if cwd := cwd or self.server.cwd:
            prefix += f"cd {shlex.quote(cwd)} && "
        return prefix + command

    def run(
        self,
        command: str,
        timeout: float | None = None,
        sudo: bool = False,
        input: str | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        max_output: int | None = None,
    ) -> CommandResult:
        """Run a command. `input` is written to the remote stdin, e.g. a script for `bash -s`."""
        started = time.monotonic()
        log = {"server": self.server.name, "source": self.source, "command": command, "sudo": sudo}
        if input:
            log["script"] = input
        try:
            check_command(self.server, command + ("\n" + input if input else ""), sudo=sudo)
        except PolicyError as exc:
            audit.record(**self._redact_log(log), blocked=True, error=str(exc))
            raise

        try:
            result = self._execute(command, timeout, sudo, input, cwd, env, max_output, started)
        except Exception as exc:
            audit.record(
                **self._redact_log(log),
                error=f"{type(exc).__name__}: {exc}",
                duration_s=round(time.monotonic() - started, 3),
            )
            raise
        audit.record(
            **self._redact_log(log),
            exit_code=result.exit_code,
            duration_s=result.duration_s,
            truncated=result.truncated,
        )
        return result

    def _execute(self, command, timeout, sudo, input, cwd, env, max_output, started) -> CommandResult:
        self.connect()
        assert self._client is not None and self._secrets is not None
        remote = command
        if sudo:
            remote = f"sudo -S -p '' {remote}"
        remote = self._wrap(remote, cwd, env)
        stdin, stdout, _ = self._client.exec_command(remote, timeout=timeout)
        if sudo and self._secrets.password:
            stdin.write(self._secrets.password + "\n")
        if input:
            stdin.write(input)
        stdin.flush()
        stdin.channel.shutdown_write()
        limit = self.server.max_output if max_output is None else max_output
        out, err = self._drain(stdout.channel, timeout, limit)
        code = stdout.channel.recv_exit_status()
        secrets = self._secrets.values()
        return CommandResult(
            server=self.server.name,
            command=command,
            stdout=_redact(out.text(), secrets),
            stderr=_redact(err.text(), secrets),
            exit_code=code,
            duration_s=round(time.monotonic() - started, 3),
            truncated=bool(out.dropped or err.dropped),
            stdout_bytes=out.total,
            stderr_bytes=err.total,
        )

    def _redact_log(self, log: dict) -> dict:
        secrets = self._secrets.values() if self._secrets else []
        return {k: _redact(v, secrets)[:4000] if isinstance(v, str) else v for k, v in log.items()}

    @staticmethod
    def _drain(channel: paramiko.Channel, timeout: float | None, limit: int) -> tuple[_Capture, _Capture]:
        # Read both streams together: reading stdout to EOF first can deadlock when the
        # command writes enough stderr to fill the SSH window. Keep reading past the
        # output limit too, otherwise the remote command blocks on a full window.
        out, err = _Capture(limit), _Capture(limit)
        deadline = time.monotonic() + timeout if timeout else None
        while True:
            idle = True
            while channel.recv_ready():
                out.add(channel.recv(32768))
                idle = False
            while channel.recv_stderr_ready():
                err.add(channel.recv_stderr(32768))
                idle = False
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if deadline and time.monotonic() > deadline:
                channel.close()
                raise CommandTimeout(f"command did not finish within {timeout}s")
            if idle:
                time.sleep(0.02)
        return out, err

    def upload(self, local: str | os.PathLike[str], remote: str) -> None:
        log = {"server": self.server.name, "source": self.source, "action": "upload", "local": str(local), "remote": remote}
        try:
            check_upload(self.server)
        except PolicyError as exc:
            audit.record(**log, blocked=True, error=str(exc))
            raise
        self.connect()
        assert self._client is not None
        with self._client.open_sftp() as sftp:
            sftp.put(str(local), remote)
        audit.record(**log)

    def download(self, remote: str, local: str | os.PathLike[str]) -> None:
        self.connect()
        assert self._client is not None
        with self._client.open_sftp() as sftp:
            sftp.get(remote, str(local))
        audit.record(server=self.server.name, source=self.source, action="download", remote=remote, local=str(local))

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
        if self.jump is not None:
            self.jump.close()

    def __enter__(self) -> SSHConnection:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class SSHManager:
    """Entry point: resolves server names from the YAML config and runs commands.

    With keep_alive=True connections are cached and reused between calls (used by the
    MCP server); call close_all() when done.
    """

    def __init__(
        self,
        config_path: str | os.PathLike[str] | None = None,
        keep_alive: bool = False,
        source: str = "api",
    ) -> None:
        self.servers = load_config(config_path)
        self.keep_alive = keep_alive
        self.source = source
        self._pool: dict[str, SSHConnection] = {}
        self._lock = threading.Lock()

    def get(self, name: str) -> ServerConfig:
        try:
            return self.servers[name]
        except KeyError:
            available = ", ".join(sorted(self.servers)) or "(none)"
            raise KeyError(f"unknown server '{name}'. Available: {available}") from None

    def connect(self, name: str, _chain: tuple[str, ...] = ()) -> SSHConnection:
        """New (not yet opened) connection, including its proxy_jump chain."""
        if name in _chain:
            raise ConfigError(f"proxy_jump loop: {' -> '.join((*_chain, name))}")
        server = self.get(name)
        jump = self.connect(server.proxy_jump, (*_chain, name)) if server.proxy_jump else None
        return SSHConnection(server, jump=jump, source=self.source)

    def connection(self, name: str) -> SSHConnection:
        """Pooled connection when keep_alive is on, otherwise a fresh one."""
        if not self.keep_alive:
            return self.connect(name)
        with self._lock:
            conn = self._pool.get(name)
            if conn is None or (conn._client is not None and not conn.is_active):
                if conn is not None:
                    conn.close()
                conn = self._pool[name] = self.connect(name)
            return conn

    def _use(self, name: str, fn):
        conn = self.connection(name)
        try:
            return fn(conn)
        except CommandTimeout:
            raise
        except (OSError, paramiko.SSHException):
            # A pooled connection may have died; drop it so the next call reconnects.
            if self.keep_alive:
                with self._lock:
                    if self._pool.get(name) is conn:
                        del self._pool[name]
                conn.close()
            raise
        finally:
            if not self.keep_alive:
                conn.close()

    def run(self, name: str, command: str, **kwargs) -> CommandResult:
        """Run `command`; kwargs: timeout, sudo, input, cwd, env, max_output."""
        return self._use(name, lambda conn: conn.run(command, **kwargs))

    def run_script(self, name: str, script: str, args: list[str] | None = None, **kwargs) -> CommandResult:
        return self.run(name, script_command(args), input=script, **kwargs)

    def run_many(self, names: list[str], command: str, **kwargs) -> list[CommandResult]:
        """Run on several servers in parallel; failures become results with exit_code 255."""

        def job(name: str) -> CommandResult:
            try:
                return self.run(name, command, **kwargs)
            except Exception as exc:  # report per-server failures without aborting the others
                return CommandResult.failure(name, command, exc)

        with ThreadPoolExecutor(max_workers=max(1, min(len(names), 16))) as pool:
            return list(pool.map(job, names))

    def upload(self, name: str, local: str | os.PathLike[str], remote: str) -> None:
        self._use(name, lambda conn: conn.upload(local, remote))

    def download(self, name: str, remote: str, local: str | os.PathLike[str]) -> None:
        self._use(name, lambda conn: conn.download(remote, local))

    def by_tag(self, tag: str) -> list[ServerConfig]:
        return [s for s in self.servers.values() if tag in s.tags]

    def close_all(self) -> None:
        with self._lock:
            for conn in self._pool.values():
                conn.close()
            self._pool.clear()
