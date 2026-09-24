"""MCP server (stdio): lets AI agents run commands on configured servers without seeing credentials."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .client import SSHManager
from .config import ConfigError

INSTRUCTIONS = """\
Run shell commands on remote servers over SSH. Credentials live in the server config and are
never exposed; just pass the server name. Call list_servers first to see names, tags and each
server's policy (read_only / allow_sudo / allow / deny). Output is capped (head + tail kept,
`truncated` tells you); narrow your command (grep, tail, head) instead of dumping large files.
Prefer run_script for multi-line scripts: it avoids quoting problems. Every call is audited.
"""

DEFAULT_TIMEOUT = 120.0


def build_server(config_path: str | os.PathLike[str] | None = None) -> MCPServer:
    # paramiko logs every connection at INFO; keep the server's stderr for real problems.
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    manager = SSHManager(config_path, keep_alive=True, source="mcp")

    @asynccontextmanager
    async def lifespan(_app: MCPServer) -> AsyncIterator[None]:
        try:
            yield
        finally:
            manager.close_all()

    mcp = MCPServer("ai-sshclient", instructions=INSTRUCTIONS, lifespan=lifespan)

    def guarded(fn, *args, **kwargs):
        # MCPServer hides the message of unexpected exceptions; agents need it to recover.
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            raise ToolError(f"{type(exc).__name__}: {exc}") from exc

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def list_servers(tag: str | None = None) -> list[dict]:
        """List configured servers (name, host, user, tags, description, policy). Never includes secrets."""
        servers = manager.by_tag(tag) if tag else manager.servers.values()
        return [s.public_info() for s in servers]

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True, openWorldHint=True))
    def run_command(
        server: str,
        command: str,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        sudo: bool = False,
        max_output: int | None = None,
    ) -> dict:
        """Run a shell command on `server` and return stdout, stderr, exit_code, duration_s and truncated.

        cwd: remote working directory. env: extra environment variables. sudo: run through sudo
        using the configured password (if the policy allows). max_output: byte cap per stream.
        """
        return guarded(
            manager.run, server, command, cwd=cwd, env=env, timeout=timeout, sudo=sudo, max_output=max_output
        ).to_dict()

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True, openWorldHint=True))
    def run_script(
        server: str,
        script: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_output: int | None = None,
    ) -> dict:
        """Run a multi-line bash script on `server` (sent over stdin, no quoting needed). `args` become $1, $2..."""
        return guarded(
            manager.run_script, server, script, args=args, cwd=cwd, timeout=timeout, max_output=max_output
        ).to_dict()

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True, openWorldHint=True))
    def run_on_tag(tag: str, command: str, timeout: float = DEFAULT_TIMEOUT, max_output: int | None = None) -> list[dict]:
        """Run the same command in parallel on every server with `tag`. Per-server failures are reported, not raised."""
        names = [s.name for s in manager.by_tag(tag)]
        if not names:
            raise ToolError(f"no servers with tag '{tag}'")
        return [r.to_dict() for r in manager.run_many(names, command, timeout=timeout, max_output=max_output)]

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
    def upload(server: str, local_path: str, remote_path: str) -> str:
        """Copy a local file to `remote_path` on `server` (SFTP)."""
        guarded(manager.upload, server, os.path.expanduser(local_path), remote_path)
        return f"uploaded {local_path} -> {server}:{remote_path}"

    @mcp.tool()
    def download(server: str, remote_path: str, local_path: str) -> str:
        """Copy `remote_path` from `server` to a local file (SFTP)."""
        guarded(manager.download, server, remote_path, os.path.expanduser(local_path))
        return f"downloaded {server}:{remote_path} -> {local_path}"

    return mcp


def serve(config_path: str | os.PathLike[str] | None = None) -> int:
    try:
        server = build_server(config_path)
    except ConfigError as exc:
        print(f"error: {exc}", file=__import__("sys").stderr)
        return 2
    server.run("stdio")
    return 0
