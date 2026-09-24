"""Command line interface: ai-sshclient {list,run,upload,download,mcp}."""

from __future__ import annotations

import argparse
import json
import sys

from .client import CommandResult, SSHManager, script_command
from .config import ConfigError
from .policy import PolicyError


def _targets(manager: SSHManager, server: str | None, tag: str | None) -> list[str]:
    if tag:
        names = [s.name for s in manager.by_tag(tag)]
        if not names:
            raise KeyError(f"no servers with tag '{tag}'")
        return names
    if not server:
        raise KeyError("provide a server name or --tag")
    manager.get(server)
    return [server]


def _print_result(result: CommandResult, as_json: bool, prefix: bool) -> None:
    if as_json:
        print(json.dumps(result.to_dict(), ensure_ascii=False))
        return
    if prefix:
        print(f"=== {result.server} (exit {result.exit_code}) ===")
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.truncated:
        print(
            f"[ai-sshclient: output truncated; stdout {result.stdout_bytes} bytes, stderr {result.stderr_bytes} bytes]",
            file=sys.stderr,
        )


def _parse_env(pairs: list[str]) -> dict[str, str]:
    env = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise KeyError(f"--env expects KEY=VALUE, got {pair!r}")
        env[key] = value
    return env


def cmd_list(manager: SSHManager, args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps([s.public_info() for s in manager.servers.values()], ensure_ascii=False, indent=2))
        return 0
    for s in manager.servers.values():
        tags = f" [{', '.join(s.tags)}]" if s.tags else ""
        desc = f" - {s.description}" if s.description else ""
        via = f" via {s.proxy_jump}" if s.proxy_jump else ""
        ro = " read-only" if s.policy.read_only else ""
        print(f"{s.name:20} {s.user}@{s.host}:{s.port} ({s.auth_method}{via}{ro}){tags}{desc}")
    return 0


def cmd_run(manager: SSHManager, args: argparse.Namespace) -> int:
    names = _targets(manager, args.server, args.tag)
    script = None
    if args.script:
        # Send the script over stdin to a remote shell: no quoting/escaping needed.
        script = sys.stdin.read() if args.script == "-" else open(args.script).read()
        command = script_command(args.command)
    else:
        command = " ".join(args.command)

    results = manager.run_many(
        names,
        command,
        timeout=args.timeout,
        sudo=args.sudo,
        input=script,
        cwd=args.cwd,
        env=_parse_env(args.env),
        max_output=args.max_output,
    )
    for result in results:
        _print_result(result, args.json, prefix=len(names) > 1)
    return max(r.exit_code for r in results)


def cmd_upload(manager: SSHManager, args: argparse.Namespace) -> int:
    manager.upload(args.server, args.local, args.remote)
    return 0


def cmd_download(manager: SSHManager, args: argparse.Namespace) -> int:
    manager.download(args.server, args.remote, args.local)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ai-sshclient", description="Run commands on servers defined in a YAML file.")
    parser.add_argument("-c", "--config", help="path to servers YAML (default: $AI_SSHCLIENT_CONFIG, ./servers.yaml, ~/.config/ai-sshclient/servers.yaml)")
    sub = parser.add_subparsers(dest="action", required=True)

    ls = sub.add_parser("list", help="list configured servers")
    ls.add_argument("--json", action="store_true", help="print as JSON (no secrets)")
    ls.set_defaults(func=cmd_list)

    run = sub.add_parser("run", help="run a command and print its output")
    run.add_argument("server", nargs="?", help="server name from the YAML")
    run.add_argument("command", nargs=argparse.REMAINDER, help="command to run")
    run.add_argument("-t", "--tag", help="run on every server with this tag (server positional becomes part of the command)")
    run.add_argument("-s", "--script", metavar="FILE", help="run a local shell script remotely ('-' reads it from stdin); extra args become $1, $2...")
    run.add_argument("--cwd", help="remote working directory")
    run.add_argument("-e", "--env", action="append", default=[], metavar="KEY=VALUE", help="environment variable for the command (repeatable)")
    run.add_argument("--timeout", type=float, help="command timeout in seconds")
    run.add_argument("--max-output", type=int, help="byte cap per stream, keeping head and tail (0 = unlimited; default from config, 64000)")
    run.add_argument("--sudo", action="store_true", help="run with sudo, feeding the configured password")
    run.add_argument("--json", action="store_true", help="print one JSON object per server")
    run.set_defaults(func=cmd_run)

    up = sub.add_parser("upload", help="copy a local file to the server")
    up.add_argument("server")
    up.add_argument("local")
    up.add_argument("remote")
    up.set_defaults(func=cmd_upload)

    down = sub.add_parser("download", help="copy a remote file to the local machine")
    down.add_argument("server")
    down.add_argument("remote")
    down.add_argument("local")
    down.set_defaults(func=cmd_download)

    sub.add_parser("mcp", help="run as an MCP server over stdio (for AI agents)")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.action == "mcp":
        from .mcp_server import serve

        return serve(args.config)
    if args.action == "run":
        if args.tag and args.server:
            args.command = [args.server, *args.command]
            args.server = None
        if not args.command and not args.script:
            print("error: no command given", file=sys.stderr)
            return 2
    try:
        manager = SSHManager(args.config, source="cli")
        return args.func(manager, args)
    except (ConfigError, KeyError, PolicyError) as exc:
        print(f"error: {exc.args[0] if exc.args else exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # connection/SFTP failures: one line, no traceback
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 255
