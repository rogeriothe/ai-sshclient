"""Command line interface: ai-sshclient {list,run,upload,download}."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from concurrent.futures import ThreadPoolExecutor

from .client import CommandResult, SSHManager
from .config import ConfigError


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
        print(json.dumps(result.__dict__, ensure_ascii=False))
        return
    if prefix:
        print(f"=== {result.server} (exit {result.exit_code}) ===")
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)


def cmd_list(manager: SSHManager, args: argparse.Namespace) -> int:
    for s in manager.servers.values():
        auth = "key" if s.key_path else "password" if s.password else "agent"
        tags = f" [{', '.join(s.tags)}]" if s.tags else ""
        desc = f" - {s.description}" if s.description else ""
        print(f"{s.name:20} {s.user}@{s.host}:{s.port} ({auth}){tags}{desc}")
    return 0


def cmd_run(manager: SSHManager, args: argparse.Namespace) -> int:
    names = _targets(manager, args.server, args.tag)
    script = None
    if args.script:
        # Send the script over stdin to a remote shell: no quoting/escaping needed.
        script = sys.stdin.read() if args.script == "-" else open(args.script).read()
        command = "bash -s" + (" -- " + shlex.join(args.command) if args.command else "")
    else:
        command = " ".join(args.command)

    def job(name: str) -> CommandResult:
        try:
            return manager.run(name, command, timeout=args.timeout, sudo=args.sudo, input=script)
        except Exception as exc:  # report per-server failures without aborting the others
            return CommandResult(name, command, "", f"{type(exc).__name__}: {exc}\n", 255)

    with ThreadPoolExecutor(max_workers=min(len(names), 16)) as pool:
        results = list(pool.map(job, names))

    for result in results:
        _print_result(result, args.json, prefix=len(names) > 1)
    return max(r.exit_code for r in results)


def cmd_upload(manager: SSHManager, args: argparse.Namespace) -> int:
    with manager.connect(args.server) as conn:
        conn.upload(args.local, args.remote)
    return 0


def cmd_download(manager: SSHManager, args: argparse.Namespace) -> int:
    with manager.connect(args.server) as conn:
        conn.download(args.remote, args.local)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ai-sshclient", description="Run commands on servers defined in a YAML file.")
    parser.add_argument("-c", "--config", help="path to servers YAML (default: $AI_SSHCLIENT_CONFIG, ./servers.yaml, ~/.config/ai-sshclient/servers.yaml)")
    sub = parser.add_subparsers(dest="action", required=True)

    sub.add_parser("list", help="list configured servers").set_defaults(func=cmd_list)

    run = sub.add_parser("run", help="run a command and print its output")
    run.add_argument("server", nargs="?", help="server name from the YAML")
    run.add_argument("command", nargs=argparse.REMAINDER, help="command to run")
    run.add_argument("-t", "--tag", help="run on every server with this tag (server positional becomes part of the command)")
    run.add_argument("-s", "--script", metavar="FILE", help="run a local shell script remotely ('-' reads it from stdin); extra args become $1, $2...")
    run.add_argument("--timeout", type=float, help="command timeout in seconds")
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

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.action == "run":
        if args.tag and args.server:
            args.command = [args.server, *args.command]
            args.server = None
        if not args.command and not args.script:
            print("error: no command given", file=sys.stderr)
            return 2
    try:
        manager = SSHManager(args.config)
        return args.func(manager, args)
    except (ConfigError, KeyError) as exc:
        print(f"error: {exc.args[0] if exc.args else exc}", file=sys.stderr)
        return 2
