# ai-sshclient

SSH wrapper for AI agents (and humans): run commands on remote servers and read their
output without typing passwords or key paths. Servers live in a YAML file; the agent only
ever sees server names. Available as an MCP server, a CLI and a Python API.

## Config

Copy `servers.example.yaml` to one of these (first match wins) and `chmod 600` it:

1. `--config PATH`
2. `$AI_SSHCLIENT_CONFIG`
3. `./servers.yaml`
4. `~/.config/ai-sshclient/servers.yaml`

| Field | Meaning |
|---|---|
| `host`, `user` | required |
| `port` | default 22 |
| `password` / `password_command` | literal/`${VAR}`, or a command whose first output line is the password (`pass show x`) |
| `key_path`, `key_passphrase` / `passphrase_command` | private key and its passphrase |
| `proxy_jump` | name of another server used as bastion |
| `host_key_policy` | `tofu` (default): accept unknown keys once and remember them in `~/.config/ai-sshclient/known_hosts`; `strict`: only known keys; `warn` |
| `timeout` | connect timeout in seconds |
| `max_output` | bytes kept per stream (head + tail), default 64000, `0` = unlimited |
| `cwd`, `env` | default remote directory and environment variables |
| `policy` | `read_only`, `allow_sudo`, `deny: [regex]`, `allow: [regex]` |
| `description`, `tags` | shown to agents; tags select groups |

The `defaults` block applies to every server. Secrets are resolved only when a server is
used, so a missing `${VAR}` breaks only that server. With no `password`/`key_path`,
ssh-agent and `~/.ssh` keys are used. A changed host key is always rejected.

### Policy

`policy` is a guard rail against agent mistakes, **not a sandbox**: anyone who can run
arbitrary shell can find a way around regexes. For real isolation use a restricted remote
user.

- `read_only: true` blocks common write commands (`rm`, `mv`, `>`, `sed -i`,
  `systemctl restart`, `docker rm/compose down`, package installs...) and uploads.
- `allow_sudo: false` blocks `--sudo` and `sudo` in the command.
- `deny` blocks commands matching any regex; `allow`, when set, requires a match.

### Audit log

Every command, script, upload and download (including blocked ones) is appended as JSON
to `~/.local/state/ai-sshclient/audit.log`: time, server, source (`cli`/`mcp`/`api`),
command, exit code, duration. Output is never logged and secrets are redacted.
Change the path with `AI_SSHCLIENT_AUDIT=/path`, disable with `AI_SSHCLIENT_AUDIT=off`.

Secrets that appear in command output are also replaced by `***`.

## MCP server (for AI agents)

```sh
claude mcp add ssh -e CHAVE_SENHA="$CHAVE_SENHA" -- \
  uv --directory /dados/projetos/ai-sshclient run ai-sshclient mcp
```

MCP clients start the server with a minimal environment: pass every variable used by
`${VAR}` with `-e` (or use `password_command`), otherwise the tool call fails with
`environment variable 'X' is not set`.

Tools: `list_servers`, `run_command` (cwd, env, timeout, sudo, max_output), `run_script`
(multi-line bash over stdin, with args), `run_on_tag` (parallel), `upload`, `download`.
Connections are kept open between calls. Results are structured: `stdout`, `stderr`,
`exit_code`, `duration_s`, `truncated`, `stdout_bytes`, `stderr_bytes`.

## CLI

```sh
ai-sshclient list [--json]
ai-sshclient run web1 df -h
ai-sshclient run --cwd /var/log -e LANG=C web1 'ls -t | head'
ai-sshclient run --sudo db systemctl restart postgresql
ai-sshclient run --tag prod uptime          # runs in parallel on every server tagged "prod"
ai-sshclient run --json web1 cat /etc/os-release
ai-sshclient run -s check.sh web1 arg1 arg2   # runs a local script remotely (no quoting headaches)
ai-sshclient run -s - web1 <<'EOF'            # or read the script from stdin
docker ps --format '{{.Names}}'
EOF
ai-sshclient run --timeout 30 web1 long-task  # aborts if the command takes longer
ai-sshclient run --max-output 0 web1 cat big.log   # disable the output cap
ai-sshclient upload web1 ./app.tar.gz /tmp/app.tar.gz
ai-sshclient download web1 /var/log/syslog ./syslog
ai-sshclient mcp                              # MCP server over stdio
```

The exit code is the remote command's exit code (highest one when using `--tag`); 255
for connection/policy errors.

## Python

```python
from ai_sshclient import SSHManager

ssh = SSHManager()                      # or SSHManager("path/to/servers.yaml")
result = ssh.run("web1", "uptime", timeout=30)
print(result.stdout, result.exit_code, result.ok, result.truncated)

ssh.run_script("web1", "cd /srv\ngit log -1", cwd="/srv")
ssh.run_many(["web1", "web2"], "uptime")

pooled = SSHManager(keep_alive=True)    # reuse connections across calls
pooled.run("web1", "whoami"); pooled.run("web1", "ls")
pooled.close_all()
```

## Tests

```sh
uv run pytest
```
