# ai-sshclient

SSH wrapper: run commands on remote servers and read their output without typing
passwords or key paths every time. Servers live in a YAML file.

## Config

Copy `servers.example.yaml` to one of these (first match wins):

1. `--config PATH`
2. `$AI_SSHCLIENT_CONFIG`
3. `./servers.yaml`
4. `~/.config/ai-sshclient/servers.yaml`

Per-server fields: `host`, `user` (required), `port`, `password`, `key_path`,
`key_passphrase`, `timeout`, `description`, `tags`. The `defaults` block applies
to every server. `${VAR}` expands to an environment variable, so secrets can stay
out of the file. With no `password`/`key_path`, ssh-agent and `~/.ssh` keys are used.

Keep the file private: `chmod 600 servers.yaml`.

## CLI

```sh
ai-sshclient list
ai-sshclient run web1 df -h
ai-sshclient run --sudo db systemctl restart postgresql
ai-sshclient run --tag prod uptime          # runs in parallel on every server tagged "prod"
ai-sshclient run --json web1 cat /etc/os-release
ai-sshclient run -s check.sh web1 arg1 arg2   # runs a local script remotely (no quoting headaches)
ai-sshclient run -s - web1 <<'EOF'            # or read the script from stdin
docker ps --format '{{.Names}}'
EOF
ai-sshclient run --timeout 30 web1 long-task  # aborts if the command takes longer
ai-sshclient upload web1 ./app.tar.gz /tmp/app.tar.gz
ai-sshclient download web1 /var/log/syslog ./syslog
```

The exit code is the remote command's exit code (highest one when using `--tag`).

## Python

```python
from ai_sshclient import SSHManager

ssh = SSHManager()                      # or SSHManager("path/to/servers.yaml")
result = ssh.run("web1", "uptime")
print(result.stdout, result.exit_code, result.ok)

with ssh.connect("web1") as conn:       # reuse one connection for several commands
    print(conn.run("whoami").stdout)
    print(conn.run("ls /var/www").stdout)
```
