# ai-sshclient

**Idioma / Language:** English | [Português](#ai-sshclient-português)

SSH wrapper for AI agents (and humans): run commands on remote servers and read their
output without typing passwords or key paths. Servers live in a YAML file; the agent only
ever sees server names. Available as an MCP server and a CLI. Single static binary, no
runtime dependencies (Rust + russh, no OpenSSL/libssh2).

## Build

```sh
make build          # cargo build --release (this machine's glibc)
make dist            # static x86_64-unknown-linux-musl binary in dist/, runs on any x86_64 Linux
make install          # builds and installs to ~/.local/bin, wires PATH into ~/.bashrc and ~/.zshrc
make test
```

`make dist` needs `rustup target add x86_64-unknown-linux-musl` and `musl-tools`
(`sudo apt install musl-tools`); the target prints these if either is missing.

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
| `log_output` | log this server's full command output (see [Output log](#output-log)), default `true` |

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

### Output log

By default every command (and script) run over SSH also has its full `stdout`/`stderr`
appended as JSON Lines to `~/.local/state/ai-sshclient/commands/<server>.log` — one file per
server: time, server, source, command, sudo, exit code, duration, stdout, stderr, truncated.
One JSON object per line, same format as the audit log, secrets redacted the same way. Change
the directory with `AI_SSHCLIENT_OUTPUT_LOG=/path`, disable it process-wide with
`AI_SSHCLIENT_OUTPUT_LOG=off`, or disable it for one server (or every server, in `defaults`)
with `log_output: false` in servers.yaml.

## MCP server (for AI agents)

```sh
claude mcp add ssh -e CHAVE_SENHA="$CHAVE_SENHA" -- \
  /home/you/.local/bin/ai-sshclient mcp
```

MCP clients start the server with a minimal environment: pass every variable used by
`${VAR}` with `-e` (or use `password_command`), otherwise the tool call fails with
`environment variable 'X' is not set`.

Tools: `list_servers`, `run_command` (cwd, env, timeout, sudo, max_output), `run_script`
(multi-line bash over stdin, with args), `run_on_tag` (parallel), `upload`, `download`.
Connections are kept open between calls.

Results are plain text by default, to save agent tokens (no JSON escaping):

```
exit=0 0.42s truncated (stdout 120000 B, stderr 0 B)
<stdout>
--- stderr ---
<stderr, only when non-empty>
```

`truncated (...)` appears only when the cap kicked in; `run_on_tag` prefixes each server with
`=== name exit=N 0.4s ===`. Pass `format: "json"` for a JSON object (`exit_code`,
`duration_s`, plus `stdout`/`stderr`/`error`/`truncated`/`*_bytes` only when non-empty).

MCP output is also compacted: remote commands get `NO_COLOR=1 TERM=dumb PAGER=cat
GIT_PAGER=cat SYSTEMD_PAGER=cat SYSTEMD_COLORS=0` (server/call `env` wins), ANSI escapes are
stripped, `\r`-redrawn lines (progress bars) keep only their final state and 3+ identical
consecutive lines are folded into one plus `[previous line repeated N more times]`. The CLI
never does this, so its output stays byte-exact.

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
ai-sshclient update --check                   # is there a newer GitHub release?
ai-sshclient update                           # download it, verify SHA256, replace this executable
```

The exit code is the remote command's exit code (highest one when using `--tag`); 255
for connection/policy errors.

## Tests

```sh
make test            # cargo test -- --test-threads=1 (offline: config, policy, capture, redaction)
```

---

# ai-sshclient (Português)

**Idioma / Language:** [English](#ai-sshclient) | Português

Wrapper de SSH para agentes de IA (e humanos): executa comandos em servidores remotos e lê
a saída sem digitar senhas nem caminhos de chave. Os servidores ficam em um arquivo YAML; o
agente só enxerga os nomes dos servidores. Disponível como servidor MCP e CLI. Um único
binário estático, sem dependências em tempo de execução (Rust + russh, sem
OpenSSL/libssh2).

## Compilação

```sh
make build          # cargo build --release (glibc desta máquina)
make dist            # binário estático x86_64-unknown-linux-musl em dist/, roda em qualquer Linux x86_64
make install          # compila e instala em ~/.local/bin, configura o PATH em ~/.bashrc e ~/.zshrc
make test
```

`make dist` precisa de `rustup target add x86_64-unknown-linux-musl` e `musl-tools`
(`sudo apt install musl-tools`); o target mostra esses comandos se algum deles estiver
faltando.

## Configuração

Copie `servers.example.yaml` para um destes locais (vale o primeiro encontrado) e aplique
`chmod 600`:

1. `--config CAMINHO`
2. `$AI_SSHCLIENT_CONFIG`
3. `./servers.yaml`
4. `~/.config/ai-sshclient/servers.yaml`

| Campo | Significado |
|---|---|
| `host`, `user` | obrigatórios |
| `port` | padrão 22 |
| `password` / `password_command` | literal/`${VAR}`, ou comando cuja primeira linha de saída é a senha (`pass show x`) |
| `key_path`, `key_passphrase` / `passphrase_command` | chave privada e sua senha |
| `proxy_jump` | nome de outro servidor usado como bastion |
| `host_key_policy` | `tofu` (padrão): aceita chaves desconhecidas uma vez e as guarda em `~/.config/ai-sshclient/known_hosts`; `strict`: só chaves conhecidas; `warn` |
| `timeout` | tempo limite de conexão em segundos |
| `max_output` | bytes mantidos por stream (início + fim), padrão 64000, `0` = ilimitado |
| `cwd`, `env` | diretório remoto padrão e variáveis de ambiente |
| `policy` | `read_only`, `allow_sudo`, `deny: [regex]`, `allow: [regex]` |
| `description`, `tags` | exibidos aos agentes; tags selecionam grupos |
| `log_output` | registra a saída completa dos comandos deste servidor (veja [Log de saída](#log-de-saída)), padrão `true` |

O bloco `defaults` se aplica a todos os servidores. Os segredos só são resolvidos quando um
servidor é usado, então um `${VAR}` ausente afeta apenas aquele servidor. Sem
`password`/`key_path`, são usados o ssh-agent e as chaves de `~/.ssh`. Uma chave de host
alterada é sempre rejeitada.

### Política

`policy` é uma proteção contra erros de agentes, **não uma sandbox**: quem pode executar
shell arbitrário consegue contornar regex. Para isolamento real, use um usuário remoto
restrito.

- `read_only: true` bloqueia comandos comuns de escrita (`rm`, `mv`, `>`, `sed -i`,
  `systemctl restart`, `docker rm/compose down`, instalação de pacotes...) e uploads.
- `allow_sudo: false` bloqueia `--sudo` e `sudo` no comando.
- `deny` bloqueia comandos que casam com qualquer regex; `allow`, quando definido, exige
  que o comando case.

### Log de auditoria

Todo comando, script, upload e download (incluindo os bloqueados) é adicionado como JSON a
`~/.local/state/ai-sshclient/audit.log`: horário, servidor, origem (`cli`/`mcp`/`api`),
comando, código de saída, duração. A saída nunca é registrada e os segredos são ocultados.
Altere o caminho com `AI_SSHCLIENT_AUDIT=/caminho` e desative com `AI_SSHCLIENT_AUDIT=off`.

Segredos que aparecem na saída dos comandos também são substituídos por `***`.

### Log de saída

Por padrão, todo comando (e script) executado por SSH também tem seu `stdout`/`stderr`
completo adicionado em JSON Lines a `~/.local/state/ai-sshclient/commands/<servidor>.log`,
um arquivo por servidor: horário, servidor, origem, comando, sudo, código de saída, duração,
stdout, stderr, truncado. É um objeto JSON por linha, no mesmo formato do log de auditoria e
com segredos ocultados da mesma forma. Altere o diretório com
`AI_SSHCLIENT_OUTPUT_LOG=/caminho`, desative para todo o processo com
`AI_SSHCLIENT_OUTPUT_LOG=off`, ou desative para um servidor (ou para todos, em `defaults`)
com `log_output: false` no servers.yaml.

## Servidor MCP (para agentes de IA)

```sh
claude mcp add ssh -e CHAVE_SENHA="$CHAVE_SENHA" -- \
  /home/you/.local/bin/ai-sshclient mcp
```

Clientes MCP iniciam o servidor com um ambiente mínimo: passe com `-e` toda variável usada
em `${VAR}` (ou use `password_command`), senão a chamada da ferramenta falha com
`environment variable 'X' is not set`.

Ferramentas: `list_servers`, `run_command` (cwd, env, timeout, sudo, max_output),
`run_script` (bash de várias linhas via stdin, com argumentos), `run_on_tag` (em paralelo),
`upload`, `download`. As conexões ficam abertas entre as chamadas.

Por padrão, os resultados são texto puro, para economizar tokens do agente (sem escape de
JSON):

```
exit=0 0.42s truncated (stdout 120000 B, stderr 0 B)
<stdout>
--- stderr ---
<stderr, apenas quando não vazio>
```

`truncated (...)` só aparece quando o limite foi atingido; `run_on_tag` prefixa cada servidor
com `=== nome exit=N 0.4s ===`. Passe `format: "json"` para receber um objeto JSON
(`exit_code`, `duration_s`, mais `stdout`/`stderr`/`error`/`truncated`/`*_bytes` apenas
quando não vazios).

A saída do MCP também é compactada: comandos remotos recebem `NO_COLOR=1 TERM=dumb PAGER=cat
GIT_PAGER=cat SYSTEMD_PAGER=cat SYSTEMD_COLORS=0` (o `env` do servidor/chamada tem
prioridade), escapes ANSI são removidos, linhas redesenhadas com `\r` (barras de progresso)
mantêm só o estado final e 3 ou mais linhas idênticas consecutivas viram uma só, seguida de
`[previous line repeated N more times]`. A CLI nunca faz isso, então sua saída permanece
idêntica byte a byte.

## CLI

```sh
ai-sshclient list [--json]
ai-sshclient run web1 df -h
ai-sshclient run --cwd /var/log -e LANG=C web1 'ls -t | head'
ai-sshclient run --sudo db systemctl restart postgresql
ai-sshclient run --tag prod uptime          # roda em paralelo em todo servidor com a tag "prod"
ai-sshclient run --json web1 cat /etc/os-release
ai-sshclient run -s check.sh web1 arg1 arg2   # roda um script local no servidor (sem dor de cabeça com aspas)
ai-sshclient run -s - web1 <<'EOF'            # ou lê o script do stdin
docker ps --format '{{.Names}}'
EOF
ai-sshclient run --timeout 30 web1 long-task  # aborta se o comando demorar mais
ai-sshclient run --max-output 0 web1 cat big.log   # desativa o limite de saída
ai-sshclient upload web1 ./app.tar.gz /tmp/app.tar.gz
ai-sshclient download web1 /var/log/syslog ./syslog
ai-sshclient mcp                              # servidor MCP via stdio
ai-sshclient update --check                   # há uma release mais nova no GitHub?
ai-sshclient update                           # baixa, confere o SHA256 e substitui este executável
```

O código de saída é o do comando remoto (o maior deles ao usar `--tag`); 255 para erros de
conexão/política.

## Testes

```sh
make test            # cargo test -- --test-threads=1 (offline: config, policy, capture, redaction)
```
