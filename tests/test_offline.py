"""Tests that need no network: config loading, policy, output capture, redaction."""

import json
import textwrap

import pytest

from ai_sshclient import audit
from ai_sshclient.client import SSHConnection, SSHManager, _Capture, _redact, script_command
from ai_sshclient.config import ConfigError, load_config
from ai_sshclient.policy import PolicyError, check_command, check_upload


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_SSHCLIENT_AUDIT", str(tmp_path / "audit.log"))
    path = tmp_path / "servers.yaml"
    path.write_text(
        textwrap.dedent(
            """
            defaults:
              user: deploy
            servers:
              web:
                host: 10.0.0.1
                password: ${MISSING_VAR_FOR_TEST}
                tags: [prod]
              ro:
                host: 10.0.0.2
                password_command: echo s3cret-pass
                policy:
                  read_only: true
                  allow_sudo: false
              strict:
                host: 10.0.0.3
                policy:
                  deny: ['\\bdrop\\s+table\\b']
                  allow: ['^(ls|cat|grep)\\b']
              inner:
                host: 10.0.0.4
                proxy_jump: web
            """
        )
    )
    return path


def test_missing_env_var_only_fails_the_server_that_uses_it(config):
    servers = load_config(config)
    assert set(servers) == {"web", "ro", "strict", "inner"}
    with pytest.raises(ConfigError, match="web.*MISSING_VAR_FOR_TEST"):
        servers["web"].resolve_secrets()


def test_password_command_and_repr_hides_secrets(config):
    ro = load_config(config)["ro"]
    assert ro.resolve_secrets().password == "s3cret-pass"
    assert "s3cret" not in repr(ro)
    assert "s3cret" not in json.dumps(ro.public_info())
    assert ro.auth_method == "password"


def test_proxy_jump_validation_and_loop(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("servers:\n  a: {host: h, user: u, proxy_jump: nope}\n")
    with pytest.raises(ConfigError, match="proxy_jump 'nope'"):
        load_config(bad)
    loop = tmp_path / "loop.yaml"
    loop.write_text("servers:\n  a: {host: h, user: u, proxy_jump: b}\n  b: {host: h, user: u, proxy_jump: a}\n")
    with pytest.raises(ConfigError, match="loop"):
        SSHManager(loop).connect("a")


def test_jump_chain(config):
    conn = SSHManager(config).connect("inner")
    assert conn.jump is not None and conn.jump.server.name == "web"


@pytest.mark.parametrize(
    "command",
    ["rm -rf /tmp/x", "echo hi > /etc/motd", "systemctl restart nginx", "docker compose down", "sed -i s/a/b/ f"],
)
def test_read_only_blocks_writes(config, command):
    with pytest.raises(PolicyError, match="read_only"):
        check_command(load_config(config)["ro"], command)


@pytest.mark.parametrize("command", ["ls -la", "docker ps", "grep x f 2>&1 | tail", "cat /etc/os-release", "df -h"])
def test_read_only_allows_reads(config, command):
    check_command(load_config(config)["ro"], command)


def test_sudo_policy_and_upload(config):
    ro = load_config(config)["ro"]
    with pytest.raises(PolicyError, match="sudo"):
        check_command(ro, "ls", sudo=True)
    with pytest.raises(PolicyError, match="sudo"):
        check_command(ro, "cd /x && sudo ls")
    with pytest.raises(PolicyError):
        check_upload(ro)


def test_allow_and_deny(config):
    s = load_config(config)["strict"]
    check_command(s, "ls /")
    with pytest.raises(PolicyError, match="no allowed"):
        check_command(s, "uptime")
    with pytest.raises(PolicyError, match="denied"):
        check_command(s, "cat x; drop table users")


def test_blocked_command_is_audited(config, tmp_path):
    conn = SSHConnection(load_config(config)["ro"], source="test")
    with pytest.raises(PolicyError):
        conn.run("rm -rf /")
    entry = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
    assert entry["blocked"] is True and entry["server"] == "ro" and entry["command"] == "rm -rf /"


def test_audit_can_be_disabled(monkeypatch):
    monkeypatch.setenv("AI_SSHCLIENT_AUDIT", "off")
    assert audit.audit_path() is None


def test_capture_keeps_head_and_tail():
    cap = _Capture(10)
    for chunk in (b"0123", b"456789", b"abcdefghij"):
        cap.add(chunk)
    assert cap.total == 20 and cap.dropped == 10
    assert cap.text() == "01234\n...[10 bytes truncated]...\nfghij"


def test_capture_no_truncation_under_limit_and_unlimited():
    cap = _Capture(100)
    cap.add(b"hello ")
    cap.add(b"world")
    assert cap.text() == "hello world" and not cap.dropped
    unlimited = _Capture(0)
    unlimited.add(b"x" * 1000)
    assert unlimited.text() == "x" * 1000


def test_redact_and_script_command():
    assert _redact("pw=hunter22 ok", ["hunter22", "ab"]) == "pw=*** ok"
    assert script_command(["a", "b c"]) == "bash -s -- a 'b c'"
    assert script_command() == "bash -s"


def test_wrap_cwd_and_env(config):
    conn = SSHConnection(load_config(config)["strict"])
    assert conn._wrap("ls", "/opt/my dir", {"X": "1 2"}) == "export X='1 2'; cd '/opt/my dir' && ls"
