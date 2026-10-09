//! Tests that need no network: config loading, policy, output capture, redaction.
//! Port of `tests/test_offline.py`. Tests that touch process-wide env vars hold
//! `env_lock()` so they can run in parallel with the rest.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};

use ai_sshclient::client::{
    RunOptions, SSHConnection, SSHManager, capture::Capture, redact, script_command, sudo_command,
    wrap_command,
};
use ai_sshclient::config::load_config;
use ai_sshclient::policy::{check_command, check_upload};

const BASE_YAML: &str = r#"
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
      deny: ['\bdrop\s+table\b']
      allow: ['^(ls|cat|grep)\b']
  inner:
    host: 10.0.0.4
    proxy_jump: web
"#;

/// Like `Result::unwrap_err`, but without requiring the `Ok` type to implement `Debug`
/// (several `Ok` types here deliberately don't, to keep secrets out of debug output).
fn expect_err<T, E>(result: Result<T, E>) -> E {
    match result {
        Err(e) => e,
        Ok(_) => panic!("expected Err"),
    }
}

fn unique_dir() -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ai-sshclient-test-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

/// Serializes tests that set or read process-wide env vars.
fn env_lock() -> MutexGuard<'static, ()> {
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Writes `yaml` as `servers.yaml` in a fresh temp dir and points `AI_SSHCLIENT_AUDIT` at a
/// fresh `audit.log` next to it. Returns (config_path, audit_path, env guard); keep the guard
/// alive while the test depends on that env.
fn setup(yaml: &str) -> (PathBuf, PathBuf, MutexGuard<'static, ()>) {
    let env = env_lock();
    let dir = unique_dir();
    let config_path = dir.join("servers.yaml");
    std::fs::write(&config_path, yaml).unwrap();
    let audit_path = dir.join("audit.log");
    unsafe {
        std::env::set_var("AI_SSHCLIENT_AUDIT", &audit_path);
    }
    (config_path, audit_path, env)
}

#[test]
fn missing_env_var_only_fails_the_server_that_uses_it() {
    let (config_path, _audit, _env) = setup(BASE_YAML);
    unsafe {
        std::env::remove_var("MISSING_VAR_FOR_TEST");
    }
    let servers = load_config(Some(&config_path)).unwrap();
    let mut names: Vec<&str> = servers.keys().map(|s| s.as_str()).collect();
    names.sort();
    assert_eq!(names, ["inner", "ro", "strict", "web"]);

    let err = expect_err(servers["web"].resolve_secrets());
    assert!(err.0.contains("web"), "{}", err.0);
    assert!(err.0.contains("MISSING_VAR_FOR_TEST"), "{}", err.0);
}

#[test]
fn password_command_and_repr_hides_secrets() {
    let (config_path, _audit, _env) = setup(BASE_YAML);
    let servers = load_config(Some(&config_path)).unwrap();
    let ro = &servers["ro"];

    let secrets = ro.resolve_secrets().unwrap();
    assert_eq!(secrets.password.as_deref(), Some("s3cret-pass"));

    let debug = format!("{ro:?}");
    assert!(!debug.contains("s3cret"), "{debug}");

    let info = ro.public_info();
    assert!(!info.to_string().contains("s3cret"), "{info}");

    assert_eq!(ro.auth_method(), "password");
}

#[test]
fn proxy_jump_validation_and_loop() {
    let _env = env_lock();
    let dir = unique_dir();
    unsafe {
        std::env::set_var("AI_SSHCLIENT_AUDIT", dir.join("audit.log"));
    }

    let bad = dir.join("bad.yaml");
    std::fs::write(
        &bad,
        "servers:\n  a: {host: h, user: u, proxy_jump: nope}\n",
    )
    .unwrap();
    let err = load_config(Some(&bad)).unwrap_err();
    assert!(err.0.contains("proxy_jump 'nope'"), "{}", err.0);

    let loop_yaml = dir.join("loop.yaml");
    std::fs::write(
        &loop_yaml,
        "servers:\n  a: {host: h, user: u, proxy_jump: b}\n  b: {host: h, user: u, proxy_jump: a}\n",
    )
    .unwrap();
    let manager = SSHManager::new(Some(&loop_yaml), false, "test").unwrap();
    let err = expect_err(manager.connect("a"));
    assert!(err.to_string().contains("loop"), "{err}");
}

#[tokio::test]
async fn jump_chain() {
    let (config_path, _audit, env) = setup(BASE_YAML);
    drop(env); // no env needed past setup; don't hold the guard across awaits
    let manager = SSHManager::new(Some(&config_path), false, "test").unwrap();
    let conn = manager.connect("inner").unwrap();
    let guard = conn.lock().await;
    let jump = guard.jump().expect("inner has a proxy_jump");
    assert_eq!(jump.lock().await.server.name, "web");
}

#[test]
fn read_only_blocks_writes() {
    let (config_path, _audit, _env) = setup(BASE_YAML);
    let servers = load_config(Some(&config_path)).unwrap();
    let ro = &servers["ro"];
    for command in [
        "rm -rf /tmp/x",
        "echo hi > /etc/motd",
        "systemctl restart nginx",
        "docker compose down",
        "sed -i s/a/b/ f",
    ] {
        let err = check_command(ro, command, false).unwrap_err();
        assert!(err.0.contains("read_only"), "{command:?}: {}", err.0);
    }
}

#[test]
fn read_only_allows_reads() {
    let (config_path, _audit, _env) = setup(BASE_YAML);
    let servers = load_config(Some(&config_path)).unwrap();
    let ro = &servers["ro"];
    for command in [
        "ls -la",
        "docker ps",
        "grep x f 2>&1 | tail",
        "cat /etc/os-release",
        "df -h",
    ] {
        check_command(ro, command, false).unwrap();
    }
}

#[test]
fn sudo_policy_and_upload() {
    let (config_path, _audit, _env) = setup(BASE_YAML);
    let servers = load_config(Some(&config_path)).unwrap();
    let ro = &servers["ro"];

    let err = check_command(ro, "ls", true).unwrap_err();
    assert!(err.0.contains("sudo"), "{}", err.0);

    let err = check_command(ro, "cd /x && sudo ls", false).unwrap_err();
    assert!(err.0.contains("sudo"), "{}", err.0);

    check_upload(ro).unwrap_err();
}

#[test]
fn allow_and_deny() {
    let (config_path, _audit, _env) = setup(BASE_YAML);
    let servers = load_config(Some(&config_path)).unwrap();
    let strict = &servers["strict"];

    check_command(strict, "ls /", false).unwrap();

    let err = check_command(strict, "uptime", false).unwrap_err();
    assert!(err.0.contains("no allowed"), "{}", err.0);

    let err = check_command(strict, "cat x; drop table users", false).unwrap_err();
    assert!(err.0.contains("denied"), "{}", err.0);
}

#[test]
fn blocked_command_is_audited() {
    let (config_path, audit_path, _env) = setup(BASE_YAML);
    let servers = load_config(Some(&config_path)).unwrap();
    let ro = servers["ro"].clone();

    let mut conn = SSHConnection::new(ro, None, "test".to_string());
    // Sync test driving its own runtime, so the env guard is never held across an await.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(conn.run("rm -rf /", &RunOptions::default()))
        .unwrap_err();
    assert!(err.to_string().contains("read_only"), "{err}");

    let log = std::fs::read_to_string(&audit_path).unwrap();
    let last_line = log.lines().last().unwrap();
    let entry: serde_json::Value = serde_json::from_str(last_line).unwrap();
    assert_eq!(entry["blocked"], serde_json::json!(true));
    assert_eq!(entry["server"], serde_json::json!("ro"));
    assert_eq!(entry["command"], serde_json::json!("rm -rf /"));
}

#[test]
fn audit_can_be_disabled() {
    let _env = env_lock();
    unsafe {
        std::env::set_var("AI_SSHCLIENT_AUDIT", "off");
    }
    assert!(ai_sshclient::audit::audit_path().is_none());
    unsafe {
        std::env::remove_var("AI_SSHCLIENT_AUDIT");
    }
}

#[test]
fn log_output_defaults_to_true() {
    let (config_path, _audit, _env) = setup(BASE_YAML);
    let servers = load_config(Some(&config_path)).unwrap();
    assert!(servers["web"].log_output);
}

#[test]
fn log_output_can_be_disabled_per_server() {
    let dir = unique_dir();
    let config_path = dir.join("servers.yaml");
    std::fs::write(
        &config_path,
        r#"
servers:
  quiet:
    host: 10.0.0.9
    user: x
    log_output: false
  loud:
    host: 10.0.0.9
    user: x
"#,
    )
    .unwrap();
    let servers = load_config(Some(&config_path)).unwrap();
    assert!(!servers["quiet"].log_output);
    assert!(servers["loud"].log_output);
}

#[test]
fn output_log_can_be_disabled_via_env() {
    let _env = env_lock();
    unsafe {
        std::env::set_var("AI_SSHCLIENT_OUTPUT_LOG", "off");
    }
    assert!(ai_sshclient::output_log::output_log_dir().is_none());
    unsafe {
        std::env::remove_var("AI_SSHCLIENT_OUTPUT_LOG");
    }
}

#[test]
fn capture_keeps_head_and_tail() {
    let mut cap = Capture::new(10);
    for chunk in [
        b"0123".as_slice(),
        b"456789".as_slice(),
        b"abcdefghij".as_slice(),
    ] {
        cap.add(chunk);
    }
    assert_eq!(cap.total(), 20);
    assert_eq!(cap.dropped(), 10);
    assert_eq!(cap.text(), "01234\n...[10 bytes truncated]...\nfghij");
}

#[test]
fn capture_no_truncation_under_limit_and_unlimited() {
    let mut cap = Capture::new(100);
    cap.add(b"hello ");
    cap.add(b"world");
    assert_eq!(cap.text(), "hello world");
    assert_eq!(cap.dropped(), 0);

    let mut unlimited = Capture::new(0);
    unlimited.add(&[b'x'; 1000]);
    assert_eq!(unlimited.text(), "x".repeat(1000));
}

#[test]
fn redact_and_script_command() {
    assert_eq!(
        redact(
            "pw=hunter22 ok",
            &["hunter22".to_string(), "ab".to_string()]
        ),
        "pw=*** ok"
    );
    assert_eq!(
        script_command(&["a".to_string(), "b c".to_string()]),
        "bash -s -- a 'b c'"
    );
    assert_eq!(script_command(&[]), "bash -s");
}

#[test]
fn wrap_cwd_and_env() {
    let (config_path, _audit, _env) = setup(BASE_YAML);
    let servers = load_config(Some(&config_path)).unwrap();
    let strict = &servers["strict"];
    let mut env = BTreeMap::new();
    env.insert("X".to_string(), "1 2".to_string());
    let wrapped = wrap_command(strict, "ls", Some("/opt/my dir"), &env);
    assert_eq!(wrapped, "export X='1 2'; cd '/opt/my dir' && ls");
}

#[test]
fn sudo_covers_whole_command_line() {
    assert_eq!(
        sudo_command("apt-get update && apt-get upgrade -y"),
        "sudo -S -p '' sh -c 'apt-get update && apt-get upgrade -y'"
    );
    assert_eq!(
        sudo_command("export X='1 2'; cd /tmp && ls"),
        "sudo -S -p '' sh -c 'export X='\\''1 2'\\''; cd /tmp && ls'"
    );
}

#[test]
fn compact_strips_ansi_and_redraws() {
    use ai_sshclient::client::clean::compact;
    assert_eq!(compact("\x1b[1;31merror\x1b[0m ok\n"), "error ok\n");
    assert_eq!(compact("\x1b]0;title\x07done"), "done");
    assert_eq!(compact("10%\r50%\r100%\nnext\n"), "100%\nnext\n");
    assert_eq!(compact("dos\r\nline\r\n"), "dos\nline\n");
}

#[test]
fn compact_folds_repeated_lines() {
    use ai_sshclient::client::clean::compact;
    assert_eq!(compact("a\na\nb\n"), "a\na\nb\n");
    assert_eq!(
        compact("x\nx\nx\nx\ny"),
        "x\n[previous line repeated 3 more times]\ny"
    );
    assert_eq!(compact(""), "");
    assert_eq!(compact("\n\n"), "\n\n");
}
