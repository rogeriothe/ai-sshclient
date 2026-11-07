//! Thin wrapper over russh that runs commands on configured servers.

pub mod capture;
pub mod clean;
pub mod hostkeys;

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;

use crate::audit;
use crate::config::{ConfigError, Secrets, ServerConfig, connect_timeout};
use crate::output_log;
use crate::policy::{PolicyError, check_command, check_upload};
use capture::Capture;

const REDACTED: &str = "***";

#[derive(Debug, thiserror::Error)]
#[error("command did not finish within {0}s")]
pub struct CommandTimeout(pub f64);

/// A caller-facing usage mistake (unknown server, bad flag combination) — exit code 2,
/// same bucket as `ConfigError`/`PolicyError`, not a connection failure (exit code 255).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct UsageError(pub String);

#[derive(Debug, Clone, Serialize)]
pub struct CommandResult {
    pub server: String,
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_s: f64,
    pub truncated: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub error: Option<String>,
}

impl CommandResult {
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    pub fn failure(server: &str, command: &str, err: &str) -> Self {
        CommandResult {
            server: server.to_string(),
            command: command.to_string(),
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 255,
            duration_s: 0.0,
            truncated: false,
            stdout_bytes: 0,
            stderr_bytes: 0,
            error: Some(err.to_string()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub timeout: Option<f64>,
    pub sudo: bool,
    pub input: Option<String>,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub max_output: Option<i64>,
    /// Shrink output for AI agents (see `clean`): quiet env, no ANSI, folded repeats.
    pub compact: bool,
}

/// Remote command that runs a script sent over stdin; `args` become $1, $2...
pub fn script_command(args: &[String]) -> String {
    if args.is_empty() {
        "bash -s".to_string()
    } else {
        format!("bash -s -- {}", shell_words::join(args))
    }
}

/// Run the whole command line as root: a bare `sudo` prefix would only cover
/// its first simple command (`sudo a && b` runs `b` unprivileged).
pub fn sudo_command(command: &str) -> String {
    format!("sudo -S -p '' sh -c {}", shell_words::quote(command))
}

pub fn redact(text: &str, secrets: &[String]) -> String {
    let mut text = text.to_string();
    for secret in secrets {
        if secret.len() >= 4 {
            text = text.replace(secret.as_str(), REDACTED);
        }
    }
    text
}

fn redact_log(secrets: &[String], log: Map<String, Value>) -> Map<String, Value> {
    log.into_iter()
        .map(|(k, v)| {
            let v = match v {
                Value::String(s) => Value::String(redact(&s, secrets).chars().take(4000).collect()),
                other => other,
            };
            (k, v)
        })
        .collect()
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

pub fn wrap_command(
    server: &ServerConfig,
    command: &str,
    cwd: Option<&str>,
    env: &BTreeMap<String, String>,
) -> String {
    let mut prefix = String::new();
    let mut merged_env = server.env.clone();
    for (k, v) in env {
        merged_env.insert(k.clone(), v.clone());
    }
    for (k, v) in &merged_env {
        prefix.push_str(&format!("export {}={}; ", k, shell_words::quote(v)));
    }
    let cwd = cwd.or(server.cwd.as_deref());
    if let Some(cwd) = cwd {
        prefix.push_str(&format!("cd {} && ", shell_words::quote(cwd)));
    }
    format!("{prefix}{command}")
}

struct ClientHandler {
    host: String,
    policy: String,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(hostkeys::check(&self.host, &self.policy, server_public_key))
    }
}

/// RSA signature hash to use. Servers that do not send `server-sig-algs`
/// (RFC 8308) still accept rsa-sha2-256; legacy ssh-rsa (SHA-1) is used only
/// when the server explicitly advertises it as its sole RSA option.
async fn rsa_hash(
    handle: &russh::client::Handle<ClientHandler>,
) -> Result<Option<russh::keys::HashAlg>, russh::Error> {
    Ok(handle
        .best_supported_rsa_hash()
        .await?
        .unwrap_or(Some(russh::keys::HashAlg::Sha256)))
}

async fn authenticate(
    handle: &mut russh::client::Handle<ClientHandler>,
    server: &ServerConfig,
    secrets: &Secrets,
) -> anyhow::Result<()> {
    if let Some(key_path) = &server.key_path {
        let key = russh::keys::load_secret_key(key_path, secrets.key_passphrase.as_deref())
            .map_err(|e| anyhow!("failed to load key {key_path}: {e}"))?;
        let hash_alg = rsa_hash(handle).await?;
        let res = handle
            .authenticate_publickey(
                server.user.clone(),
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
            )
            .await?;
        if !res.success() {
            bail!("authentication (key) failed for server '{}'", server.name);
        }
        return Ok(());
    }

    if let Some(password) = &secrets.password {
        let res = handle
            .authenticate_password(server.user.clone(), password.clone())
            .await?;
        if !res.success() {
            bail!(
                "authentication (password) failed for server '{}'",
                server.name
            );
        }
        return Ok(());
    }

    // No explicit credential: fall back to ssh-agent, then default ~/.ssh keys.
    // ssh-agent via SSH_AUTH_SOCK is Unix-only (russh has no connect_env on Windows).
    #[cfg(unix)]
    {
        if let Ok(mut agent) = russh::keys::agent::client::AgentClient::connect_env().await
            && let Ok(identities) = agent.request_identities().await {
                for identity in identities {
                    if let russh::keys::agent::AgentIdentity::PublicKey { key, .. } = identity {
                        let hash_alg = rsa_hash(handle).await?;
                        if let Ok(res) = handle
                            .authenticate_publickey_with(server.user.clone(), key, hash_alg, &mut agent)
                            .await
                            && res.success() {
                                return Ok(());
                            }
                    }
                }
            }
    }

    for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
        let Some(home) = dirs::home_dir() else {
            continue;
        };
        let path = home.join(".ssh").join(name);
        if !path.exists() {
            continue;
        }
        if let Ok(key) = russh::keys::load_secret_key(&path, None) {
            let hash_alg = rsa_hash(handle).await?;
            if let Ok(res) = handle
                .authenticate_publickey(
                    server.user.clone(),
                    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
                )
                .await
                && res.success() {
                    return Ok(());
                }
        }
    }

    bail!(
        "no authentication method succeeded for server '{}' (no explicit credential; ssh-agent/~/.ssh keys failed)",
        server.name
    );
}

async fn open_sftp(
    handle: &russh::client::Handle<ClientHandler>,
) -> anyhow::Result<russh_sftp::client::SftpSession> {
    let channel = handle.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream()).await?;
    Ok(sftp)
}

/// A (lazily opened) connection to one server. Wrap in `Arc<Mutex<_>>` to share.
pub struct SSHConnection {
    pub server: ServerConfig,
    jump: Option<Arc<Mutex<SSHConnection>>>,
    source: String,
    handle: Option<Arc<russh::client::Handle<ClientHandler>>>,
    secrets: Option<Secrets>,
}

impl SSHConnection {
    pub fn new(
        server: ServerConfig,
        jump: Option<Arc<Mutex<SSHConnection>>>,
        source: String,
    ) -> Self {
        SSHConnection {
            server,
            jump,
            source,
            handle: None,
            secrets: None,
        }
    }

    pub fn jump(&self) -> Option<&Arc<Mutex<SSHConnection>>> {
        self.jump.as_ref()
    }

    pub fn is_active(&self) -> bool {
        self.handle
            .as_ref()
            .map(|h| !h.is_closed())
            .unwrap_or(false)
    }

    pub async fn connect(&mut self) -> anyhow::Result<()> {
        if self.handle.is_some() {
            return Ok(());
        }
        let secrets = self.server.resolve_secrets()?;
        let handler = ClientHandler {
            host: self.server.host.clone(),
            policy: self.server.host_key_policy.clone(),
        };
        let config = Arc::new(russh::client::Config {
            nodelay: true,
            ..Default::default()
        });
        let timeout = connect_timeout(&self.server);

        let mut handle = if let Some(jump) = &self.jump {
            let jump_handle = {
                let mut jump_conn = jump.lock().await;
                Box::pin(jump_conn.connect()).await?;
                jump_conn
                    .handle
                    .clone()
                    .ok_or_else(|| anyhow!("jump connection not established"))?
            };
            let channel = jump_handle
                .channel_open_direct_tcpip(
                    self.server.host.clone(),
                    self.server.port as u32,
                    "127.0.0.1".to_string(),
                    0,
                )
                .await?;
            tokio::time::timeout(
                timeout,
                russh::client::connect_stream(config, channel.into_stream(), handler),
            )
            .await
            .map_err(|_| anyhow!("connect timeout"))??
        } else {
            let addr = format!("{}:{}", self.server.host, self.server.port);
            tokio::time::timeout(timeout, russh::client::connect(config, addr, handler))
                .await
                .map_err(|_| anyhow!("connect timeout"))??
        };

        authenticate(&mut handle, &self.server, &secrets).await?;

        self.handle = Some(Arc::new(handle));
        self.secrets = Some(secrets);
        Ok(())
    }

    pub fn close(&mut self) {
        self.handle = None;
    }

    fn current_secret_values(&self) -> Vec<String> {
        self.secrets
            .as_ref()
            .map(|s| s.values())
            .unwrap_or_default()
    }

    pub async fn run(&mut self, command: &str, opts: &RunOptions) -> anyhow::Result<CommandResult> {
        let started = Instant::now();
        let mut log = Map::new();
        log.insert("server".into(), json!(self.server.name));
        log.insert("source".into(), json!(self.source));
        log.insert("command".into(), json!(command));
        log.insert("sudo".into(), json!(opts.sudo));
        if let Some(input) = &opts.input {
            log.insert("script".into(), json!(input));
        }

        let check_text = match &opts.input {
            Some(input) => format!("{command}\n{input}"),
            None => command.to_string(),
        };
        if let Err(e) = check_command(&self.server, &check_text, opts.sudo) {
            let mut entry = redact_log(&self.current_secret_values(), log);
            entry.insert("blocked".into(), json!(true));
            entry.insert("error".into(), json!(e.0));
            audit::record(entry);
            return Err(e.into());
        }

        match self.execute(command, opts, started).await {
            Ok(result) => {
                let mut entry = redact_log(&self.current_secret_values(), log);
                entry.insert("exit_code".into(), json!(result.exit_code));
                entry.insert("duration_s".into(), json!(result.duration_s));
                entry.insert("truncated".into(), json!(result.truncated));
                audit::record(entry);

                if self.server.log_output {
                    let mut out_entry = Map::new();
                    out_entry.insert("server".into(), json!(self.server.name));
                    out_entry.insert("source".into(), json!(self.source));
                    out_entry.insert(
                        "command".into(),
                        json!(redact(command, &self.current_secret_values())),
                    );
                    out_entry.insert("sudo".into(), json!(opts.sudo));
                    out_entry.insert("exit_code".into(), json!(result.exit_code));
                    out_entry.insert("duration_s".into(), json!(result.duration_s));
                    out_entry.insert("stdout".into(), json!(result.stdout));
                    out_entry.insert("stderr".into(), json!(result.stderr));
                    out_entry.insert("truncated".into(), json!(result.truncated));
                    output_log::record(&self.server.name, out_entry);
                }
                Ok(result)
            }
            Err(e) => {
                let mut entry = redact_log(&self.current_secret_values(), log);
                entry.insert("error".into(), json!(e.to_string()));
                entry.insert(
                    "duration_s".into(),
                    json!(round3(started.elapsed().as_secs_f64())),
                );
                audit::record(entry);
                Err(e)
            }
        }
    }

    async fn execute(
        &mut self,
        command: &str,
        opts: &RunOptions,
        started: Instant,
    ) -> anyhow::Result<CommandResult> {
        self.connect().await?;
        let handle = self
            .handle
            .clone()
            .ok_or_else(|| anyhow!("not connected"))?;
        let secrets = self
            .secrets
            .clone()
            .ok_or_else(|| anyhow!("secrets not resolved"))?;

        if opts.sudo
            && let Some(e) = &secrets.sudo_error {
                bail!("{e}");
            }
        let mut env = opts.env.clone();
        if opts.compact {
            for (k, v) in clean::QUIET_ENV {
                if !self.server.env.contains_key(*k) && !env.contains_key(*k) {
                    env.insert(k.to_string(), v.to_string());
                }
            }
        }
        let mut remote = wrap_command(&self.server, command, opts.cwd.as_deref(), &env);
        if opts.sudo {
            remote = sudo_command(&remote);
        }

        let mut channel = handle.channel_open_session().await?;
        channel.exec(true, remote).await?;

        if opts.sudo
            && let Some(pw) = &secrets.sudo_password {
                channel.data(format!("{pw}\n").as_bytes()).await?;
            }
        if let Some(input) = &opts.input {
            channel.data(input.as_bytes()).await?;
        }
        channel.eof().await?;

        let limit = opts.max_output.unwrap_or(self.server.max_output);
        let mut out = Capture::new(limit);
        let mut err = Capture::new(limit);
        let mut code: Option<u32> = None;

        let deadline = opts
            .timeout
            .map(|t| tokio::time::Instant::now() + std::time::Duration::from_secs_f64(t));

        loop {
            let msg = if let Some(deadline) = deadline {
                match tokio::time::timeout_at(deadline, channel.wait()).await {
                    Ok(Some(m)) => m,
                    Ok(None) => break,
                    Err(_) => {
                        let _ = channel.close().await;
                        return Err(CommandTimeout(opts.timeout.unwrap_or_default()).into());
                    }
                }
            } else {
                match channel.wait().await {
                    Some(m) => m,
                    None => break,
                }
            };
            match msg {
                russh::ChannelMsg::Data { data } => out.add(&data),
                russh::ChannelMsg::ExtendedData { data, ext: 1 } => err.add(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                _ => {}
            }
        }

        let secret_values = secrets.values();
        let (stdout, stderr) = if opts.compact {
            (clean::compact(&out.text()), clean::compact(&err.text()))
        } else {
            (out.text(), err.text())
        };
        Ok(CommandResult {
            server: self.server.name.clone(),
            command: command.to_string(),
            stdout: redact(&stdout, &secret_values),
            stderr: redact(&stderr, &secret_values),
            exit_code: code.unwrap_or(255) as i32,
            duration_s: round3(started.elapsed().as_secs_f64()),
            truncated: out.dropped() > 0 || err.dropped() > 0,
            stdout_bytes: out.total() as u64,
            stderr_bytes: err.total() as u64,
            error: None,
        })
    }

    pub async fn upload(&mut self, local: &Path, remote: &str) -> anyhow::Result<()> {
        let mut log = Map::new();
        log.insert("server".into(), json!(self.server.name));
        log.insert("source".into(), json!(self.source));
        log.insert("action".into(), json!("upload"));
        log.insert("local".into(), json!(local.display().to_string()));
        log.insert("remote".into(), json!(remote));

        if let Err(e) = check_upload(&self.server) {
            let mut entry = log.clone();
            entry.insert("blocked".into(), json!(true));
            entry.insert("error".into(), json!(e.0));
            audit::record(entry);
            return Err(e.into());
        }

        self.connect().await?;
        let handle = self
            .handle
            .clone()
            .ok_or_else(|| anyhow!("not connected"))?;
        let sftp = open_sftp(&handle).await?;
        let data = tokio::fs::read(local)
            .await
            .map_err(|e| anyhow!("read {}: {e}", local.display()))?;
        // `sftp.write()` opens with `WRITE` only and fails on a missing remote file;
        // `create()` adds `CREATE | TRUNCATE`, matching "upload" semantics.
        use tokio::io::AsyncWriteExt as _;
        let mut file = sftp
            .create(remote.to_string())
            .await
            .map_err(|e| anyhow!("sftp create {remote}: {e}"))?;
        file.write_all(&data)
            .await
            .map_err(|e| anyhow!("sftp write {remote}: {e}"))?;
        file.close().await.map_err(|e| anyhow!("sftp close {remote}: {e}"))?;
        audit::record(log);
        Ok(())
    }

    pub async fn download(&mut self, remote: &str, local: &Path) -> anyhow::Result<()> {
        self.connect().await?;
        let handle = self
            .handle
            .clone()
            .ok_or_else(|| anyhow!("not connected"))?;
        let sftp = open_sftp(&handle).await?;
        let data = sftp
            .read(remote.to_string())
            .await
            .map_err(|e| anyhow!("sftp read {remote}: {e}"))?;
        tokio::fs::write(local, &data)
            .await
            .map_err(|e| anyhow!("write {}: {e}", local.display()))?;

        let mut log = Map::new();
        log.insert("server".into(), json!(self.server.name));
        log.insert("source".into(), json!(self.source));
        log.insert("action".into(), json!("download"));
        log.insert("remote".into(), json!(remote));
        log.insert("local".into(), json!(local.display().to_string()));
        audit::record(log);
        Ok(())
    }
}

/// Entry point: resolves server names from the YAML config and runs commands.
///
/// With `keep_alive: true` connections are cached and reused between calls (used by the
/// MCP server); call `close_all()` when done.
pub struct SSHManager {
    pub servers: BTreeMap<String, ServerConfig>,
    keep_alive: bool,
    source: String,
    pool: Mutex<HashMap<String, Arc<Mutex<SSHConnection>>>>,
}

impl SSHManager {
    pub fn new(
        config_path: Option<&Path>,
        keep_alive: bool,
        source: &str,
    ) -> Result<Self, ConfigError> {
        let servers = crate::config::load_config(config_path)?;
        Ok(SSHManager {
            servers,
            keep_alive,
            source: source.to_string(),
            pool: Mutex::new(HashMap::new()),
        })
    }

    pub fn get(&self, name: &str) -> anyhow::Result<&ServerConfig> {
        self.servers.get(name).ok_or_else(|| {
            let available = if self.servers.is_empty() {
                "(none)".to_string()
            } else {
                self.servers.keys().cloned().collect::<Vec<_>>().join(", ")
            };
            UsageError(format!("unknown server '{name}'. Available: {available}")).into()
        })
    }

    fn build_chain(
        &self,
        name: &str,
        chain: Vec<String>,
    ) -> anyhow::Result<Arc<Mutex<SSHConnection>>> {
        if chain.iter().any(|c| c == name) {
            let mut path = chain;
            path.push(name.to_string());
            bail!("proxy_jump loop: {}", path.join(" -> "));
        }
        let server = self.get(name)?.clone();
        let mut next_chain = chain;
        next_chain.push(name.to_string());
        let jump = match &server.proxy_jump {
            Some(jn) => Some(self.build_chain(jn, next_chain)?),
            None => None,
        };
        Ok(Arc::new(Mutex::new(SSHConnection::new(
            server,
            jump,
            self.source.clone(),
        ))))
    }

    /// New (not yet opened) connection, including its proxy_jump chain.
    pub fn connect(&self, name: &str) -> anyhow::Result<Arc<Mutex<SSHConnection>>> {
        self.build_chain(name, Vec::new())
    }

    /// Pooled connection when keep_alive is on, otherwise a fresh one.
    async fn connection(&self, name: &str) -> anyhow::Result<Arc<Mutex<SSHConnection>>> {
        if !self.keep_alive {
            return self.connect(name);
        }
        let mut pool = self.pool.lock().await;
        if let Some(conn) = pool.get(name) {
            let dead = {
                let guard = conn.lock().await;
                guard.handle.is_some() && !guard.is_active()
            };
            if dead {
                pool.remove(name);
            }
        }
        if !pool.contains_key(name) {
            let conn = self.connect(name)?;
            pool.insert(name.to_string(), conn);
        }
        Ok(pool.get(name).expect("just inserted").clone())
    }

    fn is_evictable(err: &anyhow::Error) -> bool {
        err.downcast_ref::<PolicyError>().is_none()
            && err.downcast_ref::<CommandTimeout>().is_none()
    }

    async fn finish_use(&self, name: &str, conn: &Arc<Mutex<SSHConnection>>, evict: bool) {
        if self.keep_alive {
            if evict {
                let mut pool = self.pool.lock().await;
                if let Some(pooled) = pool.get(name)
                    && Arc::ptr_eq(pooled, conn) {
                        pool.remove(name);
                    }
                conn.lock().await.close();
            }
        } else {
            conn.lock().await.close();
        }
    }

    pub async fn run(
        &self,
        name: &str,
        command: &str,
        opts: RunOptions,
    ) -> anyhow::Result<CommandResult> {
        let conn = self.connection(name).await?;
        let result = {
            let mut guard = conn.lock().await;
            guard.run(command, &opts).await
        };
        let evict = matches!(&result, Err(e) if Self::is_evictable(e));
        self.finish_use(name, &conn, evict).await;
        result
    }

    pub async fn run_script(
        &self,
        name: &str,
        script: &str,
        args: &[String],
        mut opts: RunOptions,
    ) -> anyhow::Result<CommandResult> {
        opts.input = Some(script.to_string());
        self.run(name, &script_command(args), opts).await
    }

    /// Run on several servers in parallel; failures become results with exit_code 255.
    /// Result order matches `names`.
    pub async fn run_many(
        self: &Arc<Self>,
        names: &[String],
        command: &str,
        opts: RunOptions,
    ) -> Vec<CommandResult> {
        let permits = 16.min(names.len().max(1));
        let sem = Arc::new(tokio::sync::Semaphore::new(permits));
        let mut set = tokio::task::JoinSet::new();
        for (idx, name) in names.iter().enumerate() {
            let mgr = Arc::clone(self);
            let name = name.clone();
            let command = command.to_string();
            let opts = opts.clone();
            let sem = Arc::clone(&sem);
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore closed");
                let result = match mgr.run(&name, &command, opts).await {
                    Ok(r) => r,
                    Err(e) => CommandResult::failure(&name, &command, &e.to_string()),
                };
                (idx, result)
            });
        }
        let mut results: Vec<(usize, CommandResult)> = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Ok(pair) = res {
                results.push(pair);
            }
        }
        results.sort_by_key(|(i, _)| *i);
        results.into_iter().map(|(_, r)| r).collect()
    }

    pub async fn upload(&self, name: &str, local: &Path, remote: &str) -> anyhow::Result<()> {
        let conn = self.connection(name).await?;
        let result = {
            let mut guard = conn.lock().await;
            guard.upload(local, remote).await
        };
        let evict = matches!(&result, Err(e) if Self::is_evictable(e));
        self.finish_use(name, &conn, evict).await;
        result
    }

    pub async fn download(&self, name: &str, remote: &str, local: &Path) -> anyhow::Result<()> {
        let conn = self.connection(name).await?;
        let result = {
            let mut guard = conn.lock().await;
            guard.download(remote, local).await
        };
        let evict = matches!(&result, Err(e) if Self::is_evictable(e));
        self.finish_use(name, &conn, evict).await;
        result
    }

    pub fn by_tag(&self, tag: &str) -> Vec<&ServerConfig> {
        self.servers
            .values()
            .filter(|s| s.tags.iter().any(|t| t == tag))
            .collect()
    }

    pub async fn close_all(&self) {
        let mut pool = self.pool.lock().await;
        for (_, conn) in pool.drain() {
            conn.lock().await.close();
        }
    }
}
