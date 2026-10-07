//! Load server definitions from a YAML file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde::Deserialize;
use serde_json::json;

pub const ENV_CONFIG_VAR: &str = "AI_SSHCLIENT_CONFIG";
const HOST_KEY_POLICIES: [&str; 3] = ["tofu", "strict", "warn"];

static ENV_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap());

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

impl ConfigError {
    fn new(msg: impl Into<String>) -> Self {
        ConfigError(msg.into())
    }
}

/// Guard rails for commands sent to a server. A safety net against mistakes, not a sandbox.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub read_only: bool,
    #[serde(default = "default_true")]
    pub allow_sudo: bool,
    pub deny: Vec<String>,
    pub allow: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Policy {
    fn validate(&self, server: &str) -> Result<(), ConfigError> {
        for key in ["deny", "allow"] {
            let patterns = if key == "deny" {
                &self.deny
            } else {
                &self.allow
            };
            for pattern in patterns {
                if let Err(exc) = Regex::new(pattern) {
                    return Err(ConfigError::new(format!(
                        "server '{server}': invalid policy.{key} regex {pattern:?}: {exc}"
                    )));
                }
            }
        }
        Ok(())
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            read_only: false,
            allow_sudo: true,
            deny: Vec::new(),
            allow: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct Secrets {
    pub password: Option<String>,
    pub key_passphrase: Option<String>,
    pub sudo_password: Option<String>,
    pub sudo_error: Option<String>,
}

impl Secrets {
    pub fn values(&self) -> Vec<String> {
        [&self.password, &self.key_passphrase, &self.sudo_password]
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[derive(Default)]
struct RawServer {
    host: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    password: Option<String>,
    password_command: Option<String>,
    sudo_password: Option<String>,
    sudo_password_command: Option<String>,
    key_path: Option<String>,
    key_passphrase: Option<String>,
    passphrase_command: Option<String>,
    proxy_jump: Option<String>,
    host_key_policy: Option<String>,
    timeout: Option<f64>,
    max_output: Option<i64>,
    cwd: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    policy: Policy,
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    log_output: Option<bool>,
}


impl RawServer {
    /// Shallow-merge `override_` over `self` (defaults <- server-specific).
    fn merged(&self, over: &RawServer) -> RawServer {
        RawServer {
            host: over.host.clone().or_else(|| self.host.clone()),
            user: over.user.clone().or_else(|| self.user.clone()),
            port: over.port.or(self.port),
            password: over.password.clone().or_else(|| self.password.clone()),
            password_command: over
                .password_command
                .clone()
                .or_else(|| self.password_command.clone()),
            sudo_password: over
                .sudo_password
                .clone()
                .or_else(|| self.sudo_password.clone()),
            sudo_password_command: over
                .sudo_password_command
                .clone()
                .or_else(|| self.sudo_password_command.clone()),
            key_path: over.key_path.clone().or_else(|| self.key_path.clone()),
            key_passphrase: over
                .key_passphrase
                .clone()
                .or_else(|| self.key_passphrase.clone()),
            passphrase_command: over
                .passphrase_command
                .clone()
                .or_else(|| self.passphrase_command.clone()),
            proxy_jump: over.proxy_jump.clone().or_else(|| self.proxy_jump.clone()),
            host_key_policy: over
                .host_key_policy
                .clone()
                .or_else(|| self.host_key_policy.clone()),
            timeout: over.timeout.or(self.timeout),
            max_output: over.max_output.or(self.max_output),
            cwd: over.cwd.clone().or_else(|| self.cwd.clone()),
            env: if over.env.is_empty() {
                self.env.clone()
            } else {
                over.env.clone()
            },
            policy: if over_has_policy(over) {
                over.policy.clone()
            } else {
                self.policy.clone()
            },
            description: over
                .description
                .clone()
                .or_else(|| self.description.clone()),
            tags: if over.tags.is_empty() {
                self.tags.clone()
            } else {
                over.tags.clone()
            },
            log_output: over.log_output.or(self.log_output),
        }
    }
}

fn over_has_policy(over: &RawServer) -> bool {
    over.policy.read_only
        || !over.policy.allow_sudo
        || !over.policy.deny.is_empty()
        || !over.policy.allow.is_empty()
}

#[derive(Debug, Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    defaults: RawServer,
    #[serde(default)]
    servers: BTreeMap<String, RawServer>,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub name: String,
    pub host: String,
    pub user: String,
    pub port: u16,
    pub password: Option<String>,
    pub password_command: Option<String>,
    pub sudo_password: Option<String>,
    pub sudo_password_command: Option<String>,
    pub key_path: Option<String>,
    pub key_passphrase: Option<String>,
    pub passphrase_command: Option<String>,
    pub proxy_jump: Option<String>,
    pub host_key_policy: String,
    pub timeout: f64,
    pub max_output: i64,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub policy: Policy,
    pub description: String,
    pub tags: Vec<String>,
    pub log_output: bool,
}

impl std::fmt::Debug for ServerConfig {
    /// Never prints secrets, even at debug verbosity (mirrors the Python dataclass's
    /// `field(repr=False)` on password/passphrase).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("name", &self.name)
            .field("host", &self.host)
            .field("user", &self.user)
            .field("port", &self.port)
            .field("key_path", &self.key_path)
            .field("proxy_jump", &self.proxy_jump)
            .field("host_key_policy", &self.host_key_policy)
            .field("tags", &self.tags)
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    pub fn auth_method(&self) -> &'static str {
        if self.key_path.is_some() {
            "key"
        } else if self.password.is_some() || self.password_command.is_some() {
            "password"
        } else {
            "agent"
        }
    }

    /// Expand `${VAR}` and run `*_command` entries. Fails naming this server.
    pub fn resolve_secrets(&self) -> Result<Secrets, ConfigError> {
        let password = resolve_secret(self.password.as_deref(), self.password_command.as_deref())
            .map_err(|e| ConfigError::new(format!("server '{}': {}", self.name, e.0)))?;
        let key_passphrase = resolve_secret(
            self.key_passphrase.as_deref(),
            self.passphrase_command.as_deref(),
        )
        .map_err(|e| ConfigError::new(format!("server '{}': {}", self.name, e.0)))?;
        // Deferred: a missing sudo secret must only fail commands that actually use sudo.
        let (sudo_password, sudo_error) = match resolve_secret(
            self.sudo_password.as_deref(),
            self.sudo_password_command.as_deref(),
        ) {
            Ok(v) => (v.or_else(|| password.clone()), None),
            Err(e) => (None, Some(format!("server '{}': {}", self.name, e.0))),
        };
        Ok(Secrets {
            password,
            key_passphrase,
            sudo_password,
            sudo_error,
        })
    }

    /// Everything an agent may see: no secrets.
    pub fn public_info(&self) -> serde_json::Value {
        json!({
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "auth": self.auth_method(),
            "proxy_jump": self.proxy_jump,
            "description": self.description,
            "tags": self.tags,
            "cwd": self.cwd,
            "policy": {
                "read_only": self.policy.read_only,
                "allow_sudo": self.policy.allow_sudo,
                "deny": self.policy.deny,
                "allow": self.policy.allow,
            },
            "log_output": self.log_output,
        })
    }
}

pub fn expand_env(value: &str) -> Result<String, ConfigError> {
    let mut err: Option<String> = None;
    let result = ENV_PATTERN.replace_all(value, |caps: &regex::Captures| {
        let var = &caps[1];
        match std::env::var(var) {
            Ok(v) => v,
            Err(_) => {
                err = Some(format!("environment variable '{var}' is not set"));
                String::new()
            }
        }
    });
    match err {
        Some(e) => Err(ConfigError::new(e)),
        None => Ok(result.into_owned()),
    }
}

fn resolve_secret(
    value: Option<&str>,
    command: Option<&str>,
) -> Result<Option<String>, ConfigError> {
    if let Some(value) = value {
        return Ok(Some(expand_env(value)?));
    }
    if let Some(command) = command {
        let parts = shell_words::split(command)
            .map_err(|e| ConfigError::new(format!("invalid secret command {command:?}: {e}")))?;
        let (program, args) = parts.split_first().ok_or_else(|| {
            ConfigError::new(format!("invalid secret command {command:?}: empty"))
        })?;
        let program_name = program.clone();
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| {
                ConfigError::new(format!("secret command {program_name:?} failed: {e}"))
            })?;
        if !output.status.success() {
            return Err(ConfigError::new(format!(
                "secret command {program_name:?} exited with {}",
                output.status.code().unwrap_or(-1)
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Ok(Some(stdout.lines().next().unwrap_or("").to_string()));
    }
    Ok(None)
}

pub const ENV_CONFIG_DEFAULT_CANDIDATES: &[&str] = &["servers.yaml"];

fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("servers.yaml")];
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".config/ai-sshclient/servers.yaml"));
    }
    paths
}

pub fn find_config_path(explicit: Option<&Path>) -> Result<PathBuf, ConfigError> {
    if let Some(explicit) = explicit {
        return Ok(expand_tilde(explicit));
    }
    if let Ok(env) = std::env::var(ENV_CONFIG_VAR) {
        return Ok(expand_tilde(Path::new(&env)));
    }
    for candidate in default_config_paths() {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    let searched = default_config_paths()
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(ConfigError::new(format!(
        "no config file found (searched: {searched}; or set ${ENV_CONFIG_VAR})"
    )))
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~")
        && let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    path.to_path_buf()
}

pub fn load_config(path: Option<&Path>) -> Result<BTreeMap<String, ServerConfig>, ConfigError> {
    let config_path = find_config_path(path)?;
    let text = std::fs::read_to_string(&config_path).map_err(|_| {
        ConfigError::new(format!("config file not found: {}", config_path.display()))
    })?;
    let raw: RawConfig = serde_yaml_ng::from_str(&text)
        .map_err(|e| ConfigError::new(format!("invalid YAML in {}: {e}", config_path.display())))?;

    let mut result = BTreeMap::new();
    for (name, settings) in &raw.servers {
        let merged = raw.defaults.merged(settings);

        let host = merged
            .host
            .clone()
            .ok_or_else(|| ConfigError::new(format!("server '{name}': 'host' is required")))?;
        let user = merged
            .user
            .clone()
            .ok_or_else(|| ConfigError::new(format!("server '{name}': 'user' is required")))?;

        let key_path = match &merged.key_path {
            Some(kp) => {
                let expanded = expand_env(kp)
                    .map_err(|e| ConfigError::new(format!("server '{name}': {}", e.0)))?;
                Some(expand_tilde(Path::new(&expanded)).display().to_string())
            }
            None => None,
        };

        let host_key_policy = merged
            .host_key_policy
            .clone()
            .unwrap_or_else(|| "tofu".to_string());
        if !HOST_KEY_POLICIES.contains(&host_key_policy.as_str()) {
            return Err(ConfigError::new(format!(
                "server '{name}': host_key_policy must be one of {}",
                HOST_KEY_POLICIES.join(", ")
            )));
        }

        merged.policy.validate(name)?;

        let server = ServerConfig {
            name: name.clone(),
            host,
            user,
            port: merged.port.unwrap_or(22),
            password: merged.password.clone(),
            password_command: merged.password_command.clone(),
            sudo_password: merged.sudo_password.clone(),
            sudo_password_command: merged.sudo_password_command.clone(),
            key_path,
            key_passphrase: merged.key_passphrase.clone(),
            passphrase_command: merged.passphrase_command.clone(),
            proxy_jump: merged.proxy_jump.clone(),
            host_key_policy,
            timeout: merged.timeout.unwrap_or(10.0),
            max_output: merged.max_output.unwrap_or(64000),
            cwd: merged.cwd.clone(),
            env: merged.env.clone(),
            policy: merged.policy.clone(),
            description: merged.description.clone().unwrap_or_default(),
            tags: merged.tags.clone(),
            log_output: merged.log_output.unwrap_or(true),
        };
        result.insert(name.clone(), server);
    }

    for server in result.values() {
        if let Some(jump) = &server.proxy_jump
            && !result.contains_key(jump) {
                return Err(ConfigError::new(format!(
                    "server '{}': proxy_jump '{jump}' is not a configured server",
                    server.name
                )));
            }
    }

    Ok(result)
}

pub fn connect_timeout(server: &ServerConfig) -> Duration {
    Duration::from_secs_f64(server.timeout.max(0.0))
}
