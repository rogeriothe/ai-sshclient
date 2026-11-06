//! Import server definitions from OpenSSH config (~/.ssh/config) into servers.yaml.

use std::path::{Path, PathBuf};
use regex::RegexBuilder;

#[derive(Debug, Clone, clap::Args)]
pub struct ImportArgs {
    /// Server name/host alias to import from ssh config
    pub server: String,

    /// Name of the server in servers.yaml (default: same as server)
    #[arg(long)]
    pub name: Option<String>,

    /// Path to ssh config file (default: ./.ssh/config if exists, else ~/.ssh/config)
    #[arg(long = "ssh-config")]
    pub ssh_config: Option<PathBuf>,

    /// Path to target servers.yaml (default: ./servers.yaml)
    #[arg(short = 'o', long = "out")]
    pub out: Option<PathBuf>,

    /// Overwrite existing server entry if it already exists
    #[arg(long)]
    pub overwrite: bool,

    /// Override host
    #[arg(long)]
    pub host: Option<String>,

    /// Override user
    #[arg(short = 'u', long)]
    pub user: Option<String>,

    /// Override port
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Override description
    #[arg(short = 'd', long)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SshHostConfig {
    pub name: String,
    pub host: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub key_path: Option<String>,
    pub proxy_jump: Option<String>,
    pub description: Option<String>,
    pub is_found: bool,
}

#[derive(Debug, Clone)]
struct SshSection {
    patterns: Option<String>,
    comment: Option<String>,
    directives: Vec<(String, String)>,
}

/// Strip surrounding single or double quotes.
fn strip_quotes(val: &str) -> String {
    let val = val.trim();
    if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
        || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
    {
        val[1..val.len() - 1].to_string()
    } else {
        val.to_string()
    }
}

/// Parse a single directive line into (lowercase_key, value).
fn parse_directive_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let (key, val) = if let Some(eq_idx) = line.find('=') {
        let space_idx = line.find(char::is_whitespace);
        if let Some(s_idx) = space_idx && s_idx < eq_idx {
            let (k, v) = line.split_at(s_idx);
            (k.trim(), v.trim())
        } else {
            let (k, v) = line.split_at(eq_idx);
            (k.trim(), v[1..].trim())
        }
    } else {
        let mut parts = line.splitn(2, char::is_whitespace);
        let k = parts.next()?;
        let v = parts.next().unwrap_or("").trim();
        (k, v)
    };

    let val = strip_quotes(val);
    Some((key.to_lowercase(), val))
}

/// Parse ssh config file content into sections.
fn parse_ssh_config_sections(content: &str) -> Vec<SshSection> {
    let mut sections = Vec::new();
    let mut current_patterns: Option<String> = None;
    let mut current_comment: Option<String> = None;
    let mut current_directives: Vec<(String, String)> = Vec::new();
    let mut pending_comment_lines: Vec<String> = Vec::new();
    // `Match` conditions are not evaluated, so their directives are skipped.
    let mut in_match = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            pending_comment_lines.clear();
            continue;
        }

        if trimmed.starts_with('#') {
            let c = trimmed.trim_start_matches('#').trim();
            // Ignore decorative divider comments like "===== SITE ====="
            if !c.starts_with('=') && !c.starts_with('-') && !c.is_empty() {
                pending_comment_lines.push(c.to_string());
            }
            continue;
        }

        let (key, val) = match parse_directive_line(trimmed) {
            Some(pair) => pair,
            None => continue,
        };

        if key == "host" {
            if current_patterns.is_some() || !current_directives.is_empty() {
                sections.push(SshSection {
                    patterns: current_patterns,
                    comment: current_comment,
                    directives: std::mem::take(&mut current_directives),
                });
            }

            let comment = pending_comment_lines.last().cloned();
            pending_comment_lines.clear();

            current_patterns = Some(val);
            current_comment = comment;
            in_match = false;
        } else if key == "match" {
            if current_patterns.is_some() || !current_directives.is_empty() {
                sections.push(SshSection {
                    patterns: current_patterns,
                    comment: current_comment,
                    directives: std::mem::take(&mut current_directives),
                });
            }
            pending_comment_lines.clear();
            current_patterns = None;
            current_comment = None;
            in_match = true;
        } else {
            pending_comment_lines.clear();
            if !in_match {
                current_directives.push((key, val));
            }
        }
    }

    if current_patterns.is_some() || !current_directives.is_empty() {
        sections.push(SshSection {
            patterns: current_patterns,
            comment: current_comment,
            directives: current_directives,
        });
    }

    sections
}

/// Matches a glob-style pattern (* and ?) against target string, case-insensitively.
fn pattern_matches(pattern: &str, target: &str) -> bool {
    let mut regex_str = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex_str.push('\\');
                regex_str.push(ch);
            }
            _ => regex_str.push(ch),
        }
    }
    regex_str.push('$');

    if let Ok(re) = RegexBuilder::new(&regex_str).case_insensitive(true).build() {
        re.is_match(target)
    } else {
        false
    }
}

/// Evaluates a list of patterns from a `Host` line against the target host.
/// Returns (matched, priority). The priority only classifies how the block
/// matched; it does not decide which value wins (see
/// `resolve_host_from_ssh_config`):
/// - priority 100: exact match
/// - priority 10 + len: wildcard pattern (e.g. web-*)
/// - priority 1: catch-all "*"
/// - priority 0: no patterns
fn evaluate_patterns(patterns_str: &str, target: &str) -> (bool, u32) {
    let tokens: Vec<&str> = patterns_str
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let mut matched = false;
    let mut max_priority = 0;

    for token in tokens {
        if let Some(neg) = token.strip_prefix('!') {
            if pattern_matches(neg, target) {
                return (false, 0);
            }
        } else if pattern_matches(token, target) {
            matched = true;
            let priority = if token.eq_ignore_ascii_case(target) {
                100
            } else if token == "*" {
                1
            } else {
                10 + token.chars().filter(|c| *c != '*' && *c != '?').count() as u32
            };
            if priority > max_priority {
                max_priority = priority;
            }
        }
    }

    (matched, max_priority)
}

/// Extracts a list of all distinct host aliases defined in the ssh config.
pub fn list_available_hosts(content: &str) -> Vec<String> {
    let sections = parse_ssh_config_sections(content);
    let mut hosts = Vec::new();
    for s in sections {
        if let Some(patterns) = s.patterns {
            for token in patterns.split(|c: char| c.is_whitespace() || c == ',') {
                let token = token.trim();
                if !token.is_empty() && !token.starts_with('!') && token != "*" {
                    if !hosts.contains(&token.to_string()) {
                        hosts.push(token.to_string());
                    }
                }
            }
        }
    }
    hosts
}

/// Resolve host settings from ssh config content for a given target name.
///
/// Follows OpenSSH: blocks are read in file order and, for each setting, the
/// first value obtained from a matching block wins. `Match` blocks and
/// `Include` are not evaluated.
pub fn resolve_host_from_ssh_config(content: &str, target: &str) -> Result<SshHostConfig, anyhow::Error> {
    let sections = parse_ssh_config_sections(content);

    let mut host: Option<String> = None;
    let mut user: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut key_path: Option<String> = None;
    let mut proxy_jump: Option<String> = None;
    let mut description: Option<String> = None;
    let mut is_found = false;

    for section in &sections {
        let (matched, priority) = if let Some(patterns) = &section.patterns {
            evaluate_patterns(patterns, target)
        } else {
            // Global block before any Host line
            (true, 0)
        };

        if !matched {
            continue;
        }

        if priority >= 10 {
            is_found = true;
        }

        if priority == 100 && description.is_none() {
            description = section.comment.clone();
        }

        for (key, val) in &section.directives {
            match key.as_str() {
                "hostname" => {
                    is_found = true;
                    host.get_or_insert_with(|| val.clone());
                }
                "user" => {
                    user.get_or_insert_with(|| val.clone());
                }
                "port" => {
                    if port.is_none() {
                        port = val.parse::<u16>().ok();
                    }
                }
                "identityfile" => {
                    // OpenSSH expands %d to home directory
                    key_path.get_or_insert_with(|| val.replace("%d", "~"));
                }
                "proxyjump" => {
                    proxy_jump.get_or_insert_with(|| val.clone());
                }
                _ => {}
            }
        }
    }

    let host = host.or_else(|| is_found.then(|| target.to_string()));

    Ok(SshHostConfig {
        name: target.to_string(),
        host,
        user,
        port,
        key_path,
        proxy_jump,
        description,
        is_found,
    })
}

/// Find ssh config path, checking `--ssh-config`, then `./.ssh/config`, then `~/.ssh/config`.
pub fn find_ssh_config(explicit: Option<&Path>) -> Result<PathBuf, anyhow::Error> {
    if let Some(p) = explicit {
        let path = crate::config::expand_tilde(p);
        if path.is_file() {
            return Ok(path);
        }
        return Err(anyhow::anyhow!("ssh config file not found: {}", p.display()));
    }

    // 1. Check ./.ssh/config
    let local = PathBuf::from("./.ssh/config");
    if local.is_file() {
        return Ok(local);
    }

    // 2. Check ~/.ssh/config
    if let Some(home) = dirs::home_dir() {
        let user_config = home.join(".ssh/config");
        if user_config.is_file() {
            return Ok(user_config);
        }
    }

    Err(anyhow::anyhow!(
        "ssh config file not found (searched ./.ssh/config, ~/.ssh/config)"
    ))
}

/// Format YAML string value with quotes if needed.
fn format_yaml_val(s: &str) -> String {
    let needs_quotes = s.is_empty()
        || s.contains(':')
        || s.contains('#')
        || s.contains('\'')
        || s.contains('"')
        || s.contains('{')
        || s.contains('}')
        || s.contains('[')
        || s.contains(']')
        || s.contains(',')
        || s.contains('&')
        || s.contains('*')
        || s.contains('?')
        || s.contains('|')
        || s.starts_with(' ')
        || s.ends_with(' ');

    if !needs_quotes {
        s.to_string()
    } else if !s.contains('\'') {
        format!("'{s}'")
    } else {
        serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""))
    }
}

/// Generate YAML block for a single server.
pub fn format_server_yaml(name: &str, server: &SshHostConfig) -> String {
    let mut out = String::new();
    out.push_str(&format!("  {}:\n", name));
    if let Some(host) = &server.host {
        out.push_str(&format!("    host: {}\n", format_yaml_val(host)));
    }
    if let Some(user) = &server.user {
        out.push_str(&format!("    user: {}\n", format_yaml_val(user)));
    }
    if let Some(port) = server.port {
        if port != 22 {
            out.push_str(&format!("    port: {}\n", port));
        }
    }
    if let Some(key_path) = &server.key_path {
        out.push_str(&format!("    key_path: {}\n", format_yaml_val(key_path)));
    }
    if let Some(proxy_jump) = &server.proxy_jump {
        out.push_str(&format!("    proxy_jump: {}\n", format_yaml_val(proxy_jump)));
    }
    if let Some(desc) = &server.description {
        out.push_str(&format!("    description: {}\n", format_yaml_val(desc)));
    }
    out
}

/// Check if server name exists in existing YAML content.
pub fn server_exists_in_yaml(content: &str, name: &str) -> bool {
    if let Ok(val) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(content) {
        if let Some(servers) = val.get("servers").and_then(|s| s.as_mapping()) {
            return servers.contains_key(&serde_yaml_ng::Value::String(name.to_string()));
        }
    }
    let mut in_servers = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if indent == 0 && (trimmed == "servers:" || trimmed.starts_with("servers: ")) {
            in_servers = true;
        } else if indent == 0 && !trimmed.starts_with('#') && !trimmed.is_empty() {
            in_servers = false;
        }
        if in_servers && indent == 2 {
            let key = trimmed
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(|c| c == '\'' || c == '"');
            if key == name {
                return true;
            }
        }
    }
    false
}

/// Check if defaults in existing YAML specifies a user.
pub fn defaults_has_user(content: &str) -> bool {
    if let Ok(val) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(content) {
        if let Some(defaults) = val.get("defaults").and_then(|d| d.as_mapping()) {
            return defaults.contains_key(&serde_yaml_ng::Value::String("user".to_string()));
        }
    }
    false
}

/// Resolve proxy_jump to match an existing server name in YAML if possible.
pub fn resolve_proxy_jump_name(raw_jump: &str, yaml_content: &str) -> String {
    if let Ok(val) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(yaml_content) {
        if let Some(servers) = val.get("servers").and_then(|s| s.as_mapping()) {
            // 1. Direct match with server name
            let jump_key = serde_yaml_ng::Value::String(raw_jump.to_string());
            if servers.contains_key(&jump_key) {
                return raw_jump.to_string();
            }

            // 2. Extract host from user@host:port
            let host_part = if let Some((_, rest)) = raw_jump.split_once('@') {
                rest
            } else {
                raw_jump
            };
            let host_clean = if let Some((h, _)) = host_part.split_once(':') {
                h
            } else {
                host_part
            };

            let clean_key = serde_yaml_ng::Value::String(host_clean.to_string());
            if servers.contains_key(&clean_key) {
                return host_clean.to_string();
            }

            // 3. Match against any server's `host` field
            for (srv_name, srv_val) in servers {
                if let Some(h) = srv_val.get("host").and_then(|v| v.as_str()) {
                    if h == host_clean {
                        if let Some(name_str) = srv_name.as_str() {
                            return name_str.to_string();
                        }
                    }
                }
            }
            return host_clean.to_string();
        }
    }
    raw_jump.to_string()
}

/// Appends a new server YAML block to existing YAML content.
pub fn append_server_to_yaml(content: &str, server_yaml: &str) -> String {
    let mut result = content.to_string();
    if !result.is_empty() && !result.ends_with('\n') {
        result.push('\n');
    }

    let has_servers_root = result.lines().any(|l| {
        let t = l.trim_start();
        l.len() == t.len() && (t == "servers:" || t.starts_with("servers: "))
    });

    if !has_servers_root {
        if !result.trim().is_empty() && !result.ends_with("\n\n") {
            result.push('\n');
        }
        result.push_str("servers:\n");
        result.push_str(server_yaml);
    } else {
        let last_non_empty = result.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
        if last_non_empty.trim() == "servers:" {
            result.push_str(server_yaml);
        } else {
            if !result.ends_with("\n\n") {
                result.push('\n');
            }
            result.push_str(server_yaml);
        }
    }
    result
}

/// Replaces an existing server entry in YAML content in place, preserving surrounding content.
pub fn replace_server_in_yaml(content: &str, name: &str, server_yaml: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut in_servers = false;
    let mut start_idx = None;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();

        if indent == 0 {
            if trimmed == "servers:" || trimmed.starts_with("servers: ") {
                in_servers = true;
            } else if !trimmed.starts_with('#') && !trimmed.is_empty() {
                in_servers = false;
            }
        }

        if in_servers && indent == 2 {
            let key = trimmed
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(|c| c == '\'' || c == '"');
            if key == name {
                start_idx = Some(idx);
                break;
            }
        }
    }

    let start = start_idx?;

    let mut end = lines.len();
    for idx in (start + 1)..lines.len() {
        let line = lines[idx];
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();

        if trimmed.is_empty() {
            continue;
        }

        if indent <= 2 {
            let mut cut = idx;
            while cut > start + 1 && lines[cut - 1].trim().is_empty() {
                cut -= 1;
            }
            end = cut;
            break;
        }
    }

    let mut result = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if i == start {
            result.push(server_yaml.trim_end());
        } else if i > start && i < end {
            // skip old server lines
        } else {
            result.push(line);
        }
    }

    let mut output = result.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }
    Some(output)
}

/// Write servers.yaml readable only by its owner, since it may hold secrets.
/// Permissions are tightened before the content is written.
fn write_private(path: &Path, content: &str) -> Result<(), anyhow::Error> {
    let fail = |e: std::io::Error| anyhow::anyhow!("failed to write {}: {e}", path.display());

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        // Without truncate: a chmod failure must leave the existing file intact.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(fail)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(fail)?;
        file.set_len(0).map_err(fail)?;
        file.write_all(content.as_bytes()).map_err(fail)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, content).map_err(fail)?;

    Ok(())
}

/// Primary entrypoint to import a server from .ssh/config into servers.yaml.
pub fn import_server(args: ImportArgs) -> Result<(), anyhow::Error> {
    let ssh_config_path = find_ssh_config(args.ssh_config.as_deref())?;
    let ssh_config_text = std::fs::read_to_string(&ssh_config_path)
        .map_err(|e| anyhow::anyhow!("failed to read ssh config {}: {e}", ssh_config_path.display()))?;

    let resolved = resolve_host_from_ssh_config(&ssh_config_text, &args.server)?;
    if !resolved.is_found {
        let available = list_available_hosts(&ssh_config_text);
        if available.is_empty() {
            return Err(anyhow::anyhow!(
                "server '{}' not found in {}",
                args.server,
                ssh_config_path.display()
            ));
        } else {
            return Err(anyhow::anyhow!(
                "server '{}' not found in {}. Available servers: {}",
                args.server,
                ssh_config_path.display(),
                available.join(", ")
            ));
        }
    }

    let server_name = args.name.unwrap_or(args.server.clone());
    let out_path = args.out.unwrap_or_else(|| PathBuf::from("servers.yaml"));

    let existing_content = if out_path.exists() {
        Some(std::fs::read_to_string(&out_path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", out_path.display()))?)
    } else {
        None
    };

    if let Some(content) = &existing_content {
        let exists = server_exists_in_yaml(content, &server_name);
        if exists && !args.overwrite {
            return Err(anyhow::anyhow!(
                "server '{server_name}' already exists in {} (use --overwrite to replace)",
                out_path.display()
            ));
        }
    }

    let host = args.host.or(resolved.host).unwrap_or_else(|| server_name.clone());

    let user = args.user.or(resolved.user).or_else(|| {
        if let Some(content) = &existing_content {
            if defaults_has_user(content) {
                return None;
            }
        }
        std::env::var("USER").ok().or_else(|| Some("root".to_string()))
    });

    let port = args.port.or(resolved.port);

    let proxy_jump = resolved.proxy_jump.map(|pj| {
        if let Some(content) = &existing_content {
            resolve_proxy_jump_name(&pj, content)
        } else {
            pj
        }
    });

    let description = args
        .description
        .or(resolved.description)
        .or_else(|| Some(server_name.clone()));

    let config = SshHostConfig {
        name: server_name.clone(),
        host: Some(host),
        user,
        port,
        key_path: resolved.key_path,
        proxy_jump,
        description,
        is_found: true,
    };

    let block = format_server_yaml(&server_name, &config);

    if let Some(content) = &existing_content {
        let exists = server_exists_in_yaml(content, &server_name);
        if exists && args.overwrite {
            let new_content = replace_server_in_yaml(content, &server_name, &block)
                .ok_or_else(|| anyhow::anyhow!("failed to replace server '{server_name}' in YAML"))?;
            write_private(&out_path, &new_content)?;
            println!("Replaced server '{server_name}' in {}", out_path.display());
        } else {
            let new_content = append_server_to_yaml(content, &block);
            write_private(&out_path, &new_content)?;
            println!("Added server '{server_name}' to {}", out_path.display());
        }
    } else {
        let default_content = format!(
            "# Servers configuration for ai-sshclient\n\ndefaults:\n  port: 22\n  timeout: 10\n\nservers:\n{}",
            block
        );
        write_private(&out_path, &default_content)?;
        println!("Created {} with server '{server_name}'", out_path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SSH_CONFIG: &str = r#"
# Group defaults
Host web-*
  User webadmin
  IdentityFile /keys/example.pem

# Multi-host alias
Host h1 h2
  Port 2222

# Specific server with comment description
# Application Server
Host app1
  HostName 10.0.0.1
  User appuser
  Port 8022
  IdentityFile ~/.ssh/id_ed25519
  ProxyJump bastion

# Negated pattern host
Host *.internal !bad.internal
  User internaluser

Host bare-host
  # No hostname

# Global options
Host *
  ServerAliveInterval 60
  User defaultuser
"#;

    #[test]
    fn test_resolve_exact_server() {
        let res = resolve_host_from_ssh_config(SAMPLE_SSH_CONFIG, "app1").unwrap();
        assert!(res.is_found);
        assert_eq!(res.host.as_deref(), Some("10.0.0.1"));
        assert_eq!(res.user.as_deref(), Some("appuser"));
        assert_eq!(res.port, Some(8022));
        assert_eq!(res.key_path.as_deref(), Some("~/.ssh/id_ed25519"));
        assert_eq!(res.proxy_jump.as_deref(), Some("bastion"));
        assert_eq!(res.description.as_deref(), Some("Application Server"));
    }

    #[test]
    fn test_resolve_wildcard_inheritance() {
        let res = resolve_host_from_ssh_config(SAMPLE_SSH_CONFIG, "web-01").unwrap();
        assert!(res.is_found);
        assert_eq!(res.host.as_deref(), Some("web-01"));
        assert_eq!(res.user.as_deref(), Some("webadmin"));
        assert_eq!(res.key_path.as_deref(), Some("/keys/example.pem"));
    }

    #[test]
    fn test_resolve_multi_host() {
        let res = resolve_host_from_ssh_config(SAMPLE_SSH_CONFIG, "h2").unwrap();
        assert!(res.is_found);
        assert_eq!(res.port, Some(2222));
    }

    #[test]
    fn test_negated_pattern() {
        let res_good = resolve_host_from_ssh_config(SAMPLE_SSH_CONFIG, "good.internal").unwrap();
        assert!(res_good.is_found);
        assert_eq!(res_good.user.as_deref(), Some("internaluser"));

        let res_bad = resolve_host_from_ssh_config(SAMPLE_SSH_CONFIG, "bad.internal").unwrap();
        assert_eq!(res_bad.user.as_deref(), Some("defaultuser"));
        assert!(!res_bad.is_found);
    }

    #[test]
    fn test_first_matching_value_wins_like_openssh() {
        let config = "Host *\n  User first\n  Port 2200\n\nHost app\n  HostName 10.0.0.1\n  User second\n  Port 2201\n";
        let res = resolve_host_from_ssh_config(config, "app").unwrap();
        assert_eq!(res.host.as_deref(), Some("10.0.0.1"));
        assert_eq!(res.user.as_deref(), Some("first"));
        assert_eq!(res.port, Some(2200));
    }

    #[test]
    fn test_match_block_directives_are_ignored() {
        let config = "Match user nobody\n  User wrong\n\nHost app\n  User right\n\nMatch all\n  Port 2200\n";
        let res = resolve_host_from_ssh_config(config, "app").unwrap();
        assert_eq!(res.user.as_deref(), Some("right"));
        assert_eq!(res.port, None);
    }

    #[test]
    fn test_append_server_to_yaml() {
        let base = "defaults:\n  port: 22\n\nservers:\n  s1:\n    host: 1.1.1.1\n";
        let to_add = "  s2:\n    host: 2.2.2.2\n";
        let updated = append_server_to_yaml(base, to_add);
        assert_eq!(
            updated,
            "defaults:\n  port: 22\n\nservers:\n  s1:\n    host: 1.1.1.1\n\n  s2:\n    host: 2.2.2.2\n"
        );
    }

    #[test]
    fn test_replace_server_in_yaml() {
        let base = "defaults:\n  port: 22\n\nservers:\n  s1:\n    host: 1.1.1.1\n\n  s2:\n    host: 2.2.2.2\n";
        let replacement = "  s1:\n    host: 9.9.9.9\n";
        let updated = replace_server_in_yaml(base, "s1", replacement).unwrap();
        assert_eq!(
            updated,
            "defaults:\n  port: 22\n\nservers:\n  s1:\n    host: 9.9.9.9\n\n  s2:\n    host: 2.2.2.2\n"
        );
    }
}

