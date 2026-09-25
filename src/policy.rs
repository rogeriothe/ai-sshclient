//! Command checks applied before anything is sent to a server.

use std::sync::LazyLock;

use regex::Regex;

use crate::config::ServerConfig;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PolicyError(pub String);

// Commands that change state. Used by `read_only: true`. Deliberately broad: a false
// positive costs the agent a retry, a false negative can cost a server.
const WRITE_PATTERNS: &[&str] = &[
    r"\b(rm|rmdir|mv|cp|dd|mkfs(\.\w+)?|shred|truncate|chmod|chown|chgrp|ln|touch|mkdir|tee|install)\b",
    r"\b(shutdown|reboot|halt|poweroff|kill|killall|pkill)\b",
    r"\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask|kill)\b",
    r"\bservice\s+\S+\s+(start|stop|restart|reload)\b",
    r"\bdocker\s+(rm|rmi|stop|kill|restart|start|run|exec|create|prune|compose\s+(down|up|rm|restart|stop))\b",
    r"\bdocker\s+\w+\s+(prune|rm)\b",
    r"\b(apt|apt-get|yum|dnf|pip|npm)\s+(install|remove|purge|upgrade|update)\b",
    r"\b(useradd|userdel|usermod|passwd|crontab\s+-[er])\b",
    r"\bsed\s+(-\w*i|--in-place)",
    r"\bgit\s+(push|reset|checkout|commit|merge|rebase|clean)\b",
    r"(^|[^<>&0-9])>>?\s*[^&\s]", // output redirection to a file (not 2>&1)
];

static WRITE_RE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    WRITE_PATTERNS
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect()
});

static SUDO_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|[;&|(`\s])sudo\b").unwrap());

/// Raise PolicyError if `command` (or script text) is not allowed on `server`.
pub fn check_command(server: &ServerConfig, command: &str, sudo: bool) -> Result<(), PolicyError> {
    let policy = &server.policy;
    if (sudo || SUDO_RE.is_match(command)) && !policy.allow_sudo {
        return Err(PolicyError(format!(
            "server '{}': sudo is not allowed by policy",
            server.name
        )));
    }
    for pattern in &policy.deny {
        let re = Regex::new(pattern)
            .map_err(|e| PolicyError(format!("invalid regex {pattern:?}: {e}")))?;
        if re.is_match(command) {
            return Err(PolicyError(format!(
                "server '{}': command matches denied pattern {pattern:?}",
                server.name
            )));
        }
    }
    if !policy.allow.is_empty() {
        let matched = policy.allow.iter().any(|p| {
            Regex::new(p)
                .map(|re| re.is_match(command))
                .unwrap_or(false)
        });
        if !matched {
            return Err(PolicyError(format!(
                "server '{}': command matches no allowed pattern",
                server.name
            )));
        }
    }
    if policy.read_only {
        for regex in WRITE_RE.iter() {
            if let Some(m) = regex.find(command) {
                return Err(PolicyError(format!(
                    "server '{}' is read_only: command looks like a write ({:?})",
                    server.name,
                    m.as_str().trim()
                )));
            }
        }
    }
    Ok(())
}

pub fn check_upload(server: &ServerConfig) -> Result<(), PolicyError> {
    if server.policy.read_only {
        return Err(PolicyError(format!(
            "server '{}' is read_only: uploads are not allowed",
            server.name
        )));
    }
    Ok(())
}
