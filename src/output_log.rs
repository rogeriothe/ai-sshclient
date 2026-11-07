//! Append-only JSONL log of every command's full output (stdout/stderr) sent over SSH,
//! kept as one file per server.
//!
//! Distinct from `audit`, which never logs output. On by default; disable per-server (or for
//! everyone via the `defaults` block) with `log_output: false` in servers.yaml, or point it
//! elsewhere / turn it off process-wide with `AI_SSHCLIENT_OUTPUT_LOG`.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::Utc;
use serde_json::{Map, Value};

pub const ENV_OUTPUT_LOG_VAR: &str = "AI_SSHCLIENT_OUTPUT_LOG";

static LOCK: Mutex<()> = Mutex::new(());

fn default_output_log_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".local/state/ai-sshclient/commands"))
}

/// Directory holding one JSONL file per server, or `None` if output logging is off.
pub fn output_log_dir() -> Option<PathBuf> {
    match std::env::var(ENV_OUTPUT_LOG_VAR) {
        Ok(value) => {
            let lower = value.to_lowercase();
            if matches!(lower.as_str(), "" | "0" | "off" | "false" | "no") {
                None
            } else {
                Some(crate::config::expand_tilde(std::path::Path::new(&value)))
            }
        }
        Err(_) => default_output_log_dir(),
    }
}

/// Server names are config keys (not attacker-controlled path input), but sanitize anyway
/// so a stray `/` or `..` can't escape the log directory.
fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "_".to_string()
    } else {
        cleaned
    }
}

pub fn record(server: &str, entry: Map<String, Value>) {
    let Some(dir) = output_log_dir() else { return };
    let path = dir.join(format!("{}.log", sanitize_filename(server)));

    let mut entry = entry;
    let mut ordered = Map::new();
    ordered.insert(
        "ts".to_string(),
        Value::String(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
    );
    ordered.append(&mut entry);

    let Ok(line) = serde_json::to_string(&Value::Object(ordered)) else {
        return;
    };

    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path);
        if let Ok(mut file) = file {
            let _ = writeln!(file, "{line}");
        }
    }
    // Windows: files under the user profile are private by default ACLs.
    #[cfg(not(unix))]
    {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path);
        if let Ok(mut file) = file {
            let _ = writeln!(file, "{line}");
        }
    }
}
