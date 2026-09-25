//! Append-only JSONL log of every action sent to a server (never command output).

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::Utc;
use serde_json::{Map, Value};

pub const ENV_AUDIT_VAR: &str = "AI_SSHCLIENT_AUDIT";

static LOCK: Mutex<()> = Mutex::new(());

fn default_audit_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".local/state/ai-sshclient/audit.log"))
}

pub fn audit_path() -> Option<PathBuf> {
    match std::env::var(ENV_AUDIT_VAR) {
        Ok(value) => {
            let lower = value.to_lowercase();
            if matches!(lower.as_str(), "" | "0" | "off" | "false" | "no") {
                None
            } else {
                Some(crate::config::expand_tilde(std::path::Path::new(&value)))
            }
        }
        Err(_) => default_audit_path(),
    }
}

pub fn record(entry: Map<String, Value>) {
    let Some(path) = audit_path() else { return };
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
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
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
}
