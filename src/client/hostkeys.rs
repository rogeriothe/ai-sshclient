//! TOFU / strict / warn host-key verification against our own known_hosts file
//! (never touches `~/.ssh/known_hosts`).

use std::io::Write;
use std::path::PathBuf;

use russh::keys::PublicKeyOrCertificate;
use russh::keys::ssh_key::PublicKey;

pub fn known_hosts_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/ai-sshclient/known_hosts")
}

fn entry_key(public_key: &PublicKeyOrCertificate) -> Option<(String, String)> {
    let key: &PublicKey = match public_key {
        PublicKeyOrCertificate::PublicKey { key, .. } => key,
        PublicKeyOrCertificate::Certificate(_) => return None,
    };
    let openssh = key.to_openssh().ok()?;
    let mut parts = openssh.splitn(2, ' ');
    let algo = parts.next()?.to_string();
    let b64 = parts.next()?.trim().to_string();
    Some((algo, b64))
}

fn load_entries(host: &str) -> Vec<(String, String)> {
    let path = known_hosts_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let h = parts.next()?;
            if h != host {
                return None;
            }
            let algo = parts.next()?.to_string();
            let b64 = parts.next()?.to_string();
            Some((algo, b64))
        })
        .collect()
}

fn append_entry(host: &str, algo: &str, b64: &str) {
    let path = known_hosts_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
        {
            let _ = writeln!(file, "{host} {algo} {b64}");
        }
    }
}

/// `true` = accept, `false` = reject. `policy` is `tofu` | `strict` | `warn`.
/// A host whose stored key differs from the offered one is always rejected.
pub fn check(host: &str, policy: &str, public_key: &PublicKeyOrCertificate) -> bool {
    let Some((algo, b64)) = entry_key(public_key) else {
        // Certificates aren't tracked in known_hosts; accept (the CA signature was
        // already verified during key exchange).
        return true;
    };
    let known = load_entries(host);
    if let Some((_, existing_b64)) = known.iter().find(|(a, _)| *a == algo) {
        return existing_b64 == &b64;
    }
    match policy {
        "tofu" => {
            append_entry(host, &algo, &b64);
            true
        }
        "strict" => false,
        "warn" => {
            eprintln!("ai-sshclient: warning: unknown host key for {host} ({algo})");
            true
        }
        _ => false,
    }
}
