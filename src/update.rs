//! Self-update from the latest GitHub release: `ai-sshclient update [--check]`.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const DEFAULT_API: &str = "https://api.github.com/repos/rogeriothe/ai-sshclient/releases/latest";
pub const ENV_API: &str = "AI_SSHCLIENT_UPDATE_URL";
const MAX_DOWNLOAD: u64 = 200 * 1024 * 1024;

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Release asset holding the binary for the platform we are running on.
pub fn asset_name() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("ai-sshclient-x86_64-linux"),
        ("windows", "x86_64") => Ok("ai-sshclient-x86_64-windows.exe"),
        (os, arch) => bail!("no prebuilt release for {os}/{arch}"),
    }
}

/// Parses `v1.2.3` / `1.2.3` (ignoring any `-pre` suffix) into comparable parts.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    let mut it = core.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Looks up `name` in `sha256sum` output (`<hex>  <file>` lines).
pub fn checksum_for(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hash, file) = line.split_once(char::is_whitespace)?;
        (file.trim().trim_start_matches('*') == name).then(|| hash.to_lowercase())
    })
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .user_agent(concat!("ai-sshclient/", env!("CARGO_PKG_VERSION")))
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .build()
        .into()
}

fn download(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>> {
    let mut resp = agent.get(url).call().with_context(|| format!("GET {url}"))?;
    let mut buf = Vec::new();
    resp.body_mut()
        .as_reader()
        .take(MAX_DOWNLOAD)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// Replaces `target` with `data`. Works while `target` is the running binary
/// (Windows cannot overwrite it, but can rename it out of the way).
fn replace_binary(target: &Path, data: &[u8]) -> Result<()> {
    let dir = target.parent().context("executable has no parent directory")?;
    let tmp = dir.join(".ai-sshclient.update.tmp");
    std::fs::write(&tmp, data).with_context(|| format!("write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(windows)]
    {
        let old = dir.join("ai-sshclient.exe.old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(target, &old).context("move running executable aside")?;
    }
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("replace {}", target.display()));
    }
    Ok(())
}

pub fn run(check_only: bool) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let api = std::env::var(ENV_API).unwrap_or_else(|_| DEFAULT_API.to_string());
    let agent = agent();

    let release: Release = agent
        .get(&api)
        .header("Accept", "application/vnd.github+json")
        .call()
        .with_context(|| format!("GET {api}"))?
        .body_mut()
        .read_json()
        .context("parse release info")?;

    let latest = parse_version(&release.tag_name)
        .with_context(|| format!("unrecognized release tag '{}'", release.tag_name))?;
    let have = parse_version(current).context("invalid current version")?;

    if latest <= have {
        println!("ai-sshclient {current} is up to date (latest: {}).", release.tag_name);
        return Ok(());
    }
    println!("new version available: {} (current: v{current})", release.tag_name);
    if check_only {
        println!("run `ai-sshclient update` to install it.");
        return Ok(());
    }

    let name = asset_name()?;
    let find = |n: &str| release.assets.iter().find(|a| a.name == n);
    let bin = find(name).with_context(|| format!("release has no asset '{name}'"))?;
    let sums = find("SHA256SUMS").context("release has no SHA256SUMS; refusing to install")?;

    let sums_text = String::from_utf8(download(&agent, &sums.browser_download_url)?)
        .context("SHA256SUMS is not UTF-8")?;
    let expected = checksum_for(&sums_text, name)
        .with_context(|| format!("no checksum for '{name}' in SHA256SUMS"))?;

    println!("downloading {name}...");
    let data = download(&agent, &bin.browser_download_url)?;
    let actual = format!("{:x}", Sha256::digest(&data));
    if actual != expected {
        bail!("checksum mismatch for {name}: expected {expected}, got {actual}");
    }

    let exe = std::env::current_exe().context("locate current executable")?;
    replace_binary(&exe, &data)?;
    println!("updated to {} ({}).", release.tag_name, exe.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_compare() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.10.0-rc1"), Some((0, 10, 0)));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("x.y.z"), None);
        assert!(parse_version("v0.10.0") > parse_version("v0.9.9"));
    }

    #[test]
    fn checksum_lookup() {
        let sums = "AB12  ai-sshclient-x86_64-linux\ncd34 *ai-sshclient-x86_64-windows.exe\n";
        assert_eq!(checksum_for(sums, "ai-sshclient-x86_64-linux").as_deref(), Some("ab12"));
        assert_eq!(
            checksum_for(sums, "ai-sshclient-x86_64-windows.exe").as_deref(),
            Some("cd34")
        );
        assert_eq!(checksum_for(sums, "nope"), None);
    }

    #[test]
    fn replace_binary_overwrites_target() {
        let dir = std::env::temp_dir().join(format!("aissh-upd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("ai-sshclient.exe");
        std::fs::write(&target, b"old").unwrap();
        replace_binary(&target, b"new").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
