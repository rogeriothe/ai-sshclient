//! MCP server (stdio): lets AI agents run commands on configured servers without seeing credentials.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, Implementation, ServerCapabilities,
    ServerConfig as McpServerConfig,
};
use rmcp::{ErrorData as McpError, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use serde::Deserialize;

use crate::client::{CommandResult, CommandTimeout, RunOptions, SSHManager, UsageError};
use crate::config::{ConfigError, expand_tilde};
use crate::policy::PolicyError;

const INSTRUCTIONS: &str = "\
Run shell commands on remote servers over SSH. Credentials live in the server config and are \
never exposed; just pass the server name. Call list_servers first to see names, tags and each \
server's policy (read_only / allow_sudo / allow / deny). Results are plain text: a header line \
`exit=N 0.12s`, then stdout, then `--- stderr ---` and stderr if any (format=json for a JSON \
object). Colors are stripped and repeated lines folded. Output is capped (head + tail kept, the \
header says `truncated`); narrow your command (grep, tail, head) instead of dumping large files. \
Prefer run_script for multi-line scripts: it avoids quoting problems. Every call is audited.";

const DEFAULT_TIMEOUT: f64 = 120.0;

fn default_timeout() -> f64 {
    DEFAULT_TIMEOUT
}

fn json_result<T: serde::Serialize>(value: &T) -> CallToolResult {
    let text = serde_json::to_string(value).unwrap_or_default();
    CallToolResult::success(vec![ContentBlock::text(text)])
}

/// How command results are returned to the agent. Text avoids JSON-escaping the output.
#[derive(Debug, Default, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum Format {
    #[default]
    Text,
    Json,
}

/// Header line plus raw output; `server` adds a `=== name ===` prefix (run_on_tag).
fn result_text(r: &CommandResult, server: bool) -> String {
    let mut out = String::new();
    if server {
        out.push_str(&format!("=== {} ", r.server));
    }
    out.push_str(&format!("exit={} {}s", r.exit_code, r.duration_s));
    if r.truncated {
        out.push_str(&format!(
            " truncated (stdout {} B, stderr {} B)",
            r.stdout_bytes, r.stderr_bytes
        ));
    }
    if server {
        out.push_str(" ===");
    }
    out.push('\n');
    if let Some(e) = &r.error {
        out.push_str(&format!("error: {e}\n"));
        return out;
    }
    push_block(&mut out, &r.stdout);
    if !r.stderr.is_empty() {
        out.push_str("--- stderr ---\n");
        push_block(&mut out, &r.stderr);
    }
    out
}

fn push_block(out: &mut String, text: &str) {
    out.push_str(text);
    if !text.is_empty() && !text.ends_with('\n') {
        out.push('\n');
    }
}

/// JSON without what the agent already knows (command, server unless asked) or empty fields.
fn result_json(r: &CommandResult, server: bool) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if server {
        m.insert("server".into(), r.server.clone().into());
    }
    m.insert("exit_code".into(), r.exit_code.into());
    m.insert("duration_s".into(), r.duration_s.into());
    if let Some(e) = &r.error {
        m.insert("error".into(), e.clone().into());
        return m.into();
    }
    if !r.stdout.is_empty() {
        m.insert("stdout".into(), r.stdout.clone().into());
    }
    if !r.stderr.is_empty() {
        m.insert("stderr".into(), r.stderr.clone().into());
    }
    if r.truncated {
        m.insert("truncated".into(), true.into());
        m.insert("stdout_bytes".into(), r.stdout_bytes.into());
        m.insert("stderr_bytes".into(), r.stderr_bytes.into());
    }
    m.into()
}

fn command_result(r: &CommandResult, format: Format) -> CallToolResult {
    match format {
        Format::Text => text_result(result_text(r, false)),
        Format::Json => json_result(&result_json(r, false)),
    }
}

fn text_result(message: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(message.into())])
}

fn expand_local_path(s: &str) -> PathBuf {
    expand_tilde(Path::new(s))
}

/// MCPServer hides the message of unexpected exceptions; agents need it to recover.
fn guard(e: anyhow::Error) -> McpError {
    let kind = if e.downcast_ref::<PolicyError>().is_some() {
        "PolicyError"
    } else if e.downcast_ref::<ConfigError>().is_some() {
        "ConfigError"
    } else if e.downcast_ref::<UsageError>().is_some() {
        "UsageError"
    } else if e.downcast_ref::<CommandTimeout>().is_some() {
        "CommandTimeout"
    } else {
        "Error"
    };
    McpError::internal_error(format!("{kind}: {e}"), None)
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListServersParams {
    tag: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RunCommandParams {
    server: String,
    command: String,
    cwd: Option<String>,
    env: Option<HashMap<String, String>>,
    #[serde(default = "default_timeout")]
    timeout: f64,
    #[serde(default)]
    sudo: bool,
    max_output: Option<i64>,
    #[serde(default)]
    format: Format,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RunScriptParams {
    server: String,
    script: String,
    args: Option<Vec<String>>,
    cwd: Option<String>,
    #[serde(default = "default_timeout")]
    timeout: f64,
    max_output: Option<i64>,
    #[serde(default)]
    format: Format,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RunOnTagParams {
    tag: String,
    command: String,
    #[serde(default = "default_timeout")]
    timeout: f64,
    max_output: Option<i64>,
    #[serde(default)]
    format: Format,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UploadParams {
    server: String,
    local_path: String,
    remote_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DownloadParams {
    server: String,
    remote_path: String,
    local_path: String,
}

#[derive(Clone)]
struct AiSshClient {
    manager: Arc<SSHManager>,
    // Read by the `#[tool_handler]`-generated `call_tool`/`list_tools`, invisible to dead_code
    // analysis since that codegen lives in a derived trait impl.
    #[allow(dead_code)]
    tool_router: ToolRouter<AiSshClient>,
}

#[tool_router]
impl AiSshClient {
    fn new(manager: Arc<SSHManager>) -> Self {
        Self {
            manager,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List configured servers (name, host, user, tags, description, policy). Never includes secrets."
    )]
    async fn list_servers(
        &self,
        Parameters(p): Parameters<ListServersParams>,
    ) -> Result<CallToolResult, McpError> {
        let servers: Vec<serde_json::Value> = match p.tag {
            Some(t) => self
                .manager
                .by_tag(&t)
                .into_iter()
                .map(|s| s.public_info())
                .collect(),
            None => self
                .manager
                .servers
                .values()
                .map(|s| s.public_info())
                .collect(),
        };
        Ok(json_result(&servers))
    }

    #[tool(
        description = "Run a shell command on `server`; returns exit code, duration, stdout and stderr. cwd: remote working directory. env: extra environment variables. sudo: run through sudo using the configured password (if the policy allows). max_output: byte cap per stream. format: text (default) or json."
    )]
    async fn run_command(
        &self,
        Parameters(p): Parameters<RunCommandParams>,
    ) -> Result<CallToolResult, McpError> {
        let opts = RunOptions {
            timeout: Some(p.timeout),
            sudo: p.sudo,
            input: None,
            cwd: p.cwd,
            env: p.env.unwrap_or_default().into_iter().collect(),
            max_output: p.max_output,
            compact: true,
        };
        let result = self
            .manager
            .run(&p.server, &p.command, opts)
            .await
            .map_err(guard)?;
        Ok(command_result(&result, p.format))
    }

    #[tool(
        description = "Run a multi-line bash script on `server` (sent over stdin, no quoting needed). `args` become $1, $2..."
    )]
    async fn run_script(
        &self,
        Parameters(p): Parameters<RunScriptParams>,
    ) -> Result<CallToolResult, McpError> {
        let opts = RunOptions {
            timeout: Some(p.timeout),
            sudo: false,
            input: None,
            cwd: p.cwd,
            env: Default::default(),
            max_output: p.max_output,
            compact: true,
        };
        let args = p.args.unwrap_or_default();
        let result = self
            .manager
            .run_script(&p.server, &p.script, &args, opts)
            .await
            .map_err(guard)?;
        Ok(command_result(&result, p.format))
    }

    #[tool(
        description = "Run the same command in parallel on every server with `tag`. Per-server failures are reported, not raised."
    )]
    async fn run_on_tag(
        &self,
        Parameters(p): Parameters<RunOnTagParams>,
    ) -> Result<CallToolResult, McpError> {
        let names: Vec<String> = self
            .manager
            .by_tag(&p.tag)
            .into_iter()
            .map(|s| s.name.clone())
            .collect();
        if names.is_empty() {
            return Err(McpError::invalid_params(
                format!("no servers with tag '{}'", p.tag),
                None,
            ));
        }
        let opts = RunOptions {
            timeout: Some(p.timeout),
            sudo: false,
            input: None,
            cwd: None,
            env: Default::default(),
            max_output: p.max_output,
            compact: true,
        };
        let results = self.manager.run_many(&names, &p.command, opts).await;
        Ok(match p.format {
            Format::Text => text_result(
                results
                    .iter()
                    .map(|r| result_text(r, true))
                    .collect::<String>(),
            ),
            Format::Json => json_result(
                &results
                    .iter()
                    .map(|r| result_json(r, true))
                    .collect::<Vec<_>>(),
            ),
        })
    }

    #[tool(description = "Copy a local file to `remote_path` on `server` (SFTP).")]
    async fn upload(
        &self,
        Parameters(p): Parameters<UploadParams>,
    ) -> Result<CallToolResult, McpError> {
        let local = expand_local_path(&p.local_path);
        self.manager
            .upload(&p.server, &local, &p.remote_path)
            .await
            .map_err(guard)?;
        Ok(text_result(format!(
            "uploaded {} -> {}:{}",
            p.local_path, p.server, p.remote_path
        )))
    }

    #[tool(description = "Copy `remote_path` from `server` to a local file (SFTP).")]
    async fn download(
        &self,
        Parameters(p): Parameters<DownloadParams>,
    ) -> Result<CallToolResult, McpError> {
        let local = expand_local_path(&p.local_path);
        self.manager
            .download(&p.server, &p.remote_path, &local)
            .await
            .map_err(guard)?;
        Ok(text_result(format!(
            "downloaded {}:{} -> {}",
            p.server, p.remote_path, p.local_path
        )))
    }
}

#[tool_handler]
impl ServerHandler for AiSshClient {
    fn get_info(&self) -> McpServerConfig {
        McpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(INSTRUCTIONS.to_string())
    }
}

pub async fn serve(config_path: Option<&Path>) -> anyhow::Result<i32> {
    let manager = match SSHManager::new(config_path, true, "mcp") {
        Ok(m) => Arc::new(m),
        Err(e) => {
            eprintln!("error: {e}");
            return Ok(2);
        }
    };
    let service = AiSshClient::new(manager.clone());
    let running = service.serve(rmcp::transport::stdio()).await?;
    running.waiting().await?;
    manager.close_all().await;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(stdout: &str, stderr: &str) -> CommandResult {
        CommandResult {
            server: "web".into(),
            command: "ls".into(),
            stdout: stdout.into(),
            stderr: stderr.into(),
            exit_code: 0,
            duration_s: 0.25,
            truncated: false,
            stdout_bytes: stdout.len() as u64,
            stderr_bytes: stderr.len() as u64,
            error: None,
        }
    }

    #[test]
    fn text_has_header_and_optional_stderr() {
        assert_eq!(result_text(&result("a\nb", ""), false), "exit=0 0.25s\na\nb\n");
        assert_eq!(
            result_text(&result("out\n", "warn\n"), true),
            "=== web exit=0 0.25s ===\nout\n--- stderr ---\nwarn\n"
        );
        let failed = CommandResult::failure("db", "ls", "connect timeout");
        assert_eq!(
            result_text(&failed, true),
            "=== db exit=255 0s ===\nerror: connect timeout\n"
        );
    }

    #[test]
    fn json_omits_known_and_empty_fields() {
        let v = result_json(&result("hi\n", ""), false);
        assert_eq!(v, serde_json::json!({"exit_code": 0, "duration_s": 0.25, "stdout": "hi\n"}));
        let mut r = result("x", "");
        r.truncated = true;
        let v = result_json(&r, true);
        assert_eq!(v["server"], "web");
        assert_eq!(v["truncated"], true);
        assert_eq!(v["stdout_bytes"], 1);
    }
}
