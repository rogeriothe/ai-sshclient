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

use crate::client::{CommandTimeout, RunOptions, SSHManager, UsageError};
use crate::config::{ConfigError, expand_tilde};
use crate::policy::PolicyError;

const INSTRUCTIONS: &str = "\
Run shell commands on remote servers over SSH. Credentials live in the server config and are \
never exposed; just pass the server name. Call list_servers first to see names, tags and each \
server's policy (read_only / allow_sudo / allow / deny). Output is capped (head + tail kept, \
`truncated` tells you); narrow your command (grep, tail, head) instead of dumping large files. \
Prefer run_script for multi-line scripts: it avoids quoting problems. Every call is audited.";

const DEFAULT_TIMEOUT: f64 = 120.0;

fn default_timeout() -> f64 {
    DEFAULT_TIMEOUT
}

fn json_result<T: serde::Serialize>(value: &T) -> CallToolResult {
    let text = serde_json::to_string(value).unwrap_or_default();
    CallToolResult::success(vec![ContentBlock::text(text)])
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
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RunOnTagParams {
    tag: String,
    command: String,
    #[serde(default = "default_timeout")]
    timeout: f64,
    max_output: Option<i64>,
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
        description = "Run a shell command on `server` and return stdout, stderr, exit_code, duration_s and truncated. cwd: remote working directory. env: extra environment variables. sudo: run through sudo using the configured password (if the policy allows). max_output: byte cap per stream."
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
        };
        let result = self
            .manager
            .run(&p.server, &p.command, opts)
            .await
            .map_err(guard)?;
        Ok(json_result(&result))
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
        };
        let args = p.args.unwrap_or_default();
        let result = self
            .manager
            .run_script(&p.server, &p.script, &args, opts)
            .await
            .map_err(guard)?;
        Ok(json_result(&result))
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
        };
        let results = self.manager.run_many(&names, &p.command, opts).await;
        Ok(json_result(&results))
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
