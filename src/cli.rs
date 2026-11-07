//! Command line interface: ai-sshclient {list,run,upload,download,mcp}.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};

use crate::client::{CommandResult, RunOptions, SSHManager, UsageError, script_command};
use crate::config::ConfigError;
use crate::policy::PolicyError;

#[derive(Parser)]
#[command(
    name = "ai-sshclient",
    about = "Run commands on servers defined in a YAML file.",
    disable_help_subcommand = true,
    version
)]
pub struct Cli {
    /// path to servers YAML (default: $AI_SSHCLIENT_CONFIG, ./servers.yaml, ~/.config/ai-sshclient/servers.yaml)
    #[arg(short = 'c', long = "config", global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Subcommand)]
pub enum Action {
    /// list configured servers
    List {
        /// print as JSON (no secrets)
        #[arg(long)]
        json: bool,
    },
    /// run a command and print its output
    Run(RunArgs),
    /// copy a local file to the server
    Upload {
        server: String,
        local: PathBuf,
        remote: String,
    },
    /// copy a remote file to the local machine
    Download {
        server: String,
        remote: String,
        local: PathBuf,
    },
    /// import a server from ~/.ssh/config into servers.yaml
    #[command(alias = "import-ssh", alias = "add")]
    Import(crate::ssh_config::ImportArgs),
    /// run as an MCP server over stdio (for AI agents)
    Mcp,
    /// check for a newer GitHub release and install it
    Update {
        /// only report whether a newer version exists
        #[arg(long)]
        check: bool,
    },
}

#[derive(Args)]
#[command(trailing_var_arg = true)]
pub struct RunArgs {
    /// server name from the YAML
    pub server: Option<String>,
    /// command to run
    #[arg(allow_hyphen_values = true)]
    pub command: Vec<String>,
    /// run on every server with this tag (server positional becomes part of the command)
    #[arg(short = 't', long)]
    pub tag: Option<String>,
    /// run a local shell script remotely ('-' reads it from stdin); extra args become $1, $2...
    #[arg(short = 's', long, value_name = "FILE")]
    pub script: Option<String>,
    /// remote working directory
    #[arg(long)]
    pub cwd: Option<String>,
    /// environment variable for the command (repeatable)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,
    /// command timeout in seconds
    #[arg(long)]
    pub timeout: Option<f64>,
    /// byte cap per stream, keeping head and tail (0 = unlimited; default from config, 64000)
    #[arg(long = "max-output")]
    pub max_output: Option<i64>,
    /// run with sudo, feeding the configured password
    #[arg(long)]
    pub sudo: bool,
    /// print one JSON object per server
    #[arg(long)]
    pub json: bool,
}

fn targets(
    manager: &SSHManager,
    server: Option<&str>,
    tag: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    if let Some(tag) = tag {
        let names: Vec<String> = manager
            .by_tag(tag)
            .into_iter()
            .map(|s| s.name.clone())
            .collect();
        if names.is_empty() {
            return Err(UsageError(format!("no servers with tag '{tag}'")).into());
        }
        return Ok(names);
    }
    let server = server.ok_or_else(|| UsageError("provide a server name or --tag".to_string()))?;
    manager.get(server)?;
    Ok(vec![server.to_string()])
}

fn print_result(result: &CommandResult, as_json: bool, prefix: bool) {
    use std::io::Write as _;
    if as_json {
        println!("{}", result.to_json());
        return;
    }
    if prefix {
        println!("=== {} (exit {}) ===", result.server, result.exit_code);
    }
    print!("{}", result.stdout);
    let _ = std::io::stdout().flush();
    eprint!("{}", result.stderr);
    if result.truncated {
        eprintln!(
            "[ai-sshclient: output truncated; stdout {} bytes, stderr {} bytes]",
            result.stdout_bytes, result.stderr_bytes
        );
    }
}

fn parse_env(pairs: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for pair in pairs {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| UsageError(format!("--env expects KEY=VALUE, got {pair:?}")))?;
        if key.is_empty() {
            return Err(UsageError(format!("--env expects KEY=VALUE, got {pair:?}")).into());
        }
        env.insert(key.to_string(), value.to_string());
    }
    Ok(env)
}

async fn cmd_list(manager: &SSHManager, as_json: bool) -> i32 {
    if as_json {
        let list: Vec<serde_json::Value> =
            manager.servers.values().map(|s| s.public_info()).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&list).unwrap_or_default()
        );
        return 0;
    }
    for s in manager.servers.values() {
        let tags = if s.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", s.tags.join(", "))
        };
        let desc = if s.description.is_empty() {
            String::new()
        } else {
            format!(" - {}", s.description)
        };
        let via = s
            .proxy_jump
            .as_ref()
            .map(|j| format!(" via {j}"))
            .unwrap_or_default();
        let ro = if s.policy.read_only { " read-only" } else { "" };
        println!(
            "{:<20} {}@{}:{} ({}{}{}){}{}",
            s.name,
            s.user,
            s.host,
            s.port,
            s.auth_method(),
            via,
            ro,
            tags,
            desc
        );
    }
    0
}

async fn cmd_run(manager: Arc<SSHManager>, args: RunArgs) -> anyhow::Result<i32> {
    let names = targets(&manager, args.server.as_deref(), args.tag.as_deref())?;
    let env = parse_env(&args.env)?;

    let (command, input) = if let Some(script_path) = &args.script {
        let text = if script_path == "-" {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            std::fs::read_to_string(script_path)?
        };
        (script_command(&args.command), Some(text))
    } else {
        (args.command.join(" "), None)
    };

    let opts = RunOptions {
        timeout: args.timeout,
        sudo: args.sudo,
        input,
        cwd: args.cwd.clone(),
        env,
        max_output: args.max_output,
        compact: false,
    };

    let results = manager.run_many(&names, &command, opts).await;
    let prefix = names.len() > 1;
    for r in &results {
        print_result(r, args.json, prefix);
    }
    Ok(results.iter().map(|r| r.exit_code).max().unwrap_or(0))
}

fn map_error(e: anyhow::Error) -> i32 {
    eprintln!("error: {e}");
    if e.downcast_ref::<ConfigError>().is_some()
        || e.downcast_ref::<PolicyError>().is_some()
        || e.downcast_ref::<UsageError>().is_some()
    {
        2
    } else {
        255
    }
}

pub async fn run() -> i32 {
    let cli = Cli::parse();

    if matches!(cli.action, Action::Mcp) {
        return match crate::mcp_server::serve(cli.config.as_deref()).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("error: {e}");
                2
            }
        };
    }

    if let Action::Update { check } = cli.action {
        // Blocking HTTP: keep it off the async runtime threads.
        let res = tokio::task::spawn_blocking(move || crate::update::run(check)).await;
        return match res {
            Ok(Ok(())) => 0,
            Ok(Err(e)) => {
                eprintln!("error: {e:#}");
                1
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        };
    }

    if let Action::Import(mut args) = cli.action {
        if args.out.is_none() && cli.config.is_some() {
            args.out = cli.config;
        }
        return match crate::ssh_config::import_server(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                2
            }
        };
    }

    let mut action = cli.action;
    if let Action::Run(ref mut args) = action {
        if args.tag.is_some() && args.server.is_some() {
            let mut cmd = vec![args.server.take().expect("checked is_some")];
            cmd.append(&mut args.command);
            args.command = cmd;
        }
        if args.command.is_empty() && args.script.is_none() {
            eprintln!("error: no command given");
            return 2;
        }
    }

    let manager = match SSHManager::new(cli.config.as_deref(), false, "cli") {
        Ok(m) => Arc::new(m),
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    match action {
        Action::List { json } => cmd_list(&manager, json).await,
        Action::Run(args) => match cmd_run(manager, args).await {
            Ok(code) => code,
            Err(e) => map_error(e),
        },
        Action::Upload {
            server,
            local,
            remote,
        } => match manager.upload(&server, &local, &remote).await {
            Ok(()) => 0,
            Err(e) => map_error(e),
        },
        Action::Download {
            server,
            remote,
            local,
        } => match manager.download(&server, &remote, &local).await {
            Ok(()) => 0,
            Err(e) => map_error(e),
        },
        Action::Mcp | Action::Import(_) | Action::Update { .. } => unreachable!("handled above"),
    }
}
