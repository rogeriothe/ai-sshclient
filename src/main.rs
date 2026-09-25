#[tokio::main]
async fn main() {
    let code = ai_sshclient::cli::run().await;
    std::process::exit(code);
}
