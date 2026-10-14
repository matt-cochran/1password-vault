use clap::Parser;
use rmcp::{ServiceExt, transport::stdio};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Read-only opv MCP server. Humans approve and execute all changes outside MCP.")]
struct Args {
    /// Trusted project directory chosen by the human launching the server.
    #[arg(long)]
    project: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let project = Args::parse().project.canonicalize()?;
    if !project.is_dir() {
        return Err("project must be a directory".into());
    }
    std::env::set_current_dir(&project)?;
    let server = opv::mcp::Server::new(project).serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}
