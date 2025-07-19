mod command;
mod display;
mod ebpf;
mod traffic;
mod utils;
mod web;

use clap::Parser;
use command::{run, Opt};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Parse command line arguments
    let opt = Opt::parse();
    run(opt).await?;
    Ok(())
}
