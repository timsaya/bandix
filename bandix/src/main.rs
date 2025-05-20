mod command;
mod ebpf;
mod web;

use clap::Parser;
use command::{run, Opt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 解析命令行参数
    let opt = Opt::parse();
    run(opt).await?;
    Ok(())
}