mod api;
mod command;
mod device;
mod ebpf;
mod monitor;
mod storage;
mod system;
mod utils;
mod web;
use clap::Parser;
use command::{run, Options};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // 解析命令行参数
    let options = Options::parse();

    // 运行主程序
    run(options).await?;

    Ok(())
}
