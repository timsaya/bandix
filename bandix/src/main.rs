mod command;
mod display;
mod ebpf;
mod monitor;
mod storage;
mod system;
mod utils;
mod web;

use crate::utils::network_utils;
use clap::Parser;
use command::{run, Opt};

// Validate arguments
fn validate_arguments(opt: &Opt) -> Result<(), anyhow::Error> {
    // Check if network interface exists
    if network_utils::get_interface_info(&opt.iface).is_none() {
        return Err(anyhow::anyhow!(
            "Network interface '{}' does not exist",
            opt.iface
        ));
    }

    // Check if port is valid (0-65535)
    if opt.port == 0 {
        return Err(anyhow::anyhow!("Port number cannot be 0"));
    }

    if opt.traffic_retention_seconds == 0 {
        return Err(anyhow::anyhow!("traffic_retention_seconds must be greater than 0"));
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Parse command line arguments
    let opt = Opt::parse();

    // Validate arguments
    validate_arguments(&opt)?;

    // Run main program
    run(opt).await?;
    Ok(())
}
