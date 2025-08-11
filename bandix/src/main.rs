mod command;
mod display;
mod ebpf;
mod storage;
mod traffic;
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
