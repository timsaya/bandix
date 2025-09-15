use crate::ebpf::egress::load_egress;
use crate::ebpf::ingress::load_ingress;
use crate::monitor::{
    dns, traffic, DnsModuleContext, ModuleContext, MonitorConfig, MonitorManager,
    TrafficModuleContext,
};
use crate::system::log_startup_info;
use crate::utils::network_utils::get_interface_info;
use crate::web;
use aya::maps::Array;
use clap::Parser;
use log::info;
use log::LevelFilter;
use std::sync::Arc;
use tokio::signal;

#[derive(Debug, Parser, Clone)]
#[clap(name = "bandix")]
#[clap(author = "github.com/timsaya")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Network traffic monitoring based on eBPF for OpenWrt")]
pub struct Options {
    #[clap(long, help = "Network interface to monitor (required)")]
    pub iface: String,

    #[clap(long, default_value = "8686", help = "Web server listening port")]
    pub port: u16,

    #[clap(
        long,
        default_value = "bandix-data",
        help = "Data directory (ring files and rate limit configurations will be stored here)"
    )]
    pub data_dir: String,

    #[clap(
        long,
        default_value = "false",
        help = "Enable web request logging (per-HTTP-request line)"
    )]
    pub web_log: bool,

    #[clap(
        long,
        default_value = "false",
        help = "Enable traffic monitoring module"
    )]
    pub enable_traffic: bool,

    #[clap(
        long,
        default_value = "600",
        help = "Retention duration (seconds), i.e., ring file capacity (one slot per second)"
    )]
    pub traffic_retention_seconds: u32,

    #[clap(
        long,
        default_value = "false",
        help = "Enable DNS monitoring module (not yet implemented)"
    )]
    pub enable_dns: bool,
}

// Validate arguments
fn validate_arguments(opt: &Options) -> Result<(), anyhow::Error> {
    // Check if network interface exists
    if get_interface_info(&opt.iface).is_none() {
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
        return Err(anyhow::anyhow!(
            "traffic_retention_seconds must be greater than 0"
        ));
    }

    Ok(())
}

// Initialize eBPF programs and maps
async fn init_ebpf_programs(options: &Options) -> Result<(aya::Ebpf, aya::Ebpf), anyhow::Error> {
    let egress_ebpf = load_egress(options.iface.clone()).await?;
    let ingress_ebpf = load_ingress(options.iface.clone()).await?;

    Ok((ingress_ebpf, egress_ebpf))
}

// Initialize subnet configuration
async fn init_subnet_info(
    egress_ebpf: &mut aya::Ebpf,
    ingress_ebpf: &mut aya::Ebpf,
    iface: String,
) -> Result<(), anyhow::Error> {
    // Configure subnet information for eBPF maps
    let interface_info = get_interface_info(&iface);
    let (interface_ip, subnet_mask) = interface_info.unwrap_or(([0, 0, 0, 0], [0, 0, 0, 0]));

    let mut subnet_info: Array<_, [u8; 4]> =
        Array::try_from(ingress_ebpf.take_map("SUBNET_INFO").unwrap())?;

    subnet_info.set(0, &interface_ip, 0)?;
    subnet_info.set(1, &subnet_mask, 0)?;

    let mut subnet_info: Array<_, [u8; 4]> =
        Array::try_from(egress_ebpf.take_map("SUBNET_INFO").unwrap())?;
    subnet_info.set(0, &interface_ip, 0)?;
    subnet_info.set(1, &subnet_mask, 0)?;

    Ok(())
}

// Run service, start web server and provide TUI output
async fn run_service(
    options: &Options,
    ingress_ebpf: aya::Ebpf,
    egress_ebpf: aya::Ebpf,
) -> Result<(), anyhow::Error> {
    // Create monitoring configuration
    let monitor_config = MonitorConfig::from_options(&options);

    // Use Notify for graceful shutdown
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let shutdown_notify_clone = shutdown_notify.clone();

    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            info!("Received shutdown signal, gracefully shutting down...");
            shutdown_notify_clone.notify_waiters();
        }
    });

    // Create module contexts based on enabled modules
    let mut module_contexts = Vec::new();

    if monitor_config.enable_traffic {
        module_contexts.push(ModuleContext::Traffic(TrafficModuleContext::new(
            options.clone(),
            ingress_ebpf,
            egress_ebpf,
        )));
    }

    if monitor_config.enable_dns {
        module_contexts.push(ModuleContext::Dns(DnsModuleContext::new(options.clone())));
    }

    // Create monitor manager
    let mut monitor_manager = MonitorManager::new(monitor_config);

    // Initialize all enabled modules
    monitor_manager.init_modules(&module_contexts).await?;

    // Start web server with API router
    let api_router = monitor_manager.get_api_router().clone();
    let options_for_web = options.clone();
    tokio::spawn(async move {
        if let Err(e) = web::start_server(options_for_web, api_router).await {
            log::error!("Web server error: {}", e);
        }
    });

    // Start internal loops for all modules
    let mut tasks = Vec::new();
    for ctx in module_contexts {
        let shutdown_notify = shutdown_notify.clone();
        let task = tokio::spawn(async move {
            match ctx {
                ModuleContext::Traffic(mut traffic_ctx) => {
                    if let Err(e) = traffic::start(&mut traffic_ctx, shutdown_notify).await {
                        log::error!("Traffic monitoring module error: {}", e);
                    }
                }
                ModuleContext::Dns(mut dns_ctx) => {
                    let dns_monitor = dns::DnsMonitor::new();
                    if let Err(e) = dns_monitor.start(&mut dns_ctx, shutdown_notify).await {
                        log::error!("DNS monitoring module error: {}", e);
                    }
                }
            }
        });
        tasks.push(task);
    }

    // Wait for shutdown signal
    shutdown_notify.notified().await;
    info!("Stopping all modules...");

    // Wait for all tasks to complete
    for task in tasks {
        if let Err(e) = task.await {
            log::error!("Module task error: {}", e);
        }
    }

    info!("All modules stopped, program exiting");

    Ok(())
}

pub async fn run(options: Options) -> Result<(), anyhow::Error> {
    // Validate arguments
    validate_arguments(&options)?;

    // Set up logging
    env_logger::Builder::new()
        .filter(None, LevelFilter::Info)
        .target(env_logger::Target::Stdout)
        .init();

    if !(options.enable_dns || options.enable_traffic) {
        return Err(anyhow::anyhow!(
            "No monitoring modules enabled. Use --enable-traffic to enable traffic monitoring, or --enable-dns to enable DNS monitoring"
        ));
    }

    // Startup diagnostics
    log_startup_info(&options);

    let (mut ingress, mut egress) = init_ebpf_programs(&options).await?;

    // Initialize subnet configuration
    init_subnet_info(&mut ingress, &mut egress, options.iface.clone()).await?;

    // Run service (start web and TUI)
    run_service(&options, ingress, egress).await?;

    Ok(())
}
