use crate::ebpf::egress::load_egress;
use crate::ebpf::ingress::load_ingress;
use crate::monitor::{
    ConnectionModuleContext, DnsModuleContext, ModuleContext, MonitorConfig, MonitorManager,
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
        default_value = "600",
        help = "Traffic data flush interval (seconds), how often to persist memory ring data to disk"
    )]
    pub traffic_flush_interval_seconds: u32,

    #[clap(
        long,
        default_value = "false",
        help = "Enable traffic history data persistence to disk (disabled by default, data only stored in memory)"
    )]
    pub traffic_persist_history: bool,

    #[clap(
        long,
        default_value = "false",
        help = "Enable DNS monitoring module (not yet implemented)"
    )]
    pub enable_dns: bool,

    #[clap(
        long,
        default_value = "false",
        help = "Enable connection statistics monitoring module"
    )]
    pub enable_connection: bool,
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

    if opt.traffic_flush_interval_seconds == 0 {
        return Err(anyhow::anyhow!(
            "traffic_flush_interval_seconds must be greater than 0"
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

// Initialize subnet configuration (IPv4 and IPv6)
async fn init_subnet_info(
    egress_ebpf: &mut aya::Ebpf,
    ingress_ebpf: &mut aya::Ebpf,
    iface: String,
) -> Result<(), anyhow::Error> {
    // Configure IPv4 subnet information
    let interface_info = get_interface_info(&iface);
    let (interface_ip, subnet_mask) = interface_info.unwrap_or(([0, 0, 0, 0], [0, 0, 0, 0]));

    let mut ipv4_subnet_info: Array<_, [u8; 4]> =
        Array::try_from(ingress_ebpf.take_map("IPV4_SUBNET_INFO").unwrap())?;

    ipv4_subnet_info.set(0, &interface_ip, 0)?;
    ipv4_subnet_info.set(1, &subnet_mask, 0)?;

    let mut ipv4_subnet_info: Array<_, [u8; 4]> =
        Array::try_from(egress_ebpf.take_map("IPV4_SUBNET_INFO").unwrap())?;
    ipv4_subnet_info.set(0, &interface_ip, 0)?;
    ipv4_subnet_info.set(1, &subnet_mask, 0)?;

    // Configure IPv6 subnet information
    let ipv6_addresses = crate::utils::network_utils::get_interface_ipv6_info(&iface);
    
    let mut ingress_ipv6_subnet_info: Array<_, [u8; 32]> =
        Array::try_from(ingress_ebpf.take_map("IPV6_SUBNET_INFO").unwrap())?;
    
    let mut egress_ipv6_subnet_info: Array<_, [u8; 32]> =
        Array::try_from(egress_ebpf.take_map("IPV6_SUBNET_INFO").unwrap())?;

    // Initialize all entries as disabled
    for i in 0..16 {
        ingress_ipv6_subnet_info.set(i, &[0u8; 32], 0)?;
        egress_ipv6_subnet_info.set(i, &[0u8; 32], 0)?;
    }

    // Set up to 16 IPv6 prefixes (matches Linux kernel default max_addresses)
    for (idx, (ipv6_addr, prefix_len)) in ipv6_addresses.iter().enumerate().take(16) {
        let mut subnet_data = [0u8; 32];
        
        // Copy network prefix (16 bytes)
        subnet_data[0..16].copy_from_slice(ipv6_addr);
        
        // Set prefix length
        subnet_data[16] = *prefix_len;
        
        // Set enabled flag
        subnet_data[17] = 1;
        
        ingress_ipv6_subnet_info.set(idx as u32, &subnet_data, 0)?;
        egress_ipv6_subnet_info.set(idx as u32, &subnet_data, 0)?;
        
        // Classify IPv6 address type
        let addr_type = crate::utils::network_utils::classify_ipv6_address(ipv6_addr);
        
        log::info!(
            "Configured IPv6 subnet {}: {}/{} [Type: {}, Network: {}]",
            idx,
            crate::utils::network_utils::format_ipv6_with_privacy(ipv6_addr),
            prefix_len,
            addr_type.type_name(),
            addr_type.network_scope()
        );
    }

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
    
    // Create shared hostname bindings if any module needs it
    let shared_hostname_bindings = if monitor_config.enable_traffic || monitor_config.enable_connection {
        let bindings = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        
        // Load existing hostname bindings from file (priority source)
        let mut bindings_count = 0;
        if let Ok(loaded_bindings) = crate::storage::traffic::load_hostname_bindings(&options.data_dir) {
            let mut bindings_map = bindings.lock().unwrap();
            for (mac, hostname) in loaded_bindings {
                bindings_map.insert(mac, hostname);
                bindings_count += 1;
            }
            log::info!("Loaded {} hostname bindings from saved file", bindings_count);
        } else {
            log::warn!("Failed to load hostname bindings from saved file");
        }
        
        // Load additional hostname bindings from DHCP leases (fallback source)
        if let Ok(dhcp_bindings) = crate::storage::traffic::load_dhcp_leases("/tmp/dhcp.leases") {
            let mut bindings_map = bindings.lock().unwrap();
            let mut dhcp_count = 0;
            for (mac, hostname) in dhcp_bindings {
                // Only add if MAC address doesn't already exist (saved bindings take priority)
                if !bindings_map.contains_key(&mac) {
                    bindings_map.insert(mac, hostname);
                    dhcp_count += 1;
                }
            }
            if dhcp_count > 0 {
                log::info!("Loaded {} additional hostname bindings from /tmp/dhcp.leases", dhcp_count);
            }
        }
        
        Some(bindings)
    } else {
        None
    };

    if monitor_config.enable_traffic {
        let mut traffic_ctx = TrafficModuleContext::new(
            options.clone(),
            ingress_ebpf,
            egress_ebpf,
        );
        
        // Replace the traffic module's hostname_bindings with the shared one
        if let Some(ref shared_bindings) = shared_hostname_bindings {
            traffic_ctx.hostname_bindings = std::sync::Arc::clone(shared_bindings);
        }
        
        module_contexts.push(ModuleContext::Traffic(traffic_ctx));
    }

    if monitor_config.enable_dns {
        module_contexts.push(ModuleContext::Dns(DnsModuleContext::new(options.clone())));
    }

    if monitor_config.enable_connection {
        let hostname_bindings = if let Some(shared_bindings) = shared_hostname_bindings {
            shared_bindings
        } else {
            // Fallback: create independent bindings if traffic module is not enabled
            let bindings = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
            
            // Load from saved bindings file
            if let Ok(loaded_bindings) = crate::storage::traffic::load_hostname_bindings(&options.data_dir) {
                let mut bindings_map = bindings.lock().unwrap();
                for (mac, hostname) in loaded_bindings {
                    bindings_map.insert(mac, hostname);
                }
            }
            
            // Load additional bindings from DHCP leases
            if let Ok(dhcp_bindings) = crate::storage::traffic::load_dhcp_leases("/tmp/dhcp.leases") {
                let mut bindings_map = bindings.lock().unwrap();
                for (mac, hostname) in dhcp_bindings {
                    if !bindings_map.contains_key(&mac) {
                        bindings_map.insert(mac, hostname);
                    }
                }
            }
            
            bindings
        };
        
        module_contexts.push(ModuleContext::Connection(ConnectionModuleContext::new(
            options.clone(),
            hostname_bindings,
        )));
    }

    // Create monitor manager
    let mut monitor_manager = MonitorManager::new(monitor_config);

    // Initialize all enabled modules
    monitor_manager.init_modules(&module_contexts).await?;

    // Start web server with API router
    let api_router = monitor_manager.get_api_router().clone();
    let options_for_web = options.clone();
    let shutdown_notify_for_web = shutdown_notify.clone();
    let web_task = tokio::spawn(async move {
        if let Err(e) = web::start_server(options_for_web, api_router, shutdown_notify_for_web).await {
            log::error!("Web server error: {}", e);
        }
    });

    // Start internal loops for all modules via MonitorManager
    let mut tasks = monitor_manager
        .start_modules(module_contexts, shutdown_notify.clone())
        .await?;

    // Add web server task to the list
    tasks.push(web_task);

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

    if !(options.enable_dns || options.enable_traffic || options.enable_connection) {
        return Err(anyhow::anyhow!(
            "No monitoring modules enabled. Use --enable-traffic to enable traffic monitoring, --enable-dns to enable DNS monitoring, or --enable-connection to enable connection statistics monitoring"
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
